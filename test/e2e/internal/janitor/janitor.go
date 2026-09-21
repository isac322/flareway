/*
Copyright 2026 Byeonghoon Yoo.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package janitor removes stale resources created by Flareway e2e runs.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/isac322/flareway/test/e2e/internal/cfapi"
	"github.com/isac322/flareway/test/e2e/internal/names"
)

// API is the destructive subset of Cloudflare used by cleanup.
type API interface {
	ListAccessApplications(context.Context) ([]cfapi.AccessApplication, error)
	DeleteAccessApplication(context.Context, string) error
	ListAccessPolicies(context.Context) ([]cfapi.AccessPolicy, error)
	DeleteAccessPolicy(context.Context, string) error
	ListServiceTokens(context.Context) ([]cfapi.ServiceToken, error)
	DeleteServiceToken(context.Context, string) error
	ListTunnels(context.Context) ([]cfapi.Tunnel, error)
	DeleteTunnel(context.Context, string) error
	ListDNSRecords(context.Context) ([]cfapi.DNSRecord, error)
	DeleteDNSRecord(context.Context, string) error
	ListVirtualNetworks(context.Context) ([]cfapi.VirtualNetwork, error)
	DeleteVirtualNetwork(context.Context, string) error
	ListNetworkRoutes(context.Context) ([]cfapi.NetworkRoute, error)
	DeleteNetworkRoute(context.Context, string) error
	ListHostnameRoutes(context.Context) ([]cfapi.HostnameRoute, error)
	DeleteHostnameRoute(context.Context, string) error
	ListDeviceProfiles(context.Context) ([]cfapi.DeviceProfile, error)
	DeleteDeviceProfile(context.Context, string) error
	ListDeviceRegistrations(context.Context) ([]cfapi.DeviceRegistration, error)
	DeleteDeviceRegistration(context.Context, string) error
	ListAccessApplicationPolicies(context.Context, string) ([]cfapi.AccessPolicy, error)
	DeleteAccessApplicationPolicy(context.Context, string, string) error
}

// Report describes what Sweep removed and deliberately skipped.
type Report struct {
	AccessApplicationsDeleted int
	AccessPoliciesDeleted     int
	ServiceTokensDeleted      int
	HostnameRoutesDeleted     int
	NetworkRoutesDeleted      int
	VirtualNetworksDeleted    int
	DNSRecordsDeleted         int
	TunnelsDeleted            int
	DeviceProfilesDeleted     int
	DeviceRegistrationsDeleted int
	ConnectedSkipped          int
}

// Sweep removes disconnected e2e resources older than olderThan.
func Sweep(ctx context.Context, api API, olderThan time.Duration) (Report, error) {
	return SweepPrefix(ctx, api, names.OwnerPrefix, olderThan, time.Now().UTC())
}

// SweepPrefix limits cleanup to one ownership prefix. It is used by a suite's
// finalizer to clean only its run and by tests to supply a deterministic clock.
func SweepPrefix(ctx context.Context, api API, prefix string, olderThan time.Duration, now time.Time) (Report, error) {
	var report Report
	if api == nil {
		return report, fmt.Errorf("janitor API is required")
	}
	if !validSweepPrefix(prefix) {
		return report, fmt.Errorf("refusing unsafe janitor prefix %q", prefix)
	}
	if olderThan < 0 {
		return report, fmt.Errorf("older-than duration must not be negative")
	}
	cutoff := now.Add(-olderThan)
	var failures []error

	applications, err := api.ListAccessApplications(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list Access applications: %w", err))
	} else {
		sort.SliceStable(applications, func(i, j int) bool {
			return isBypassApplication(applications[i]) && !isBypassApplication(applications[j])
		})
		for _, application := range applications {
			if !ownedAccessApplication(application, prefix) || !eligibleForCleanup(application.CreatedAt, cutoff, olderThan) {
				continue
			}
			if err := api.DeleteAccessApplication(ctx, application.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete Access application %s: %w", application.ID, err))
				continue
			}
			report.AccessApplicationsDeleted++
		}
	}

	policies, err := api.ListAccessPolicies(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list Access policies: %w", err))
	} else {
		for _, policy := range policies {
			if !names.HasOwnerMarker(policy.Name, prefix) || !eligibleForCleanup(policy.CreatedAt, cutoff, olderThan) {
				continue
			}
			if err := api.DeleteAccessPolicy(ctx, policy.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete Access policy %s: %w", policy.ID, err))
				continue
			}
			report.AccessPoliciesDeleted++
		}
	}

	// Device registrations carry no name marker, so ownership is proven only
	// through a profile this sweep owns and will delete. Registrations are
	// removed before their profiles.
	ownedProfiles := make(map[string]struct{})
	profiles, err := api.ListDeviceProfiles(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list device profiles: %w", err))
	} else {
		for _, profile := range profiles {
			if ownedDeviceProfile(profile, prefix) && eligibleForCleanup(profileTime(profile), cutoff, olderThan) {
				ownedProfiles[profile.PolicyID] = struct{}{}
			}
		}
	}

	registrations, err := api.ListDeviceRegistrations(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list device registrations: %w", err))
	} else {
		for _, registration := range registrations {
			policyID := registrationProfileID(registration)
			_, owned := ownedProfiles[policyID]
			if !owned || registration.DeletedAt != nil {
				continue
			}
			if err := api.DeleteDeviceRegistration(ctx, registration.ID); err != nil {
				// Retain the owning profile: deleting it would orphan the
				// registration and erase the only ownership link.
				delete(ownedProfiles, policyID)
				failures = append(failures, fmt.Errorf("delete device registration %s: %w", registration.ID, err))
				continue
			}
			report.DeviceRegistrationsDeleted++
		}
	}

	for _, profile := range profiles {
		if _, owned := ownedProfiles[profile.PolicyID]; !owned {
			continue
		}
		if err := api.DeleteDeviceProfile(ctx, profile.PolicyID); err != nil {
			failures = append(failures, fmt.Errorf("delete device profile %s: %w", profile.PolicyID, err))
			continue
		}
		report.DeviceProfilesDeleted++
	}

	// Runner enrollment policies live on the shared WARP enrollment
	// application, which is never owned or deleted; only policies carrying the
	// run marker are removed.
	for _, application := range applications {
		if application.Type != "warp" {
			continue
		}
		appPolicies, err := api.ListAccessApplicationPolicies(ctx, application.ID)
		if err != nil {
			failures = append(failures, fmt.Errorf("list policies for Access application %s: %w", application.ID, err))
			continue
		}
		for _, policy := range appPolicies {
			if !names.HasOwnerMarker(policy.Name, prefix) || !eligibleForCleanup(policy.CreatedAt, cutoff, olderThan) {
				continue
			}
			if err := api.DeleteAccessApplicationPolicy(ctx, application.ID, policy.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete Access application %s policy %s: %w", application.ID, policy.ID, err))
				continue
			}
			report.AccessPoliciesDeleted++
		}
	}

	tokens, err := api.ListServiceTokens(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list Access service tokens: %w", err))
	} else {
		for _, token := range tokens {
			if !names.HasOwnerMarker(token.Name, prefix) || !eligibleForCleanup(token.CreatedAt, cutoff, olderThan) {
				continue
			}
			if err := api.DeleteServiceToken(ctx, token.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete Access service token %s: %w", token.ID, err))
				continue
			}
			report.ServiceTokensDeleted++
		}
	}

	hostnameRoutes, err := api.ListHostnameRoutes(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list hostname routes: %w", err))
	} else {
		for _, route := range hostnameRoutes {
			if !ownedPrivateResource(route.Hostname, route.Comment, prefix) || !eligibleForCleanup(route.CreatedAt, cutoff, olderThan) {
				continue
			}
			if err := api.DeleteHostnameRoute(ctx, route.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete hostname route %s: %w", route.ID, err))
				continue
			}
			report.HostnameRoutesDeleted++
		}
	}

	networkRoutes, err := api.ListNetworkRoutes(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list network routes: %w", err))
	} else {
		for _, route := range networkRoutes {
			if !ownedPrivateResource(route.Network, route.Comment, prefix) || !eligibleForCleanup(route.CreatedAt, cutoff, olderThan) {
				continue
			}
			if err := api.DeleteNetworkRoute(ctx, route.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete network route %s: %w", route.ID, err))
				continue
			}
			report.NetworkRoutesDeleted++
		}
	}

	virtualNetworks, err := api.ListVirtualNetworks(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list virtual networks: %w", err))
	} else {
		for _, network := range virtualNetworks {
			if !ownedPrivateResource(network.Name, network.Comment, prefix) || !eligibleForCleanup(network.CreatedAt, cutoff, olderThan) {
				continue
			}
			if err := api.DeleteVirtualNetwork(ctx, network.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete virtual network %s: %w", network.ID, err))
				continue
			}
			report.VirtualNetworksDeleted++
		}
	}

	records, err := api.ListDNSRecords(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list DNS records: %w", err))
	} else {
		for _, record := range records {
			if !ownedDNSRecord(record, prefix) || !beforeCutoff(recordTime(record), cutoff) {
				continue
			}
			if err := api.DeleteDNSRecord(ctx, record.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete DNS record %s: %w", record.ID, err))
				continue
			}
			report.DNSRecordsDeleted++
		}
	}

	tunnels, err := api.ListTunnels(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list tunnels: %w", err))
	} else {
		for _, tunnel := range tunnels {
			if !names.HasOwnerMarker(tunnel.Name, prefix) || !beforeCutoff(tunnel.CreatedAt, cutoff) {
				continue
			}
			if len(tunnel.Connections) != 0 || tunnel.Status == "healthy" || tunnel.Status == "degraded" {
				report.ConnectedSkipped++
				continue
			}
			if err := api.DeleteTunnel(ctx, tunnel.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete tunnel %s: %w", tunnel.ID, err))
				continue
			}
			report.TunnelsDeleted++
		}
	}

	return report, errors.Join(failures...)
}

func ownedDNSRecord(record cfapi.DNSRecord, prefix string) bool {
	if names.HasOwnerMarker(record.Name, prefix) || names.HasOwnerMarker(record.Comment, prefix) {
		return true
	}
	for _, tag := range record.Tags {
		if names.HasOwnerMarker(tag, prefix) {
			return true
		}
	}
	return false
}

func ownedPrivateResource(primary, comment, prefix string) bool {
	return names.HasOwnerMarker(primary, prefix) || names.HasOwnerMarker(comment, prefix)
}

// ownedDeviceProfile matches only custom profiles: the default profile is
// never deleted or modified by the janitor. The match expression is a second
// marker surface because the suite embeds the run ID in the identity email.
func ownedDeviceProfile(profile cfapi.DeviceProfile, prefix string) bool {
	if profile.Default || profile.PolicyID == "" {
		return false
	}
	return names.HasOwnerMarker(profile.Name, prefix) || names.HasOwnerMarker(profile.Match, prefix)
}

// registrationProfileID resolves the profile binding of a registration from
// the nested policy object populated by include=policy.
func registrationProfileID(registration cfapi.DeviceRegistration) string {
	if registration.Policy == nil {
		return ""
	}
	return registration.Policy.ID
}

func ownedAccessApplication(application cfapi.AccessApplication, prefix string) bool {
	if names.HasOwnerMarker(application.Name, prefix) || names.HasOwnerMarker(application.Domain, prefix) {
		return true
	}
	for _, tag := range application.Tags {
		if names.HasOwnerMarker(tag, prefix) {
			return true
		}
	}
	return false
}

func isBypassApplication(application cfapi.AccessApplication) bool {
	if strings.Contains(strings.ToLower(application.Name), "/bypass/") {
		return true
	}
	for _, tag := range application.Tags {
		if strings.HasPrefix(strings.ToLower(tag), "flareway-bypass-") {
			return true
		}
	}
	return false
}

func eligibleForCleanup(createdAt, cutoff time.Time, olderThan time.Duration) bool {
	if createdAt.IsZero() {
		return olderThan == 0
	}
	return beforeCutoff(createdAt, cutoff)
}

// validSweepPrefix accepts only the bare owner prefix (global stale sweep) or
// the owner prefix plus one complete run ID (per-run cleanup). Anything else,
// including truncated or extended run IDs, is rejected before any listing.
func validSweepPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	if prefix == names.OwnerPrefix {
		return true
	}
	runID, found := strings.CutPrefix(prefix, names.OwnerPrefix)
	return found && names.IsRunID(runID)
}

func beforeCutoff(createdAt, cutoff time.Time) bool {
	return !createdAt.IsZero() && !createdAt.After(cutoff)
}

func recordTime(record cfapi.DNSRecord) time.Time {
	if !record.CreatedOn.IsZero() {
		return record.CreatedOn
	}
	return record.ModifiedOn
}

// profileTime dates a device profile for stale eligibility. The profiles API
// omits created_at, so the RFC3339 marker embedded in the description by the
// suite and runner bootstrap is the fallback; profiles without either stay
// eligible only for run-scoped (olderThan=0) cleanup.
func profileTime(profile cfapi.DeviceProfile) time.Time {
	if !profile.CreatedAt.IsZero() {
		return profile.CreatedAt
	}
	if !profile.UpdatedAt.IsZero() {
		return profile.UpdatedAt
	}
	return createdMarkerTime(profile.Description)
}

// createdMarkerTime extracts the names.CreatedMarkerPrefix timestamp from a
// resource description, returning the zero time when it is absent or invalid.
func createdMarkerTime(description string) time.Time {
	index := strings.Index(description, names.CreatedMarkerPrefix)
	if index < 0 {
		return time.Time{}
	}
	value := description[index+len(names.CreatedMarkerPrefix):]
	if end := strings.IndexAny(value, " \t|"); end >= 0 {
		value = value[:end]
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
