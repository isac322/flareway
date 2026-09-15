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
	if !strings.HasPrefix(strings.ToLower(prefix), names.OwnerPrefix) {
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
			if !containsPrefix(policy.Name, prefix) || !eligibleForCleanup(policy.CreatedAt, cutoff, olderThan) {
				continue
			}
			if err := api.DeleteAccessPolicy(ctx, policy.ID); err != nil {
				failures = append(failures, fmt.Errorf("delete Access policy %s: %w", policy.ID, err))
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
			if !containsPrefix(token.Name, prefix) || !eligibleForCleanup(token.CreatedAt, cutoff, olderThan) {
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
			if !containsPrefix(tunnel.Name, prefix) || !beforeCutoff(tunnel.CreatedAt, cutoff) {
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
	if containsPrefix(record.Name, prefix) || containsPrefix(record.Comment, prefix) {
		return true
	}
	for _, tag := range record.Tags {
		if containsPrefix(tag, prefix) {
			return true
		}
	}
	return false
}

func ownedPrivateResource(primary, comment, prefix string) bool {
	return containsPrefix(primary, prefix) || containsPrefix(comment, prefix)
}

func ownedAccessApplication(application cfapi.AccessApplication, prefix string) bool {
	if containsPrefix(application.Name, prefix) || containsPrefix(application.Domain, prefix) {
		return true
	}
	for _, tag := range application.Tags {
		if containsPrefix(tag, prefix) {
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
		if strings.HasPrefix(strings.ToLower(tag), "flareway-bypass-of=") {
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

func containsPrefix(value, prefix string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(prefix))
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
