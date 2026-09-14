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

package cfstub

import (
	"context"
	"testing"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"

	flarev1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestM2RoutesDecodeThroughCloudflareSDKAdapter(t *testing.T) {
	server := New(t)
	server.State.AddZone(Zone{
		ID: "zone-1", Name: "example.com", AccountID: "account-1", AccountName: "Example Account",
	})
	server.State.SetOrganization("account-1", Organization{
		ID: "organization-1", Name: "Example", AuthDomain: "example.cloudflareaccess.com",
	})
	api := flarecloudflare.New(
		"api-token", "account-1", logr.Discard(),
		flarecloudflare.WithBaseURL(server.URL),
		flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)),
	)
	ctx := context.Background()

	verification, err := api.VerifyToken(ctx)
	if err != nil || !verification.Active() {
		t.Fatalf("VerifyToken = %#v, %v", verification, err)
	}
	zones, err := api.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].AccountID != "account-1" || zones[0].AccountName != "Example Account" {
		t.Fatalf("ListZones = %#v, %v", zones, err)
	}
	organization, err := api.GetOrganization(ctx)
	if err != nil || organization.AuthDomain != "example.cloudflareaccess.com" {
		t.Fatalf("GetOrganization = %#v, %v", organization, err)
	}

	tunnel, err := api.CreateTunnel(ctx, "flareway-e2e-deadbeef-public")
	if err != nil || tunnel.ID == "" || tunnel.Status != "inactive" {
		t.Fatalf("CreateTunnel = %#v, %v", tunnel, err)
	}
	token, err := api.GetTunnelToken(ctx, tunnel.ID)
	if err != nil || token == "" {
		t.Fatalf("GetTunnelToken = %q, %v", token, err)
	}
	version, err := api.GetTunnelConfigurationVersion(ctx, tunnel.ID)
	if err != nil || version != 0 {
		t.Fatalf("GetTunnelConfigurationVersion = %d, %v", version, err)
	}
	version, err = api.UpdateTunnelConfiguration(ctx, tunnel.ID, zero_trust.TunnelCloudflaredConfigurationUpdateParams{
		Config: cloudflaresdk.F(zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfig{
			Ingress: cloudflaresdk.F([]zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngress{{
				Hostname: cloudflaresdk.F("e2e-deadbeef-1.example.com"),
				Service:  cloudflaresdk.F("http://127.0.0.1:18080"),
			}, {
				Service: cloudflaresdk.F("http_status:404"),
			}}),
		}),
	})
	if err != nil || version != 1 {
		t.Fatalf("UpdateTunnelConfiguration = %d, %v", version, err)
	}
	version, err = api.GetTunnelConfigurationVersion(ctx, tunnel.ID)
	if err != nil || version != 1 {
		t.Fatalf("GetTunnelConfigurationVersion after update = %d, %v", version, err)
	}

	input := flarecloudflare.DNSRecordInput{
		Name: "e2e-deadbeef-1.example.com", Content: tunnel.ID + ".cfargotunnel.com",
		Comment: "flareway flareway-e2e-deadbeef", Tags: []string{"managed-by=flareway"}, Proxied: true,
	}
	record, err := api.CreateCNAME(ctx, "zone-1", input)
	if err != nil || record.ID == "" || !record.Proxied {
		t.Fatalf("CreateCNAME = %#v, %v", record, err)
	}
	records, err := api.ListDNSRecords(ctx, "zone-1", input.Name)
	if err != nil || len(records) != 1 || records[0].ID != record.ID {
		t.Fatalf("ListDNSRecords = %#v, %v", records, err)
	}
	input.Content = "replacement.cfargotunnel.com"
	updated, err := api.UpdateCNAME(ctx, "zone-1", record.ID, input)
	if err != nil || updated.Content != input.Content {
		t.Fatalf("UpdateCNAME = %#v, %v", updated, err)
	}
	if err := api.DeleteDNSRecord(ctx, "zone-1", record.ID); err != nil {
		t.Fatalf("DeleteDNSRecord returned error: %v", err)
	}
	if err := api.DeleteTunnel(ctx, tunnel.ID, true); err != nil {
		t.Fatalf("DeleteTunnel returned error: %v", err)
	}
}

func TestM3RoutesDecodeThroughCloudflareSDKAdapter(t *testing.T) {
	server := New(t)
	api := flarecloudflare.New(
		"api-token", "account-1", logr.Discard(),
		flarecloudflare.WithBaseURL(server.URL),
		flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)),
	)
	ctx := context.Background()

	serviceToken, err := api.CreateServiceToken(ctx, flarecloudflare.ServiceTokenInput{Name: "service", Duration: "24h"})
	if err != nil || serviceToken.ID == "" || serviceToken.ClientSecret == "" {
		t.Fatalf("CreateServiceToken returned id=%q secretPresent=%t err=%v", serviceToken.ID, serviceToken.ClientSecret != "", err)
	}
	originalSecret := serviceToken.ClientSecret
	rotated, err := api.RotateServiceToken(ctx, serviceToken.ID, time.Now().UTC().Add(time.Hour))
	if err != nil || rotated.ClientSecret == "" || rotated.ClientSecret == originalSecret {
		t.Fatalf("RotateServiceToken returned id=%q secretPresent=%t secretChanged=%t err=%v", rotated.ID, rotated.ClientSecret != "", rotated.ClientSecret != originalSecret, err)
	}
	serviceToken.ClientSecret = ""
	rotated.ClientSecret = ""
	refreshed, err := api.RefreshServiceToken(ctx, serviceToken.ID)
	if err != nil || refreshed.ExpiresAt.IsZero() {
		t.Fatalf("RefreshServiceToken = %#v, %v", refreshed, err)
	}

	group, err := api.CreateAccessGroup(ctx, flarecloudflare.AccessGroupInput{
		Name: "developers", Include: []flarecloudflare.ResolvedAccessRule{{Kind: "emailDomain", Value: "example.com"}},
	})
	if err != nil || group.ID == "" {
		t.Fatalf("CreateAccessGroup = %#v, %v", group, err)
	}
	idp, err := api.CreateIdentityProvider(ctx, flarecloudflare.IdentityProviderInput{
		Name: "Google", Type: flarev1alpha1.IdentityProviderType("google"),
		Config: flarev1alpha1.IdentityProviderConfig{ClientID: "client-id"}, ClientSecret: "client-secret",
	})
	if err != nil || idp.ID == "" || idp.Type != "google" {
		t.Fatalf("CreateIdentityProvider = %#v, %v", idp, err)
	}
	posture, err := api.CreateDevicePostureRule(ctx, flarecloudflare.DevicePostureRuleInput{
		Name: "WARP", Type: flarev1alpha1.DevicePostureRuleType("warp"),
	})
	if err != nil || posture.ID == "" || posture.Type != "warp" {
		t.Fatalf("CreateDevicePostureRule = %#v, %v", posture, err)
	}
	policy, err := api.CreateAccessPolicy(ctx, flarecloudflare.AccessPolicyInput{
		Name: "service-auth", Decision: "nonIdentity",
		Include: []flarecloudflare.ResolvedAccessRule{{Kind: "serviceToken", ID: serviceToken.ID}},
	})
	if err != nil || policy.ID == "" || policy.Decision != "non_identity" {
		t.Fatalf("CreateAccessPolicy = %#v, %v", policy, err)
	}
	bypass, err := api.EnsureBypassPolicy(ctx, "bypass-everyone")
	if err != nil || bypass.ID == "" || bypass.Decision != "bypass" {
		t.Fatalf("EnsureBypassPolicy = %#v, %v", bypass, err)
	}

	tag, err := api.CreateAccessTag(ctx, "flareway-managed")
	if err != nil || tag.Name != "flareway-managed" {
		t.Fatalf("CreateAccessTag = %#v, %v", tag, err)
	}
	fetchedTag, err := api.GetAccessTag(ctx, tag.Name)
	if err != nil || fetchedTag != tag {
		t.Fatalf("GetAccessTag = %#v, %v", fetchedTag, err)
	}

	application, err := api.CreateAccessApplication(ctx, flarecloudflare.AccessApplicationInput{
		Domain: "protected.example.com", Name: "protected",
		Destinations: []flarecloudflare.AccessApplicationDestination{{Type: "public", URI: "protected.example.com"}},
		Policies: []flarecloudflare.AccessApplicationPolicyAttachment{
			{ID: policy.ID, Precedence: 1}, {ID: bypass.ID, Precedence: 2},
		},
		SessionDuration: "24h", Tags: []string{tag.Name},
	})
	if err != nil || application.ID == "" || application.AUD == "" || application.Domain != "protected.example.com" {
		t.Fatalf("CreateAccessApplication = %#v, %v", application, err)
	}
	applications, err := api.ListAccessApplications(ctx)
	if err != nil || len(applications) != 1 || applications[0].ID != application.ID {
		t.Fatalf("ListAccessApplications = %#v, %v", applications, err)
	}
	if err := api.DeleteAccessApplication(ctx, application.ID); err != nil {
		t.Fatalf("delete application: %v", err)
	}
	if err := api.DeleteAccessTag(ctx, tag.Name); err != nil {
		t.Fatalf("DeleteAccessTag: %v", err)
	}

	for label, deleteFn := range map[string]func() error{
		"policy":  func() error { return api.DeleteAccessPolicy(ctx, policy.ID) },
		"bypass":  func() error { return api.DeleteAccessPolicy(ctx, bypass.ID) },
		"group":   func() error { return api.DeleteAccessGroup(ctx, group.ID) },
		"idp":     func() error { return api.DeleteIdentityProvider(ctx, idp.ID) },
		"posture": func() error { return api.DeleteDevicePostureRule(ctx, posture.ID) },
		"token":   func() error { return api.DeleteServiceToken(ctx, serviceToken.ID) },
	} {
		if err := deleteFn(); err != nil {
			t.Fatalf("delete %s: %v", label, err)
		}
	}
}
