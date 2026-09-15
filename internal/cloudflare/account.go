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

package cloudflare

import (
	"context"
	"fmt"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/user"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"github.com/cloudflare/cloudflare-go/v7/zones"
)

// AccountAPI is the read-only account verification surface.
type AccountAPI interface {
	VerifyToken(ctx context.Context) (TokenVerification, error)
	ListZones(ctx context.Context) ([]Zone, error)
	GetOrganization(ctx context.Context) (Organization, error)
}

// TokenVerification is the non-secret result of user/tokens/verify.
type TokenVerification struct {
	ID     string
	Status string
}

// Active reports whether Cloudflare considers the token usable.
func (verification TokenVerification) Active() bool {
	return verification.Status == string(user.TokenVerifyResponseStatusActive)
}

// Zone is the account and DNS-zone metadata needed by reconcilers.
type Zone struct {
	ID          string
	Name        string
	AccountID   string
	AccountName string
}

// Organization is the non-secret Zero Trust organization state returned by Cloudflare.
type Organization struct {
	Name                                   string
	AuthDomain                             string
	SessionDuration                        string
	WARPAuthSessionDuration                string
	AllowAuthenticateViaWARP               bool
	AutoRedirectToIdentity                 bool
	IsUIReadOnly                           bool
	UIReadOnlyToggleReason                 string
	DenyUnmatchedRequests                  bool
	DenyUnmatchedRequestsExemptedZoneNames []string
	WARPAuthNonBrowser401                  bool
	UserSeatExpirationInactiveTime         string
	CustomPages                            OrganizationCustomPages
	LoginDesign                            OrganizationLoginDesign
	MFAConfig                              OrganizationMFAConfig
	MFAPIVKeyRequirements                  OrganizationMFAPIVKeyRequirements
	MFARequiredForAllApps                  bool
}

// VerifyToken verifies the configured API token without returning its value.
func (client *Client) VerifyToken(ctx context.Context) (TokenVerification, error) {
	result, err := client.sdk.User.Tokens.Verify(ctx)
	if err != nil {
		return TokenVerification{}, fmt.Errorf("verify Cloudflare API token: %w", err)
	}
	return TokenVerification{ID: result.ID, Status: string(result.Status)}, nil
}

// ListZones returns every zone belonging to the configured account.
func (client *Client) ListZones(ctx context.Context) ([]Zone, error) {
	pager := client.sdk.Zones.ListAutoPaging(ctx, zones.ZoneListParams{
		Account: cloudflaresdk.F(zones.ZoneListParamsAccount{ID: cloudflaresdk.F(client.accountID)}),
		PerPage: cloudflaresdk.F(50.0),
	})

	result := make([]Zone, 0)
	for pager.Next() {
		zone := pager.Current()
		result = append(result, Zone{
			ID:          zone.ID,
			Name:        zone.Name,
			AccountID:   zone.Account.ID,
			AccountName: zone.Account.Name,
		})
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare zones: %w", err)
	}
	return result, nil
}

// GetOrganization returns the Zero Trust organization for the configured account.
func (client *Client) GetOrganization(ctx context.Context) (Organization, error) {
	result, err := client.sdk.ZeroTrust.Organizations.List(ctx, zero_trust.OrganizationListParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return Organization{}, fmt.Errorf("get Cloudflare Zero Trust organization: %w", err)
	}
	return organizationFromSDK(result), nil
}
