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
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// OrganizationAPI reads and updates the account Zero Trust organization.
type OrganizationAPI interface {
	GetOrganization(context.Context) (Organization, error)
	UpdateOrganization(context.Context, OrganizationInput) (Organization, error)
}

// OrganizationInput preserves optional update semantics for organization fields.
type OrganizationInput struct {
	SessionDuration          *string
	WARPAuthSessionDuration  *string
	AllowAuthenticateViaWARP *bool
	IsUIReadOnly             *bool
	DenyUnmatchedRequests    *bool
	WARPAuthNonBrowser401    *bool
}

// UpdateOrganization is part of the Cloudflare adapter API.
func (client *Client) UpdateOrganization(ctx context.Context, input OrganizationInput) (Organization, error) {
	params := zero_trust.OrganizationUpdateParams{AccountID: cloudflaresdk.F(client.accountID)}
	if input.SessionDuration != nil {
		params.SessionDuration = cloudflaresdk.F(*input.SessionDuration)
	}
	if input.WARPAuthSessionDuration != nil {
		params.WARPAuthSessionDuration = cloudflaresdk.F(*input.WARPAuthSessionDuration)
	}
	if input.AllowAuthenticateViaWARP != nil {
		params.AllowAuthenticateViaWARP = cloudflaresdk.F(*input.AllowAuthenticateViaWARP)
	}
	if input.IsUIReadOnly != nil {
		params.IsUIReadOnly = cloudflaresdk.F(*input.IsUIReadOnly)
	}
	if input.DenyUnmatchedRequests != nil {
		params.DenyUnmatchedRequests = cloudflaresdk.F(*input.DenyUnmatchedRequests)
	}
	if input.WARPAuthNonBrowser401 != nil {
		params.WARPAuthNonBrowser401 = cloudflaresdk.F(*input.WARPAuthNonBrowser401)
	}
	remote, err := client.sdk.ZeroTrust.Organizations.Update(ctx, params)
	if err != nil {
		return Organization{}, fmt.Errorf("update Cloudflare Zero Trust organization: %w", err)
	}
	return organizationFromSDK(remote), nil
}

func organizationFromSDK(remote *zero_trust.Organization) Organization {
	return Organization{
		AuthDomain:               remote.AuthDomain,
		Name:                     remote.Name,
		SessionDuration:          remote.SessionDuration,
		WARPAuthSessionDuration:  remote.WARPAuthSessionDuration,
		AllowAuthenticateViaWARP: remote.AllowAuthenticateViaWARP,
		IsUIReadOnly:             remote.IsUIReadOnly,
		DenyUnmatchedRequests:    remote.DenyUnmatchedRequests,
		WARPAuthNonBrowser401:    remote.WARPAuthNonBrowser401,
	}
}
