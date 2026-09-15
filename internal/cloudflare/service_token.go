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
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// ServiceTokenAPI is part of the Flareway API.
type ServiceTokenAPI interface {
	CreateServiceToken(context.Context, AccessScope, ServiceTokenInput) (ServiceTokenSecret, error)
	UpdateServiceToken(context.Context, AccessScope, string, ServiceTokenInput) (ServiceToken, error)
	GetServiceToken(context.Context, AccessScope, string) (ServiceToken, error)
	ListServiceTokens(context.Context, AccessScope) ([]ServiceToken, error)
	DeleteServiceToken(context.Context, AccessScope, string) error
	RotateServiceToken(context.Context, string, time.Time) (ServiceTokenSecret, error)
	RefreshServiceToken(context.Context, string) (ServiceToken, error)
}

// ServiceTokenInput is part of the Flareway API.
type ServiceTokenInput struct {
	Name     string
	Duration string
	Enabled  bool
}

// ServiceToken is part of the Flareway API.
type ServiceToken struct {
	ID        string
	ClientID  string
	Name      string
	Duration  string
	Enabled   bool
	ExpiresAt time.Time
}

// ServiceTokenSecret is part of the Flareway API.
type ServiceTokenSecret struct {
	ServiceToken
	ClientSecret string
}

// CreateServiceToken is part of the Flareway API.
func (client *Client) CreateServiceToken(ctx context.Context, scope AccessScope, input ServiceTokenInput) (ServiceTokenSecret, error) {
	params := zero_trust.AccessServiceTokenNewParams{
		Name:    cloudflaresdk.F(input.Name),
		Enabled: cloudflaresdk.F(input.Enabled),
	}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	if input.Duration != "" {
		params.Duration = cloudflaresdk.F(input.Duration)
	}
	result, err := client.sdk.ZeroTrust.Access.ServiceTokens.New(ctx, params)
	if err != nil {
		return ServiceTokenSecret{}, fmt.Errorf("create Access service token: %w", err)
	}
	return ServiceTokenSecret{ServiceToken: ServiceToken{ID: result.ID, ClientID: result.ClientID, Name: result.Name, Duration: result.Duration, Enabled: result.Enabled}, ClientSecret: result.ClientSecret}, nil
}

// UpdateServiceToken is part of the Flareway API.
func (client *Client) UpdateServiceToken(ctx context.Context, scope AccessScope, id string, input ServiceTokenInput) (ServiceToken, error) {
	params := zero_trust.AccessServiceTokenUpdateParams{Enabled: cloudflaresdk.F(input.Enabled)}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	if input.Name != "" {
		params.Name = cloudflaresdk.F(input.Name)
	}
	if input.Duration != "" {
		params.Duration = cloudflaresdk.F(input.Duration)
	}
	result, err := client.sdk.ZeroTrust.Access.ServiceTokens.Update(ctx, id, params)
	if err != nil {
		return ServiceToken{}, fmt.Errorf("update Access service token: %w", err)
	}
	return serviceTokenFromSDK(result), nil
}

// GetServiceToken is part of the Flareway API.
func (client *Client) GetServiceToken(ctx context.Context, scope AccessScope, id string) (ServiceToken, error) {
	params := zero_trust.AccessServiceTokenGetParams{}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	result, err := client.sdk.ZeroTrust.Access.ServiceTokens.Get(ctx, id, params)
	if err != nil {
		return ServiceToken{}, fmt.Errorf("get Access service token: %w", err)
	}
	return serviceTokenFromSDK(result), nil
}

// ListServiceTokens is part of the Flareway API.
func (client *Client) ListServiceTokens(ctx context.Context, scope AccessScope) ([]ServiceToken, error) {
	params := zero_trust.AccessServiceTokenListParams{}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	pager := client.sdk.ZeroTrust.Access.ServiceTokens.ListAutoPaging(ctx, params)
	var result []ServiceToken
	for pager.Next() {
		value := pager.Current()
		result = append(result, serviceTokenFromSDK(&value))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Access service tokens: %w", err)
	}
	return result, nil
}

// DeleteServiceToken is part of the Flareway API.
func (client *Client) DeleteServiceToken(ctx context.Context, scope AccessScope, id string) error {
	params := zero_trust.AccessServiceTokenDeleteParams{}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	_, err := client.sdk.ZeroTrust.Access.ServiceTokens.Delete(ctx, id, params)
	if err != nil {
		return fmt.Errorf("delete Access service token: %w", err)
	}
	return nil
}

// RotateServiceToken is part of the Flareway API.
func (client *Client) RotateServiceToken(ctx context.Context, id string, previousSecretExpiresAt time.Time) (ServiceTokenSecret, error) {
	result, err := client.sdk.ZeroTrust.Access.ServiceTokens.Rotate(ctx, id, zero_trust.AccessServiceTokenRotateParams{
		AccountID:                     cloudflaresdk.F(client.accountID),
		PreviousClientSecretExpiresAt: cloudflaresdk.F(previousSecretExpiresAt),
	})
	if err != nil {
		return ServiceTokenSecret{}, fmt.Errorf("rotate Access service token: %w", err)
	}
	return ServiceTokenSecret{ServiceToken: ServiceToken{ID: result.ID, ClientID: result.ClientID, Name: result.Name, Duration: result.Duration, Enabled: result.Enabled}, ClientSecret: result.ClientSecret}, nil
}

// RefreshServiceToken is part of the Flareway API.
func (client *Client) RefreshServiceToken(ctx context.Context, id string) (ServiceToken, error) {
	result, err := client.sdk.ZeroTrust.Access.ServiceTokens.Refresh(ctx, id, zero_trust.AccessServiceTokenRefreshParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return ServiceToken{}, fmt.Errorf("refresh Access service token: %w", err)
	}
	return serviceTokenFromSDK(result), nil
}

func serviceTokenFromSDK(value *zero_trust.ServiceToken) ServiceToken {
	return ServiceToken{ID: value.ID, ClientID: value.ClientID, Name: value.Name, Duration: value.Duration, Enabled: value.Enabled, ExpiresAt: value.ExpiresAt}
}
