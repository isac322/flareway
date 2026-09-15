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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// IdentityProviderAPI is part of the Flareway API.
type IdentityProviderAPI interface {
	CreateIdentityProvider(context.Context, IdentityProviderInput) (IdentityProvider, error)
	UpdateIdentityProvider(context.Context, string, IdentityProviderInput) (IdentityProvider, error)
	GetIdentityProvider(context.Context, string) (IdentityProvider, error)
	ListIdentityProviders(context.Context) ([]IdentityProvider, error)
	DeleteIdentityProvider(context.Context, string) error
	CreateIdentityProviderSAMLCertificate(context.Context, string) (IdentityProviderSAMLCertificateSet, error)
	ListIdentityProviderSCIMUsers(context.Context, string, int64) ([]IdentityProviderSCIMUser, bool, error)
	ListIdentityProviderSCIMGroups(context.Context, string, int64) ([]IdentityProviderSCIMGroup, bool, error)
}

// IdentityProviderInput is part of the Flareway API.
type IdentityProviderInput struct {
	Name                 string
	Type                 v1alpha1.IdentityProviderType
	Config               v1alpha1.IdentityProviderConfig
	SCIMConfig           *v1alpha1.IdentityProviderSCIMConfig
	ClientSecret         string
	SAMLCertificateSetID string
}

// IdentityProvider is part of the Flareway API.
type IdentityProvider struct {
	ID                   string
	Name                 string
	Type                 v1alpha1.IdentityProviderType
	Config               v1alpha1.IdentityProviderConfig
	RedirectURL          string
	SCIMConfig           *v1alpha1.IdentityProviderSCIMConfig
	SCIMBaseURL          string
	SCIMSecret           string
	SAMLCertificateSetID string
	SAMLCertificateSet   *IdentityProviderSAMLCertificateSet
	ReadOnly             bool
}

// IdentityProviderSAMLCertificateSet is a public SAML encryption certificate observation.
type IdentityProviderSAMLCertificateSet struct {
	ID        string
	CreatedAt time.Time
	UpdatedAt time.Time
	Current   *IdentityProviderSAMLCertificate
	Previous  *IdentityProviderSAMLCertificate
}

// IdentityProviderSAMLCertificate is one public SAML encryption certificate.
type IdentityProviderSAMLCertificate struct {
	ID                string
	Current           bool
	NotAfter          time.Time
	PublicCertificate string
}

// IdentityProviderSCIMUser is a credential-free SCIM user summary.
type IdentityProviderSCIMUser struct {
	ID          string
	ExternalID  string
	DisplayName string
	Active      bool
	Emails      []string
}

// IdentityProviderSCIMGroup is a credential-free SCIM group summary.
type IdentityProviderSCIMGroup struct {
	ID          string
	ExternalID  string
	DisplayName string
}

// CreateIdentityProvider is part of the Flareway API.
func (client *Client) CreateIdentityProvider(ctx context.Context, input IdentityProviderInput) (IdentityProvider, error) {
	body, err := identityProviderBody(input)
	if err != nil {
		return IdentityProvider{}, err
	}
	result, err := client.sdk.ZeroTrust.IdentityProviders.New(ctx, zero_trust.IdentityProviderNewParams{
		AccountID:        cloudflaresdk.F(client.accountID),
		IdentityProvider: body,
	})
	if err != nil {
		return IdentityProvider{}, fmt.Errorf("create Access identity provider: %w", err)
	}
	provider, err := identityProviderFromSDK(result)
	if err != nil {
		return IdentityProvider{}, fmt.Errorf("decode created Access identity provider: %w", err)
	}
	return provider, nil
}

// UpdateIdentityProvider is part of the Flareway API.
func (client *Client) UpdateIdentityProvider(ctx context.Context, id string, input IdentityProviderInput) (IdentityProvider, error) {
	body, err := identityProviderBody(input)
	if err != nil {
		return IdentityProvider{}, err
	}
	result, err := client.sdk.ZeroTrust.IdentityProviders.Update(ctx, id, zero_trust.IdentityProviderUpdateParams{
		AccountID:        cloudflaresdk.F(client.accountID),
		IdentityProvider: body,
	})
	if err != nil {
		return IdentityProvider{}, fmt.Errorf("update Access identity provider: %w", err)
	}
	provider, err := identityProviderFromSDK(result)
	if err != nil {
		return IdentityProvider{}, fmt.Errorf("decode updated Access identity provider: %w", err)
	}
	return provider, nil
}

// GetIdentityProvider is part of the Flareway API.
func (client *Client) GetIdentityProvider(ctx context.Context, id string) (IdentityProvider, error) {
	result, err := client.sdk.ZeroTrust.IdentityProviders.Get(ctx, id, zero_trust.IdentityProviderGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return IdentityProvider{}, fmt.Errorf("get Access identity provider: %w", err)
	}
	provider, err := identityProviderFromSDK(result)
	if err != nil {
		return IdentityProvider{}, fmt.Errorf("decode Access identity provider: %w", err)
	}
	return provider, nil
}

// ListIdentityProviders is part of the Flareway API.
func (client *Client) ListIdentityProviders(ctx context.Context) ([]IdentityProvider, error) {
	const perPage int64 = 1000
	result := make([]IdentityProvider, 0)
	for page := int64(1); page <= 1000; page++ {
		response, err := client.sdk.ZeroTrust.IdentityProviders.List(ctx, zero_trust.IdentityProviderListParams{
			AccountID: cloudflaresdk.F(client.accountID),
			Page:      cloudflaresdk.F(page),
			PerPage:   cloudflaresdk.F(perPage),
		})
		if err != nil {
			return nil, fmt.Errorf("list Access identity providers: %w", err)
		}
		for index := range response.Result {
			value := response.Result[index]
			provider, decodeErr := identityProviderFromListSDK(&value)
			if decodeErr != nil {
				return nil, fmt.Errorf("decode listed Access identity provider %q: %w", value.ID, decodeErr)
			}
			result = append(result, provider)
		}
		if len(response.Result) < int(perPage) {
			return result, nil
		}
	}
	return nil, errors.New("access identity provider pagination exceeded 1000 pages")
}

// DeleteIdentityProvider is part of the Flareway API.
func (client *Client) DeleteIdentityProvider(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.IdentityProviders.Delete(ctx, id, zero_trust.IdentityProviderDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Access identity provider: %w", err)
	}
	return nil
}

// CreateIdentityProviderSAMLCertificate creates or returns the assigned certificate set.
func (client *Client) CreateIdentityProviderSAMLCertificate(ctx context.Context, id string) (IdentityProviderSAMLCertificateSet, error) {
	result, err := client.sdk.ZeroTrust.IdentityProviders.SAMLCertificate.New(ctx, id, zero_trust.IdentityProviderSAMLCertificateNewParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return IdentityProviderSAMLCertificateSet{}, fmt.Errorf("create Access identity provider SAML certificate: %w", err)
	}
	certificate := IdentityProviderSAMLCertificateSet{
		ID:        result.UID,
		CreatedAt: result.CreatedAt,
		UpdatedAt: result.UpdatedAt,
		Current: &IdentityProviderSAMLCertificate{
			ID:                result.CurrentCertificate.UID,
			Current:           result.CurrentCertificate.IsCurrent,
			NotAfter:          result.CurrentCertificate.NotAfter,
			PublicCertificate: result.CurrentCertificate.PublicCertificate,
		},
	}
	certificate.Previous = identityProviderCertificateFromAny(result.PreviousCertificate)
	return certificate, nil
}

// ListIdentityProviderSCIMUsers reads one bounded page of SCIM users.
func (client *Client) ListIdentityProviderSCIMUsers(ctx context.Context, id string, limit int64) ([]IdentityProviderSCIMUser, bool, error) {
	if limit <= 0 || limit > 50 {
		limit = 50
	}
	page, err := client.sdk.ZeroTrust.IdentityProviders.SCIM.Users.List(ctx, id, zero_trust.IdentityProviderSCIMUserListParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Page:      cloudflaresdk.F(int64(1)),
		PerPage:   cloudflaresdk.F(limit),
	})
	if err != nil {
		return nil, false, fmt.Errorf("list Access identity provider SCIM users: %w", err)
	}
	truncated := int64(len(page.Result)) >= limit
	values := page.Result
	if int64(len(values)) > limit {
		values = values[:limit]
	}
	result := make([]IdentityProviderSCIMUser, 0, len(values))
	for _, value := range values {
		emails := make([]string, 0, min(len(value.Emails), 10))
		for _, email := range value.Emails {
			if email.Value != "" {
				emails = append(emails, email.Value)
				if len(emails) == 10 {
					break
				}
			}
		}
		sort.Strings(emails)
		result = append(result, IdentityProviderSCIMUser{ID: value.ID, ExternalID: value.ExternalID, DisplayName: value.DisplayName, Active: value.Active, Emails: emails})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, truncated, nil
}

// ListIdentityProviderSCIMGroups reads one bounded page of SCIM groups.
func (client *Client) ListIdentityProviderSCIMGroups(ctx context.Context, id string, limit int64) ([]IdentityProviderSCIMGroup, bool, error) {
	if limit <= 0 || limit > 50 {
		limit = 50
	}
	page, err := client.sdk.ZeroTrust.IdentityProviders.SCIM.Groups.List(ctx, id, zero_trust.IdentityProviderSCIMGroupListParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Page:      cloudflaresdk.F(int64(1)),
		PerPage:   cloudflaresdk.F(limit),
	})
	if err != nil {
		return nil, false, fmt.Errorf("list Access identity provider SCIM groups: %w", err)
	}
	truncated := int64(len(page.Result)) >= limit
	values := page.Result
	if int64(len(values)) > limit {
		values = values[:limit]
	}
	result := make([]IdentityProviderSCIMGroup, 0, len(values))
	for _, value := range values {
		result = append(result, IdentityProviderSCIMGroup{ID: value.ID, ExternalID: value.ExternalID, DisplayName: value.DisplayName})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, truncated, nil
}

func identityProviderFromSDK(value *zero_trust.IdentityProvider) (IdentityProvider, error) {
	return identityProviderFromValues(value.ID, value.Name, value.Type, value.JSON.RawJSON(), value.ReadOnly, value.SAMLCertificateSetID, value.SAMLCertificateSet, value.SCIMConfig)
}

func identityProviderFromListSDK(value *zero_trust.IdentityProviderListResponse) (IdentityProvider, error) {
	return identityProviderFromValues(value.ID, value.Name, value.Type, value.JSON.RawJSON(), value.ReadOnly, value.SAMLCertificateSetID, value.SAMLCertificateSet, value.SCIMConfig)
}

func identityProviderFromValues(id, name string, providerType zero_trust.IdentityProviderType, raw string, readOnly bool, certificateSetID string, certificateSet any, scim zero_trust.IdentityProviderSCIMConfig) (IdentityProvider, error) {
	config, redirectURL, err := identityProviderObservationFromRaw(providerType, raw)
	if err != nil {
		return IdentityProvider{}, err
	}
	result := IdentityProvider{
		ID:                   id,
		Name:                 name,
		Type:                 identityProviderTypeFromSDK(providerType),
		Config:               config,
		RedirectURL:          redirectURL,
		ReadOnly:             readOnly,
		SAMLCertificateSetID: certificateSetID,
		SCIMConfig:           identityProviderSCIMFromSDK(scim),
		SCIMBaseURL:          scim.SCIMBaseURL,
		SCIMSecret:           scim.Secret,
	}
	result.SAMLCertificateSet = identityProviderCertificateSetFromAny(certificateSetID, certificateSet)
	return result, nil
}

type identityProviderWireConfig struct {
	ClientID                 string                                    `json:"client_id"`
	Claims                   []string                                  `json:"claims"`
	EmailClaimName           string                                    `json:"email_claim_name"`
	DirectoryID              string                                    `json:"directory_id"`
	ConditionalAccessEnabled *bool                                     `json:"conditional_access_enabled"`
	SupportGroups            *bool                                     `json:"support_groups"`
	Prompt                   string                                    `json:"prompt"`
	AppsDomain               string                                    `json:"apps_domain"`
	CentrifyAccount          string                                    `json:"centrify_account"`
	CentrifyAppID            string                                    `json:"centrify_app_id"`
	AuthorizationServerID    string                                    `json:"authorization_server_id"`
	OktaAccount              string                                    `json:"okta_account"`
	OneloginAccount          string                                    `json:"onelogin_account"`
	PingEnvironmentID        string                                    `json:"ping_env_id"`
	AuthURL                  string                                    `json:"auth_url"`
	CertsURL                 string                                    `json:"certs_url"`
	TokenURL                 string                                    `json:"token_url"`
	PKCEEnabled              *bool                                     `json:"pkce_enabled"`
	Scopes                   []string                                  `json:"scopes"`
	Attributes               []string                                  `json:"attributes"`
	EmailAttributeName       string                                    `json:"email_attribute_name"`
	EnableEncryption         *bool                                     `json:"enable_encryption"`
	ForceAuthn               *bool                                     `json:"force_authn"`
	HeaderAttributes         []identityProviderWireSAMLHeaderAttribute `json:"header_attributes"`
	IDPPublicCerts           []string                                  `json:"idp_public_certs"`
	IssuerURL                string                                    `json:"issuer_url"`
	MaxSSOURLLength          *int64                                    `json:"max_sso_url_length"`
	RedirectURL              string                                    `json:"redirect_url"`
	SignRequest              *bool                                     `json:"sign_request"`
	SSOTargetURL             string                                    `json:"sso_target_url"`
	RestrictToAccountMembers *bool                                     `json:"restrict_to_account_members"`
}

type identityProviderWireSAMLHeaderAttribute struct {
	HeaderName    string `json:"header_name"`
	AttributeName string `json:"attribute_name"`
}

func identityProviderObservationFromRaw(providerType zero_trust.IdentityProviderType, raw string) (v1alpha1.IdentityProviderConfig, string, error) {
	if !providerType.IsKnown() {
		return v1alpha1.IdentityProviderConfig{}, "", fmt.Errorf("unsupported identity provider type %q", providerType)
	}
	if raw == "" {
		return v1alpha1.IdentityProviderConfig{}, "", fmt.Errorf("%s identity provider raw response is empty", providerType)
	}
	var response struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		return v1alpha1.IdentityProviderConfig{}, "", fmt.Errorf("decode %s identity provider raw response: %w", providerType, err)
	}
	configJSON := bytes.TrimSpace(response.Config)
	if len(configJSON) == 0 {
		return v1alpha1.IdentityProviderConfig{}, "", fmt.Errorf("%s identity provider config is missing", providerType)
	}
	if bytes.Equal(configJSON, []byte("null")) {
		return v1alpha1.IdentityProviderConfig{}, "", fmt.Errorf("%s identity provider config is null", providerType)
	}
	var wire identityProviderWireConfig
	if err := json.Unmarshal(configJSON, &wire); err != nil {
		return v1alpha1.IdentityProviderConfig{}, "", fmt.Errorf("decode %s identity provider config: %w", providerType, err)
	}
	config := v1alpha1.IdentityProviderConfig{
		ClientID:                 wire.ClientID,
		Claims:                   append([]string(nil), wire.Claims...),
		EmailClaimName:           wire.EmailClaimName,
		DirectoryID:              wire.DirectoryID,
		ConditionalAccessEnabled: wire.ConditionalAccessEnabled,
		SupportGroups:            wire.SupportGroups,
		Prompt:                   identityProviderPromptFromSDK(wire.Prompt),
		AppsDomain:               wire.AppsDomain,
		CentrifyAccount:          wire.CentrifyAccount,
		CentrifyAppID:            wire.CentrifyAppID,
		AuthorizationServerID:    wire.AuthorizationServerID,
		OktaAccount:              wire.OktaAccount,
		OneloginAccount:          wire.OneloginAccount,
		PingEnvironmentID:        wire.PingEnvironmentID,
		AuthURL:                  wire.AuthURL,
		CertsURL:                 wire.CertsURL,
		TokenURL:                 wire.TokenURL,
		PKCEEnabled:              wire.PKCEEnabled,
		Scopes:                   append([]string(nil), wire.Scopes...),
		Attributes:               append([]string(nil), wire.Attributes...),
		EmailAttributeName:       wire.EmailAttributeName,
		EnableEncryption:         wire.EnableEncryption,
		ForceAuthn:               wire.ForceAuthn,
		IDPPublicCerts:           append([]string(nil), wire.IDPPublicCerts...),
		IssuerURL:                wire.IssuerURL,
		MaxSSOURLLength:          wire.MaxSSOURLLength,
		SignRequest:              wire.SignRequest,
		SSOTargetURL:             wire.SSOTargetURL,
		RestrictToAccountMembers: wire.RestrictToAccountMembers,
	}
	for _, header := range wire.HeaderAttributes {
		config.HeaderAttributes = append(config.HeaderAttributes, v1alpha1.IdentityProviderSAMLHeaderAttribute{Name: header.HeaderName, AttributeName: header.AttributeName})
	}
	switch providerType {
	case zero_trust.IdentityProviderTypeOnetimepin, zero_trust.IdentityProviderTypeCloudflare:
		return config, wire.RedirectURL, nil
	default:
		return config, "", nil
	}
}

func identityProviderSCIMFromSDK(value zero_trust.IdentityProviderSCIMConfig) *v1alpha1.IdentityProviderSCIMConfig {
	if value.JSON.Enabled.IsMissing() && value.JSON.IdentityUpdateBehavior.IsMissing() && value.JSON.SeatDeprovision.IsMissing() && value.JSON.UserDeprovision.IsMissing() {
		return nil
	}
	result := &v1alpha1.IdentityProviderSCIMConfig{IdentityUpdateBehavior: identityProviderSCIMBehaviorFromSDK(value.IdentityUpdateBehavior)}
	if !value.JSON.Enabled.IsMissing() {
		enabled := value.Enabled
		result.Enabled = &enabled
	}
	if !value.JSON.SeatDeprovision.IsMissing() {
		seatDeprovision := value.SeatDeprovision
		result.SeatDeprovision = &seatDeprovision
	}
	if !value.JSON.UserDeprovision.IsMissing() {
		userDeprovision := value.UserDeprovision
		result.UserDeprovision = &userDeprovision
	}
	return result
}

type identityProviderWireCertificateSet struct {
	UID                 string                           `json:"uid"`
	CreatedAt           time.Time                        `json:"created_at"`
	UpdatedAt           time.Time                        `json:"updated_at"`
	CurrentCertificate  *identityProviderWireCertificate `json:"current_certificate"`
	PreviousCertificate *identityProviderWireCertificate `json:"previous_certificate"`
}

type identityProviderWireCertificate struct {
	UID               string    `json:"uid"`
	IsCurrent         bool      `json:"is_current"`
	NotAfter          time.Time `json:"not_after"`
	PublicCertificate string    `json:"public_certificate"`
}

func identityProviderCertificateSetFromAny(id string, value any) *IdentityProviderSAMLCertificateSet {
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var wire identityProviderWireCertificateSet
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil
	}
	if id == "" {
		id = wire.UID
	}
	if id == "" {
		return nil
	}
	return &IdentityProviderSAMLCertificateSet{
		ID:        id,
		CreatedAt: wire.CreatedAt,
		UpdatedAt: wire.UpdatedAt,
		Current:   identityProviderCertificateFromWire(wire.CurrentCertificate),
		Previous:  identityProviderCertificateFromWire(wire.PreviousCertificate),
	}
}

func identityProviderCertificateFromAny(value any) *IdentityProviderSAMLCertificate {
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var wire identityProviderWireCertificate
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil
	}
	return identityProviderCertificateFromWire(&wire)
}

func identityProviderCertificateFromWire(value *identityProviderWireCertificate) *IdentityProviderSAMLCertificate {
	if value == nil || value.UID == "" {
		return nil
	}
	return &IdentityProviderSAMLCertificate{ID: value.UID, Current: value.IsCurrent, NotAfter: value.NotAfter, PublicCertificate: value.PublicCertificate}
}

func identityProviderBody(input IdentityProviderInput) (zero_trust.IdentityProviderUnionParam, error) {
	providerType, err := identityProviderTypeToSDK(input.Type)
	if err != nil {
		return nil, err
	}
	scim, hasSCIM, err := identityProviderSCIM(input.SCIMConfig)
	if err != nil {
		return nil, err
	}
	config := input.Config
	switch input.Type {
	case v1alpha1.IdentityProviderTypeAzureAD:
		body := zero_trust.AzureADParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(identityProviderAzureADConfig(config, input.ClientSecret))}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeCentrify:
		body := zero_trust.IdentityProviderAccessCentrifyParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(identityProviderCentrifyConfig(config, input.ClientSecret))}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeGoogle:
		body := zero_trust.IdentityProviderAccessGoogleParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(identityProviderGoogleConfig(config, input.ClientSecret))}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeGoogleApps:
		googleConfig, configErr := identityProviderGoogleAppsConfig(config, input.ClientSecret)
		if configErr != nil {
			return nil, configErr
		}
		body := zero_trust.IdentityProviderAccessGoogleAppsParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(googleConfig)}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeOIDC:
		body := zero_trust.IdentityProviderAccessOIDCParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(identityProviderOIDCConfig(config, input.ClientSecret))}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeOkta:
		body := zero_trust.IdentityProviderAccessOktaParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(identityProviderOktaConfig(config, input.ClientSecret))}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeOneLogin:
		body := zero_trust.IdentityProviderAccessOneloginParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(identityProviderOneLoginConfig(config, input.ClientSecret))}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypePingOne:
		body := zero_trust.IdentityProviderAccessPingoneParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(identityProviderPingOneConfig(config, input.ClientSecret))}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeSAML:
		body := zero_trust.IdentityProviderAccessSAMLParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(identityProviderSAMLConfig(config))}
		if input.SAMLCertificateSetID != "" {
			body.SAMLCertificateSetID = cloudflaresdk.F(input.SAMLCertificateSetID)
		}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeOneTimePIN:
		body := zero_trust.IdentityProviderAccessOnetimepinParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessOnetimepinConfigParam{})}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeCloudflare:
		body := zero_trust.IdentityProviderAccessCloudflareParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(identityProviderCloudflareConfig(config))}
		if hasSCIM {
			body.SCIMConfig = cloudflaresdk.F(scim)
		}
		return body, nil
	case v1alpha1.IdentityProviderTypeFacebook, v1alpha1.IdentityProviderTypeGitHub, v1alpha1.IdentityProviderTypeLinkedIn, v1alpha1.IdentityProviderTypeYandex:
		generic := zero_trust.GenericOAuthConfigParam{}
		if config.ClientID != "" {
			generic.ClientID = cloudflaresdk.F(config.ClientID)
		}
		if input.ClientSecret != "" {
			generic.ClientSecret = cloudflaresdk.F(input.ClientSecret)
		}
		switch input.Type {
		case v1alpha1.IdentityProviderTypeFacebook:
			body := zero_trust.IdentityProviderAccessFacebookParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(generic)}
			if hasSCIM {
				body.SCIMConfig = cloudflaresdk.F(scim)
			}
			return body, nil
		case v1alpha1.IdentityProviderTypeGitHub:
			body := zero_trust.IdentityProviderAccessGitHubParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(generic)}
			if hasSCIM {
				body.SCIMConfig = cloudflaresdk.F(scim)
			}
			return body, nil
		case v1alpha1.IdentityProviderTypeLinkedIn:
			body := zero_trust.IdentityProviderAccessLinkedinParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(generic)}
			if hasSCIM {
				body.SCIMConfig = cloudflaresdk.F(scim)
			}
			return body, nil
		default:
			body := zero_trust.IdentityProviderAccessYandexParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(providerType), Config: cloudflaresdk.F(generic)}
			if hasSCIM {
				body.SCIMConfig = cloudflaresdk.F(scim)
			}
			return body, nil
		}
	default:
		return nil, fmt.Errorf("unsupported identity provider type %q", input.Type)
	}
}

func identityProviderAzureADConfig(config v1alpha1.IdentityProviderConfig, secret string) zero_trust.AzureADConfigParam {
	result := zero_trust.AzureADConfigParam{}
	if len(config.Claims) > 0 {
		result.Claims = cloudflaresdk.F(config.Claims)
	}
	if config.ClientID != "" {
		result.ClientID = cloudflaresdk.F(config.ClientID)
	}
	if secret != "" {
		result.ClientSecret = cloudflaresdk.F(secret)
	}
	if config.ConditionalAccessEnabled != nil {
		result.ConditionalAccessEnabled = cloudflaresdk.F(*config.ConditionalAccessEnabled)
	}
	if config.DirectoryID != "" {
		result.DirectoryID = cloudflaresdk.F(config.DirectoryID)
	}
	if config.EmailClaimName != "" {
		result.EmailClaimName = cloudflaresdk.F(config.EmailClaimName)
	}
	if config.Prompt != "" {
		result.Prompt = cloudflaresdk.F(zero_trust.AzureADConfigPrompt(identityProviderPromptToSDK(config.Prompt)))
	}
	if config.SupportGroups != nil {
		result.SupportGroups = cloudflaresdk.F(*config.SupportGroups)
	}
	return result
}

func identityProviderCentrifyConfig(config v1alpha1.IdentityProviderConfig, secret string) zero_trust.IdentityProviderAccessCentrifyConfigParam {
	result := zero_trust.IdentityProviderAccessCentrifyConfigParam{}
	if config.CentrifyAccount != "" {
		result.CentrifyAccount = cloudflaresdk.F(config.CentrifyAccount)
	}
	if config.CentrifyAppID != "" {
		result.CentrifyAppID = cloudflaresdk.F(config.CentrifyAppID)
	}
	if len(config.Claims) > 0 {
		result.Claims = cloudflaresdk.F(config.Claims)
	}
	if config.ClientID != "" {
		result.ClientID = cloudflaresdk.F(config.ClientID)
	}
	if secret != "" {
		result.ClientSecret = cloudflaresdk.F(secret)
	}
	if config.EmailClaimName != "" {
		result.EmailClaimName = cloudflaresdk.F(config.EmailClaimName)
	}
	return result
}

func identityProviderGoogleConfig(config v1alpha1.IdentityProviderConfig, secret string) zero_trust.IdentityProviderAccessGoogleConfigParam {
	result := zero_trust.IdentityProviderAccessGoogleConfigParam{}
	if len(config.Claims) > 0 {
		result.Claims = cloudflaresdk.F(config.Claims)
	}
	if config.ClientID != "" {
		result.ClientID = cloudflaresdk.F(config.ClientID)
	}
	if secret != "" {
		result.ClientSecret = cloudflaresdk.F(secret)
	}
	if config.EmailClaimName != "" {
		result.EmailClaimName = cloudflaresdk.F(config.EmailClaimName)
	}
	return result
}

func identityProviderGoogleAppsConfig(config v1alpha1.IdentityProviderConfig, secret string) (zero_trust.IdentityProviderAccessGoogleAppsConfigParam, error) {
	result := zero_trust.IdentityProviderAccessGoogleAppsConfigParam{}
	if config.AppsDomain != "" {
		result.AppsDomain = cloudflaresdk.F(config.AppsDomain)
	}
	if len(config.Claims) > 0 {
		result.Claims = cloudflaresdk.F(config.Claims)
	}
	if config.ClientID != "" {
		result.ClientID = cloudflaresdk.F(config.ClientID)
	}
	if secret != "" {
		result.ClientSecret = cloudflaresdk.F(secret)
	}
	if config.EmailClaimName != "" {
		result.EmailClaimName = cloudflaresdk.F(config.EmailClaimName)
	}
	if config.Prompt != "" {
		prompt, err := identityProviderGoogleAppsPromptToSDK(config.Prompt)
		if err != nil {
			return result, err
		}
		result.Prompt = cloudflaresdk.F(prompt)
	}
	return result, nil
}

func identityProviderOIDCConfig(config v1alpha1.IdentityProviderConfig, secret string) zero_trust.IdentityProviderAccessOIDCConfigParam {
	result := zero_trust.IdentityProviderAccessOIDCConfigParam{}
	if config.AuthURL != "" {
		result.AuthURL = cloudflaresdk.F(config.AuthURL)
	}
	if config.CertsURL != "" {
		result.CERTsURL = cloudflaresdk.F(config.CertsURL)
	}
	if len(config.Claims) > 0 {
		result.Claims = cloudflaresdk.F(config.Claims)
	}
	if config.ClientID != "" {
		result.ClientID = cloudflaresdk.F(config.ClientID)
	}
	if secret != "" {
		result.ClientSecret = cloudflaresdk.F(secret)
	}
	if config.EmailClaimName != "" {
		result.EmailClaimName = cloudflaresdk.F(config.EmailClaimName)
	}
	if config.PKCEEnabled != nil {
		result.PKCEEnabled = cloudflaresdk.F(*config.PKCEEnabled)
	}
	if len(config.Scopes) > 0 {
		result.Scopes = cloudflaresdk.F(config.Scopes)
	}
	if config.TokenURL != "" {
		result.TokenURL = cloudflaresdk.F(config.TokenURL)
	}
	return result
}

func identityProviderOktaConfig(config v1alpha1.IdentityProviderConfig, secret string) zero_trust.IdentityProviderAccessOktaConfigParam {
	result := zero_trust.IdentityProviderAccessOktaConfigParam{}
	if config.AuthorizationServerID != "" {
		result.AuthorizationServerID = cloudflaresdk.F(config.AuthorizationServerID)
	}
	if len(config.Claims) > 0 {
		result.Claims = cloudflaresdk.F(config.Claims)
	}
	if config.ClientID != "" {
		result.ClientID = cloudflaresdk.F(config.ClientID)
	}
	if secret != "" {
		result.ClientSecret = cloudflaresdk.F(secret)
	}
	if config.EmailClaimName != "" {
		result.EmailClaimName = cloudflaresdk.F(config.EmailClaimName)
	}
	if config.OktaAccount != "" {
		result.OktaAccount = cloudflaresdk.F(config.OktaAccount)
	}
	return result
}

func identityProviderOneLoginConfig(config v1alpha1.IdentityProviderConfig, secret string) zero_trust.IdentityProviderAccessOneloginConfigParam {
	result := zero_trust.IdentityProviderAccessOneloginConfigParam{}
	if len(config.Claims) > 0 {
		result.Claims = cloudflaresdk.F(config.Claims)
	}
	if config.ClientID != "" {
		result.ClientID = cloudflaresdk.F(config.ClientID)
	}
	if secret != "" {
		result.ClientSecret = cloudflaresdk.F(secret)
	}
	if config.EmailClaimName != "" {
		result.EmailClaimName = cloudflaresdk.F(config.EmailClaimName)
	}
	if config.OneloginAccount != "" {
		result.OneloginAccount = cloudflaresdk.F(config.OneloginAccount)
	}
	return result
}

func identityProviderPingOneConfig(config v1alpha1.IdentityProviderConfig, secret string) zero_trust.IdentityProviderAccessPingoneConfigParam {
	result := zero_trust.IdentityProviderAccessPingoneConfigParam{}
	if len(config.Claims) > 0 {
		result.Claims = cloudflaresdk.F(config.Claims)
	}
	if config.ClientID != "" {
		result.ClientID = cloudflaresdk.F(config.ClientID)
	}
	if secret != "" {
		result.ClientSecret = cloudflaresdk.F(secret)
	}
	if config.EmailClaimName != "" {
		result.EmailClaimName = cloudflaresdk.F(config.EmailClaimName)
	}
	if config.PingEnvironmentID != "" {
		result.PingEnvID = cloudflaresdk.F(config.PingEnvironmentID)
	}
	return result
}

func identityProviderSAMLConfig(config v1alpha1.IdentityProviderConfig) zero_trust.IdentityProviderAccessSAMLConfigParam {
	result := zero_trust.IdentityProviderAccessSAMLConfigParam{}
	if len(config.Attributes) > 0 {
		result.Attributes = cloudflaresdk.F(config.Attributes)
	}
	if config.EmailAttributeName != "" {
		result.EmailAttributeName = cloudflaresdk.F(config.EmailAttributeName)
	}
	if config.EnableEncryption != nil {
		result.EnableEncryption = cloudflaresdk.F(*config.EnableEncryption)
	}
	if config.ForceAuthn != nil {
		result.ForceAuthn = cloudflaresdk.F(*config.ForceAuthn)
	}
	if len(config.HeaderAttributes) > 0 {
		headers := make([]zero_trust.IdentityProviderAccessSAMLConfigHeaderAttributeParam, 0, len(config.HeaderAttributes))
		for _, value := range config.HeaderAttributes {
			header := zero_trust.IdentityProviderAccessSAMLConfigHeaderAttributeParam{}
			if value.Name != "" {
				header.HeaderName = cloudflaresdk.F(value.Name)
			}
			if value.AttributeName != "" {
				header.AttributeName = cloudflaresdk.F(value.AttributeName)
			}
			headers = append(headers, header)
		}
		result.HeaderAttributes = cloudflaresdk.F(headers)
	}
	if len(config.IDPPublicCerts) > 0 {
		result.IdPPublicCERTs = cloudflaresdk.F(config.IDPPublicCerts)
	}
	if config.IssuerURL != "" {
		result.IssuerURL = cloudflaresdk.F(config.IssuerURL)
	}
	if config.MaxSSOURLLength != nil {
		result.MaxSSOURLLength = cloudflaresdk.F(*config.MaxSSOURLLength)
	}
	if config.SignRequest != nil {
		result.SignRequest = cloudflaresdk.F(*config.SignRequest)
	}
	if config.SSOTargetURL != "" {
		result.SSOTargetURL = cloudflaresdk.F(config.SSOTargetURL)
	}
	return result
}

func identityProviderCloudflareConfig(config v1alpha1.IdentityProviderConfig) zero_trust.IdentityProviderAccessCloudflareConfigParam {
	result := zero_trust.IdentityProviderAccessCloudflareConfigParam{}
	if config.RestrictToAccountMembers != nil {
		result.RestrictToAccountMembers = cloudflaresdk.F(*config.RestrictToAccountMembers)
	}
	return result
}

func identityProviderSCIM(value *v1alpha1.IdentityProviderSCIMConfig) (zero_trust.IdentityProviderSCIMConfigParam, bool, error) {
	if value == nil {
		return zero_trust.IdentityProviderSCIMConfigParam{}, false, nil
	}
	result := zero_trust.IdentityProviderSCIMConfigParam{}
	present := false
	if value.Enabled != nil {
		result.Enabled = cloudflaresdk.F(*value.Enabled)
		present = true
	}
	if value.IdentityUpdateBehavior != "" {
		behavior, err := identityProviderSCIMBehaviorToSDK(value.IdentityUpdateBehavior)
		if err != nil {
			return result, false, err
		}
		result.IdentityUpdateBehavior = cloudflaresdk.F(behavior)
		present = true
	}
	if value.SeatDeprovision != nil {
		result.SeatDeprovision = cloudflaresdk.F(*value.SeatDeprovision)
		present = true
	}
	if value.UserDeprovision != nil {
		result.UserDeprovision = cloudflaresdk.F(*value.UserDeprovision)
		present = true
	}
	return result, present, nil
}

func identityProviderTypeToSDK(value v1alpha1.IdentityProviderType) (zero_trust.IdentityProviderType, error) {
	switch value {
	case v1alpha1.IdentityProviderTypeOneTimePIN:
		return zero_trust.IdentityProviderTypeOnetimepin, nil
	case v1alpha1.IdentityProviderTypeAzureAD:
		return zero_trust.IdentityProviderTypeAzureAD, nil
	case v1alpha1.IdentityProviderTypeSAML:
		return zero_trust.IdentityProviderTypeSAML, nil
	case v1alpha1.IdentityProviderTypeCentrify:
		return zero_trust.IdentityProviderTypeCentrify, nil
	case v1alpha1.IdentityProviderTypeFacebook:
		return zero_trust.IdentityProviderTypeFacebook, nil
	case v1alpha1.IdentityProviderTypeGitHub:
		return zero_trust.IdentityProviderTypeGitHub, nil
	case v1alpha1.IdentityProviderTypeGoogleApps:
		return zero_trust.IdentityProviderTypeGoogleApps, nil
	case v1alpha1.IdentityProviderTypeGoogle:
		return zero_trust.IdentityProviderTypeGoogle, nil
	case v1alpha1.IdentityProviderTypeLinkedIn:
		return zero_trust.IdentityProviderTypeLinkedin, nil
	case v1alpha1.IdentityProviderTypeOIDC:
		return zero_trust.IdentityProviderTypeOIDC, nil
	case v1alpha1.IdentityProviderTypeOkta:
		return zero_trust.IdentityProviderTypeOkta, nil
	case v1alpha1.IdentityProviderTypeOneLogin:
		return zero_trust.IdentityProviderTypeOnelogin, nil
	case v1alpha1.IdentityProviderTypePingOne:
		return zero_trust.IdentityProviderTypePingone, nil
	case v1alpha1.IdentityProviderTypeYandex:
		return zero_trust.IdentityProviderTypeYandex, nil
	case v1alpha1.IdentityProviderTypeCloudflare:
		return zero_trust.IdentityProviderTypeCloudflare, nil
	default:
		return "", fmt.Errorf("unsupported identity provider type %q", value)
	}
}

func identityProviderTypeFromSDK(value zero_trust.IdentityProviderType) v1alpha1.IdentityProviderType {
	switch value {
	case zero_trust.IdentityProviderTypeOnetimepin:
		return v1alpha1.IdentityProviderTypeOneTimePIN
	case zero_trust.IdentityProviderTypeAzureAD:
		return v1alpha1.IdentityProviderTypeAzureAD
	case zero_trust.IdentityProviderTypeSAML:
		return v1alpha1.IdentityProviderTypeSAML
	case zero_trust.IdentityProviderTypeCentrify:
		return v1alpha1.IdentityProviderTypeCentrify
	case zero_trust.IdentityProviderTypeFacebook:
		return v1alpha1.IdentityProviderTypeFacebook
	case zero_trust.IdentityProviderTypeGitHub:
		return v1alpha1.IdentityProviderTypeGitHub
	case zero_trust.IdentityProviderTypeGoogleApps:
		return v1alpha1.IdentityProviderTypeGoogleApps
	case zero_trust.IdentityProviderTypeGoogle:
		return v1alpha1.IdentityProviderTypeGoogle
	case zero_trust.IdentityProviderTypeLinkedin:
		return v1alpha1.IdentityProviderTypeLinkedIn
	case zero_trust.IdentityProviderTypeOIDC:
		return v1alpha1.IdentityProviderTypeOIDC
	case zero_trust.IdentityProviderTypeOkta:
		return v1alpha1.IdentityProviderTypeOkta
	case zero_trust.IdentityProviderTypeOnelogin:
		return v1alpha1.IdentityProviderTypeOneLogin
	case zero_trust.IdentityProviderTypePingone:
		return v1alpha1.IdentityProviderTypePingOne
	case zero_trust.IdentityProviderTypeYandex:
		return v1alpha1.IdentityProviderTypeYandex
	case zero_trust.IdentityProviderTypeCloudflare:
		return v1alpha1.IdentityProviderTypeCloudflare
	default:
		return v1alpha1.IdentityProviderType(value)
	}
}

func identityProviderPromptToSDK(value v1alpha1.IdentityProviderPrompt) string {
	switch value {
	case v1alpha1.IdentityProviderPromptLogin:
		return "login"
	case v1alpha1.IdentityProviderPromptSelectAccount:
		return "select_account"
	case v1alpha1.IdentityProviderPromptNone:
		return "none"
	default:
		return string(value)
	}
}

func identityProviderPromptFromSDK(value string) v1alpha1.IdentityProviderPrompt {
	switch value {
	case "login":
		return v1alpha1.IdentityProviderPromptLogin
	case "select_account":
		return v1alpha1.IdentityProviderPromptSelectAccount
	case "none":
		return v1alpha1.IdentityProviderPromptNone
	default:
		return v1alpha1.IdentityProviderPrompt(value)
	}
}

func identityProviderGoogleAppsPromptToSDK(value v1alpha1.IdentityProviderPrompt) (zero_trust.IdentityProviderAccessGoogleAppsConfigPrompt, error) {
	if value != v1alpha1.IdentityProviderPromptSelectAccount {
		return "", fmt.Errorf("identity provider GoogleApps prompt must be %q", v1alpha1.IdentityProviderPromptSelectAccount)
	}
	return zero_trust.IdentityProviderAccessGoogleAppsConfigPromptSelectAccount, nil
}

func identityProviderSCIMBehaviorToSDK(value v1alpha1.IdentityProviderSCIMIdentityUpdateBehavior) (zero_trust.IdentityProviderSCIMConfigIdentityUpdateBehavior, error) {
	switch value {
	case v1alpha1.IdentityProviderSCIMIdentityUpdateAutomatic:
		return zero_trust.IdentityProviderSCIMConfigIdentityUpdateBehaviorAutomatic, nil
	case v1alpha1.IdentityProviderSCIMIdentityUpdateReauth:
		return zero_trust.IdentityProviderSCIMConfigIdentityUpdateBehaviorReauth, nil
	case v1alpha1.IdentityProviderSCIMIdentityUpdateNoAction:
		return zero_trust.IdentityProviderSCIMConfigIdentityUpdateBehaviorNoAction, nil
	default:
		return "", fmt.Errorf("unsupported SCIM identity update behavior %q", value)
	}
}

func identityProviderSCIMBehaviorFromSDK(value zero_trust.IdentityProviderSCIMConfigIdentityUpdateBehavior) v1alpha1.IdentityProviderSCIMIdentityUpdateBehavior {
	switch value {
	case zero_trust.IdentityProviderSCIMConfigIdentityUpdateBehaviorAutomatic:
		return v1alpha1.IdentityProviderSCIMIdentityUpdateAutomatic
	case zero_trust.IdentityProviderSCIMConfigIdentityUpdateBehaviorReauth:
		return v1alpha1.IdentityProviderSCIMIdentityUpdateReauth
	case zero_trust.IdentityProviderSCIMConfigIdentityUpdateBehaviorNoAction:
		return v1alpha1.IdentityProviderSCIMIdentityUpdateNoAction
	default:
		return v1alpha1.IdentityProviderSCIMIdentityUpdateBehavior(value)
	}
}
