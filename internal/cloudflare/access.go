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
	"strconv"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// AccessAPI is the complete M3 Cloudflare Access surface.
type AccessAPI interface {
	AccessApplicationAPI
	AccessTagAPI
	AccessPolicyAPI
	AccessGroupAPI
	IdentityProviderAPI
	DevicePostureRuleAPI
	ServiceTokenAPI
}

// AccessApplicationAPI is part of the Flareway API.
type AccessApplicationAPI interface {
	CreateAccessApplication(context.Context, AccessApplicationInput) (AccessApplication, error)
	UpdateAccessApplication(context.Context, string, AccessApplicationInput) (AccessApplication, error)
	GetAccessApplication(context.Context, string) (AccessApplication, error)
	ListAccessApplications(context.Context) ([]AccessApplication, error)
	DeleteAccessApplication(context.Context, string) error
	EnsureBypassPolicy(context.Context, string) (AccessPolicy, error)
}

// AccessTagAPI is part of the Flareway API.
type AccessTagAPI interface {
	GetAccessTag(context.Context, string) (AccessTag, error)
	CreateAccessTag(context.Context, string) (AccessTag, error)
	DeleteAccessTag(context.Context, string) error
}

// AccessPolicyAPI is part of the Flareway API.
type AccessPolicyAPI interface {
	CreateAccessPolicy(context.Context, AccessPolicyInput) (AccessPolicy, error)
	UpdateAccessPolicy(context.Context, string, AccessPolicyInput) (AccessPolicy, error)
	GetAccessPolicy(context.Context, string) (AccessPolicy, error)
	ListAccessPolicies(context.Context) ([]AccessPolicy, error)
	DeleteAccessPolicy(context.Context, string) error
}

// AccessGroupAPI is part of the Flareway API.
type AccessGroupAPI interface {
	CreateAccessGroup(context.Context, AccessGroupInput) (AccessGroup, error)
	UpdateAccessGroup(context.Context, string, AccessGroupInput) (AccessGroup, error)
	GetAccessGroup(context.Context, string) (AccessGroup, error)
	ListAccessGroups(context.Context) ([]AccessGroup, error)
	DeleteAccessGroup(context.Context, string) error
}

// IdentityProviderAPI is part of the Flareway API.
type IdentityProviderAPI interface {
	CreateIdentityProvider(context.Context, IdentityProviderInput) (IdentityProvider, error)
	UpdateIdentityProvider(context.Context, string, IdentityProviderInput) (IdentityProvider, error)
	GetIdentityProvider(context.Context, string) (IdentityProvider, error)
	ListIdentityProviders(context.Context) ([]IdentityProvider, error)
	DeleteIdentityProvider(context.Context, string) error
}

// DevicePostureRuleAPI is part of the Flareway API.
type DevicePostureRuleAPI interface {
	CreateDevicePostureRule(context.Context, DevicePostureRuleInput) (DevicePostureRule, error)
	UpdateDevicePostureRule(context.Context, string, DevicePostureRuleInput) (DevicePostureRule, error)
	GetDevicePostureRule(context.Context, string) (DevicePostureRule, error)
	ListDevicePostureRules(context.Context) ([]DevicePostureRule, error)
	DeleteDevicePostureRule(context.Context, string) error
}

// ServiceTokenAPI is part of the Flareway API.
type ServiceTokenAPI interface {
	CreateServiceToken(context.Context, ServiceTokenInput) (ServiceTokenSecret, error)
	UpdateServiceToken(context.Context, string, ServiceTokenInput) (ServiceToken, error)
	GetServiceToken(context.Context, string) (ServiceToken, error)
	ListServiceTokens(context.Context) ([]ServiceToken, error)
	DeleteServiceToken(context.Context, string) error
	RotateServiceToken(context.Context, string, time.Time) (ServiceTokenSecret, error)
	RefreshServiceToken(context.Context, string) (ServiceToken, error)
}

// AccessApplicationDestination is part of the Flareway API.
type AccessApplicationDestination struct {
	Type       string
	URI        string
	Hostname   string
	CIDR       string
	PortRange  string
	L4Protocol string
	VNetID     string
}

// AccessApplicationPolicyAttachment is part of the Flareway API.
type AccessApplicationPolicyAttachment struct {
	ID         string
	Precedence int64
}

// AccessApplicationInput is part of the Flareway API.
type AccessApplicationInput struct {
	Domain                      string
	Name                        string
	Destinations                []AccessApplicationDestination
	Policies                    []AccessApplicationPolicyAttachment
	AllowedIDPs                 []string
	SessionDuration             string
	AllowAuthenticateViaWARP    *bool
	SkipInterstitial            *bool
	AutoRedirectToIdentity      *bool
	AppLauncherVisible          *bool
	ServiceAuth401Redirect      *bool
	EnableBindingCookie         *bool
	HTTPOnlyCookieAttribute     *bool
	SameSiteCookieAttribute     string
	PathCookieAttribute         *bool
	OptionsPreflightBypass      *bool
	CORSHeaders                 *v1alpha1.AccessCORSHeaders
	ReadServiceTokensFromHeader string
	CustomDenyMessage           string
	CustomDenyURL               string
	CustomNonIdentityDenyURL    string
	CustomPages                 []string
	Tags                        []string
}

// AccessApplication is part of the Flareway API.
type AccessApplication struct {
	ID              string
	AUD             string
	Name            string
	Domain          string
	Type            string
	SessionDuration string
	Tags            []string
}

// AccessTag is the secret-free Access application tag representation.
type AccessTag struct {
	Name string
}

// ResolvedAccessRule is part of the Flareway API.
type ResolvedAccessRule struct {
	Kind               string
	Value              string
	Value2             string
	Value3             string
	Values             []string
	ID                 string
	IdentityProviderID string
	AccountID          string
}

// AccessPolicyInput is part of the Flareway API.
type AccessPolicyInput struct {
	Name                         string
	Decision                     string
	Include                      []ResolvedAccessRule
	Require                      []ResolvedAccessRule
	Exclude                      []ResolvedAccessRule
	SessionDuration              string
	PurposeJustificationRequired bool
	PurposeJustificationPrompt   string
	ApprovalRequired             bool
	ApprovalGroups               []AccessApprovalGroup
	IsolationRequired            bool
}

// AccessApprovalGroup is part of the Flareway API.
type AccessApprovalGroup struct {
	ApprovalsNeeded int32
	EmailAddresses  []string
	EmailListID     string
}

// AccessPolicy is part of the Flareway API.
type AccessPolicy struct {
	ID              string
	Name            string
	Decision        string
	SessionDuration string
}

// AccessGroupInput is part of the Flareway API.
type AccessGroupInput struct {
	Name    string
	Include []ResolvedAccessRule
	Require []ResolvedAccessRule
	Exclude []ResolvedAccessRule
}

// AccessGroup is part of the Flareway API.
type AccessGroup struct {
	ID   string
	Name string
}

// IdentityProviderInput is part of the Flareway API.
type IdentityProviderInput struct {
	Name         string
	Type         v1alpha1.IdentityProviderType
	Config       v1alpha1.IdentityProviderConfig
	SCIMConfig   *v1alpha1.IdentityProviderSCIMConfig
	ClientSecret string
}

// IdentityProvider is part of the Flareway API.
type IdentityProvider struct {
	ID       string
	Name     string
	Type     string
	ReadOnly bool
}

// DevicePostureRuleInput is part of the Flareway API.
type DevicePostureRuleInput struct {
	Name        string
	Type        v1alpha1.DevicePostureRuleType
	Description string
	Schedule    string
	Expiration  string
	Match       []v1alpha1.DevicePostureMatch
	Input       v1alpha1.DevicePostureInput
}

// DevicePostureRule is part of the Flareway API.
type DevicePostureRule struct {
	ID          string
	Name        string
	Type        string
	Description string
	Enabled     bool
	Schedule    string
	Expiration  string
}

// ServiceTokenInput is part of the Flareway API.
type ServiceTokenInput struct {
	Name     string
	Duration string
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

// CreateAccessApplication is part of the Flareway API.
func (client *Client) CreateAccessApplication(ctx context.Context, input AccessApplicationInput) (AccessApplication, error) {
	result, err := client.sdk.ZeroTrust.Access.Applications.New(ctx, zero_trust.AccessApplicationNewParams{
		AccountID: cloudflaresdk.F(client.accountID), Body: accessApplicationNewBody(input),
	})
	if err != nil {
		return AccessApplication{}, fmt.Errorf("create Access application: %w", err)
	}
	return AccessApplication{ID: result.ID, AUD: result.AUD, Name: result.Name, Domain: result.Domain, Type: string(result.Type), SessionDuration: result.SessionDuration, Tags: accessApplicationTags(result.Tags)}, nil
}

// UpdateAccessApplication is part of the Flareway API.
func (client *Client) UpdateAccessApplication(ctx context.Context, id string, input AccessApplicationInput) (AccessApplication, error) {
	result, err := client.sdk.ZeroTrust.Access.Applications.Update(ctx, id, zero_trust.AccessApplicationUpdateParams{
		AccountID: cloudflaresdk.F(client.accountID), Body: accessApplicationUpdateBody(input),
	})
	if err != nil {
		return AccessApplication{}, fmt.Errorf("update Access application: %w", err)
	}
	return AccessApplication{ID: result.ID, AUD: result.AUD, Name: result.Name, Domain: result.Domain, Type: string(result.Type), SessionDuration: result.SessionDuration, Tags: accessApplicationTags(result.Tags)}, nil
}

// GetAccessApplication is part of the Flareway API.
func (client *Client) GetAccessApplication(ctx context.Context, id string) (AccessApplication, error) {
	result, err := client.sdk.ZeroTrust.Access.Applications.Get(ctx, id, zero_trust.AccessApplicationGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return AccessApplication{}, fmt.Errorf("get Access application: %w", err)
	}
	return AccessApplication{ID: result.ID, AUD: result.AUD, Name: result.Name, Domain: result.Domain, Type: string(result.Type), SessionDuration: result.SessionDuration, Tags: accessApplicationTags(result.Tags)}, nil
}

// ListAccessApplications is part of the Flareway API.
func (client *Client) ListAccessApplications(ctx context.Context) ([]AccessApplication, error) {
	pager := client.sdk.ZeroTrust.Access.Applications.ListAutoPaging(ctx, zero_trust.AccessApplicationListParams{AccountID: cloudflaresdk.F(client.accountID), PerPage: cloudflaresdk.F(int64(100))})
	var applications []AccessApplication
	for pager.Next() {
		result := pager.Current()
		applications = append(applications, AccessApplication{ID: result.ID, AUD: result.AUD, Name: result.Name, Domain: result.Domain, Type: string(result.Type), SessionDuration: result.SessionDuration, Tags: accessApplicationTags(result.Tags)})
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Access applications: %w", err)
	}
	return applications, nil
}

func accessApplicationTags(value any) []string {
	tags, _ := value.([]string)
	return append([]string(nil), tags...)
}

// DeleteAccessApplication is part of the Flareway API.
func (client *Client) DeleteAccessApplication(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Access.Applications.Delete(ctx, id, zero_trust.AccessApplicationDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Access application: %w", err)
	}
	return nil
}

// GetAccessTag is part of the Flareway API.
func (client *Client) GetAccessTag(ctx context.Context, name string) (AccessTag, error) {
	result, err := client.sdk.ZeroTrust.Access.Tags.Get(ctx, name, zero_trust.AccessTagGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return AccessTag{}, fmt.Errorf("get Access tag: %w", err)
	}
	return AccessTag{Name: result.Name}, nil
}

// CreateAccessTag is part of the Flareway API.
func (client *Client) CreateAccessTag(ctx context.Context, name string) (AccessTag, error) {
	result, err := client.sdk.ZeroTrust.Access.Tags.New(ctx, zero_trust.AccessTagNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(name),
	})
	if err != nil {
		return AccessTag{}, fmt.Errorf("create Access tag: %w", err)
	}
	return AccessTag{Name: result.Name}, nil
}

// DeleteAccessTag is part of the Flareway API.
func (client *Client) DeleteAccessTag(ctx context.Context, name string) error {
	_, err := client.sdk.ZeroTrust.Access.Tags.Delete(ctx, name, zero_trust.AccessTagDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Access tag: %w", err)
	}
	return nil
}

func accessApplicationNewBody(input AccessApplicationInput) zero_trust.AccessApplicationNewParamsBodySelfHostedApplication {
	body := zero_trust.AccessApplicationNewParamsBodySelfHostedApplication{Domain: cloudflaresdk.F(input.Domain), Type: cloudflaresdk.F(zero_trust.ApplicationTypeSelfHosted), Name: cloudflaresdk.F(input.Name)}
	body.Destinations = cloudflaresdk.F(newDestinations(input.Destinations))
	body.Policies = cloudflaresdk.F(newPolicyLinks(input.Policies))
	applyNewApplicationOptions(&body, input)
	return body
}

func accessApplicationUpdateBody(input AccessApplicationInput) zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplication {
	body := zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplication{Domain: cloudflaresdk.F(input.Domain), Type: cloudflaresdk.F(zero_trust.ApplicationTypeSelfHosted), Name: cloudflaresdk.F(input.Name)}
	body.Destinations = cloudflaresdk.F(updateDestinations(input.Destinations))
	body.Policies = cloudflaresdk.F(updatePolicyLinks(input.Policies))
	applyUpdateApplicationOptions(&body, input)
	return body
}

func newDestinations(values []AccessApplicationDestination) []zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationDestinationUnion {
	out := make([]zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationDestinationUnion, 0, len(values))
	for _, value := range values {
		if value.Type == "private" {
			out = append(out, zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationDestinationsPrivateDestination{Type: cloudflaresdk.F(zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationDestinationsPrivateDestinationTypePrivate), Hostname: cloudflaresdk.F(value.Hostname), CIDR: cloudflaresdk.F(value.CIDR), PortRange: cloudflaresdk.F(value.PortRange), L4Protocol: cloudflaresdk.F(zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationDestinationsPrivateDestinationL4Protocol(value.L4Protocol)), VnetID: cloudflaresdk.F(value.VNetID)})
		} else {
			out = append(out, zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationDestinationsPublicDestination{Type: cloudflaresdk.F(zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationDestinationsPublicDestinationTypePublic), URI: cloudflaresdk.F(value.URI)})
		}
	}
	return out
}

func updateDestinations(values []AccessApplicationDestination) []zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationDestinationUnion {
	out := make([]zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationDestinationUnion, 0, len(values))
	for _, value := range values {
		if value.Type == "private" {
			out = append(out, zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationDestinationsPrivateDestination{Type: cloudflaresdk.F(zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationDestinationsPrivateDestinationTypePrivate), Hostname: cloudflaresdk.F(value.Hostname), CIDR: cloudflaresdk.F(value.CIDR), PortRange: cloudflaresdk.F(value.PortRange), L4Protocol: cloudflaresdk.F(zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationDestinationsPrivateDestinationL4Protocol(value.L4Protocol)), VnetID: cloudflaresdk.F(value.VNetID)})
		} else {
			out = append(out, zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationDestinationsPublicDestination{Type: cloudflaresdk.F(zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationDestinationsPublicDestinationTypePublic), URI: cloudflaresdk.F(value.URI)})
		}
	}
	return out
}

func newPolicyLinks(values []AccessApplicationPolicyAttachment) []zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationPolicyUnion {
	out := make([]zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationPolicyUnion, 0, len(values))
	for _, value := range values {
		out = append(out, zero_trust.AccessApplicationNewParamsBodySelfHostedApplicationPoliciesAccessAppPolicyLink{ID: cloudflaresdk.F(value.ID), Precedence: cloudflaresdk.F(value.Precedence)})
	}
	return out
}
func updatePolicyLinks(values []AccessApplicationPolicyAttachment) []zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationPolicyUnion {
	out := make([]zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationPolicyUnion, 0, len(values))
	for _, value := range values {
		out = append(out, zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplicationPoliciesAccessAppPolicyLink{ID: cloudflaresdk.F(value.ID), Precedence: cloudflaresdk.F(value.Precedence)})
	}
	return out
}

func applyNewApplicationOptions(body *zero_trust.AccessApplicationNewParamsBodySelfHostedApplication, input AccessApplicationInput) {
	body.AllowedIdPs = cloudflaresdk.F(append([]string(nil), input.AllowedIDPs...))
	body.SessionDuration = cloudflaresdk.F(input.SessionDuration)
	body.SameSiteCookieAttribute = cloudflaresdk.F(input.SameSiteCookieAttribute)
	body.ReadServiceTokensFromHeader = cloudflaresdk.F(input.ReadServiceTokensFromHeader)
	body.CustomDenyMessage = cloudflaresdk.F(input.CustomDenyMessage)
	body.CustomDenyURL = cloudflaresdk.F(input.CustomDenyURL)
	body.CustomNonIdentityDenyURL = cloudflaresdk.F(input.CustomNonIdentityDenyURL)
	body.CustomPages = cloudflaresdk.F(append([]string(nil), input.CustomPages...))
	body.Tags = cloudflaresdk.F(append([]string(nil), input.Tags...))
	applyNewBoolOptions(body, input)
	if input.CORSHeaders != nil {
		body.CORSHeaders = cloudflaresdk.F(corsHeaders(input.CORSHeaders))
	}
}
func applyUpdateApplicationOptions(body *zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplication, input AccessApplicationInput) {
	body.AllowedIdPs = cloudflaresdk.F(append([]string(nil), input.AllowedIDPs...))
	body.SessionDuration = cloudflaresdk.F(input.SessionDuration)
	body.SameSiteCookieAttribute = cloudflaresdk.F(input.SameSiteCookieAttribute)
	body.ReadServiceTokensFromHeader = cloudflaresdk.F(input.ReadServiceTokensFromHeader)
	body.CustomDenyMessage = cloudflaresdk.F(input.CustomDenyMessage)
	body.CustomDenyURL = cloudflaresdk.F(input.CustomDenyURL)
	body.CustomNonIdentityDenyURL = cloudflaresdk.F(input.CustomNonIdentityDenyURL)
	body.CustomPages = cloudflaresdk.F(append([]string(nil), input.CustomPages...))
	body.Tags = cloudflaresdk.F(append([]string(nil), input.Tags...))
	applyUpdateBoolOptions(body, input)
	if input.CORSHeaders != nil {
		body.CORSHeaders = cloudflaresdk.F(corsHeaders(input.CORSHeaders))
	}
}
func corsHeaders(value *v1alpha1.AccessCORSHeaders) zero_trust.CORSHeadersParam {
	result := zero_trust.CORSHeadersParam{AllowedHeaders: cloudflaresdk.F(append([]string(nil), value.AllowedHeaders...)), AllowedOrigins: cloudflaresdk.F(append([]string(nil), value.AllowedOrigins...))}
	methods := make([]zero_trust.AllowedMethods, len(value.AllowedMethods))
	for i := range value.AllowedMethods {
		methods[i] = zero_trust.AllowedMethods(value.AllowedMethods[i])
	}
	result.AllowedMethods = cloudflaresdk.F(methods)
	if value.AllowAllHeaders != nil {
		result.AllowAllHeaders = cloudflaresdk.F(*value.AllowAllHeaders)
	}
	if value.AllowAllMethods != nil {
		result.AllowAllMethods = cloudflaresdk.F(*value.AllowAllMethods)
	}
	if value.AllowAllOrigins != nil {
		result.AllowAllOrigins = cloudflaresdk.F(*value.AllowAllOrigins)
	}
	if value.AllowCredentials != nil {
		result.AllowCredentials = cloudflaresdk.F(*value.AllowCredentials)
	}
	if value.MaxAge != nil {
		result.MaxAge = cloudflaresdk.F(float64(*value.MaxAge))
	}
	return result
}
func applyNewBoolOptions(body *zero_trust.AccessApplicationNewParamsBodySelfHostedApplication, in AccessApplicationInput) {
	if in.AllowAuthenticateViaWARP != nil {
		body.AllowAuthenticateViaWARP = cloudflaresdk.F(*in.AllowAuthenticateViaWARP)
	}
	if in.SkipInterstitial != nil {
		body.SkipInterstitial = cloudflaresdk.F(*in.SkipInterstitial)
	}
	if in.AutoRedirectToIdentity != nil {
		body.AutoRedirectToIdentity = cloudflaresdk.F(*in.AutoRedirectToIdentity)
	}
	if in.AppLauncherVisible != nil {
		body.AppLauncherVisible = cloudflaresdk.F(*in.AppLauncherVisible)
	}
	if in.ServiceAuth401Redirect != nil {
		body.ServiceAuth401Redirect = cloudflaresdk.F(*in.ServiceAuth401Redirect)
	}
	if in.EnableBindingCookie != nil {
		body.EnableBindingCookie = cloudflaresdk.F(*in.EnableBindingCookie)
	}
	if in.HTTPOnlyCookieAttribute != nil {
		body.HTTPOnlyCookieAttribute = cloudflaresdk.F(*in.HTTPOnlyCookieAttribute)
	}
	if in.PathCookieAttribute != nil {
		body.PathCookieAttribute = cloudflaresdk.F(*in.PathCookieAttribute)
	}
	if in.OptionsPreflightBypass != nil {
		body.OptionsPreflightBypass = cloudflaresdk.F(*in.OptionsPreflightBypass)
	}
}
func applyUpdateBoolOptions(body *zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplication, in AccessApplicationInput) {
	if in.AllowAuthenticateViaWARP != nil {
		body.AllowAuthenticateViaWARP = cloudflaresdk.F(*in.AllowAuthenticateViaWARP)
	}
	if in.SkipInterstitial != nil {
		body.SkipInterstitial = cloudflaresdk.F(*in.SkipInterstitial)
	}
	if in.AutoRedirectToIdentity != nil {
		body.AutoRedirectToIdentity = cloudflaresdk.F(*in.AutoRedirectToIdentity)
	}
	if in.AppLauncherVisible != nil {
		body.AppLauncherVisible = cloudflaresdk.F(*in.AppLauncherVisible)
	}
	if in.ServiceAuth401Redirect != nil {
		body.ServiceAuth401Redirect = cloudflaresdk.F(*in.ServiceAuth401Redirect)
	}
	if in.EnableBindingCookie != nil {
		body.EnableBindingCookie = cloudflaresdk.F(*in.EnableBindingCookie)
	}
	if in.HTTPOnlyCookieAttribute != nil {
		body.HTTPOnlyCookieAttribute = cloudflaresdk.F(*in.HTTPOnlyCookieAttribute)
	}
	if in.PathCookieAttribute != nil {
		body.PathCookieAttribute = cloudflaresdk.F(*in.PathCookieAttribute)
	}
	if in.OptionsPreflightBypass != nil {
		body.OptionsPreflightBypass = cloudflaresdk.F(*in.OptionsPreflightBypass)
	}
}

// CreateAccessPolicy is part of the Flareway API.
func (client *Client) CreateAccessPolicy(ctx context.Context, input AccessPolicyInput) (AccessPolicy, error) {
	params, err := accessPolicyNewParams(client.accountID, input)
	if err != nil {
		return AccessPolicy{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Policies.New(ctx, params)
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("create Access policy: %w", err)
	}
	return AccessPolicy{ID: result.ID, Name: result.Name, Decision: string(result.Decision), SessionDuration: result.SessionDuration}, nil
}

// UpdateAccessPolicy is part of the Flareway API.
func (client *Client) UpdateAccessPolicy(ctx context.Context, id string, input AccessPolicyInput) (AccessPolicy, error) {
	params, err := accessPolicyUpdateParams(client.accountID, input)
	if err != nil {
		return AccessPolicy{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Policies.Update(ctx, id, params)
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("update Access policy: %w", err)
	}
	return AccessPolicy{ID: result.ID, Name: result.Name, Decision: string(result.Decision), SessionDuration: result.SessionDuration}, nil
}

// GetAccessPolicy is part of the Flareway API.
func (client *Client) GetAccessPolicy(ctx context.Context, id string) (AccessPolicy, error) {
	result, err := client.sdk.ZeroTrust.Access.Policies.Get(ctx, id, zero_trust.AccessPolicyGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("get Access policy: %w", err)
	}
	return AccessPolicy{ID: result.ID, Name: result.Name, Decision: string(result.Decision), SessionDuration: result.SessionDuration}, nil
}

// ListAccessPolicies is part of the Flareway API.
func (client *Client) ListAccessPolicies(ctx context.Context) ([]AccessPolicy, error) {
	pager := client.sdk.ZeroTrust.Access.Policies.ListAutoPaging(ctx, zero_trust.AccessPolicyListParams{AccountID: cloudflaresdk.F(client.accountID), PerPage: cloudflaresdk.F(int64(100))})
	var out []AccessPolicy
	for pager.Next() {
		v := pager.Current()
		out = append(out, AccessPolicy{ID: v.ID, Name: v.Name, Decision: string(v.Decision), SessionDuration: v.SessionDuration})
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Access policies: %w", err)
	}
	return out, nil
}

// DeleteAccessPolicy is part of the Flareway API.
func (client *Client) DeleteAccessPolicy(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Access.Policies.Delete(ctx, id, zero_trust.AccessPolicyDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Access policy: %w", err)
	}
	return nil
}

func accessPolicyNewParams(accountID string, input AccessPolicyInput) (zero_trust.AccessPolicyNewParams, error) {
	include, err := AccessRulesToSDK(input.Include)
	if err != nil {
		return zero_trust.AccessPolicyNewParams{}, err
	}
	require, err := AccessRulesToSDK(input.Require)
	if err != nil {
		return zero_trust.AccessPolicyNewParams{}, err
	}
	exclude, err := AccessRulesToSDK(input.Exclude)
	if err != nil {
		return zero_trust.AccessPolicyNewParams{}, err
	}
	return zero_trust.AccessPolicyNewParams{AccountID: cloudflaresdk.F(accountID), Name: cloudflaresdk.F(input.Name), Decision: cloudflaresdk.F(zero_trust.Decision(decisionValue(input.Decision))), Include: cloudflaresdk.F(include), Require: cloudflaresdk.F(require), Exclude: cloudflaresdk.F(exclude), SessionDuration: cloudflaresdk.F(input.SessionDuration), PurposeJustificationRequired: cloudflaresdk.F(input.PurposeJustificationRequired), PurposeJustificationPrompt: cloudflaresdk.F(input.PurposeJustificationPrompt), ApprovalRequired: cloudflaresdk.F(input.ApprovalRequired), ApprovalGroups: cloudflaresdk.F(approvalGroups(input.ApprovalGroups)), IsolationRequired: cloudflaresdk.F(input.IsolationRequired)}, nil
}
func accessPolicyUpdateParams(accountID string, input AccessPolicyInput) (zero_trust.AccessPolicyUpdateParams, error) {
	include, err := AccessRulesToSDK(input.Include)
	if err != nil {
		return zero_trust.AccessPolicyUpdateParams{}, err
	}
	require, err := AccessRulesToSDK(input.Require)
	if err != nil {
		return zero_trust.AccessPolicyUpdateParams{}, err
	}
	exclude, err := AccessRulesToSDK(input.Exclude)
	if err != nil {
		return zero_trust.AccessPolicyUpdateParams{}, err
	}
	return zero_trust.AccessPolicyUpdateParams{AccountID: cloudflaresdk.F(accountID), Name: cloudflaresdk.F(input.Name), Decision: cloudflaresdk.F(zero_trust.Decision(decisionValue(input.Decision))), Include: cloudflaresdk.F(include), Require: cloudflaresdk.F(require), Exclude: cloudflaresdk.F(exclude), SessionDuration: cloudflaresdk.F(input.SessionDuration), PurposeJustificationRequired: cloudflaresdk.F(input.PurposeJustificationRequired), PurposeJustificationPrompt: cloudflaresdk.F(input.PurposeJustificationPrompt), ApprovalRequired: cloudflaresdk.F(input.ApprovalRequired), ApprovalGroups: cloudflaresdk.F(approvalGroups(input.ApprovalGroups)), IsolationRequired: cloudflaresdk.F(input.IsolationRequired)}, nil
}
func decisionValue(value string) string {
	if value == "nonIdentity" {
		return "non_identity"
	}
	return value
}
func approvalGroups(values []AccessApprovalGroup) []zero_trust.ApprovalGroupParam {
	out := make([]zero_trust.ApprovalGroupParam, len(values))
	for i, v := range values {
		out[i] = zero_trust.ApprovalGroupParam{ApprovalsNeeded: cloudflaresdk.F(float64(v.ApprovalsNeeded)), EmailAddresses: cloudflaresdk.F(append([]string(nil), v.EmailAddresses...)), EmailListUUID: cloudflaresdk.F(v.EmailListID)}
	}
	return out
}

// EnsureBypassPolicy is part of the Flareway API.
func (client *Client) EnsureBypassPolicy(ctx context.Context, name string) (AccessPolicy, error) {
	policies, err := client.ListAccessPolicies(ctx)
	if err != nil {
		return AccessPolicy{}, err
	}
	for _, policy := range policies {
		if policy.Name == name {
			if policy.Decision != "bypass" {
				return AccessPolicy{}, fmt.Errorf("access policy %q exists with decision %q", name, policy.Decision)
			}
			return policy, nil
		}
	}
	return client.CreateAccessPolicy(ctx, AccessPolicyInput{Name: name, Decision: "bypass", Include: []ResolvedAccessRule{{Kind: "everyone"}}})
}

// CreateAccessGroup is part of the Flareway API.
func (client *Client) CreateAccessGroup(ctx context.Context, input AccessGroupInput) (AccessGroup, error) {
	params, err := accessGroupNewParams(client.accountID, input)
	if err != nil {
		return AccessGroup{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Groups.New(ctx, params)
	if err != nil {
		return AccessGroup{}, fmt.Errorf("create Access group: %w", err)
	}
	return AccessGroup{ID: result.ID, Name: result.Name}, nil
}

// UpdateAccessGroup is part of the Flareway API.
func (client *Client) UpdateAccessGroup(ctx context.Context, id string, input AccessGroupInput) (AccessGroup, error) {
	params, err := accessGroupUpdateParams(client.accountID, input)
	if err != nil {
		return AccessGroup{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Groups.Update(ctx, id, params)
	if err != nil {
		return AccessGroup{}, fmt.Errorf("update Access group: %w", err)
	}
	return AccessGroup{ID: result.ID, Name: result.Name}, nil
}

// GetAccessGroup is part of the Flareway API.
func (client *Client) GetAccessGroup(ctx context.Context, id string) (AccessGroup, error) {
	result, err := client.sdk.ZeroTrust.Access.Groups.Get(ctx, id, zero_trust.AccessGroupGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return AccessGroup{}, fmt.Errorf("get Access group: %w", err)
	}
	return AccessGroup{ID: result.ID, Name: result.Name}, nil
}

// ListAccessGroups is part of the Flareway API.
func (client *Client) ListAccessGroups(ctx context.Context) ([]AccessGroup, error) {
	pager := client.sdk.ZeroTrust.Access.Groups.ListAutoPaging(ctx, zero_trust.AccessGroupListParams{AccountID: cloudflaresdk.F(client.accountID)})
	var out []AccessGroup
	for pager.Next() {
		v := pager.Current()
		out = append(out, AccessGroup{ID: v.ID, Name: v.Name})
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Access groups: %w", err)
	}
	return out, nil
}

// DeleteAccessGroup is part of the Flareway API.
func (client *Client) DeleteAccessGroup(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Access.Groups.Delete(ctx, id, zero_trust.AccessGroupDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Access group: %w", err)
	}
	return nil
}
func accessGroupNewParams(accountID string, input AccessGroupInput) (zero_trust.AccessGroupNewParams, error) {
	include, err := AccessRulesToSDK(input.Include)
	if err != nil {
		return zero_trust.AccessGroupNewParams{}, err
	}
	require, err := AccessRulesToSDK(input.Require)
	if err != nil {
		return zero_trust.AccessGroupNewParams{}, err
	}
	exclude, err := AccessRulesToSDK(input.Exclude)
	if err != nil {
		return zero_trust.AccessGroupNewParams{}, err
	}
	return zero_trust.AccessGroupNewParams{AccountID: cloudflaresdk.F(accountID), Name: cloudflaresdk.F(input.Name), Include: cloudflaresdk.F(include), Require: cloudflaresdk.F(require), Exclude: cloudflaresdk.F(exclude)}, nil
}
func accessGroupUpdateParams(accountID string, input AccessGroupInput) (zero_trust.AccessGroupUpdateParams, error) {
	include, err := AccessRulesToSDK(input.Include)
	if err != nil {
		return zero_trust.AccessGroupUpdateParams{}, err
	}
	require, err := AccessRulesToSDK(input.Require)
	if err != nil {
		return zero_trust.AccessGroupUpdateParams{}, err
	}
	exclude, err := AccessRulesToSDK(input.Exclude)
	if err != nil {
		return zero_trust.AccessGroupUpdateParams{}, err
	}
	return zero_trust.AccessGroupUpdateParams{AccountID: cloudflaresdk.F(accountID), Name: cloudflaresdk.F(input.Name), Include: cloudflaresdk.F(include), Require: cloudflaresdk.F(require), Exclude: cloudflaresdk.F(exclude)}, nil
}

// AccessRulesToSDK converts every typed Flareway Access rule to cloudflare-go's typed union.
func AccessRulesToSDK(values []ResolvedAccessRule) ([]zero_trust.AccessRuleUnionParam, error) {
	out := make([]zero_trust.AccessRuleUnionParam, 0, len(values))
	for _, v := range values {
		var rule zero_trust.AccessRuleUnionParam
		switch v.Kind {
		case "email":
			rule = zero_trust.EmailRuleParam{Email: cloudflaresdk.F(zero_trust.EmailRuleEmailParam{Email: cloudflaresdk.F(v.Value)})}
		case "emailDomain":
			rule = zero_trust.DomainRuleParam{EmailDomain: cloudflaresdk.F(zero_trust.DomainRuleEmailDomainParam{Domain: cloudflaresdk.F(v.Value)})}
		case "emailList":
			rule = zero_trust.EmailListRuleParam{EmailList: cloudflaresdk.F(zero_trust.EmailListRuleEmailListParam{ID: cloudflaresdk.F(v.ID)})}
		case "everyone":
			rule = zero_trust.EveryoneRuleParam{Everyone: cloudflaresdk.F(zero_trust.EveryoneRuleEveryoneParam{})}
		case "ip":
			rule = zero_trust.IPRuleParam{IP: cloudflaresdk.F(zero_trust.IPRuleIPParam{IP: cloudflaresdk.F(v.Value)})}
		case "ipList":
			rule = zero_trust.IPListRuleParam{IPList: cloudflaresdk.F(zero_trust.IPListRuleIPListParam{ID: cloudflaresdk.F(v.ID)})}
		case "certificate":
			rule = zero_trust.CertificateRuleParam{Certificate: cloudflaresdk.F(zero_trust.CertificateRuleCertificateParam{})}
		case "commonName":
			rule = zero_trust.AccessRuleAccessCommonNameRuleParam{CommonName: cloudflaresdk.F(zero_trust.AccessRuleAccessCommonNameRuleCommonNameParam{CommonName: cloudflaresdk.F(v.Value)})}
		case "group":
			rule = zero_trust.GroupRuleParam{Group: cloudflaresdk.F(zero_trust.GroupRuleGroupParam{ID: cloudflaresdk.F(v.ID)})}
		case "azureAD":
			rule = zero_trust.AzureGroupRuleParam{AzureAD: cloudflaresdk.F(zero_trust.AzureGroupRuleAzureADParam{ID: cloudflaresdk.F(v.ID), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "githubOrganization":
			rule = zero_trust.GitHubOrganizationRuleParam{GitHubOrganization: cloudflaresdk.F(zero_trust.GitHubOrganizationRuleGitHubOrganizationParam{Name: cloudflaresdk.F(v.Value), Team: cloudflaresdk.F(v.Value2), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "gsuite":
			rule = zero_trust.GSuiteGroupRuleParam{GSuite: cloudflaresdk.F(zero_trust.GSuiteGroupRuleGSuiteParam{Email: cloudflaresdk.F(v.Value), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "okta":
			rule = zero_trust.OktaGroupRuleParam{Okta: cloudflaresdk.F(zero_trust.OktaGroupRuleOktaParam{Name: cloudflaresdk.F(v.Value), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "saml":
			rule = zero_trust.SAMLGroupRuleParam{SAML: cloudflaresdk.F(zero_trust.SAMLGroupRuleSAMLParam{AttributeName: cloudflaresdk.F(v.Value), AttributeValue: cloudflaresdk.F(v.Value2), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "oidc":
			rule = zero_trust.AccessRuleAccessOIDCClaimRuleParam{OIDC: cloudflaresdk.F(zero_trust.AccessRuleAccessOIDCClaimRuleOIDCParam{ClaimName: cloudflaresdk.F(v.Value), ClaimValue: cloudflaresdk.F(v.Value2), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "serviceToken":
			rule = zero_trust.ServiceTokenRuleParam{ServiceToken: cloudflaresdk.F(zero_trust.ServiceTokenRuleServiceTokenParam{TokenID: cloudflaresdk.F(v.ID)})}
		case "anyValidServiceToken":
			rule = zero_trust.AnyValidServiceTokenRuleParam{AnyValidServiceToken: cloudflaresdk.F(zero_trust.AnyValidServiceTokenRuleAnyValidServiceTokenParam{})}
		case "externalEvaluation":
			rule = zero_trust.ExternalEvaluationRuleParam{ExternalEvaluation: cloudflaresdk.F(zero_trust.ExternalEvaluationRuleExternalEvaluationParam{EvaluateURL: cloudflaresdk.F(v.Value), KeysURL: cloudflaresdk.F(v.Value2)})}
		case "geo":
			rule = zero_trust.CountryRuleParam{Geo: cloudflaresdk.F(zero_trust.CountryRuleGeoParam{CountryCode: cloudflaresdk.F(v.Value)})}
		case "authMethod":
			rule = zero_trust.AuthenticationMethodRuleParam{AuthMethod: cloudflaresdk.F(zero_trust.AuthenticationMethodRuleAuthMethodParam{AuthMethod: cloudflaresdk.F(v.Value)})}
		case "devicePosture":
			rule = zero_trust.AccessDevicePostureRuleParam{DevicePosture: cloudflaresdk.F(zero_trust.AccessDevicePostureRuleDevicePostureParam{IntegrationUID: cloudflaresdk.F(v.ID), AccountID: cloudflaresdk.F(v.AccountID)})}
		case "loginMethod":
			rule = zero_trust.AccessRuleAccessLoginMethodRuleParam{LoginMethod: cloudflaresdk.F(zero_trust.AccessRuleAccessLoginMethodRuleLoginMethodParam{ID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "authContext":
			rule = zero_trust.AccessRuleAccessAuthContextRuleParam{AuthContext: cloudflaresdk.F(zero_trust.AccessRuleAccessAuthContextRuleAuthContextParam{ID: cloudflaresdk.F(v.Value), AcID: cloudflaresdk.F(v.Value2), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "linkedAppToken":
			rule = zero_trust.AccessRuleAccessLinkedAppTokenRuleParam{LinkedAppToken: cloudflaresdk.F(zero_trust.AccessRuleAccessLinkedAppTokenRuleLinkedAppTokenParam{AppUID: cloudflaresdk.F(v.ID)})}
		case "userRiskScore":
			levels := make([]zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreUserRiskScore, len(v.Values))
			for i := range v.Values {
				levels[i] = zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreUserRiskScore(v.Values[i])
			}
			rule = zero_trust.AccessRuleAccessUserRiskScoreRuleParam{UserRiskScore: cloudflaresdk.F(zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreParam{UserRiskScore: cloudflaresdk.F(levels)})}
		case "cloudflareAccountMember":
			rule = zero_trust.AccessRuleAccessCloudflareAccountMemberRuleParam{CloudflareAccountMember: cloudflaresdk.F(zero_trust.AccessRuleAccessCloudflareAccountMemberRuleCloudflareAccountMemberParam{AccountID: cloudflaresdk.F(v.AccountID)})}
		default:
			return nil, fmt.Errorf("unsupported Access rule kind %q", v.Kind)
		}
		out = append(out, rule)
	}
	return out, nil
}

// CreateIdentityProvider is part of the Flareway API.
func (client *Client) CreateIdentityProvider(ctx context.Context, input IdentityProviderInput) (IdentityProvider, error) {
	body, err := identityProviderBody(input)
	if err != nil {
		return IdentityProvider{}, err
	}
	result, err := client.sdk.ZeroTrust.IdentityProviders.New(ctx, zero_trust.IdentityProviderNewParams{
		AccountID: cloudflaresdk.F(client.accountID), IdentityProvider: body,
	})
	if err != nil {
		return IdentityProvider{}, fmt.Errorf("create Access identity provider: %w", err)
	}
	return identityProviderFromSDK(result), nil
}

// UpdateIdentityProvider is part of the Flareway API.
func (client *Client) UpdateIdentityProvider(ctx context.Context, id string, input IdentityProviderInput) (IdentityProvider, error) {
	body, err := identityProviderBody(input)
	if err != nil {
		return IdentityProvider{}, err
	}
	result, err := client.sdk.ZeroTrust.IdentityProviders.Update(ctx, id, zero_trust.IdentityProviderUpdateParams{
		AccountID: cloudflaresdk.F(client.accountID), IdentityProvider: body,
	})
	if err != nil {
		return IdentityProvider{}, fmt.Errorf("update Access identity provider: %w", err)
	}
	return identityProviderFromSDK(result), nil
}

// GetIdentityProvider is part of the Flareway API.
func (client *Client) GetIdentityProvider(ctx context.Context, id string) (IdentityProvider, error) {
	result, err := client.sdk.ZeroTrust.IdentityProviders.Get(ctx, id, zero_trust.IdentityProviderGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return IdentityProvider{}, fmt.Errorf("get Access identity provider: %w", err)
	}
	return identityProviderFromSDK(result), nil
}

// ListIdentityProviders is part of the Flareway API.
func (client *Client) ListIdentityProviders(ctx context.Context) ([]IdentityProvider, error) {
	pager := client.sdk.ZeroTrust.IdentityProviders.ListAutoPaging(ctx, zero_trust.IdentityProviderListParams{AccountID: cloudflaresdk.F(client.accountID)})
	var result []IdentityProvider
	for pager.Next() {
		value := pager.Current()
		result = append(result, IdentityProvider{ID: value.ID, Name: value.Name, Type: string(value.Type)})
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Access identity providers: %w", err)
	}
	return result, nil
}

// DeleteIdentityProvider is part of the Flareway API.
func (client *Client) DeleteIdentityProvider(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.IdentityProviders.Delete(ctx, id, zero_trust.IdentityProviderDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Access identity provider: %w", err)
	}
	return nil
}

func identityProviderFromSDK(value *zero_trust.IdentityProvider) IdentityProvider {
	return IdentityProvider{ID: value.ID, Name: value.Name, Type: string(value.Type), ReadOnly: value.ReadOnly}
}

func identityProviderBody(input IdentityProviderInput) (zero_trust.IdentityProviderUnionParam, error) {
	config := input.Config
	scim := identityProviderSCIM(input.SCIMConfig)
	switch string(input.Type) {
	case "azureAD":
		return zero_trust.AzureADParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeAzureAD),
			Config: cloudflaresdk.F(zero_trust.AzureADConfigParam{
				Claims: cloudflaresdk.F(config.Claims), ClientID: cloudflaresdk.F(config.ClientID),
				ClientSecret: cloudflaresdk.F(input.ClientSecret), ConditionalAccessEnabled: cloudflaresdk.F(config.ConditionalAccessEnabled),
				DirectoryID: cloudflaresdk.F(config.DirectoryID), EmailClaimName: cloudflaresdk.F(config.EmailClaimName),
				Prompt: cloudflaresdk.F(zero_trust.AzureADConfigPrompt(config.Prompt)), SupportGroups: cloudflaresdk.F(config.SupportGroups),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "centrify":
		return zero_trust.IdentityProviderAccessCentrifyParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeCentrify),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessCentrifyConfigParam{
				CentrifyAccount: cloudflaresdk.F(config.CentrifyAccount), CentrifyAppID: cloudflaresdk.F(config.CentrifyAppID),
				Claims: cloudflaresdk.F(config.Claims), ClientID: cloudflaresdk.F(config.ClientID),
				ClientSecret: cloudflaresdk.F(input.ClientSecret), EmailClaimName: cloudflaresdk.F(config.EmailClaimName),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "google":
		return zero_trust.IdentityProviderAccessGoogleParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeGoogle),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessGoogleConfigParam{
				Claims: cloudflaresdk.F(config.Claims), ClientID: cloudflaresdk.F(config.ClientID),
				ClientSecret: cloudflaresdk.F(input.ClientSecret), EmailClaimName: cloudflaresdk.F(config.EmailClaimName),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "google-apps":
		return zero_trust.IdentityProviderAccessGoogleAppsParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeGoogleApps),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessGoogleAppsConfigParam{
				AppsDomain: cloudflaresdk.F(config.AppsDomain), Claims: cloudflaresdk.F(config.Claims),
				ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret),
				EmailClaimName: cloudflaresdk.F(config.EmailClaimName),
				Prompt:         cloudflaresdk.F(zero_trust.IdentityProviderAccessGoogleAppsConfigPrompt(config.Prompt)),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "oidc":
		return zero_trust.IdentityProviderAccessOIDCParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeOIDC),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessOIDCConfigParam{
				AuthURL: cloudflaresdk.F(config.AuthURL), CERTsURL: cloudflaresdk.F(config.CertsURL),
				Claims: cloudflaresdk.F(config.Claims), ClientID: cloudflaresdk.F(config.ClientID),
				ClientSecret: cloudflaresdk.F(input.ClientSecret), EmailClaimName: cloudflaresdk.F(config.EmailClaimName),
				PKCEEnabled: cloudflaresdk.F(config.PKCEEnabled), Scopes: cloudflaresdk.F(config.Scopes),
				TokenURL: cloudflaresdk.F(config.TokenURL),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "okta":
		return zero_trust.IdentityProviderAccessOktaParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeOkta),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessOktaConfigParam{
				AuthorizationServerID: cloudflaresdk.F(config.AuthorizationServerID), Claims: cloudflaresdk.F(config.Claims),
				ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret),
				EmailClaimName: cloudflaresdk.F(config.EmailClaimName), OktaAccount: cloudflaresdk.F(config.OktaAccount),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "onelogin":
		return zero_trust.IdentityProviderAccessOneloginParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeOnelogin),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessOneloginConfigParam{
				Claims: cloudflaresdk.F(config.Claims), ClientID: cloudflaresdk.F(config.ClientID),
				ClientSecret: cloudflaresdk.F(input.ClientSecret), EmailClaimName: cloudflaresdk.F(config.EmailClaimName),
				OneloginAccount: cloudflaresdk.F(config.OneloginAccount),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "pingone":
		return zero_trust.IdentityProviderAccessPingoneParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypePingone),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessPingoneConfigParam{
				Claims: cloudflaresdk.F(config.Claims), ClientID: cloudflaresdk.F(config.ClientID),
				ClientSecret: cloudflaresdk.F(input.ClientSecret), EmailClaimName: cloudflaresdk.F(config.EmailClaimName),
				PingEnvID: cloudflaresdk.F(config.PingEnvironmentID),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "saml":
		headers := make([]zero_trust.IdentityProviderAccessSAMLConfigHeaderAttributeParam, len(config.HeaderAttributes))
		for i := range config.HeaderAttributes {
			headers[i] = zero_trust.IdentityProviderAccessSAMLConfigHeaderAttributeParam{
				HeaderName:    cloudflaresdk.F(config.HeaderAttributes[i].Name),
				AttributeName: cloudflaresdk.F(config.HeaderAttributes[i].AttributeName),
			}
		}
		return zero_trust.IdentityProviderAccessSAMLParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeSAML),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessSAMLConfigParam{
				Attributes: cloudflaresdk.F(config.Attributes), EmailAttributeName: cloudflaresdk.F(config.EmailAttributeName),
				EnableEncryption: cloudflaresdk.F(config.EnableEncryption), ForceAuthn: cloudflaresdk.F(config.ForceAuthn),
				HeaderAttributes: cloudflaresdk.F(headers), IdPPublicCERTs: cloudflaresdk.F(config.IDPPublicCerts),
				IssuerURL: cloudflaresdk.F(config.IssuerURL), MaxSSOURLLength: cloudflaresdk.F(config.MaxSSOURLLength),
				SignRequest: cloudflaresdk.F(config.SignRequest), SSOTargetURL: cloudflaresdk.F(config.SSOTargetURL),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "onetimepin":
		return zero_trust.IdentityProviderAccessOnetimepinParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeOnetimepin),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessOnetimepinConfigParam{}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "cloudflare":
		return zero_trust.IdentityProviderAccessCloudflareParam{
			Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.IdentityProviderTypeCloudflare),
			Config: cloudflaresdk.F(zero_trust.IdentityProviderAccessCloudflareConfigParam{
				RestrictToAccountMembers: cloudflaresdk.F(config.RestrictToAccountMembers),
			}), SCIMConfig: cloudflaresdk.F(scim),
		}, nil
	case "facebook", "github", "linkedin", "yandex":
		kind := map[string]zero_trust.IdentityProviderType{
			"facebook": zero_trust.IdentityProviderTypeFacebook, "github": zero_trust.IdentityProviderTypeGitHub,
			"linkedin": zero_trust.IdentityProviderTypeLinkedin, "yandex": zero_trust.IdentityProviderTypeYandex,
		}[string(input.Type)]
		body := zero_trust.GenericOAuthConfigParam{ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret)}
		switch string(input.Type) {
		case "facebook":
			return zero_trust.IdentityProviderAccessFacebookParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(kind), Config: cloudflaresdk.F(body), SCIMConfig: cloudflaresdk.F(scim)}, nil
		case "github":
			return zero_trust.IdentityProviderAccessGitHubParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(kind), Config: cloudflaresdk.F(body), SCIMConfig: cloudflaresdk.F(scim)}, nil
		case "linkedin":
			return zero_trust.IdentityProviderAccessLinkedinParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(kind), Config: cloudflaresdk.F(body), SCIMConfig: cloudflaresdk.F(scim)}, nil
		default:
			return zero_trust.IdentityProviderAccessYandexParam{Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(kind), Config: cloudflaresdk.F(body), SCIMConfig: cloudflaresdk.F(scim)}, nil
		}
	default:
		return nil, fmt.Errorf("unsupported identity provider type %q", input.Type)
	}
}

func identityProviderSCIM(value *v1alpha1.IdentityProviderSCIMConfig) zero_trust.IdentityProviderSCIMConfigParam {
	if value == nil {
		return zero_trust.IdentityProviderSCIMConfigParam{}
	}
	return zero_trust.IdentityProviderSCIMConfigParam{
		Enabled:                cloudflaresdk.F(value.Enabled),
		IdentityUpdateBehavior: cloudflaresdk.F(zero_trust.IdentityProviderSCIMConfigIdentityUpdateBehavior(value.IdentityUpdateBehavior)),
		SeatDeprovision:        cloudflaresdk.F(value.SeatDeprovision),
		UserDeprovision:        cloudflaresdk.F(value.UserDeprovision),
	}
}

// CreateDevicePostureRule is part of the Flareway API.
func (client *Client) CreateDevicePostureRule(ctx context.Context, input DevicePostureRuleInput) (DevicePostureRule, error) {
	postureInput, err := deviceInput(input.Input)
	if err != nil {
		return DevicePostureRule{}, err
	}
	result, err := client.sdk.ZeroTrust.Devices.Posture.New(ctx, zero_trust.DevicePostureNewParams{
		AccountID: cloudflaresdk.F(client.accountID), Name: cloudflaresdk.F(input.Name),
		Type:        cloudflaresdk.F(zero_trust.DevicePostureNewParamsType(input.Type)),
		Description: cloudflaresdk.F(input.Description), Schedule: cloudflaresdk.F(input.Schedule),
		Expiration: cloudflaresdk.F(input.Expiration), Match: cloudflaresdk.F(deviceMatches(input.Match)),
		Input: cloudflaresdk.F[zero_trust.DeviceInputUnionParam](postureInput),
	})
	if err != nil {
		return DevicePostureRule{}, fmt.Errorf("create device posture rule: %w", err)
	}
	return devicePostureRuleFromSDK(result), nil
}

// UpdateDevicePostureRule is part of the Flareway API.
func (client *Client) UpdateDevicePostureRule(ctx context.Context, id string, input DevicePostureRuleInput) (DevicePostureRule, error) {
	postureInput, err := deviceInput(input.Input)
	if err != nil {
		return DevicePostureRule{}, err
	}
	result, err := client.sdk.ZeroTrust.Devices.Posture.Update(ctx, id, zero_trust.DevicePostureUpdateParams{
		AccountID: cloudflaresdk.F(client.accountID), Name: cloudflaresdk.F(input.Name),
		Type:        cloudflaresdk.F(zero_trust.DevicePostureUpdateParamsType(input.Type)),
		Description: cloudflaresdk.F(input.Description), Schedule: cloudflaresdk.F(input.Schedule),
		Expiration: cloudflaresdk.F(input.Expiration), Match: cloudflaresdk.F(deviceMatches(input.Match)),
		Input: cloudflaresdk.F[zero_trust.DeviceInputUnionParam](postureInput),
	})
	if err != nil {
		return DevicePostureRule{}, fmt.Errorf("update device posture rule: %w", err)
	}
	return devicePostureRuleFromSDK(result), nil
}

// GetDevicePostureRule is part of the Flareway API.
func (client *Client) GetDevicePostureRule(ctx context.Context, id string) (DevicePostureRule, error) {
	result, err := client.sdk.ZeroTrust.Devices.Posture.Get(ctx, id, zero_trust.DevicePostureGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return DevicePostureRule{}, fmt.Errorf("get device posture rule: %w", err)
	}
	return devicePostureRuleFromSDK(result), nil
}

// ListDevicePostureRules is part of the Flareway API.
func (client *Client) ListDevicePostureRules(ctx context.Context) ([]DevicePostureRule, error) {
	pager := client.sdk.ZeroTrust.Devices.Posture.ListAutoPaging(ctx, zero_trust.DevicePostureListParams{AccountID: cloudflaresdk.F(client.accountID)})
	var result []DevicePostureRule
	for pager.Next() {
		value := pager.Current()
		result = append(result, devicePostureRuleFromSDK(&value))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list device posture rules: %w", err)
	}
	return result, nil
}

// DeleteDevicePostureRule is part of the Flareway API.
func (client *Client) DeleteDevicePostureRule(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Devices.Posture.Delete(ctx, id, zero_trust.DevicePostureDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete device posture rule: %w", err)
	}
	return nil
}

func deviceMatches(values []v1alpha1.DevicePostureMatch) []zero_trust.DeviceMatchParam {
	result := make([]zero_trust.DeviceMatchParam, len(values))
	for i := range values {
		result[i] = zero_trust.DeviceMatchParam{Platform: cloudflaresdk.F(zero_trust.DeviceMatchPlatform(values[i].Platform))}
	}
	return result
}

func deviceInput(value v1alpha1.DevicePostureInput) (zero_trust.DeviceInputParam, error) {
	result := zero_trust.DeviceInputParam{
		ID: cloudflaresdk.F(value.ID), ConnectionID: cloudflaresdk.F(value.ConnectionID),
		OperatingSystem: cloudflaresdk.F(zero_trust.DeviceInputOperatingSystem(value.OperatingSystem)),
		Path:            cloudflaresdk.F(value.Path), Sha256: cloudflaresdk.F(value.SHA256),
		Domain: cloudflaresdk.F(value.Domain), Version: cloudflaresdk.F(value.Version),
		VersionOperator:  cloudflaresdk.F(zero_trust.DeviceInputVersionOperator(value.VersionOperator)),
		Operator:         cloudflaresdk.F(zero_trust.DeviceInputOperator(value.Operator)),
		ComplianceStatus: cloudflaresdk.F(zero_trust.DeviceInputComplianceStatus(value.ComplianceStatus)),
		NetworkStatus:    cloudflaresdk.F(zero_trust.DeviceInputNetworkStatus(value.NetworkStatus)),
		OperationalState: cloudflaresdk.F(zero_trust.DeviceInputOperationalState(value.OperationalState)),
		State:            cloudflaresdk.F(zero_trust.DeviceInputState(value.State)),
		RiskLevel:        cloudflaresdk.F(zero_trust.DeviceInputRiskLevel(value.RiskLevel)),
		LastSeen:         cloudflaresdk.F(value.LastSeen), EidLastSeen: cloudflaresdk.F(value.EIDLastSeen),
		IssueCount: cloudflaresdk.F(value.IssueCount), SensorConfig: cloudflaresdk.F(value.SensorConfig),
		CertificateID: cloudflaresdk.F(value.CertificateID), Cn: cloudflaresdk.F(value.CommonName),
		Thumbprint: cloudflaresdk.F(value.Thumbprint), OS: cloudflaresdk.F(value.OS),
		OSDistroName: cloudflaresdk.F(value.OSDistroName), OSDistroRevision: cloudflaresdk.F(value.OSDistroRevision),
		OSVersionExtra: cloudflaresdk.F(value.OSVersionExtra), Overall: cloudflaresdk.F(value.Overall),
	}
	if value.Enabled != nil {
		result.Enabled = cloudflaresdk.F(*value.Enabled)
	}
	if value.Exists != nil {
		result.Exists = cloudflaresdk.F(*value.Exists)
	}
	if value.RequireAll != nil {
		result.RequireAll = cloudflaresdk.F(*value.RequireAll)
	}
	if value.Infected != nil {
		result.Infected = cloudflaresdk.F(*value.Infected)
	}
	if value.IsActive != nil {
		result.IsActive = cloudflaresdk.F(*value.IsActive)
	}
	if value.CheckPrivateKey != nil {
		result.CheckPrivateKey = cloudflaresdk.F(*value.CheckPrivateKey)
	}
	if value.Score != "" {
		number, err := parsePostureFloat("score", value.Score)
		if err != nil {
			return zero_trust.DeviceInputParam{}, err
		}
		result.Score = cloudflaresdk.F(number)
	}
	if value.TotalScore != "" {
		number, err := parsePostureFloat("totalScore", value.TotalScore)
		if err != nil {
			return zero_trust.DeviceInputParam{}, err
		}
		result.TotalScore = cloudflaresdk.F(number)
	}
	if value.ActiveThreats != "" {
		number, err := parsePostureFloat("activeThreats", value.ActiveThreats)
		if err != nil {
			return zero_trust.DeviceInputParam{}, err
		}
		result.ActiveThreats = cloudflaresdk.F(number)
	}
	if value.UpdateWindowDays != "" {
		number, err := parsePostureFloat("updateWindowDays", value.UpdateWindowDays)
		if err != nil {
			return zero_trust.DeviceInputParam{}, err
		}
		result.UpdateWindowDays = cloudflaresdk.F(number)
	}
	return result, nil
}

func parsePostureFloat(field, value string) (float64, error) {
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("parse device posture %s %q: %w", field, value, err)
	}
	return number, nil
}

func devicePostureRuleFromSDK(value *zero_trust.DevicePostureRule) DevicePostureRule {
	return DevicePostureRule{
		ID: value.ID, Name: value.Name, Type: string(value.Type), Description: value.Description,
		Enabled: value.Enabled, Schedule: value.Schedule, Expiration: value.Expiration,
	}
}

// CreateServiceToken is part of the Flareway API.
func (client *Client) CreateServiceToken(ctx context.Context, input ServiceTokenInput) (ServiceTokenSecret, error) {
	result, err := client.sdk.ZeroTrust.Access.ServiceTokens.New(ctx, zero_trust.AccessServiceTokenNewParams{
		AccountID: cloudflaresdk.F(client.accountID), Name: cloudflaresdk.F(input.Name),
		Duration: cloudflaresdk.F(input.Duration), Enabled: cloudflaresdk.F(true),
	})
	if err != nil {
		return ServiceTokenSecret{}, fmt.Errorf("create Access service token: %w", err)
	}
	return ServiceTokenSecret{ServiceToken: ServiceToken{ID: result.ID, ClientID: result.ClientID, Name: result.Name, Duration: result.Duration, Enabled: result.Enabled}, ClientSecret: result.ClientSecret}, nil
}

// UpdateServiceToken is part of the Flareway API.
func (client *Client) UpdateServiceToken(ctx context.Context, id string, input ServiceTokenInput) (ServiceToken, error) {
	result, err := client.sdk.ZeroTrust.Access.ServiceTokens.Update(ctx, id, zero_trust.AccessServiceTokenUpdateParams{
		AccountID: cloudflaresdk.F(client.accountID), Name: cloudflaresdk.F(input.Name),
		Duration: cloudflaresdk.F(input.Duration), Enabled: cloudflaresdk.F(true),
	})
	if err != nil {
		return ServiceToken{}, fmt.Errorf("update Access service token: %w", err)
	}
	return serviceTokenFromSDK(result), nil
}

// GetServiceToken is part of the Flareway API.
func (client *Client) GetServiceToken(ctx context.Context, id string) (ServiceToken, error) {
	result, err := client.sdk.ZeroTrust.Access.ServiceTokens.Get(ctx, id, zero_trust.AccessServiceTokenGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return ServiceToken{}, fmt.Errorf("get Access service token: %w", err)
	}
	return serviceTokenFromSDK(result), nil
}

// ListServiceTokens is part of the Flareway API.
func (client *Client) ListServiceTokens(ctx context.Context) ([]ServiceToken, error) {
	pager := client.sdk.ZeroTrust.Access.ServiceTokens.ListAutoPaging(ctx, zero_trust.AccessServiceTokenListParams{AccountID: cloudflaresdk.F(client.accountID)})
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
func (client *Client) DeleteServiceToken(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Access.ServiceTokens.Delete(ctx, id, zero_trust.AccessServiceTokenDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
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
