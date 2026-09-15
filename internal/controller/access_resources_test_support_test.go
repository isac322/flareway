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

package controller

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

type fakeAccessResourceCloudflare struct {
	flarecloudflare.AccessAPI
	mu           sync.Mutex
	next         int
	policies     map[string]flarecloudflare.AccessPolicy
	groups       map[string]flarecloudflare.AccessGroup
	providers    map[string]flarecloudflare.IdentityProvider
	posture      map[string]flarecloudflare.DevicePostureRule
	tokens       map[string]flarecloudflare.ServiceToken
	secrets      map[string]string
	tokenCreates int
	rotations    int
	clientCalls  int
	clientErr    error
}

func newFakeAccessResourceCloudflare() *fakeAccessResourceCloudflare {
	fake := &fakeAccessResourceCloudflare{}
	fake.reset()
	return fake
}
func (f *fakeAccessResourceCloudflare) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next = 0
	f.policies = map[string]flarecloudflare.AccessPolicy{}
	f.groups = map[string]flarecloudflare.AccessGroup{}
	f.providers = map[string]flarecloudflare.IdentityProvider{}
	f.posture = map[string]flarecloudflare.DevicePostureRule{}
	f.tokens = map[string]flarecloudflare.ServiceToken{}
	f.secrets = map[string]string{}
	f.tokenCreates = 0
	f.rotations = 0
	f.clientCalls = 0
	f.clientErr = nil
}
func (f *fakeAccessResourceCloudflare) Client(string, string) (flarecloudflare.AccessAPI, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clientCalls++
	return f, f.clientErr
}
func (f *fakeAccessResourceCloudflare) newID(prefix string) string {
	f.next++
	return fmt.Sprintf("%s-%d", prefix, f.next)
}
func cloneResolvedAccessRules(in []flarecloudflare.ResolvedAccessRule) []flarecloudflare.ResolvedAccessRule {
	if in == nil {
		return nil
	}
	out := make([]flarecloudflare.ResolvedAccessRule, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Values = append([]string(nil), in[i].Values...)
	}
	return out
}

func fakeAccessPolicy(id string, in flarecloudflare.AccessPolicyInput) flarecloudflare.AccessPolicy {
	v := flarecloudflare.AccessPolicy{
		ID: id, Name: in.Name, Decision: in.Decision,
		Include:         cloneResolvedAccessRules(in.Include),
		Require:         cloneResolvedAccessRules(in.Require),
		Exclude:         cloneResolvedAccessRules(in.Exclude),
		SessionDuration: in.SessionDuration, PurposeJustificationPrompt: in.PurposeJustificationPrompt,
		ApprovalGroups: append([]flarecloudflare.AccessApprovalGroup(nil), in.ApprovalGroups...),
	}
	if in.PurposeJustificationRequired != nil {
		v.PurposeJustificationRequired = *in.PurposeJustificationRequired
	}
	if in.ApprovalRequired != nil {
		v.ApprovalRequired = *in.ApprovalRequired
	}
	if in.IsolationRequired != nil {
		v.IsolationRequired = *in.IsolationRequired
	}
	if in.ConnectionRules != nil {
		v.ConnectionRules = *in.ConnectionRules
	}
	if in.MFAConfig != nil {
		v.MFAConfig = *in.MFAConfig
	}
	return v
}

func (f *fakeAccessResourceCloudflare) CreateAccessPolicy(_ context.Context, in flarecloudflare.AccessPolicyInput) (flarecloudflare.AccessPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := fakeAccessPolicy(f.newID("policy"), in)
	f.policies[v.ID] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) UpdateAccessPolicy(_ context.Context, id string, in flarecloudflare.AccessPolicyInput) (flarecloudflare.AccessPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := fakeAccessPolicy(id, in)
	f.policies[id] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) GetAccessPolicy(_ context.Context, id string) (flarecloudflare.AccessPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.policies[id]
	if !ok {
		return v, fmt.Errorf("policy not found")
	}
	return v, nil
}
func (f *fakeAccessResourceCloudflare) ListAccessPolicies(context.Context) ([]flarecloudflare.AccessPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]flarecloudflare.AccessPolicy, 0, len(f.policies))
	for _, v := range f.policies {
		out = append(out, v)
	}
	return out, nil
}
func (f *fakeAccessResourceCloudflare) DeleteAccessPolicy(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.policies, id)
	return nil
}
func fakeAccessGroupKey(scope flarecloudflare.AccessScope, id string) string {
	if scope.ZoneID == "" {
		return id
	}
	return "zone:" + scope.ZoneID + "/" + id
}

func fakeAccessGroup(id string, in flarecloudflare.AccessGroupInput) flarecloudflare.AccessGroup {
	isDefault := in.IsDefault
	return flarecloudflare.AccessGroup{
		ID: id, Name: in.Name,
		Include:   cloneResolvedAccessRules(in.Include),
		Require:   cloneResolvedAccessRules(in.Require),
		Exclude:   cloneResolvedAccessRules(in.Exclude),
		IsDefault: &isDefault,
	}
}

func (f *fakeAccessResourceCloudflare) onlyAccessGroupID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.groups) != 1 {
		return ""
	}
	for _, group := range f.groups {
		return group.ID
	}
	return ""
}

func (f *fakeAccessResourceCloudflare) CreateAccessGroup(_ context.Context, scope flarecloudflare.AccessScope, in flarecloudflare.AccessGroupInput) (flarecloudflare.AccessGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := fakeAccessGroup(f.newID("group"), in)
	f.groups[fakeAccessGroupKey(scope, v.ID)] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) UpdateAccessGroup(_ context.Context, scope flarecloudflare.AccessScope, id string, in flarecloudflare.AccessGroupInput) (flarecloudflare.AccessGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := fakeAccessGroup(id, in)
	f.groups[fakeAccessGroupKey(scope, id)] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) GetAccessGroup(_ context.Context, scope flarecloudflare.AccessScope, id string) (flarecloudflare.AccessGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.groups[fakeAccessGroupKey(scope, id)]
	if !ok {
		return v, fmt.Errorf("group not found")
	}
	return v, nil
}
func (f *fakeAccessResourceCloudflare) ListAccessGroups(_ context.Context, options flarecloudflare.AccessGroupListOptions) ([]flarecloudflare.AccessGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]flarecloudflare.AccessGroup, 0, len(f.groups))
	prefix := ""
	if options.Scope.ZoneID != "" {
		prefix = "zone:" + options.Scope.ZoneID + "/"
	}
	for key, v := range f.groups {
		inScope := (prefix == "" && !strings.HasPrefix(key, "zone:")) || (prefix != "" && strings.HasPrefix(key, prefix))
		if inScope && (options.Name == "" || v.Name == options.Name) && (options.Search == "" || strings.Contains(v.Name, options.Search)) {
			out = append(out, v)
		}
	}
	return out, nil
}
func (f *fakeAccessResourceCloudflare) DeleteAccessGroup(_ context.Context, scope flarecloudflare.AccessScope, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.groups, fakeAccessGroupKey(scope, id))
	return nil
}
func fakeIdentityProvider(id string, in flarecloudflare.IdentityProviderInput) flarecloudflare.IdentityProvider {
	config := *in.Config.DeepCopy()
	config.ClientSecretRef = nil
	var scim *v1alpha1.IdentityProviderSCIMConfig
	if in.SCIMConfig != nil {
		scimConfigCopy := *in.SCIMConfig.DeepCopy()
		scimConfigCopy.SecretRef = nil
		scim = &scimConfigCopy
	}
	return flarecloudflare.IdentityProvider{
		ID: id, Name: in.Name, Type: in.Type, Config: config, SCIMConfig: scim,
		SAMLCertificateSetID: in.SAMLCertificateSetID,
	}
}

func (f *fakeAccessResourceCloudflare) CreateIdentityProvider(_ context.Context, in flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := fakeIdentityProvider(f.newID("idp"), in)
	f.providers[v.ID] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) UpdateIdentityProvider(_ context.Context, id string, in flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := fakeIdentityProvider(id, in)
	f.providers[id] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) GetIdentityProvider(_ context.Context, id string) (flarecloudflare.IdentityProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.providers[id]
	if !ok {
		return v, fmt.Errorf("identity provider not found")
	}
	return v, nil
}
func (f *fakeAccessResourceCloudflare) ListIdentityProviders(context.Context) ([]flarecloudflare.IdentityProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]flarecloudflare.IdentityProvider, 0, len(f.providers))
	for _, v := range f.providers {
		out = append(out, v)
	}
	return out, nil
}
func (f *fakeAccessResourceCloudflare) DeleteIdentityProvider(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.providers, id)
	return nil
}
func fakeDevicePostureRule(id string, in flarecloudflare.DevicePostureRuleInput) flarecloudflare.DevicePostureRule {
	input := *in.Input.DeepCopy()
	if in.ConnectionID != "" {
		input.IntegrationRef = &v1alpha1.DevicePostureIntegrationReference{ExternalID: in.ConnectionID}
	}
	return flarecloudflare.DevicePostureRule{
		ID: id, Name: in.Name, Type: in.Type, Description: in.Description, Enabled: true,
		Schedule: in.Schedule, Expiration: in.Expiration,
		Match: append([]v1alpha1.DevicePostureMatch(nil), in.Match...), Input: input,
	}
}

func (f *fakeAccessResourceCloudflare) CreateDevicePostureRule(_ context.Context, in flarecloudflare.DevicePostureRuleInput) (flarecloudflare.DevicePostureRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := fakeDevicePostureRule(f.newID("posture"), in)
	f.posture[v.ID] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) UpdateDevicePostureRule(_ context.Context, id string, in flarecloudflare.DevicePostureRuleInput) (flarecloudflare.DevicePostureRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := fakeDevicePostureRule(id, in)
	f.posture[id] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) GetDevicePostureRule(_ context.Context, id string) (flarecloudflare.DevicePostureRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.posture[id]
	if !ok {
		return v, fmt.Errorf("posture rule not found")
	}
	return v, nil
}
func (f *fakeAccessResourceCloudflare) ListDevicePostureRules(context.Context) ([]flarecloudflare.DevicePostureRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]flarecloudflare.DevicePostureRule, 0, len(f.posture))
	for _, v := range f.posture {
		out = append(out, v)
	}
	return out, nil
}
func (f *fakeAccessResourceCloudflare) DeleteDevicePostureRule(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.posture, id)
	return nil
}
func fakeServiceTokenKey(scope flarecloudflare.AccessScope, id string) string {
	if scope.ZoneID == "" {
		return id
	}
	return "zone:" + scope.ZoneID + "/" + id
}

func (f *fakeAccessResourceCloudflare) CreateServiceToken(_ context.Context, scope flarecloudflare.AccessScope, in flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceTokenSecret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenCreates++
	id := f.newID("token")
	v := flarecloudflare.ServiceToken{ID: id, ClientID: "client-" + id, Name: in.Name, Duration: in.Duration, Enabled: in.Enabled, ExpiresAt: time.Now().Add(365 * 24 * time.Hour)}
	key := fakeServiceTokenKey(scope, id)
	f.tokens[key] = v
	secret := "secret-" + id
	f.secrets[key] = secret
	return flarecloudflare.ServiceTokenSecret{ServiceToken: v, ClientSecret: secret}, nil
}
func (f *fakeAccessResourceCloudflare) UpdateServiceToken(_ context.Context, scope flarecloudflare.AccessScope, id string, in flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fakeServiceTokenKey(scope, id)
	v := f.tokens[key]
	v.Name = in.Name
	v.Duration = in.Duration
	v.Enabled = in.Enabled
	f.tokens[key] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) GetServiceToken(_ context.Context, scope flarecloudflare.AccessScope, id string) (flarecloudflare.ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.tokens[fakeServiceTokenKey(scope, id)]
	if !ok {
		return v, fmt.Errorf("service token not found")
	}
	return v, nil
}
func (f *fakeAccessResourceCloudflare) ListServiceTokens(_ context.Context, scope flarecloudflare.AccessScope) ([]flarecloudflare.ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]flarecloudflare.ServiceToken, 0, len(f.tokens))
	prefix := ""
	if scope.ZoneID != "" {
		prefix = "zone:" + scope.ZoneID + "/"
	}
	for key, v := range f.tokens {
		if (prefix == "" && !strings.HasPrefix(key, "zone:")) || (prefix != "" && strings.HasPrefix(key, prefix)) {
			out = append(out, v)
		}
	}
	return out, nil
}
func (f *fakeAccessResourceCloudflare) DeleteServiceToken(_ context.Context, scope flarecloudflare.AccessScope, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fakeServiceTokenKey(scope, id)
	delete(f.tokens, key)
	delete(f.secrets, key)
	return nil
}
func (f *fakeAccessResourceCloudflare) RotateServiceToken(_ context.Context, id string, _ time.Time) (flarecloudflare.ServiceTokenSecret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.tokens[id]
	f.rotations++
	secret := fmt.Sprintf("rotated-%d", f.rotations)
	f.secrets[id] = secret
	return flarecloudflare.ServiceTokenSecret{ServiceToken: v, ClientSecret: secret}, nil
}
func (f *fakeAccessResourceCloudflare) RefreshServiceToken(_ context.Context, id string) (flarecloudflare.ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.tokens[id]
	v.ExpiresAt = time.Now().Add(365 * 24 * time.Hour)
	f.tokens[id] = v
	return v, nil
}
