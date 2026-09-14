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
	"sync"
	"time"

	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

type fakeAccessResourceCloudflare struct {
	flarecloudflare.AccessAPI
	mu          sync.Mutex
	next        int
	policies    map[string]flarecloudflare.AccessPolicy
	groups      map[string]flarecloudflare.AccessGroup
	providers   map[string]flarecloudflare.IdentityProvider
	posture     map[string]flarecloudflare.DevicePostureRule
	tokens      map[string]flarecloudflare.ServiceToken
	secrets     map[string]string
	rotations   int
	clientCalls int
	clientErr   error
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
func (f *fakeAccessResourceCloudflare) CreateAccessPolicy(_ context.Context, in flarecloudflare.AccessPolicyInput) (flarecloudflare.AccessPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := flarecloudflare.AccessPolicy{ID: f.newID("policy"), Name: in.Name, Decision: in.Decision, SessionDuration: in.SessionDuration}
	f.policies[v.ID] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) UpdateAccessPolicy(_ context.Context, id string, in flarecloudflare.AccessPolicyInput) (flarecloudflare.AccessPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := flarecloudflare.AccessPolicy{ID: id, Name: in.Name, Decision: in.Decision, SessionDuration: in.SessionDuration}
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
func (f *fakeAccessResourceCloudflare) CreateAccessGroup(_ context.Context, in flarecloudflare.AccessGroupInput) (flarecloudflare.AccessGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := flarecloudflare.AccessGroup{ID: f.newID("group"), Name: in.Name}
	f.groups[v.ID] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) UpdateAccessGroup(_ context.Context, id string, in flarecloudflare.AccessGroupInput) (flarecloudflare.AccessGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := flarecloudflare.AccessGroup{ID: id, Name: in.Name}
	f.groups[id] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) GetAccessGroup(_ context.Context, id string) (flarecloudflare.AccessGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.groups[id]
	if !ok {
		return v, fmt.Errorf("group not found")
	}
	return v, nil
}
func (f *fakeAccessResourceCloudflare) ListAccessGroups(context.Context) ([]flarecloudflare.AccessGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]flarecloudflare.AccessGroup, 0, len(f.groups))
	for _, v := range f.groups {
		out = append(out, v)
	}
	return out, nil
}
func (f *fakeAccessResourceCloudflare) DeleteAccessGroup(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.groups, id)
	return nil
}
func (f *fakeAccessResourceCloudflare) CreateIdentityProvider(_ context.Context, in flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := flarecloudflare.IdentityProvider{ID: f.newID("idp"), Name: in.Name, Type: string(in.Type)}
	f.providers[v.ID] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) UpdateIdentityProvider(_ context.Context, id string, in flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := flarecloudflare.IdentityProvider{ID: id, Name: in.Name, Type: string(in.Type)}
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
func (f *fakeAccessResourceCloudflare) CreateDevicePostureRule(_ context.Context, in flarecloudflare.DevicePostureRuleInput) (flarecloudflare.DevicePostureRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := flarecloudflare.DevicePostureRule{ID: f.newID("posture"), Name: in.Name, Type: string(in.Type), Description: in.Description, Enabled: true, Schedule: in.Schedule, Expiration: in.Expiration}
	f.posture[v.ID] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) UpdateDevicePostureRule(_ context.Context, id string, in flarecloudflare.DevicePostureRuleInput) (flarecloudflare.DevicePostureRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := flarecloudflare.DevicePostureRule{ID: id, Name: in.Name, Type: string(in.Type), Description: in.Description, Enabled: true, Schedule: in.Schedule, Expiration: in.Expiration}
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
func (f *fakeAccessResourceCloudflare) CreateServiceToken(_ context.Context, in flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceTokenSecret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.newID("token")
	v := flarecloudflare.ServiceToken{ID: id, ClientID: "client-" + id, Name: in.Name, Duration: in.Duration, Enabled: true, ExpiresAt: time.Now().Add(365 * 24 * time.Hour)}
	f.tokens[id] = v
	secret := "secret-" + id
	f.secrets[id] = secret
	return flarecloudflare.ServiceTokenSecret{ServiceToken: v, ClientSecret: secret}, nil
}
func (f *fakeAccessResourceCloudflare) UpdateServiceToken(_ context.Context, id string, in flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.tokens[id]
	v.Name = in.Name
	v.Duration = in.Duration
	f.tokens[id] = v
	return v, nil
}
func (f *fakeAccessResourceCloudflare) GetServiceToken(_ context.Context, id string) (flarecloudflare.ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.tokens[id]
	if !ok {
		return v, fmt.Errorf("service token not found")
	}
	return v, nil
}
func (f *fakeAccessResourceCloudflare) ListServiceTokens(context.Context) ([]flarecloudflare.ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]flarecloudflare.ServiceToken, 0, len(f.tokens))
	for _, v := range f.tokens {
		out = append(out, v)
	}
	return out, nil
}
func (f *fakeAccessResourceCloudflare) DeleteServiceToken(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tokens, id)
	delete(f.secrets, id)
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
