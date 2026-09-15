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
	"slices"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

type fakeGlobalDeviceCloudflare struct {
	mu       sync.Mutex
	settings flarecloudflare.DeviceSettings
	calls    []string
}

func (f *fakeGlobalDeviceCloudflare) Client(_, _ string) (flarecloudflare.DeviceSettingsAPI, error) {
	return f, nil
}
func (f *fakeGlobalDeviceCloudflare) GetDeviceSettings(context.Context) (flarecloudflare.DeviceSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GetDeviceSettings")
	return f.settings, nil
}
func (f *fakeGlobalDeviceCloudflare) UpdateDeviceSettings(_ context.Context, input flarecloudflare.DeviceSettingsInput) (flarecloudflare.DeviceSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateDeviceSettings")
	if input.GatewayProxyEnabled != nil {
		f.settings.GatewayProxyEnabled = *input.GatewayProxyEnabled
	}
	if input.GatewayUDPProxyEnabled != nil {
		f.settings.GatewayUDPProxyEnabled = *input.GatewayUDPProxyEnabled
	}
	if input.RootCertificateInstallationEnabled != nil {
		f.settings.RootCertificateInstallationEnabled = *input.RootCertificateInstallationEnabled
	}
	if input.UseZTVirtualIP != nil {
		f.settings.UseZTVirtualIP = *input.UseZTVirtualIP
	}
	if input.DisableForTime != nil {
		f.settings.DisableForTime = *input.DisableForTime
	}
	return f.settings, nil
}
func (f *fakeGlobalDeviceCloudflare) reset(settings flarecloudflare.DeviceSettings) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settings = settings
	f.calls = nil
}
func (f *fakeGlobalDeviceCloudflare) count(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, current := range f.calls {
		if current == call {
			count++
		}
	}
	return count
}

type fakeGlobalOrganizationCloudflare struct {
	mu           sync.Mutex
	organization flarecloudflare.Organization
	calls        []string
}

func (f *fakeGlobalOrganizationCloudflare) Client(_, _ string) (flarecloudflare.OrganizationAPI, error) {
	return f, nil
}
func (f *fakeGlobalOrganizationCloudflare) GetOrganization(context.Context) (flarecloudflare.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GetOrganization")
	return f.organization, nil
}
func (f *fakeGlobalOrganizationCloudflare) UpdateOrganization(_ context.Context, input flarecloudflare.OrganizationInput) (flarecloudflare.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateOrganization")
	if input.SessionDuration != nil {
		f.organization.SessionDuration = *input.SessionDuration
	}
	if input.WARPAuthSessionDuration != nil {
		f.organization.WARPAuthSessionDuration = *input.WARPAuthSessionDuration
	}
	if input.AllowAuthenticateViaWARP != nil {
		f.organization.AllowAuthenticateViaWARP = *input.AllowAuthenticateViaWARP
	}
	if input.IsUIReadOnly != nil {
		f.organization.IsUIReadOnly = *input.IsUIReadOnly
	}
	if input.DenyUnmatchedRequests != nil {
		f.organization.DenyUnmatchedRequests = *input.DenyUnmatchedRequests
	}
	if input.WARPAuthNonBrowser401 != nil {
		f.organization.WARPAuthNonBrowser401 = *input.WARPAuthNonBrowser401
	}
	return f.organization, nil
}
func (f *fakeGlobalOrganizationCloudflare) reset(organization flarecloudflare.Organization) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.organization = organization
	f.calls = nil
}
func (f *fakeGlobalOrganizationCloudflare) count(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, current := range f.calls {
		if current == call {
			count++
		}
	}
	return count
}

type fakeGlobalGatewayCloudflare struct {
	mu    sync.Mutex
	next  int
	rules map[string]flarecloudflare.GatewayRule
	lists map[string]flarecloudflare.GatewayList
	calls []string
}

func newFakeGlobalGatewayCloudflare() *fakeGlobalGatewayCloudflare {
	f := new(fakeGlobalGatewayCloudflare)
	f.reset()
	return f
}
func (f *fakeGlobalGatewayCloudflare) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next = 0
	f.rules = map[string]flarecloudflare.GatewayRule{}
	f.lists = map[string]flarecloudflare.GatewayList{}
	f.calls = nil
}
func (f *fakeGlobalGatewayCloudflare) Client(_, _ string) (flarecloudflare.GatewayAPI, error) {
	return f, nil
}
func (f *fakeGlobalGatewayCloudflare) id(kind string) string {
	f.next++
	return fmt.Sprintf("%s-%d", kind, f.next)
}
func (f *fakeGlobalGatewayCloudflare) missing(resource, id string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "cloudflare", Resource: resource}, id)
}
func (f *fakeGlobalGatewayCloudflare) CreateGatewayRule(_ context.Context, input flarecloudflare.GatewayRuleInput) (flarecloudflare.GatewayRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "CreateGatewayRule")
	remote := gatewayRuleFromFakeInput(f.id("rule"), input)
	f.rules[remote.ID] = remote
	return remote, nil
}
func (f *fakeGlobalGatewayCloudflare) UpdateGatewayRule(_ context.Context, id string, input flarecloudflare.GatewayRuleInput) (flarecloudflare.GatewayRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateGatewayRule")
	if _, ok := f.rules[id]; !ok {
		return flarecloudflare.GatewayRule{}, f.missing("gatewayrules", id)
	}
	remote := gatewayRuleFromFakeInput(id, input)
	f.rules[id] = remote
	return remote, nil
}
func (f *fakeGlobalGatewayCloudflare) GetGatewayRule(_ context.Context, id string) (flarecloudflare.GatewayRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GetGatewayRule")
	remote, ok := f.rules[id]
	if !ok {
		return flarecloudflare.GatewayRule{}, f.missing("gatewayrules", id)
	}
	return remote, nil
}
func (f *fakeGlobalGatewayCloudflare) ListGatewayRules(context.Context) ([]flarecloudflare.GatewayRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ListGatewayRules")
	result := make([]flarecloudflare.GatewayRule, 0, len(f.rules))
	for _, remote := range f.rules {
		result = append(result, remote)
	}
	slices.SortFunc(result, func(a, b flarecloudflare.GatewayRule) int { return compareStrings(a.ID, b.ID) })
	return result, nil
}
func (f *fakeGlobalGatewayCloudflare) DeleteGatewayRule(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "DeleteGatewayRule")
	delete(f.rules, id)
	return nil
}
func (f *fakeGlobalGatewayCloudflare) CreateGatewayList(_ context.Context, input flarecloudflare.GatewayListInput) (flarecloudflare.GatewayList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "CreateGatewayList")
	id := f.id("list")
	remote := flarecloudflare.GatewayList{ID: id, Name: input.Name, Type: input.Type, Items: append([]flarecloudflare.GatewayListItem(nil), input.Items...), Count: int64(len(input.Items))}
	f.lists[id] = remote
	return remote, nil
}
func (f *fakeGlobalGatewayCloudflare) UpdateGatewayList(_ context.Context, id, name string) (flarecloudflare.GatewayList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateGatewayList")
	remote, ok := f.lists[id]
	if !ok {
		return flarecloudflare.GatewayList{}, f.missing("gatewaylists", id)
	}
	remote.Name = name
	f.lists[id] = remote
	return remote, nil
}
func (f *fakeGlobalGatewayCloudflare) GetGatewayList(_ context.Context, id string) (flarecloudflare.GatewayList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GetGatewayList")
	remote, ok := f.lists[id]
	if !ok {
		return flarecloudflare.GatewayList{}, f.missing("gatewaylists", id)
	}
	remote.Items = append([]flarecloudflare.GatewayListItem(nil), remote.Items...)
	return remote, nil
}
func (f *fakeGlobalGatewayCloudflare) ListGatewayLists(context.Context) ([]flarecloudflare.GatewayList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ListGatewayLists")
	result := make([]flarecloudflare.GatewayList, 0, len(f.lists))
	for _, remote := range f.lists {
		result = append(result, remote)
	}
	slices.SortFunc(result, func(a, b flarecloudflare.GatewayList) int { return compareStrings(a.ID, b.ID) })
	return result, nil
}
func (f *fakeGlobalGatewayCloudflare) DeleteGatewayList(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "DeleteGatewayList")
	delete(f.lists, id)
	return nil
}
func (f *fakeGlobalGatewayCloudflare) ReplaceGatewayListItems(_ context.Context, id, name string, items []flarecloudflare.GatewayListItem) (flarecloudflare.GatewayList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ReplaceGatewayListItems")
	remote, ok := f.lists[id]
	if !ok {
		return flarecloudflare.GatewayList{}, f.missing("gatewaylists", id)
	}
	remote.Name = name
	remote.Items = append([]flarecloudflare.GatewayListItem(nil), items...)
	remote.Count = int64(len(items))
	f.lists[id] = remote
	return remote, nil
}
func (f *fakeGlobalGatewayCloudflare) count(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, current := range f.calls {
		if current == call {
			count++
		}
	}
	return count
}
func (f *fakeGlobalGatewayCloudflare) putList(remote flarecloudflare.GatewayList) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists[remote.ID] = remote
}

func gatewayRuleFromFakeInput(id string, input flarecloudflare.GatewayRuleInput) flarecloudflare.GatewayRule {
	remote := flarecloudflare.GatewayRule{ID: id, Name: input.Name, Filters: append([]flarecloudflare.GatewayRuleFilter(nil), input.Filters...), Action: input.Action, Traffic: input.Traffic}
	if input.Description != nil {
		remote.Description = *input.Description
	}
	if input.Enabled != nil {
		remote.Enabled = *input.Enabled
	}
	if input.Precedence != nil {
		remote.Precedence = *input.Precedence
	}
	if input.Identity != nil {
		remote.Identity = *input.Identity
	}
	if input.DevicePosture != nil {
		remote.DevicePosture = *input.DevicePosture
	}
	if input.RuleSettings != nil {
		remote.RuleSettings = *input.RuleSettings
	}
	return remote
}
func compareStrings(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
func (f *fakeGlobalGatewayCloudflare) putRule(remote flarecloudflare.GatewayRule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[remote.ID] = remote
}
func (f *fakeGlobalGatewayCloudflare) rule(id string) (flarecloudflare.GatewayRule, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	remote, ok := f.rules[id]
	return remote, ok
}
func (f *fakeGlobalGatewayCloudflare) list(id string) (flarecloudflare.GatewayList, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	remote, ok := f.lists[id]
	return remote, ok
}
