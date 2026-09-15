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
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestAccessGroupScopeUsesVerifiedZoneID(t *testing.T) {
	t.Parallel()

	accountScope, err := accessGroupScope("", nil)
	if err != nil || accountScope.ZoneID != "" {
		t.Fatalf("account scope = %#v, %v", accountScope, err)
	}
	zoneScope, err := accessGroupScope("Example.COM.", []v1alpha1.CloudflareVerifiedZone{{ID: "zone-id", Name: "example.com"}})
	if err != nil || zoneScope.ZoneID != "zone-id" {
		t.Fatalf("zone scope = %#v, %v", zoneScope, err)
	}
	if _, err := accessGroupScope("example.com", []v1alpha1.CloudflareVerifiedZone{{Name: "example.com"}}); err == nil {
		t.Fatal("expected a verified zone without an ID to fail")
	}
	if _, err := accessGroupScope("missing.example", []v1alpha1.CloudflareVerifiedZone{{ID: "zone-id", Name: "example.com"}}); err == nil {
		t.Fatal("expected an unverified zone to fail")
	}
}

func TestAccessGroupEnsureManagedSkipsConvergedUpdate(t *testing.T) {
	t.Parallel()

	isDefault := true
	input := accessGroupParityInput("managed")
	remote := accessGroupParityRemote("group-id", input, &isDefault)
	fake := &accessGroupParityCloudflare{groups: map[string]flarecloudflare.AccessGroup{remote.ID: remote}}
	object := &v1alpha1.AccessGroup{
		ObjectMeta: metav1.ObjectMeta{Generation: 4},
		Status: v1alpha1.AccessGroupStatus{
			GroupID: "group-id", OwnershipVerified: true, ObservedGeneration: 4,
		},
	}
	scope := flarecloudflare.AccessScope{ZoneID: "zone-id"}

	observed, owned, conflict, err := (&AccessGroupReconciler{}).ensureManaged(context.Background(), fake, scope, object, input)
	if err != nil || conflict != "" || !owned {
		t.Fatalf("ensure managed = remote %#v, owned %t, conflict %q, err %v", observed, owned, conflict, err)
	}
	if fake.updates != 0 {
		t.Fatalf("converged group caused %d updates", fake.updates)
	}
	if fake.getScope != scope {
		t.Fatalf("get scope = %#v, want %#v", fake.getScope, scope)
	}
}

func TestAccessGroupEnsureManagedAppliesUnobservableDefaultOncePerSpecGeneration(t *testing.T) {
	t.Parallel()

	input := accessGroupParityInput("managed")
	remote := accessGroupParityRemote("group-id", input, nil)
	fake := &accessGroupParityCloudflare{groups: map[string]flarecloudflare.AccessGroup{remote.ID: remote}}
	object := &v1alpha1.AccessGroup{
		ObjectMeta: metav1.ObjectMeta{Generation: 7},
		Status: v1alpha1.AccessGroupStatus{
			GroupID: "group-id", OwnershipVerified: true, ObservedGeneration: 6,
		},
	}

	_, owned, conflict, err := (&AccessGroupReconciler{}).ensureManaged(context.Background(), fake, flarecloudflare.AccessScope{}, object, input)
	if err != nil || conflict != "" || !owned {
		t.Fatalf("ensure managed = owned %t, conflict %q, err %v", owned, conflict, err)
	}
	if fake.updates != 1 {
		t.Fatalf("unobservable isDefault update count = %d, want 1", fake.updates)
	}
	if fake.updateInput.IsDefault != input.IsDefault {
		t.Fatalf("updated isDefault = %t, want %t", fake.updateInput.IsDefault, input.IsDefault)
	}
}

func TestAccessGroupEnsureManagedTreatsDefaultRuleResponseAsConverged(t *testing.T) {
	t.Parallel()

	input := accessGroupParityInput("managed")
	remote := accessGroupParityRemote("group-id", input, nil)
	remote.Default = []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}}
	fake := &accessGroupParityCloudflare{groups: map[string]flarecloudflare.AccessGroup{remote.ID: remote}}
	object := &v1alpha1.AccessGroup{
		ObjectMeta: metav1.ObjectMeta{Generation: 7},
		Status: v1alpha1.AccessGroupStatus{
			GroupID: "group-id", OwnershipVerified: true, ObservedGeneration: 7,
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
		},
	}

	_, owned, conflict, err := (&AccessGroupReconciler{}).ensureManaged(context.Background(), fake, flarecloudflare.AccessScope{}, object, input)
	if err != nil || conflict != "" || !owned {
		t.Fatalf("ensure managed = owned %t, conflict %q, err %v", owned, conflict, err)
	}
	if fake.updates != 0 {
		t.Fatalf("default rule-array response caused %d updates", fake.updates)
	}
}

func TestAccessGroupRecoveryUsesExactNameFilterWithoutUpdatingConvergedState(t *testing.T) {
	t.Parallel()

	isDefault := true
	input := accessGroupParityInput("flareway/cluster/namespace/group")
	remote := accessGroupParityRemote("recovered", input, &isDefault)
	fake := &accessGroupParityCloudflare{groups: map[string]flarecloudflare.AccessGroup{remote.ID: remote}}
	object := &v1alpha1.AccessGroup{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status:     v1alpha1.AccessGroupStatus{ObservedGeneration: 3},
	}
	scope := flarecloudflare.AccessScope{ZoneID: "zone-id"}

	got, owned, conflict, err := (&AccessGroupReconciler{}).ensureManaged(context.Background(), fake, scope, object, input)
	if err != nil || conflict != "" || !owned || got.ID != remote.ID {
		t.Fatalf("recovery = %#v, owned %t, conflict %q, err %v", got, owned, conflict, err)
	}
	wantOptions := flarecloudflare.AccessGroupListOptions{Scope: scope, Name: input.Name}
	if fake.listOptions != wantOptions {
		t.Fatalf("list options = %#v, want %#v", fake.listOptions, wantOptions)
	}
	if fake.updates != 0 || fake.creates != 0 {
		t.Fatalf("converged recovery mutated remote: creates=%d updates=%d", fake.creates, fake.updates)
	}
}

func TestAccessGroupAdoptionVerifiesNameAndAppliesDesiredState(t *testing.T) {
	t.Parallel()

	input := accessGroupParityInput("managed")
	remote := accessGroupParityRemote("adopted", input, nil)
	remote.Include = []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}}
	fake := &accessGroupParityCloudflare{groups: map[string]flarecloudflare.AccessGroup{remote.ID: remote}}
	object := &v1alpha1.AccessGroup{
		Spec: v1alpha1.AccessGroupSpec{
			ExternalRef: &v1alpha1.AccessGroupExternalReference{GroupID: remote.ID},
			Adoption:    v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID},
		},
	}

	got, owned, conflict, err := (&AccessGroupReconciler{}).ensureManaged(context.Background(), fake, flarecloudflare.AccessScope{}, object, input)
	if err != nil || conflict != "" || !owned || got.ID != remote.ID {
		t.Fatalf("adoption = %#v, owned %t, conflict %q, err %v", got, owned, conflict, err)
	}
	if fake.updates != 1 {
		t.Fatalf("adoption update count = %d, want 1", fake.updates)
	}

	fake.groups[remote.ID] = flarecloudflare.AccessGroup{ID: remote.ID, Name: "unexpected"}
	object.Status = v1alpha1.AccessGroupStatus{}
	_, owned, conflict, err = (&AccessGroupReconciler{}).ensureManaged(context.Background(), fake, flarecloudflare.AccessScope{}, object, input)
	if err != nil || conflict == "" || owned {
		t.Fatalf("mismatched adoption = owned %t, conflict %q, err %v", owned, conflict, err)
	}
	if fake.updates != 1 {
		t.Fatalf("name-conflicted adoption performed an update; count=%d", fake.updates)
	}
}

func TestAccessGroupObserveOnlyVerifiesEveryObservableMutableField(t *testing.T) {
	t.Parallel()

	isDefault := true
	input := accessGroupParityInput("terraform-group")
	remote := accessGroupParityRemote("external", input, &isDefault)
	object := &v1alpha1.AccessGroup{Spec: v1alpha1.AccessGroupSpec{Adoption: v1alpha1.AdoptionSpec{Expect: v1alpha1.AdoptionExpect{Name: input.Name}}}}
	if conflict := validateObservedAccessGroup(object, input, remote); conflict != "" {
		t.Fatalf("converged ObserveOnly group conflicted: %s", conflict)
	}

	remote.Require = nil
	if conflict := validateObservedAccessGroup(object, input, remote); conflict == "" {
		t.Fatal("ObserveOnly did not reject mismatched require rules")
	}
	remote = accessGroupParityRemote("external", input, &isDefault)
	falseValue := false
	remote.IsDefault = &falseValue
	if conflict := validateObservedAccessGroup(object, input, remote); conflict == "" {
		t.Fatal("ObserveOnly did not reject mismatched isDefault")
	}
}

func TestAccessGroupObservedStatePreservesDefaultRuleArray(t *testing.T) {
	t.Parallel()

	remote := flarecloudflare.AccessGroup{
		ID:      "default",
		Name:    "default-group",
		Include: []flarecloudflare.ResolvedAccessRule{{Kind: "email", Value: "user@example.com"}},
		Default: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}},
	}
	observed, err := accessGroupObservedState(remote)
	if err != nil {
		t.Fatalf("convert observed state: %v", err)
	}
	if observed.IsDefault != nil {
		t.Fatalf("asymmetric default response invented boolean value %t", *observed.IsDefault)
	}
	if len(observed.Default) != 1 || observed.Default[0].Kind != "everyone" || observed.Default[0].Value != "" {
		t.Fatalf("default rule array was not retained: %#v", observed.Default)
	}
	if len(observed.Include) != 1 || observed.Include[0].Kind != "email" || observed.Include[0].Value != "user@example.com" {
		t.Fatalf("include rules were not retained: %#v", observed.Include)
	}
}

func TestAccessGroupObservedStateRejectsUnknownRuleKind(t *testing.T) {
	t.Parallel()

	_, err := accessGroupObservedState(flarecloudflare.AccessGroup{
		Name:    "unknown-rule",
		Include: []flarecloudflare.ResolvedAccessRule{{Kind: "mystery"}},
	})
	if err == nil {
		t.Fatal("unknown remote rule kind was silently dropped")
	}
}

func TestAccessGroupRemoteRuleDecodeFailureRemainsVisible(t *testing.T) {
	t.Parallel()

	decodeErr := &flarecloudflare.UnsupportedAccessPolicyFieldError{Field: "rule variant", Value: "mystery"}
	fake := &accessGroupParityCloudflare{getErr: decodeErr}
	object := &v1alpha1.AccessGroup{Status: v1alpha1.AccessGroupStatus{GroupID: "group-id", OwnershipVerified: true}}
	_, _, conflict, err := (&AccessGroupReconciler{}).ensureManaged(context.Background(), fake, flarecloudflare.AccessScope{}, object, accessGroupParityInput("managed"))
	if !errors.Is(err, decodeErr) || conflict != "" {
		t.Fatalf("decode failure = conflict %q, err %v", conflict, err)
	}
	if reason := accessGroupErrorReason(err); reason != "Unsupported" {
		t.Fatalf("decode failure reason = %q, want Unsupported", reason)
	}
}

func accessGroupParityInput(name string) flarecloudflare.AccessGroupInput {
	return flarecloudflare.AccessGroupInput{
		Name:      name,
		Include:   []flarecloudflare.ResolvedAccessRule{{Kind: "emailDomain", Value: "example.com"}},
		Require:   []flarecloudflare.ResolvedAccessRule{{Kind: "devicePosture", ID: "posture-id", AccountID: "account-id"}},
		Exclude:   []flarecloudflare.ResolvedAccessRule{{Kind: "geo", Value: "AQ"}},
		IsDefault: true,
	}
}

func accessGroupParityRemote(id string, input flarecloudflare.AccessGroupInput, isDefault *bool) flarecloudflare.AccessGroup {
	return flarecloudflare.AccessGroup{
		ID: id, Name: input.Name, Include: input.Include, Require: input.Require, Exclude: input.Exclude, IsDefault: isDefault,
	}
}

type accessGroupParityCloudflare struct {
	groups      map[string]flarecloudflare.AccessGroup
	getErr      error
	getScope    flarecloudflare.AccessScope
	listOptions flarecloudflare.AccessGroupListOptions
	updateInput flarecloudflare.AccessGroupInput
	creates     int
	updates     int
	deletes     int
}

func (f *accessGroupParityCloudflare) CreateAccessGroup(_ context.Context, _ flarecloudflare.AccessScope, input flarecloudflare.AccessGroupInput) (flarecloudflare.AccessGroup, error) {
	f.creates++
	isDefault := input.IsDefault
	remote := accessGroupParityRemote("created", input, &isDefault)
	if f.groups == nil {
		f.groups = map[string]flarecloudflare.AccessGroup{}
	}
	f.groups[remote.ID] = remote
	return remote, nil
}

func (f *accessGroupParityCloudflare) UpdateAccessGroup(_ context.Context, _ flarecloudflare.AccessScope, id string, input flarecloudflare.AccessGroupInput) (flarecloudflare.AccessGroup, error) {
	f.updates++
	f.updateInput = input
	isDefault := input.IsDefault
	remote := accessGroupParityRemote(id, input, &isDefault)
	if f.groups == nil {
		f.groups = map[string]flarecloudflare.AccessGroup{}
	}
	f.groups[id] = remote
	return remote, nil
}

func (f *accessGroupParityCloudflare) GetAccessGroup(_ context.Context, scope flarecloudflare.AccessScope, id string) (flarecloudflare.AccessGroup, error) {
	f.getScope = scope
	if f.getErr != nil {
		return flarecloudflare.AccessGroup{}, f.getErr
	}
	remote, ok := f.groups[id]
	if !ok {
		return flarecloudflare.AccessGroup{}, errors.New("access group not found")
	}
	return remote, nil
}

func (f *accessGroupParityCloudflare) ListAccessGroups(_ context.Context, options flarecloudflare.AccessGroupListOptions) ([]flarecloudflare.AccessGroup, error) {
	f.listOptions = options
	result := make([]flarecloudflare.AccessGroup, 0, len(f.groups))
	for _, remote := range f.groups {
		if options.Name == "" || remote.Name == options.Name {
			result = append(result, remote)
		}
	}
	return result, nil
}

func (f *accessGroupParityCloudflare) DeleteAccessGroup(_ context.Context, _ flarecloudflare.AccessScope, id string) error {
	f.deletes++
	delete(f.groups, id)
	return nil
}

var _ flarecloudflare.AccessGroupAPI = (*accessGroupParityCloudflare)(nil)
