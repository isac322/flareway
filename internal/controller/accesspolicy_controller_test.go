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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// accessPolicyTestFixture seeds a tenant namespace, the kube-system namespace
// carrying the cluster UID used by the ownership-marker name, the credential
// Secret, and an accepted CloudflareAccount whose grant matches the tenant and
// applies the given platformObjects permission.
func accessPolicyTestFixture(t *testing.T, platformObjects v1alpha1.GrantPermission, objects ...client.Object) (client.Client, *runtime.Scheme) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"access-policy-tenant": "true"}
	seed := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Labels: labels}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "api-token", Namespace: "tenant-a"},
			Data:       map[string][]byte{"token": []byte("value")},
		},
		&v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account"},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID: "0123456789abcdef0123456789abcdef",
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Name: "api-token", Namespace: "tenant-a", Key: "token",
				}},
				Grants: []v1alpha1.CloudflareAccountGrant{{
					NamespaceSelector: metav1.LabelSelector{MatchLabels: labels},
					Hostnames:         []string{"*"},
					Zones:             []string{"*"},
					Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
					AccessPolicyRefs:  v1alpha1.GrantPermissionAllowed,
					PlatformObjects:   platformObjects,
				}},
			},
			Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.Now()},
				{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.Now()},
			}},
		},
	}
	seed = append(seed, objects...)
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.AccessPolicy{}).
		WithObjects(seed...).Build()
	return kube, scheme
}

func accessPolicyTestObject(name string) *v1alpha1.AccessPolicy {
	return &v1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "tenant-a",
			Finalizers: []string{v1alpha1.AccessPolicyFinalizer},
		},
		Spec: v1alpha1.AccessPolicySpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			Name:       name,
			Decision:   v1alpha1.AccessPolicyDecisionAllow,
			Include:    []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
		},
	}
}

// accessPolicyFakeCloudflare is a stateful fake of the reusable-policy surface.
// Like the real Cloudflare API it permits duplicate policy names, which is what
// makes an orphaned policy observable.
type accessPolicyFakeCloudflare struct {
	flarecloudflare.AccessAPI
	policies map[string]flarecloudflare.AccessPolicy
	creates  int
	updates  int
	next     int
}

func (f *accessPolicyFakeCloudflare) CreateAccessPolicy(_ context.Context, input flarecloudflare.AccessPolicyInput) (flarecloudflare.AccessPolicy, error) {
	f.next++
	f.creates++
	policy := flarecloudflare.AccessPolicy{
		ID: fmt.Sprintf("remote-policy-%d", f.next), Name: input.Name,
		Decision: input.Decision, Include: input.Include, Require: input.Require, Exclude: input.Exclude,
	}
	f.policies[policy.ID] = policy
	return policy, nil
}

func (f *accessPolicyFakeCloudflare) UpdateAccessPolicy(_ context.Context, id string, input flarecloudflare.AccessPolicyInput) (flarecloudflare.AccessPolicy, error) {
	f.updates++
	policy := flarecloudflare.AccessPolicy{
		ID: id, Name: input.Name,
		Decision: input.Decision, Include: input.Include, Require: input.Require, Exclude: input.Exclude,
	}
	f.policies[id] = policy
	return policy, nil
}

func (f *accessPolicyFakeCloudflare) GetAccessPolicy(_ context.Context, id string) (flarecloudflare.AccessPolicy, error) {
	policy, found := f.policies[id]
	if !found {
		return flarecloudflare.AccessPolicy{}, fmt.Errorf("fake: policy %q not found", id)
	}
	return policy, nil
}

func (f *accessPolicyFakeCloudflare) ListAccessPolicies(context.Context) ([]flarecloudflare.AccessPolicy, error) {
	out := make([]flarecloudflare.AccessPolicy, 0, len(f.policies))
	for _, policy := range f.policies {
		out = append(out, policy)
	}
	return out, nil
}

func (f *accessPolicyFakeCloudflare) DeleteAccessPolicy(_ context.Context, id string) error {
	delete(f.policies, id)
	return nil
}

func accessPolicyReadyCondition(t *testing.T, kube client.Client, key client.ObjectKey) *metav1.Condition {
	t.Helper()
	current := new(v1alpha1.AccessPolicy)
	if err := kube.Get(context.Background(), key, current); err != nil {
		t.Fatal(err)
	}
	return meta.FindStatusCondition(current.Status.Conditions, "Ready")
}

// A grant that matches the namespace but denies platformObjects must stop the
// reconciler before any Cloudflare mutation.
func TestAccessPolicyReconcileDeniedWithoutPlatformObjectsGrant(t *testing.T) {
	ctx := context.Background()
	policy := accessPolicyTestObject("denied-policy")
	kube, scheme := accessPolicyTestFixture(t, v1alpha1.GrantPermissionDenied, policy)

	// Fixture controls: the grant matches the namespace but denies platform
	// objects, so the gate under test is the PlatformObject request flag.
	var account v1alpha1.CloudflareAccount
	if err := kube.Get(ctx, types.NamespacedName{Name: "account"}, &account); err != nil {
		t.Fatal(err)
	}
	var tenant corev1.Namespace
	if err := kube.Get(ctx, types.NamespacedName{Name: "tenant-a"}, &tenant); err != nil {
		t.Fatal(err)
	}
	if decision := authz.Evaluate(&account, &tenant, authz.Request{PlatformObject: true}); decision.Allowed {
		t.Fatalf("fixture grant unexpectedly permits platform objects: %#v", decision)
	}
	if decision := authz.Evaluate(&account, &tenant, authz.Request{}); !decision.Allowed {
		t.Fatalf("fixture grant must still match the namespace: %#v", decision)
	}

	api := &accessPolicyFakeCloudflare{policies: map[string]flarecloudflare.AccessPolicy{}}
	reconciler := &AccessPolicyReconciler{
		Client: kube, Scheme: scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return api, nil },
	}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(policy)})
	if err == nil || !strings.Contains(err.Error(), string(authz.ReasonRefNotPermitted)) {
		t.Fatalf("reconcile error = %v, want a RefNotPermitted denial", err)
	}
	if api.creates != 0 || len(api.policies) != 0 {
		t.Fatalf("denied reconcile mutated the remote: creates=%d policies=%d", api.creates, len(api.policies))
	}
	if condition := accessPolicyReadyCondition(t, kube, client.ObjectKeyFromObject(policy)); condition != nil && condition.Status == metav1.ConditionTrue {
		t.Errorf("Ready condition = %#v, want no Ready=True under a denied platformObjects grant", condition)
	}
}

// A lost status.policyId checkpoint must recover the existing remote policy by
// its ownership-marker name instead of creating a duplicate.
func TestAccessPolicyReconcileRecoversRemotePolicyAfterCheckpointLoss(t *testing.T) {
	ctx := context.Background()
	policy := accessPolicyTestObject("checkpoint-loss")
	kube, scheme := accessPolicyTestFixture(t, v1alpha1.GrantPermissionAllowed, policy)
	api := &accessPolicyFakeCloudflare{policies: map[string]flarecloudflare.AccessPolicy{}}
	reconciler := &AccessPolicyReconciler{
		Client: kube, Scheme: scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return api, nil },
	}
	key := client.ObjectKeyFromObject(policy)
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if api.creates != 1 {
		t.Fatalf("CreateAccessPolicy calls after the first reconcile = %d, want 1", api.creates)
	}
	current := new(v1alpha1.AccessPolicy)
	if err := kube.Get(ctx, key, current); err != nil {
		t.Fatal(err)
	}
	firstID := current.Status.PolicyID
	if firstID == "" {
		t.Fatal("the first reconcile did not record status.policyId")
	}

	// Inject the checkpoint loss: the status write that recorded policyId
	// never landed (apiserver error, conflict, or controller restart between
	// the remote create and the status patch).
	current.Status.PolicyID = ""
	current.Status.OwnershipVerified = false
	if err := kube.Status().Update(ctx, current); err != nil {
		t.Fatal(err)
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(api.policies) != 1 {
		t.Fatalf("remote policies after checkpoint loss = %d, want exactly 1 (the original must be recovered, not duplicated)", len(api.policies))
	}
	if api.creates != 1 {
		t.Fatalf("CreateAccessPolicy calls after checkpoint loss = %d, want 1", api.creates)
	}
	if api.updates != 0 {
		t.Fatalf("recovering a converged remote policy performed %d updates, want 0", api.updates)
	}
	if err := kube.Get(ctx, key, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.PolicyID != firstID || !current.Status.OwnershipVerified {
		t.Fatalf("recovered status = policyId %q ownershipVerified %t, want the original id %q verified", current.Status.PolicyID, current.Status.OwnershipVerified, firstID)
	}
	if condition := meta.FindStatusCondition(current.Status.Conditions, "Ready"); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("Ready condition after recovery = %#v, want Ready=True", condition)
	}
}

// Two remote policies carrying the same ownership-marker name are ambiguous:
// the reconciler must fail closed rather than adopt one or create a third.
func TestAccessPolicyReconcileFailsClosedOnDuplicateMarkerName(t *testing.T) {
	ctx := context.Background()
	policy := accessPolicyTestObject("ambiguous")
	kube, scheme := accessPolicyTestFixture(t, v1alpha1.GrantPermissionAllowed, policy)
	marker := "flareway/cluster-id/tenant-a/ambiguous"
	api := &accessPolicyFakeCloudflare{policies: map[string]flarecloudflare.AccessPolicy{
		"remote-a": {ID: "remote-a", Name: marker, Decision: string(v1alpha1.AccessPolicyDecisionAllow), Include: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}}},
		"remote-b": {ID: "remote-b", Name: marker, Decision: string(v1alpha1.AccessPolicyDecisionAllow), Include: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}}},
	}}
	reconciler := &AccessPolicyReconciler{
		Client: kube, Scheme: scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return api, nil },
	}
	key := client.ObjectKeyFromObject(policy)
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("reconcile succeeded despite an ambiguous ownership-marker name")
	}
	if api.creates != 0 || api.updates != 0 || len(api.policies) != 2 {
		t.Fatalf("ambiguous marker name mutated the remote: creates=%d updates=%d policies=%d", api.creates, api.updates, len(api.policies))
	}
	current := new(v1alpha1.AccessPolicy)
	if err := kube.Get(ctx, key, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.PolicyID != "" || current.Status.OwnershipVerified {
		t.Fatalf("ambiguous recovery recorded identity policyId %q ownershipVerified %t, want neither", current.Status.PolicyID, current.Status.OwnershipVerified)
	}
	if condition := meta.FindStatusCondition(current.Status.Conditions, "Ready"); condition != nil && condition.Status == metav1.ConditionTrue {
		t.Errorf("Ready condition = %#v, want no Ready=True for an ambiguous remote", condition)
	}
}

// A dependency change must enqueue dependents in every namespace: a grant may
// permit a tenant AccessPolicy to reference a platform-namespace dependency.
func TestAccessPolicyDependencyWatchEnqueuesCrossNamespaceDependents(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	dependent := &v1alpha1.AccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "dependent-policy", Namespace: "tenant-a"}}
	crossDep := &v1alpha1.DevicePostureRule{ObjectMeta: metav1.ObjectMeta{Name: "posture-rule", Namespace: "platform"}}
	localDep := &v1alpha1.DevicePostureRule{ObjectMeta: metav1.ObjectMeta{Name: "posture-rule", Namespace: "tenant-a"}}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithObjects(dependent, crossDep, localDep).Build()
	reconciler := &AccessPolicyReconciler{Client: kube, Scheme: scheme}
	want := types.NamespacedName{Namespace: "tenant-a", Name: "dependent-policy"}

	requests := reconciler.policiesForDependency(ctx, crossDep)
	if len(requests) != 1 || requests[0].NamespacedName != want {
		t.Fatalf("policiesForDependency(cross-namespace dependency) = %v, want [%v]", requests, want)
	}
	requests = reconciler.policiesForDependency(ctx, localDep)
	if len(requests) != 1 || requests[0].NamespacedName != want {
		t.Fatalf("policiesForDependency(same-namespace dependency) = %v, want [%v]", requests, want)
	}
}
