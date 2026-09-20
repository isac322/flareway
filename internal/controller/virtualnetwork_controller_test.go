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
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

var virtualNetworkTestClock = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func virtualNetworkTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add flareway v1alpha1 to scheme: %v", err)
	}
	return scheme
}

// virtualNetworkTestAccount grants platform objects only to namespaces carrying
// the tenant=true label.
func virtualNetworkTestAccount() *v1alpha1.CloudflareAccount {
	return &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{
				APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"},
			},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(virtualNetworkTestClock)},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.NewTime(virtualNetworkTestClock)},
		}},
	}
}

func virtualNetworkFixture(namespace, name string, created time.Time) *v1alpha1.VirtualNetwork {
	return &v1alpha1.VirtualNetwork{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         namespace,
			Name:              name,
			UID:               types.UID("vnet-" + namespace + "-" + name),
			CreationTimestamp: metav1.NewTime(created),
			Finalizers:        []string{v1alpha1.VirtualNetworkFinalizer},
		},
		Spec: v1alpha1.VirtualNetworkSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Name:             "default",
			IsDefault:        true,
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
}

func virtualNetworkWriterClient(t *testing.T, objects ...client.Object) (client.Client, *runtime.Scheme) {
	t.Helper()
	scheme := virtualNetworkTestScheme(t)
	seed := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "squatter"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("value")}},
		virtualNetworkTestAccount(),
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.VirtualNetwork{}).
		WithObjects(append(seed, objects...)...).
		Build()
	return kube, scheme
}

// An earlier VirtualNetwork in a namespace the CloudflareAccount does not
// grant must not block the authorized writer.
func TestVirtualNetworkWriterArbitrationSkipsUngrantedContender(t *testing.T) {
	ctx := context.Background()
	squatter := virtualNetworkFixture("squatter", "squat", virtualNetworkTestClock)
	authorized := virtualNetworkFixture("tenant", "prod", virtualNetworkTestClock.Add(time.Hour))
	kube, scheme := virtualNetworkWriterClient(t, squatter, authorized)

	api := newFakePrivateNetworkCloudflare()
	reconciler := &VirtualNetworkReconciler{Client: kube, Scheme: scheme, NewCloudflareClient: api.Client}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(authorized)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var current v1alpha1.VirtualNetwork
	if err := kube.Get(ctx, client.ObjectKeyFromObject(authorized), &current); err != nil {
		t.Fatalf("get VirtualNetwork: %v", err)
	}
	ready := meta.FindStatusCondition(current.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("authorized VirtualNetwork was blocked by an ungranted contender: %#v", ready)
	}
	if api.count("CreateVirtualNetwork") != 1 {
		t.Fatalf("expected one remote virtual network creation, calls=%v", api.callsSnapshot())
	}
}

// Control: an earlier contender in a granted namespace still wins arbitration,
// so the authorization filter cannot simply disable the single-writer check.
func TestVirtualNetworkWriterArbitrationBlocksGrantedContender(t *testing.T) {
	ctx := context.Background()
	first := virtualNetworkFixture("tenant", "first", virtualNetworkTestClock)
	second := virtualNetworkFixture("tenant", "second", virtualNetworkTestClock.Add(time.Hour))
	kube, scheme := virtualNetworkWriterClient(t, first, second)

	api := newFakePrivateNetworkCloudflare()
	reconciler := &VirtualNetworkReconciler{Client: kube, Scheme: scheme, NewCloudflareClient: api.Client}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(second)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var current v1alpha1.VirtualNetwork
	if err := kube.Get(ctx, client.ObjectKeyFromObject(second), &current); err != nil {
		t.Fatalf("get VirtualNetwork: %v", err)
	}
	accepted := meta.FindStatusCondition(current.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
	if accepted == nil || accepted.Status != metav1.ConditionFalse || accepted.Reason != "Conflict" {
		t.Fatalf("later authorized VirtualNetwork should lose arbitration with Accepted=False/Conflict, got %#v", accepted)
	}
	if api.count("CreateVirtualNetwork") != 0 {
		t.Fatalf("losing contender must not create a remote virtual network, calls=%v", api.callsSnapshot())
	}
}

// namespaceGetErrorClient fails Namespace reads so arbitration cannot prove a
// contender's grant.
type namespaceGetErrorClient struct {
	client.Client
	err error
}

func (c *namespaceGetErrorClient) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	if _, ok := object.(*corev1.Namespace); ok && key.Name == "squatter" {
		return c.err
	}
	return c.Client.Get(ctx, key, object, opts...)
}

// An indeterminate API error while checking a contender's grant must propagate
// (fail closed) instead of silently electing the new writer.
func TestVirtualNetworkWriterArbitrationPropagatesContenderLookupError(t *testing.T) {
	ctx := context.Background()
	squatter := virtualNetworkFixture("squatter", "squat", virtualNetworkTestClock)
	authorized := virtualNetworkFixture("tenant", "prod", virtualNetworkTestClock.Add(time.Hour))
	kube, scheme := virtualNetworkWriterClient(t, squatter, authorized)

	lookupErr := errors.New("namespace lookup unavailable")
	reconciler := &VirtualNetworkReconciler{Client: &namespaceGetErrorClient{Client: kube, err: lookupErr}, Scheme: scheme}
	account := virtualNetworkTestAccount()
	if err := reconciler.checkSingleWriter(ctx, account, authorized); !errors.Is(err, lookupErr) {
		t.Fatalf("checkSingleWriter = %v, want propagated lookup error", err)
	}
}

// A NetworkRoute whose only link to a VirtualNetwork is
// spec.ipLookup.virtualNetworkRef must still block deletion, and the reported
// blocker must be deterministic regardless of list order.
func TestVirtualNetworkDeletionGuardIncludesIPLookupReference(t *testing.T) {
	scheme := virtualNetworkTestScheme(t)
	vnet := &v1alpha1.VirtualNetwork{
		ObjectMeta: metav1.ObjectMeta{Namespace: "platform", Name: "vnet", Generation: 1},
		Spec:       v1alpha1.VirtualNetworkSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "tenant-vnet"},
	}
	lookupRoute := &v1alpha1.NetworkRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "platform", Name: "a-lookup", UID: types.UID("route-lookup")},
		Spec: v1alpha1.NetworkRouteSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			Network:    "10.30.0.0/16",
			TunnelRef:  v1alpha1.TunnelReference{Name: "edge"},
			IPLookup: &v1alpha1.NetworkRouteIPLookupSpec{
				IP:                "10.30.0.7",
				VirtualNetworkRef: &corev1.LocalObjectReference{Name: "vnet"},
			},
		},
	}
	directRoute := &v1alpha1.NetworkRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "platform", Name: "z-direct", UID: types.UID("route-direct")},
		Spec: v1alpha1.NetworkRouteSpec{
			AccountRef:        corev1.LocalObjectReference{Name: "account"},
			Network:           "10.40.0.0/16",
			TunnelRef:         v1alpha1.TunnelReference{Name: "edge"},
			VirtualNetworkRef: &corev1.LocalObjectReference{Name: "vnet"},
		},
	}
	deletedAt := metav1.NewTime(virtualNetworkTestClock)
	deletingRoute := &v1alpha1.NetworkRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "platform", Name: "a-deleting", UID: types.UID("route-deleting"),
			Finalizers: []string{v1alpha1.NetworkRouteFinalizer}, DeletionTimestamp: &deletedAt,
		},
		Spec: v1alpha1.NetworkRouteSpec{
			AccountRef:        corev1.LocalObjectReference{Name: "account"},
			Network:           "10.50.0.0/16",
			TunnelRef:         v1alpha1.TunnelReference{Name: "edge"},
			VirtualNetworkRef: &corev1.LocalObjectReference{Name: "vnet"},
		},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(vnet, lookupRoute, directRoute, deletingRoute).Build()
	reconciler := &VirtualNetworkReconciler{Client: kube, Scheme: scheme}

	blockedBy, err := reconciler.networkRouteReferences(context.Background(), vnet)
	if err != nil {
		t.Fatalf("networkRouteReferences: %v", err)
	}
	if blockedBy != "platform/a-lookup" {
		t.Fatalf("networkRouteReferences = %q, want the deterministically first live blocker platform/a-lookup", blockedBy)
	}
}

// A deletion blocked by a referencing NetworkRoute must leave a CR-visible
// diagnostic (CleanupBlocked=True, Ready=False) while preserving Accepted, the
// finalizer, and the remote virtual network.
func TestVirtualNetworkBlockedDeletionReportsCleanupBlocked(t *testing.T) {
	ctx := context.Background()
	scheme := virtualNetworkTestScheme(t)
	deletedAt := metav1.NewTime(virtualNetworkTestClock)
	vnet := &v1alpha1.VirtualNetwork{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "vnet", Generation: 1,
			UID: types.UID("vnet-tenant"), Finalizers: []string{v1alpha1.VirtualNetworkFinalizer},
			DeletionTimestamp: &deletedAt,
		},
		Spec: v1alpha1.VirtualNetworkSpec{
			AccountRef:     corev1.LocalObjectReference{Name: "account"},
			Name:           "tenant-vnet",
			DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
		Status: v1alpha1.VirtualNetworkStatus{
			VirtualNetworkID:   "remote-vnet",
			OwnershipVerified:  true,
			ObservedGeneration: 1,
			Conditions: []metav1.Condition{
				{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue, Reason: "Ready", Message: "synchronized", ObservedGeneration: 1, LastTransitionTime: metav1.NewTime(virtualNetworkTestClock)},
				{Type: v1alpha1.PrivateNetworkConditionReady, Status: metav1.ConditionTrue, Reason: "Ready", Message: "synchronized", ObservedGeneration: 1, LastTransitionTime: metav1.NewTime(virtualNetworkTestClock)},
			},
		},
	}
	route := &v1alpha1.NetworkRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "route", UID: types.UID("route-tenant")},
		Spec: v1alpha1.NetworkRouteSpec{
			AccountRef:        corev1.LocalObjectReference{Name: "account"},
			Network:           "10.20.0.0/16",
			TunnelRef:         v1alpha1.TunnelReference{Name: "edge"},
			VirtualNetworkRef: &corev1.LocalObjectReference{Name: "vnet"},
		},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.VirtualNetwork{}).
		WithObjects(vnet, route,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("value")}},
			virtualNetworkTestAccount()).
		Build()
	api := newFakePrivateNetworkCloudflare()
	api.virtualNetworks["remote-vnet"] = flarecloudflare.VirtualNetwork{ID: "remote-vnet", Name: "tenant-vnet"}
	reconciler := &VirtualNetworkReconciler{Client: kube, Scheme: scheme, NewCloudflareClient: api.Client}

	current := &v1alpha1.VirtualNetwork{}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(vnet), current); err != nil {
		t.Fatalf("get VirtualNetwork: %v", err)
	}
	if err := reconciler.reconcileDelete(ctx, current); err == nil {
		t.Fatal("reconcileDelete succeeded while a NetworkRoute still references the VirtualNetwork")
	}

	final := &v1alpha1.VirtualNetwork{}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(vnet), final); err != nil {
		t.Fatalf("get VirtualNetwork after blocked deletion: %v", err)
	}
	blocked := meta.FindStatusCondition(final.Status.Conditions, "CleanupBlocked")
	if blocked == nil || blocked.Status != metav1.ConditionTrue || blocked.Reason != "Referenced" {
		t.Fatalf("blocked deletion must report CleanupBlocked=True/Referenced, got %#v", blocked)
	}
	ready := meta.FindStatusCondition(final.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "CleanupBlocked" {
		t.Fatalf("blocked deletion must report Ready=False/CleanupBlocked, got %#v", ready)
	}
	accepted := meta.FindStatusCondition(final.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
	if accepted == nil || accepted.Status != metav1.ConditionTrue {
		t.Fatalf("blocked deletion must preserve Accepted=True, got %#v", accepted)
	}
	if !slices.Contains(final.Finalizers, v1alpha1.VirtualNetworkFinalizer) {
		t.Fatalf("blocked deletion removed the finalizer: %v", final.Finalizers)
	}
	if api.count("DeleteVirtualNetwork") != 0 {
		t.Fatalf("blocked deletion deleted the remote virtual network, calls=%v", api.callsSnapshot())
	}
}

