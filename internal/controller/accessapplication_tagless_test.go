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
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/gatewayapi"
)

func TestRemoteApplicationInputOmitsProxyEndpointOwnerTags(t *testing.T) {
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy", Namespace: "tenant"},
		Spec: v1alpha1.AccessApplicationSpec{
			Type:          v1alpha1.AccessApplicationTypeProxyEndpoint,
			ProxyEndpoint: &v1alpha1.AccessProxyEndpointApplicationSpec{},
			Application:   v1alpha1.AccessApplicationSettings{Name: "proxy-endpoint"},
		},
	}
	input := remoteApplicationInput(application, []gatewayapi.AccessDestination{{
		Type: v1alpha1.AccessApplicationDestinationPublic,
		URI:  "proxy.example.test",
	}}, nil, nil, nil, nil, "owner-tag")
	if input.Name != "proxy-endpoint" {
		t.Fatalf("ProxyEndpoint name = %q", input.Name)
	}
	if len(input.Tags) != 0 {
		t.Fatalf("ProxyEndpoint input contains unsupported tags: %#v", input.Tags)
	}
}

func TestProxyEndpointRejectsUnsupportedApplicationTags(t *testing.T) {
	application := &v1alpha1.AccessApplication{Spec: v1alpha1.AccessApplicationSpec{
		Type:          v1alpha1.AccessApplicationTypeProxyEndpoint,
		ProxyEndpoint: &v1alpha1.AccessProxyEndpointApplicationSpec{},
		Application:   v1alpha1.AccessApplicationSettings{Tags: []string{"customer-tag"}},
	}}
	_, err := (&AccessApplicationReconciler{}).reconcileRemoteApplication(
		context.Background(),
		newFakeAccessApplicationCloudflare(),
		flarecloudflare.AccessScope{},
		application,
		flarecloudflare.AccessApplicationInput{Type: flarecloudflare.AccessApplicationTypeProxyEndpoint},
		"unused-owner-tag",
	)
	if err == nil || !strings.Contains(err.Error(), "do not support application tags") {
		t.Fatalf("ProxyEndpoint tags error = %v", err)
	}
}

func TestProxyEndpointCheckpointLifecycleDoesNotClaimForeignMatch(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	legacyOwnerTag := "legacy-owner"
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy", Namespace: "tenant", UID: types.UID("proxy-uid")},
		Spec: v1alpha1.AccessApplicationSpec{
			Type:             v1alpha1.AccessApplicationTypeProxyEndpoint,
			ProxyEndpoint:    &v1alpha1.AccessProxyEndpointApplicationSpec{},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	kube := controllerfake.NewClientBuilder().WithScheme(scheme).WithObjects(application).Build()
	reconciler := &AccessApplicationReconciler{Client: kube, Scheme: scheme}
	remote := newFakeAccessApplicationCloudflare()
	foreign := flarecloudflare.AccessApplication{
		ID: "foreign-match", Type: flarecloudflare.AccessApplicationTypeProxyEndpoint,
		Name: "proxy-endpoint", Domain: "proxy.example.test",
		Destinations: []flarecloudflare.AccessApplicationDestination{{
			Type: flarecloudflare.AccessApplicationDestinationTypePublic,
			URI:  "proxy.example.test",
		}},
		Tags: []string{accessManagedTag, legacyOwnerTag},
	}
	remote.Put(foreign)
	input := flarecloudflare.AccessApplicationInput{
		Type:   flarecloudflare.AccessApplicationTypeProxyEndpoint,
		Name:   foreign.Name,
		Domain: foreign.Domain,
		Destinations: []flarecloudflare.AccessApplicationDestination{{
			Type: flarecloudflare.AccessApplicationDestinationTypePublic,
			URI:  "proxy.example.test",
		}},
	}

	created, err := reconciler.reconcileRemoteApplication(ctx, remote, flarecloudflare.AccessScope{}, application, input, "unused-owner-tag")
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == foreign.ID {
		t.Fatal("managed create claimed a foreign matching ProxyEndpoint")
	}
	listsAfterCreate := countAccessCallsWithPrefix(remote.Calls(), "List")
	if listsAfterCreate != 1 {
		t.Fatalf("ProxyEndpoint create did not record exactly one pre-create baseline: %#v", remote.Calls())
	}
	checkpoint := readProxyEndpointCheckpointForTest(ctx, t, kube, application)
	if checkpoint.ApplicationID != created.ID || !proxyEndpointCheckpointMatchesInput(checkpoint, input) {
		t.Fatalf("created checkpoint = %#v", checkpoint)
	}

	recovered, err := reconciler.reconcileRemoteApplication(ctx, remote, flarecloudflare.AccessScope{}, application, input, "unused-owner-tag")
	if err != nil {
		t.Fatal(err)
	}
	if recovered.ID != created.ID {
		t.Fatalf("status-loss recovery returned %q, want %q", recovered.ID, created.ID)
	}
	if countAccessCallsWithPrefix(remote.Calls(), "Create:") != 1 {
		t.Fatalf("status-loss recovery created a duplicate: %#v", remote.Calls())
	}
	if countAccessCallsWithPrefix(remote.Calls(), "List") != listsAfterCreate {
		t.Fatalf("status-loss recovery listed matching applications despite a completed checkpoint: %#v", remote.Calls())
	}
	application.Status.ApplicationID = created.ID
	application.Status.Type = v1alpha1.AccessApplicationTypeProxyEndpoint
	application.Status.Domain = input.Domain

	updatedInput := input
	updatedInput.Domain = "updated.example.test"
	updated, err := reconciler.reconcileRemoteApplication(ctx, remote, flarecloudflare.AccessScope{}, application, updatedInput, "unused-owner-tag")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.Domain != updatedInput.Domain {
		t.Fatalf("updated ProxyEndpoint = %#v", updated)
	}
	checkpoint = readProxyEndpointCheckpointForTest(ctx, t, kube, application)
	if !proxyEndpointCheckpointMatchesInput(checkpoint, updatedInput) {
		t.Fatalf("updated checkpoint = %#v", checkpoint)
	}

	application.Status.ApplicationID = created.ID
	application.Status.Type = v1alpha1.AccessApplicationTypeProxyEndpoint
	application.Status.Domain = updatedInput.Domain
	if err := reconciler.deleteManagedProxyEndpointApplication(ctx, remote, flarecloudflare.AccessScope{}, application); err != nil {
		t.Fatal(err)
	}
	if remote.Has(created.ID) {
		t.Fatal("checkpointed ProxyEndpoint was not deleted")
	}
	if !remote.Has(foreign.ID) {
		t.Fatal("foreign matching ProxyEndpoint was deleted")
	}
	var secret corev1.Secret
	err = kube.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: proxyEndpointCheckpointName(application.UID)}, &secret)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("checkpoint Secret still exists after deletion: %v", err)
	}
}

func TestProxyEndpointRecoversCreateAfterCheckpointCompletionFailure(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy-recover", Namespace: "tenant", UID: types.UID("proxy-recover-uid")},
		Spec: v1alpha1.AccessApplicationSpec{
			Type:          v1alpha1.AccessApplicationTypeProxyEndpoint,
			ProxyEndpoint: &v1alpha1.AccessProxyEndpointApplicationSpec{},
		},
	}
	kube := controllerfake.NewClientBuilder().WithScheme(scheme).WithObjects(application).Build()
	reconciler := &AccessApplicationReconciler{Client: kube, Scheme: scheme}
	input := flarecloudflare.AccessApplicationInput{
		Type: flarecloudflare.AccessApplicationTypeProxyEndpoint,
		Name: "proxy-endpoint", Domain: "proxy.example.test",
		Destinations: []flarecloudflare.AccessApplicationDestination{{
			Type: flarecloudflare.AccessApplicationDestinationTypePublic,
			URI:  "proxy.example.test",
		}},
	}
	intent := proxyEndpointCheckpointFromInput("", input)
	intent.ExistingIDs = []string{"foreign-before-intent"}
	if err := reconciler.persistProxyEndpointCheckpoint(ctx, application, intent); err != nil {
		t.Fatal(err)
	}
	remote := newFakeAccessApplicationCloudflare()
	remote.Put(flarecloudflare.AccessApplication{
		ID: "foreign-before-intent", Type: input.Type, Name: input.Name, Domain: input.Domain,
	})
	remote.Put(flarecloudflare.AccessApplication{
		ID: "created-after-intent", Type: input.Type, Name: input.Name, Domain: input.Domain,
	})

	recovered, err := reconciler.reconcileRemoteApplication(ctx, remote, flarecloudflare.AccessScope{}, application, input, "unused-owner-tag")
	if err != nil {
		t.Fatal(err)
	}
	if recovered.ID != "created-after-intent" {
		t.Fatalf("recovered ProxyEndpoint ID = %q", recovered.ID)
	}
	if countAccessCallsWithPrefix(remote.Calls(), "Create:") != 0 {
		t.Fatalf("pending create recovery created a duplicate: %#v", remote.Calls())
	}
	checkpoint := readProxyEndpointCheckpointForTest(ctx, t, kube, application)
	if checkpoint.ApplicationID != recovered.ID || len(checkpoint.ExistingIDs) != 0 {
		t.Fatalf("completed recovery checkpoint = %#v", checkpoint)
	}
	if !remote.Has("foreign-before-intent") {
		t.Fatal("pending create recovery claimed or deleted a pre-existing foreign match")
	}
}

func TestProxyEndpointAdoptsOnlyExplicitIDAndCheckpointsIt(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy-adopt", Namespace: "tenant", UID: types.UID("proxy-adopt-success-uid")},
		Spec: v1alpha1.AccessApplicationSpec{
			Type:          v1alpha1.AccessApplicationTypeProxyEndpoint,
			ProxyEndpoint: &v1alpha1.AccessProxyEndpointApplicationSpec{},
			ExternalRef:   &v1alpha1.AccessApplicationExternalReference{ApplicationID: "explicit"},
			Adoption: v1alpha1.AdoptionSpec{
				Mode:   v1alpha1.AdoptionModeAdoptByID,
				Expect: v1alpha1.AdoptionExpect{Name: "proxy-endpoint", Domain: "proxy.example.test"},
			},
		},
	}
	kube := controllerfake.NewClientBuilder().WithScheme(scheme).WithObjects(application).Build()
	reconciler := &AccessApplicationReconciler{Client: kube, Scheme: scheme}
	remote := newFakeAccessApplicationCloudflare()
	remote.Put(flarecloudflare.AccessApplication{
		ID: "foreign-match", Type: flarecloudflare.AccessApplicationTypeProxyEndpoint,
		Name: "proxy-endpoint", Domain: "proxy.example.test",
	})
	remote.Put(flarecloudflare.AccessApplication{
		ID: "explicit", Type: flarecloudflare.AccessApplicationTypeProxyEndpoint,
		Name: "proxy-endpoint", Domain: "proxy.example.test",
	})
	input := flarecloudflare.AccessApplicationInput{
		Type: flarecloudflare.AccessApplicationTypeProxyEndpoint,
		Name: "proxy-endpoint", Domain: "proxy.example.test",
	}

	adopted, err := reconciler.reconcileRemoteApplication(ctx, remote, flarecloudflare.AccessScope{}, application, input, "unused-owner-tag")
	if err != nil {
		t.Fatal(err)
	}
	if adopted.ID != "explicit" {
		t.Fatalf("adopted ProxyEndpoint ID = %q", adopted.ID)
	}
	checkpoint := readProxyEndpointCheckpointForTest(ctx, t, kube, application)
	if checkpoint.ApplicationID != "explicit" || !proxyEndpointCheckpointMatchesInput(checkpoint, input) {
		t.Fatalf("adoption checkpoint = %#v", checkpoint)
	}
	if !remote.Has("foreign-match") || containsAccessCall(remote.Calls(), "Create:proxy-endpoint") {
		t.Fatalf("adoption touched a foreign match or created a replacement: %#v", remote.Calls())
	}
}

func TestProxyEndpointCheckpointPreventsAdoptionRepoint(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy", Namespace: "tenant", UID: types.UID("proxy-adopt-uid")},
		Spec: v1alpha1.AccessApplicationSpec{
			Type:          v1alpha1.AccessApplicationTypeProxyEndpoint,
			ProxyEndpoint: &v1alpha1.AccessProxyEndpointApplicationSpec{},
			ExternalRef:   &v1alpha1.AccessApplicationExternalReference{ApplicationID: "foreign"},
			Adoption:      v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID},
		},
	}
	kube := controllerfake.NewClientBuilder().WithScheme(scheme).WithObjects(application).Build()
	reconciler := &AccessApplicationReconciler{Client: kube, Scheme: scheme}
	input := flarecloudflare.AccessApplicationInput{Type: flarecloudflare.AccessApplicationTypeProxyEndpoint, Domain: "proxy.example.test"}
	if err := reconciler.persistProxyEndpointCheckpoint(ctx, application, proxyEndpointCheckpointFromInput("owned", input)); err != nil {
		t.Fatal(err)
	}
	remote := newFakeAccessApplicationCloudflare()
	remote.Put(flarecloudflare.AccessApplication{ID: "foreign", Type: flarecloudflare.AccessApplicationTypeProxyEndpoint, Domain: input.Domain})

	_, err := reconciler.reconcileRemoteApplication(ctx, remote, flarecloudflare.AccessScope{}, application, input, "unused-owner-tag")
	if err == nil || !strings.Contains(err.Error(), "checkpoint identifies") {
		t.Fatalf("adoption repoint error = %v", err)
	}
	if containsAccessCall(remote.Calls(), "Update:foreign") {
		t.Fatalf("foreign adoption target was mutated: %#v", remote.Calls())
	}
}

func readProxyEndpointCheckpointForTest(ctx context.Context, t *testing.T, kube client.Client, application *v1alpha1.AccessApplication) accessApplicationProxyCheckpoint {
	t.Helper()
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: proxyEndpointCheckpointName(application.UID)}, &secret); err != nil {
		t.Fatal(err)
	}
	var checkpoint accessApplicationProxyCheckpoint
	if err := json.Unmarshal(secret.Data[accessApplicationProxyIdentityKey], &checkpoint); err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func containsAccessCall(calls []string, expected string) bool {
	for _, call := range calls {
		if call == expected {
			return true
		}
	}
	return false
}

func countAccessCallsWithPrefix(calls []string, prefix string) int {
	count := 0
	for _, call := range calls {
		if strings.HasPrefix(call, prefix) {
			count++
		}
	}
	return count
}
