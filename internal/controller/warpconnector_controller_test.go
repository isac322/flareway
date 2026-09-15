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
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	flarewayv1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestWARPConnectorLifecycleHAFailoverAndTokenSecrecy(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)
	remote := newFakeWARPConnectorCloudflare()
	remote.clients = oversizedWARPClients(clock)
	kube, reconciler, object := newWARPConnectorTestReconciler(t, remote, clock)
	object.Spec.HighAvailability = flarewayv1alpha1.WARPConnectorHighAvailability{
		Enabled: new(true),
		Mode:    flarewayv1alpha1.WARPConnectorHAModeLocal,
		Local: &flarewayv1alpha1.WARPConnectorLocalHAConfig{
			VIPs:         []flarewayv1alpha1.WARPConnectorVirtualIP{{Address: "192.0.2.10"}, {Address: "2001:db8::10"}},
			VIPsPrevious: []flarewayv1alpha1.WARPConnectorVirtualIP{{Address: "192.0.2.9"}},
		},
	}
	object.Spec.Failover = &flarewayv1alpha1.WARPConnectorFailoverRequest{ClientID: "client-00", RequestID: "request-1"}
	object.Spec.DeletionPolicy = flarewayv1alpha1.DeletionPolicyDelete
	if err := kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}

	reconcileWARPConnector(ctx, t, reconciler, request, "add finalizer")
	reconcileWARPConnector(ctx, t, reconciler, request, "prepare create recovery")
	var checkpointed flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, request.NamespacedName, &checkpointed); err != nil {
		t.Fatal(err)
	}
	if checkpointed.Status.CreateAttemptName != "site-warp" ||
		checkpointed.Status.CreateAttemptGeneration != checkpointed.Generation || remote.creates != 0 {
		t.Fatalf("create was not checkpointed before mutation: status=%#v creates=%d", checkpointed.Status, remote.creates)
	}
	if accepted := meta.FindStatusCondition(checkpointed.Status.Conditions, flarewayv1alpha1.WARPConnectorConditionAccepted); accepted != nil && accepted.Reason == "Conflict" {
		t.Fatalf("fresh create claimed a foreign name collision: %#v", accepted)
	}
	reconcileWARPConnector(ctx, t, reconciler, request, "create and configure")

	var current flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.TunnelID == "" || !current.Status.OwnershipVerified {
		t.Fatalf("remote ownership was not checkpointed: %#v", current.Status)
	}
	if remote.creates != 1 || remote.createInput.HighlyAvailable == nil || !*remote.createInput.HighlyAvailable {
		t.Fatalf("create-only HA flag was not sent exactly once: creates=%d input=%#v", remote.creates, remote.createInput)
	}
	if remote.configurationUpdates != 1 || remote.configuration.Mode != flarecloudflare.WARPConnectorHAModeLocal || remote.configuration.Local == nil {
		t.Fatalf("local HA configuration was not applied: updates=%d configuration=%#v", remote.configurationUpdates, remote.configuration)
	}
	if remote.failovers != 1 || remote.failedOverClient != "client-00" {
		t.Fatalf("declarative failover was not applied: calls=%d client=%q", remote.failovers, remote.failedOverClient)
	}
	if remote.clientLists == 0 {
		t.Fatal("dedicated WARP Connector client endpoint was not called")
	}
	if len(current.Status.Clients) != 25 {
		t.Fatalf("bounded client observations = %d, want 25", len(current.Status.Clients))
	}
	firstClient := current.Status.Clients[0]
	if len(firstClient.Connections) != 16 ||
		firstClient.Connections[0].ID != "connection-00" ||
		len(firstClient.Features) != 64 {
		t.Fatalf("dedicated client observation was not bounded: %#v", firstClient)
	}
	if current.Status.Configuration.Mode != flarewayv1alpha1.WARPConnectorHAModeLocal || current.Status.Failover == nil || current.Status.Failover.RequestID != "request-1" {
		t.Fatalf("HA/failover status was not recorded: configuration=%#v failover=%#v", current.Status.Configuration, current.Status.Failover)
	}
	if condition := meta.FindStatusCondition(current.Status.Conditions, flarewayv1alpha1.WARPConnectorConditionReady); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %#v", condition)
	}

	secretKey := types.NamespacedName{Namespace: object.Namespace, Name: warpConnectorSecretPrefix + object.Name}
	var tokenSecret corev1.Secret
	if err := kube.Get(ctx, secretKey, &tokenSecret); err != nil {
		t.Fatal(err)
	}
	if string(tokenSecret.Data[flarewayv1alpha1.WARPConnectorTokenSecretKey]) != remote.token || !metav1.IsControlledBy(&tokenSecret, &current) {
		t.Fatalf("owned token Secret is invalid: owner=%#v keys=%v", tokenSecret.OwnerReferences, tokenSecret.Data)
	}
	statusJSON, err := json.Marshal(current.Status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(statusJSON), remote.token) {
		t.Fatalf("connector token leaked into status: %s", statusJSON)
	}

	reconcileWARPConnector(ctx, t, reconciler, request, "idempotent refresh")
	if remote.creates != 1 || remote.configurationUpdates != 1 || remote.failovers != 1 || remote.tokenGets != 1 {
		t.Fatalf("idempotent reconcile repeated mutations: creates=%d config=%d failovers=%d tokens=%d", remote.creates, remote.configurationUpdates, remote.failovers, remote.tokenGets)
	}

	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	current.Spec.Name = "renamed-warp"
	current.Spec.Failover.RequestID = "request-2"
	if err := kube.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	reconcileWARPConnector(ctx, t, reconciler, request, "repair name and apply new failover request")
	if remote.nameUpdates != 1 || remote.connector.Name != "renamed-warp" || remote.failovers != 2 {
		t.Fatalf("name drift or failover request was not reconciled: names=%d remote=%q failovers=%d", remote.nameUpdates, remote.connector.Name, remote.failovers)
	}

	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if err := kube.Delete(ctx, &current); err != nil {
		t.Fatal(err)
	}
	reconcileWARPConnector(ctx, t, reconciler, request, "delete remote WARP Connector")
	if remote.deletes != 1 {
		t.Fatalf("remote delete calls = %d", remote.deletes)
	}
	if err := kube.Get(ctx, request.NamespacedName, new(flarewayv1alpha1.WARPConnector)); !apierrors.IsNotFound(err) {
		t.Fatalf("WARPConnector still exists after finalization: %v", err)
	}
}

func TestWARPConnectorObserveOnlyReportsDriftWithoutSecretsOrMutation(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 13, 0, 0, 0, time.UTC)
	remote := newFakeWARPConnectorCloudflare()
	remote.connector = flarecloudflare.WARPConnector{ID: "external-warp", AccountTag: "account-id", Name: "terraform-name", Status: flarecloudflare.TunnelStatusHealthy, TunnelType: flarecloudflare.TunnelTypeWARPConnector}
	remote.configuration = flarecloudflare.WARPConnectorConfiguration{TunnelID: "external-warp", Mode: flarecloudflare.WARPConnectorHAModeAWS, AWS: &flarecloudflare.WARPConnectorAWSConfiguration{FloatingNetworkResourceID: "eni-external"}}
	kube, reconciler, object := newWARPConnectorTestReconciler(t, remote, clock)
	object.Name = "observed"
	object.Spec.Name = "desired-name"
	object.Spec.ManagementPolicy = flarewayv1alpha1.ManagementPolicyObserveOnly
	object.Spec.ExternalRef = &flarewayv1alpha1.WARPConnectorExternalReference{TunnelID: "external-warp"}
	object.Spec.HighAvailability = flarewayv1alpha1.WARPConnectorHighAvailability{Enabled: new(true), Mode: flarewayv1alpha1.WARPConnectorHAModeLocal, Local: &flarewayv1alpha1.WARPConnectorLocalHAConfig{VIPs: []flarewayv1alpha1.WARPConnectorVirtualIP{{Address: "192.0.2.20"}}}}
	if err := kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
	reconcileWARPConnector(ctx, t, reconciler, request, "add finalizer")
	reconcileWARPConnector(ctx, t, reconciler, request, "observe external connector")

	var current flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.OwnershipVerified || current.Status.TokenSecretRef != nil {
		t.Fatalf("ObserveOnly claimed ownership or token Secret: %#v", current.Status)
	}
	conflict := meta.FindStatusCondition(current.Status.Conditions, flarewayv1alpha1.WARPConnectorConditionConflict)
	if conflict == nil || conflict.Status != metav1.ConditionTrue || !strings.Contains(conflict.Message, "remote name") || !strings.Contains(conflict.Message, "HA configuration") {
		t.Fatalf("ObserveOnly drift condition = %#v", conflict)
	}
	if remote.creates != 0 || remote.nameUpdates != 0 || remote.configurationUpdates != 0 || remote.tokenGets != 0 || remote.failovers != 0 {
		t.Fatalf("ObserveOnly mutated Cloudflare: %#v", remote)
	}
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: warpConnectorSecretPrefix + object.Name}, &secret); !apierrors.IsNotFound(err) {
		t.Fatalf("ObserveOnly token Secret exists: %v", err)
	}

	current.Spec.DeletionPolicy = flarewayv1alpha1.DeletionPolicyDelete
	if err := kube.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if err := kube.Delete(ctx, &current); err != nil {
		t.Fatal(err)
	}
	reconcileWARPConnector(ctx, t, reconciler, request, "finalize ObserveOnly")
	if remote.deletes != 0 {
		t.Fatalf("ObserveOnly deleted remote connector: %d", remote.deletes)
	}
	reconcileWARPConnector(ctx, t, reconciler, request, "remove ObserveOnly finalizer")
	if err := kube.Get(ctx, request.NamespacedName, new(flarewayv1alpha1.WARPConnector)); !apierrors.IsNotFound(err) {
		t.Fatalf("ObserveOnly WARPConnector still exists after finalization: %v", err)
	}
}

func TestWARPConnectorAdoptionVerifiesExpectedNameBeforeMutation(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 14, 0, 0, 0, time.UTC)
	remote := newFakeWARPConnectorCloudflare()
	remote.connector = flarecloudflare.WARPConnector{ID: "adopted-warp", AccountTag: "account-id", Name: "expected-old-name", Status: flarecloudflare.TunnelStatusInactive, TunnelType: flarecloudflare.TunnelTypeWARPConnector}
	remote.configuration = flarecloudflare.WARPConnectorConfiguration{TunnelID: "adopted-warp", Mode: flarecloudflare.WARPConnectorHAModeDisabled}
	kube, reconciler, object := newWARPConnectorTestReconciler(t, remote, clock)
	object.Name = "adopted"
	object.Spec.Name = "managed-new-name"
	object.Spec.ExternalRef = &flarewayv1alpha1.WARPConnectorExternalReference{TunnelID: "adopted-warp"}
	object.Spec.Adoption = flarewayv1alpha1.AdoptionSpec{Mode: flarewayv1alpha1.AdoptionModeAdoptByID, Expect: flarewayv1alpha1.AdoptionExpect{Name: "expected-old-name"}}
	if err := kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
	reconcileWARPConnector(ctx, t, reconciler, request, "add finalizer")
	reconcileWARPConnector(ctx, t, reconciler, request, "adopt connector")

	var current flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.TunnelID != "adopted-warp" || !current.Status.OwnershipVerified || remote.creates != 0 || remote.nameUpdates != 1 {
		t.Fatalf("adoption result: status=%#v creates=%d updates=%d", current.Status, remote.creates, remote.nameUpdates)
	}
}

func TestWARPConnectorCreateAttemptAnnotationCannotAuthorizeRecovery(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 15, 0, 0, 0, time.UTC)
	remote := newFakeWARPConnectorCloudflare()
	remote.connector = flarecloudflare.WARPConnector{
		ID: "foreign-warp", AccountTag: "account-id", Name: "site-warp",
		Status: flarecloudflare.TunnelStatusInactive, TunnelType: flarecloudflare.TunnelTypeWARPConnector,
	}
	remote.configuration = flarecloudflare.WARPConnectorConfiguration{TunnelID: "foreign-warp", Mode: flarecloudflare.WARPConnectorHAModeDisabled}
	kube, reconciler, object := newWARPConnectorTestReconciler(t, remote, clock)
	object.Finalizers = []string{flarewayv1alpha1.WARPConnectorFinalizer}
	object.Annotations = map[string]string{"flareway.bhyoo.com/warp-connector-create-attempted": "true"}
	if err := kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
	reconcileWARPConnector(ctx, t, reconciler, request, "reject annotation-only recovery")

	var current flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	accepted := meta.FindStatusCondition(current.Status.Conditions, flarewayv1alpha1.WARPConnectorConditionAccepted)
	if current.Status.TunnelID != "" || current.Status.OwnershipVerified || remote.creates != 0 ||
		accepted == nil || accepted.Reason != "Conflict" || !strings.Contains(accepted.Message, "AdoptById") {
		t.Fatalf("annotation authorized foreign recovery: status=%#v creates=%d accepted=%#v", current.Status, remote.creates, accepted)
	}
}

func TestWARPConnectorRecoversCreateFromControllerStatusCheckpoint(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 15, 30, 0, 0, time.UTC)
	remote := newFakeWARPConnectorCloudflare()
	remote.connector = flarecloudflare.WARPConnector{
		ID: "recovered-warp", AccountTag: "account-id", Name: "site-warp",
		Status: flarecloudflare.TunnelStatusInactive, TunnelType: flarecloudflare.TunnelTypeWARPConnector,
	}
	remote.configuration = flarecloudflare.WARPConnectorConfiguration{TunnelID: "recovered-warp", Mode: flarecloudflare.WARPConnectorHAModeDisabled}
	kube, reconciler, object := newWARPConnectorTestReconciler(t, remote, clock)
	object.Finalizers = []string{flarewayv1alpha1.WARPConnectorFinalizer}
	object.Generation = 7
	if err := kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	var checkpointed flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, client.ObjectKeyFromObject(object), &checkpointed); err != nil {
		t.Fatal(err)
	}
	checkpointed.Status.CreateAttemptName = "site-warp"
	checkpointed.Status.CreateAttemptGeneration = checkpointed.Generation
	if err := kube.Status().Update(ctx, &checkpointed); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
	reconcileWARPConnector(ctx, t, reconciler, request, "recover created connector")
	reconcileWARPConnector(ctx, t, reconciler, request, "refresh recovered connector")

	var current flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.TunnelID != "recovered-warp" || !current.Status.OwnershipVerified ||
		current.Status.CreateAttemptName != "" || current.Status.CreateAttemptGeneration != 0 || remote.creates != 0 {
		t.Fatalf("create recovery result: status=%#v creates=%d", current.Status, remote.creates)
	}
}

func TestWARPConnectorCreateRecoveryRequiresExactRemoteContract(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeWARPConnectorCloudflare, *flarewayv1alpha1.WARPConnector)
	}{
		{
			name: "account",
			mutate: func(remote *fakeWARPConnectorCloudflare, _ *flarewayv1alpha1.WARPConnector) {
				remote.connector.AccountTag = "other-account"
			},
		},
		{
			name: "type",
			mutate: func(remote *fakeWARPConnectorCloudflare, _ *flarewayv1alpha1.WARPConnector) {
				remote.connector.TunnelType = flarecloudflare.TunnelTypeCloudflared
			},
		},
		{
			name: "name",
			mutate: func(remote *fakeWARPConnectorCloudflare, _ *flarewayv1alpha1.WARPConnector) {
				remote.connector.Name = "SITE-WARP"
			},
		},
		{
			name: "HA capability",
			mutate: func(_ *fakeWARPConnectorCloudflare, object *flarewayv1alpha1.WARPConnector) {
				object.Spec.HighAvailability.Enabled = new(true)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			clock := time.Date(2026, time.September, 14, 16, 0, 0, 0, time.UTC)
			remote := newFakeWARPConnectorCloudflare()
			remote.connector = flarecloudflare.WARPConnector{
				ID: "foreign-warp", AccountTag: "account-id", Name: "site-warp",
				Status: flarecloudflare.TunnelStatusInactive, TunnelType: flarecloudflare.TunnelTypeWARPConnector,
			}
			remote.configuration = flarecloudflare.WARPConnectorConfiguration{TunnelID: "foreign-warp", Mode: flarecloudflare.WARPConnectorHAModeDisabled}
			kube, reconciler, object := newWARPConnectorTestReconciler(t, remote, clock)
			object.Finalizers = []string{flarewayv1alpha1.WARPConnectorFinalizer}
			object.Generation = 8
			test.mutate(remote, object)
			if err := kube.Create(ctx, object); err != nil {
				t.Fatal(err)
			}
			var checkpointed flarewayv1alpha1.WARPConnector
			if err := kube.Get(ctx, client.ObjectKeyFromObject(object), &checkpointed); err != nil {
				t.Fatal(err)
			}
			checkpointed.Status.CreateAttemptName = "site-warp"
			checkpointed.Status.CreateAttemptGeneration = checkpointed.Generation
			if err := kube.Status().Update(ctx, &checkpointed); err != nil {
				t.Fatal(err)
			}
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
			reconcileWARPConnector(ctx, t, reconciler, request, "reject mismatched create recovery")

			var current flarewayv1alpha1.WARPConnector
			if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
				t.Fatal(err)
			}
			accepted := meta.FindStatusCondition(current.Status.Conditions, flarewayv1alpha1.WARPConnectorConditionAccepted)
			if current.Status.TunnelID != "" || current.Status.OwnershipVerified || remote.creates != 0 ||
				accepted == nil || accepted.Reason != "Conflict" || !strings.Contains(accepted.Message, "AdoptById") {
				t.Fatalf("mismatched connector was recovered: status=%#v creates=%d accepted=%#v", current.Status, remote.creates, accepted)
			}
		})
	}
}

func TestWARPConnectorAdoptionRequiresExpectedName(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 16, 30, 0, 0, time.UTC)
	remote := newFakeWARPConnectorCloudflare()
	remote.connector = flarecloudflare.WARPConnector{
		ID: "adopted-warp", AccountTag: "account-id", Name: "existing-name",
		Status: flarecloudflare.TunnelStatusInactive, TunnelType: flarecloudflare.TunnelTypeWARPConnector,
	}
	kube, reconciler, object := newWARPConnectorTestReconciler(t, remote, clock)
	object.Finalizers = []string{flarewayv1alpha1.WARPConnectorFinalizer}
	object.Spec.ExternalRef = &flarewayv1alpha1.WARPConnectorExternalReference{TunnelID: "adopted-warp"}
	object.Spec.Adoption.Mode = flarewayv1alpha1.AdoptionModeAdoptByID
	if err := kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
	reconcileWARPConnector(ctx, t, reconciler, request, "reject adoption without expected name")

	var current flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	accepted := meta.FindStatusCondition(current.Status.Conditions, flarewayv1alpha1.WARPConnectorConditionAccepted)
	if current.Status.TunnelID != "" || current.Status.OwnershipVerified ||
		accepted == nil || accepted.Reason != "Invalid" || !strings.Contains(accepted.Message, "adoption.expect.name") {
		t.Fatalf("adoption without expectation was accepted: status=%#v accepted=%#v", current.Status, accepted)
	}
}

func TestWARPConnectorClearsCreateCheckpointOnGenerationChangeAndDeletion(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 17, 0, 0, 0, time.UTC)
	remote := newFakeWARPConnectorCloudflare()
	kube, reconciler, object := newWARPConnectorTestReconciler(t, remote, clock)
	object.Finalizers = []string{flarewayv1alpha1.WARPConnectorFinalizer}
	object.Generation = 9
	if err := kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
	var current flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	current.Status.CreateAttemptName = "site-warp"
	current.Status.CreateAttemptGeneration = current.Generation + 1
	if err := kube.Status().Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	reconcileWARPConnector(ctx, t, reconciler, request, "clear stale generation checkpoint")
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.CreateAttemptName != "" || current.Status.CreateAttemptGeneration != 0 || remote.creates != 0 {
		t.Fatalf("stale checkpoint was not cleared: status=%#v creates=%d", current.Status, remote.creates)
	}

	current.Status.CreateAttemptName = "site-warp"
	current.Status.CreateAttemptGeneration = current.Generation
	if err := kube.Status().Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if err := kube.Delete(ctx, &current); err != nil {
		t.Fatal(err)
	}
	reconcileWARPConnector(ctx, t, reconciler, request, "clear deleting checkpoint")
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.CreateAttemptName != "" || current.Status.CreateAttemptGeneration != 0 || remote.deletes != 0 {
		t.Fatalf("deleting checkpoint was not cleared: status=%#v deletes=%d", current.Status, remote.deletes)
	}
}

func TestWARPConnectorCreateCheckpointUsesNormalizedName(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 17, 30, 0, 0, time.UTC)
	remote := newFakeWARPConnectorCloudflare()
	kube, reconciler, object := newWARPConnectorTestReconciler(t, remote, clock)
	object.Finalizers = []string{flarewayv1alpha1.WARPConnectorFinalizer}
	object.Spec.Name = "  site-warp  "
	if err := kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
	reconcileWARPConnector(ctx, t, reconciler, request, "checkpoint normalized create")

	var current flarewayv1alpha1.WARPConnector
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.CreateAttemptName != "site-warp" ||
		current.Status.CreateAttemptGeneration != current.Generation || remote.creates != 0 {
		t.Fatalf("normalized create was not checkpointed before mutation: status=%#v creates=%d", current.Status, remote.creates)
	}
	if accepted := meta.FindStatusCondition(current.Status.Conditions, flarewayv1alpha1.WARPConnectorConditionAccepted); accepted != nil && accepted.Reason == "Conflict" {
		t.Fatalf("normalized fresh create claimed a foreign name collision: %#v", accepted)
	}

	reconcileWARPConnector(ctx, t, reconciler, request, "create with normalized name")
	if remote.creates != 1 || remote.createInput.Name != "site-warp" {
		t.Fatalf("create input was not normalized: creates=%d input=%#v", remote.creates, remote.createInput)
	}
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.CreateAttemptName != "" || current.Status.CreateAttemptGeneration != 0 {
		t.Fatalf("successful create did not clear checkpoint: %#v", current.Status)
	}
}

func newWARPConnectorTestReconciler(t *testing.T, remote *fakeWARPConnectorCloudflare, clock time.Time) (client.Client, *WARPConnectorReconciler, *flarewayv1alpha1.WARPConnector) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := flarewayv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}}
	credential := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "platform"}, Data: map[string][]byte{"token": []byte("api-token")}}
	platform := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	account := &flarewayv1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: flarewayv1alpha1.CloudflareAccountSpec{
			AccountID:   "account-id",
			Credentials: flarewayv1alpha1.CloudflareAccountCredentials{APITokenSecretRef: flarewayv1alpha1.NamespacedSecretKeyReference{Name: "credentials", Namespace: "platform", Key: "token"}},
			Grants:      []flarewayv1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}}, PlatformObjects: flarewayv1alpha1.GrantPermissionAllowed}},
		},
		Status: flarewayv1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: flarewayv1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(clock)},
			{Type: flarewayv1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: metav1.NewTime(clock)},
		}},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&flarewayv1alpha1.WARPConnector{}).WithObjects(namespace, platform, credential, account).Build()
	factory := func(token, accountID string) (flarecloudflare.WARPConnectorAPI, error) {
		if token != "api-token" || accountID != "account-id" {
			return nil, fmt.Errorf("unexpected credentials")
		}
		return remote, nil
	}
	object := &flarewayv1alpha1.WARPConnector{
		ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: types.UID("warp-uid")},
		Spec: flarewayv1alpha1.WARPConnectorSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Name:             "site-warp",
			HighAvailability: flarewayv1alpha1.WARPConnectorHighAvailability{Enabled: new(false), Mode: flarewayv1alpha1.WARPConnectorHAModeDisabled},
			ManagementPolicy: flarewayv1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   flarewayv1alpha1.DeletionPolicyOrphan,
		},
	}
	return kube, &WARPConnectorReconciler{Client: kube, Scheme: scheme, NewCloudflareClient: factory, Now: func() time.Time { return clock }}, object
}

func reconcileWARPConnector(ctx context.Context, t *testing.T, reconciler *WARPConnectorReconciler, request ctrl.Request, step string) {
	t.Helper()
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("%s: %v", step, err)
	}
}

type fakeWARPConnectorCloudflare struct {
	connector            flarecloudflare.WARPConnector
	configuration        flarecloudflare.WARPConnectorConfiguration
	clients              []flarecloudflare.WARPConnectorClient
	token                string
	createInput          flarecloudflare.WARPConnectorCreateInput
	creates              int
	nameUpdates          int
	configurationUpdates int
	failovers            int
	tokenGets            int
	clientLists          int
	deletes              int
	failedOverClient     string
}

func newFakeWARPConnectorCloudflare() *fakeWARPConnectorCloudflare {
	return &fakeWARPConnectorCloudflare{token: "warp-bootstrap-secret", configuration: flarecloudflare.WARPConnectorConfiguration{Mode: flarecloudflare.WARPConnectorHAModeDisabled}}
}

func (fake *fakeWARPConnectorCloudflare) CreateWARPConnector(_ context.Context, input flarecloudflare.WARPConnectorCreateInput) (flarecloudflare.WARPConnector, error) {
	fake.creates++
	fake.createInput = input
	fake.connector = flarecloudflare.WARPConnector{ID: "warp-id", AccountTag: "account-id", Name: input.Name, Status: flarecloudflare.TunnelStatusInactive, TunnelType: flarecloudflare.TunnelTypeWARPConnector}
	fake.configuration.TunnelID = fake.connector.ID
	return fake.connector, nil
}
func (fake *fakeWARPConnectorCloudflare) ListWARPConnectors(context.Context, flarecloudflare.WARPConnectorListFilter) ([]flarecloudflare.WARPConnector, error) {
	if fake.connector.ID == "" || fake.connector.Name == "" {
		return nil, nil
	}
	return []flarecloudflare.WARPConnector{fake.connector}, nil
}

func (fake *fakeWARPConnectorCloudflare) DeleteWARPConnector(_ context.Context, _ string) (flarecloudflare.WARPConnector, error) {
	fake.deletes++
	fake.connector.DeletedAt = new(time.Now())
	return fake.connector, nil
}

func (fake *fakeWARPConnectorCloudflare) UpdateWARPConnector(_ context.Context, _ string, input flarecloudflare.WARPConnectorUpdateInput) (flarecloudflare.WARPConnector, error) {
	if input.Name != nil {
		fake.nameUpdates++
		fake.connector.Name = *input.Name
	}
	return fake.connector, nil
}

func (fake *fakeWARPConnectorCloudflare) GetWARPConnector(_ context.Context, tunnelID string) (flarecloudflare.WARPConnector, error) {
	if fake.connector.ID != tunnelID {
		return flarecloudflare.WARPConnector{}, fmt.Errorf("connector %q not found", tunnelID)
	}
	return fake.connector, nil
}

func (fake *fakeWARPConnectorCloudflare) UpdateWARPConnectorConfiguration(_ context.Context, tunnelID string, input flarecloudflare.WARPConnectorConfigurationInput) (flarecloudflare.WARPConnectorConfiguration, error) {
	fake.configurationUpdates++
	fake.configuration = configurationFromInput(tunnelID, fake.configuration.Version+1, input)
	return fake.configuration, nil
}

func (fake *fakeWARPConnectorCloudflare) GetWARPConnectorConfiguration(context.Context, string) (flarecloudflare.WARPConnectorConfiguration, error) {
	return fake.configuration, nil
}

func (fake *fakeWARPConnectorCloudflare) ListWARPConnectorClients(context.Context, string) ([]flarecloudflare.WARPConnectorClient, error) {
	fake.clientLists++
	return append([]flarecloudflare.WARPConnectorClient(nil), fake.clients...), nil
}

func (fake *fakeWARPConnectorCloudflare) GetWARPConnectorClient(_ context.Context, _, connectorID string) (flarecloudflare.WARPConnectorClient, error) {
	for index := range fake.clients {
		if fake.clients[index].ID == connectorID {
			return fake.clients[index], nil
		}
	}
	return flarecloudflare.WARPConnectorClient{}, fmt.Errorf("client %q not found", connectorID)
}

func (fake *fakeWARPConnectorCloudflare) FailoverWARPConnector(_ context.Context, _ string, clientID string) error {
	fake.failovers++
	fake.failedOverClient = clientID
	for index := range fake.clients {
		if fake.clients[index].ID == clientID {
			fake.clients[index].HAStatus = flarecloudflare.WARPConnectorClientHAStatusActive
		} else if fake.clients[index].HAStatus == flarecloudflare.WARPConnectorClientHAStatusActive {
			fake.clients[index].HAStatus = flarecloudflare.WARPConnectorClientHAStatusPassive
		}
	}
	return nil
}

func (fake *fakeWARPConnectorCloudflare) GetWARPConnectorToken(context.Context, string) (string, error) {
	fake.tokenGets++
	return fake.token, nil
}

func configurationFromInput(tunnelID string, version int64, input flarecloudflare.WARPConnectorConfigurationInput) flarecloudflare.WARPConnectorConfiguration {
	result := flarecloudflare.WARPConnectorConfiguration{TunnelID: tunnelID, Version: version, Mode: input.Mode}
	if input.AWS != nil {
		result.AWS = new(*input.AWS)
	}
	if input.Local != nil {
		result.Local = &flarecloudflare.WARPConnectorLocalConfiguration{
			VIPs:         append([]string(nil), input.Local.VIPs...),
			VIPsPrevious: append([]string(nil), input.Local.VIPsPrevious...),
		}
	}
	return result
}

func oversizedWARPClients(clock time.Time) []flarecloudflare.WARPConnectorClient {
	clients := make([]flarecloudflare.WARPConnectorClient, 30)
	for clientIndex := range clients {
		connections := make([]flarecloudflare.WARPConnectorConnection, 20)
		for connectionIndex := range connections {
			connections[connectionIndex] = flarecloudflare.WARPConnectorConnection{
				ID:            fmt.Sprintf("connection-%02d", connectionIndex),
				ClientID:      fmt.Sprintf("client-%02d", clientIndex),
				ClientVersion: "2026.9",
				ColoName:      "SFO",
				OpenedAt:      new(clock.Add(time.Duration(connectionIndex) * time.Minute)),
				OriginIP:      "192.0.2.1",
			}
		}
		features := make([]string, 70)
		for featureIndex := range features {
			features[featureIndex] = fmt.Sprintf("feature-%02d", featureIndex)
		}
		clients[clientIndex] = flarecloudflare.WARPConnectorClient{
			ID: fmt.Sprintf("client-%02d", clientIndex), Arch: "arm64",
			Connections: connections, Features: features,
			HAStatus: flarecloudflare.WARPConnectorClientHAStatusPassive,
			RunAt:    new(clock), Version: "2026.9",
		}
	}
	return clients
}
