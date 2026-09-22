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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

func TestDevicePostureIntegrationRemoteErrorRecordsStatus(t *testing.T) {
	ctx := context.Background()
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "posture-integration-test", Labels: map[string]string{"posture-test": "true"}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: namespace.Name}, Data: map[string][]byte{"token": []byte("api-token")}}
	account := postureReadyAccount(namespace.Name, secret.Name)
	object := &v1alpha1.DevicePostureIntegration{ObjectMeta: metav1.ObjectMeta{Name: "integration", Namespace: namespace.Name, Finalizers: []string{v1alpha1.DevicePostureIntegrationFinalizer}}, Spec: v1alpha1.DevicePostureIntegrationSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "integration", Type: v1alpha1.DevicePostureIntegrationTypeKolide, Interval: "1h", ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly, ExternalRef: &v1alpha1.DevicePostureIntegrationExternalReference{IntegrationID: "integration-id"}}}
	kube := controllerfake.NewClientBuilder().WithScheme(testScheme()).WithStatusSubresource(object, account).WithObjects(namespace, secret, account, object).Build()
	remoteErr := errors.New("cloudflare integration unavailable")
	reconciler := &DevicePostureIntegrationReconciler{Client: kube, Scheme: testScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) {
		return &failingPostureAPI{integrationErr: remoteErr}, nil
	}, Now: func() time.Time { return time.Unix(10, 0) }}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)})
	if !errors.Is(err, remoteErr) {
		t.Fatalf("Reconcile() error = %v, want %v", err, remoteErr)
	}
	current := new(v1alpha1.DevicePostureIntegration)
	if err := kube.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
		t.Fatal(err)
	}
	if current.Status.ObservedGeneration != current.Generation {
		t.Fatalf("observedGeneration = %d, want %d", current.Status.ObservedGeneration, current.Generation)
	}
	ready := statusutil.FindCondition(current.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "CloudflareError" {
		t.Fatalf("Ready condition = %#v, want False/CloudflareError", ready)
	}
}

func TestDevicePostureRuleRemoteErrorRecordsStatus(t *testing.T) {
	ctx := context.Background()
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "posture-rule-test", Labels: map[string]string{"posture-test": "true"}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: namespace.Name}, Data: map[string][]byte{"token": []byte("api-token")}}
	account := postureReadyAccount(namespace.Name, secret.Name)
	object := &v1alpha1.DevicePostureRule{ObjectMeta: metav1.ObjectMeta{Name: "rule", Namespace: namespace.Name, Finalizers: []string{v1alpha1.DevicePostureRuleFinalizer}}, Spec: v1alpha1.DevicePostureRuleSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "rule", Type: v1alpha1.DevicePostureRuleTypeWARP, Match: []v1alpha1.DevicePostureMatch{{Platform: v1alpha1.DevicePosturePlatformWindows}}, ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly, ExternalRef: &v1alpha1.DevicePostureRuleExternalReference{RuleID: "rule-id"}}}
	kube := controllerfake.NewClientBuilder().WithScheme(testScheme()).WithStatusSubresource(object, account).WithObjects(namespace, secret, account, object).Build()
	remoteErr := errors.New("cloudflare rule unavailable")
	reconciler := &DevicePostureRuleReconciler{Client: kube, Scheme: testScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) {
		return &failingPostureAPI{ruleErr: remoteErr}, nil
	}, Now: func() time.Time { return time.Unix(10, 0) }}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)})
	if !errors.Is(err, remoteErr) {
		t.Fatalf("Reconcile() error = %v, want %v", err, remoteErr)
	}
	current := new(v1alpha1.DevicePostureRule)
	if err := kube.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
		t.Fatal(err)
	}
	if current.Status.ObservedGeneration != current.Generation {
		t.Fatalf("observedGeneration = %d, want %d", current.Status.ObservedGeneration, current.Generation)
	}
	for _, name := range []string{"Accepted", "Ready"} {
		condition := statusutil.FindCondition(current.Status.Conditions, name)
		if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "CloudflareError" {
			t.Fatalf("%s condition = %#v, want False/CloudflareError", name, condition)
		}
	}
}

func postureReadyAccount(namespaceName, secretName string) *v1alpha1.CloudflareAccount {
	return &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: "account"}, Spec: v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef", Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: secretName, Namespace: namespaceName, Key: "token"}}, Grants: []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"posture-test": "true"}}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePrivate}, PlatformObjects: v1alpha1.GrantPermissionAllowed}}}, Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue}, {Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue}}}}
}

type failingPostureAPI struct {
	flarecloudflare.AccessAPI
	integrationErr error
	ruleErr        error
}

func (f *failingPostureAPI) GetDevicePostureIntegration(context.Context, string) (flarecloudflare.DevicePostureIntegration, error) {
	return flarecloudflare.DevicePostureIntegration{}, f.integrationErr
}

func (f *failingPostureAPI) GetDevicePostureRule(context.Context, string) (flarecloudflare.DevicePostureRule, error) {
	return flarecloudflare.DevicePostureRule{}, f.ruleErr
}

func (f *failingPostureAPI) CreateDevicePostureIntegration(context.Context, flarecloudflare.DevicePostureIntegrationInput) (flarecloudflare.DevicePostureIntegration, error) {
	return flarecloudflare.DevicePostureIntegration{}, f.integrationErr
}
func (f *failingPostureAPI) CreateDevicePostureRule(context.Context, flarecloudflare.DevicePostureRuleInput) (flarecloudflare.DevicePostureRule, error) {
	return flarecloudflare.DevicePostureRule{}, f.ruleErr
}

func testScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	return scheme
}
