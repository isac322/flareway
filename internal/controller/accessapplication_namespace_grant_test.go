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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// An AccessApplication in a namespace no account grant selects is told so,
// instead of TargetNotFound for a Gateway that exists, and never reaches the
// Cloudflare client.
func TestAccessApplicationInUngrantedNamespaceReportsRefNotPermitted(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewTime(time.Unix(10, 0))
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", Labels: map[string]string{"tenant": "demo"}}}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "other"}},
			Hostnames:         []string{"*"},
			Zones:             []string{"*"},
			Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
		}}},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: now},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: now},
		}},
	}
	hostname := gatewayv1.Hostname("app.example.com")
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: namespace.Name, UID: "gw-uid"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Listeners:        []gatewayv1.Listener{{Name: "web", Protocol: gatewayv1.HTTPSProtocolType, Port: 443, Hostname: &hostname}},
		},
	}
	section := gatewayv1.SectionName("web")
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app", Namespace: namespace.Name, UID: "app-uid", Generation: 1,
			Finalizers: []string{v1alpha1.AccessApplicationFinalizer},
		},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name},
			Type:       v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
					Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: gatewayv1.ObjectName(gateway.Name),
				},
				SectionName: &section,
			}},
			Application:      v1alpha1.AccessApplicationSettings{Name: "demo/app", SessionDuration: "1h"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	kube := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.AccessApplication{}).
		WithObjects(namespace, account, gateway, application).
		Build()
	r := &AccessApplicationReconciler{
		Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) {
			t.Fatal("an ungranted AccessApplication constructed a Cloudflare client")
			return nil, nil
		},
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(application)}); err != nil {
		t.Fatal(err)
	}

	var stored v1alpha1.AccessApplication
	if err := kube.Get(ctx, client.ObjectKeyFromObject(application), &stored); err != nil {
		t.Fatal(err)
	}
	accepted := meta.FindStatusCondition(stored.Status.Conditions, accessApplicationConditionAccepted)
	if accepted == nil || accepted.Status != metav1.ConditionFalse || accepted.Reason != "RefNotPermitted" ||
		!strings.Contains(accepted.Message, `namespace "demo" is not granted`) {
		t.Fatalf("Accepted = %#v, want False/RefNotPermitted naming the namespace", accepted)
	}
}
