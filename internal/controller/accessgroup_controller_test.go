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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestAccessGroupErrorPreservesRecordedZoneID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{
				APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"},
			},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
				Zones:             []string{"*"},
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{
			Verified: v1alpha1.CloudflareAccountVerifiedStatus{
				Zones: []v1alpha1.CloudflareVerifiedZone{
					{ID: "zone-a", Name: "a.example.com"},
					{ID: "zone-b", Name: "b.example.com"},
				},
			},
			Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(clock)},
				{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.NewTime(clock)},
			},
		},
	}

	baseGroup := func() *v1alpha1.AccessGroup {
		return &v1alpha1.AccessGroup{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:  "tenant",
				Name:       "grp",
				UID:        types.UID("grp-uid"),
				Generation: 2,
				Finalizers: []string{v1alpha1.AccessGroupFinalizer},
			},
			Spec: v1alpha1.AccessGroupSpec{
				AccountRef:       corev1.LocalObjectReference{Name: account.Name},
				Zone:             "b.example.com",
				Name:             "grp",
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			},
			Status: v1alpha1.AccessGroupStatus{
				GroupID:           "remote-grp-a",
				ZoneID:            "zone-a",
				OwnershipVerified: true,
			},
		}
	}

	missingRule := []v1alpha1.AccessRule{{
		DevicePosture: &v1alpha1.AccessDevicePostureRuleReference{
			RuleRef: v1alpha1.AccessObjectReference{Name: "missing-posture"},
		},
	}}

	for _, tc := range []struct {
		name       string
		mutate     func(*v1alpha1.AccessGroup)
		wantErr    bool
		wantReason string
	}{
		{
			name: "account_lookup_error_preserves_recorded_zone",
			mutate: func(g *v1alpha1.AccessGroup) {
				g.Spec.AccountRef.Name = "missing-account"
			},
			wantErr: true,
		},
		{
			name: "unverified_target_zone_preserves_recorded_zone",
			mutate: func(g *v1alpha1.AccessGroup) {
				g.Spec.Zone = "unverified.example.com"
			},
			wantReason: "Invalid",
		},
		{
			name: "include_rule_error_preserves_recorded_zone",
			mutate: func(g *v1alpha1.AccessGroup) {
				g.Spec.Include = missingRule
			},
			wantReason: "RefNotPermitted",
		},
		{
			name: "require_rule_error_preserves_recorded_zone",
			mutate: func(g *v1alpha1.AccessGroup) {
				g.Spec.Require = missingRule
			},
			wantReason: "RefNotPermitted",
		},
		{
			name: "exclude_rule_error_preserves_recorded_zone",
			mutate: func(g *v1alpha1.AccessGroup) {
				g.Spec.Exclude = missingRule
			},
			wantReason: "RefNotPermitted",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			group := baseGroup()
			tc.mutate(group)

			kube := fakeclient.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&v1alpha1.AccessGroup{}).
				WithObjects(
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("tok")}},
					account.DeepCopy(),
					group,
				).Build()
			reconciler := &AccessGroupReconciler{
				Client:              kube,
				APIReader:           kube,
				Scheme:              scheme,
				NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return &serviceTokenFakeAPI{}, nil },
				Now:                 func() time.Time { return clock },
			}

			req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant", Name: "grp"}}
			_, err := reconciler.Reconcile(ctx, req)
			if tc.wantErr && err == nil {
				t.Fatal("expected reconcile error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected reconcile error: %v", err)
			}

			var updated v1alpha1.AccessGroup
			if err := kube.Get(ctx, req.NamespacedName, &updated); err != nil {
				t.Fatal(err)
			}
			if updated.Status.GroupID != "remote-grp-a" {
				t.Fatalf("Status.GroupID = %q, want remote-grp-a", updated.Status.GroupID)
			}
			if updated.Status.ZoneID != "zone-a" {
				t.Fatalf("Status.ZoneID = %q, want preserved zone-a (never overwritten on failure before move)", updated.Status.ZoneID)
			}
			if tc.wantReason != "" {
				ready := serviceTokenCondition(updated.Status.Conditions, "Ready")
				if ready == nil || ready.Reason != tc.wantReason {
					t.Fatalf("Ready = %#v, want reason %q", ready, tc.wantReason)
				}
			}
		})
	}
}
