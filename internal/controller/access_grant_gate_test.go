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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestAccessCustomPageReferenceHonoursPerKindGrantGate(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	newAccount := func(customPages, policies v1alpha1.GrantPermission) *v1alpha1.CloudflareAccount {
		return &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account"},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID: "0123456789abcdef0123456789abcdef",
				Grants: []v1alpha1.CloudflareAccountGrant{{
					NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
					PlatformObjects:      v1alpha1.GrantPermissionAllowed,
					AccessPolicyRefs:     policies,
					AccessCustomPageRefs: customPages,
				}},
			},
		}
	}
	page := &v1alpha1.AccessCustomPage{
		ObjectMeta: metav1.ObjectMeta{Namespace: "pages", Name: "managed-page"},
		Spec: v1alpha1.AccessCustomPageSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			Name:       "managed-page",
			HTML:       "<html></html>",
		},
		Status: v1alpha1.AccessCustomPageStatus{
			CustomPageID: "remote-custom-page",
			Conditions: []metav1.Condition{
				{Type: "Accepted", Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.Now()},
			},
		},
	}
	organization := &v1alpha1.ZeroTrustOrganization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "default"},
		Spec:       v1alpha1.ZeroTrustOrganizationSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}},
	}

	for _, tc := range []struct {
		name        string
		customPages v1alpha1.GrantPermission
		policies    v1alpha1.GrantPermission
		wantID      string
		wantReason  string
	}{
		{name: "denied custom page grant blocks the reference", customPages: v1alpha1.GrantPermissionDenied, policies: v1alpha1.GrantPermissionAllowed, wantReason: authz.ReasonRefNotPermitted},
		{name: "allowed custom page grant resolves despite denied policy grant", customPages: v1alpha1.GrantPermissionAllowed, policies: v1alpha1.GrantPermissionDenied, wantID: "remote-custom-page"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := newAccount(tc.customPages, tc.policies)
			kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "pages", Labels: map[string]string{"tenant": "true"}}},
				account, page, organization,
			).Build()

			reconciler := &ZeroTrustOrganizationReconciler{Client: kube, Scheme: scheme}
			resolved, err := reconciler.resolveOrganizationCustomPageID(ctx, organization, account, nil,
				v1alpha1.AccessObjectReference{Name: page.Name, Namespace: page.Namespace})
			if tc.wantReason != "" {
				if err == nil {
					t.Fatalf("cross-namespace AccessCustomPage reference resolved to %q although the grant denies it", resolved)
				}
				if reason := privateErrorReason(err); reason != tc.wantReason {
					t.Fatalf("denial reason = %q, want %q (error: %v)", reason, tc.wantReason, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("cross-namespace AccessCustomPage reference was denied although the grant allows accessCustomPageRefs: %v", err)
			}
			if resolved != tc.wantID {
				t.Fatalf("resolved custom page ID = %q, want %q", resolved, tc.wantID)
			}
		})
	}

	policyDenied := newAccount(v1alpha1.GrantPermissionAllowed, v1alpha1.GrantPermissionDenied)
	policyKube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
		policyDenied,
	).Build()
	if err := authorizeAccessReference(ctx, policyKube, "tenant", "other", policyDenied, "AccessPolicy"); err == nil {
		t.Fatal("cross-namespace AccessPolicy reference unexpectedly bypassed the policy grant gate")
	} else if reason := privateErrorReason(err); reason != authz.ReasonRefNotPermitted {
		t.Fatalf("AccessPolicy denial reason = %q, want %q (error: %v)", reason, authz.ReasonRefNotPermitted, err)
	}
}

// denialRecordingAccessAPI is never reached on the denial path; the stub makes
// a hypothetical authorization bypass observable as a remote create.
type denialRecordingAccessAPI struct {
	flarecloudflare.AccessAPI
	creates int
}

func (f *denialRecordingAccessAPI) CreateServiceToken(_ context.Context, _ flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceTokenSecret, error) {
	f.creates++
	return flarecloudflare.ServiceTokenSecret{
		ServiceToken: flarecloudflare.ServiceToken{ID: fmt.Sprintf("remote-token-%d", f.creates), Name: input.Name},
	}, nil
}

func TestServiceTokenGrantDenialReportsRefNotPermitted(t *testing.T) {
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
				AccessPolicyRefs:  v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{
			Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(clock)},
				{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.NewTime(clock)},
			},
		},
	}
	token := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "tenant",
			Name:       "token",
			Finalizers: []string{v1alpha1.ServiceTokenFinalizer},
		},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			Name:             "token",
			Enabled:          true,
			Duration:         "8760h",
			SecretRef:        corev1.LocalObjectReference{Name: "token-credentials"},
			Rotation:         v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "1h"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	// The "tenant" namespace carries no labels, so no grant matches it.
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.ServiceToken{}).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("value")}},
			account, token,
		).Build()

	api := &denialRecordingAccessAPI{}
	reconciler := &ServiceTokenReconciler{
		Client:              kube,
		Scheme:              scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return api, nil },
		Now:                 func() time.Time { return clock },
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(token)}); err == nil {
		t.Fatal("reconcile in an ungranted namespace unexpectedly succeeded")
	}
	if api.creates != 0 {
		t.Fatalf("a remote service token was issued despite the grant denial: creates=%d", api.creates)
	}

	var denied v1alpha1.ServiceToken
	if err := kube.Get(ctx, client.ObjectKeyFromObject(token), &denied); err != nil {
		t.Fatal(err)
	}
	accepted := meta.FindStatusCondition(denied.Status.Conditions, "Accepted")
	if accepted == nil {
		t.Fatal("no Accepted condition was written for an authorization denial")
	}
	if accepted.Status != metav1.ConditionFalse {
		t.Fatalf("authorization denial condition status = %q, want False", accepted.Status)
	}
	if accepted.Reason != authz.ReasonRefNotPermitted {
		t.Errorf("authorization denial condition reason = %q, want %q (message was %q)", accepted.Reason, authz.ReasonRefNotPermitted, accepted.Message)
	}
}

func TestServiceTokenMissingAccountReportsPending(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	token := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "tenant",
			Name:       "token",
			Finalizers: []string{v1alpha1.ServiceTokenFinalizer},
		},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "absent-account"},
			Name:             "token",
			Enabled:          true,
			Duration:         "8760h",
			SecretRef:        corev1.LocalObjectReference{Name: "token-credentials"},
			Rotation:         v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "1h"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.ServiceToken{}).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
			token,
		).Build()

	reconciler := &ServiceTokenReconciler{
		Client:              kube,
		Scheme:              scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return &denialRecordingAccessAPI{}, nil },
		Now:                 func() time.Time { return clock },
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(token)}); err == nil {
		t.Fatal("reconcile with a missing CloudflareAccount unexpectedly succeeded")
	}

	var pending v1alpha1.ServiceToken
	if err := kube.Get(ctx, client.ObjectKeyFromObject(token), &pending); err != nil {
		t.Fatal(err)
	}
	accepted := meta.FindStatusCondition(pending.Status.Conditions, "Accepted")
	if accepted == nil {
		t.Fatal("no Accepted condition was written for a missing CloudflareAccount")
	}
	if accepted.Reason != "Pending" {
		t.Errorf("missing-account condition reason = %q, want %q: infrastructure failures must stay Pending, not be reclassified as authorization denials", accepted.Reason, "Pending")
	}
}
