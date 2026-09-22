/*
Copyright 2026 Byeonghoon Yoo.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestObserveGatewayListRediscoveriesAfterNameChange(t *testing.T) {
	api := newFakeGlobalGatewayCloudflare()
	api.putList(flarecloudflare.GatewayList{ID: "list-a", Name: "list-a", Type: flarecloudflare.GatewayListTypeDomain})
	api.putList(flarecloudflare.GatewayList{ID: "list-b", Name: "list-b", Type: flarecloudflare.GatewayListTypeDomain})
	object := &v1alpha1.ZeroTrustList{Spec: v1alpha1.ZeroTrustListSpec{Name: "list-b", Type: v1alpha1.ZeroTrustListTypeDomain}, Status: v1alpha1.ZeroTrustListStatus{ListID: "list-a"}}

	observed, err := observeGatewayList(context.Background(), api, object)
	if err != nil {
		t.Fatalf("observe renamed list: %v", err)
	}
	if observed.ID != "list-b" || observed.Name != "list-b" {
		t.Fatalf("observed list = %#v, want list-b", observed)
	}
	if got := api.count("ListGatewayLists"); got != 1 {
		t.Fatalf("ListGatewayLists calls = %d, want 1 after stale cached ID", got)
	}
}

func TestObserveGatewayRuleRediscoveriesAfterNameChange(t *testing.T) {
	api := newFakeGlobalGatewayCloudflare()
	api.putRule(flarecloudflare.GatewayRule{ID: "rule-a", Name: "rule-a"})
	api.putRule(flarecloudflare.GatewayRule{ID: "rule-b", Name: "rule-b"})
	object := &v1alpha1.ZeroTrustGatewayPolicy{Spec: v1alpha1.ZeroTrustGatewayPolicySpec{Name: "rule-b"}, Status: v1alpha1.ZeroTrustGatewayPolicyStatus{RuleID: "rule-a"}}

	observed, err := observeGatewayRule(context.Background(), api, object)
	if err != nil {
		t.Fatalf("observe renamed rule: %v", err)
	}
	if observed.ID != "rule-b" || observed.Name != "rule-b" {
		t.Fatalf("observed rule = %#v, want rule-b", observed)
	}
	if got := api.count("ListGatewayRules"); got != 1 {
		t.Fatalf("ListGatewayRules calls = %d, want 1 after stale cached ID", got)
	}
}

type zeroTrustAbsentOrganizationAPI struct {
	flarecloudflare.OrganizationAPI
}

func (zeroTrustAbsentOrganizationAPI) GetAccessOrganization(context.Context, flarecloudflare.AccessScope) (flarecloudflare.Organization, error) {
	request, _ := http.NewRequest(http.MethodGet, "https://api.cloudflare.test/resource", nil)
	return flarecloudflare.Organization{}, &cloudflaresdk.Error{StatusCode: http.StatusNotFound, Request: request, Response: &http.Response{StatusCode: http.StatusNotFound}}
}

func TestZeroTrustOrganizationAbsentRemoteIsNotReadyAfterReconcile(t *testing.T) {
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: "account"}, Spec: v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef", Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"}}, Grants: []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}}, PlatformObjects: v1alpha1.GrantPermissionAllowed}}}, Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue}, {Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue}}}}
	organization := &v1alpha1.ZeroTrustOrganization{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "default", UID: types.UID("org-uid"), Generation: 1, Finalizers: []string{v1alpha1.ZeroTrustOrganizationFinalizer}}, Spec: v1alpha1.ZeroTrustOrganizationSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly, DeletionPolicy: v1alpha1.DeletionPolicyOrphan}}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.ZeroTrustOrganization{}).WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("api-token")}}, account, organization).Build()
	api := zeroTrustAbsentOrganizationAPI{}
	reconciler := &ZeroTrustOrganizationReconciler{Client: kube, Scheme: scheme, APIReader: kube, NewCloudflareClient: func(string, string) (flarecloudflare.OrganizationAPI, error) { return api, nil }, Now: func() time.Time { return clock }}
	key := client.ObjectKeyFromObject(organization)
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("ObserveOnly reconcile: %v", err)
	}
	current := new(v1alpha1.ZeroTrustOrganization)
	if err := kube.Get(context.Background(), key, current); err != nil {
		t.Fatal(err)
	}
	for _, condition := range current.Status.Conditions {
		if (condition.Type == v1alpha1.ZeroTrustOrganizationConditionReady || condition.Type == v1alpha1.ZeroTrustOrganizationConditionAccepted) && condition.Status == metav1.ConditionTrue {
			t.Fatalf("absent organization reported %s=True: %#v", condition.Type, condition)
		}
	}
}

type zeroTrustListDeleteAPI struct {
	*fakeGlobalGatewayCloudflare
	deleteErr error
	deletes   int
}

func (f *zeroTrustListDeleteAPI) Client(string, string) (flarecloudflare.GatewayAPI, error) {
	return f, nil
}
func (f *zeroTrustListDeleteAPI) DeleteGatewayList(context.Context, string) error {
	f.deletes++
	return f.deleteErr
}

func TestZeroTrustListBlockedDeletionReportsCleanupBlockedAfterReconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: "account"}, Spec: v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef", Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "platform", Name: "api-token", Key: "token"}}, Grants: []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"platform": "true"}}, PlatformObjects: v1alpha1.GrantPermissionAllowed}}}, Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue}, {Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue}}}}
	list := &v1alpha1.ZeroTrustList{ObjectMeta: metav1.ObjectMeta{Name: "blocked", Namespace: "platform", Finalizers: []string{v1alpha1.ZeroTrustListFinalizer}}, Spec: v1alpha1.ZeroTrustListSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "blocked-list", Type: v1alpha1.ZeroTrustListTypeIP, ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete}, Status: v1alpha1.ZeroTrustListStatus{ListID: "list-1", OwnershipVerified: true}}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.ZeroTrustList{}).WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "platform", Labels: map[string]string{"platform": "true"}}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "platform", Name: "api-token"}, Data: map[string][]byte{"token": []byte("api-token")}}, account, list).Build()
	remote := &zeroTrustListDeleteAPI{fakeGlobalGatewayCloudflare: newFakeGlobalGatewayCloudflare(), deleteErr: errors.New("cloudflare: list is referenced by Gateway rule")}
	reconciler := &ZeroTrustListReconciler{Client: kube, Scheme: scheme, APIReader: kube, NewCloudflareClient: remote.Client}
	key := client.ObjectKeyFromObject(list)
	if err := kube.Delete(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("expected blocked remote deletion error")
	}
	current := new(v1alpha1.ZeroTrustList)
	if err := kube.Get(context.Background(), key, current); err != nil {
		t.Fatalf("list disappeared: %v", err)
	}
	if len(current.Finalizers) == 0 {
		t.Fatal("finalizer released despite blocked remote deletion")
	}
	blocked := findZeroTrustCondition(current.Status.Conditions, "CleanupBlocked")
	if blocked == nil || blocked.Status != metav1.ConditionTrue {
		t.Fatalf("CleanupBlocked = %#v", blocked)
	}
	ready := findZeroTrustCondition(current.Status.Conditions, v1alpha1.ZeroTrustListConditionReady)
	if ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("Ready = %#v", ready)
	}
	if remote.deletes != 1 {
		t.Fatalf("DeleteGatewayList calls = %d, want 1", remote.deletes)
	}
}

func findZeroTrustCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}
