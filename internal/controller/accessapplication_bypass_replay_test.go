package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/gatewayapi"
)

func TestAdoptedBypassExpectationIsNotReplayed(t *testing.T) {
	const (
		childID      = "adopted-child"
		hostname     = "api.example.test"
		path         = "/public"
		legacyName   = "terraform-public"
		legacyDomain = "legacy.example.test/public"
		desiredName  = "tenant/parent/public"
	)

	ownerTag := accessDigestTag(accessOwnerTagPrefix, "owner")
	remote := newFakeAccessApplicationCloudflare()
	remote.Put(flarecloudflare.AccessApplication{
		ID: childID, Type: flarecloudflare.AccessApplicationTypeSelfHosted,
		Name: legacyName, Domain: legacyDomain,
	})
	application := bypassReplayApplication(hostname, path, desiredName, childID, legacyName)
	application.Spec.Bypass.Children[0].Adoption.Expect.Domain = legacyDomain

	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.AccessApplication{}).
		WithObjects(application.DeepCopy()).
		Build()
	reconciler := &AccessApplicationReconciler{Client: kube, Scheme: scheme}
	bypasses := []gatewayapi.AccessBypass{{Hostname: hostname, Path: path}}

	children, _, err := reconciler.reconcileBypassApplications(
		context.Background(), remote, flarecloudflare.AccessScope{}, application, bypasses, ownerTag, "cluster",
	)
	if err != nil {
		t.Fatalf("first adoption reconcile failed: %v", err)
	}
	if len(children) != 1 || children[0].ApplicationID != childID || children[0].Origin != v1alpha1.AccessBypassApplicationOriginAdopted {
		t.Fatalf("unexpected adopted child status: %#v", children)
	}
	if children[0].Name != desiredName {
		t.Fatalf("adopted child name = %q, want %q", children[0].Name, desiredName)
	}
	if updates := countAccessCalls(remote.Calls(), "Update:"+childID); updates != 1 {
		t.Fatalf("updates after adoption = %d, want 1", updates)
	}

	children, _, err = reconciler.reconcileBypassApplications(
		context.Background(), remote, flarecloudflare.AccessScope{}, application, bypasses, ownerTag, "cluster",
	)
	if err != nil {
		t.Fatalf("converged adoption reconcile replayed the original expectation: %v", err)
	}
	if len(children) != 1 || children[0].Name != desiredName {
		t.Fatalf("unexpected converged child status: %#v", children)
	}
	if updates := countAccessCalls(remote.Calls(), "Update:"+childID); updates != 1 {
		t.Fatalf("updates after converged reconcile = %d, want 1", updates)
	}

	application.Status.BypassApplications = nil
	children, _, err = reconciler.reconcileBypassApplications(
		context.Background(), remote, flarecloudflare.AccessScope{}, application, bypasses, ownerTag, "cluster",
	)
	if err != nil {
		t.Fatalf("owned child recovery without an adoption checkpoint failed: %v", err)
	}
	if len(children) != 1 || children[0].Origin != v1alpha1.AccessBypassApplicationOriginAdopted {
		t.Fatalf("unexpected recovered adoption status: %#v", children)
	}
	if updates := countAccessCalls(remote.Calls(), "Update:"+childID); updates != 1 {
		t.Fatalf("updates after checkpoint recovery = %d, want 1", updates)
	}
}

func TestAdoptedBypassExternalRefChangeRechecksExpectation(t *testing.T) {
	const (
		hostname = "api.example.test"
		path     = "/public"
		oldID    = "old-adopted-child"
		newID    = "replacement-child"
	)

	ownerTag := accessDigestTag(accessOwnerTagPrefix, "owner")
	desiredName := "tenant/parent/public"
	remote := newFakeAccessApplicationCloudflare()
	remote.Put(flarecloudflare.AccessApplication{
		ID: newID, Type: flarecloudflare.AccessApplicationTypeSelfHosted,
		Name: "unexpected-replacement", Domain: "api.example.test/public",
	})
	application := bypassReplayApplication(hostname, path, desiredName, newID, "expected-replacement")
	application.Status.BypassApplications = []v1alpha1.AccessBypassApplicationStatus{{
		Hostname: hostname, Path: path, ApplicationID: oldID, Name: desiredName,
		Origin: v1alpha1.AccessBypassApplicationOriginAdopted,
	}}

	_, _, err := (&AccessApplicationReconciler{}).reconcileBypassApplications(
		context.Background(), remote, flarecloudflare.AccessScope{}, application,
		[]gatewayapi.AccessBypass{{Hostname: hostname, Path: path}}, ownerTag, "cluster",
	)
	if err == nil || !strings.Contains(err.Error(), "adoption conflict") {
		t.Fatalf("externalRef change error = %v, want adoption conflict", err)
	}
	if updates := countAccessCalls(remote.Calls(), "Update:"+newID); updates != 0 {
		t.Fatalf("replacement updates = %d, want 0", updates)
	}
}

func TestAdoptedBypassManagedRecoveryRequiresOwnershipTags(t *testing.T) {
	const (
		childID  = "adopted-child"
		hostname = "api.example.test"
		path     = "/public"
	)

	ownerTag := accessDigestTag(accessOwnerTagPrefix, "owner")
	desiredName := "tenant/parent/public"
	remote := newFakeAccessApplicationCloudflare()
	remote.Put(flarecloudflare.AccessApplication{
		ID: childID, Type: flarecloudflare.AccessApplicationTypeSelfHosted,
		Name: desiredName, Domain: "api.example.test/public",
		Tags: []string{accessManagedTag, ownerTag},
	})
	application := bypassReplayApplication(hostname, path, desiredName, childID, "original-name")
	application.Status.BypassApplications = []v1alpha1.AccessBypassApplicationStatus{{
		Hostname: hostname, Path: path, ApplicationID: childID, Name: desiredName,
		Origin: v1alpha1.AccessBypassApplicationOriginAdopted,
	}}

	_, _, err := (&AccessApplicationReconciler{}).reconcileBypassApplications(
		context.Background(), remote, flarecloudflare.AccessScope{}, application,
		[]gatewayapi.AccessBypass{{Hostname: hostname, Path: path}}, ownerTag, "cluster",
	)
	if err == nil || !strings.Contains(err.Error(), "ownership conflict") {
		t.Fatalf("missing bypass ownership tag error = %v, want ownership conflict", err)
	}
	if updates := countAccessCalls(remote.Calls(), "Update:"+childID); updates != 0 {
		t.Fatalf("foreign child updates = %d, want 0", updates)
	}
}

func bypassReplayApplication(hostname, path, desiredName, externalID, expectedName string) *v1alpha1.AccessApplication {
	return &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "parent"},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			Type:       v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			Application: v1alpha1.AccessApplicationSettings{
				Name: "tenant/parent",
			},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			Bypass: v1alpha1.AccessBypassSpec{Children: []v1alpha1.AccessBypassChildSpec{{
				Hostname: hostname,
				Path:     path,
				Name:     desiredName,
				ExternalRef: &v1alpha1.AccessApplicationExternalReference{
					ApplicationID: externalID,
				},
				Adoption: v1alpha1.AdoptionSpec{
					Mode:   v1alpha1.AdoptionModeAdoptByID,
					Expect: v1alpha1.AdoptionExpect{Name: expectedName},
				},
			}}},
		},
	}
}

func countAccessCalls(calls []string, operation string) int {
	count := 0
	for _, call := range calls {
		if call == operation {
			count++
		}
	}
	return count
}
