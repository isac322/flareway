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
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

// deviceProfileReadCounter counts the remote reads the fake device profile
// Cloudflare does not record itself; its mutations are in its own call log.
type deviceProfileReadCounter struct {
	flarecloudflare.DeviceProfileAPI
	reads int
}

func (c *deviceProfileReadCounter) GetDefaultDeviceProfile(ctx context.Context) (flarecloudflare.DeviceProfile, error) {
	c.reads++
	return c.DeviceProfileAPI.GetDefaultDeviceProfile(ctx)
}

func (c *deviceProfileReadCounter) ListCustomDeviceProfiles(ctx context.Context) ([]flarecloudflare.DeviceProfile, error) {
	c.reads++
	return c.DeviceProfileAPI.ListCustomDeviceProfiles(ctx)
}

func (c *deviceProfileReadCounter) GetCustomDeviceProfile(ctx context.Context, id string) (flarecloudflare.DeviceProfile, error) {
	c.reads++
	return c.DeviceProfileAPI.GetCustomDeviceProfile(ctx, id)
}

func (c *deviceProfileReadCounter) GetDeviceProfileInclude(ctx context.Context, ref flarecloudflare.DeviceProfileRef) ([]flarecloudflare.SplitTunnelEntry, error) {
	c.reads++
	return c.DeviceProfileAPI.GetDeviceProfileInclude(ctx, ref)
}

func (c *deviceProfileReadCounter) GetDeviceProfileExclude(ctx context.Context, ref flarecloudflare.DeviceProfileRef) ([]flarecloudflare.SplitTunnelEntry, error) {
	c.reads++
	return c.DeviceProfileAPI.GetDeviceProfileExclude(ctx, ref)
}

func (c *deviceProfileReadCounter) GetDeviceProfileFallbackDomains(ctx context.Context, ref flarecloudflare.DeviceProfileRef) ([]flarecloudflare.FallbackDomain, error) {
	c.reads++
	return c.DeviceProfileAPI.GetDeviceProfileFallbackDomains(ctx, ref)
}

// A converged Managed DeviceProfile re-verifies its whole lists once the gate
// expires. When they still match, the pass must not write status: appliedAt
// records when the applied hash was recorded, and every rewrite is a watch
// event. The gate must still open right after the re-verify.
func TestDeviceProfileReverifyWritesNoStatus(t *testing.T) {
	ctx := context.Background()
	scheme := deviceProfileAggregateScheme(t)
	address := "10.20.0.0/16"
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account", Generation: 1},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: "api-token", Namespace: "tenant", Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: 1},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", ObservedGeneration: 1},
		}},
	}
	profile := &v1alpha1.DeviceProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "profile", Namespace: "tenant", UID: "profile-uid", Generation: 1,
			Finalizers: []string{v1alpha1.DeviceProfileFinalizer},
		},
		Spec: v1alpha1.DeviceProfileSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name},
			Profile:    v1alpha1.DeviceProfileTarget{Kind: v1alpha1.DeviceProfileKindDefault},
			SplitTunnel: v1alpha1.DeviceProfileSplitTunnel{
				Mode:   v1alpha1.DeviceProfileSplitTunnelModeInclude,
				Static: []v1alpha1.DeviceProfileSplitTunnelEntry{{Address: &address, Description: "static"}},
			},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyOrphan,
		},
	}
	counter := &statusWriteCounter{}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.DeviceProfile{}, &v1alpha1.CloudflareAccount{}).
		WithIndex(&v1alpha1.DeviceProfile{}, deviceProfileAccountIndex, func(object client.Object) []string {
			return []string{object.(*v1alpha1.DeviceProfile).Spec.AccountRef.Name}
		}).
		WithIndex(&v1alpha1.CloudflareAccount{}, deviceProfileCloudflareAccountIDIndex, func(object client.Object) []string {
			return []string{object.(*v1alpha1.CloudflareAccount).Spec.AccountID}
		}).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("value")}},
			account, profile,
		).
		WithInterceptorFuncs(counter.funcs()).
		Build()
	fake := newFakeDeviceProfileCloudflare()
	api := &deviceProfileReadCounter{DeviceProfileAPI: fake}
	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	reconciler := &DeviceProfileReconciler{
		Client: kube, Scheme: scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.DeviceProfileAPI, error) { return api, nil },
		Freshness:           policy,
		Invalidator:         latch,
	}
	key := client.ObjectKeyFromObject(profile)
	pass := func(t *testing.T, label string) (int, ctrl.Result) {
		t.Helper()
		before := api.reads + fake.mutationCount()
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return api.reads + fake.mutationCount() - before, result
	}
	stored := func(t *testing.T) v1alpha1.DeviceProfile {
		t.Helper()
		var current v1alpha1.DeviceProfile
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatalf("get DeviceProfile: %v", err)
		}
		return current
	}

	pass(t, "converge")
	// The first pass hashed a desired state without the bound profile ID, so
	// the stamp only settles once the ID is part of it.
	pass(t, "rebind")
	if calls, _ := pass(t, "steady"); calls != 0 {
		t.Fatalf("fixture never reached the gate-open steady state: %d remote calls", calls)
	}
	converged := stored(t)
	if converged.Status.AppliedHash == "" || converged.Status.AppliedAt == nil || len(fake.includeSnapshot(flarecloudflare.DeviceProfileRef{Kind: flarecloudflare.DeviceProfileKindDefault, ID: converged.Status.ProfileID})) == 0 {
		t.Fatalf("fixture never converged: %+v", converged.Status)
	}

	// The reconciler reads the wall clock, so the TTL elapsing is modelled by
	// moving both gate anchors — the recorded appliedAt and the in-memory
	// verify record — back past the TTL.
	expired := metav1.NewTime(time.Now().Add(-policy.TTL(freshness.GradeIndirect) - time.Second).Truncate(time.Second))
	converged.Status.AppliedAt = &expired
	if err := kube.Status().Update(ctx, &converged); err != nil {
		t.Fatalf("backdate appliedAt: %v", err)
	}
	latch.MarkVerified("DeviceProfile", key, converged.Status.AppliedHash, expired.Time)
	counter.writes = 0
	mutations := fake.mutationCount()

	calls, result := pass(t, "re-verify")
	if calls == 0 {
		t.Fatal("expired gate did not re-read the remote lists")
	}
	if fake.mutationCount() != mutations {
		t.Fatalf("unchanged re-verify mutated the remote profile: %v", fake.callsSnapshot()[mutations:])
	}
	if counter.writes != 0 {
		t.Fatalf("unchanged re-verify wrote status %d times", counter.writes)
	}
	if got := stored(t).Status.AppliedAt; !got.Equal(&expired) {
		t.Fatalf("appliedAt moved from %v to %v although appliedHash did not change", expired, got)
	}
	if result.RequeueAfter != policy.TTL(freshness.GradeIndirect) {
		t.Fatalf("re-verify requeue = %v, want the indirect TTL %v", result.RequeueAfter, policy.TTL(freshness.GradeIndirect))
	}

	// The next pass is well inside the TTL of the re-verify and must not read
	// the remote at all.
	if calls, _ := pass(t, "after re-verify"); calls != 0 {
		t.Fatalf("gate stayed closed after an unchanged re-verify: %d remote calls", calls)
	}
}
