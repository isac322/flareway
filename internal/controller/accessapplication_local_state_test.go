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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/gatewayapi"
)

// newGatewayAccessWorld is accessFreshnessWorld with the application behind a
// Flareway Gateway, so it has a data plane: Programmed depends on the
// CloudflareTunnel acknowledging the application's forwarding guard, and the
// closed-gate path publishes the AUD handoff Secret for the Gateway.
func newGatewayAccessWorld(t *testing.T) (*accessFreshnessWorld, types.NamespacedName) {
	t.Helper()
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
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	epoch := metav1.NewTime(start)
	hostname := gatewayv1.Hostname("app.example.test")
	section := gatewayv1.SectionName("public")
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 1},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			Type:       v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: "gateway"},
				SectionName:                &section,
			}},
			Application:      v1alpha1.AccessApplicationSettings{Name: "tenant/app", SessionDuration: "1h"},
			Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: accessFreshnessPolicyA}}},
			OriginJWT:        v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: "tenant", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{}, Hostnames: []string{"*.example.test"}, Zones: []string{"example.test"},
				Exposures:        []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				AccessPolicyRefs: v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{
			Verified: v1alpha1.CloudflareAccountVerifiedStatus{
				AuthDomain: "team.cloudflareaccess.com", TeamName: "team",
				Zones: []v1alpha1.CloudflareVerifiedZone{{ID: "zone-example", Name: "example.test"}},
			},
			Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: epoch},
				{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: epoch},
			},
		},
	}
	group := gatewayv1.Group(v1alpha1.Group)
	config := &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: "config"}, Spec: v1alpha1.GatewayClassConfigSpec{AccountRef: &corev1.LocalObjectReference{Name: "account"}}}
	class := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: group, Kind: "GatewayClassConfig", Name: "config"},
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: "gateway-uid"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Listeners:        []gatewayv1.Listener{{Name: section, Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname}},
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: group, Kind: "CloudflareTunnel", Name: "tunnel",
			}},
		},
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "tunnel", Namespace: "tenant", UID: "tunnel-uid"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "remote-tunnel"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			DNS: v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}
	counter := &statusWriteCounter{}
	kube := accessApplicationTestClientBuilder(scheme).
		WithStatusSubresource(&v1alpha1.AccessApplication{}, &v1alpha1.CloudflareTunnel{}).
		WithObjects(application, account, config, class, gateway, tunnel,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: accessApplicationAUDNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
		).
		WithInterceptorFuncs(counter.funcs()).
		Build()
	remote := newFakeAccessApplicationCloudflare()
	remote.SetPolicy(flarecloudflare.AccessPolicy{ID: accessFreshnessPolicyA, Name: "a", Decision: "Allow"})
	world := &accessFreshnessWorld{
		kube: kube, remote: remote, counter: counter, now: start,
		request: ctrl.Request{NamespacedName: client.ObjectKeyFromObject(application)},
	}
	world.reconciler = &AccessApplicationReconciler{
		Client: kube, APIReader: kube, Scheme: scheme, OperatorNamespace: accessApplicationAUDNamespace,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Now:                 func() time.Time { return world.now },
		Freshness:           freshness.DefaultPolicy(),
		Invalidator:         freshness.NewLatch(),
	}
	return world, client.ObjectKeyFromObject(tunnel)
}

// setForwarding makes the data plane acknowledge (or drop) the application's
// forwarding guard at the tunnel's applied config version, the way the Gateway
// controller reports it once Envoy serves the protected hostname.
func setForwarding(t *testing.T, world *accessFreshnessWorld, tunnelKey types.NamespacedName, protectionDomain string, forwarding bool) {
	t.Helper()
	var tunnel v1alpha1.CloudflareTunnel
	if err := world.kube.Get(context.Background(), tunnelKey, &tunnel); err != nil {
		t.Fatalf("get CloudflareTunnel: %v", err)
	}
	tunnel.Status.ConfigVersion.Desired++
	tunnel.Status.ConfigVersion.Applied = tunnel.Status.ConfigVersion.Desired
	tunnel.Status.Hostnames = nil
	if forwarding {
		tunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: "app.example.test", ProtectionDomain: protectionDomain,
			AccessApplication: world.request.Namespace + "/" + world.request.Name,
			Guard:             v1alpha1.HostnameGuardForwarding, AppliedVersion: tunnel.Status.ConfigVersion.Applied,
		}}
	}
	if err := world.kube.Status().Update(context.Background(), &tunnel); err != nil {
		t.Fatalf("update CloudflareTunnel status: %v", err)
	}
}

func programmedStatus(t *testing.T, world *accessFreshnessWorld) metav1.ConditionStatus {
	t.Helper()
	condition := meta.FindStatusCondition(world.stored(t).Status.Conditions, accessApplicationConditionProgrammed)
	if condition == nil {
		return metav1.ConditionUnknown
	}
	return condition.Status
}

// A sweep confirmation keeps an application's gate open for twice the TTL and
// the sweep keeps renewing it, so the application's own closed-gate pass may
// never run while the sweep is healthy. That pass is also where Programmed is
// derived from the data plane and the AUD handoff is published. A data-plane
// change must therefore close the gate by itself: Programmed has to follow
// the tunnel's forwarding acknowledgement immediately, not after a TTL that a
// healthy sweep never lets expire.
func TestSweepConfirmedApplicationFollowsDataPlaneChanges(t *testing.T) {
	world, tunnelKey := newGatewayAccessWorld(t)
	latch := world.reconciler.Invalidator
	ttl := world.reconciler.Freshness.TTL(freshness.GradeAuthz)

	// Converge: the first passes compile the data plane but stay
	// unprogrammed until the tunnel acknowledges forwarding.
	var protectionDomain string
	for attempt := 0; attempt < 5 && protectionDomain == ""; attempt++ {
		world.pass(t, "bootstrap")
		if dataPlanes := world.stored(t).Status.DataPlanes; len(dataPlanes) > 0 {
			protectionDomain = dataPlanes[0].ProtectionDomain
		}
	}
	if protectionDomain == "" {
		t.Fatalf("the application never compiled a data plane: %+v", world.stored(t).Status)
	}
	setForwarding(t, world, tunnelKey, protectionDomain, true)
	for attempt := 0; attempt < 5; attempt++ {
		world.now = world.now.Add(time.Second)
		world.pass(t, "converge")
		if programmedStatus(t, world) == metav1.ConditionTrue && world.stored(t).Status.AppliedHash != "" {
			break
		}
	}
	converged := world.stored(t)
	if programmedStatus(t, world) != metav1.ConditionTrue {
		t.Fatalf("fixture never reached Programmed=True: %+v", meta.FindStatusCondition(converged.Status.Conditions, accessApplicationConditionProgrammed))
	}
	// One more pass must settle the gate stamp: it is open with zero calls.
	world.now = world.now.Add(time.Second)
	if calls, _ := world.pass(t, "settled"); len(calls) != 0 {
		t.Fatalf("converged fixture did not settle its gate, calls: %v", calls)
	}
	gatewayKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
	handoffKey := types.NamespacedName{Namespace: accessApplicationAUDNamespace, Name: accessAUDSecretName(&converged, gatewayKey)}
	var handoff corev1.Secret
	if err := world.kube.Get(context.Background(), handoffKey, &handoff); err != nil {
		t.Fatalf("converged application did not publish its AUD handoff: %v", err)
	}

	confirm := func() {
		t.Helper()
		listing, found := sweepListing(t, world.remote, converged.Status.ApplicationID)
		if !found {
			t.Fatalf("remote application %q is not listed", converged.Status.ApplicationID)
		}
		if latch.ConfirmContent("AccessApplication", world.request.NamespacedName, listing, world.now) {
			t.Fatal("the sweep found the converged application's content drifted")
		}
	}

	// (1) Past the TTL, a sweep-confirmed application with no local change
	// is a free pass: no Cloudflare calls and no status write.
	world.now = world.now.Add(ttl / 2)
	confirm()
	world.now = world.now.Add(ttl)
	writes := world.counter.writes
	if calls, _ := world.pass(t, "confirmed after TTL"); len(calls) != 0 {
		t.Fatalf("a sweep-confirmed pass past the TTL made Cloudflare calls: %v", calls)
	}
	if world.counter.writes != writes {
		t.Fatalf("a sweep-confirmed pass past the TTL wrote status %d times", world.counter.writes-writes)
	}

	// (2) The data plane drops the forwarding acknowledgement. The watch
	// event's pass must report it at once, inside the confirmation window.
	confirm()
	setForwarding(t, world, tunnelKey, protectionDomain, false)
	world.now = world.now.Add(time.Second)
	world.pass(t, "forwarding lost")
	if status := programmedStatus(t, world); status != metav1.ConditionFalse {
		t.Fatalf("Programmed = %s after the data plane lost forwarding; the sweep confirmation hid the change", status)
	}

	// (3) Forwarding comes back; Programmed must follow within a few passes.
	setForwarding(t, world, tunnelKey, protectionDomain, true)
	recovered := false
	for attempt := 0; attempt < 3 && !recovered; attempt++ {
		world.now = world.now.Add(time.Second)
		world.pass(t, "forwarding restored")
		recovered = programmedStatus(t, world) == metav1.ConditionTrue
	}
	if !recovered {
		t.Fatalf("Programmed did not recover after forwarding was restored: %+v", meta.FindStatusCondition(world.stored(t).Status.Conditions, accessApplicationConditionProgrammed))
	}
	if err := world.kube.Get(context.Background(), handoffKey, &handoff); err != nil {
		t.Fatalf("the AUD handoff did not survive the data-plane round trip: %v", err)
	}
}
