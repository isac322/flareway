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
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	cloudflaredconfig "github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
)

func tunnelFreshnessScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, gatewayv1.Install, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

// configVersionWriteCounter counts status writes that change a
// CloudflareTunnel's stored status.configVersion. The tunnel writers use
// server-side apply, JSON patches, and merge patches, so the only reliable
// signal is the stored value before and after each write.
type configVersionWriteCounter struct {
	writes int
}

func (c *configVersionWriteCounter) funcs() interceptor.Funcs {
	observe := func(ctx context.Context, kube client.Client, key types.NamespacedName, write func() error) error {
		var before v1alpha1.CloudflareTunnel
		beforeErr := kube.Get(ctx, key, &before)
		if err := write(); err != nil {
			return err
		}
		var after v1alpha1.CloudflareTunnel
		if beforeErr == nil && kube.Get(ctx, key, &after) == nil &&
			!equality.Semantic.DeepEqual(before.Status.ConfigVersion, after.Status.ConfigVersion) {
			c.writes++
		}
		return nil
	}
	return interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, kube client.Client, sub string, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
			return observe(ctx, kube, client.ObjectKeyFromObject(object), func() error {
				return kube.SubResource(sub).Patch(ctx, object, patch, options...)
			})
		},
		SubResourceUpdate: func(ctx context.Context, kube client.Client, sub string, object client.Object, options ...client.SubResourceUpdateOption) error {
			return observe(ctx, kube, client.ObjectKeyFromObject(object), func() error {
				return kube.SubResource(sub).Update(ctx, object, options...)
			})
		},
		SubResourceApply: func(ctx context.Context, kube client.Client, sub string, object runtime.ApplyConfiguration, options ...client.SubResourceApplyOption) error {
			var document struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			}
			if payload, err := json.Marshal(object); err == nil {
				_ = json.Unmarshal(payload, &document)
			}
			key := types.NamespacedName{Namespace: document.Metadata.Namespace, Name: document.Metadata.Name}
			return observe(ctx, kube, key, func() error {
				return kube.SubResource(sub).Apply(ctx, object, options...)
			})
		},
	}
}

// A converged Direct-mode tunnel re-reads its remote configuration once the
// gate expires. Confirming the recorded version is not an apply: appliedAt
// documents when the configuration was written, and rewriting it on every
// confirm is a status write and watch event per tunnel per TTL. The gate must
// still open between confirms, which only works if the confirm time is kept
// in memory.
func TestDirectTunnelConfirmKeepsAppliedAt(t *testing.T) {
	ctx := context.Background()
	scheme := tunnelFreshnessScheme(t)
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account", Generation: 1},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: "cloudflare-token", Namespace: "apps", Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "apps"}},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: 1},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", ObservedGeneration: 1},
		}},
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{
			Name: "direct", Namespace: "apps", UID: "tunnel-uid", Generation: 1,
			Finalizers: []string{v1alpha1.CloudflareTunnelFinalizer},
		},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "direct"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
			Configuration: v1alpha1.CloudflareTunnelConfiguration{
				Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
				Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{Ingress: []v1alpha1.CloudflareTunnelIngressRule{{
					Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}},
				}}},
			},
		},
	}
	counter := &configVersionWriteCounter{}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.CloudflareTunnel{}, &v1alpha1.CloudflareAccount{}).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"tenant": "apps"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cloudflare-token", Namespace: "apps"}, Data: map[string][]byte{"token": []byte("api-token")}},
			account, tunnel,
		).
		WithInterceptorFuncs(counter.funcs()).
		Build()
	remote := newFakeTunnelCloudflareFactory()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	policy := freshness.DefaultPolicy()
	reconciler := &CloudflareTunnelReconciler{
		Client: kube, APIReader: kube, Scheme: scheme,
		NewCloudflareClient: remote.Client,
		Now:                 func() time.Time { return now },
		Freshness:           policy,
		Invalidator:         freshness.NewLatch(),
	}
	key := client.ObjectKeyFromObject(tunnel)
	pass := func(t *testing.T, label string) (ctrl.Result, []string) {
		t.Helper()
		before := len(remote.Calls())
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return result, remote.Calls()[before:]
	}
	stored := func(t *testing.T) v1alpha1.CloudflareTunnel {
		t.Helper()
		var current v1alpha1.CloudflareTunnel
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatalf("get CloudflareTunnel: %v", err)
		}
		return current
	}

	// Create the remote tunnel, write the configuration, and settle into the
	// gate-open steady state.
	pass(t, "create")
	now = now.Add(10 * time.Second)
	if _, calls := pass(t, "steady"); slices.Contains(calls, "GetTunnelConfiguration") {
		t.Fatalf("fixture never reached the gate-open steady state: %v", calls)
	}
	converged := stored(t).Status.ConfigVersion
	if converged.Applied == 0 || converged.AppliedAt == nil {
		t.Fatalf("fixture never applied a configuration: %+v", converged)
	}
	counter.writes = 0

	// Past the TTL the tunnel re-reads its configuration, finds the recorded
	// version, and must not rewrite configVersion.
	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	result, calls := pass(t, "confirm")
	if !slices.Contains(calls, "GetTunnelConfiguration") {
		t.Fatalf("expired gate did not re-read the remote configuration: %v", calls)
	}
	if slices.Contains(calls, "UpdateTunnelConfiguration") {
		t.Fatalf("confirm of the recorded version rewrote the remote configuration: %v", calls)
	}
	if got := stored(t).Status.ConfigVersion.AppliedAt; !got.Equal(converged.AppliedAt) {
		t.Fatalf("confirm moved configVersion.appliedAt from %v to %v", converged.AppliedAt, got)
	}
	if counter.writes != 0 {
		t.Fatalf("confirm of the recorded version wrote configVersion %d times", counter.writes)
	}
	if result.RequeueAfter != policy.TTL(freshness.GradeTraffic) {
		t.Fatalf("confirm requeue = %v, want the traffic TTL %v", result.RequeueAfter, policy.TTL(freshness.GradeTraffic))
	}

	// Shortly after the confirm the gate is open again: the confirm time is
	// anchored in memory, not in status.
	now = now.Add(10 * time.Second)
	if _, calls := pass(t, "after confirm"); slices.Contains(calls, "GetTunnelConfiguration") {
		t.Fatalf("gate stayed closed after an unchanged confirm: %v", calls)
	}

	// A real configuration change still writes the remote and moves
	// appliedAt to the time it was written.
	current := stored(t)
	current.Spec.Configuration.Direct.Ingress[0].Service.HTTPStatus.Code = 503
	current.Generation++
	if err := kube.Update(ctx, &current); err != nil {
		t.Fatalf("update spec: %v", err)
	}
	now = now.Add(time.Second)
	if _, calls := pass(t, "spec change"); !slices.Contains(calls, "UpdateTunnelConfiguration") {
		t.Fatalf("spec change did not write the remote configuration: %v", calls)
	}
	changed := stored(t).Status.ConfigVersion
	if changed.DesiredHash == converged.DesiredHash {
		t.Fatal("spec change did not record a new desired hash")
	}
	if changed.AppliedAt == nil || !changed.AppliedAt.Time.Equal(now) {
		t.Fatalf("appliedAt = %v, want the time the new configuration was written (%v)", changed.AppliedAt, now)
	}
	if counter.writes == 0 {
		t.Fatal("the configVersion write for a new configuration was not observed, so the zero-write check above proves nothing")
	}
}

// tunnelFreshnessGatewayAPI is a Cloudflare fake for the Gateway-mode tunnel
// configuration writer that counts every remote call it serves.
type tunnelFreshnessGatewayAPI struct {
	flarecloudflare.API
	accountID     string
	remoteVersion int64
	calls         []string
}

func (api *tunnelFreshnessGatewayAPI) WithTunnelLock(_ context.Context, _ string, fn func() error) error {
	return fn()
}

func (api *tunnelFreshnessGatewayAPI) GetTunnel(_ context.Context, tunnelID string) (flarecloudflare.Tunnel, error) {
	api.calls = append(api.calls, "GetTunnel")
	return flarecloudflare.Tunnel{
		ID: tunnelID, AccountTag: api.accountID,
		Type:         flarecloudflare.TunnelTypeCloudflared,
		ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (api *tunnelFreshnessGatewayAPI) GetTunnelConfiguration(_ context.Context, tunnelID string) (flarecloudflare.TunnelConfiguration, error) {
	api.calls = append(api.calls, "GetTunnelConfiguration")
	return flarecloudflare.TunnelConfiguration{
		AccountID: api.accountID, TunnelID: tunnelID, Version: api.remoteVersion,
		Source: flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (api *tunnelFreshnessGatewayAPI) UpdateTunnelConfiguration(_ context.Context, tunnelID string, _ zero_trust.TunnelCloudflaredConfigurationUpdateParams) (flarecloudflare.TunnelConfiguration, error) {
	api.calls = append(api.calls, "UpdateTunnelConfiguration")
	api.remoteVersion++
	return flarecloudflare.TunnelConfiguration{
		AccountID: api.accountID, TunnelID: tunnelID, Version: api.remoteVersion,
		Source: flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

// The Gateway-mode writer confirms the recorded configuration version the
// same way. Its result feeds status.configVersion.appliedAt in the Gateway
// status patch, so a confirm that returns a fresh time rewrites status on
// every TTL. The whole Gateway Reconcile additionally needs the xDS snapshot,
// dataplane, prober, and DNS machinery, none of which touch appliedAt, so the
// writer is exercised at its own boundary.
func TestGatewayTunnelConfigConfirmKeepsAppliedAt(t *testing.T) {
	ctx := context.Background()
	scheme := tunnelFreshnessScheme(t)
	const accountID = "0123456789abcdef0123456789abcdef"
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps", UID: "gateway-uid", Generation: 1},
		Spec: gatewayv1.GatewaySpec{Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
			Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
		}}},
	}
	compiled := &ir.Gateway{
		Key:        client.ObjectKeyFromObject(gateway),
		UID:        gateway.UID,
		Cloudflare: &ir.Cloudflare{AccountID: accountID, TunnelID: "remote-id"},
		Listeners:  []ir.Listener{{Name: "http", Hostname: "edge.example.com", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{{
			Name: "http", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
			VirtualHosts: []ir.VirtualHost{{Hostname: "edge.example.com"}},
		}},
	}
	_, hash, err := cloudflaredconfig.Compile(compiled)
	if err != nil {
		t.Fatal(err)
	}
	policy := freshness.DefaultPolicy()
	ttl := policy.TTL(freshness.GradeTraffic)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	written := metav1.NewTime(now.Add(-2 * ttl))
	gateway = &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps", UID: "gateway-uid", Generation: 1},
		Spec: gatewayv1.GatewaySpec{Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
			Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
		}}},
		Status: gatewayv1.GatewayStatus{Conditions: []metav1.Condition{{
			Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue,
			ObservedGeneration: 1, Reason: "Programmed", LastTransitionTime: written,
		}}},
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "apps", UID: "tunnel-uid", Generation: 1},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID:                "remote-id",
			AccountID:               accountID,
			OwnershipVerified:       true,
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "tunnel-token"},
			GatewayRef:              &corev1.LocalObjectReference{Name: gateway.Name},
			GatewayUID:              gateway.UID,
			ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{
				Desired: 5, DesiredHash: hash, Applied: 5, Remote: 5, AppliedAt: &written,
			},
			Conditions: []metav1.Condition{{
				Type: v1alpha1.CloudflareTunnelConditionConfigApplied, Status: metav1.ConditionTrue,
				ObservedGeneration: 1, Reason: "Applied", LastTransitionTime: written,
			}},
		},
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: "cloudflare-token", Namespace: "apps", Key: "token",
			}},
		},
	}
	counter := &configVersionWriteCounter{}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &v1alpha1.CloudflareTunnel{}).
		WithObjects(
			gateway, tunnel, account,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cloudflare-token", Namespace: "apps"}, Data: map[string][]byte{"token": []byte("api-token")}},
		).
		WithInterceptorFuncs(counter.funcs()).
		Build()
	remote := &tunnelFreshnessGatewayAPI{accountID: accountID, remoteVersion: 5}
	reconciler := &GatewayReconciler{
		Client: kube, APIReader: kube, Scheme: scheme,
		CloudflareFactory: gatewayCloudflareFactory{api: remote},
		Now:               func() time.Time { return now },
		Freshness:         policy,
		Invalidator:       freshness.NewLatch(),
	}
	configure := func(t *testing.T, label string, gateway *ir.Gateway) (cloudflareConfigResult, []string) {
		t.Helper()
		var observed v1alpha1.CloudflareTunnel
		if err := kube.Get(ctx, client.ObjectKeyFromObject(tunnel), &observed); err != nil {
			t.Fatalf("%s get tunnel: %v", label, err)
		}
		before := len(remote.calls)
		result, err := reconciler.reconcileCloudflaredConfiguration(ctx, gateway, &observed, account)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		return result, remote.calls[before:]
	}

	// The recorded appliedAt is older than the TTL, so the writer re-reads
	// the remote configuration and finds the recorded version.
	result, calls := configure(t, "confirm", compiled)
	if !slices.Contains(calls, "GetTunnelConfiguration") {
		t.Fatalf("expired gate did not re-read the remote configuration: %v", calls)
	}
	if slices.Contains(calls, "UpdateTunnelConfiguration") {
		t.Fatalf("confirm of the recorded version rewrote the remote configuration: %v", calls)
	}
	if result.appliedAt == nil || !result.appliedAt.Equal(&written) {
		t.Fatalf("confirm reported appliedAt %v, want the recorded write time %v", result.appliedAt, written)
	}
	if result.requeue != ttl {
		t.Fatalf("confirm requeue = %v, want the traffic TTL %v", result.requeue, ttl)
	}
	if counter.writes != 0 {
		t.Fatalf("confirm of the recorded version wrote configVersion %d times", counter.writes)
	}

	// Shortly after the confirm the gate is open although status still holds
	// the old appliedAt: the confirm time is anchored in memory.
	now = now.Add(10 * time.Second)
	if _, calls := configure(t, "after confirm", compiled); len(calls) != 0 {
		t.Fatalf("gate stayed closed after an unchanged confirm: %v", calls)
	}

	// A real configuration change still writes the remote and reports the
	// time it was written.
	changed := *compiled
	changed.Listeners = []ir.Listener{{Name: "http", Hostname: "other.example.com", Exposure: ir.ExposurePublic}}
	changed.Domains = []ir.ProtectionDomain{{
		Name: "http", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
		VirtualHosts: []ir.VirtualHost{{Hostname: "other.example.com"}},
	}}
	now = now.Add(time.Second)
	result, calls = configure(t, "spec change", &changed)
	if !slices.Contains(calls, "UpdateTunnelConfiguration") {
		t.Fatalf("desired change did not write the remote configuration: %v", calls)
	}
	if result.appliedAt == nil || !result.appliedAt.Time.Equal(now) {
		t.Fatalf("appliedAt = %v, want the time the new configuration was written (%v)", result.appliedAt, now)
	}
	if counter.writes == 0 {
		t.Fatal("the configVersion checkpoint for a new configuration was not observed, so the zero-write check above proves nothing")
	}
}

func TestGatewayConfigFreshnessDoesNotClearTunnelDNSInvalidation(t *testing.T) {
	ctx := context.Background()
	scheme := tunnelFreshnessScheme(t)
	const accountID = "0123456789abcdef0123456789abcdef"
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps", UID: "gateway-uid", Generation: 1},
		Spec: gatewayv1.GatewaySpec{Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
			Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
		}}},
	}
	compiled := &ir.Gateway{
		Key:        client.ObjectKeyFromObject(gateway),
		UID:        gateway.UID,
		Cloudflare: &ir.Cloudflare{AccountID: accountID, TunnelID: "remote-id"},
		Listeners:  []ir.Listener{{Name: "http", Hostname: "edge.example.com", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{{
			Name: "http", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
			VirtualHosts: []ir.VirtualHost{{Hostname: "edge.example.com"}},
		}},
	}
	_, hash, err := cloudflaredconfig.Compile(compiled)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "apps", UID: "tunnel-uid", Generation: 1},
		Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID: "remote-id", AccountID: accountID, OwnershipVerified: true,
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "tunnel-token"},
			GatewayRef:              &corev1.LocalObjectReference{Name: gateway.Name}, GatewayUID: gateway.UID,
			ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 5, DesiredHash: hash, Applied: 5, Remote: 5},
		},
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: "cloudflare-token", Namespace: "apps", Key: "token",
			}},
		},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithObjects(gateway, tunnel, account, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "cloudflare-token", Namespace: "apps"}, Data: map[string][]byte{"token": []byte("tok")},
		}).Build()
	latch := freshness.NewLatch()
	tunnelKey := client.ObjectKeyFromObject(tunnel)
	latch.Invalidate("CloudflareTunnel", tunnelKey, "DNS record drift")

	reconciler := &GatewayReconciler{
		Client: kube, APIReader: kube, Scheme: scheme,
		CloudflareFactory: gatewayCloudflareFactory{api: &tunnelFreshnessGatewayAPI{accountID: accountID, remoteVersion: 5}},
		Now:               func() time.Time { return now },
		Freshness:         freshness.DefaultPolicy(),
		Invalidator:       latch,
	}
	if _, err := reconciler.reconcileCloudflaredConfiguration(ctx, compiled, tunnel, account); err != nil {
		t.Fatalf("reconcileCloudflaredConfiguration: %v", err)
	}
	if !latch.IsInvalidated("CloudflareTunnel", tunnelKey) {
		t.Fatal("Gateway config confirmation cleared CloudflareTunnel DNS/identity sweep invalidation")
	}
}

// Finding 1 (P0): Gateway CloudflareTunnelConfig gate MUST require BOTH
// current-generation ConfigApplied=True on the tunnel AND current-generation
// Programmed=True on the Gateway; missing ConfigApplied, ConfigApplied=False/Pending,
// Gateway Programmed=False, or stale ObservedGeneration MUST run GetTunnelConfiguration.
func TestGatewayConfigGateRequiresCurrentConfigAppliedAndGatewayProgrammed(t *testing.T) {
	ctx := context.Background()
	scheme := tunnelFreshnessScheme(t)
	const accountID = "0123456789abcdef0123456789abcdef"
	compiled := &ir.Gateway{
		Key:        types.NamespacedName{Namespace: "apps", Name: "edge"},
		UID:        "gateway-uid",
		Cloudflare: &ir.Cloudflare{AccountID: accountID, TunnelID: "remote-id"},
		Listeners:  []ir.Listener{{Name: "http", Hostname: "edge.example.com", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{{
			Name: "http", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
			VirtualHosts: []ir.VirtualHost{{Hostname: "edge.example.com"}},
		}},
	}
	_, hash, err := cloudflaredconfig.Compile(compiled)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	oneSecAgo := metav1.NewTime(now.Add(-time.Second))

	runCase := func(t *testing.T, gwGen int64, gwConds []metav1.Condition, tunnelGen int64, tunnelConds []metav1.Condition, wantSkip bool) {
		t.Helper()
		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps", UID: "gateway-uid", Generation: gwGen},
			Spec: gatewayv1.GatewaySpec{Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
			}}},
			Status: gatewayv1.GatewayStatus{Conditions: gwConds},
		}
		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "apps", UID: "tunnel-uid", Generation: tunnelGen},
			Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged},
			Status: v1alpha1.CloudflareTunnelStatus{
				TunnelID: "remote-id", AccountID: accountID, OwnershipVerified: true,
				ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "tunnel-token"},
				GatewayRef:              &corev1.LocalObjectReference{Name: gateway.Name}, GatewayUID: gateway.UID,
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{
					Desired: 5, DesiredHash: hash, Applied: 5, Remote: 5, AppliedAt: &oneSecAgo,
				},
				Conditions: tunnelConds,
			},
		}
		account := &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account"},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID: accountID,
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Name: "cloudflare-token", Namespace: "apps", Key: "token",
				}},
			},
		}
		kube := fakeclient.NewClientBuilder().WithScheme(scheme).
			WithStatusSubresource(&gatewayv1.Gateway{}, &v1alpha1.CloudflareTunnel{}).
			WithObjects(gateway, tunnel, account, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "cloudflare-token", Namespace: "apps"}, Data: map[string][]byte{"token": []byte("tok")},
			}).Build()
		remote := &tunnelFreshnessGatewayAPI{accountID: accountID, remoteVersion: 5}
		reconciler := &GatewayReconciler{
			Client: kube, APIReader: kube, Scheme: scheme,
			CloudflareFactory: gatewayCloudflareFactory{api: remote},
			Now:               func() time.Time { return now },
			Freshness:         freshness.DefaultPolicy(),
			Invalidator:       freshness.NewLatch(),
		}
		if _, err := reconciler.reconcileCloudflaredConfiguration(ctx, compiled, tunnel, account); err != nil {
			t.Fatalf("reconcileCloudflaredConfiguration: %v", err)
		}
		if wantSkip && len(remote.calls) != 0 {
			t.Fatalf("converged control unexpectedly called Cloudflare: %v", remote.calls)
		}
		if !wantSkip && !slices.Contains(remote.calls, "GetTunnelConfiguration") {
			t.Fatalf("unconverged gate skipped GetTunnelConfiguration; calls=%v", remote.calls)
		}
	}

	gwReady := []metav1.Condition{{Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue, ObservedGeneration: 1, Reason: "Programmed", LastTransitionTime: oneSecAgo}}
	gwFalse := []metav1.Condition{{Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionFalse, ObservedGeneration: 1, Reason: "Pending", LastTransitionTime: oneSecAgo}}
	caTrue := []metav1.Condition{{Type: v1alpha1.CloudflareTunnelConditionConfigApplied, Status: metav1.ConditionTrue, ObservedGeneration: 1, Reason: "Applied", LastTransitionTime: oneSecAgo}}
	caPending := []metav1.Condition{{Type: v1alpha1.CloudflareTunnelConditionConfigApplied, Status: metav1.ConditionFalse, ObservedGeneration: 1, Reason: "Pending", LastTransitionTime: oneSecAgo}}

	t.Run("missing ConfigApplied", func(t *testing.T) { runCase(t, 1, gwReady, 1, nil, false) })
	t.Run("ConfigApplied False Pending", func(t *testing.T) { runCase(t, 1, gwReady, 1, caPending, false) })
	t.Run("Gateway Programmed False", func(t *testing.T) { runCase(t, 1, gwFalse, 1, caTrue, false) })
	t.Run("stale ConfigApplied ObservedGeneration", func(t *testing.T) { runCase(t, 1, gwReady, 2, caTrue, false) })
	t.Run("stale Gateway Programmed ObservedGeneration", func(t *testing.T) { runCase(t, 2, gwReady, 1, caTrue, false) })
	t.Run("converged current generation skips remote read", func(t *testing.T) { runCase(t, 1, gwReady, 1, caTrue, true) })
}

// Finding 2 (P1): Gateway pre-gate demotions that write Programmed=False must
// forget CloudflareTunnelConfig freshness only when this Gateway is the live
// writer for that tunnel, while leaving CloudflareTunnel DNS/tunnel state alone
// and protecting another owner's gate from a conflicting Gateway.
func TestGatewayPreGateDemotionsForgetOwnConfigGateButProtectForeignOwner(t *testing.T) {
	ctx := context.Background()
	scheme := tunnelFreshnessScheme(t)
	ownerGW := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps", UID: "gw-owner", Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
			}},
		},
	}
	foreignGW := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "intruder", Namespace: "apps", UID: "gw-intruder", Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
			}},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName},
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "apps", UID: "tunnel-uid", Generation: 1},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			Configuration: v1alpha1.CloudflareTunnelConfiguration{
				Mode: v1alpha1.CloudflareTunnelConfigurationModeGateway,
			},
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID: "remote-id", AccountID: "0123456789abcdef0123456789abcdef", OwnershipVerified: true,
			GatewayRef: &corev1.LocalObjectReference{Name: ownerGW.Name}, GatewayUID: ownerGW.UID,
		},
	}
	tunnelKey := client.ObjectKeyFromObject(tunnel)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &v1alpha1.CloudflareTunnel{}).
		WithObjects(gc, ownerGW, foreignGW, tunnel).Build()

	latch := freshness.NewLatch()
	reconciler := &GatewayReconciler{
		Client: kube, APIReader: kube, Scheme: scheme,
		Now:         func() time.Time { return now },
		Freshness:   freshness.DefaultPolicy(),
		Invalidator: latch,
	}

	// Seed both keys so we also verify key isolation.
	latch.MarkVerified("CloudflareTunnelConfig", tunnelKey, "cfg-h1", now)
	latch.MarkVerified("CloudflareTunnel", tunnelKey, "tun-h1", now)

	// 1. A non-owner (conflicting) Gateway demoting itself must NOT forget the real owner's config gate.
	foreignStatuses := &gatewayapi.Statuses{
		Gateway: *foreignGW.Status.DeepCopy(),
	}
	_ = reconciler.reportDataplaneRejection(ctx, client.ObjectKeyFromObject(foreignGW), foreignGW, foreignStatuses, foreignGW, &dataplaneRejectionError{reason: "Invalid"})
	if _, ok := latch.VerifiedAt("CloudflareTunnelConfig", tunnelKey, "cfg-h1"); !ok {
		t.Fatal("non-owner Gateway demotion cleared the legitimate owner's CloudflareTunnelConfig gate")
	}

	// 2. Owner Gateway demoting via handleSnapshotBuildFailure MUST forget CloudflareTunnelConfig (and keep CloudflareTunnel).
	ownerStatuses := &gatewayapi.Statuses{Gateway: *ownerGW.Status.DeepCopy()}
	_ = reconciler.handleSnapshotBuildFailure(ctx, client.ObjectKeyFromObject(ownerGW), ownerGW, nil, nil, ownerStatuses, errors.New("snapshot boom"))
	if _, ok := latch.VerifiedAt("CloudflareTunnelConfig", tunnelKey, "cfg-h1"); ok {
		t.Fatal("owner Gateway handleSnapshotBuildFailure did not forget CloudflareTunnelConfig")
	}
	if _, ok := latch.VerifiedAt("CloudflareTunnel", tunnelKey, "tun-h1"); !ok {
		t.Fatal("Gateway demotion touched distinct CloudflareTunnel freshness key")
	}

	// 3. Owner Gateway demoting via reportDataplaneRejection MUST forget CloudflareTunnelConfig.
	latch.MarkVerified("CloudflareTunnelConfig", tunnelKey, "cfg-h1", now)
	_ = reconciler.reportDataplaneRejection(ctx, client.ObjectKeyFromObject(ownerGW), ownerGW, ownerStatuses, ownerGW, &dataplaneRejectionError{reason: "Invalid"})
	if _, ok := latch.VerifiedAt("CloudflareTunnelConfig", tunnelKey, "cfg-h1"); ok {
		t.Fatal("owner Gateway reportDataplaneRejection did not forget CloudflareTunnelConfig")
	}

	// 4. Owner Gateway demoting via reportCloudflareUnprogrammed MUST forget CloudflareTunnelConfig.
	latch.MarkVerified("CloudflareTunnelConfig", tunnelKey, "cfg-h1", now)
	if err := reconciler.reportCloudflareUnprogrammed(ctx, client.ObjectKeyFromObject(ownerGW), ownerGW, nil, nil, ownerStatuses, "unprogrammed", false); err != nil {
		t.Fatalf("owner reportCloudflareUnprogrammed: %v", err)
	}
	if _, ok := latch.VerifiedAt("CloudflareTunnelConfig", tunnelKey, "cfg-h1"); ok {
		t.Fatal("owner Gateway reportCloudflareUnprogrammed did not forget CloudflareTunnelConfig")
	}

	// 5. Owner Gateway demoting via rejectGatewayAdmission (e.g., loadGatewayClassConfig invalid
	// parametersRef) MUST forget CloudflareTunnelConfig while preserving CloudflareTunnel, and
	// a non-owner Gateway hitting rejectGatewayAdmission MUST NOT clear the real owner's key.
	latch.MarkVerified("CloudflareTunnelConfig", tunnelKey, "cfg-h1", now)
	if err := reconciler.rejectGatewayAdmission(ctx, foreignGW, "InvalidParameters", "bad class", "bad class"); err != nil {
		t.Fatalf("foreign rejectGatewayAdmission: %v", err)
	}
	if _, ok := latch.VerifiedAt("CloudflareTunnelConfig", tunnelKey, "cfg-h1"); !ok {
		t.Fatal("non-owner rejectGatewayAdmission cleared the real owner's CloudflareTunnelConfig gate")
	}
	if err := reconciler.rejectGatewayAdmission(ctx, ownerGW, "InvalidParameters", "missing GatewayClassConfig", "GatewayClass parametersRef cannot be resolved"); err != nil {
		t.Fatalf("owner rejectGatewayAdmission: %v", err)
	}
	if _, ok := latch.VerifiedAt("CloudflareTunnelConfig", tunnelKey, "cfg-h1"); ok {
		t.Fatal("owner Gateway rejectGatewayAdmission did not forget CloudflareTunnelConfig")
	}
	if _, ok := latch.VerifiedAt("CloudflareTunnel", tunnelKey, "tun-h1"); !ok {
		t.Fatal("rejectGatewayAdmission touched distinct CloudflareTunnel freshness key")
	}
}

// A healthy Gateway-mode CloudflareTunnel (e.g., DNSModeExternal) must record
// MarkVerified after TTL expiry verification so subsequent reconciles open the
// gate without forcing repeated remote reads or resetting Gateway AppliedAt.
func TestGatewayModeExternalDNSTunnelRenewsGateAfterExpiry(t *testing.T) {
	ctx := context.Background()
	scheme := tunnelFreshnessScheme(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account", Generation: 1},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: "cloudflare-token", Namespace: "apps", Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "apps"}},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: 1},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", ObservedGeneration: 1},
		}},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps", UID: "gw-uid", Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "edge",
			}},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName},
	}
	appliedAt := metav1.NewTime(now)
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{
			Name: "edge", Namespace: "apps", UID: "tunnel-uid", Generation: 1,
			Finalizers: []string{v1alpha1.CloudflareTunnelFinalizer},
		},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "edge"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
			Configuration: v1alpha1.CloudflareTunnelConfiguration{
				Mode: v1alpha1.CloudflareTunnelConfigurationModeGateway,
			},
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID:          "tunnel-1",
			AccountID:         account.Spec.AccountID,
			OwnershipVerified: true,
			GatewayRef:        &corev1.LocalObjectReference{Name: gw.Name},
			GatewayUID:        gw.UID,
			ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{
				Desired:     1,
				DesiredHash: "cfg-h1",
				Applied:     1,
				Remote:      1,
				AppliedAt:   &appliedAt,
			},
			Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareTunnelConditionReady, Status: metav1.ConditionTrue, Reason: "Ready", ObservedGeneration: 1},
				{Type: v1alpha1.CloudflareTunnelConditionDNSReady, Status: metav1.ConditionTrue, Reason: "NotApplicable", ObservedGeneration: 1},
				{Type: v1alpha1.CloudflareTunnelConditionConfigApplied, Status: metav1.ConditionTrue, Reason: "Applied", ObservedGeneration: 1},
			},
		},
	}
	counter := &configVersionWriteCounter{}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.CloudflareTunnel{}, &v1alpha1.CloudflareAccount{}, &gatewayv1.Gateway{}).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"tenant": "apps"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cloudflare-token", Namespace: "apps"}, Data: map[string][]byte{"token": []byte("api-token")}},
			account, gc, gw, tunnel,
		).
		WithInterceptorFuncs(counter.funcs()).
		Build()
	remote := newFakeTunnelCloudflareFactory()
	remote.tunnels["tunnel-1"] = RemoteTunnel{
		ID:           "tunnel-1",
		AccountTag:   account.Spec.AccountID,
		Name:         "edge",
		Type:         flarecloudflare.TunnelTypeCloudflared,
		ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
		Status:       flarecloudflare.TunnelStatusHealthy,
	}
	remote.tokens["tunnel-1"] = "token-tunnel-1"
	policy := freshness.DefaultPolicy()
	latch := freshness.NewLatch()
	reconciler := &CloudflareTunnelReconciler{
		Client: kube, APIReader: kube, Scheme: scheme,
		NewCloudflareClient: remote.Client,
		Now:                 func() time.Time { return now },
		Freshness:           policy,
		Invalidator:         latch,
	}
	key := client.ObjectKeyFromObject(tunnel)

	// Initial pass sets up connector secrets & opens gate within initial TTL.
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("seed reconcile: %v", err)
	}
	counter.writes = 0

	// Advance past T2 TTL without Gateway rewriting AppliedAt: one re-verify read
	// runs, keeps AppliedAt unchanged, and MUST renew the in-memory gate.
	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	callsBeforeExpiry := len(remote.Calls())
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("expiry reconcile: %v", err)
	}
	if len(remote.Calls()) == callsBeforeExpiry {
		t.Fatalf("expired Gateway-mode tunnel did not re-verify remote")
	}
	if counter.writes != 0 {
		t.Fatalf("Gateway-mode tunnel verify mutated configVersion %d times", counter.writes)
	}
	if _, ok := latch.VerifiedAt("CloudflareTunnel", key, "cfg-h1"); !ok {
		t.Fatalf("Gateway-mode External DNS tunnel did not renew VerifiedAt in latch after verify")
	}

	// Next pass within TTL MUST stay open with zero Cloudflare calls.
	now = now.Add(10 * time.Second)
	callsBeforeSteady := len(remote.Calls())
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("post-verify steady reconcile: %v", err)
	}
	if got := remote.Calls()[callsBeforeSteady:]; len(got) != 0 {
		t.Fatalf("post-verify Gateway-mode tunnel still hit Cloudflare after renewal: %v", got)
	}
}

// tunnelGatewayDataUnchanged must return false if flareway-gateway still
// co-owns status.conditions, uses a non-status/non-Apply entry, or misses any
// granular leaf ownership across configVersion, hostnames, listeners, or
// nested protectionDomains.
func TestTunnelGatewayDataUnchangedChecksFieldsV1(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	config := v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, DesiredHash: "h1", Applied: 1, Remote: 1, AppliedAt: &now}
	hostnames := []v1alpha1.CloudflareTunnelHostnameStatus{{
		Hostname: "app.example.com", ProtectionDomain: "pd-1", AccessApplication: "apps/app",
		Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
	}}
	listeners := []v1alpha1.CloudflareTunnelListenerStatus{{
		Name: "http", Exposure: v1alpha1.ExposurePublic,
		ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{Name: "pd-1", EnvoyPort: 10001, Protected: true}},
	}}

	makeTunnel := func(op metav1.ManagedFieldsOperationType, subresource, fieldsJSON string) *v1alpha1.CloudflareTunnel {
		return &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{
				ManagedFields: []metav1.ManagedFieldsEntry{{
					Manager:     gatewayFieldManager,
					Operation:   op,
					Subresource: subresource,
					FieldsType:  "FieldsV1",
					FieldsV1:    metav1.NewFieldsV1(fieldsJSON),
				}},
			},
			Status: v1alpha1.CloudflareTunnelStatus{
				ConfigVersion: config,
				Hostnames:     hostnames,
				Listeners:     listeners,
			},
		}
	}

	fullClean := `{"f:status":{` +
		`"f:configVersion":{"f:applied":{},"f:appliedAt":{},"f:desired":{},"f:desiredHash":{},"f:remote":{}},` +
		`"f:hostnames":{"k:{\"accessApplication\":\"apps/app\",\"hostname\":\"app.example.com\",\"protectionDomain\":\"pd-1\"}":{"f:accessApplication":{},"f:appliedVersion":{},"f:guard":{},"f:hostname":{},"f:protectionDomain":{}}},` +
		`"f:listeners":{"k:{\"name\":\"http\"}":{"f:exposure":{},"f:name":{},"f:protectionDomains":{"k:{\"name\":\"pd-1\"}":{"f:envoyPort":{},"f:name":{},"f:protected":{}}}}}` +
		`}}`
	if !tunnelGatewayDataUnchanged(makeTunnel(metav1.ManagedFieldsOperationApply, "status", fullClean), config, hostnames, listeners) {
		t.Fatal("tunnelGatewayDataUnchanged returned false for full granular Apply status ownership")
	}
	if tunnelGatewayDataUnchanged(makeTunnel(metav1.ManagedFieldsOperationApply, "", fullClean), config, hostnames, listeners) {
		t.Fatal("tunnelGatewayDataUnchanged accepted non-status subresource entry")
	}
	if tunnelGatewayDataUnchanged(makeTunnel(metav1.ManagedFieldsOperationUpdate, "status", fullClean), config, hostnames, listeners) {
		t.Fatal("tunnelGatewayDataUnchanged accepted Update entry instead of Apply")
	}

	withConditions := `{"f:status":{"f:conditions":{},` +
		`"f:configVersion":{"f:applied":{},"f:appliedAt":{},"f:desired":{},"f:desiredHash":{},"f:remote":{}},` +
		`"f:hostnames":{"k:{\"accessApplication\":\"apps/app\",\"hostname\":\"app.example.com\",\"protectionDomain\":\"pd-1\"}":{"f:accessApplication":{},"f:appliedVersion":{},"f:guard":{},"f:hostname":{},"f:protectionDomain":{}}},` +
		`"f:listeners":{"k:{\"name\":\"http\"}":{"f:exposure":{},"f:name":{},"f:protectionDomains":{"k:{\"name\":\"pd-1\"}":{"f:envoyPort":{},"f:name":{},"f:protected":{}}}}}` +
		`}}`
	if tunnelGatewayDataUnchanged(makeTunnel(metav1.ManagedFieldsOperationApply, "status", withConditions), config, hostnames, listeners) {
		t.Fatal("tunnelGatewayDataUnchanged returned true when flareway-gateway still owns status.conditions")
	}

	missingConfigLeaf := `{"f:status":{` +
		`"f:configVersion":{"f:applied":{},"f:desired":{},"f:desiredHash":{},"f:remote":{}},` +
		`"f:hostnames":{"k:{\"accessApplication\":\"apps/app\",\"hostname\":\"app.example.com\",\"protectionDomain\":\"pd-1\"}":{"f:accessApplication":{},"f:appliedVersion":{},"f:guard":{},"f:hostname":{},"f:protectionDomain":{}}},` +
		`"f:listeners":{"k:{\"name\":\"http\"}":{"f:exposure":{},"f:name":{},"f:protectionDomains":{"k:{\"name\":\"pd-1\"}":{"f:envoyPort":{},"f:name":{},"f:protected":{}}}}}` +
		`}}`
	if tunnelGatewayDataUnchanged(makeTunnel(metav1.ManagedFieldsOperationApply, "status", missingConfigLeaf), config, hostnames, listeners) {
		t.Fatal("tunnelGatewayDataUnchanged returned true when configVersion.appliedAt leaf is unowned")
	}

	missingHostnameLeaf := `{"f:status":{` +
		`"f:configVersion":{"f:applied":{},"f:appliedAt":{},"f:desired":{},"f:desiredHash":{},"f:remote":{}},` +
		`"f:hostnames":{"k:{\"accessApplication\":\"apps/app\",\"hostname\":\"app.example.com\",\"protectionDomain\":\"pd-1\"}":{"f:accessApplication":{},"f:appliedVersion":{},"f:hostname":{},"f:protectionDomain":{}}},` +
		`"f:listeners":{"k:{\"name\":\"http\"}":{"f:exposure":{},"f:name":{},"f:protectionDomains":{"k:{\"name\":\"pd-1\"}":{"f:envoyPort":{},"f:name":{},"f:protected":{}}}}}` +
		`}}`
	if tunnelGatewayDataUnchanged(makeTunnel(metav1.ManagedFieldsOperationApply, "status", missingHostnameLeaf), config, hostnames, listeners) {
		t.Fatal("tunnelGatewayDataUnchanged returned true when hostnames[].guard leaf is unowned")
	}

	missingProtectionDomainLeaf := `{"f:status":{` +
		`"f:configVersion":{"f:applied":{},"f:appliedAt":{},"f:desired":{},"f:desiredHash":{},"f:remote":{}},` +
		`"f:hostnames":{"k:{\"accessApplication\":\"apps/app\",\"hostname\":\"app.example.com\",\"protectionDomain\":\"pd-1\"}":{"f:accessApplication":{},"f:appliedVersion":{},"f:guard":{},"f:hostname":{},"f:protectionDomain":{}}},` +
		`"f:listeners":{"k:{\"name\":\"http\"}":{"f:exposure":{},"f:name":{},"f:protectionDomains":{"k:{\"name\":\"pd-1\"}":{"f:name":{},"f:protected":{}}}}}` +
		`}}`
	if tunnelGatewayDataUnchanged(makeTunnel(metav1.ManagedFieldsOperationApply, "status", missingProtectionDomainLeaf), config, hostnames, listeners) {
		t.Fatal("tunnelGatewayDataUnchanged returned true when listeners[].protectionDomains[].envoyPort leaf is unowned")
	}
}
