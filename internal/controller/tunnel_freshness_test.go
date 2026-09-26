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
