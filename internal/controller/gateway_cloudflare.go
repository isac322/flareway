/*
Copyright 2026 The Flareway Authors.

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
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	cloudflaredconfig "github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
)

const cloudflareConvergenceTimeout = 30 * time.Second

type cloudflareConfigResult struct {
	version int64
	hash    string
	pending string
	drift   bool
	message string
}

func accessBlockFirstGateway(gateway *ir.Gateway, tunnel *v1alpha1.CloudflareTunnel) (*ir.Gateway, bool, error) {
	if gateway == nil || tunnel == nil || gateway.Cloudflare == nil {
		return gateway, false, nil
	}
	_, desiredHash, err := cloudflaredconfig.Compile(gateway)
	if err != nil {
		return nil, false, err
	}
	if desiredHash == tunnel.Status.ConfigVersion.DesiredHash {
		return gateway, false, nil
	}

	currentGuards := make(map[string]v1alpha1.HostnameGuard, len(tunnel.Status.Hostnames))
	unprotectedHosts := make(map[string]bool)
	for _, hostname := range tunnel.Status.Hostnames {
		host := strings.ToLower(hostname.Hostname)
		currentGuards[strings.Join([]string{host, hostname.ProtectionDomain, hostname.AccessApplication}, "\x00")] = hostname.Guard
		if hostname.Guard == v1alpha1.HostnameGuardUnprotected {
			unprotectedHosts[host] = true
		}
	}
	requiresBlock := false
	for _, domain := range gateway.Domains {
		if !domain.Protected || domain.Guard != ir.GuardForwarding {
			continue
		}
		for _, virtualHost := range domain.VirtualHosts {
			host := strings.ToLower(virtualHost.Hostname)
			guard := currentGuards[strings.Join([]string{host, domain.Name, domain.AccessApplication}, "\x00")]
			if guard == v1alpha1.HostnameGuardBlocked {
				// The block-first handshake already completed for this domain;
				// a public carve-out on the same hostname must not re-block it.
				continue
			}
			if guard == v1alpha1.HostnameGuardForwarding || unprotectedHosts[host] {
				requiresBlock = true
				break
			}
		}
		if requiresBlock {
			break
		}
	}
	if !requiresBlock {
		return gateway, false, nil
	}

	blocked := *gateway
	blocked.Domains = append([]ir.ProtectionDomain(nil), gateway.Domains...)
	for index := range blocked.Domains {
		if blocked.Domains[index].Protected {
			blocked.Domains[index].Guard = ir.GuardBlocked
			blocked.Domains[index].Access = nil
		}
	}
	return &blocked, true, nil
}

func retainAccessRevocationDomains(gateway *ir.Gateway, tunnel *v1alpha1.CloudflareTunnel, applications []v1alpha1.AccessApplication) {
	if gateway == nil || tunnel == nil {
		return
	}
	existing := make(map[string]struct{}, len(gateway.Domains))
	for _, domain := range gateway.Domains {
		existing[domain.Name+"\x00"+domain.AccessApplication] = struct{}{}
	}
	existingListeners := make(map[string]struct{}, len(gateway.Listeners))
	for _, listener := range gateway.Listeners {
		existingListeners[listener.Name] = struct{}{}
	}
	retainedListeners := make(map[string]ir.Listener)
	type tombstone struct {
		domain ir.ProtectionDomain
		key    string
	}
	tombstones := make([]tombstone, 0)
	for index := range applications {
		application := &applications[index]
		if application.DeletionTimestamp.IsZero() && application.Annotations[accessApplicationRevocationAnnotation] == "" {
			continue
		}
		applicationKey := application.Namespace + "/" + application.Name
		for _, dataPlane := range application.Status.DataPlanes {
			if dataPlane.Tunnel != tunnel.Name || dataPlane.ProtectionDomain == "" {
				continue
			}
			key := dataPlane.ProtectionDomain + "\x00" + applicationKey
			if _, found := existing[key]; found {
				continue
			}
			hostnames := retainedAccessHostnames(tunnel, application, dataPlane.ProtectionDomain, applicationKey)
			if len(hostnames) == 0 {
				continue
			}
			virtualHosts := make([]ir.VirtualHost, 0, len(hostnames))
			for _, hostname := range hostnames {
				virtualHosts = append(virtualHosts, ir.VirtualHost{
					Name:     dataPlane.ProtectionDomain + "-revoked-" + strings.ReplaceAll(hostname, "*", "wildcard"),
					Hostname: hostname,
				})
			}
			listenerName := string(dataPlane.Listener)
			if _, found := existingListeners[listenerName]; !found {
				exposure := ir.ExposurePublic
				for _, listener := range tunnel.Spec.Listeners {
					if string(listener.Name) == listenerName && listener.Exposure == v1alpha1.ExposurePrivate {
						exposure = ir.ExposurePrivate
						break
					}
				}
				retainedListeners[listenerName] = ir.Listener{
					Name: listenerName, Hostname: hostnames[0], EnvoyPort: dataPlane.EnvoyPort,
					Protocol: string(gatewayv1.HTTPProtocolType), Exposure: exposure,
				}
			}
			tombstones = append(tombstones, tombstone{
				key: key,
				domain: ir.ProtectionDomain{
					Name: dataPlane.ProtectionDomain, ListenerName: string(dataPlane.Listener), EnvoyPort: dataPlane.EnvoyPort,
					Protected: true, AccessApplication: applicationKey, Guard: ir.GuardBlocked, VirtualHosts: virtualHosts,
				},
			})
			existing[key] = struct{}{}
		}
	}
	sort.Slice(tombstones, func(i, j int) bool { return tombstones[i].key < tombstones[j].key })
	listenerNames := make([]string, 0, len(retainedListeners))
	for name := range retainedListeners {
		listenerNames = append(listenerNames, name)
	}
	sort.Strings(listenerNames)
	for _, name := range listenerNames {
		gateway.Listeners = append(gateway.Listeners, retainedListeners[name])
	}
	for _, retained := range tombstones {
		gateway.Domains = append(gateway.Domains, retained.domain)
	}
}

func retainedAccessHostnames(tunnel *v1alpha1.CloudflareTunnel, application *v1alpha1.AccessApplication, protectionDomain, applicationKey string) []string {
	hostnames := make([]string, 0)
	for _, status := range tunnel.Status.Hostnames {
		if status.ProtectionDomain == protectionDomain && status.AccessApplication == applicationKey && status.Hostname != "" {
			hostnames = append(hostnames, strings.ToLower(strings.TrimSuffix(status.Hostname, ".")))
		}
	}
	if len(hostnames) == 0 {
		for _, destination := range application.Status.Destinations {
			hostname := destination.Hostname
			if hostname == "" && destination.URI != "" {
				hostname, _, _ = strings.Cut(destination.URI, "/")
			}
			hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
			if hostname != "" {
				hostnames = append(hostnames, hostname)
			}
		}
	}
	sort.Strings(hostnames)
	return slices.Compact(hostnames)
}

func (r *GatewayReconciler) resolveCloudflareContext(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	cfg *v1alpha1.GatewayClassConfig,
) (*v1alpha1.CloudflareTunnel, *v1alpha1.CloudflareAccount, *v1alpha1.GatewayClassConfig, bool, error) {
	if cfg.Spec.ConformanceMode {
		return nil, nil, cfg, false, nil
	}

	tunnelName, explicit, supported := referencedTunnelName(gateway)
	if !supported {
		return nil, nil, cfg, false, nil
	}
	if tunnelName == "" {
		tunnelName = gateway.Name
	}
	key := types.NamespacedName{Namespace: gateway.Namespace, Name: tunnelName}
	var tunnel v1alpha1.CloudflareTunnel
	if err := r.Get(ctx, key, &tunnel); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, nil, cfg, false, fmt.Errorf("get CloudflareTunnel %s: %w", key, err)
		}
		if explicit {
			return nil, nil, cfg, false, fmt.Errorf("referenced CloudflareTunnel %s was not found", key)
		}
		if cfg.Spec.AccountRef == nil || cfg.Spec.AccountRef.Name == "" {
			return nil, nil, cfg, false, errors.New("the GatewayClassConfig accountRef is required in Cloudflare mode")
		}
		tunnel = v1alpha1.CloudflareTunnel{
			TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "CloudflareTunnel"},
			ObjectMeta: metav1.ObjectMeta{Name: tunnelName, Namespace: gateway.Namespace},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef:       *cfg.Spec.AccountRef.DeepCopy(),
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				DNS: v1alpha1.CloudflareTunnelDNSConfig{
					Mode: cfg.Spec.DNS.Mode, Proxied: cloneBool(cfg.Spec.DNS.Proxied),
					TTL: cloneInt64(cfg.Spec.DNS.TTL), Settings: cloneDNSSettings(cfg.Spec.DNS.Settings),
				},
			},
		}
		if err := controllerutil.SetControllerReference(gateway, &tunnel, r.Scheme); err != nil {
			return nil, nil, cfg, false, fmt.Errorf("set Gateway owner on default CloudflareTunnel: %w", err)
		}
		if err := r.Create(ctx, &tunnel); err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, nil, cfg, false, fmt.Errorf("create default CloudflareTunnel %s: %w", key, err)
		}
		return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), true, nil
	}
	if tunnelConfigurationMode(&tunnel) == v1alpha1.CloudflareTunnelConfigurationModeGateway {
		selected, _, waitingForDrain, err := selectLiveTunnelGateway(ctx, r.Client, &tunnel)
		if err != nil {
			return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), false, err
		}
		authorized := sameGatewayIdentity(gateway, selected) && tunnelGatewayStatusIdentityMatches(&tunnel, gateway)
		if !authorized || tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly ||
			tunnel.Status.DeletedAt != nil || !tunnel.Status.OwnershipVerified ||
			tunnel.Status.TunnelID == "" || tunnel.Status.ConnectorTokenSecretRef == nil {
			message := fmt.Sprintf("Waiting for exact UID-bound ownership of CloudflareTunnel %s", key)
			switch {
			case tunnel.Status.DeletedAt != nil:
				message = fmt.Sprintf("CloudflareTunnel %s is remotely deleted and draining its connector dataplane", key)
			case waitingForDrain:
				message = fmt.Sprintf("CloudflareTunnel %s is draining its prior Gateway UID dataplane", key)
			case selected != nil && !sameGatewayIdentity(gateway, selected):
				message = fmt.Sprintf("CloudflareTunnel %s is owned by Gateway %s/%s UID %s", key, selected.Namespace, selected.Name, selected.UID)
			case tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly:
				message = fmt.Sprintf("CloudflareTunnel %s is ObserveOnly and cannot authorize a connector dataplane", key)
			case authorized && !tunnel.Status.OwnershipVerified:
				message = fmt.Sprintf("CloudflareTunnel %s has not verified remote ownership", key)
			case authorized && (tunnel.Status.TunnelID == "" || tunnel.Status.ConnectorTokenSecretRef == nil):
				message = fmt.Sprintf("CloudflareTunnel %s is waiting for verified connector credentials", key)
			}
			r.clearSnapshot(client.ObjectKeyFromObject(gateway))
			var current gatewayv1.Gateway
			if err := r.Get(ctx, client.ObjectKeyFromObject(gateway), &current); err != nil {
				if apierrors.IsNotFound(err) {
					return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), true, nil
				}
				return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), false, err
			}
			if !sameGatewayIdentity(gateway, &current) {
				return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), true, nil
			}
			status := current.DeepCopy().Status
			r.prepareGatewayStatus(&status, &current)
			status.Addresses = nil
			r.setCloudflareProgrammedStatus(&status, &current, false, message)
			if err := r.patchGatewayStatus(ctx, client.ObjectKeyFromObject(&current), status); err != nil {
				return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), false, err
			}
			return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), true, nil
		}
	}

	var account v1alpha1.CloudflareAccount
	if tunnel.Spec.AccountRef.Name == "" {
		return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), false, errors.New("the CloudflareTunnel accountRef is empty")
	}
	if err := r.Get(ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &account); err != nil {
		return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), false, fmt.Errorf("get CloudflareAccount %q: %w", tunnel.Spec.AccountRef.Name, err)
	}
	return &tunnel, &account, effectiveGatewayConfig(cfg, &tunnel), false, nil
}

func referencedTunnelName(gateway *gatewayv1.Gateway) (name string, explicit, supported bool) {
	if gateway.Spec.Infrastructure == nil || gateway.Spec.Infrastructure.ParametersRef == nil {
		return "", false, true
	}
	ref := gateway.Spec.Infrastructure.ParametersRef
	if string(ref.Group) != v1alpha1.Group || string(ref.Kind) != "CloudflareTunnel" {
		return "", true, false
	}
	return ref.Name, true, true
}

func sameGatewayIdentity(expected, actual *gatewayv1.Gateway) bool {
	return expected != nil && actual != nil &&
		expected.Namespace == actual.Namespace &&
		expected.Name == actual.Name &&
		expected.UID == actual.UID
}
func (r *GatewayReconciler) validateGatewayTunnelWriter(ctx context.Context, gateway *ir.Gateway, tunnel *v1alpha1.CloudflareTunnel) (*v1alpha1.CloudflareTunnel, error) {
	if gateway == nil || gateway.UID == "" || tunnel == nil {
		return nil, errors.New("gateway Tunnel writer requires non-empty Gateway UID and Tunnel")
	}
	var currentGateway gatewayv1.Gateway
	if err := r.Get(ctx, gateway.Key, &currentGateway); err != nil {
		return nil, fmt.Errorf("revalidate Gateway %s before Tunnel write: %w", gateway.Key, err)
	}
	if currentGateway.UID != gateway.UID || !currentGateway.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("gateway %s UID %s is no longer the live writer", gateway.Key, gateway.UID)
	}
	var currentTunnel v1alpha1.CloudflareTunnel
	if err := r.Get(ctx, client.ObjectKeyFromObject(tunnel), &currentTunnel); err != nil {
		return nil, fmt.Errorf("revalidate CloudflareTunnel %s/%s before Gateway write: %w", tunnel.Namespace, tunnel.Name, err)
	}
	if tunnel.UID != "" && currentTunnel.UID != tunnel.UID {
		return nil, fmt.Errorf("CloudflareTunnel %s/%s was recreated before Gateway write", tunnel.Namespace, tunnel.Name)
	}
	selected, _, waitingForDrain, err := selectLiveTunnelGateway(ctx, r.Client, &currentTunnel)
	if err != nil {
		return nil, err
	}
	if waitingForDrain || !sameGatewayIdentity(&currentGateway, selected) || !tunnelGatewayStatusIdentityMatches(&currentTunnel, &currentGateway) {
		return nil, fmt.Errorf("gateway %s UID %s does not hold the current UID-bound Tunnel ownership", gateway.Key, gateway.UID)
	}
	if currentTunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly ||
		currentTunnel.Status.DeletedAt != nil ||
		!currentTunnel.Status.OwnershipVerified ||
		currentTunnel.Status.TunnelID == "" ||
		currentTunnel.Status.ConnectorTokenSecretRef == nil {
		return nil, fmt.Errorf("CloudflareTunnel %s/%s is not verified for managed Gateway writes", currentTunnel.Namespace, currentTunnel.Name)
	}
	return &currentTunnel, nil
}

func effectiveGatewayConfig(base *v1alpha1.GatewayClassConfig, tunnel *v1alpha1.CloudflareTunnel) *v1alpha1.GatewayClassConfig {
	result := base.DeepCopy()
	result.Spec.OriginRequest = gatewayOriginDefaults(result.Spec.OriginRequest)
	if tunnel == nil {
		return result
	}
	if override := tunnel.Spec.Connector; override != nil {
		if override.Image != "" {
			result.Spec.Connector.Image = override.Image
		}
		if override.Replicas != nil {
			result.Spec.Connector.Replicas = new(*override.Replicas)
		}
		if override.Protocol != "" {
			result.Spec.Connector.Protocol = override.Protocol
		}
		if override.GracePeriod.Duration > 0 {
			result.Spec.Connector.GracePeriod = override.GracePeriod
		}
		if len(override.Resources.Requests) > 0 || len(override.Resources.Limits) > 0 {
			result.Spec.Connector.Resources = *override.Resources.DeepCopy()
		}
	}
	if override := tunnel.Spec.Proxy; override != nil {
		if override.Image != "" {
			result.Spec.Proxy.Image = override.Image
		}
		if override.Concurrency != nil {
			result.Spec.Proxy.Concurrency = new(*override.Concurrency)
		}
		if override.StreamIdleTimeout.Duration > 0 {
			result.Spec.Proxy.StreamIdleTimeout = override.StreamIdleTimeout
		}
		if len(override.Resources.Requests) > 0 || len(override.Resources.Limits) > 0 {
			result.Spec.Proxy.Resources = *override.Resources.DeepCopy()
		}
	}
	if override := tunnel.Spec.PrivateDNS; override != nil {
		if override.Image != "" {
			result.Spec.PrivateDNS.Image = override.Image
		}
		if len(override.Resources.Requests) > 0 || len(override.Resources.Limits) > 0 {
			result.Spec.PrivateDNS.Resources = *override.Resources.DeepCopy()
		}
	}
	if override := tunnel.Spec.OriginRequest; override != nil {
		overlayGatewayOriginRequest(&result.Spec.OriginRequest, override)
	}
	return result
}

func gatewayOriginDefaults(origin v1alpha1.GatewayOriginRequestSpec) v1alpha1.GatewayOriginRequestSpec {
	if origin.ConnectTimeout == nil {
		value := metav1.Duration{Duration: 30 * time.Second}
		origin.ConnectTimeout = &value
	}
	if origin.KeepAliveTimeout == nil {
		value := metav1.Duration{Duration: 90 * time.Second}
		origin.KeepAliveTimeout = &value
	}
	if origin.KeepAliveConnections == nil {
		value := int64(100)
		origin.KeepAliveConnections = &value
	}
	if origin.NoHappyEyeballs == nil {
		value := false
		origin.NoHappyEyeballs = &value
	}
	return origin
}

func overlayGatewayOriginRequest(target *v1alpha1.GatewayOriginRequestSpec, override *v1alpha1.GatewayOriginRequestSpec) {
	if override.ConnectTimeout != nil {
		value := *override.ConnectTimeout
		target.ConnectTimeout = &value
	}
	if override.KeepAliveTimeout != nil {
		value := *override.KeepAliveTimeout
		target.KeepAliveTimeout = &value
	}
	if override.TCPKeepAlive != nil {
		value := *override.TCPKeepAlive
		target.TCPKeepAlive = &value
	}
	if override.KeepAliveConnections != nil {
		target.KeepAliveConnections = cloneInt64(override.KeepAliveConnections)
	}
	if override.NoHappyEyeballs != nil {
		target.NoHappyEyeballs = cloneBool(override.NoHappyEyeballs)
	}
	if override.DisableChunkedEncoding != nil {
		target.DisableChunkedEncoding = cloneBool(override.DisableChunkedEncoding)
	}
	if override.HTTP2Origin != nil {
		target.HTTP2Origin = cloneBool(override.HTTP2Origin)
	}
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneDNSSettings(value *v1alpha1.DNSRecordSettings) *v1alpha1.DNSRecordSettings {
	if value == nil {
		return nil
	}
	return &v1alpha1.DNSRecordSettings{IPv4Only: cloneBool(value.IPv4Only), IPv6Only: cloneBool(value.IPv6Only)}
}

func (r *GatewayReconciler) reconcileCloudflaredConfiguration(
	ctx context.Context,
	gateway *ir.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	account *v1alpha1.CloudflareAccount,
) (cloudflareConfigResult, error) {
	if tunnelConfigurationMode(tunnel) != v1alpha1.CloudflareTunnelConfigurationModeGateway {
		return cloudflareConfigResult{}, errors.New("the Gateway reconciler cannot write a Direct-mode CloudflareTunnel")
	}
	if tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		return cloudflareConfigResult{pending: "tunnel is ObserveOnly; no ingress will be written"}, nil
	}
	currentTunnel, err := r.validateGatewayTunnelWriter(ctx, gateway, tunnel)
	if err != nil {
		return cloudflareConfigResult{}, err
	}
	tunnel = currentTunnel
	params, hash, err := cloudflaredconfig.Compile(gateway)
	if err != nil {
		return cloudflareConfigResult{}, err
	}
	api, err := r.cloudflareClient(ctx, account)
	if err != nil {
		return cloudflareConfigResult{}, err
	}
	remoteTunnel, err := api.GetTunnel(ctx, tunnel.Status.TunnelID)
	if err != nil {
		return cloudflareConfigResult{}, fmt.Errorf("get Cloudflare Tunnel before configuration update: %w", err)
	}
	if err := validateRemoteTunnel(remoteTunnel, account.Spec.AccountID); err != nil {
		return cloudflareConfigResult{}, err
	}
	result := cloudflareConfigResult{hash: hash}
	err = api.WithTunnelLock(ctx, tunnel.Status.TunnelID, func() error {
		remote, err := api.GetTunnelConfiguration(ctx, tunnel.Status.TunnelID)
		if err != nil {
			return err
		}
		if err := validateRemoteConfiguration(remote, account.Spec.AccountID, tunnel.Status.TunnelID); err != nil {
			return err
		}
		if tunnel.Status.ConfigVersion.Desired > 0 &&
			tunnel.Status.ConfigVersion.DesiredHash == hash &&
			remote.Version == tunnel.Status.ConfigVersion.Desired {
			result.version = tunnel.Status.ConfigVersion.Desired
			return nil
		}
		baseline := tunnel.Status.ConfigVersion.Applied
		if baseline == 0 {
			baseline = tunnel.Status.ConfigVersion.Desired
		}
		if baseline != 0 && remote.Version != baseline {
			result.drift = true
			result.message = fmt.Sprintf("Cloudflare Tunnel configuration changed out of band: remote version %d, expected %d; overwriting with desired configuration", remote.Version, baseline)
		}
		updated, err := api.UpdateTunnelConfiguration(ctx, tunnel.Status.TunnelID, params)
		if err != nil {
			return err
		}
		if err := validateRemoteConfiguration(updated, account.Spec.AccountID, tunnel.Status.TunnelID); err != nil {
			return err
		}
		result.version = updated.Version
		return nil
	})
	if err != nil {
		return cloudflareConfigResult{}, fmt.Errorf("update Cloudflare Tunnel configuration: %w", err)
	}
	return result, nil
}

func (r *GatewayReconciler) cloudflareClient(ctx context.Context, account *v1alpha1.CloudflareAccount) (flarecloudflare.API, error) {
	if r.CloudflareFactory == nil {
		return nil, errors.New("gateway reconciler requires a Cloudflare client factory in Cloudflare mode")
	}
	ref := account.Spec.Credentials.APITokenSecretRef
	key := types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}
	var secret corev1.Secret
	if err := r.Get(ctx, key, &secret); err != nil {
		return nil, fmt.Errorf("get Cloudflare API token Secret %s: %w", key, err)
	}
	if ref.Key == "" {
		ref.Key = "token"
	}
	token := secret.Data[ref.Key]
	if len(token) == 0 {
		return nil, fmt.Errorf("cloudflare API token Secret %s has no %q key", key, ref.Key)
	}
	api := r.CloudflareFactory.Client(string(token), account.Spec.AccountID)
	if api == nil {
		return nil, errors.New("cloudflare client factory returned nil")
	}
	return api, nil
}

func (r *GatewayReconciler) cloudflareGate(
	ctx context.Context,
	gateway *ir.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	version, snapshotVersion string,
) (ready bool, lagging []string, dnsReady bool, err error) {
	if _, err := r.validateGatewayTunnelWriter(ctx, gateway, tunnel); err != nil {
		return false, nil, false, err
	}
	if version == "0" || version == "" {
		return false, []string{"remote configuration version is not available"}, false, nil
	}
	wantVersion, err := parseVersion(version)
	if err != nil {
		return false, nil, false, err
	}

	prober := r.Prober
	if prober == nil {
		prober = dataplane.NewHTTPProber(5 * time.Second)
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(gateway.Key.Namespace), client.MatchingLabels{dataplane.StandardGatewayLabelKey: gateway.Key.Name}); err != nil {
		return false, nil, false, fmt.Errorf("list dataplane Pods: %w", err)
	}
	activePods := 0
	for index := range pods.Items {
		pod := &pods.Items[index]
		if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		activePods++
		if pod.Status.PodIP == "" {
			lagging = append(lagging, pod.Name+"(no Pod IP)")
			continue
		}
		if err := prober.Ready(ctx, pod.Status.PodIP); err != nil {
			lagging = append(lagging, pod.Name+"(not ready)")
			continue
		}
		got, err := prober.ConfigVersion(ctx, pod.Status.PodIP)
		if err != nil {
			lagging = append(lagging, pod.Name+"(config unavailable)")
			continue
		}
		if got != wantVersion {
			lagging = append(lagging, fmt.Sprintf("%s(version %d)", pod.Name, got))
		}
	}
	if activePods == 0 {
		lagging = append(lagging, "no active dataplane Pods")
	}
	if !r.Snapshots.IsACKed(gateway.Key.String(), snapshotVersion) {
		message := "Envoy xDS ACK"
		if diagnostics, ok := r.Snapshots.(interface {
			ACKDetails(node, version string) string
		}); ok {
			if details := diagnostics.ACKDetails(gateway.Key.String(), snapshotVersion); details != "" {
				message += " (" + details + ")"
			}
		}
		lagging = append(lagging, message)
	}

	dnsReady = tunnel.Spec.DNS.Mode == v1alpha1.DNSModeExternal || publicDNSReady(gateway, tunnel)
	if !dnsReady {
		lagging = append(lagging, "managed DNS records")
	}
	return len(lagging) == 0, lagging, dnsReady, nil
}

func parseVersion(version string) (int64, error) {
	var value int64
	if _, err := fmt.Sscan(version, &value); err != nil {
		return 0, fmt.Errorf("parse Cloudflare configuration version %q: %w", version, err)
	}
	return value, nil
}

func publicDNSReady(gateway *ir.Gateway, tunnel *v1alpha1.CloudflareTunnel) bool {
	wanted := make(map[string]struct{})
	for _, listener := range gateway.Listeners {
		if listener.Exposure == ir.ExposurePublic && listener.Hostname != "" {
			wanted[strings.ToLower(listener.Hostname)] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return true
	}
	for _, record := range tunnel.Status.DNSRecords {
		delete(wanted, strings.ToLower(record.Hostname))
	}
	return len(wanted) == 0
}

func desiredTunnelHostnames(gateway *ir.Gateway, appliedVersion int64) []v1alpha1.CloudflareTunnelHostnameStatus {
	result := make([]v1alpha1.CloudflareTunnelHostnameStatus, 0)
	teardown := gateway.Cloudflare != nil && gateway.Cloudflare.Teardown
	for _, domain := range gateway.Domains {
		for _, host := range domain.VirtualHosts {
			if host.Hostname == "" || host.Hostname == "*" {
				continue
			}
			guard := v1alpha1.HostnameGuard(domain.Guard)
			if teardown {
				guard = v1alpha1.HostnameGuardBlocked
			}
			result = append(result, v1alpha1.CloudflareTunnelHostnameStatus{
				Hostname:          host.Hostname,
				ProtectionDomain:  domain.Name,
				AccessApplication: domain.AccessApplication,
				Guard:             guard,
				AppliedVersion:    appliedVersion,
			})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Hostname != result[j].Hostname {
			return result[i].Hostname < result[j].Hostname
		}
		if result[i].ProtectionDomain != result[j].ProtectionDomain {
			return result[i].ProtectionDomain < result[j].ProtectionDomain
		}
		return result[i].AccessApplication < result[j].AccessApplication
	})
	return result
}

func desiredTunnelListeners(gateway *ir.Gateway) []v1alpha1.CloudflareTunnelListenerStatus {
	result := make([]v1alpha1.CloudflareTunnelListenerStatus, 0, len(gateway.Listeners))
	for _, listener := range gateway.Listeners {
		status := v1alpha1.CloudflareTunnelListenerStatus{Name: gatewayv1.SectionName(listener.Name), Exposure: v1alpha1.Exposure(listener.Exposure)}
		if listener.Exposure == ir.ExposurePrivate {
			status.Binding = v1alpha1.ListenerBindingLoopback
			if listener.Binding == ir.ListenerBindingPodIP {
				status.Binding = v1alpha1.ListenerBindingPodIP
			}
		}
		for _, domain := range gateway.Domains {
			if domain.ListenerName == listener.Name {
				status.ProtectionDomains = append(status.ProtectionDomains, v1alpha1.CloudflareProtectionDomainStatus{Name: domain.Name, EnvoyPort: domain.EnvoyPort, Protected: domain.Protected})
			}
		}
		result = append(result, status)
	}
	return result
}

func tunnelGatewayAddresses(gateway *ir.Gateway, tunnel *v1alpha1.CloudflareTunnel) []gatewayv1.GatewayStatusAddress {
	if tunnel == nil || tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly ||
		tunnel.Status.DeletedAt != nil || tunnel.Status.TunnelID == "" || !tunnel.Status.OwnershipVerified {
		return nil
	}
	for _, listener := range gateway.Listeners {
		if listener.Exposure == ir.ExposurePublic {
			addressType := gatewayv1.HostnameAddressType
			return []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: tunnel.Status.TunnelID + ".cfargotunnel.com"}}
		}
	}
	return nil
}

func (r *GatewayReconciler) patchTunnelGatewayStatus(
	ctx context.Context,
	gateway *ir.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	config v1alpha1.CloudflareTunnelConfigVersion,
	hostnames []v1alpha1.CloudflareTunnelHostnameStatus,
	listeners []v1alpha1.CloudflareTunnelListenerStatus,
	conditions ...metav1.Condition,
) error {
	if tunnelConfigurationMode(tunnel) != v1alpha1.CloudflareTunnelConfigurationModeGateway {
		return errors.New("the Gateway reconciler cannot own Direct-mode CloudflareTunnel status")
	}
	currentTunnel, err := r.validateGatewayTunnelWriter(ctx, gateway, tunnel)
	if err != nil {
		return err
	}
	tunnel = currentTunnel
	statusValue := v1alpha1.CloudflareTunnelStatus{
		ConfigVersion: config,
		Hostnames:     hostnames,
		Listeners:     listeners,
		Conditions:    conditions,
	}
	statusMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&statusValue)
	if err != nil {
		return fmt.Errorf("convert Gateway-owned CloudflareTunnel status: %w", err)
	}
	if configMap, ok := statusMap["configVersion"].(map[string]any); ok {
		delete(configMap, "remote")
		delete(configMap, "createdAt")
		statusMap["configVersion"] = configMap
	}
	// Force empty lists into the apply document so removing the last hostname or
	// listener releases stale status instead of omitting the field.
	if len(hostnames) == 0 {
		statusMap["hostnames"] = []any{}
	}
	if len(listeners) == 0 {
		statusMap["listeners"] = []any{}
	}
	if len(conditions) == 0 {
		statusMap["conditions"] = []any{}
	}
	apply := &unstructured.Unstructured{Object: map[string]any{"status": statusMap}}
	apply.SetAPIVersion(v1alpha1.GroupVersion.String())
	apply.SetKind("CloudflareTunnel")
	apply.SetName(tunnel.Name)
	apply.SetNamespace(tunnel.Namespace)
	if err := r.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner(gatewayFieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("apply Gateway-owned CloudflareTunnel status: %w", err)
	}
	return nil
}

func gatewayTunnelCondition(tunnel *v1alpha1.CloudflareTunnel, conditionType string, status metav1.ConditionStatus, reason, message string, now metav1.Time) metav1.Condition {
	transition := now
	if existing := meta.FindStatusCondition(tunnel.Status.Conditions, conditionType); existing != nil && existing.Status == status {
		transition = existing.LastTransitionTime
	}
	return metav1.Condition{Type: conditionType, Status: status, Reason: reason, Message: message, ObservedGeneration: tunnel.Generation, LastTransitionTime: transition}
}

func (r *GatewayReconciler) gatewayNow() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *GatewayReconciler) setCloudflareProgrammedStatus(status *gatewayv1.GatewayStatus, gateway *gatewayv1.Gateway, programmed bool, message string) {
	now := metav1.Now()
	if r.Now != nil {
		now = metav1.NewTime(r.Now())
	}
	conditionStatus := metav1.ConditionFalse
	reason := string(gatewayv1.GatewayReasonPending)
	if programmed {
		conditionStatus = metav1.ConditionTrue
		reason = string(gatewayv1.GatewayReasonProgrammed)
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: string(gatewayv1.GatewayConditionProgrammed), Status: conditionStatus, Reason: reason, Message: message, ObservedGeneration: gateway.Generation, LastTransitionTime: now})
	for index := range status.Listeners {
		listener := &status.Listeners[index]
		accepted := meta.FindStatusCondition(listener.Conditions, string(gatewayv1.ListenerConditionAccepted))
		listenerStatus := conditionStatus
		listenerReason := reason
		listenerMessage := message
		switch {
		case accepted != nil && accepted.Status == metav1.ConditionFalse:
			listenerStatus = metav1.ConditionFalse
			listenerReason = string(gatewayv1.ListenerReasonInvalid)
			listenerMessage = "Listener configuration is invalid"
		case programmed:
			listenerReason = string(gatewayv1.ListenerReasonProgrammed)
		default:
			listenerReason = string(gatewayv1.ListenerReasonPending)
		}
		meta.SetStatusCondition(&listener.Conditions, metav1.Condition{Type: string(gatewayv1.ListenerConditionProgrammed), Status: listenerStatus, Reason: listenerReason, Message: listenerMessage, ObservedGeneration: gateway.Generation, LastTransitionTime: now})
	}
}

func shouldScaleDownTunnel(tunnel *v1alpha1.CloudflareTunnel) bool {
	if tunnel.DeletionTimestamp.IsZero() || tunnel.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation] != "true" || len(tunnel.Status.DNSRecords) != 0 {
		return false
	}
	for _, hostname := range tunnel.Status.Hostnames {
		if hostname.Guard != v1alpha1.HostnameGuardBlocked {
			return false
		}
	}
	return true
}

func scaleDesiredDeploymentToZero(objects []client.Object) {
	for _, object := range objects {
		if deployment, ok := object.(*appsv1.Deployment); ok {
			zero := int32(0)
			deployment.Spec.Replicas = &zero
		}
	}
}

func (r *GatewayReconciler) mapTunnelToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	tunnel, ok := object.(*v1alpha1.CloudflareTunnel)
	if !ok {
		return nil
	}
	var gateways gatewayv1.GatewayList
	if err := r.List(ctx, &gateways, client.InNamespace(tunnel.Namespace)); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list Gateways for CloudflareTunnel", "tunnel", client.ObjectKeyFromObject(tunnel))
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for index := range gateways.Items {
		name, _, supported := referencedTunnelName(&gateways.Items[index])
		if supported && (name == tunnel.Name || (name == "" && gateways.Items[index].Name == tunnel.Name)) {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&gateways.Items[index])})
		}
	}
	return deduplicateRequests(requests)
}

func (r *GatewayReconciler) mapPodToGateway(_ context.Context, object client.Object) []reconcile.Request {
	name := object.GetLabels()[dataplane.StandardGatewayLabelKey]
	if name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: object.GetNamespace(), Name: name}}}
}
