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
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/authz"
	cloudflaredconfig "github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/observability"
)

const cloudflareConvergenceTimeout = 30 * time.Second

// errTunnelConvergenceLost marks promotion-guard failures caused by lost
// convergence evidence that is ordinary pending, not a fault: the compiled
// snapshot lost its ACK or the programming gate reopened. Callers demote
// ConfigApplied and requeue rather than surfacing a Go error.
var errTunnelConvergenceLost = errors.New("tunnel convergence evidence lost")

// errTunnelGateObservation marks promotion-guard failures caused by a real
// observation error (Pod list, probe transport, writer revalidation). Callers
// demote ConfigApplied and still surface the error.
var errTunnelGateObservation = errors.New("tunnel gate observation failed")

type cloudflareConfigResult struct {
	hash            string
	version         int64
	remoteVersion   int64
	remoteCreatedAt *metav1.Time
	// appliedAt is set only when this pass freshly confirmed or wrote the
	// remote configuration. The caller stamps it into
	// status.configVersion.appliedAt; an open gate leaves it nil so the
	// recorded freshness timestamp is preserved.
	appliedAt *metav1.Time
	// requeue is the self-expiry delay until the desired-hash gate needs
	// re-evaluation (D10). Zero means no freshness-driven requeue.
	requeue time.Duration
	drift   bool
	message string
	pending string
	// held reports that drift was detected but the configured DriftPolicy
	// suppressed the overwrite.
	held bool
	// remoteChanged reports that this pass issued a remote
	// UpdateTunnelConfiguration and carries the provider-assigned version.
	// The caller checkpoints desired=remote before the convergence gate.
	remoteChanged bool
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
	// applicationGuards records each host's guard per Access application
	// regardless of protection domain name, so a domain renamed across
	// releases still sees the guard the tunnel reports for its host.
	applicationGuards := make(map[string]v1alpha1.HostnameGuard, len(tunnel.Status.Hostnames))
	unprotectedHosts := make(map[string]bool)
	for _, hostname := range tunnel.Status.Hostnames {
		host := strings.ToLower(hostname.Hostname)
		currentGuards[strings.Join([]string{host, hostname.ProtectionDomain, hostname.AccessApplication}, "\x00")] = hostname.Guard
		if hostname.AccessApplication != "" {
			applicationKey := host + "\x00" + hostname.AccessApplication
			if applicationGuards[applicationKey] != v1alpha1.HostnameGuardForwarding {
				applicationGuards[applicationKey] = hostname.Guard
			}
		}
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
			guard, found := currentGuards[strings.Join([]string{host, domain.Name, domain.AccessApplication}, "\x00")]
			if !found && domain.AccessApplication != "" {
				guard = applicationGuards[host+"\x00"+domain.AccessApplication]
			}
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

// tunnelProgrammingBlock explains why the resolved CloudflareTunnel cannot be
// programmed by this Gateway yet. It never affects admission: the Gateway is
// still translated so Accepted, listener, and route status stay current, but
// nothing is published or written on the tunnel's behalf.
type tunnelProgrammingBlock struct {
	// message is the Programmed=False message.
	message string
	// retractDataplane scales the Gateway's own dataplane to zero. Only a
	// verified owner waiting on connector credentials keeps it running.
	retractDataplane bool
	// terminal stops polling: the block only clears after a spec or grant
	// change, which the CloudflareTunnel and CloudflareAccount watches observe.
	terminal bool
}

func (r *GatewayReconciler) resolveCloudflareContext(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	cfg *v1alpha1.GatewayClassConfig,
) (*v1alpha1.CloudflareTunnel, *v1alpha1.CloudflareAccount, *v1alpha1.GatewayClassConfig, *tunnelProgrammingBlock, error) {
	if cfg.Spec.ConformanceMode {
		return nil, nil, cfg, nil, nil
	}

	tunnelName, explicit, supported := referencedTunnelName(gateway)
	if !supported {
		return nil, nil, cfg, nil, nil
	}
	if tunnelName == "" {
		tunnelName = gateway.Name
	}
	key := types.NamespacedName{Namespace: gateway.Namespace, Name: tunnelName}
	var tunnel v1alpha1.CloudflareTunnel
	if err := r.Get(ctx, key, &tunnel); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, nil, cfg, nil, fmt.Errorf("get CloudflareTunnel %s: %w", key, err)
		}
		if explicit {
			return nil, nil, cfg, nil, &missingExplicitTunnelError{key: key}
		}
		if cfg.Spec.AccountRef == nil || cfg.Spec.AccountRef.Name == "" {
			return nil, nil, cfg, nil, errors.New("the GatewayClassConfig accountRef is required in Cloudflare mode")
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
			return nil, nil, cfg, nil, fmt.Errorf("set Gateway owner on default CloudflareTunnel: %w", err)
		}
		if err := r.Create(ctx, &tunnel); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return nil, nil, cfg, nil, fmt.Errorf("create default CloudflareTunnel %s: %w", key, err)
			}
			if err := r.directReader().Get(ctx, key, &tunnel); err != nil {
				return nil, nil, cfg, nil, fmt.Errorf("get existing default CloudflareTunnel %s: %w", key, err)
			}
		}
		// A just-created tunnel has no ownership checkpoint, so it resolves to
		// a programming block below and the Gateway is still translated.
	}
	var block *tunnelProgrammingBlock
	if tunnelConfigurationMode(&tunnel) == v1alpha1.CloudflareTunnelConfigurationModeGateway {
		selected, _, waitingForDrain, err := selectLiveTunnelGateway(ctx, r.Client, &tunnel)
		if err != nil {
			return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), nil, err
		}
		block = gatewayTunnelProgrammingBlock(gateway, &tunnel, selected, waitingForDrain)
	}

	var account v1alpha1.CloudflareAccount
	if tunnel.Spec.AccountRef.Name == "" {
		return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), block, errors.New("the CloudflareTunnel accountRef is empty")
	}
	// Reading the account is a cache read with no credential or remote access;
	// the translator needs its grants to report listener authorization even
	// while the tunnel is blocked.
	if err := r.Get(ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &account); err != nil {
		if apierrors.IsNotFound(err) {
			// A missing CloudflareAccount is dependency loss, not a hard
			// failure: the Gateway stays Accepted but unprogrammed while the
			// account is absent. The typed error lets Reconcile stop polling;
			// the CloudflareAccount watch re-enqueues the Gateway when the
			// account is recreated.
			return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), block, &missingCloudflareAccountError{name: tunnel.Spec.AccountRef.Name}
		}
		return &tunnel, nil, effectiveGatewayConfig(cfg, &tunnel), block, fmt.Errorf("get CloudflareAccount %q: %w", tunnel.Spec.AccountRef.Name, err)
	}
	return &tunnel, &account, effectiveGatewayConfig(cfg, &tunnel), block, nil
}

// gatewayTunnelProgrammingBlock returns nil only when this exact Gateway UID
// owns the Gateway-mode tunnel and the tunnel holds verified connector
// credentials.
func gatewayTunnelProgrammingBlock(
	gateway *gatewayv1.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	selected *gatewayv1.Gateway,
	waitingForDrain bool,
) *tunnelProgrammingBlock {
	key := client.ObjectKeyFromObject(tunnel)
	authorized := sameGatewayIdentity(gateway, selected) && tunnelGatewayStatusIdentityMatches(tunnel, gateway)
	observeOnly := tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly
	credentialsMissing := tunnel.Status.TunnelID == "" || tunnel.Status.ConnectorTokenSecretRef == nil
	if authorized && !observeOnly && tunnel.Status.DeletedAt == nil && tunnel.Status.OwnershipVerified && !credentialsMissing {
		return nil
	}
	block := &tunnelProgrammingBlock{
		message:          fmt.Sprintf("Waiting for exact UID-bound ownership of CloudflareTunnel %s", key),
		retractDataplane: true,
	}
	switch {
	case tunnel.Status.DeletedAt != nil:
		block.message = fmt.Sprintf("CloudflareTunnel %s is remotely deleted and draining its connector dataplane", key)
	case waitingForDrain:
		block.message = fmt.Sprintf("CloudflareTunnel %s is draining its prior Gateway UID dataplane", key)
	case selected != nil && !sameGatewayIdentity(gateway, selected):
		block.message = fmt.Sprintf("CloudflareTunnel %s is owned by Gateway %s/%s UID %s", key, selected.Namespace, selected.Name, selected.UID)
	case observeOnly:
		block.message = fmt.Sprintf("CloudflareTunnel %s is ObserveOnly and cannot authorize a connector dataplane", key)
		block.terminal = true
	default:
		if rejection := currentTunnelRejection(tunnel, gateway); rejection != nil {
			block.message = fmt.Sprintf("CloudflareTunnel %s is not accepted: %s: %s", key, rejection.Reason, rejection.Message)
			block.terminal = terminalTunnelRejectionReasons.Has(rejection.Reason)
		} else if authorized && !tunnel.Status.OwnershipVerified {
			block.message = fmt.Sprintf("CloudflareTunnel %s has not verified remote ownership", key)
		} else if authorized && credentialsMissing {
			block.message = fmt.Sprintf("CloudflareTunnel %s is waiting for verified connector credentials", key)
		}
		if authorized && tunnel.Status.OwnershipVerified && credentialsMissing {
			// A verified owner waiting on connector credentials is a
			// recoverable convergence gap, not dependency loss: the
			// published snapshot is still retracted and the Gateway stays
			// unprogrammed, but the owned dataplane keeps running so a
			// stale or in-flight credential write cannot drop live traffic.
			block.retractDataplane = false
		}
	}
	return block
}

// terminalTunnelRejectionReasons are tunnel Accepted=False verdicts that only
// a spec, grant, or account change can clear. The tunnel controller does not
// requeue them either.
var terminalTunnelRejectionReasons = sets.New(authz.ReasonRefNotPermitted, authz.ReasonUnsupportedValue, "Invalid")

// currentTunnelRejection returns the tunnel's Accepted=False condition when it
// describes the tunnel's current spec and this exact Gateway. The Gateway
// controller only reads it to explain Programmed=False.
func currentTunnelRejection(tunnel *v1alpha1.CloudflareTunnel, gateway *gatewayv1.Gateway) *metav1.Condition {
	if !tunnelGatewayStatusIdentityMatches(tunnel, gateway) {
		return nil
	}
	accepted := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionAccepted)
	if accepted == nil || accepted.Status != metav1.ConditionFalse || accepted.ObservedGeneration != tunnel.Generation {
		return nil
	}
	return accepted
}

// missingExplicitTunnelError reports that a Gateway explicitly referenced a
// CloudflareTunnel that does not exist. Unlike the implicit tunnel named after
// the Gateway, an explicit reference is never auto-provisioned, so the Gateway
// is rejected instead of creating a replacement.
type missingExplicitTunnelError struct {
	key types.NamespacedName
}

func (e *missingExplicitTunnelError) Error() string {
	return fmt.Sprintf("referenced CloudflareTunnel %s was not found", e.key)
}

// missingCloudflareAccountError reports that the CloudflareAccount referenced
// by the resolved CloudflareTunnel is confirmed absent. Unlike a missing
// explicit tunnel this is not an admission rejection: the Gateway stays
// Accepted but unprogrammed, and the typed error lets Reconcile stop polling
// because the CloudflareAccount watch re-enqueues it on recreation.
type missingCloudflareAccountError struct {
	name string
}

func (e *missingCloudflareAccountError) Error() string {
	return fmt.Sprintf("referenced CloudflareAccount %q was not found", e.name)
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

// directReader returns the uncached reader used for writer revalidation and
// condition-commit bases. APIReader is preferred; tests that never wire it
// fall back to Client, which is still a direct read for envtest/fake clients.
func (r *GatewayReconciler) directReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *GatewayReconciler) validateGatewayTunnelWriter(ctx context.Context, gateway *ir.Gateway, tunnel *v1alpha1.CloudflareTunnel) (*v1alpha1.CloudflareTunnel, error) {
	if gateway == nil || gateway.UID == "" || tunnel == nil {
		return nil, errors.New("gateway Tunnel writer requires non-empty Gateway UID and Tunnel")
	}
	reader := r.directReader()
	var currentGateway gatewayv1.Gateway
	if err := reader.Get(ctx, gateway.Key, &currentGateway); err != nil {
		return nil, fmt.Errorf("revalidate Gateway %s before Tunnel write: %w", gateway.Key, err)
	}
	if currentGateway.UID != gateway.UID || !currentGateway.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("gateway %s UID %s is no longer the live writer", gateway.Key, gateway.UID)
	}
	var currentTunnel v1alpha1.CloudflareTunnel
	if err := reader.Get(ctx, client.ObjectKeyFromObject(tunnel), &currentTunnel); err != nil {
		return nil, fmt.Errorf("revalidate CloudflareTunnel %s/%s before Gateway write: %w", tunnel.Namespace, tunnel.Name, err)
	}
	if tunnel.UID != "" && currentTunnel.UID != tunnel.UID {
		return nil, fmt.Errorf("CloudflareTunnel %s/%s was recreated before Gateway write", tunnel.Namespace, tunnel.Name)
	}
	// The fresh read may only replace the observed snapshot when it is the
	// same spec revision and the same remote/owner identity: adopting a
	// newer generation would rebase this pass's stale observations onto the
	// new spec, and adopting a changed tunnelId/accountId/gateway binding
	// would let promotion compare fresh provenance against itself. Other
	// status fields (dnsRecords, conditions) legitimately move mid-pass and
	// are not identity.
	if currentTunnel.Generation != tunnel.Generation ||
		tunnelConfigurationMode(&currentTunnel) != tunnelConfigurationMode(tunnel) {
		return nil, fmt.Errorf("CloudflareTunnel %s/%s spec changed since this pass observed it (generation %d -> %d)", tunnel.Namespace, tunnel.Name, tunnel.Generation, currentTunnel.Generation)
	}
	if currentTunnel.Status.TunnelID != tunnel.Status.TunnelID ||
		currentTunnel.Status.AccountID != tunnel.Status.AccountID ||
		currentTunnel.Status.GatewayUID != tunnel.Status.GatewayUID ||
		localRefName(currentTunnel.Status.GatewayRef) != localRefName(tunnel.Status.GatewayRef) {
		return nil, fmt.Errorf("CloudflareTunnel %s/%s remote or owner identity changed since this pass observed it", tunnel.Namespace, tunnel.Name)
	}
	selected, _, waitingForDrain, err := selectLiveTunnelGateway(ctx, reader, &currentTunnel)
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

func localRefName(ref *corev1.LocalObjectReference) string {
	if ref == nil {
		return ""
	}
	return ref.Name
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
		return cloudflareConfigResult{
			remoteVersion:   tunnel.Status.ConfigVersion.Remote,
			remoteCreatedAt: tunnel.Status.ConfigVersion.CreatedAt,
			pending:         "tunnel is ObserveOnly; no ingress will be written",
		}, nil
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
	// Desired-hash gate (D11): evaluated outside the tunnel lock and before
	// the Cloudflare client is built. An open gate skips client creation,
	// GetTunnel, and the lock entirely; the result is reconstructed from the
	// status recorded by the last converged pass so configVersion.remote and
	// createdAt keep their values (C14 #9). A closed gate runs the unchanged
	// remote path below — the lock closure never serves cached state.
	now := r.gatewayNow()
	gateKey := client.ObjectKeyFromObject(tunnel)
	gate := evaluateGateWithHash(
		r.Freshness,
		r.Invalidator,
		freshness.GradeTraffic,
		"CloudflareTunnel",
		gateKey,
		tunnel.Status.ConfigVersion.DesiredHash,
		hash,
		tunnel.Status.ConfigVersion.AppliedAt,
		now,
	).Gate
	if gate.Open {
		return cloudflareConfigResult{
			hash:            hash,
			version:         tunnel.Status.ConfigVersion.Desired,
			remoteVersion:   tunnel.Status.ConfigVersion.Remote,
			remoteCreatedAt: tunnel.Status.ConfigVersion.CreatedAt,
			requeue:         gate.Requeue,
		}, nil
	}
	api, err := r.cloudflareClient(ctx, account)
	if err != nil {
		return cloudflareConfigResult{}, r.remoteConfigFailure(ctx, gateway, tunnel, now, err)
	}
	remoteTunnel, err := api.GetTunnel(ctx, tunnel.Status.TunnelID)
	if err != nil {
		return cloudflareConfigResult{}, r.remoteConfigFailure(ctx, gateway, tunnel, now, fmt.Errorf("get Cloudflare Tunnel before configuration update: %w", err))
	}
	if err := validateRemoteTunnel(remoteTunnel, account.Spec.AccountID); err != nil {
		return cloudflareConfigResult{}, r.remoteConfigFailure(ctx, gateway, tunnel, now, err)
	}
	freshAppliedAt := metav1.NewTime(now)
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
			result.remoteVersion = remote.Version
			result.remoteCreatedAt = timeStatus(remote.CreatedAt)
			// Confirming the recorded version is not an apply: appliedAt
			// keeps the time the configuration was written, and the
			// verify time goes to the latch below.
			result.appliedAt = &freshAppliedAt
			if recorded := tunnel.Status.ConfigVersion.AppliedAt; recorded != nil {
				result.appliedAt = recorded
			}
			return nil
		}
		baseline := tunnel.Status.ConfigVersion.Applied
		if baseline == 0 {
			baseline = tunnel.Status.ConfigVersion.Desired
		}
		if remote.Version != baseline {
			result.drift = true
			action := "overwriting with desired configuration"
			if r.DriftPolicy == DriftPolicyHold {
				result.held = true
				action = "automatic overwrite held by policy"
			}
			result.message = fmt.Sprintf("Cloudflare Tunnel configuration changed out of band: remote version %d, expected %d; %s", remote.Version, baseline, action)
			observability.ObserveDrift("CloudflareTunnel", "version")
		}
		if result.held {
			result.remoteVersion = remote.Version
			result.remoteCreatedAt = timeStatus(remote.CreatedAt)
			return nil
		}
		// Durable invalidation before the remote mutation: ConfigApplied and
		// the derived Ready drop to False so a crash anywhere below leaves a
		// fail-closed record instead of a stale True describing a superseded
		// desired state. The intended hash rides in the message only —
		// status.configVersion.desiredHash stays the hash of the last
		// successful remote write until the checkpoint below records the
		// provider-assigned version.
		if err := r.demoteTunnelConfigApplied(ctx, gateway, tunnel, now, "Applying", fmt.Sprintf("Applying Cloudflare Tunnel configuration with desired hash %s", hash)); err != nil {
			return err
		}
		updated, err := api.UpdateTunnelConfiguration(ctx, tunnel.Status.TunnelID, params)
		if err != nil {
			return err
		}
		if err := validateRemoteConfiguration(updated, account.Spec.AccountID, tunnel.Status.TunnelID); err != nil {
			return err
		}
		result.version = updated.Version
		result.remoteVersion = updated.Version
		result.remoteCreatedAt = timeStatus(updated.CreatedAt)
		result.appliedAt = &freshAppliedAt
		result.remoteChanged = true
		return nil
	})
	if err != nil {
		return cloudflareConfigResult{}, r.remoteConfigFailure(ctx, gateway, tunnel, now, fmt.Errorf("update Cloudflare Tunnel configuration: %w", err))
	}
	if result.remoteChanged {
		// The provider-assigned version checkpoints before the convergence
		// gate: desired=remote records what was actually written so a crash
		// before promotion still describes remote truth. Conditions are
		// untouched — ConfigApplied=False from the demotion persists.
		checkpoint := tunnel.Status.ConfigVersion
		checkpoint.Desired = result.version
		checkpoint.DesiredHash = result.hash
		checkpoint.Remote = result.remoteVersion
		checkpoint.CreatedAt = result.remoteCreatedAt
		checkpoint.AppliedAt = result.appliedAt
		if err := r.patchTunnelGatewayData(ctx, gateway, tunnel, checkpoint, tunnel.Status.Hostnames, desiredTunnelListeners(gateway)); err != nil {
			return cloudflareConfigResult{}, fmt.Errorf("checkpoint Cloudflare Tunnel configuration version: %w", err)
		}
	}
	if result.appliedAt != nil {
		// The remote state was freshly confirmed or written: release any
		// sweep invalidation, record the verify time, and requeue at the
		// freshness horizon so the next pass re-evaluates the gate exactly
		// when it expires (D10).
		clearGate(r.Invalidator, "CloudflareTunnel", gateKey)
		r.Invalidator.MarkVerified("CloudflareTunnel", gateKey, hash, now)
		result.requeue = r.Freshness.TTL(freshness.GradeTraffic)
	}
	return result, nil
}

// remoteConfigFailure records ConfigApplied=False before returning a remote
// path error so a quiet True never masks a real failure. The demotion is
// best-effort: a commit failure is reported alongside the original error, and
// a writer-guard rejection (ownership lost mid-pass) leaves the original
// error authoritative.
func (r *GatewayReconciler) remoteConfigFailure(ctx context.Context, gateway *ir.Gateway, tunnel *v1alpha1.CloudflareTunnel, now time.Time, cause error) error {
	if demoteErr := r.demoteTunnelConfigApplied(ctx, gateway, tunnel, now, "RemoteError", "Cloudflare Tunnel remote operation failed; see controller logs"); demoteErr != nil {
		return fmt.Errorf("%w (recording ConfigApplied=False also failed: %v)", cause, demoteErr)
	}
	return cause
}

// demoteTunnelConfigApplied commits ConfigApplied=False through the shared
// conditions transaction. Ready is derived False in the same document.
func (r *GatewayReconciler) demoteTunnelConfigApplied(ctx context.Context, gateway *ir.Gateway, tunnel *v1alpha1.CloudflareTunnel, now time.Time, reason, message string) error {
	return r.patchTunnelGatewayConditions(ctx, gateway, tunnel, metav1.NewTime(now),
		gatewayTunnelCondition(tunnel, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionFalse, reason, message, metav1.NewTime(now)))
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
		if record.State != dnsRecordStateConflict {
			delete(wanted, strings.ToLower(record.Hostname))
		}
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
		// One ir.ProtectionDomain is produced per virtual host. Fragments that
		// share a name are one Envoy route table on one port: hosts with no
		// Access claim reuse the listener's base domain, and private Access
		// hosts share the listener port. translator.Build rejects a name that
		// maps to more than one route table, so the fragments are identical
		// here, and each public Access host carries its own name and port.
		//
		// ProtectionDomains is +listMapKey=name, so emitting fragments
		// one-for-one makes the whole status object unpatchable: server-side
		// apply rejects it with "duplicate entries for key [name=...]" and the
		// Gateway reconcile fails before any route status is written. Report
		// each distinct protection domain once instead.
		seen := make(map[string]struct{}, len(gateway.Domains))
		for _, domain := range gateway.Domains {
			if domain.ListenerName != listener.Name {
				continue
			}
			if _, duplicate := seen[domain.Name]; duplicate {
				continue
			}
			seen[domain.Name] = struct{}{}
			status.ProtectionDomains = append(status.ProtectionDomains, v1alpha1.CloudflareProtectionDomainStatus{Name: domain.Name, EnvoyPort: domain.EnvoyPort, Protected: domain.Protected})
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

// patchTunnelGatewayStatus is the demotion-shaped write: the conditions
// transaction commits before the data apply so a persisted ConfigApplied=False
// (or a no-change re-authoring) never trails the fields it describes. Callers
// promoting ConfigApplied to True must use patchTunnelGatewayData followed by
// patchTunnelGatewayConditions instead — promotion commits after the
// justifying configVersion is durable.
func (r *GatewayReconciler) patchTunnelGatewayStatus(
	ctx context.Context,
	gateway *ir.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	config v1alpha1.CloudflareTunnelConfigVersion,
	hostnames []v1alpha1.CloudflareTunnelHostnameStatus,
	listeners []v1alpha1.CloudflareTunnelListenerStatus,
	conditions ...metav1.Condition,
) error {
	if err := r.patchTunnelGatewayConditions(ctx, gateway, tunnel, metav1.NewTime(r.gatewayNow()), conditions...); err != nil {
		return err
	}
	return r.patchTunnelGatewayData(ctx, gateway, tunnel, config, hostnames, listeners)
}

// patchTunnelGatewayConditions commits the authored Gateway-owned condition
// deltas through the shared flareway-tunnel-status transaction: a fresh read
// supplies the resourceVersion basis, the writer guard re-runs per attempt,
// and Ready is derived in the same document. With no authored deltas the call
// performs only legacy-ownership migration and the Ready clamp — the required
// pre-data stage on promotion passes.
func (r *GatewayReconciler) patchTunnelGatewayConditions(
	ctx context.Context,
	gateway *ir.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	now metav1.Time,
	conditions ...metav1.Condition,
) error {
	return r.patchTunnelGatewayConditionsValidated(ctx, gateway, tunnel, now, nil, conditions...)
}

// patchTunnelGatewayConditionsValidated is patchTunnelGatewayConditions with
// an additional caller guard (Tier-2 promotion evidence) evaluated against the
// fresh live object on every commit attempt.
func (r *GatewayReconciler) patchTunnelGatewayConditionsValidated(
	ctx context.Context,
	gateway *ir.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	now metav1.Time,
	extraValidate func(*v1alpha1.CloudflareTunnel) error,
	conditions ...metav1.Condition,
) error {
	if tunnelConfigurationMode(tunnel) != v1alpha1.CloudflareTunnelConfigurationModeGateway {
		return errors.New("the Gateway reconciler cannot own Direct-mode CloudflareTunnel status")
	}
	guard := r.gatewayTunnelConditionGuard(ctx, gateway, tunnel)
	validate := func(live *v1alpha1.CloudflareTunnel) error {
		if err := guard(live); err != nil {
			return err
		}
		if extraValidate != nil {
			return extraValidate(live)
		}
		return nil
	}
	return patchTunnelConditions(ctx, r.Client, r.directReader(), tunnelConditionUpdate{
		Observed:   tunnel,
		Conditions: conditions,
		Now:        now,
		Validate:   validate,
	})
}

// gatewayTunnelConditionGuard revalidates the Gateway-writer preconditions
// against the fresh live Tunnel on every conditions-commit attempt: the live
// Gateway still exists with the observed UID and no deletionTimestamp, the
// Tunnel still names it as its verified UID-bound owner, no drain is pending,
// and the Tunnel is managed and verified. The Tunnel object CAS covers the
// Tunnel revision; the Gateway is a separate object, so a bounded cross-object
// race remains — the Gateway watch requeues a correcting pass.
func (r *GatewayReconciler) gatewayTunnelConditionGuard(ctx context.Context, gateway *ir.Gateway, observed *v1alpha1.CloudflareTunnel) func(*v1alpha1.CloudflareTunnel) error {
	return func(live *v1alpha1.CloudflareTunnel) error {
		if gateway == nil || gateway.UID == "" || live == nil {
			return errors.New("gateway Tunnel writer requires non-empty Gateway UID and Tunnel")
		}
		reader := r.directReader()
		var currentGateway gatewayv1.Gateway
		if err := reader.Get(ctx, gateway.Key, &currentGateway); err != nil {
			return fmt.Errorf("revalidate Gateway %s before Tunnel conditions write: %w", gateway.Key, err)
		}
		if currentGateway.UID != gateway.UID || !currentGateway.DeletionTimestamp.IsZero() {
			return fmt.Errorf("gateway %s UID %s is no longer the live writer", gateway.Key, gateway.UID)
		}
		if observed != nil &&
			(live.Status.TunnelID != observed.Status.TunnelID ||
				live.Status.AccountID != observed.Status.AccountID ||
				live.Status.GatewayUID != observed.Status.GatewayUID ||
				localRefName(live.Status.GatewayRef) != localRefName(observed.Status.GatewayRef)) {
			return fmt.Errorf("CloudflareTunnel %s/%s remote or owner identity changed since this pass observed it", live.Namespace, live.Name)
		}
		selected, _, waitingForDrain, err := selectLiveTunnelGateway(ctx, reader, live)
		if err != nil {
			return err
		}
		if waitingForDrain || !sameGatewayIdentity(&currentGateway, selected) || !tunnelGatewayStatusIdentityMatches(live, &currentGateway) {
			return fmt.Errorf("gateway %s UID %s does not hold the current UID-bound Tunnel ownership", gateway.Key, gateway.UID)
		}
		if live.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly ||
			live.Status.DeletedAt != nil ||
			!live.Status.OwnershipVerified ||
			live.Status.TunnelID == "" ||
			live.Status.ConnectorTokenSecretRef == nil {
			return fmt.Errorf("CloudflareTunnel %s/%s is not verified for managed Gateway writes", live.Namespace, live.Name)
		}
		return nil
	}
}

// gatewayPromotionGuard returns the Tier-2 evidence check for a
// ConfigApplied=True commit, evaluated against the fresh live Tunnel on every
// commit attempt. The three domains are judged in their own units: the exact
// compiled xDS snapshot identity must be ACKed, the live configVersion must
// still record this pass's desired version/hash and observed remote version,
// and — when requireGate is set — the full Cloudflare programming gate
// (cloudflared Pod versions and managed DNS) must still hold. The xDS string
// identity and the Cloudflare int64 version are never equated.
func (r *GatewayReconciler) gatewayPromotionGuard(
	ctx context.Context,
	gateway *ir.Gateway,
	result cloudflareConfigResult,
	snapshotVersion string,
	requireGate bool,
) func(*v1alpha1.CloudflareTunnel) error {
	return func(live *v1alpha1.CloudflareTunnel) error {
		if live.Status.ConfigVersion.Desired != result.version ||
			live.Status.ConfigVersion.DesiredHash != result.hash ||
			live.Status.ConfigVersion.Remote != result.remoteVersion {
			return fmt.Errorf("live CloudflareTunnel %s/%s configVersion no longer records this pass's desired state", live.Namespace, live.Name)
		}
		if !r.Snapshots.IsACKed(gateway.Key.String(), snapshotVersion) {
			return fmt.Errorf("%w: compiled xDS snapshot %s is not ACKed", errTunnelConvergenceLost, snapshotVersion)
		}
		if requireGate {
			ready, lagging, _, err := r.cloudflareGate(ctx, gateway, live, fmt.Sprint(result.version), snapshotVersion)
			if err != nil {
				return fmt.Errorf("%w: %v", errTunnelGateObservation, err)
			}
			if !ready {
				return fmt.Errorf("%w: Cloudflare programming gate no longer holds: %s", errTunnelConvergenceLost, strings.Join(lagging, ", "))
			}
		}
		return nil
	}
}

// patchTunnelGatewayData applies the Gateway-owned data fields
// (configVersion, hostnames, listeners) under the flareway-gateway manager.
// The document deliberately omits status.conditions: they are owned by the
// shared flareway-tunnel-status manager, and every call site must run the
// conditions stage first so legacy ownership has migrated before this apply —
// otherwise the apply would delete old-manager condition entries.
func (r *GatewayReconciler) patchTunnelGatewayData(
	ctx context.Context,
	gateway *ir.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	config v1alpha1.CloudflareTunnelConfigVersion,
	hostnames []v1alpha1.CloudflareTunnelHostnameStatus,
	listeners []v1alpha1.CloudflareTunnelListenerStatus,
) error {
	if tunnelConfigurationMode(tunnel) != v1alpha1.CloudflareTunnelConfigurationModeGateway {
		return errors.New("the Gateway reconciler cannot own Direct-mode CloudflareTunnel status")
	}
	statusValue := v1alpha1.CloudflareTunnelStatus{
		ConfigVersion: config,
		Hostnames:     hostnames,
		Listeners:     listeners,
	}
	statusMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&statusValue)
	if err != nil {
		return fmt.Errorf("convert Gateway-owned CloudflareTunnel status: %w", err)
	}
	// Force empty lists into the apply document so removing the last hostname or
	// listener releases stale status instead of omitting the field.
	if len(hostnames) == 0 {
		statusMap["hostnames"] = []any{}
	}
	if len(listeners) == 0 {
		statusMap["listeners"] = []any{}
	}
	key := client.ObjectKeyFromObject(tunnel)
	validate := r.gatewayTunnelConditionGuard(ctx, gateway, tunnel)
	var lastErr error
	for range tunnelConditionMaxAttempts {
		// Every attempt re-reads the live object through the direct reader and
		// re-runs the shared identity check plus the writer provenance guard
		// before pinning the apply to that revision — a UID replacement or a
		// generation/mode transition between the caller's snapshot and this
		// write must never receive this pass's data.
		var live v1alpha1.CloudflareTunnel
		if err := r.directReader().Get(ctx, key, &live); err != nil {
			return fmt.Errorf("read live CloudflareTunnel %s for Gateway data: %w", key, err)
		}
		if err := tunnelConditionIdentityCheck(tunnel, &live); err != nil {
			return err
		}
		if err := validate(&live); err != nil {
			return err
		}
		apply := &unstructured.Unstructured{Object: map[string]any{"status": statusMap}}
		apply.SetAPIVersion(v1alpha1.GroupVersion.String())
		apply.SetKind("CloudflareTunnel")
		apply.SetName(live.Name)
		apply.SetNamespace(live.Namespace)
		apply.SetResourceVersion(live.ResourceVersion)
		err = r.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner(gatewayFieldManager), client.ForceOwnership)
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return fmt.Errorf("apply Gateway-owned CloudflareTunnel status: %w", err)
		}
		lastErr = err
	}
	return fmt.Errorf("apply Gateway-owned CloudflareTunnel %s status: conflict after %d attempts: %w", key, tunnelConditionMaxAttempts, lastErr)
}

// gatewayTunnelCondition stamps an authored condition with the caller's clock.
// The shared conditions transaction compares against the live entry and keeps
// its lastTransitionTime when the status is unchanged, so this function must
// not inherit timestamps from the caller's pre-pass snapshot — that is what
// made recovered True values regress in time.
func gatewayTunnelCondition(tunnel *v1alpha1.CloudflareTunnel, conditionType string, status metav1.ConditionStatus, reason, message string, now metav1.Time) metav1.Condition {
	return metav1.Condition{Type: conditionType, Status: status, Reason: reason, Message: message, ObservedGeneration: tunnel.Generation, LastTransitionTime: now}
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

// mapAccountToGateways enqueues every Gateway whose referenced CloudflareTunnel
// uses the changed CloudflareAccount so a recreated account revives Gateways
// that stopped polling while the account was absent.
func (r *GatewayReconciler) mapAccountToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	var tunnels v1alpha1.CloudflareTunnelList
	if err := r.List(ctx, &tunnels); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list CloudflareTunnels for CloudflareAccount", "account", client.ObjectKeyFromObject(object))
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for index := range tunnels.Items {
		if tunnels.Items[index].Spec.AccountRef.Name != object.GetName() {
			continue
		}
		requests = append(requests, r.mapTunnelToGateways(ctx, &tunnels.Items[index])...)
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
