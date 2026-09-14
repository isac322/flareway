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

package dataplane

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/pki"
)

// Dataplane defaults and labels shared by the resource builders.
const (
	DefaultOperatorNamespace = "flareway-system"
	XDSServiceHost           = "flareway-xds.flareway-system.svc.cluster.local"
	XDSPort                  = int32(18000)
	EnvoyAdminPort           = int32(19000)
	EnvoyHealthPort          = int32(19001)
	CloudflaredMetricsPort   = int32(2000)
	PrivateDNSPort           = int32(53)
	EnvoyRuntimeUID          = int64(65532)
	CloudflaredRuntimeUID    = int64(65532)
	PrivateDNSRuntimeUID     = int64(65532)

	GatewayLabelKey         = "flareway.bhyoo.com/gateway"
	ManagedByLabelKey       = "flareway.bhyoo.com/managed-by"
	ConfigHashKey           = "flareway.bhyoo.com/config-hash"
	StandardGatewayLabelKey = "gateway.networking.k8s.io/gateway-name"
)

// ResourceName returns the common name for a Gateway's dataplane resources.
func ResourceName(gw *ir.Gateway) string {
	return dnsLabelName("flareway-gw-", gw.Key.Name, "")
}

// BootstrapConfigMapName returns the ConfigMap mounted at /etc/envoy.
func BootstrapConfigMapName(gw *ir.Gateway) string {
	return dnsLabelName("flareway-gw-", gw.Key.Name, "-envoy")
}

// XDSClientSecretName returns the Secret containing a Gateway's xDS client keypair.
func XDSClientSecretName(gw *ir.Gateway) string {
	return pki.ClientSecretName(gw.Key.Name)
}

// TunnelTokenSecretName returns the Secret used by cloudflared. An explicit
// tunnel may have a name different from the Gateway.
func TunnelTokenSecretName(gw *ir.Gateway) string {
	if gw.Cloudflare != nil && gw.Cloudflare.TokenSecretName != "" {
		return gw.Cloudflare.TokenSecretName
	}
	return dnsLabelName("flareway-tunnel-", gw.Key.Name, "")
}

func gatewayLabelValue(gw *ir.Gateway) string {
	return labelValue(gw.Key.Namespace + "--" + gw.Key.Name)
}

func managedByValue(gw *ir.Gateway) string {
	return gw.Key.Namespace + "/" + gw.Key.Name
}

func resourceLabels(gw *ir.Gateway) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "flareway-gateway",
		"app.kubernetes.io/component": "dataplane",
		GatewayLabelKey:               gatewayLabelValue(gw),
		ManagedByLabelKey:             "flareway",
		StandardGatewayLabelKey:       gw.Key.Name,
	}
}

func selectorLabels(gw *ir.Gateway) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name": "flareway-gateway",
		GatewayLabelKey:          gatewayLabelValue(gw),
	}
}

// mergeMetadata copies user metadata, then applies required metadata so
// operator-owned identity and configuration keys win deterministic conflicts.
func mergeMetadata(user, required map[string]string) map[string]string {
	merged := make(map[string]string, len(user)+len(required))
	for key, value := range user {
		merged[key] = value
	}
	for key, value := range required {
		merged[key] = value
	}
	return merged
}

func configHashLabel(hash string) string {
	return labelValue(hash)
}

func listenerPortName(index int) string {
	return "listener-" + strconv.Itoa(index)
}

func dnsLabelName(prefix, name, suffix string) string {
	full := prefix + name + suffix
	if len(full) <= 63 {
		return full
	}

	digest := sha256.Sum256([]byte(full))
	hash := hex.EncodeToString(digest[:4])
	keep := 63 - len(hash) - 1
	base := strings.Trim(full[:keep], "-.")
	return base + "-" + hash
}

func labelValue(value string) string {
	if len(value) <= 63 {
		return value
	}

	digest := sha256.Sum256([]byte(value))
	hash := hex.EncodeToString(digest[:4])
	keep := 63 - len(hash) - 1
	base := strings.Trim(value[:keep], "-_.")
	return base + "-" + hash
}
