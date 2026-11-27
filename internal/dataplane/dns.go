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
	"fmt"
	"regexp"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/isac322/flareway/internal/ir"
)

// PrivateDNSConfigMapName returns the ConfigMap mounted into the pod-local
// CoreDNS sidecar.
func PrivateDNSConfigMapName(gw *ir.Gateway) string {
	return dnsLabelName("flareway-gw-", gw.Key.Name, "-dns")
}

// BuildPrivateDNSConfigMap renders pod-local DNS for private listener
// hostnames. It returns nil when the Gateway has no private listener.
func BuildPrivateDNSConfigMap(gw *ir.Gateway) *corev1.ConfigMap {
	entries := privateDNSHostnames(gw)
	if len(entries) == 0 {
		return nil
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1.SchemeGroupVersion.String(), Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            PrivateDNSConfigMapName(gw),
			Namespace:       gw.Key.Namespace,
			Labels:          resourceLabels(gw),
			Annotations:     map[string]string{ManagedByLabelKey: managedByValue(gw)},
			OwnerReferences: gatewayOwnerReferences(gw),
		},
		Data: map[string]string{"Corefile": renderPrivateCorefile(entries)},
	}
}

type privateDNSEntry struct {
	hostname string
	podIP    bool
}

func privateDNSHostnames(gw *ir.Gateway) []privateDNSEntry {
	byHost := make(map[string]bool)
	for _, listener := range gw.Listeners {
		if listener.Exposure != ir.ExposurePrivate || listener.Hostname == "" {
			continue
		}
		hostname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(listener.Hostname), "."))
		if hostname == "" {
			continue
		}
		podIP := listener.Binding == ir.ListenerBindingPodIP
		if existing, seen := byHost[hostname]; seen {
			// When mixed bindings share the exact same hostname, prefer loopback.
			byHost[hostname] = existing && podIP
			continue
		}
		byHost[hostname] = podIP
	}
	entries := make([]privateDNSEntry, 0, len(byHost))
	for hostname, podIP := range byHost {
		entries = append(entries, privateDNSEntry{hostname: hostname, podIP: podIP})
	}
	slices.SortFunc(entries, func(left, right privateDNSEntry) int {
		return strings.Compare(left.hostname, right.hostname)
	})
	return entries
}

func privateDNSAnswerAddress(podIP bool) string {
	if podIP {
		return "{$POD_IP}"
	}
	return "127.0.0.1"
}

func escapeCoreDNSRegex(host string) string {
	return strings.ReplaceAll(regexp.QuoteMeta(host), `\.`, "[.]")
}

func writePrivateDNSTemplate(builder *strings.Builder, pattern, addr string) {
	builder.WriteString("    template IN A {\n")
	fmt.Fprintf(builder, "        match %q\n", pattern)
	fmt.Fprintf(builder, "        answer \"{{ .Name }} 30 IN A %s\"\n", addr)
	builder.WriteString("        fallthrough\n    }\n")
}

func renderPrivateCorefile(entries []privateDNSEntry) string {
	exact := make([]privateDNSEntry, 0, len(entries))
	wildcards := make([]privateDNSEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.hostname, "*.") {
			wildcards = append(wildcards, entry)
		} else {
			exact = append(exact, entry)
		}
	}

	var builder strings.Builder
	builder.WriteString(".:53 {\n    bind 127.0.0.1\n")
	// CoreDNS executes template plugins before hosts in plugin.cfg order.
	// Render exact hostnames as template blocks ahead of wildcards so an exact
	// hostname always takes precedence over an overlapping wildcard binding.
	for _, entry := range exact {
		pattern := "^" + escapeCoreDNSRegex(entry.hostname) + "[.]?$"
		writePrivateDNSTemplate(&builder, pattern, privateDNSAnswerAddress(entry.podIP))
	}
	for _, entry := range wildcards {
		suffix := strings.TrimPrefix(entry.hostname, "*.")
		pattern := "^[^.]+[.]" + escapeCoreDNSRegex(suffix) + "[.]?$"
		writePrivateDNSTemplate(&builder, pattern, privateDNSAnswerAddress(entry.podIP))
	}
	builder.WriteString("    forward . /etc/resolv.conf\n    reload 5s 2s\n    errors\n}\n")
	return builder.String()
}
