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
	hostnames, podIP := privateDNSHostnames(gw)
	if len(hostnames) == 0 {
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
		Data: map[string]string{"Corefile": renderPrivateCorefile(hostnames, podIP)},
	}
}

func privateDNSHostnames(gw *ir.Gateway) ([]string, bool) {
	seen := make(map[string]struct{})
	podIP := false
	for _, listener := range gw.Listeners {
		if listener.Exposure != ir.ExposurePrivate || listener.Hostname == "" {
			continue
		}
		hostname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(listener.Hostname), "."))
		if hostname == "" {
			continue
		}
		seen[hostname] = struct{}{}
		podIP = podIP || listener.Binding == ir.ListenerBindingPodIP
	}
	hostnames := make([]string, 0, len(seen))
	for hostname := range seen {
		hostnames = append(hostnames, hostname)
	}
	slices.Sort(hostnames)
	return hostnames, podIP
}

func renderPrivateCorefile(hostnames []string, podIP bool) string {
	answerAddress := "127.0.0.1"
	if podIP {
		answerAddress = "{$POD_IP}"
	}

	exact := make([]string, 0, len(hostnames))
	wildcards := make([]string, 0, len(hostnames))
	for _, hostname := range hostnames {
		if strings.HasPrefix(hostname, "*.") {
			wildcards = append(wildcards, strings.TrimPrefix(hostname, "*."))
		} else {
			exact = append(exact, hostname)
		}
	}

	var builder strings.Builder
	builder.WriteString(".:53 {\n    bind 127.0.0.1\n")
	for _, suffix := range wildcards {
		pattern := "^[^.]+[.]" + strings.ReplaceAll(regexp.QuoteMeta(suffix), `\.`, "[.]") + "[.]?$"
		builder.WriteString("    template IN A {\n")
		fmt.Fprintf(&builder, "        match %q\n", pattern)
		fmt.Fprintf(&builder, "        answer \"{{ .Name }} 30 IN A %s\"\n", answerAddress)
		builder.WriteString("        fallthrough\n    }\n")
	}
	if len(exact) > 0 {
		builder.WriteString("    hosts {\n")
		for _, hostname := range exact {
			fmt.Fprintf(&builder, "        %s %s\n", answerAddress, hostname)
		}
		builder.WriteString("        ttl 30\n        no_reverse\n        fallthrough\n    }\n")
	}
	builder.WriteString("    forward . /etc/resolv.conf\n    reload 5s 2s\n    errors\n}\n")
	return builder.String()
}
