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

// Package dataplane builds the Kubernetes resources for a Gateway data plane.
package dataplane

import (
	"fmt"
	"net"
	"strconv"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/bootstrap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BuildBootstrapConfigMap renders the static Delta ADS bootstrap and the two
// file-backed SDS resources used for the xDS client certificate and CA.
func BuildBootstrapConfigMap(gw *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) (*corev1.ConfigMap, error) {
	files, err := bootstrap.Render(bootstrap.Options{
		NodeCluster:     gw.Key.String(),
		XDSAddress:      net.JoinHostPort(XDSServiceHost, strconv.Itoa(int(XDSPort))),
		ConformanceMode: conformanceMode(gw, cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("render Envoy bootstrap for Gateway %s: %w", gw.Key, err)
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1.SchemeGroupVersion.String(), Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            BootstrapConfigMapName(gw),
			Namespace:       gw.Key.Namespace,
			Labels:          resourceLabels(gw),
			Annotations:     map[string]string{ManagedByLabelKey: managedByValue(gw)},
			OwnerReferences: gatewayOwnerReferences(gw),
		},
		Data: map[string]string{
			"bootstrap.yaml":     files.BootstrapYAML,
			"client-secret.yaml": files.ClientSecretYAML,
			"ca-secret.yaml":     files.CASecretYAML,
		},
	}, nil
}
