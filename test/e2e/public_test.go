//go:build e2e

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

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isac322/flareway/test/e2e/internal/poll"
)

var _ = Describe("Public Cloudflare edge", Label("public"), Ordered, func() {
	var gatewayName string
	var gateway, route, tunnel *unstructured.Unstructured
	var tunnelID string

	BeforeAll(func(ctx SpecContext) {
		gatewayName = "public"
		gateway = object("gateway.networking.k8s.io/v1", "Gateway", namespace, gatewayName, map[string]any{
			"gatewayClassName": className,
			"listeners": []any{map[string]any{
				"name": "http", "hostname": hostname, "port": int64(80), "protocol": "HTTP",
				"allowedRoutes": map[string]any{"namespaces": map[string]any{"from": "Same"}},
			}},
		})
		Expect(kubeClient.Create(ctx, gateway)).To(Succeed())

		route = object("gateway.networking.k8s.io/v1", "HTTPRoute", namespace, "public", map[string]any{
			"parentRefs": []any{map[string]any{"name": gatewayName}},
			"hostnames":  []any{hostname},
			"rules": []any{map[string]any{
				"matches":     []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/get"}}},
				"backendRefs": []any{map[string]any{"name": "echo", "port": int64(8080)}},
			}},
		})
		Expect(kubeClient.Create(ctx, route)).To(Succeed())
		tunnel = object("flareway.bhyoo.com/v1alpha1", "CloudflareTunnel", namespace, gatewayName, nil)
	}, NodeTimeout(time.Minute))

	AfterAll(func(ctx SpecContext) {
		deleteObject(ctx, route)
		deleteObject(ctx, tunnel)
		deleteObject(ctx, gateway)
	}, NodeTimeout(time.Minute))

	It("programs DNS, tunnel, cloudflared, Envoy, and backend truthfully", func(ctx SpecContext) {
		programCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		duration, err := poll.Until(programCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			return hasCondition(checkCtx, gateway, "Programmed", "True")
		})
		if err != nil {
			GinkgoWriter.Printf("Dataplane diagnostics:\n%s\n", dataplaneDiagnostics())
		}
		Expect(err).NotTo(HaveOccurred(), "Gateway conditions: %s", conditionSummary(gateway))
		recordLatency("public-programmed", duration)

		duration, err = poll.Until(programCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			if err := kubeClient.Get(checkCtx, client.ObjectKeyFromObject(tunnel), tunnel); err != nil {
				return false, client.IgnoreNotFound(err)
			}
			value, found, nestedErr := unstructured.NestedString(tunnel.Object, "status", "tunnelId")
			if nestedErr != nil || !found || value == "" {
				return false, nestedErr
			}
			tunnelID = value
			return hasCondition(checkCtx, tunnel, "Ready", "True")
		})
		Expect(err).NotTo(HaveOccurred(), "CloudflareTunnel conditions: %s", conditionSummary(tunnel))
		recordLatency("public-tunnel-ready", duration)

		var status int
		var body string
		var requestErr error
		duration, err = poll.Until(programCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			status, body, requestErr = edgeRequest(checkCtx, "/get")
			return requestErr == nil && status == http.StatusOK, nil
		})
		Expect(
			err,
		).NotTo(
			HaveOccurred(),
			"edge /get did not become ready: status=%d body=%q error=%v",
			status,
			body,
			requestErr,
		)
		recordLatency("public-edge-ready", duration)

		duration, err = poll.Until(programCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			status, body, requestErr = edgeRequest(checkCtx, "/nope")
			return requestErr == nil && status == http.StatusNotFound, nil
		})
		Expect(
			err,
		).NotTo(
			HaveOccurred(),
			"edge /nope did not become fail-closed: status=%d body=%q error=%v",
			status,
			body,
			requestErr,
		)
	}, NodeTimeout(6*time.Minute))

	It("removes route configuration and remote resources", func(ctx SpecContext) {
		before, err := tunnelConfigVersion(ctx, tunnel)
		Expect(err).NotTo(HaveOccurred())
		Expect(kubeClient.Delete(ctx, route)).To(Succeed())

		convergeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		duration, err := poll.Until(convergeCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			desired, applied, versionErr := tunnelConfigVersions(checkCtx, tunnel)
			return desired > before && applied == desired, versionErr
		})
		Expect(err).NotTo(HaveOccurred())
		recordLatency("public-route-removal", duration)

		status, body, err := edgeRequest(ctx, "/get")
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusNotFound), "deleted HTTPRoute must stop forwarding; body: %s", body)

		Expect(kubeClient.Delete(ctx, gateway)).To(Succeed())
		cleanupCtx, cleanupCancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cleanupCancel()
		duration, err = poll.Until(cleanupCtx, 5*time.Second, func(checkCtx context.Context) (bool, error) {
			current := tunnel.DeepCopy()
			getErr := kubeClient.Get(checkCtx, client.ObjectKeyFromObject(tunnel), current)
			return apierrors.IsNotFound(getErr), client.IgnoreNotFound(getErr)
		})
		Expect(err).NotTo(HaveOccurred())
		recordLatency("public-kubernetes-cleanup", duration)

		duration, err = poll.Until(cleanupCtx, 5*time.Second, func(checkCtx context.Context) (bool, error) {
			tunnels, listErr := cloudflareAPI.ListTunnels(checkCtx)
			if listErr != nil {
				return false, listErr
			}
			for _, candidate := range tunnels {
				if candidate.ID == tunnelID {
					return false, nil
				}
			}
			records, listErr := cloudflareAPI.ListDNSRecords(checkCtx)
			if listErr != nil {
				return false, listErr
			}
			for _, record := range records {
				if record.Name == hostname {
					return false, nil
				}
			}
			return true, nil
		})
		Expect(err).NotTo(HaveOccurred())
		recordLatency("public-cloudflare-cleanup", duration)
	}, NodeTimeout(7*time.Minute))
})

func edgeRequest(ctx context.Context, path string) (int, string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+path, nil)
	if err != nil {
		return 0, "", fmt.Errorf("create edge request: %w", err)
	}
	request.Header.Set("User-Agent", e2eUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return 0, "", fmt.Errorf("send edge request: %w", err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, "", fmt.Errorf("read edge response: %w", err)
	}
	return response.StatusCode, string(content), nil
}

func tunnelConfigVersion(ctx context.Context, tunnel *unstructured.Unstructured) (int64, error) {
	desired, _, err := tunnelConfigVersions(ctx, tunnel)
	return desired, err
}

func tunnelConfigVersions(ctx context.Context, tunnel *unstructured.Unstructured) (int64, int64, error) {
	current := tunnel.DeepCopy()
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(tunnel), current); err != nil {
		return 0, 0, err
	}
	desired, _, err := unstructured.NestedInt64(current.Object, "status", "configVersion", "desired")
	if err != nil {
		return 0, 0, err
	}
	applied, _, err := unstructured.NestedInt64(current.Object, "status", "configVersion", "applied")
	return desired, applied, err
}
