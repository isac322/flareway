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
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isac322/flareway/test/e2e/internal/poll"
)

// accessRevocationAnnotation mirrors gatewayapi.AccessRevocationAnnotation:
// the latch that turns a revoked application's data plane into a tombstone.
const accessRevocationAnnotation = "flareway.bhyoo.com/access-revocation"

// Deleting the last HTTPRoute of an Access-protected wildcard listener must
// not wedge the Gateway: the revoked application's Blocked tombstone keeps
// the Envoy port the applied tunnel config routes its host to, and the live
// Access host on a later listener must not be renumbered onto that port
// (isac322/flareway#141). Listener order is load-bearing: public listener
// ports are positional from 18080 and Access host ports follow them.
var _ = Describe("Access revocation tombstone port", Label("access-revocation"), Ordered, func() {
	var (
		serviceToken       *unstructured.Unstructured
		servicePolicy      *unstructured.Unstructured
		denyPolicy         *unstructured.Unstructured
		gateway            *unstructured.Unstructured
		previewRoute       *unstructured.Unstructured
		webRoute           *unstructured.Unstructured
		previewApplication *unstructured.Unstructured
		webApplication     *unstructured.Unstructured
		tunnel             *unstructured.Unstructured
		serviceTokenHeader map[string]string
	)

	BeforeAll(func(ctx SpecContext) {
		serviceToken = object("flareway.bhyoo.com/v1alpha1", "ServiceToken", namespace, "revocation-e2e", map[string]any{
			"accountRef": map[string]any{"name": accountName},
			"name":       namespace + "/revocation-e2e", "duration": "24h",
			"secretRef":        map[string]any{"name": "revocation-e2e-token"},
			"rotation":         map[string]any{"mode": "Manual", "graceDuration": "1h"},
			"managementPolicy": "Managed", "deletionPolicy": "Delete",
		})
		servicePolicy = object("flareway.bhyoo.com/v1alpha1", "AccessPolicy", namespace, "revocation-service-auth", map[string]any{
			"accountRef": map[string]any{"name": accountName},
			"name":       namespace + "/revocation-service-auth",
			"decision":   "NonIdentity",
			"include": []any{map[string]any{"serviceToken": map[string]any{
				"tokenRef": map[string]any{"name": serviceToken.GetName()},
			}}},
			"managementPolicy": "Managed", "deletionPolicy": "Delete",
		})
		denyPolicy = object("flareway.bhyoo.com/v1alpha1", "AccessPolicy", namespace, "revocation-deny-everyone", map[string]any{
			"accountRef":       map[string]any{"name": accountName},
			"name":             namespace + "/revocation-deny-everyone",
			"decision":         "Deny",
			"include":          []any{map[string]any{"everyone": map[string]any{}}},
			"managementPolicy": "Managed", "deletionPolicy": "Delete",
		})
		// "preview" must come first: it takes public port 18080, "web" takes
		// 18081, and Access host ports are handed out after them.
		gateway = object("gateway.networking.k8s.io/v1", "Gateway", namespace, "revocation", map[string]any{
			"gatewayClassName": className,
			"listeners": []any{
				edgeTerminatedListener("preview", revocationWildcardHostname),
				edgeTerminatedListener("web", revocationWebHostname),
			},
		})
		previewRoute = sectionRoute("preview-route", gateway.GetName(), "preview", revocationPreviewHostname)
		webRoute = sectionRoute("b-route", gateway.GetName(), "web", revocationWebHostname)
		previewApplication = sectionAccessApplication("app-a", gateway.GetName(), "preview", servicePolicy, denyPolicy)
		webApplication = sectionAccessApplication("app-b", gateway.GetName(), "web", servicePolicy, denyPolicy)
		tunnel = object("flareway.bhyoo.com/v1alpha1", "CloudflareTunnel", namespace, gateway.GetName(), nil)

		// Reverse remote-dependency order: application finalizers first,
		// then routes and the Gateway, the controller-created tunnel while
		// the suite CloudflareAccount still exists, and finally the policies
		// and the service token they reference.
		DeferCleanup(func(ctx SpecContext) {
			for _, value := range []*unstructured.Unstructured{webApplication, previewApplication} {
				deleteObject(ctx, value)
			}
			for _, value := range []*unstructured.Unstructured{webApplication, previewApplication} {
				waitForObjectDeletion(ctx, value)
			}
			for _, value := range []*unstructured.Unstructured{webRoute, previewRoute, gateway} {
				deleteObject(ctx, value)
			}
			for _, value := range []*unstructured.Unstructured{webRoute, previewRoute, gateway, tunnel} {
				waitForObjectDeletion(ctx, value)
			}
			for _, value := range []*unstructured.Unstructured{denyPolicy, servicePolicy} {
				deleteObject(ctx, value)
			}
			for _, value := range []*unstructured.Unstructured{denyPolicy, servicePolicy} {
				waitForObjectDeletion(ctx, value)
			}
			deleteObject(ctx, serviceToken)
			waitForObjectDeletion(ctx, serviceToken)
		}, NodeTimeout(8*time.Minute))

		for _, value := range []*unstructured.Unstructured{serviceToken, servicePolicy, denyPolicy} {
			Expect(kubeClient.Create(ctx, value)).To(Succeed())
		}
		for _, value := range []*unstructured.Unstructured{gateway, previewRoute, webRoute, previewApplication, webApplication} {
			Expect(kubeClient.Create(ctx, value)).To(Succeed())
		}
	}, NodeTimeout(time.Minute))

	It("protects the preview and web hosts behind Access before revocation", func(ctx SpecContext) {
		readyCtx, cancel := context.WithTimeout(ctx, 9*time.Minute)
		defer cancel()
		for _, value := range []*unstructured.Unstructured{serviceToken, servicePolicy, denyPolicy} {
			_, err := poll.Until(readyCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
				return hasCondition(checkCtx, value, "Accepted", "True")
			})
			Expect(err).NotTo(HaveOccurred(), "wait for %s/%s: %s", value.GetKind(), value.GetName(), conditionSummary(value))
		}
		serviceTokenHeader = waitForServiceTokenHeaders(readyCtx, serviceToken)
		waitForAccessReady(readyCtx, gateway, tunnel, webApplication, revocationWebHostname)
		waitForAccessReady(readyCtx, gateway, tunnel, previewApplication, revocationPreviewHostname)
		GinkgoWriter.Printf("Access data planes before revocation:\n%s", accessDataPlanePorts(previewApplication, webApplication))

		for _, host := range []string{revocationWebHostname, revocationPreviewHostname} {
			var status int
			var body string
			var requestErr error
			_, err := poll.Until(readyCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
				status, _, body, requestErr = edgeRequestTo(checkCtx, host, "/get", serviceTokenHeader)
				return requestErr == nil && status == http.StatusOK, nil
			})
			if err != nil {
				GinkgoWriter.Printf("Dataplane diagnostics:\n%s\n", dataplaneDiagnostics())
			}
			Expect(err).NotTo(HaveOccurred(),
				"service token must reach the origin through %s: status=%d body=%q error=%v",
				host, status, body, requestErr)

			status, headers, body, err := edgeRequestTo(readyCtx, host, "/get", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(http.StatusFound),
				"unauthenticated request to %s must redirect to authentication: body: %s", host, body)
			expectAccessChallenge(headers, "unauthenticated request to "+host)
		}
	}, NodeTimeout(10*time.Minute))

	It("keeps the Gateway programmed and the web host reachable after the preview listener loses its last route", func(ctx SpecContext) {
		GinkgoWriter.Printf("Access data planes before route deletion:\n%s", accessDataPlanePorts(previewApplication, webApplication))
		Expect(kubeClient.Delete(ctx, previewRoute)).To(Succeed())
		waitForObjectDeletion(ctx, previewRoute)

		// Gate on the controller consuming the deletion: the preview host
		// stops Forwarding once the block-first handshake (or the tombstone)
		// takes over. Without this gate the recovery poll below could pass
		// on the pre-deletion state.
		revokedCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		duration, err := poll.Until(revokedCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			forwarding, err := tunnelHostnameGuard(checkCtx, tunnel, revocationPreviewHostname, "Forwarding")
			return !forwarding, err
		})
		if err != nil {
			printRevocationDiagnostics(gateway, tunnel, previewApplication, webApplication)
		}
		Expect(err).NotTo(HaveOccurred(),
			"preview host %s kept Forwarding after its last HTTPRoute was deleted; Tunnel status: %s",
			revocationPreviewHostname, statusSummary(tunnel))
		recordLatency("access-revocation-preview-unforwarded", duration)

		// The discriminator. On the defect the tombstone re-takes the stale
		// envoyPort the live web Access host was just renumbered onto, xDS
		// refuses to build ("cannot share"), Programmed stays False/Invalid,
		// and the web host stays at the block-first 403 forever. Fixed code
		// keeps the ports apart and the web host recovers.
		var programmed string
		var webStatus, previewStatus int
		var webBody, previewBody string
		var webErr, previewErr error
		consecutive := 0
		recoverCtx, recoverCancel := context.WithTimeout(ctx, 5*time.Minute)
		defer recoverCancel()
		duration, err = poll.Until(recoverCtx, 5*time.Second, func(checkCtx context.Context) (bool, error) {
			var ready bool
			var err error
			ready, programmed, err = gatewayProgrammedForGeneration(checkCtx, gateway)
			if err != nil {
				return false, err
			}
			previewStatus, _, previewBody, previewErr = edgeRequestTo(checkCtx, revocationPreviewHostname, "/get", serviceTokenHeader)
			if previewErr == nil && successful(previewStatus) {
				return false, fmt.Errorf("revoked preview host %s reached the origin after its route was deleted: status=%d body=%q",
					revocationPreviewHostname, previewStatus, previewBody)
			}
			webStatus, _, webBody, webErr = edgeRequestTo(checkCtx, revocationWebHostname, "/get", serviceTokenHeader)
			if !ready || webErr != nil || !successful(webStatus) {
				consecutive = 0
				return false, nil
			}
			consecutive++
			return consecutive >= 3, nil
		})
		if err != nil {
			printRevocationDiagnostics(gateway, tunnel, previewApplication, webApplication)
		}
		Expect(err).NotTo(HaveOccurred(),
			"Gateway did not recover after the preview listener lost its last route: Programmed %s; "+
				"web host %s status=%d body=%q error=%v; preview host %s status=%d error=%v; Gateway conditions: %s",
			programmed, revocationWebHostname, webStatus, webBody, webErr,
			revocationPreviewHostname, previewStatus, previewErr, conditionSummary(gateway))
		recordLatency("access-revocation-web-recovered", duration)

		// The revoked preview host stays fail-closed: 403 from the tombstone
		// or 404 once its ingress is withdrawn, never the origin.
		finalCtx, finalCancel := context.WithTimeout(ctx, 2*time.Minute)
		defer finalCancel()
		consecutive = 0
		_, err = poll.Until(finalCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			previewStatus, _, previewBody, previewErr = edgeRequestTo(checkCtx, revocationPreviewHostname, "/get", serviceTokenHeader)
			if previewErr != nil {
				consecutive = 0
				return false, nil
			}
			if successful(previewStatus) {
				return false, fmt.Errorf("revoked preview host %s reached the origin: status=%d body=%q",
					revocationPreviewHostname, previewStatus, previewBody)
			}
			if previewStatus != http.StatusForbidden && previewStatus != http.StatusNotFound {
				consecutive = 0
				return false, nil
			}
			consecutive++
			return consecutive >= 3, nil
		})
		Expect(err).NotTo(HaveOccurred(),
			"revoked preview host %s did not stay fail-closed: status=%d body=%q error=%v",
			revocationPreviewHostname, previewStatus, previewBody, previewErr)
	}, NodeTimeout(13*time.Minute))
})

// edgeTerminatedListener is a public HTTPS listener whose certificate
// Cloudflare holds; Envoy serves it as cleartext on loopback.
func edgeTerminatedListener(name, host string) map[string]any {
	return map[string]any{
		"name": name, "hostname": host, "port": int64(443), "protocol": "HTTPS",
		"allowedRoutes": map[string]any{"namespaces": map[string]any{"from": "Same"}},
	}
}

func sectionRoute(name, gatewayName, section, host string) *unstructured.Unstructured {
	return object("gateway.networking.k8s.io/v1", "HTTPRoute", namespace, name, map[string]any{
		"parentRefs": []any{map[string]any{"name": gatewayName, "sectionName": section}},
		"hostnames":  []any{host},
		"rules": []any{map[string]any{
			"backendRefs": []any{map[string]any{"name": "echo", "port": int64(8080)}},
		}},
	})
}

func sectionAccessApplication(name, gatewayName, section string, policies ...*unstructured.Unstructured) *unstructured.Unstructured {
	refs := make([]any, 0, len(policies))
	for _, policy := range policies {
		refs = append(refs, map[string]any{"policyRef": map[string]any{"name": policy.GetName()}})
	}
	return object("flareway.bhyoo.com/v1alpha1", "AccessApplication", namespace, name, map[string]any{
		"accountRef": map[string]any{"name": accountName},
		"type":       "SelfHosted",
		"selfHosted": map[string]any{},
		"targetRefs": []any{map[string]any{
			"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": gatewayName, "sectionName": section,
		}},
		"application": map[string]any{
			"name": namespace + "/" + name, "sessionDuration": "24h", "appLauncherVisible": false,
		},
		"policies":         refs,
		"originJWT":        map[string]any{"mode": "Required"},
		"managementPolicy": "Managed", "deletionPolicy": "Delete",
	})
}

func successful(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

// gatewayProgrammedForGeneration reports whether Programmed is True for the
// Gateway's current generation, plus a one-line summary of the condition.
func gatewayProgrammedForGeneration(ctx context.Context, gateway *unstructured.Unstructured) (bool, string, error) {
	current := gateway.DeepCopy()
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(gateway), current); err != nil {
		return false, "", err
	}
	conditions, _, err := unstructured.NestedSlice(current.Object, "status", "conditions")
	if err != nil {
		return false, "", err
	}
	for _, item := range conditions {
		condition, ok := item.(map[string]any)
		if !ok || condition["type"] != "Programmed" {
			continue
		}
		observed, _, _ := unstructured.NestedInt64(condition, "observedGeneration")
		summary := fmt.Sprintf("status=%v reason=%v observedGeneration=%d generation=%d message=%q",
			condition["status"], condition["reason"], observed, current.GetGeneration(), condition["message"])
		return condition["status"] == "True" && observed == current.GetGeneration(), summary, nil
	}
	return false, "Programmed condition absent", nil
}

func printRevocationDiagnostics(gateway, tunnel *unstructured.Unstructured, applications ...*unstructured.Unstructured) {
	GinkgoWriter.Printf("Gateway conditions: %s\n", conditionSummary(gateway))
	GinkgoWriter.Printf("Tunnel status: %s\n", statusSummary(tunnel))
	for _, application := range applications {
		GinkgoWriter.Printf("AccessApplication %s status: %s\n", application.GetName(), statusSummary(application))
	}
	GinkgoWriter.Printf("Access data planes:\n%s", accessDataPlanePorts(applications...))
	GinkgoWriter.Printf("Controller xDS build errors:\n%s", controllerBuildErrors())
	GinkgoWriter.Printf("Dataplane diagnostics:\n%s\n", dataplaneDiagnostics())
}

// accessDataPlanePorts lists each application's recorded data planes and
// flags any Envoy port recorded by more than one protection domain: a
// revoked tombstone and a live domain cannot share one cleartext bind.
func accessDataPlanePorts(applications ...*unstructured.Unstructured) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var summary strings.Builder
	owners := make(map[int64][]string)
	for _, application := range applications {
		current := application.DeepCopy()
		if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(application), current); err != nil {
			fmt.Fprintf(&summary, "get AccessApplication %s: %v\n", application.GetName(), err)
			continue
		}
		_, latched := current.GetAnnotations()[accessRevocationAnnotation]
		dataPlanes, _, err := unstructured.NestedSlice(current.Object, "status", "dataPlanes")
		if err != nil {
			fmt.Fprintf(&summary, "read AccessApplication %s data planes: %v\n", current.GetName(), err)
			continue
		}
		if len(dataPlanes) == 0 {
			fmt.Fprintf(&summary, "AccessApplication %s revocationLatched=%t has no data planes\n", current.GetName(), latched)
		}
		for _, item := range dataPlanes {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			port, _, _ := unstructured.NestedInt64(entry, "envoyPort")
			listener, _, _ := unstructured.NestedString(entry, "listener")
			domain, _, _ := unstructured.NestedString(entry, "protectionDomain")
			fmt.Fprintf(&summary, "AccessApplication %s revocationLatched=%t listener=%s protectionDomain=%s envoyPort=%d\n",
				current.GetName(), latched, listener, domain, port)
			owners[port] = append(owners[port], current.GetName()+"/"+domain)
		}
	}
	ports := make([]int64, 0, len(owners))
	for port := range owners {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	for _, port := range ports {
		if len(owners[port]) > 1 {
			fmt.Fprintf(&summary, "PORT COLLISION: envoyPort %d is recorded by %s\n", port, strings.Join(owners[port], ", "))
		}
	}
	return summary.String()
}

// controllerBuildErrors returns only the controller log lines carrying the
// xDS build rejection of a shared cleartext bind. The filter is deliberately
// narrow so no request or credential detail reaches the test output.
func controllerBuildErrors() string {
	if kubeClientset == nil {
		return "Kubernetes clientset is unavailable\n"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pods, err := kubeClientset.CoreV1().Pods("flareway-system").List(ctx, metav1.ListOptions{
		LabelSelector: "control-plane=controller-manager",
	})
	if err != nil {
		return fmt.Sprintf("list controller Pods: %v\n", err)
	}
	const maxLines = 20
	var summary strings.Builder
	for index := range pods.Items {
		pod := &pods.Items[index]
		tailLines := int64(5000)
		logs, err := kubeClientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
			Container: "manager",
			TailLines: &tailLines,
		}).DoRaw(ctx)
		if err != nil {
			fmt.Fprintf(&summary, "Pod %s logs: %v\n", pod.Name, err)
			continue
		}
		matches := make([]string, 0)
		for _, line := range strings.Split(string(logs), "\n") {
			if strings.Contains(line, "cannot share") {
				matches = append(matches, line)
			}
		}
		if len(matches) > maxLines {
			matches = matches[len(matches)-maxLines:]
		}
		fmt.Fprintf(&summary, "Pod %s: %d recent line(s) containing \"cannot share\"\n", pod.Name, len(matches))
		for _, line := range matches {
			fmt.Fprintf(&summary, "  %s\n", line)
		}
	}
	if summary.Len() == 0 {
		return "no controller Pods found\n"
	}
	return summary.String()
}
