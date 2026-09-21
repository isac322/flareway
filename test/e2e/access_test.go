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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isac322/flareway/test/e2e/internal/poll"
)

var _ = Describe("Cloudflare Access", Label("access"), Ordered, func() {
	var (
		serviceToken       *unstructured.Unstructured
		servicePolicy      *unstructured.Unstructured
		denyPolicy         *unstructured.Unstructured
		accessGateway      *unstructured.Unstructured
		accessRoute        *unstructured.Unstructured
		accessTunnel       *unstructured.Unstructured
		accessApplication  *unstructured.Unstructured
		mixedGateway       *unstructured.Unstructured
		mixedRoute         *unstructured.Unstructured
		mixedTunnel        *unstructured.Unstructured
		mixedApplication   *unstructured.Unstructured
		serviceTokenHeader map[string]string
	)

	BeforeAll(func(ctx SpecContext) {
		serviceToken = object("flareway.bhyoo.com/v1alpha1", "ServiceToken", namespace, "access-e2e", map[string]any{
			"accountRef":       map[string]any{"name": accountName},
			"name":             namespace + "/access-e2e",
			"duration":         "24h",
			"secretRef":        map[string]any{"name": "access-e2e-token"},
			"rotation":         map[string]any{"mode": "Manual", "graceDuration": "1h"},
			"managementPolicy": "Managed",
			"deletionPolicy":   "Delete",
		})
		servicePolicy = object("flareway.bhyoo.com/v1alpha1", "AccessPolicy", namespace, "service-auth", map[string]any{
			"accountRef": map[string]any{"name": accountName},
			"name":       namespace + "/service-auth",
			"decision":   "NonIdentity",
			"include": []any{map[string]any{
				"serviceToken": map[string]any{"tokenRef": map[string]any{"name": serviceToken.GetName()}},
			}},
			"managementPolicy": "Managed",
			"deletionPolicy":   "Delete",
		})
		denyPolicy = object("flareway.bhyoo.com/v1alpha1", "AccessPolicy", namespace, "deny-everyone", map[string]any{
			"accountRef":       map[string]any{"name": accountName},
			"name":             namespace + "/deny-everyone",
			"decision":         "Deny",
			"include":          []any{map[string]any{"everyone": map[string]any{}}},
			"managementPolicy": "Managed",
			"deletionPolicy":   "Delete",
		})
		for _, value := range []*unstructured.Unstructured{serviceToken, servicePolicy, denyPolicy} {
			Expect(kubeClient.Create(ctx, value)).To(Succeed())
		}

		accessGateway = publicGateway("access", accessHostname)
		accessRoute = object("gateway.networking.k8s.io/v1", "HTTPRoute", namespace, "access", map[string]any{
			"parentRefs": []any{map[string]any{"name": accessGateway.GetName()}},
			"hostnames":  []any{accessHostname},
			"rules": []any{map[string]any{
				"backendRefs": []any{map[string]any{"name": "echo", "port": int64(8080)}},
			}},
		})
		accessApplication = object("flareway.bhyoo.com/v1alpha1", "AccessApplication", namespace, "access", map[string]any{
			"accountRef": map[string]any{"name": accountName},
			"type":       "SelfHosted",
			"selfHosted": map[string]any{},
			"targetRefs": []any{map[string]any{
				"group": "gateway.networking.k8s.io", "kind": "Gateway",
				"name": accessGateway.GetName(), "sectionName": "web",
			}},
			"application": map[string]any{
				"name": namespace + "/access", "sessionDuration": "24h", "appLauncherVisible": false,
			},
			"policies": []any{
				map[string]any{"policyRef": map[string]any{"name": servicePolicy.GetName()}},
				map[string]any{"policyRef": map[string]any{"name": denyPolicy.GetName()}},
			},
			"originJWT":        map[string]any{"mode": "Required"},
			"managementPolicy": "Managed",
			"deletionPolicy":   "Delete",
		})
		accessTunnel = object("flareway.bhyoo.com/v1alpha1", "CloudflareTunnel", namespace, accessGateway.GetName(), nil)

		mixedGateway = publicGateway("mixed", mixedHostname)
		mixedRoute = object("gateway.networking.k8s.io/v1", "HTTPRoute", namespace, "mixed", map[string]any{
			"parentRefs": []any{map[string]any{"name": mixedGateway.GetName()}},
			"hostnames":  []any{mixedHostname},
			"rules": []any{
				rewrittenRule("public-v1", "/v1"),
				rewrittenRule("public-tools", "/backend-api/tools"),
				rewrittenRule("dashboard", "/"),
			},
		})
		mixedApplication = object("flareway.bhyoo.com/v1alpha1", "AccessApplication", namespace, "mixed", map[string]any{
			"accountRef": map[string]any{"name": accountName},
			"type":       "SelfHosted",
			"selfHosted": map[string]any{},
			"targetRefs": []any{map[string]any{
				"group": "gateway.networking.k8s.io", "kind": "HTTPRoute",
				"name": mixedRoute.GetName(), "sectionName": "dashboard",
			}},
			"application": map[string]any{
				"name": namespace + "/mixed", "sessionDuration": "24h", "appLauncherVisible": false,
			},
			"policies": []any{
				map[string]any{"policyRef": map[string]any{"name": servicePolicy.GetName()}},
				map[string]any{"policyRef": map[string]any{"name": denyPolicy.GetName()}},
			},
			"originJWT":        map[string]any{"mode": "Required"},
			"managementPolicy": "Managed",
			"deletionPolicy":   "Delete",
		})
		mixedTunnel = object("flareway.bhyoo.com/v1alpha1", "CloudflareTunnel", namespace, mixedGateway.GetName(), nil)

		for _, value := range []*unstructured.Unstructured{accessGateway, accessRoute, accessApplication, mixedGateway, mixedRoute, mixedApplication} {
			Expect(kubeClient.Create(ctx, value)).To(Succeed())
		}

		readyCtx, cancel := context.WithTimeout(ctx, 7*time.Minute)
		defer cancel()
		for _, value := range []*unstructured.Unstructured{serviceToken, servicePolicy, denyPolicy} {
			_, err := poll.Until(readyCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
				return hasCondition(checkCtx, value, "Accepted", "True")
			})
			Expect(err).NotTo(HaveOccurred(), "wait for %s/%s", value.GetKind(), value.GetName())
		}
		serviceTokenHeader = waitForServiceTokenHeaders(readyCtx, serviceToken)
		waitForAccessReady(readyCtx, accessGateway, accessTunnel, accessApplication, accessHostname)
		waitForAccessReady(readyCtx, mixedGateway, mixedTunnel, mixedApplication, mixedHostname)
	}, NodeTimeout(9*time.Minute))

	AfterAll(func(ctx SpecContext) {
		// Reverse remote-dependency order: application finalizers remove
		// remote bypass children first, then routes and gateways, then the
		// shared policies, and finally the service token they reference.
		for _, value := range []*unstructured.Unstructured{mixedApplication, accessApplication} {
			deleteObject(ctx, value)
		}
		for _, value := range []*unstructured.Unstructured{mixedApplication, accessApplication} {
			waitForObjectDeletion(ctx, value)
		}
		for _, value := range []*unstructured.Unstructured{
			mixedRoute, accessRoute,
			mixedGateway, accessGateway,
		} {
			deleteObject(ctx, value)
		}
		// The controller-created CloudflareTunnels must finish remote cleanup
		// while the suite-level CloudflareAccount still exists.
		for _, value := range []*unstructured.Unstructured{
			mixedRoute, accessRoute,
			mixedGateway, accessGateway,
			mixedTunnel, accessTunnel,
		} {
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
	}, NodeTimeout(5*time.Minute))

	It("denies unauthenticated and forged assertions while accepting a service token", func(ctx SpecContext) {
		status, responseHeaders, body, err := edgeRequestTo(ctx, accessHostname, "/get", nil)
		Expect(err).NotTo(HaveOccurred())
		if status != http.StatusFound {
			GinkgoWriter.Printf("Unauthenticated Access response: status=%d server=%q ray=%q content-type=%q body-bytes=%d\n",
				status, responseHeaders.Get("Server"), responseHeaders.Get("Cf-Ray"), responseHeaders.Get("Content-Type"), len(body))
		}
		Expect(status).To(Equal(http.StatusFound), "unauthenticated Access request must redirect to authentication; body: %s", body)
		expectAccessChallenge(responseHeaders, "unauthenticated Access request")

		status, _, body, err = edgeRequestTo(ctx, accessHostname, "/get", serviceTokenHeader)
		Expect(err).NotTo(HaveOccurred())
		if status != http.StatusOK {
			GinkgoWriter.Printf("Dataplane diagnostics:\n%s\n", dataplaneDiagnostics())
		}
		Expect(status).To(Equal(http.StatusOK), "valid service token must reach the origin; body: %s", body)

		for name, assertion := range map[string]string{
			"forged":    "forged.invalid.signature",
			"wrong-aud": syntheticJWT("aud-for-a-different-application"),
		} {
			status, responseHeaders, body, err = edgeRequestTo(ctx, accessHostname, "/get", map[string]string{"Cf-Access-Jwt-Assertion": assertion})
			Expect(err).NotTo(HaveOccurred(), name)
			Expect(status).To(
				SatisfyAny(Equal(http.StatusFound), Equal(http.StatusUnauthorized), Equal(http.StatusForbidden)),
				"%s assertion must receive an Access denial or challenge instead of reaching the origin; body: %s",
				name,
				body,
			)
			if status == http.StatusFound {
				expectAccessChallenge(responseHeaders, name+" assertion")
			}
		}
	}, NodeTimeout(2*time.Minute))

	It("keeps child bypass paths public while protecting the enclosing dashboard", func(ctx SpecContext) {

		current := mixedApplication.DeepCopy()
		Expect(kubeClient.Get(ctx, client.ObjectKeyFromObject(mixedApplication), current)).To(Succeed())
		children, found, err := unstructured.NestedSlice(current.Object, "status", "bypassApplications")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(children).To(HaveLen(2), "each public carve-out requires an operator-owned child application")
		readyCtx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		consecutive := 0
		duration, readyErr := poll.Until(readyCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			status, _, _, err := edgeRequestTo(checkCtx, mixedHostname, "/dashboard", nil)
			GinkgoWriter.Printf("bypass convergence /dashboard: HTTP %d, request error=%v\n", status, err)
			if err != nil {
				consecutive = 0
				return false, nil
			}
			if status >= http.StatusOK && status < http.StatusMultipleChoices {
				return false, fmt.Errorf("protected dashboard became public while waiting for bypass convergence: HTTP %d", status)
			}
			ready := status == http.StatusFound
			for _, path := range []string{"/v1", "/backend-api/tools"} {
				status, _, _, err = edgeRequestTo(checkCtx, mixedHostname, path, nil)
				GinkgoWriter.Printf("bypass convergence %s: HTTP %d, request error=%v\n", path, status, err)
				ready = ready && err == nil && status == http.StatusOK
			}
			if !ready {
				consecutive = 0
				return false, nil
			}
			consecutive++
			return consecutive >= 3, nil
		})
		if readyErr != nil {
			GinkgoWriter.Printf("bypass readiness failure; AccessApplication: %s; Gateway: %s\n",
				statusSummary(mixedApplication), statusSummary(mixedGateway))
		}
		Expect(readyErr).NotTo(HaveOccurred(), "child bypass paths did not converge while the dashboard remained protected")
		recordLatency("access-bypass-edge-ready", duration)

		for _, path := range []string{"/v1", "/backend-api/tools"} {
			status, _, body, err := edgeRequestTo(ctx, mixedHostname, path, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(http.StatusOK), "operator-owned bypass path %s must stay public; body: %s", path, body)
		}

		status, responseHeaders, body, err := edgeRequestTo(ctx, mixedHostname, "/dashboard", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusFound), "dashboard must redirect unauthenticated clients to Access; body: %s", body)
		expectAccessChallenge(responseHeaders, "dashboard")
		status, _, body, err = edgeRequestTo(ctx, mixedHostname, "/dashboard", serviceTokenHeader)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), "service token must reach protected dashboard; body: %s", body)
	}, NodeTimeout(2*time.Minute))

	It("blocks immediately when the AUD Secret disappears and never becomes public", func(ctx SpecContext) {
		secret := waitForAUDSecret(ctx, accessApplication)
		Expect(kubeClient.Delete(ctx, secret)).To(Succeed())

		blockedCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		duration, err := poll.Until(blockedCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			return tunnelHostnameGuard(checkCtx, accessTunnel, accessHostname, "Blocked")
		})
		Expect(err).NotTo(HaveOccurred())
		recordLatency("access-aud-secret-blocked", duration)

		status, _, body, err := edgeRequestTo(ctx, accessHostname, "/get", serviceTokenHeader)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusForbidden), "missing AUD Secret must block instead of disabling Access; body: %s", body)
	}, NodeTimeout(2*time.Minute))

	It("keeps the hostname blocked after AccessApplication deletion", func(ctx SpecContext) {
		Expect(kubeClient.Delete(ctx, accessApplication)).To(Succeed())
		deletedCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		duration, err := poll.Until(deletedCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			current := accessApplication.DeepCopy()
			getErr := kubeClient.Get(checkCtx, client.ObjectKeyFromObject(accessApplication), current)
			return apierrors.IsNotFound(getErr), client.IgnoreNotFound(getErr)
		})
		Expect(err).NotTo(HaveOccurred())
		recordLatency("access-application-deleted", duration)
		status, _, body, err := edgeRequestTo(ctx, accessHostname, "/get", serviceTokenHeader)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(
			SatisfyAny(Equal(http.StatusForbidden), Equal(http.StatusNotFound)),
			"deleting AccessApplication must keep the hostname fail-closed; body: %s",
			body,
		)
	}, NodeTimeout(4*time.Minute))
})

func publicGateway(name, host string) *unstructured.Unstructured {
	return object("gateway.networking.k8s.io/v1", "Gateway", namespace, name, map[string]any{
		"gatewayClassName": className,
		"listeners": []any{map[string]any{
			"name": "web", "hostname": host, "port": int64(80), "protocol": "HTTP",
			"allowedRoutes": map[string]any{"namespaces": map[string]any{"from": "Same"}},
		}},
	})
}

func rewrittenRule(name, path string) map[string]any {
	return map[string]any{
		"name":    name,
		"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": path}}},
		"filters": []any{map[string]any{
			"type": "URLRewrite",
			"urlRewrite": map[string]any{"path": map[string]any{
				"type": "ReplaceFullPath", "replaceFullPath": "/get",
			}},
		}},
		"backendRefs": []any{map[string]any{"name": "echo", "port": int64(8080)}},
	}
}

func waitForServiceTokenHeaders(ctx context.Context, token *unstructured.Unstructured) map[string]string {
	var values map[string]string
	_, err := poll.Until(ctx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
		current := &corev1.Secret{}
		err := kubeClient.Get(checkCtx, client.ObjectKey{Namespace: namespace, Name: "access-e2e-token"}, current)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		clientID, clientSecret := string(current.Data["CF-Access-Client-Id"]), string(current.Data["CF-Access-Client-Secret"])
		if clientID == "" || clientSecret == "" {
			return false, nil
		}
		values = map[string]string{"CF-Access-Client-Id": clientID, "CF-Access-Client-Secret": clientSecret}
		return true, nil
	})
	Expect(err).NotTo(HaveOccurred(), "wait for one-time service-token Secret for %s", token.GetName())
	return values
}

func waitForAccessReady(ctx context.Context, gateway, tunnel, application *unstructured.Unstructured, host string) {
	started := time.Now()
	_, err := poll.Until(ctx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
		accepted, err := hasCondition(checkCtx, application, "Accepted", "True")
		if err != nil || !accepted {
			return false, err
		}
		enforced, err := hasCondition(checkCtx, application, "OriginJWTEnforced", "True")
		if err != nil || !enforced {
			return false, err
		}
		programmed, err := hasCondition(checkCtx, gateway, "Programmed", "True")
		if err != nil || !programmed {
			return false, err
		}
		return tunnelHostnameGuard(checkCtx, tunnel, host, "Forwarding")
	})
	if err != nil {
		GinkgoWriter.Printf("Dataplane diagnostics:\n%s\n", dataplaneDiagnostics())
		GinkgoWriter.Printf("AUD Secret diagnostics:\n%s\n", audSecretDiagnostics())
	}
	Expect(
		err,
	).NotTo(
		HaveOccurred(),
		"wait for protected hostname %s; application status: %s; Gateway status: %s; Tunnel status: %s",
		host,
		statusSummary(application),
		statusSummary(gateway),
		statusSummary(tunnel),
	)
	var lastStatus int
	var lastEdgeErr error
	_, err = poll.Until(ctx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
		lastStatus, _, _, lastEdgeErr = edgeRequestTo(checkCtx, host, "/", nil)
		return lastEdgeErr == nil && lastStatus < http.StatusInternalServerError, nil
	})
	Expect(err).NotTo(HaveOccurred(), "wait for edge hostname %s: status=%d error=%v", host, lastStatus, lastEdgeErr)
	recordLatency("access-ready-"+application.GetName(), time.Since(started))
}

func waitForAUDSecret(ctx context.Context, application *unstructured.Unstructured) *corev1.Secret {
	var result *corev1.Secret
	_, err := poll.Until(ctx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
		secrets := &corev1.SecretList{}
		if err := kubeClient.List(checkCtx, secrets, client.InNamespace("flareway-system")); err != nil {
			return false, err
		}
		applicationKey := namespace + "/" + application.GetName()
		matches := make([]corev1.Secret, 0, 1)
		for index := range secrets.Items {
			secret := &secrets.Items[index]
			if string(secret.Data[v1alpha1.AccessApplicationNamespacedNameSecretKey]) == applicationKey &&
				string(secret.Data[v1alpha1.AccessApplicationUIDSecretKey]) == string(application.GetUID()) {
				matches = append(matches, *secret)
			}
		}
		if len(matches) != 1 {
			return false, nil
		}
		result = matches[0].DeepCopy()
		return true, nil
	})
	Expect(err).NotTo(HaveOccurred(), "wait for AUD Secret for %s", application.GetName())
	return result
}

func tunnelHostnameGuard(ctx context.Context, tunnel *unstructured.Unstructured, host, want string) (bool, error) {
	current := tunnel.DeepCopy()
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(tunnel), current); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	hostnames, found, err := unstructured.NestedSlice(current.Object, "status", "hostnames")
	if err != nil || !found {
		return false, err
	}
	for _, item := range hostnames {
		entry, ok := item.(map[string]any)
		if ok && entry["hostname"] == host && entry["guard"] == want {
			return true, nil
		}
	}
	return false, nil
}

func edgeRequestTo(ctx context.Context, host, path string, headers map[string]string) (int, http.Header, string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return 0, nil, "", fmt.Errorf("create edge request: %w", err)
	}
	request.Header.Set("User-Agent", e2eUserAgent)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return 0, nil, "", fmt.Errorf("send edge request: %w", err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, nil, "", fmt.Errorf("read edge response: %w", err)
	}
	return response.StatusCode, response.Header, string(content), nil
}

// expectAccessChallenge proves a redirect leads to the Cloudflare Access
// login flow instead of an origin-controlled location.
func expectAccessChallenge(headers http.Header, scenario string) {
	location := headers.Get("Location")
	Expect(location).NotTo(BeEmpty(), "%s must redirect to the Access login flow", scenario)
	target, err := url.Parse(location)
	Expect(err).NotTo(HaveOccurred(), "%s redirect Location must parse: %q", scenario, location)
	Expect(target.Hostname()).To(
		HaveSuffix(".cloudflareaccess.com"),
		"%s must redirect to a Cloudflare Access team domain, got %q",
		scenario,
		location,
	)
	Expect(target.Path).To(
		HavePrefix("/cdn-cgi/access/"),
		"%s must use the Access login path, got %q",
		scenario,
		location,
	)
}

func syntheticJWT(audience string) string {
	encode := base64.RawURLEncoding.EncodeToString
	header := encode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss": "https://invalid.cloudflareaccess.com", "aud": []string{audience},
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	payload := encode(claims)
	unsigned := header + "." + payload
	mac := hmac.New(sha256.New, []byte("not-a-cloudflare-signing-key"))
	_, _ = mac.Write([]byte(unsigned))
	return strings.Join([]string{header, payload, encode(mac.Sum(nil))}, ".")
}
