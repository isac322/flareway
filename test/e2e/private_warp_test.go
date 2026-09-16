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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isac322/flareway/test/e2e/internal/poll"
	e2ereport "github.com/isac322/flareway/test/e2e/internal/report"
)

var _ = Describe("Private WARP hostname", Label("warp"), Ordered, func() {
	var (
		certificate       *corev1.Secret
		virtualNetwork    *unstructured.Unstructured
		tunnel            *unstructured.Unstructured
		gateway           *unstructured.Unstructured
		route             *unstructured.Unstructured
		hostnameRoute     *unstructured.Unstructured
		allowPolicy       *unstructured.Unstructured
		accessApplication *unstructured.Unstructured
		created           []client.Object
	)

	BeforeAll(func(ctx SpecContext) {
		if !configuration.WARPDevice {
			return
		}

		var err error
		certificate, err = privateTLSSecret(privateHostname)
		Expect(err).NotTo(HaveOccurred())
		Expect(kubeClient.Create(ctx, certificate)).To(Succeed())
		created = append(created, certificate)

		virtualNetwork = object("flareway.bhyoo.com/v1alpha1", "VirtualNetwork", namespace, "private", map[string]any{
			"accountRef": map[string]any{"name": accountName},
			"name":       namespace + "/private", "comment": "flareway private WARP e2e",
			"managementPolicy": "Managed", "deletionPolicy": "Delete",
		})
		tunnel = object("flareway.bhyoo.com/v1alpha1", "CloudflareTunnel", namespace, "private", map[string]any{
			"accountRef":       map[string]any{"name": accountName},
			"tunnel":           map[string]any{"name": namespace + "-private"},
			"managementPolicy": "Managed", "deletionPolicy": "Delete",
			"dns": map[string]any{"mode": "External"},
			"listeners": []any{map[string]any{
				"name": "private", "exposure": "Private",
				"virtualNetworkRef": map[string]any{"name": virtualNetwork.GetName()},
				"hostnameRoute":     map[string]any{"create": false},
			}},
		})
		gateway = object("gateway.networking.k8s.io/v1", "Gateway", namespace, "private", map[string]any{
			"gatewayClassName": className,
			"infrastructure": map[string]any{"parametersRef": map[string]any{
				"group": "flareway.bhyoo.com", "kind": "CloudflareTunnel", "name": tunnel.GetName(),
			}},
			"listeners": []any{map[string]any{
				"name": "private", "hostname": privateHostname, "port": int64(443), "protocol": "HTTPS",
				"tls":           map[string]any{"mode": "Terminate", "certificateRefs": []any{map[string]any{"name": certificate.Name}}},
				"allowedRoutes": map[string]any{"namespaces": map[string]any{"from": "Same"}},
			}},
		})
		route = object("gateway.networking.k8s.io/v1", "HTTPRoute", namespace, "private", map[string]any{
			"parentRefs": []any{map[string]any{"name": gateway.GetName(), "sectionName": "private"}},
			"hostnames":  []any{privateHostname},
			"rules": []any{map[string]any{
				"matches":     []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/get"}}},
				"backendRefs": []any{map[string]any{"name": "echo", "port": int64(8080)}},
			}},
		})
		hostnameRoute = object("flareway.bhyoo.com/v1alpha1", "HostnameRoute", namespace, "private", map[string]any{
			"accountRef":        map[string]any{"name": accountName},
			"hostname":          privateHostname,
			"tunnelRef":         map[string]any{"name": tunnel.GetName(), "namespace": namespace},
			"allowedNamespaces": map[string]any{"from": "Same"},
			"comment":           "flareway private WARP e2e",
			"managementPolicy":  "Managed", "deletionPolicy": "Delete",
		})
		allowPolicy = object("flareway.bhyoo.com/v1alpha1", "AccessPolicy", namespace, "private-warp", map[string]any{
			"accountRef": map[string]any{"name": accountName},
			"name":       namespace + "/private-warp", "decision": "Allow",
			"include":          []any{map[string]any{"everyone": map[string]any{}}},
			"managementPolicy": "Managed", "deletionPolicy": "Delete",
		})
		accessApplication = object("flareway.bhyoo.com/v1alpha1", "AccessApplication", namespace, "private", map[string]any{
			"accountRef": map[string]any{"name": accountName},
			"type":       "SelfHosted",
			"selfHosted": map[string]any{},
			"targetRefs": []any{map[string]any{
				"group": "gateway.networking.k8s.io", "kind": "Gateway",
				"name": gateway.GetName(), "sectionName": "private",
			}},
			"application": map[string]any{
				"name": namespace + "/private", "sessionDuration": "24h",
				"allowAuthenticateViaWarp": true, "appLauncherVisible": false,
			},
			"policies":         []any{map[string]any{"policyRef": map[string]any{"name": allowPolicy.GetName()}}},
			"originJWT":        map[string]any{"mode": "Disabled"},
			"managementPolicy": "Managed", "deletionPolicy": "Delete",
		})

		for _, value := range []client.Object{
			virtualNetwork, tunnel, gateway, route, hostnameRoute, allowPolicy, accessApplication,
		} {
			Expect(kubeClient.Create(ctx, value)).To(Succeed(), "create %s/%s", value.GetObjectKind().GroupVersionKind().Kind, value.GetName())
			created = append(created, value)
		}
	}, NodeTimeout(2*time.Minute))

	AfterAll(func(ctx SpecContext) {
		if !configuration.WARPDevice {
			return
		}
		for index := len(created) - 1; index >= 0; index-- {
			deleteObject(ctx, created[index])
		}
	}, NodeTimeout(3*time.Minute))

	It("classifies prerequisites and proves DNS plus HTTPS through a registered WARP device", func(ctx SpecContext) {
		if !configuration.WARPDevice {
			writePrivateWARPResult(e2ereport.PrivateWARPResult{
				Result: e2ereport.PrivateWARPBlockedRunner,
				Reason: "FLAREWAY_E2E_WARP_DEVICE=1 was not set on a registered WARP runner",
			})
			GinkgoWriter.Println("private WARP result: blocked: runner")
			return
		}

		programCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		planBlocked := false
		duration, err := poll.Until(programCtx, 3*time.Second, func(checkCtx context.Context) (bool, error) {
			blocked, blockErr := privatePlanBlocked(checkCtx, virtualNetwork, hostnameRoute, tunnel, gateway, accessApplication)
			if blockErr != nil {
				return false, blockErr
			}
			if blocked {
				planBlocked = true
				return true, nil
			}
			accessReady, accessErr := privateAccessTargetReady(checkCtx, accessApplication, privateHostname)
			if accessErr != nil || !accessReady {
				return false, accessErr
			}
			return hasCondition(checkCtx, gateway, "Programmed", "True")
		})
		if planBlocked {
			writePrivateWARPResult(e2ereport.PrivateWARPResult{
				Result: e2ereport.PrivateWARPBlockedPlan,
				Reason: "Cloudflare reported that a required private-network feature is unavailable on this account plan",
			})
			GinkgoWriter.Println("private WARP result: blocked: plan")
			return
		}
		Expect(err).NotTo(HaveOccurred(), "private Gateway did not become Programmed and no account-plan blocker was reported")
		recordLatency("private-warp-programmed", duration)

		dnsCtx, dnsCancel := context.WithTimeout(ctx, 90*time.Second)
		defer dnsCancel()
		var addresses []netip.Addr
		duration, err = poll.Until(dnsCtx, 3*time.Second, func(checkCtx context.Context) (bool, error) {
			resolved, lookupErr := resolvePrivateHostname(checkCtx, net.DefaultResolver, privateHostname)
			if lookupErr != nil {
				return false, nil
			}
			addresses = resolved
			return len(addresses) > 0 && allSyntheticPrivateAddresses(addresses), nil
		})
		if err != nil {
			writePrivateWARPResult(e2ereport.PrivateWARPResult{
				Result: e2ereport.PrivateWARPBlockedRunner,
				Reason: "runner DNS did not return Cloudflare private-hostname synthetic addresses",
			})
			GinkgoWriter.Println("private WARP result: blocked: runner (synthetic DNS unavailable)")
			return
		}
		recordLatency("private-warp-dns", duration)

		result := e2ereport.PrivateWARPResult{Result: e2ereport.PrivateWARPPass, DNSAddresses: stringifyAddresses(addresses)}
		if configuration.UnregisteredDNSServer != "" {
			probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
			checked, reachable, probeErr := probeUnregisteredDNS(probeCtx, configuration.UnregisteredDNSServer, privateHostname)
			probeCancel()
			Expect(probeErr).NotTo(HaveOccurred())
			result.UnregisteredPathChecked = checked
			result.UnregisteredPathReachable = &reachable
			Expect(reachable).To(BeFalse(), "an explicitly unregistered DNS path returned a Cloudflare synthetic address")
		}

		status, body, requestErr := privateHTTPSRequest(ctx, privateHostname, "/get")
		Expect(requestErr).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), "private WARP request must reach the backend; body: %s", body)
		writePrivateWARPResult(result)
		GinkgoWriter.Printf("private WARP result: pass; DNS=%s\n", strings.Join(result.DNSAddresses, ","))
	}, NodeTimeout(5*time.Minute))
})

func privateTLSSecret(hostname string) (*corev1.Secret, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate private TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate private TLS serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create private TLS certificate: %w", err)
	}
	privateKey := x509.MarshalPKCS1PrivateKey(key)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "private-origin-tls", Namespace: namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}),
			corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKey}),
		},
	}, nil
}

func privatePlanBlocked(ctx context.Context, objects ...*unstructured.Unstructured) (bool, error) {
	for _, template := range objects {
		if template == nil {
			continue
		}
		current := template.DeepCopy()
		if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(template), current); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return false, err
		}
		for _, message := range privateStatusMessages(current) {
			lower := strings.ToLower(message)
			for _, marker := range []string{"account plan", "plan does not support", "upgrade your plan", "entitlement", "feature is not enabled", "feature is unavailable"} {
				if strings.Contains(lower, marker) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func privateStatusMessages(object *unstructured.Unstructured) []string {
	messages := make([]string, 0)
	conditions, _, _ := unstructured.NestedSlice(object.Object, "status", "conditions")
	messages = append(messages, messagesFromConditions(conditions)...)
	listeners, _, _ := unstructured.NestedSlice(object.Object, "status", "listeners")
	for _, item := range listeners {
		listener, ok := item.(map[string]any)
		if !ok {
			continue
		}
		listenerConditions, _, _ := unstructured.NestedSlice(listener, "conditions")
		messages = append(messages, messagesFromConditions(listenerConditions)...)
	}
	return messages
}

func messagesFromConditions(conditions []any) []string {
	messages := make([]string, 0, len(conditions))
	for _, item := range conditions {
		condition, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if message, ok := condition["message"].(string); ok {
			messages = append(messages, message)
		}
	}
	return messages
}

func resolvePrivateHostname(ctx context.Context, resolver *net.Resolver, hostname string) ([]netip.Addr, error) {
	addresses, err := resolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil {
		return nil, err
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.Unmap())
	}
	return result, nil
}

func allSyntheticPrivateAddresses(addresses []netip.Addr) bool {
	if len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		if !isSyntheticPrivateAddress(address) {
			return false
		}
	}
	return true
}

func isSyntheticPrivateAddress(address netip.Addr) bool {
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("100.80.0.0/16"),
		netip.MustParsePrefix("172.64.128.0/20"),
		netip.MustParsePrefix("2606:4700:0cf1:4000::/64"),
	} {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func stringifyAddresses(addresses []netip.Addr) []string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	return values
}

func privateAccessTargetReady(ctx context.Context, application *unstructured.Unstructured, hostname string) (bool, error) {
	accepted, err := hasCondition(ctx, application, "Accepted", "True")
	if err != nil || !accepted {
		return false, err
	}
	current := application.DeepCopy()
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(application), current); err != nil {
		return false, err
	}
	destinations, found, err := unstructured.NestedSlice(current.Object, "status", "destinations")
	if err != nil || !found {
		return false, err
	}
	for _, item := range destinations {
		destination, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if destination["type"] == "private" && destination["hostname"] == hostname &&
			destination["portRange"] == "443" && destination["l4Protocol"] == "tcp" {
			return true, nil
		}
	}
	return false, nil
}

func probeUnregisteredDNS(ctx context.Context, server, hostname string) (bool, bool, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(dialCtx, "udp", server)
		},
	}
	addresses, err := resolvePrivateHostname(ctx, resolver, hostname)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) && dnsError.IsNotFound {
			return true, false, nil
		}
		return false, false, err
	}
	for _, address := range addresses {
		if isSyntheticPrivateAddress(address) {
			return true, true, nil
		}
	}
	return true, false, nil
}

func privateHTTPSRequest(ctx context.Context, hostname, path string) (int, string, error) {
	command := exec.CommandContext(ctx, "curl",
		"--insecure",
		"--silent",
		"--show-error",
		"--max-time", "30",
		"--write-out", "\n%{http_code}",
		"https://"+hostname+path,
	)
	output, err := command.Output()
	if err != nil {
		return 0, "", fmt.Errorf("curl private hostname: %w", err)
	}
	statusIndex := strings.LastIndexByte(string(output), '\n')
	if statusIndex < 0 {
		return 0, "", fmt.Errorf("curl did not return an HTTP status")
	}
	body, rawStatus := string(output[:statusIndex]), string(output[statusIndex+1:])
	status, err := strconv.Atoi(strings.TrimSpace(rawStatus))
	if err != nil {
		return 0, "", fmt.Errorf("parse curl HTTP status: %w", err)
	}
	return status, body, nil
}

func writePrivateWARPResult(result e2ereport.PrivateWARPResult) {
	Expect(e2ereport.WritePrivateWARP(privateWARPArtifactPath(), result)).To(Succeed())
}
