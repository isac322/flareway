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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isac322/flareway/test/e2e/internal/cfapi"
	"github.com/isac322/flareway/test/e2e/internal/janitor"
	"github.com/isac322/flareway/test/e2e/internal/names"
	"github.com/isac322/flareway/test/e2e/internal/poll"
)

const (
	controllerName = "flareway.bhyoo.com/gateway-controller"
	runLabelKey    = "flareway.bhyoo.com/e2e-run"
	e2eUserAgent   = "flareway-e2e/1.0 (+https://github.com/isac322/flareway)"
)

type suiteConfig struct {
	Token                     string
	AccountID                 string
	Zone                      string
	Kubeconfig                string
	BaseURL                   string
	WARPDevice                bool
	UnregisteredDNSServer     string
	DeviceProfileKind         string
	AllowDefaultDeviceProfile bool
}

var (
	configuration   suiteConfig
	kubeClient      client.Client
	kubeClientset   kubernetes.Interface
	cloudflareAPI   *cfapi.Client
	runID           string
	namespace       string
	hostname        string
	accessHostname  string
	mixedHostname   string
	privateHostname string
	accountName     string
	className       string
	classConfig     string
	latencies       = map[string]time.Duration{}
)

func TestE2E(t *testing.T) {
	configuration = suiteConfig{
		Token:                     os.Getenv("FLAREWAY_E2E_CF_API_TOKEN"),
		AccountID:                 os.Getenv("FLAREWAY_E2E_CF_ACCOUNT_ID"),
		Zone:                      strings.Trim(os.Getenv("FLAREWAY_E2E_ZONE"), "."),
		Kubeconfig:                os.Getenv("FLAREWAY_E2E_KUBECONFIG"),
		BaseURL:                   os.Getenv("FLAREWAY_E2E_CF_BASE_URL"),
		WARPDevice:                os.Getenv("FLAREWAY_E2E_WARP_DEVICE") == "1",
		UnregisteredDNSServer:     os.Getenv("FLAREWAY_E2E_WARP_UNREGISTERED_DNS_SERVER"),
		DeviceProfileKind:         os.Getenv("FLAREWAY_E2E_DEVICE_PROFILE_KIND"),
		AllowDefaultDeviceProfile: os.Getenv("FLAREWAY_E2E_ALLOW_DEFAULT_PROFILE") == "1",
	}
	if configuration.DeviceProfileKind == "" {
		configuration.DeviceProfileKind = "Custom"
	}
	missing := make([]string, 0, 3)
	for key, value := range map[string]string{
		"FLAREWAY_E2E_CF_API_TOKEN":  configuration.Token,
		"FLAREWAY_E2E_CF_ACCOUNT_ID": configuration.AccountID,
		"FLAREWAY_E2E_ZONE":          configuration.Zone,
	} {
		if value == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		t.Skipf("Cloudflare e2e skipped: missing %s", strings.Join(missing, ", "))
	}

	RegisterFailHandler(Fail)
	RunSpecs(t, "Flareway Cloudflare E2E Suite")
}

var _ = BeforeSuite(func(ctx SpecContext) {
	var err error
	runID, err = names.NewRunID()
	Expect(err).NotTo(HaveOccurred())
	namespace = names.Namespace(runID)
	hostname = names.Hostname(runID, 1, configuration.Zone)
	accountName = names.Resource(runID, "account")
	accessHostname = names.Hostname(runID, 2, configuration.Zone)
	mixedHostname = names.Hostname(runID, 3, configuration.Zone)
	privateHostname = fmt.Sprintf("private-%s.flareway.internal", runID)
	className = names.Resource(runID, "class")
	classConfig = names.Resource(runID, "class-config")

	restConfig, err := clientcmd.BuildConfigFromFlags("", configuration.Kubeconfig)
	Expect(err).NotTo(HaveOccurred(), "load kubeconfig")
	scheme := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	kubeClient, err = client.New(restConfig, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred(), "create Kubernetes client")
	kubeClientset, err = kubernetes.NewForConfig(restConfig)
	Expect(err).NotTo(HaveOccurred(), "create Kubernetes clientset")

	cloudflareAPI = cfapi.New(configuration.Token, configuration.AccountID, configuration.BaseURL)
	Expect(cloudflareAPI.ResolveZone(ctx, configuration.Zone)).To(Succeed())
	Expect(createSuiteFixtures(ctx)).To(Succeed())
}, NodeTimeout(5*time.Minute))

var _ = AfterSuite(func(ctx SpecContext) {
	defer writeLatencies()
	if kubeClient == nil || namespace == "" {
		return
	}
	deleteObject(ctx, object("gateway.networking.k8s.io/v1", "GatewayClass", "", className, nil))
	deleteObject(ctx, object("flareway.bhyoo.com/v1alpha1", "GatewayClassConfig", "", classConfig, nil))
	deleteObject(ctx, object("flareway.bhyoo.com/v1alpha1", "CloudflareAccount", "", accountName, nil))
	deleteObject(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	_, _ = poll.Until(waitCtx, 5*time.Second, func(checkCtx context.Context) (bool, error) {
		current := &corev1.Namespace{}
		err := kubeClient.Get(checkCtx, types.NamespacedName{Name: namespace}, current)
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	})
	if cloudflareAPI != nil {
		report, err := janitor.SweepPrefix(ctx, cloudflareAPI, namespace, 0, time.Now().UTC())
		Expect(err).NotTo(HaveOccurred())
		GinkgoWriter.Printf("e2e janitor deleted Access applications=%d policies=%d service tokens=%d hostname routes=%d network routes=%d virtual networks=%d DNS records=%d tunnels=%d; connected skipped=%d\n", report.AccessApplicationsDeleted, report.AccessPoliciesDeleted, report.ServiceTokensDeleted, report.HostnameRoutesDeleted, report.NetworkRoutesDeleted, report.VirtualNetworksDeleted, report.DNSRecordsDeleted, report.TunnelsDeleted, report.ConnectedSkipped)
	}
}, NodeTimeout(7*time.Minute))

func createSuiteFixtures(ctx context.Context) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: namespace,
		Labels: map[string]string{
			runLabelKey: runID,
			"flareway.bhyoo.com/allow-origin-jwt-disable": "true",
		},
	}}
	if err := kubeClient.Create(ctx, ns); err != nil {
		return fmt.Errorf("create namespace: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cloudflare-api-token", Namespace: namespace},
		StringData: map[string]string{"api-token": configuration.Token},
	}
	if err := kubeClient.Create(ctx, secret); err != nil {
		return fmt.Errorf("create Cloudflare API token Secret: %w", err)
	}

	account := object("flareway.bhyoo.com/v1alpha1", "CloudflareAccount", "", accountName, map[string]any{
		"accountId": configuration.AccountID,
		"credentials": map[string]any{"apiTokenSecretRef": map[string]any{
			"name": "cloudflare-api-token", "namespace": namespace, "key": "api-token",
		}},
		"grants": []any{map[string]any{
			"namespaceSelector": map[string]any{"matchLabels": map[string]any{runLabelKey: runID}},
			"hostnames":         []any{hostname, accessHostname, mixedHostname, privateHostname},
			"zones":             []any{configuration.Zone}, "exposures": []any{"Public", "Private"},
			"unprotectedHostnames": []any{hostname, mixedHostname},
			"privateRoutes": map[string]any{
				"networkRouteSelector":  map[string]any{},
				"hostnameRouteSelector": map[string]any{},
			},
			"backends":         map[string]any{"namespaces": "Same", "kinds": []any{"Service"}},
			"accessPolicyRefs": "Allowed", "platformObjects": "Allowed",
		}},
	})
	if err := kubeClient.Create(ctx, account); err != nil {
		return fmt.Errorf("create CloudflareAccount: %w", err)
	}

	gatewayClassConfig := object("flareway.bhyoo.com/v1alpha1", "GatewayClassConfig", "", classConfig, map[string]any{
		"accountRef": map[string]any{"name": accountName},
		"dns":        map[string]any{"mode": "Managed"},
	})
	if err := kubeClient.Create(ctx, gatewayClassConfig); err != nil {
		return fmt.Errorf("create GatewayClassConfig: %w", err)
	}
	gatewayClass := object("gateway.networking.k8s.io/v1", "GatewayClass", "", className, map[string]any{
		"controllerName": controllerName,
		"parametersRef": map[string]any{
			"group": "flareway.bhyoo.com", "kind": "GatewayClassConfig", "name": classConfig,
		},
	})
	if err := kubeClient.Create(ctx, gatewayClass); err != nil {
		return fmt.Errorf("create GatewayClass: %w", err)
	}
	if err := createBackend(ctx); err != nil {
		return err
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	_, err := poll.Until(waitCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
		return hasCondition(checkCtx, account, "Accepted", "True")
	})
	if err != nil {
		return fmt.Errorf("wait for CloudflareAccount acceptance: %w", err)
	}
	_, err = poll.Until(waitCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
		return hasCondition(checkCtx, gatewayClass, "Accepted", "True")
	})
	if err != nil {
		return fmt.Errorf("wait for GatewayClass acceptance: %w", err)
	}
	return nil
}

func createBackend(ctx context.Context) error {
	labels := map[string]string{"app": "echo", runLabelKey: runID}
	one := int32(1)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "echo", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "echo", Image: "registry.k8s.io/e2e-test-images/agnhost:2.53",
					Args:  []string{"netexec", "--http-port=8080"},
					Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
					ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
						Path: "/healthz", Port: intstr.FromString("http"),
					}}},
				}}},
			},
		},
	}
	if err := kubeClient.Create(ctx, deployment); err != nil {
		return fmt.Errorf("create echo Deployment: %w", err)
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo", Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports:    []corev1.ServicePort{{Name: "http", Port: 8080, TargetPort: intstr.FromString("http")}},
		},
	}
	if err := kubeClient.Create(ctx, service); err != nil {
		return fmt.Errorf("create echo Service: %w", err)
	}
	return nil
}

func hasCondition(ctx context.Context, template *unstructured.Unstructured, conditionType, status string) (bool, error) {
	current := template.DeepCopy()
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(template), current); err != nil {
		return false, err
	}
	conditions, found, err := unstructured.NestedSlice(current.Object, "status", "conditions")
	if err != nil || !found {
		return false, err
	}
	for _, item := range conditions {
		condition, ok := item.(map[string]any)
		if ok && condition["type"] == conditionType && condition["status"] == status {
			return true, nil
		}
	}
	return false, nil
}

func conditionSummary(template *unstructured.Unstructured) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	current := template.DeepCopy()
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(template), current); err != nil {
		return fmt.Sprintf("get %s/%s: %v", template.GetKind(), client.ObjectKeyFromObject(template), err)
	}
	conditions, found, err := unstructured.NestedSlice(current.Object, "status", "conditions")
	if err != nil {
		return fmt.Sprintf("read %s/%s conditions: %v", template.GetKind(), client.ObjectKeyFromObject(template), err)
	}
	if !found {
		return "conditions are absent"
	}
	payload, err := json.Marshal(conditions)
	if err != nil {
		return fmt.Sprintf("encode conditions: %v", err)
	}
	return string(payload)
}

func dataplaneDiagnostics() string {
	if kubeClientset == nil || namespace == "" {
		return "Kubernetes clientset or E2E namespace is unavailable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pods, err := kubeClientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Sprintf("list dataplane Pods: %v", err)
	}
	var summary strings.Builder
	for index := range pods.Items {
		pod := &pods.Items[index]
		fmt.Fprintf(&summary, "Pod %s phase=%s conditions=%v containerStatuses=%v\n", pod.Name, pod.Status.Phase, pod.Status.Conditions, pod.Status.ContainerStatuses)
		for _, container := range pod.Spec.Containers {
			if container.Name != "cloudflared" && container.Name != "envoy" {
				continue
			}
			tailLines := int64(80)
			logs, logErr := kubeClientset.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
				Container: container.Name,
				TailLines: &tailLines,
			}).DoRaw(ctx)
			if logErr != nil {
				fmt.Fprintf(&summary, "  %s logs: %v\n", container.Name, logErr)
				continue
			}
			fmt.Fprintf(&summary, "  %s logs:\n%s\n", container.Name, logs)
		}
	}
	return summary.String()
}

func object(apiVersion, kind, objectNamespace, name string, spec map[string]any) *unstructured.Unstructured {
	value := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name": name,
		},
	}}
	if objectNamespace != "" {
		value.SetNamespace(objectNamespace)
	}
	if spec != nil {
		value.Object["spec"] = spec
	}
	return value
}

func deleteObject(ctx context.Context, value client.Object) {
	if value == nil {
		return
	}
	err := kubeClient.Delete(ctx, value)
	if err != nil && !apierrors.IsNotFound(err) {
		GinkgoWriter.Printf("cleanup %T %s: %v\n", value, client.ObjectKeyFromObject(value), err)
	}
}

func recordLatency(name string, duration time.Duration) {
	latencies[name] = duration
}

func writeLatencies() {
	if len(latencies) == 0 {
		return
	}
	values := make(map[string]string, len(latencies))
	for key, value := range latencies {
		values[key] = value.String()
	}
	content, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		GinkgoWriter.Printf("encode e2e latency artifact: %v\n", err)
		return
	}
	artifactDir := filepath.Join("..", "..", "artifacts")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		GinkgoWriter.Printf("create e2e artifacts directory: %v\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "e2e-latency.json"), append(content, '\n'), 0o644); err != nil {
		GinkgoWriter.Printf("write e2e latency artifact: %v\n", err)
	}
}

func privateWARPArtifactPath() string {
	return filepath.Join("..", "..", "artifacts", "e2e-private-warp.json")
}
