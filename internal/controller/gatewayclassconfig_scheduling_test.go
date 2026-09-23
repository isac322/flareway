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

package controller

import (
	"fmt"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
)

// schedulingGWCC builds a GatewayClassConfig as unstructured so tests can
// express explicit nulls and omitted fields that typed Go structs cannot.
func schedulingGWCC(name string, scheduling map[string]any) *unstructured.Unstructured {
	spec := map[string]any{"conformanceMode": true}
	if scheduling != nil {
		spec["scheduling"] = scheduling
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(),
		"kind":       "GatewayClassConfig",
		"metadata":   map[string]any{"name": name},
		"spec":       spec,
	}}
}

// schedulingDeployment builds an apps/v1 Deployment whose pod template carries
// the scheduling fields verbatim, mirroring what the dataplane builder emits.
func schedulingDeployment(namespace, name string, scheduling map[string]any) *unstructured.Unstructured {
	podSpec := map[string]any{
		"containers": []any{map[string]any{"name": "envoy", "image": "envoyproxy/envoy:distroless-v1.39.1"}},
	}
	for key, value := range scheduling {
		podSpec[key] = value
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{"app": "scheduling-probe"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "scheduling-probe"}},
				"spec":     podSpec,
			},
		},
	}}
}

// deploymentExpectation selects the Deployment-admission parity check applied
// to a GatewayClassConfig scheduling row.
type deploymentExpectation int

const (
	// deploySkip performs no Deployment dry-run (null/empty scheduling rows).
	deploySkip deploymentExpectation = iota
	// deployAccept asserts Deployment admission accepts the same fields.
	deployAccept
	// deployReject asserts Deployment admission rejects the same fields; used
	// for validation intentionally deferred from the CRD to the dataplane's
	// real admission path.
	deployReject
)

func tolerationEntries(count int) []any {
	tolerations := make([]any, 0, count)
	for i := 0; i < count; i++ {
		tolerations = append(tolerations, map[string]any{"key": fmt.Sprintf("key-%02d", i), "operator": "Exists"})
	}
	return tolerations
}

func nodeSelectorEntries(count int) map[string]any {
	selector := make(map[string]any, count)
	for i := 0; i < count; i++ {
		selector[fmt.Sprintf("pool-%02d", i)] = "x"
	}
	return selector
}

func topologySpreadEntries(count int) []any {
	constraints := make([]any, 0, count)
	for i := 0; i < count; i++ {
		constraints = append(constraints, map[string]any{
			"maxSkew":           int64(1),
			"topologyKey":       fmt.Sprintf("topology.example.io/domain-%02d", i),
			"whenUnsatisfiable": "ScheduleAnyway",
		})
	}
	return constraints
}

var _ = ginkgo.Describe("GatewayClassConfig scheduling admission", ginkgo.Ordered, func() {
	var admissionNamespace string

	ginkgo.BeforeAll(func() {
		admissionNamespace = fmt.Sprintf("sched-admission-%d", fixtureCounter.Add(1))
		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: admissionNamespace}})).To(gomega.Succeed())
	})

	ginkgo.AfterAll(func() {
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: admissionNamespace}}))).To(gomega.Succeed())
	})

	// Each row creates a GatewayClassConfig carrying spec.scheduling. Accepted
	// rows may additionally dry-run a Deployment carrying the same fields to
	// prove the CRD never accepts what the dataplane's real admission path
	// rejects (or, for deferred rows, that Deployment admission is the
	// documented backstop).
	ginkgo.DescribeTable("validates spec.scheduling",
		func(scheduling map[string]any, errSubstrings []string, deploy deploymentExpectation) {
			name := fmt.Sprintf("sched-adm-%d", fixtureCounter.Add(1))
			config := schedulingGWCC(name, scheduling)
			err := testClient.Create(testContext, config)
			if len(errSubstrings) == 0 {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				ginkgo.DeferCleanup(func() {
					gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, config))).To(gomega.Succeed())
				})
			} else {
				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(apierrors.IsInvalid(err)).To(gomega.BeTrue(), "expected an Invalid rejection, got %v", err)
				for _, substring := range errSubstrings {
					gomega.Expect(err.Error()).To(gomega.ContainSubstring(substring))
				}
				return
			}

			if deploy == deploySkip {
				return
			}
			deployment := schedulingDeployment(admissionNamespace, name, scheduling)
			deployErr := testClient.Create(testContext, deployment, client.DryRunAll)
			if deploy == deployAccept {
				gomega.Expect(deployErr).NotTo(gomega.HaveOccurred())
			} else {
				gomega.Expect(deployErr).To(gomega.HaveOccurred())
				gomega.Expect(apierrors.IsInvalid(deployErr)).To(gomega.BeTrue(), "expected an Invalid rejection, got %v", deployErr)
			}
		},

		// Toleration accept rows.
		ginkgo.Entry("accepts a full Equal toleration",
			map[string]any{"tolerations": []any{map[string]any{"key": "dedicated", "operator": "Equal", "value": "edge", "effect": "NoSchedule"}}},
			nil, deployAccept),
		ginkgo.Entry("accepts an Exists toleration",
			map[string]any{"tolerations": []any{map[string]any{"key": "dedicated", "operator": "Exists", "effect": "NoSchedule"}}},
			nil, deployAccept),
		ginkgo.Entry("accepts an empty-key Exists toleration",
			map[string]any{"tolerations": []any{map[string]any{"operator": "Exists"}}},
			nil, deployAccept),
		ginkgo.Entry("accepts a toleration without effect",
			map[string]any{"tolerations": []any{map[string]any{"key": "dedicated", "operator": "Exists"}}},
			nil, deployAccept),
		ginkgo.Entry("accepts a toleration without operator",
			map[string]any{"tolerations": []any{map[string]any{"key": "dedicated", "value": "edge"}}},
			nil, deployAccept),
		ginkgo.Entry("accepts an Equal toleration with empty value",
			map[string]any{"tolerations": []any{map[string]any{"key": "dedicated", "operator": "Equal", "value": ""}}},
			nil, deployAccept),
		ginkgo.Entry("accepts a NoExecute toleration with seconds",
			map[string]any{"tolerations": []any{map[string]any{"key": "dedicated", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": int64(30)}}},
			nil, deployAccept),
		ginkgo.Entry("accepts a NoExecute toleration with negative seconds",
			map[string]any{"tolerations": []any{map[string]any{"key": "dedicated", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": int64(-1)}}},
			nil, deployAccept),
		ginkgo.Entry("accepts a NoExecute toleration without seconds",
			map[string]any{"tolerations": []any{map[string]any{"key": "dedicated", "operator": "Exists", "effect": "NoExecute"}}},
			nil, deployAccept),
		ginkgo.Entry("accepts explicit null tolerations",
			map[string]any{"tolerations": nil},
			nil, deploySkip),

		// Toleration reject rows.
		ginkgo.Entry("rejects an Exists toleration with a value",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Exists", "value": "v"}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),
		ginkgo.Entry("rejects an Equal toleration without a key",
			map[string]any{"tolerations": []any{map[string]any{"operator": "Equal", "value": "v"}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),
		ginkgo.Entry("rejects tolerationSeconds without an effect",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "tolerationSeconds": int64(30)}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),
		ginkgo.Entry("rejects tolerationSeconds with NoSchedule",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Exists", "effect": "NoSchedule", "tolerationSeconds": int64(30)}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),
		ginkgo.Entry("rejects tolerationSeconds with PreferNoSchedule",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Exists", "effect": "PreferNoSchedule", "tolerationSeconds": int64(30)}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),
		ginkgo.Entry("rejects tolerationSeconds with effect omitted",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Exists", "tolerationSeconds": int64(30)}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),
		ginkgo.Entry("rejects an unknown toleration operator",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Bogus"}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),
		ginkgo.Entry("rejects an unknown toleration effect",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Exists", "effect": "Bogus"}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),
		ginkgo.Entry("rejects the Lt toleration operator",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Lt", "value": "5"}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),
		ginkgo.Entry("rejects the Gt toleration operator",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Gt", "value": "5"}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),

		// Empty-string operator/effect boundary: the Pod API treats "" as
		// Equal and as all effects, so the CRD must match.
		ginkgo.Entry("accepts an empty-string toleration operator",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "", "value": "v"}}},
			nil, deployAccept),
		ginkgo.Entry("accepts an empty-string toleration effect",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Exists", "effect": ""}}},
			nil, deployAccept),
		ginkgo.Entry("rejects tolerationSeconds with an empty-string effect",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Exists", "effect": "", "tolerationSeconds": int64(30)}}},
			[]string{"tolerations must be valid pod tolerations"}, deploySkip),

		// TopologySpreadConstraint accept rows.
		ginkgo.Entry("accepts a ScheduleAnyway spread constraint",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
				"labelSelector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts a DoNotSchedule spread constraint with minDomains",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "DoNotSchedule", "minDomains": int64(3),
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts a DoNotSchedule spread constraint without minDomains",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "DoNotSchedule",
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts Honor nodeAffinityPolicy with Ignore nodeTaintsPolicy",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
				"nodeAffinityPolicy": "Honor", "nodeTaintsPolicy": "Ignore",
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts Ignore nodeAffinityPolicy with Honor nodeTaintsPolicy",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
				"nodeAffinityPolicy": "Ignore", "nodeTaintsPolicy": "Honor",
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts matchLabelKeys with a non-overlapping labelSelector",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
				"labelSelector":  map[string]any{"matchLabels": map[string]any{"app": "x"}},
				"matchLabelKeys": []any{"pod-template-hash"},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts empty matchLabelKeys without a labelSelector",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
				"matchLabelKeys": []any{},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts matchLabelKeys overlapping labelSelector matchExpressions",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
				"labelSelector": map[string]any{"matchExpressions": []any{map[string]any{
					"key": "pod-template-hash", "operator": "In", "values": []any{"abc"},
				}}},
				"matchLabelKeys": []any{"pod-template-hash"},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts explicit null topologySpreadConstraints",
			map[string]any{"topologySpreadConstraints": nil},
			nil, deploySkip),

		// TopologySpreadConstraint reject rows.
		ginkgo.Entry("rejects maxSkew zero",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(0), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects negative maxSkew",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(-1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects an empty topologyKey",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "", "whenUnsatisfiable": "ScheduleAnyway",
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects a missing whenUnsatisfiable",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname",
			}}},
			[]string{"Required value"}, deploySkip),
		ginkgo.Entry("rejects an unknown whenUnsatisfiable",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "Bogus",
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects zero minDomains with DoNotSchedule",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "DoNotSchedule", "minDomains": int64(0),
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects negative minDomains with DoNotSchedule",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "DoNotSchedule", "minDomains": int64(-1),
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects minDomains with ScheduleAnyway",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway", "minDomains": int64(3),
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects an unknown nodeAffinityPolicy",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway", "nodeAffinityPolicy": "Bogus",
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects an unknown nodeTaintsPolicy",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway", "nodeTaintsPolicy": "Bogus",
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects matchLabelKeys without a labelSelector",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
				"matchLabelKeys": []any{"pod-template-hash"},
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),
		ginkgo.Entry("rejects matchLabelKeys overlapping labelSelector matchLabels",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
				"labelSelector":  map[string]any{"matchLabels": map[string]any{"pod-template-hash": "abc"}},
				"matchLabelKeys": []any{"pod-template-hash"},
			}}},
			[]string{"topologySpreadConstraints must be valid pod topology spread constraints"}, deploySkip),

		// Affinity accept rows.
		ginkgo.Entry("accepts an empty affinity",
			map[string]any{"affinity": map[string]any{}},
			nil, deployAccept),
		ginkgo.Entry("accepts required node affinity",
			map[string]any{"affinity": map[string]any{"nodeAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": map[string]any{"nodeSelectorTerms": []any{map[string]any{
					"matchExpressions": []any{map[string]any{"key": "kubernetes.io/os", "operator": "In", "values": []any{"linux"}}},
				}}},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts node affinity preferred weight 1",
			map[string]any{"affinity": map[string]any{"nodeAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(1), "preference": map[string]any{},
				}},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts node affinity preferred weight 100",
			map[string]any{"affinity": map[string]any{"nodeAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(100), "preference": map[string]any{},
				}},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts required pod affinity and anti-affinity terms",
			map[string]any{"affinity": map[string]any{
				"podAffinity": map[string]any{"requiredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"topologyKey":   "kubernetes.io/hostname",
					"labelSelector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
				}}},
				"podAntiAffinity": map[string]any{"requiredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"topologyKey":   "topology.kubernetes.io/zone",
					"labelSelector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
				}}},
			}},
			nil, deployAccept),
		ginkgo.Entry("accepts pod anti-affinity preferred weight 1",
			map[string]any{"affinity": map[string]any{"podAntiAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(1), "podAffinityTerm": map[string]any{"topologyKey": "kubernetes.io/hostname"},
				}},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts pod anti-affinity preferred weight 100",
			map[string]any{"affinity": map[string]any{"podAntiAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(100), "podAffinityTerm": map[string]any{"topologyKey": "kubernetes.io/hostname"},
				}},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts matchLabelKeys and mismatchLabelKeys with a labelSelector",
			map[string]any{"affinity": map[string]any{"podAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"topologyKey":       "kubernetes.io/hostname",
					"labelSelector":     map[string]any{"matchLabels": map[string]any{"app": "x"}},
					"matchLabelKeys":    []any{"pod-template-hash"},
					"mismatchLabelKeys": []any{"revision"},
				}},
			}}},
			nil, deployAccept),
		ginkgo.Entry("accepts an empty podAntiAffinity opt-out",
			map[string]any{"affinity": map[string]any{"podAntiAffinity": map[string]any{}}},
			nil, deployAccept),
		ginkgo.Entry("accepts explicit null affinity",
			map[string]any{"affinity": nil},
			nil, deploySkip),

		// Affinity reject rows.
		ginkgo.Entry("rejects empty required nodeSelectorTerms",
			map[string]any{"affinity": map[string]any{"nodeAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": map[string]any{"nodeSelectorTerms": []any{}},
			}}},
			[]string{"requiredDuringSchedulingIgnoredDuringExecution must have at least one nodeSelectorTerm"}, deploySkip),
		ginkgo.Entry("rejects node affinity preferred weight 0",
			map[string]any{"affinity": map[string]any{"nodeAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(0), "preference": map[string]any{},
				}},
			}}},
			[]string{"nodeAffinity preferred term weights must be in the range 1-100"}, deploySkip),
		ginkgo.Entry("rejects node affinity preferred weight 101",
			map[string]any{"affinity": map[string]any{"nodeAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(101), "preference": map[string]any{},
				}},
			}}},
			[]string{"nodeAffinity preferred term weights must be in the range 1-100"}, deploySkip),
		ginkgo.Entry("rejects pod affinity preferred weight 0",
			map[string]any{"affinity": map[string]any{"podAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(0), "podAffinityTerm": map[string]any{"topologyKey": "kubernetes.io/hostname"},
				}},
			}}},
			[]string{"podAffinity terms must be valid pod affinity terms"}, deploySkip),
		ginkgo.Entry("rejects pod affinity preferred weight 101",
			map[string]any{"affinity": map[string]any{"podAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(101), "podAffinityTerm": map[string]any{"topologyKey": "kubernetes.io/hostname"},
				}},
			}}},
			[]string{"podAffinity terms must be valid pod affinity terms"}, deploySkip),
		ginkgo.Entry("rejects pod anti-affinity preferred weight 0",
			map[string]any{"affinity": map[string]any{"podAntiAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(0), "podAffinityTerm": map[string]any{"topologyKey": "kubernetes.io/hostname"},
				}},
			}}},
			[]string{"podAntiAffinity terms must be valid pod affinity terms"}, deploySkip),
		ginkgo.Entry("rejects pod anti-affinity preferred weight 101",
			map[string]any{"affinity": map[string]any{"podAntiAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(101), "podAffinityTerm": map[string]any{"topologyKey": "kubernetes.io/hostname"},
				}},
			}}},
			[]string{"podAntiAffinity terms must be valid pod affinity terms"}, deploySkip),
		ginkgo.Entry("rejects an empty topologyKey in required pod affinity",
			map[string]any{"affinity": map[string]any{"podAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{"topologyKey": ""}},
			}}},
			[]string{"podAffinity terms must be valid pod affinity terms"}, deploySkip),
		ginkgo.Entry("rejects an empty topologyKey in required pod anti-affinity",
			map[string]any{"affinity": map[string]any{"podAntiAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{"topologyKey": ""}},
			}}},
			[]string{"podAntiAffinity terms must be valid pod affinity terms"}, deploySkip),
		ginkgo.Entry("rejects an empty topologyKey in a preferred podAffinityTerm",
			map[string]any{"affinity": map[string]any{"podAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(50), "podAffinityTerm": map[string]any{"topologyKey": ""},
				}},
			}}},
			[]string{"podAffinity terms must be valid pod affinity terms"}, deploySkip),
		ginkgo.Entry("rejects pod affinity matchLabelKeys without a labelSelector",
			map[string]any{"affinity": map[string]any{"podAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"topologyKey": "kubernetes.io/hostname", "matchLabelKeys": []any{"pod-template-hash"},
				}},
			}}},
			[]string{"podAffinity terms must be valid pod affinity terms"}, deploySkip),
		ginkgo.Entry("rejects pod anti-affinity preferred matchLabelKeys without a labelSelector",
			map[string]any{"affinity": map[string]any{"podAntiAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"weight": int64(50),
					"podAffinityTerm": map[string]any{
						"topologyKey": "kubernetes.io/hostname", "matchLabelKeys": []any{"pod-template-hash"},
					},
				}},
			}}},
			[]string{"podAntiAffinity terms must be valid pod affinity terms"}, deploySkip),
		ginkgo.Entry("rejects pod anti-affinity mismatchLabelKeys without a labelSelector",
			map[string]any{"affinity": map[string]any{"podAntiAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"topologyKey": "kubernetes.io/hostname", "mismatchLabelKeys": []any{"revision"},
				}},
			}}},
			[]string{"podAntiAffinity terms must be valid pod affinity terms"}, deploySkip),

		// MaxProperties/MaxItems bounds.
		ginkgo.Entry("accepts 64 nodeSelector entries",
			map[string]any{"nodeSelector": nodeSelectorEntries(64)},
			nil, deployAccept),
		ginkgo.Entry("rejects 65 nodeSelector entries",
			map[string]any{"nodeSelector": nodeSelectorEntries(65)},
			[]string{"Too many"}, deploySkip),
		ginkgo.Entry("accepts 16 tolerations",
			map[string]any{"tolerations": tolerationEntries(16)},
			nil, deployAccept),
		ginkgo.Entry("rejects 17 tolerations",
			map[string]any{"tolerations": tolerationEntries(17)},
			[]string{"Too many"}, deploySkip),
		ginkgo.Entry("accepts 8 topologySpreadConstraints",
			map[string]any{"topologySpreadConstraints": topologySpreadEntries(8)},
			nil, deployAccept),
		ginkgo.Entry("rejects 9 topologySpreadConstraints",
			map[string]any{"topologySpreadConstraints": topologySpreadEntries(9)},
			[]string{"Too many"}, deploySkip),

		// Deferred-validation boundary: the CRD accepts these rows and
		// Deployment admission is the documented backstop that rejects them.
		ginkgo.Entry("defers an invalid nodeSelector key to Deployment admission",
			map[string]any{"nodeSelector": map[string]any{"bad key!": "linux"}},
			nil, deployReject),
		ginkgo.Entry("defers an invalid nodeSelector value to Deployment admission",
			map[string]any{"nodeSelector": map[string]any{"pool": "bad value!"}},
			nil, deployReject),
		ginkgo.Entry("defers an invalid toleration value to Deployment admission",
			map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Equal", "value": "bad value!"}}},
			nil, deployReject),
		ginkgo.Entry("defers an invalid toleration key to Deployment admission",
			map[string]any{"tolerations": []any{map[string]any{"key": "bad key!", "operator": "Exists"}}},
			nil, deployReject),
		ginkgo.Entry("defers an invalid matchLabelKeys key to Deployment admission",
			map[string]any{"topologySpreadConstraints": []any{map[string]any{
				"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
				"labelSelector":  map[string]any{"matchLabels": map[string]any{"app": "x"}},
				"matchLabelKeys": []any{"bad key!"},
			}}},
			nil, deployReject),
		ginkgo.Entry("defers an invalid podAffinityTerm namespace to Deployment admission",
			map[string]any{"affinity": map[string]any{"podAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"topologyKey":   "kubernetes.io/hostname",
					"labelSelector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
					"namespaces":    []any{"bad ns!"},
				}},
			}}},
			nil, deployReject),
		ginkgo.Entry("defers an In requirement with no values to Deployment admission",
			map[string]any{"affinity": map[string]any{"nodeAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": map[string]any{"nodeSelectorTerms": []any{map[string]any{
					"matchExpressions": []any{map[string]any{"key": "kubernetes.io/os", "operator": "In", "values": []any{}}},
				}}},
			}}},
			nil, deployReject),
		ginkgo.Entry("defers a Gt requirement with two values to Deployment admission",
			map[string]any{"affinity": map[string]any{"nodeAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": map[string]any{"nodeSelectorTerms": []any{map[string]any{
					"matchExpressions": []any{map[string]any{"key": "kubernetes.io/os", "operator": "Gt", "values": []any{"1", "2"}}},
				}}},
			}}},
			nil, deployReject),
		ginkgo.Entry("accepts an empty nodeSelectorTerm like Deployment admission does",
			map[string]any{"affinity": map[string]any{"nodeAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": map[string]any{"nodeSelectorTerms": []any{map[string]any{}}},
			}}},
			nil, deployAccept),
		ginkgo.Entry("defers an invalid pod affinity topologyKey to Deployment admission",
			map[string]any{"affinity": map[string]any{"podAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": []any{map[string]any{
					"topologyKey":   "bad key!",
					"labelSelector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
				}},
			}}},
			nil, deployReject),
	)

	ginkgo.It("rejects duplicate topologySpreadConstraints list-map keys on create and apply", func() {
		duplicate := map[string]any{"topologySpreadConstraints": []any{
			map[string]any{"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway"},
			map[string]any{"maxSkew": int64(2), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway"},
		}}

		name := fmt.Sprintf("sched-dup-%d", fixtureCounter.Add(1))
		err := testClient.Create(testContext, schedulingGWCC(name, duplicate))
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(apierrors.IsInvalid(err)).To(gomega.BeTrue(), "expected an Invalid rejection, got %v", err)
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("Duplicate value"))

		applyErr := testClient.Apply(testContext,
			client.ApplyConfigurationFromUnstructured(schedulingGWCC(name+"-ssa", duplicate)),
			client.FieldOwner("flareway-scheduling-test"))
		gomega.Expect(applyErr).To(gomega.HaveOccurred())
		gomega.Expect(applyErr.Error()).To(gomega.ContainSubstring("duplicate entries for key"))

		distinct := schedulingGWCC(name+"-distinct", map[string]any{"topologySpreadConstraints": []any{
			map[string]any{"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway"},
			map[string]any{"maxSkew": int64(1), "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "DoNotSchedule"},
		}})
		gomega.Expect(testClient.Create(testContext, distinct)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, distinct))).To(gomega.Succeed())
		})
	})

	ginkgo.It("keeps a pre-existing GatewayClassConfig valid and defaults scheduling to an empty object", func() {
		name := fmt.Sprintf("sched-upgrade-%d", fixtureCounter.Add(1))
		config := conformanceConfig(name, corev1.ServiceTypeClusterIP)
		gomega.Expect(testClient.Create(testContext, config)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, config))).To(gomega.Succeed())
		})

		stored := &unstructured.Unstructured{}
		stored.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("GatewayClassConfig"))
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: name}, stored)).To(gomega.Succeed())
		scheduling, found, err := unstructured.NestedMap(stored.Object, "spec", "scheduling")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(found).To(gomega.BeTrue(), "spec.scheduling should be defaulted on the stored object")
		gomega.Expect(scheduling).To(gomega.BeEmpty())

		var current v1alpha1.GatewayClassConfig
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: name}, &current)).To(gomega.Succeed())
		current.Labels = map[string]string{"flareway.bhyoo.com/scheduling-upgrade": "true"}
		gomega.Expect(testClient.Update(testContext, &current)).To(gomega.Succeed())
	})
})

var _ = ginkgo.Describe("GatewayClassConfig scheduling propagation", ginkgo.Ordered, func() {
	var namespaceName string
	var configName string
	var className string
	var gatewayKey types.NamespacedName
	var dataplaneKey types.NamespacedName

	ginkgo.BeforeAll(func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName = fmt.Sprintf("sched-envtest-%d", fixtureID)
		configName = fmt.Sprintf("conformance-sched-%d", fixtureID)
		className = fmt.Sprintf("flareway-sched-%d", fixtureID)
		gatewayKey = types.NamespacedName{Namespace: namespaceName, Name: "gateway"}
		dataplaneKey = types.NamespacedName{
			Namespace: namespaceName,
			Name:      dataplane.ResourceName(&ir.Gateway{Key: gatewayKey}),
		}

		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}})).To(gomega.Or(gomega.Succeed(), gomega.MatchError(gomega.ContainSubstring("already exists"))))
		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}})).To(gomega.Succeed())

		config := conformanceConfig(configName, corev1.ServiceTypeClusterIP)
		config.Spec.Scheduling = v1alpha1.DataplaneSchedulingSpec{
			NodeSelector: map[string]string{"node-pool": "edge"},
			Tolerations: []corev1.Toleration{{
				Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "edge", Effect: corev1.TaintEffectNoSchedule,
			}},
			TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "flareway-gateway"}},
			}},
			Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key: "kubernetes.io/os", Operator: corev1.NodeSelectorOpIn, Values: []string{"linux"},
						}},
					}},
				},
			}},
		}
		gomega.Expect(testClient.Create(testContext, config)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, gatewayClass(className, configName))).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, httpGateway(gatewayKey, className))).To(gomega.Succeed())
	})

	ginkgo.AfterAll(func() {
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}))).To(gomega.Succeed())
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: className}}))).To(gomega.Succeed())
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}}))).To(gomega.Succeed())
	})

	ginkgo.It("applies class scheduling and the default anti-affinity to the dataplane Deployment", func() {
		gomega.Eventually(func(g gomega.Gomega) {
			var deployment appsv1.Deployment
			g.Expect(testClient.Get(testContext, dataplaneKey, &deployment)).To(gomega.Succeed())
			podSpec := deployment.Spec.Template.Spec

			g.Expect(podSpec.NodeSelector).To(gomega.Equal(map[string]string{"node-pool": "edge"}))
			g.Expect(podSpec.Tolerations).To(gomega.Equal([]corev1.Toleration{{
				Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "edge", Effect: corev1.TaintEffectNoSchedule,
			}}))
			g.Expect(podSpec.TopologySpreadConstraints).To(gomega.Equal([]corev1.TopologySpreadConstraint{{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "flareway-gateway"}},
			}}))

			g.Expect(podSpec.Affinity).NotTo(gomega.BeNil())
			g.Expect(podSpec.Affinity.NodeAffinity).NotTo(gomega.BeNil())
			g.Expect(podSpec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution).To(gomega.Equal(
				&corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key: "kubernetes.io/os", Operator: corev1.NodeSelectorOpIn, Values: []string{"linux"},
					}},
				}}},
			))

			// The user configured no podAntiAffinity, so the soft hostname
			// spread default is injected alongside the user fields.
			antiAffinity := podSpec.Affinity.PodAntiAffinity
			g.Expect(antiAffinity).NotTo(gomega.BeNil())
			g.Expect(antiAffinity.RequiredDuringSchedulingIgnoredDuringExecution).To(gomega.BeEmpty())
			g.Expect(antiAffinity.PreferredDuringSchedulingIgnoredDuringExecution).To(gomega.HaveLen(1))
			term := antiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]
			g.Expect(term.Weight).To(gomega.Equal(int32(100)))
			g.Expect(term.PodAffinityTerm.TopologyKey).To(gomega.Equal(corev1.LabelHostname))
			g.Expect(term.PodAffinityTerm.MatchLabelKeys).To(gomega.Equal([]string{appsv1.DefaultDeploymentUniqueLabelKey}))
			g.Expect(term.PodAffinityTerm.LabelSelector).NotTo(gomega.BeNil())
			g.Expect(term.PodAffinityTerm.LabelSelector.MatchLabels).To(gomega.Equal(map[string]string{
				"app.kubernetes.io/name":  "flareway-gateway",
				dataplane.GatewayLabelKey: namespaceName + "--" + gatewayKey.Name,
			}))
		}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("propagates GatewayClassConfig scheduling updates, including field removal, to the Deployment", func() {
		var config v1alpha1.GatewayClassConfig
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: configName}, &config)).To(gomega.Succeed())
		config.Spec.Scheduling.NodeSelector = map[string]string{"node-pool": "general"}
		config.Spec.Scheduling.Tolerations = nil
		config.Spec.Scheduling.TopologySpreadConstraints = nil
		gomega.Expect(testClient.Update(testContext, &config)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var deployment appsv1.Deployment
			g.Expect(testClient.Get(testContext, dataplaneKey, &deployment)).To(gomega.Succeed())
			podSpec := deployment.Spec.Template.Spec
			g.Expect(podSpec.NodeSelector).To(gomega.Equal(map[string]string{"node-pool": "general"}))
			// Fields removed from the class must disappear from the live
			// Deployment, not linger from an earlier apply.
			g.Expect(podSpec.Tolerations).To(gomega.BeEmpty())
			g.Expect(podSpec.TopologySpreadConstraints).To(gomega.BeEmpty())
			g.Expect(podSpec.Affinity).NotTo(gomega.BeNil())
			g.Expect(podSpec.Affinity.NodeAffinity).NotTo(gomega.BeNil())
			g.Expect(podSpec.Affinity.PodAntiAffinity).NotTo(gomega.BeNil())
			g.Expect(podSpec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution).To(gomega.HaveLen(1))
		}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("opts out of and back into the default anti-affinity on the live Deployment", func() {
		var config v1alpha1.GatewayClassConfig
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: configName}, &config)).To(gomega.Succeed())
		config.Spec.Scheduling.Affinity.PodAntiAffinity = &corev1.PodAntiAffinity{}
		gomega.Expect(testClient.Update(testContext, &config)).To(gomega.Succeed())
		stored := &unstructured.Unstructured{}
		stored.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("GatewayClassConfig"))
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: configName}, stored)).To(gomega.Succeed())
		_, found, err := unstructured.NestedMap(stored.Object, "spec", "scheduling", "affinity", "podAntiAffinity")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(found).To(gomega.BeTrue(), "the API server must preserve the empty podAntiAffinity opt-out object")

		// The opt-out leaves the template without any podAntiAffinity: the
		// previously applied default term must be removed, not retained.
		gomega.Eventually(func(g gomega.Gomega) {
			var deployment appsv1.Deployment
			g.Expect(testClient.Get(testContext, dataplaneKey, &deployment)).To(gomega.Succeed())
			affinity := deployment.Spec.Template.Spec.Affinity
			g.Expect(affinity).NotTo(gomega.BeNil())
			g.Expect(affinity.PodAntiAffinity).To(gomega.BeNil())
			g.Expect(affinity.NodeAffinity).NotTo(gomega.BeNil())
		}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())

		// Removing the opt-out restores the default spread term.
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: configName}, &config)).To(gomega.Succeed())
		config.Spec.Scheduling.Affinity.PodAntiAffinity = nil
		gomega.Expect(testClient.Update(testContext, &config)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var deployment appsv1.Deployment
			g.Expect(testClient.Get(testContext, dataplaneKey, &deployment)).To(gomega.Succeed())
			affinity := deployment.Spec.Template.Spec.Affinity
			g.Expect(affinity).NotTo(gomega.BeNil())
			g.Expect(affinity.PodAntiAffinity).NotTo(gomega.BeNil())
			g.Expect(affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution).To(gomega.BeEmpty())
			g.Expect(affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution).To(gomega.HaveLen(1))
			term := affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]
			g.Expect(term.Weight).To(gomega.Equal(int32(100)))
			g.Expect(term.PodAffinityTerm.TopologyKey).To(gomega.Equal(corev1.LabelHostname))
			g.Expect(term.PodAffinityTerm.MatchLabelKeys).To(gomega.Equal([]string{appsv1.DefaultDeploymentUniqueLabelKey}))
			g.Expect(term.PodAffinityTerm.LabelSelector).NotTo(gomega.BeNil())
			g.Expect(term.PodAffinityTerm.LabelSelector.MatchLabels).To(gomega.Equal(map[string]string{
				"app.kubernetes.io/name":  "flareway-gateway",
				dataplane.GatewayLabelKey: namespaceName + "--" + gatewayKey.Name,
			}))
		}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("does not churn the converged Deployment on repeated reconciles", func() {
		var deployment appsv1.Deployment
		gomega.Expect(testClient.Get(testContext, dataplaneKey, &deployment)).To(gomega.Succeed())
		generation := deployment.Generation
		spec := deployment.Spec

		// A metadata-only Gateway update passes the reconcile predicate and
		// forces a reconcile; the periodic requeue adds more. None may change
		// the converged Deployment.
		gomega.Eventually(func() error {
			var gateway gatewayv1.Gateway
			if err := testClient.Get(testContext, gatewayKey, &gateway); err != nil {
				return err
			}
			if gateway.Annotations == nil {
				gateway.Annotations = map[string]string{}
			}
			gateway.Annotations["flareway.bhyoo.com/scheduling-stability"] = "trigger"
			return testClient.Update(testContext, &gateway)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Consistently(func(g gomega.Gomega) {
			var current appsv1.Deployment
			g.Expect(testClient.Get(testContext, dataplaneKey, &current)).To(gomega.Succeed())
			g.Expect(current.Generation).To(gomega.Equal(generation))
			g.Expect(current.Spec).To(gomega.Equal(spec))
		}).WithTimeout(4 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})
})

var _ = ginkgo.Describe("Gateway dataplane scheduling upgrade", func() {
	ginkgo.It("adds the default anti-affinity to a pre-existing Deployment without changing its selector", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("sched-upgrade-%d", fixtureID)
		configName := fmt.Sprintf("conformance-upg-%d", fixtureID)
		className := fmt.Sprintf("flareway-upg-%d", fixtureID)
		gatewayKey := types.NamespacedName{Namespace: namespaceName, Name: "gateway"}
		dataplaneKey := types.NamespacedName{
			Namespace: namespaceName,
			Name:      dataplane.ResourceName(&ir.Gateway{Key: gatewayKey}),
		}

		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}})).To(gomega.Or(gomega.Succeed(), gomega.MatchError(gomega.ContainSubstring("already exists"))))
		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}})).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}))).To(gomega.Succeed())
		})

		config := conformanceConfig(configName, corev1.ServiceTypeClusterIP)
		gomega.Expect(testClient.Create(testContext, config)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, config))).To(gomega.Succeed())
		})

		// The Gateway is created before its GatewayClass so no reconcile can
		// build the dataplane before the old-shape Deployment is seeded.
		gateway := httpGateway(gatewayKey, className)
		gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())

		oldShape := dataplane.BuildDeployment(&ir.Gateway{Key: gatewayKey, UID: gateway.UID, ConformanceMode: true}, config, "", "")
		oldShape.Spec.Template.Spec.Affinity = nil
		oldShape.Spec.Template.Spec.NodeSelector = nil
		oldShape.Spec.Template.Spec.Tolerations = nil
		oldShape.Spec.Template.Spec.TopologySpreadConstraints = nil
		gomega.Expect(testClient.Create(testContext, oldShape)).To(gomega.Succeed())
		selector := oldShape.Spec.Selector.DeepCopy()

		gomega.Expect(testClient.Create(testContext, gatewayClass(className, configName))).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: className}}))).To(gomega.Succeed())
		})

		gomega.Eventually(func(g gomega.Gomega) {
			var deployment appsv1.Deployment
			g.Expect(testClient.Get(testContext, dataplaneKey, &deployment)).To(gomega.Succeed())
			// The apply succeeded only if the immutable selector is unchanged.
			g.Expect(deployment.Spec.Selector.MatchLabels).To(gomega.Equal(selector.MatchLabels))
			g.Expect(deployment.Spec.Replicas).NotTo(gomega.BeNil())
			g.Expect(*deployment.Spec.Replicas).To(gomega.Equal(int32(2)))

			antiAffinity := deployment.Spec.Template.Spec.Affinity
			g.Expect(antiAffinity).NotTo(gomega.BeNil())
			g.Expect(antiAffinity.PodAntiAffinity).NotTo(gomega.BeNil())
			g.Expect(antiAffinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution).To(gomega.HaveLen(1))
			term := antiAffinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]
			g.Expect(term.Weight).To(gomega.Equal(int32(100)))
			g.Expect(term.PodAffinityTerm.TopologyKey).To(gomega.Equal(corev1.LabelHostname))
			g.Expect(term.PodAffinityTerm.MatchLabelKeys).To(gomega.Equal([]string{appsv1.DefaultDeploymentUniqueLabelKey}))
		}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())

		// Once converged, further reconciles must not churn the Deployment.
		var converged appsv1.Deployment
		gomega.Expect(testClient.Get(testContext, dataplaneKey, &converged)).To(gomega.Succeed())
		gomega.Consistently(func(g gomega.Gomega) {
			var current appsv1.Deployment
			g.Expect(testClient.Get(testContext, dataplaneKey, &current)).To(gomega.Succeed())
			g.Expect(current.Generation).To(gomega.Equal(converged.Generation))
			g.Expect(current.Spec).To(gomega.Equal(converged.Spec))
		}).WithTimeout(4 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})
})
