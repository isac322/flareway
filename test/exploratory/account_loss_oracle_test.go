//go:build exploratory

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

package exploratory

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// TestAccountLossOracle pins the account-loss oracle against the tunnel
// status contract. A live tunnel reports account loss as Accepted=False. A
// terminating tunnel never authors Accepted; its delete path fails closed with
// CleanupBlocked=True and keeps the finalizer, so that shape is the
// observation, whatever the reason. Absence is success.
func TestAccountLossOracle(t *testing.T) {
	const generation = 2
	deleting := metav1.Now()
	condition := func(conditionType string, status metav1.ConditionStatus, reason string, observed int64) metav1.Condition {
		return metav1.Condition{Type: conditionType, Status: status, Reason: reason, ObservedGeneration: observed}
	}
	tunnel := func(deletion *metav1.Time, finalizers []string, conditions ...metav1.Condition) *v1alpha1.CloudflareTunnel {
		return &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "ns", Generation: generation, ResourceVersion: "7",
				DeletionTimestamp: deletion, Finalizers: finalizers,
			},
			Status: v1alpha1.CloudflareTunnelStatus{Conditions: conditions},
		}
	}
	held := []string{v1alpha1.CloudflareTunnelFinalizer}
	staleAccepted := condition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionTrue, "Accepted", generation-1)

	cases := []struct {
		name     string
		tunnel   *v1alpha1.CloudflareTunnel
		observed bool
	}{
		{name: "absent tunnel", tunnel: nil, observed: true},
		{
			name:     "live tunnel reports Accepted=False",
			tunnel:   tunnel(nil, held, condition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "InvalidAccountRef", generation)),
			observed: true,
		},
		{
			name:   "live tunnel still Accepted=True",
			tunnel: tunnel(nil, held, condition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionTrue, "Accepted", generation)),
		},
		{name: "live tunnel without Accepted", tunnel: tunnel(nil, held)},
		{
			name: "live tunnel with CleanupBlocked=True is not a deletion",
			tunnel: tunnel(nil, held,
				condition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionTrue, "Accepted", generation),
				condition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "CredentialsUnavailable", generation)),
		},
		{
			name: "deleting tunnel blocked on missing credentials despite stale Accepted=True",
			tunnel: tunnel(&deleting, held, staleAccepted,
				condition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "CredentialsUnavailable", generation)),
			observed: true,
		},
		{
			name: "deleting tunnel blocked before the account lookup",
			tunnel: tunnel(&deleting, held, staleAccepted,
				condition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "WaitingForBlock", generation)),
			observed: true,
		},
		{
			name: "deleting tunnel reporting CleanupBlocked=False at the current generation",
			tunnel: tunnel(&deleting, held, staleAccepted,
				condition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionFalse, "Draining", generation)),
		},
		{
			name: "deleting tunnel with CleanupBlocked=True from an earlier generation",
			tunnel: tunnel(&deleting, held, staleAccepted,
				condition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "CredentialsUnavailable", generation-1)),
		},
		{name: "deleting tunnel without CleanupBlocked", tunnel: tunnel(&deleting, held, staleAccepted)},
		{
			name: "deleting tunnel that released its finalizer",
			tunnel: tunnel(&deleting, []string{"example.com/other"},
				condition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "CredentialsUnavailable", generation)),
		},
		{
			name: "deleting tunnel reporting Accepted=False without blocked cleanup",
			tunnel: tunnel(&deleting, held,
				condition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "InvalidAccountRef", generation)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fingerprint, err := tunnelObservedAccountLoss(tc.tunnel)
			if !tc.observed {
				if err == nil {
					t.Fatal("account loss accepted; the oracle must keep polling")
				}
				return
			}
			if err != nil {
				t.Fatalf("account loss not accepted: %v", err)
			}
			// waitStable folds the fingerprint into its quiescence signature,
			// so an accepted tunnel must be keyed by its resourceVersion.
			want := "absent"
			if tc.tunnel != nil {
				want = tc.tunnel.ResourceVersion
			}
			if fingerprint != want {
				t.Fatalf("fingerprint = %q, want %q", fingerprint, want)
			}
		})
	}
}
