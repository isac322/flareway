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
	"context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"regexp"
	"testing"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/test/cfstub"
)

const (
	smokeAccountID = "0123456789abcdef0123456789abcdef"
	smokeNamespace = "expl-smoke"
)

// TestSmokeAccountVerificationRoundTrip is a fixed, non-exploratory smoke: an
// authorized CloudflareAccount must be verified end to end through the
// production SDK against cfstub, must recover after a transient fault that
// exhausts the SDK's own retries, and must be reconciled again after a manager
// restart that keeps the same envtest environment.
func TestSmokeAccountVerificationRoundTrip(t *testing.T) {
	h := newExplorationHarness(t)
	ctx := context.Background()

	h.stub.State.SetOrganization(smokeAccountID, cfstub.Organization{
		ID:         "org-1",
		Name:       "Exploration Org",
		AuthDomain: "exploration.cloudflareaccess.com",
	})
	h.stub.State.AddZone(cfstub.Zone{
		ID:          "zone-1",
		Name:        "exploration.example.com",
		Account:     cfstub.ZoneAccount{ID: smokeAccountID, Name: "Exploration Org"},
		AccountID:   smokeAccountID,
		AccountName: "Exploration Org",
	})

	// The fault outlives the SDK's internal retries (initial attempt plus
	// DefaultMaxRetries), so the controller itself observes the failure and
	// recovers on its own retry once the fault is consumed.
	h.stub.Fault(http.MethodGet, `^/user/tokens/verify$`, cfstub.Fault{
		Status: http.StatusBadGateway,
		Times:  4,
	})

	must(t, h.client.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   smokeNamespace,
			Labels: map[string]string{"exploratory.flareway.bhyoo.com/tenant": "smoke"},
		},
	}), "create tenant namespace")
	must(t, h.client.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: smokeNamespace, Name: "cf-token"},
		Data:       map[string][]byte{"token": []byte("exploration-token")},
	}), "create token Secret")
	must(t, h.client.Create(ctx, &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "smoke-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: smokeAccountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{
				APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Namespace: smokeNamespace,
					Name:      "cf-token",
					Key:       "token",
				},
			},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"exploratory.flareway.bhyoo.com/tenant": "smoke"},
				},
				Hostnames: []string{"*"},
				Zones:     []string{"*"},
				Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
			}},
		},
	}), "create CloudflareAccount")

	must(t, h.waitStable(ctx, accountExpectation("smoke-account")), "account verification")

	// The production SDK reached cfstub: token verification, zone listing, and
	// the Zero Trust organization lookup all appear in the public journal.
	assertPublicOrder(t, h.stub,
		`^/user/tokens/verify$`,
		`^/zones$`,
		`^/accounts/\{id\}/access/organizations$`,
	)
	if got := countPublicCalls(h.stub, http.MethodGet, `^/user/tokens/verify$`); got < 5 {
		t.Fatalf("expected at least 5 token verification attempts after the transient fault, got %d", got)
	}

	// Restarting the manager keeps envtest and the stub alive; the fresh
	// manager re-lists the account and verifies it again.
	before := len(h.stub.PublicJournal())
	h.restartManager(t)
	must(t, h.waitStable(ctx, accountExpectation("smoke-account")), "account verification after restart")
	if got := len(h.stub.PublicJournal()); got <= before {
		t.Fatalf("expected new Cloudflare API calls after manager restart, journal stayed at %d calls", before)
	}
}

// assertPublicOrder verifies that each path regular expression matches a
// PublicJournal entry after the previous expression. Only the artifact-safe
// projection is used, so no raw account IDs, tokens, or hostnames are read.
func assertPublicOrder(t *testing.T, stub *cfstub.Server, pathRegex ...string) {
	t.Helper()

	patterns := make([]*regexp.Regexp, 0, len(pathRegex))
	for _, expression := range pathRegex {
		pattern, err := regexp.Compile(expression)
		must(t, err, "compile journal assertion pattern")
		patterns = append(patterns, pattern)
	}

	calls := stub.PublicJournal()
	next := 0
	for _, call := range calls {
		if next < len(patterns) && patterns[next].MatchString(call.Path) {
			next++
		}
	}
	if next != len(patterns) {
		t.Fatalf("expected public journal path matching %q after position %d; calls were %v", pathRegex[next], next, calls)
	}
}

func countPublicCalls(stub *cfstub.Server, method, pathRegex string) int {
	pattern := regexp.MustCompile(pathRegex)
	count := 0
	for _, call := range stub.PublicJournal() {
		if call.Method == method && pattern.MatchString(call.Path) {
			count++
		}
	}
	return count
}
