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
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	rapid "pgregory.net/rapid"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/test/cfstub"
)

const (
	// accessFamilyLabel marks every object this family creates so iteration
	// resets can purge leftovers without touching other families' fixtures.
	accessFamilyLabel = "exploratory.flareway.bhyoo.com/family"
	accessFamilyValue = "access"

	accessAccountID = "a1b2c3d4e5f60718293a4b5c6d7e8f9a"

	accessRemotePolicyID = "access-policy-seeded"
	accessRemoteAppID    = "access-app-seeded"
	accessRemoteTokenID  = "service-token-seeded"

	// accessRevocationAnnotation mirrors the controller-private annotation
	// name; the invariant reads it as observable object state, never writes it.
	accessRevocationAnnotation = "flareway.bhyoo.com/access-revocation"
)

// accessWorld survives rapid iterations: the harness, the sanitized recorder,
// and the name sequence that keeps every object unique across iterations.
type accessWorld struct {
	tb  *testing.T
	h   *explorationHarness
	rec *traceRecorder
	seq int
}

// accessMachine is the per-iteration model. K8s objects are unique per
// iteration; remote fixtures are re-seeded after every resetIteration.
type accessMachine struct {
	world     *accessWorld
	iteration int

	tenant    string
	account   string
	credName  string
	policy    string
	app       string
	token     string
	tokenCred string

	accountExists bool
	credSecret    bool
	granted       bool
	platformOK    bool
	policyRefsOK  bool

	policyExists   bool
	policyDeleting bool

	appExists     bool
	appDeleting   bool
	appObserve    bool
	appPolicyMode string // "managedRef" or "external"
	appMark       int

	tokenExists    bool
	tokenDeleting  bool
	tokenObserve   bool
	tokenSecretKey string
	tokenMark      int

	remotePolicySeeded bool
	remoteAppSeeded    bool
	remoteTokenSeeded  bool

	denyMark      int
	tokenDenyMark int
}

// TestAccessStateMachine explores the Access surface: CloudflareAccount
// grants, credential Secrets, AccessPolicy and AccessApplication lifecycle,
// ServiceToken one-time credential capture, transient API faults, and manager
// restarts. Every iteration resets remote state and re-seeds fixtures; K8s
// objects get fresh names so leftover objects from earlier iterations are
// purged before the reset.
func TestAccessStateMachine(t *testing.T) {
	recorder := newTraceRecorder(t, "access")
	world := &accessWorld{
		tb:  t,
		h:   newExplorationHarness(t),
		rec: recorder,
	}
	rapid.Check(t, func(rt *rapid.T) {
		machine := &accessMachine{world: world}
		machine.beginIteration(rt)
		rt.Repeat(rapid.StateMachineActions(machine))
	})
}

// beginIteration purges leftover objects while the previous remote state is
// still seeded (so no reconciler spins on a missing remote fixture), resets
// the stub, and re-seeds the organization and zone the account needs.
func (m *accessMachine) beginIteration(rt *rapid.T) {
	w := m.world
	w.seq++
	m.iteration = w.seq
	m.tenant = fmt.Sprintf("expl-access-%d", m.iteration)
	m.account = fmt.Sprintf("access-account-%d", m.iteration)
	m.credName = fmt.Sprintf("cf-token-%d", m.iteration)
	m.policy = fmt.Sprintf("access-policy-%d", m.iteration)
	m.app = fmt.Sprintf("access-app-%d", m.iteration)
	m.token = fmt.Sprintf("service-token-%d", m.iteration)
	m.tokenCred = fmt.Sprintf("token-secret-%d", m.iteration)

	m.purgeLeftovers()
	operatorNamespace := new(corev1.Namespace)
	operatorKey := types.NamespacedName{Name: dataplane.DefaultOperatorNamespace}
	if err := w.h.client.Get(context.Background(), operatorKey, operatorNamespace); apierrors.IsNotFound(err) {
		must(rt, w.h.client.Create(context.Background(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace},
		}), "create operator namespace")
	} else {
		must(rt, err, "get operator namespace")
	}
	w.h.resetIteration(w.tb)
	w.h.stub.State.SetOrganization(accessAccountID, cfstub.Organization{
		ID:         "org-access",
		Name:       "Exploration Access Org",
		AuthDomain: "exploration.cloudflareaccess.com",
	})
	w.h.stub.State.AddZone(cfstub.Zone{
		ID:          "zone-access",
		Name:        "access.example.com",
		Account:     cfstub.ZoneAccount{ID: accessAccountID, Name: "Exploration Access Org"},
		AccountID:   accessAccountID,
		AccountName: "Exploration Access Org",
	})
	m.refreshDenyMarks()
	w.rec.BeginIteration()
	w.rec.Record("beginIteration", m.tenant, 0)
}

// purgeLeftovers strips finalizers and deletes every object this family can
// create, then waits for the journal to quiesce. envtest runs no garbage
// collector, so controller-owned Secrets are removed explicitly.
func (m *accessMachine) purgeLeftovers() {
	w := m.world
	ctx := context.Background()
	strip := func(object client.Object) {
		if len(object.GetFinalizers()) == 0 {
			return
		}
		base := object.DeepCopyObject().(client.Object)
		object.SetFinalizers(nil)
		if err := w.h.client.Patch(ctx, object, client.MergeFrom(base)); err != nil && !apierrors.IsNotFound(err) {
			w.tb.Fatalf("strip finalizers on %s/%s: %v", object.GetNamespace(), object.GetName(), err)
		}
	}
	remove := func(object client.Object) {
		if err := w.h.client.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) {
			w.tb.Fatalf("delete leftover %s/%s: %v", object.GetNamespace(), object.GetName(), err)
		}
	}

	var applications v1alpha1.AccessApplicationList
	if err := w.h.client.List(ctx, &applications); err != nil {
		w.tb.Fatalf("list leftover AccessApplications: %v", err)
	}
	for index := range applications.Items {
		strip(&applications.Items[index])
		remove(&applications.Items[index])
	}
	var tokens v1alpha1.ServiceTokenList
	if err := w.h.client.List(ctx, &tokens); err != nil {
		w.tb.Fatalf("list leftover ServiceTokens: %v", err)
	}
	for index := range tokens.Items {
		strip(&tokens.Items[index])
		remove(&tokens.Items[index])
	}
	var policies v1alpha1.AccessPolicyList
	if err := w.h.client.List(ctx, &policies); err != nil {
		w.tb.Fatalf("list leftover AccessPolicies: %v", err)
	}
	for index := range policies.Items {
		strip(&policies.Items[index])
		remove(&policies.Items[index])
	}
	var accounts v1alpha1.CloudflareAccountList
	if err := w.h.client.List(ctx, &accounts); err != nil {
		w.tb.Fatalf("list leftover CloudflareAccounts: %v", err)
	}
	for index := range accounts.Items {
		remove(&accounts.Items[index])
	}

	namespaces := []string{dataplane.DefaultOperatorNamespace}
	var labeled corev1.NamespaceList
	if err := w.h.client.List(ctx, &labeled, client.MatchingLabels{accessFamilyLabel: accessFamilyValue}); err != nil {
		w.tb.Fatalf("list leftover tenant Namespaces: %v", err)
	}
	for index := range labeled.Items {
		namespaces = append(namespaces, labeled.Items[index].Name)
	}
	for _, namespace := range namespaces {
		var secrets corev1.SecretList
		if err := w.h.client.List(ctx, &secrets, client.InNamespace(namespace)); err != nil {
			w.tb.Fatalf("list leftover Secrets in %s: %v", namespace, err)
		}
		for index := range secrets.Items {
			remove(&secrets.Items[index])
		}
	}
	if err := w.h.waitStable(ctx); err != nil {
		w.tb.Fatalf("purge leftovers: %v", err)
	}
}

// accessDenied reports whether tenant Access work is currently unauthorized:
// no account, no grant covering the tenant namespace, or no credential Secret.
func (m *accessMachine) accessDenied() bool {
	return !m.accountExists || !m.granted || !m.credSecret
}

// tokenDenied reports whether ServiceToken work is unauthorized; it needs the
// platformObjects gate on top of the base grant.
func (m *accessMachine) tokenDenied() bool {
	return m.accessDenied() || !m.platformOK
}

// refreshDenyMarks records the journal length at every rising denial edge so
// the invariants can assert that no tenant Access call lands after the moment
// authorization was lost.
func (m *accessMachine) refreshDenyMarks() {
	journal := len(m.world.h.stub.PublicJournal())
	if m.accessDenied() {
		m.denyMark = journal
	}
	if m.tokenDenied() {
		m.tokenDenyMark = journal
	}
}

// settleDenyEdge keeps revocation on the warm account/Secret watch paths,
// waits for existing dependents to report the denial, and then opens the
// journal window used to verify the denied steady state.
func (m *accessMachine) settleDenyEdge(rt *rapid.T, wasAccessDenied, wasTokenDenied bool) {
	accessRising := !wasAccessDenied && m.accessDenied()
	tokenRising := !wasTokenDenied && m.tokenDenied()
	expectations := make([]stabilityExpectation, 0, 2)
	if accessRising && m.appExists && !m.appDeleting {
		expectations = append(expectations, func(ctx context.Context, h *explorationHarness) (string, error) {
			var application v1alpha1.AccessApplication
			err := h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.tenant, Name: m.app}, &application)
			if apierrors.IsNotFound(err) {
				return "absent", nil
			}
			if err != nil {
				return "", err
			}
			accepted := meta.FindStatusCondition(application.Status.Conditions, "Accepted")
			if accepted == nil || accepted.Status != metav1.ConditionFalse {
				return "", fmt.Errorf("AccessApplication %s has not observed authorization denial", m.app)
			}
			return application.ResourceVersion, nil
		})
	}
	if tokenRising && m.tokenExists && !m.tokenDeleting {
		expectations = append(expectations, func(ctx context.Context, h *explorationHarness) (string, error) {
			var token v1alpha1.ServiceToken
			err := h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.tenant, Name: m.token}, &token)
			if apierrors.IsNotFound(err) {
				return "absent", nil
			}
			if err != nil {
				return "", err
			}
			accepted := meta.FindStatusCondition(token.Status.Conditions, "Accepted")
			if accepted == nil || accepted.Status != metav1.ConditionFalse {
				return "", fmt.Errorf("ServiceToken %s has not observed authorization denial", m.token)
			}
			return token.ResourceVersion, nil
		})
	}
	if accessRising || tokenRising {
		if err := m.world.h.waitStable(context.Background(), expectations...); err != nil {
			rt.Fatalf("wait for authorization denial: %v", err)
		}
	}
	m.refreshDenyMarks()
}

// drain settles the system before a mutation that can revoke authorization,
// so calls already authorized land before the watermark is taken.
func (m *accessMachine) drain(rt *rapid.T) {
	if err := m.world.h.waitStable(context.Background()); err != nil {
		rt.Fatalf("drain before mutation: %v", err)
	}
}

// CreateAccount creates the tenant namespace, optionally the credential
// Secret, and the CloudflareAccount with a grant that may or may not cover
// the tenant. Creating the account without a matching grant is the primary
// G1 exploration: tenant objects created afterwards must never reach
// Cloudflare.
func (m *accessMachine) CreateAccount(rt *rapid.T) {
	if m.accountExists {
		rt.Skip("account already exists")
	}
	w := m.world
	ctx := context.Background()
	m.granted = rapid.Bool().Draw(rt, "granted")
	m.platformOK = rapid.Bool().Draw(rt, "platformObjects")
	m.policyRefsOK = rapid.Bool().Draw(rt, "accessPolicyRefs")
	m.credSecret = rapid.Bool().Draw(rt, "credentialSecret")

	namespace := new(corev1.Namespace)
	if err := w.h.client.Get(ctx, types.NamespacedName{Name: m.tenant}, namespace); apierrors.IsNotFound(err) {
		must(rt, w.h.client.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   m.tenant,
				Labels: map[string]string{accessFamilyLabel: accessFamilyValue},
			},
		}), "create tenant namespace")
	} else {
		must(rt, err, "get tenant namespace")
	}
	if m.credSecret {
		m.createCredentialSecret(rt)
	} else {
		err := w.h.client.Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: m.tenant, Name: m.credName},
		})
		if err != nil && !apierrors.IsNotFound(err) {
			rt.Fatalf("delete stale credential Secret: %v", err)
		}
	}
	grant := v1alpha1.CloudflareAccountGrant{
		NamespaceSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{accessFamilyLabel: accessFamilyValue},
		},
		Hostnames: []string{"*"},
		Zones:     []string{"*"},
		Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
	}
	if !m.granted {
		grant.NamespaceSelector.MatchLabels[accessFamilyLabel] = "denied-" + accessFamilyValue
	}
	if m.platformOK {
		grant.PlatformObjects = v1alpha1.GrantPermissionAllowed
	}
	if m.policyRefsOK {
		grant.AccessPolicyRefs = v1alpha1.GrantPermissionAllowed
	}
	must(rt, w.h.client.Create(ctx, &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: m.account},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: accessAccountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{
				APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Namespace: m.tenant,
					Name:      m.credName,
					Key:       "token",
				},
			},
			Grants: []v1alpha1.CloudflareAccountGrant{grant},
		},
	}), "create CloudflareAccount")
	m.accountExists = true
	m.refreshDenyMarks()
	w.rec.Record("CreateAccount",
		fmt.Sprintf("granted=%t platform=%t policyRefs=%t credentials=%t", m.granted, m.platformOK, m.policyRefsOK, m.credSecret),
		len(w.h.stub.PublicJournal()))
}

// MutateAccountGrants rewrites the single grant in place. Revocation always
// changes the grant object itself; this family never revokes by editing
// namespace labels alone.
func (m *accessMachine) MutateAccountGrants(rt *rapid.T) {
	if !m.accountExists {
		rt.Skip("no account")
	}
	m.drain(rt)
	wasAccessDenied, wasTokenDenied := m.accessDenied(), m.tokenDenied()
	ctx := context.Background()
	choice := rapid.IntRange(0, 2).Draw(rt, "grantMutation")
	must(rt, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		account := new(v1alpha1.CloudflareAccount)
		if err := m.world.h.apiReader.Get(ctx, types.NamespacedName{Name: m.account}, account); err != nil {
			return err
		}
		if len(account.Spec.Grants) == 0 {
			return fmt.Errorf("account %s has no grants", m.account)
		}
		grant := &account.Spec.Grants[0]
		switch choice {
		case 0:
			m.platformOK = !m.platformOK
			grant.PlatformObjects = grantPermission(m.platformOK)
		case 1:
			m.policyRefsOK = !m.policyRefsOK
			grant.AccessPolicyRefs = grantPermission(m.policyRefsOK)
		default:
			m.granted = !m.granted
			if m.granted {
				grant.NamespaceSelector.MatchLabels[accessFamilyLabel] = accessFamilyValue
			} else {
				grant.NamespaceSelector.MatchLabels[accessFamilyLabel] = "denied-" + accessFamilyValue
			}
		}
		return m.world.h.client.Update(ctx, account)
	}), "mutate account grants")
	m.settleDenyEdge(rt, wasAccessDenied, wasTokenDenied)
	m.world.rec.Record("MutateAccountGrants",
		fmt.Sprintf("granted=%t platform=%t policyRefs=%t", m.granted, m.platformOK, m.policyRefsOK),
		len(m.world.h.stub.PublicJournal()))
}

// ToggleCredentialSecret deletes or restores the credential Secret. While it
// is absent the account cannot verify and no tenant Access call may occur.
func (m *accessMachine) ToggleCredentialSecret(rt *rapid.T) {
	if !m.accountExists {
		rt.Skip("no account")
	}
	m.drain(rt)
	wasAccessDenied, wasTokenDenied := m.accessDenied(), m.tokenDenied()
	ctx := context.Background()
	if m.credSecret {
		err := m.world.h.client.Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: m.tenant, Name: m.credName},
		})
		if err != nil && !apierrors.IsNotFound(err) {
			rt.Fatalf("delete credential Secret: %v", err)
		}
		m.credSecret = false
	} else {
		m.createCredentialSecret(rt)
		m.credSecret = true
	}
	m.settleDenyEdge(rt, wasAccessDenied, wasTokenDenied)
	m.world.rec.Record("ToggleCredentialSecret",
		fmt.Sprintf("present=%t", m.credSecret), len(m.world.h.stub.PublicJournal()))
}

func (m *accessMachine) createCredentialSecret(rt *rapid.T) {
	err := m.world.h.client.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: m.tenant,
			Name:      m.credName,
			Labels:    map[string]string{accessFamilyLabel: accessFamilyValue},
		},
		Data: map[string][]byte{"token": []byte("exploration-access-token")},
	})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		rt.Fatalf("create credential Secret: %v", err)
	}
}

// DeleteAccount removes the CloudflareAccount. It carries no finalizer, so
// the object disappears synchronously and every tenant resource loses its
// authorization basis at once.
func (m *accessMachine) DeleteAccount(rt *rapid.T) {
	if !m.accountExists {
		rt.Skip("no account")
	}
	m.drain(rt)
	wasAccessDenied, wasTokenDenied := m.accessDenied(), m.tokenDenied()
	err := m.world.h.client.Delete(context.Background(), &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: m.account},
	})
	if err != nil && !apierrors.IsNotFound(err) {
		rt.Fatalf("delete CloudflareAccount: %v", err)
	}
	m.accountExists = false
	m.settleDenyEdge(rt, wasAccessDenied, wasTokenDenied)
	m.world.rec.Record("DeleteAccount", "deleted", len(m.world.h.stub.PublicJournal()))
}

// UpsertAccessPolicy creates the reusable AccessPolicy in the operator
// namespace or toggles its decision. The policy lives outside the tenant
// namespace so referencing it exercises the accessPolicyRefs grant gate.
func (m *accessMachine) UpsertAccessPolicy(rt *rapid.T) {
	if !m.accountExists {
		rt.Skip("no account")
	}
	ctx := context.Background()
	if !m.policyExists {
		must(rt, m.world.h.client.Create(ctx, &v1alpha1.AccessPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: dataplane.DefaultOperatorNamespace,
				Name:      m.policy,
				Labels:    map[string]string{accessFamilyLabel: accessFamilyValue},
			},
			Spec: v1alpha1.AccessPolicySpec{
				AccountRef: corev1.LocalObjectReference{Name: m.account},
				Name:       "exploration-policy",
				Decision:   v1alpha1.AccessPolicyDecisionAllow,
				Include:    []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
			},
		}), "create AccessPolicy")
		m.policyExists = true
		m.world.rec.Record("UpsertAccessPolicy", "created", len(m.world.h.stub.PublicJournal()))
		return
	}
	if m.policyDeleting {
		rt.Skip("policy is deleting")
	}
	must(rt, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		policy := new(v1alpha1.AccessPolicy)
		if err := m.world.h.apiReader.Get(ctx, types.NamespacedName{Namespace: dataplane.DefaultOperatorNamespace, Name: m.policy}, policy); err != nil {
			return err
		}
		if policy.Spec.Decision == v1alpha1.AccessPolicyDecisionAllow {
			policy.Spec.Decision = v1alpha1.AccessPolicyDecisionDeny
		} else {
			policy.Spec.Decision = v1alpha1.AccessPolicyDecisionAllow
		}
		return m.world.h.client.Update(ctx, policy)
	}), "update AccessPolicy")
	m.world.rec.Record("UpsertAccessPolicy", "decision toggled", len(m.world.h.stub.PublicJournal()))
}

// DeleteAccessPolicy removes the reusable policy. The AccessPolicy controller
// is not part of this harness, so the object carries no finalizer and the
// deletion is immediate; any AccessApplication still referencing it enters
// policy uncertainty.
func (m *accessMachine) DeleteAccessPolicy(rt *rapid.T) {
	if !m.policyExists || m.policyDeleting {
		rt.Skip("no policy")
	}
	err := m.world.h.client.Delete(context.Background(), &v1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: dataplane.DefaultOperatorNamespace, Name: m.policy},
	})
	if err != nil && !apierrors.IsNotFound(err) {
		rt.Fatalf("delete AccessPolicy: %v", err)
	}
	m.policyExists = false
	m.world.rec.Record("DeleteAccessPolicy", "deleted", len(m.world.h.stub.PublicJournal()))
}

// SeedRemoteFixtures seeds the remote objects that externalRef and
// ObserveOnly resources point at: a reusable policy, an existing application,
// and an existing service token. None of them is owned by a K8s object.
func (m *accessMachine) SeedRemoteFixtures(rt *rapid.T) {
	if m.remotePolicySeeded && m.remoteAppSeeded && m.remoteTokenSeeded {
		rt.Skip("remote fixtures already seeded")
	}
	state := m.world.h.stub.State
	if !m.remotePolicySeeded {
		state.AddAccessPolicy(accessAccountID, cfstub.AccessResource{
			"id":       accessRemotePolicyID,
			"name":     "seeded-policy",
			"decision": "allow",
			"include":  []any{map[string]any{"everyone": map[string]any{}}},
		})
		m.remotePolicySeeded = true
	}
	if !m.remoteAppSeeded {
		state.AddAccessApplication(accessAccountID, cfstub.AccessResource{
			"id":   accessRemoteAppID,
			"name": "seeded-application",
			"type": "self_hosted",
			"aud":  "aud-" + accessRemoteAppID,
		})
		m.remoteAppSeeded = true
	}
	if !m.remoteTokenSeeded {
		state.AddAccessServiceToken(accessAccountID, cfstub.AccessServiceToken{
			ID:        accessRemoteTokenID,
			ClientID:  "seeded-client-id",
			Name:      "seeded-token",
			Enabled:   true,
			Duration:  "8760h",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, "seeded-client-secret")
		m.remoteTokenSeeded = true
	}
	m.world.rec.Record("SeedRemoteFixtures", "seeded", len(m.world.h.stub.PublicJournal()))
}

// UpsertAccessApplication creates the single AccessApplication or mutates it.
// The application uses declared Worker destinations only, so it never targets
// a Gateway and never publishes an AUD handoff Secret; policy uncertainty is
// exercised through the policies list instead.
func (m *accessMachine) UpsertAccessApplication(rt *rapid.T) {
	if !m.accountExists {
		rt.Skip("no account")
	}
	ctx := context.Background()
	if !m.appExists {
		observe := rapid.Bool().Draw(rt, "observeOnly")
		policyMode := "managedRef"
		if rapid.Bool().Draw(rt, "policyMode") {
			policyMode = "external"
		}
		if observe && !m.remoteAppSeeded {
			rt.Skip("ObserveOnly application needs a seeded remote application")
		}
		if policyMode == "external" && !m.remotePolicySeeded {
			rt.Skip("external policy reference needs a seeded remote policy")
		}
		m.appObserve = observe
		m.appPolicyMode = policyMode
		m.appMark = len(m.world.h.stub.PublicJournal())
		application := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: m.tenant,
				Name:      m.app,
				Labels:    map[string]string{accessFamilyLabel: accessFamilyValue},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: m.account},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				Destinations: []v1alpha1.AccessApplicationDestinationSpec{{
					Type:       v1alpha1.AccessApplicationDestinationAllWorkers,
					AllWorkers: &v1alpha1.AccessAllWorkersDestinationSpec{},
				}},
				Policies: []v1alpha1.AccessApplicationPolicyReference{m.policyReference()},
			},
		}
		if m.appObserve {
			application.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
			application.Spec.ExternalRef = &v1alpha1.AccessApplicationExternalReference{ApplicationID: accessRemoteAppID}
		}
		must(rt, m.world.h.client.Create(ctx, application), "create AccessApplication")
		m.appExists = true
		if !m.appObserve {
			m.appMark = 0
		}
		m.world.rec.Record("UpsertAccessApplication",
			fmt.Sprintf("created observe=%t policy=%s", m.appObserve, m.appPolicyMode),
			len(m.world.h.stub.PublicJournal()))
		return
	}
	if m.appDeleting {
		rt.Skip("application is deleting")
	}
	choice := rapid.IntRange(0, 1).Draw(rt, "appUpdate")
	if choice == 1 && m.appPolicyMode != "external" && !m.remotePolicySeeded {
		choice = 0
	}
	must(rt, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		application := new(v1alpha1.AccessApplication)
		if err := m.world.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.tenant, Name: m.app}, application); err != nil {
			return err
		}
		switch choice {
		case 0:
			visible := application.Spec.Application.AppLauncherVisible == nil || !*application.Spec.Application.AppLauncherVisible
			application.Spec.Application.AppLauncherVisible = &visible
		default:
			if m.appPolicyMode == "external" {
				m.appPolicyMode = "managedRef"
			} else {
				m.appPolicyMode = "external"
			}
			application.Spec.Policies = []v1alpha1.AccessApplicationPolicyReference{m.policyReference()}
		}
		return m.world.h.client.Update(ctx, application)
	}), "update AccessApplication")
	m.world.rec.Record("UpsertAccessApplication",
		fmt.Sprintf("updated policy=%s", m.appPolicyMode), len(m.world.h.stub.PublicJournal()))
}

// policyReference renders the application's single policy reference in the
// current mode: a cross-namespace managed reference or an external ID.
func (m *accessMachine) policyReference() v1alpha1.AccessApplicationPolicyReference {
	if m.appPolicyMode == "external" {
		return v1alpha1.AccessApplicationPolicyReference{
			ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: accessRemotePolicyID},
		}
	}
	return v1alpha1.AccessApplicationPolicyReference{
		PolicyRef: &v1alpha1.NamespacedLocalObjectReference{
			Namespace: dataplane.DefaultOperatorNamespace,
			Name:      m.policy,
		},
	}
}

// DeleteAccessApplication deletes the application. The finalizer drives
// fail-closed cleanup; the object stays observable until removal completes.
func (m *accessMachine) DeleteAccessApplication(rt *rapid.T) {
	if !m.appExists || m.appDeleting {
		rt.Skip("no application")
	}
	err := m.world.h.client.Delete(context.Background(), &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.tenant, Name: m.app},
	})
	if err != nil && !apierrors.IsNotFound(err) {
		rt.Fatalf("delete AccessApplication: %v", err)
	}
	m.appDeleting = true
	m.world.rec.Record("DeleteAccessApplication", "deleting", len(m.world.h.stub.PublicJournal()))
}

// UpsertServiceToken creates the single ServiceToken or toggles its enabled
// flag. ObserveOnly tokens point at the seeded remote token and must never
// mutate remote state.
func (m *accessMachine) UpsertServiceToken(rt *rapid.T) {
	if !m.accountExists {
		rt.Skip("no account")
	}
	ctx := context.Background()
	if !m.tokenExists {
		observe := rapid.Bool().Draw(rt, "observeOnly")
		if observe && !m.remoteTokenSeeded {
			rt.Skip("ObserveOnly token needs a seeded remote token")
		}
		m.tokenObserve = observe
		m.tokenMark = len(m.world.h.stub.PublicJournal())
		token := &v1alpha1.ServiceToken{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: m.tenant,
				Name:      m.token,
				Labels:    map[string]string{accessFamilyLabel: accessFamilyValue},
			},
			Spec: v1alpha1.ServiceTokenSpec{
				AccountRef: corev1.LocalObjectReference{Name: m.account},
				Name:       "exploration-token",
				Enabled:    true,
				SecretRef:  corev1.LocalObjectReference{Name: m.tokenCred},
			},
		}
		if m.tokenObserve {
			token.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
			token.Spec.ExternalRef = &v1alpha1.ServiceTokenExternalReference{TokenID: accessRemoteTokenID}
		}
		must(rt, m.world.h.client.Create(ctx, token), "create ServiceToken")
		m.tokenExists = true
		if !m.tokenObserve {
			m.tokenMark = 0
		}
		m.world.rec.Record("UpsertServiceToken",
			fmt.Sprintf("created observe=%t", m.tokenObserve), len(m.world.h.stub.PublicJournal()))
		return
	}
	if m.tokenDeleting {
		rt.Skip("token is deleting")
	}
	must(rt, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		token := new(v1alpha1.ServiceToken)
		if err := m.world.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.tenant, Name: m.token}, token); err != nil {
			return err
		}
		token.Spec.Enabled = !token.Spec.Enabled
		return m.world.h.client.Update(ctx, token)
	}), "update ServiceToken")
	m.world.rec.Record("UpsertServiceToken", "enabled toggled", len(m.world.h.stub.PublicJournal()))
}

// DeleteServiceToken deletes the token. Managed tokens delete the remote
// object through the finalizer; ObserveOnly tokens must not.
func (m *accessMachine) DeleteServiceToken(rt *rapid.T) {
	if !m.tokenExists || m.tokenDeleting {
		rt.Skip("no token")
	}
	err := m.world.h.client.Delete(context.Background(), &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.tenant, Name: m.token},
	})
	if err != nil && !apierrors.IsNotFound(err) {
		rt.Fatalf("delete ServiceToken: %v", err)
	}
	m.tokenDeleting = true
	m.world.rec.Record("DeleteServiceToken", "deleting", len(m.world.h.stub.PublicJournal()))
}

// InjectFault installs a short transient fault on an Access endpoint. The
// fault outlives the SDK's internal retries so the controller observes the
// failure and recovers on its own requeue once the fault is consumed.
func (m *accessMachine) InjectFault(rt *rapid.T) {
	targets := []struct {
		method  string
		pattern string
	}{
		{http.MethodGet, `^/accounts/[^/]+/access/apps/[^/]+$`},
		{http.MethodPost, `^/accounts/[^/]+/access/apps$`},
		{http.MethodGet, `^/accounts/[^/]+/access/service_tokens/[^/]+$`},
		{http.MethodPost, `^/accounts/[^/]+/access/service_tokens$`},
		{http.MethodGet, `^/accounts/[^/]+/access/policies/[^/]+$`},
	}
	target := targets[rapid.IntRange(0, len(targets)-1).Draw(rt, "faultTarget")]
	m.world.h.stub.Fault(target.method, target.pattern, cfstub.Fault{
		Status: http.StatusBadGateway,
		Times:  4,
	})
	m.world.rec.Record("InjectFault", target.method+" "+target.pattern, len(m.world.h.stub.PublicJournal()))
}

// RestartManager recreates the controller manager against the same envtest
// environment and stub; every watched object is reconciled again.
func (m *accessMachine) RestartManager(rt *rapid.T) {
	m.world.h.restartManager(m.world.tb)
	m.world.rec.Record("RestartManager", "restarted", len(m.world.h.stub.PublicJournal()))
}

// Check runs after every action: it waits for the system to quiesce, syncs
// the model with the live objects, records conditions, and evaluates the
// family invariants.
func (m *accessMachine) Check(rt *rapid.T) {
	w := m.world
	ctx := context.Background()

	expectations := []stabilityExpectation{
		presentOrAbsent(types.NamespacedName{Name: m.account}, &v1alpha1.CloudflareAccount{}),
		presentOrAbsent(types.NamespacedName{Namespace: dataplane.DefaultOperatorNamespace, Name: m.policy}, &v1alpha1.AccessPolicy{}),
		presentOrAbsent(types.NamespacedName{Namespace: m.tenant, Name: m.app}, &v1alpha1.AccessApplication{}),
		presentOrAbsent(types.NamespacedName{Namespace: m.tenant, Name: m.token}, &v1alpha1.ServiceToken{}),
	}
	if err := w.h.waitStable(ctx, expectations...); err != nil {
		rt.Fatalf("system did not stabilize: %v", err)
	}

	m.syncModel(rt, ctx)
	m.checkGrantBeforeCalls(rt)
	m.checkFailClosed(rt, ctx)
	m.checkTokenSecretCapture(rt, ctx)
	m.checkObserveOnly(rt)
}

// syncModel reconciles the model with the live objects so deletion progress
// and status conditions are observed rather than assumed.
func (m *accessMachine) syncModel(rt *rapid.T, ctx context.Context) {
	w := m.world
	account := new(v1alpha1.CloudflareAccount)
	if err := w.h.apiReader.Get(ctx, types.NamespacedName{Name: m.account}, account); err == nil {
		m.accountExists = true
		for _, condition := range account.Status.Conditions {
			w.rec.RecordCondition("CloudflareAccount", condition.Type, string(condition.Status), condition.Reason)
		}
	} else if apierrors.IsNotFound(err) {
		m.accountExists = false
	} else {
		rt.Fatalf("get CloudflareAccount: %v", err)
	}

	policy := new(v1alpha1.AccessPolicy)
	policyKey := types.NamespacedName{Namespace: dataplane.DefaultOperatorNamespace, Name: m.policy}
	if err := w.h.apiReader.Get(ctx, policyKey, policy); err == nil {
		m.policyExists = true
		m.policyDeleting = !policy.DeletionTimestamp.IsZero()
		for _, condition := range policy.Status.Conditions {
			w.rec.RecordCondition("AccessPolicy", condition.Type, string(condition.Status), condition.Reason)
		}
	} else if apierrors.IsNotFound(err) {
		m.policyExists = false
		m.policyDeleting = false
	} else {
		rt.Fatalf("get AccessPolicy: %v", err)
	}

	application := new(v1alpha1.AccessApplication)
	appKey := types.NamespacedName{Namespace: m.tenant, Name: m.app}
	if err := w.h.apiReader.Get(ctx, appKey, application); err == nil {
		m.appExists = true
		m.appDeleting = !application.DeletionTimestamp.IsZero()
		for _, condition := range application.Status.Conditions {
			w.rec.RecordCondition("AccessApplication", condition.Type, string(condition.Status), condition.Reason)
		}
	} else if apierrors.IsNotFound(err) {
		m.appExists = false
		m.appDeleting = false
	} else {
		rt.Fatalf("get AccessApplication: %v", err)
	}

	token := new(v1alpha1.ServiceToken)
	tokenKey := types.NamespacedName{Namespace: m.tenant, Name: m.token}
	if err := w.h.apiReader.Get(ctx, tokenKey, token); err == nil {
		m.tokenExists = true
		m.tokenDeleting = !token.DeletionTimestamp.IsZero()
		for _, condition := range token.Status.Conditions {
			w.rec.RecordCondition("ServiceToken", condition.Type, string(condition.Status), condition.Reason)
		}
	} else if apierrors.IsNotFound(err) {
		m.tokenExists = false
		m.tokenDeleting = false
	} else {
		rt.Fatalf("get ServiceToken: %v", err)
	}

	secret := new(corev1.Secret)
	if err := w.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.tenant, Name: m.tokenCred}, secret); err == nil {
		w.rec.RecordSecret(secret.Data)
	} else if apierrors.IsNotFound(err) {
		w.rec.RecordSecret(nil)
	} else {
		rt.Fatalf("get ServiceToken Secret: %v", err)
	}
}

// checkGrantBeforeCalls enforces G1: while tenant Access work is denied, no
// call to a tenant Access endpoint may appear in the journal after the denial
// watermark. Account verification endpoints are out of scope.
func (m *accessMachine) checkGrantBeforeCalls(rt *rapid.T) {
	journal := m.world.h.stub.PublicJournal()
	if m.accessDenied() && m.denyMark <= len(journal) {
		for _, call := range journal[m.denyMark:] {
			if isAccessCall(call) {
				rt.Fatalf("G1: tenant Access call %s %s while unauthorized", call.Method, call.Path)
			}
		}
	}
	if m.tokenExists && m.tokenDenied() && m.tokenDenyMark <= len(journal) {
		for _, call := range journal[m.tokenDenyMark:] {
			if isServiceTokenCall(call) {
				rt.Fatalf("G1: ServiceToken call %s %s while platformObjects is denied", call.Method, call.Path)
			}
		}
	}
}

// checkFailClosed enforces G3: an application may report Programmed only when
// its policy reference resolved and no revocation is latched, and this family
// never publishes AUD handoff Secrets because it declares no Gateway targets.
func (m *accessMachine) checkFailClosed(rt *rapid.T, ctx context.Context) {
	w := m.world
	if m.appExists {
		application := new(v1alpha1.AccessApplication)
		if err := w.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.tenant, Name: m.app}, application); err != nil {
			rt.Fatalf("get AccessApplication for G3: %v", err)
		}
		programmed := meta.IsStatusConditionTrue(application.Status.Conditions, "Programmed")
		latched := application.Annotations[accessRevocationAnnotation] != ""
		if programmed && latched {
			rt.Fatalf("G3: AccessApplication is Programmed with a latched revocation")
		}
		if !m.appDeleting {
			resolved := m.policyResolved(ctx, application)
			if programmed && !resolved {
				rt.Fatalf("G3: AccessApplication is Programmed while its policy reference is unresolved")
			}
		}
	}
	var secrets corev1.SecretList
	if err := w.h.apiReader.List(ctx, &secrets, client.InNamespace(dataplane.DefaultOperatorNamespace)); err != nil {
		rt.Fatalf("list operator Secrets for G3: %v", err)
	}
	for index := range secrets.Items {
		if _, aud := secrets.Items[index].Labels[v1alpha1.AccessApplicationAUDSecretLabel]; aud {
			rt.Fatalf("G3: AUD handoff Secret %s exists although this family declares no Gateway targets", secrets.Items[index].Name)
		}
	}
}

// policyResolved reports whether the application's single policy reference
// currently resolves: a managed reference needs an existing, non-deleting
// AccessPolicy plus the accessPolicyRefs grant; an external reference needs
// the seeded remote policy to still exist.
func (m *accessMachine) policyResolved(ctx context.Context, application *v1alpha1.AccessApplication) bool {
	if len(application.Spec.Policies) == 0 {
		return true
	}
	reference := application.Spec.Policies[0]
	if reference.ExternalRef != nil {
		for _, remote := range m.world.h.stub.State.AccessPolicies("accounts/" + accessAccountID) {
			if remote["id"] == reference.ExternalRef.PolicyID {
				return true
			}
		}
		return false
	}
	if reference.PolicyRef == nil {
		return false
	}
	if !m.policyRefsOK || !m.policyExists || m.policyDeleting {
		return false
	}
	policy := new(v1alpha1.AccessPolicy)
	key := types.NamespacedName{Namespace: dataplane.DefaultOperatorNamespace, Name: reference.PolicyRef.Name}
	if err := m.world.h.apiReader.Get(ctx, key, policy); err != nil {
		return false
	}
	return policy.Status.PolicyID != "" &&
		meta.IsStatusConditionTrue(policy.Status.Conditions, "Accepted") &&
		policy.DeletionTimestamp.IsZero()
}

// checkTokenSecretCapture enforces G6 for Managed ServiceTokens: Ready requires
// a controller-owned credential Secret carrying both one-time credentials and
// the remote token ID. ObserveOnly tokens never capture remote credentials.
func (m *accessMachine) checkTokenSecretCapture(rt *rapid.T, ctx context.Context) {
	if !m.tokenExists || m.tokenObserve {
		return
	}
	w := m.world
	token := new(v1alpha1.ServiceToken)
	if err := w.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.tenant, Name: m.token}, token); err != nil {
		rt.Fatalf("get ServiceToken for G6: %v", err)
	}
	secret := new(corev1.Secret)
	secretErr := w.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.tenant, Name: token.Spec.SecretRef.Name}, secret)
	secretPresent := secretErr == nil
	if secretErr != nil && !apierrors.IsNotFound(secretErr) {
		rt.Fatalf("get ServiceToken Secret for G6: %v", secretErr)
	}
	ready := meta.IsStatusConditionTrue(token.Status.Conditions, "Ready")
	if !ready {
		return
	}
	if !secretPresent {
		rt.Fatalf("G6: ServiceToken is Ready without its credential Secret")
	}
	if !metav1.IsControlledBy(secret, token) {
		rt.Fatalf("G6: ServiceToken is Ready but the credential Secret is not controlled by it")
	}
	if len(secret.Data[v1alpha1.ServiceTokenClientIDKey]) == 0 ||
		len(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) == 0 {
		rt.Fatalf("G6: ServiceToken is Ready but the credential Secret lacks client credentials")
	}
	if token.Status.TokenID != "" &&
		secret.Annotations[v1alpha1.ServiceTokenIDAnnotation] != token.Status.TokenID {
		rt.Fatalf("G6: credential Secret token ID annotation does not match status.tokenId")
	}
}

// checkObserveOnly enforces G2: an ObserveOnly application or token may read
// remote state but must never issue a mutating call after its creation
// watermark, including finalizer and revocation calls during deletion.
func (m *accessMachine) checkObserveOnly(rt *rapid.T) {
	journal := m.world.h.stub.PublicJournal()
	if m.appObserve && m.appMark <= len(journal) {
		for _, call := range journal[m.appMark:] {
			if isAppMutationCall(call) {
				rt.Fatalf("G2: ObserveOnly AccessApplication caused %s %s", call.Method, call.Path)
			}
		}
		if !m.appExists {
			m.appObserve = false
		}
	}
	if m.tokenObserve && m.tokenMark <= len(journal) {
		for _, call := range journal[m.tokenMark:] {
			if isServiceTokenMutationCall(call) {
				rt.Fatalf("G2: ObserveOnly ServiceToken caused %s %s", call.Method, call.Path)
			}
		}
		if !m.tokenExists {
			m.tokenObserve = false
		}
	}
}

// presentOrAbsent fingerprints an object by resourceVersion, or reports
// "absent" when it does not exist, so waitStable converges either way.
func presentOrAbsent(key types.NamespacedName, object client.Object) stabilityExpectation {
	return func(ctx context.Context, h *explorationHarness) (string, error) {
		if err := h.apiReader.Get(ctx, key, object); err != nil {
			if apierrors.IsNotFound(err) {
				return "absent", nil
			}
			return "", err
		}
		return object.GetResourceVersion(), nil
	}
}

func grantPermission(allowed bool) v1alpha1.GrantPermission {
	if allowed {
		return v1alpha1.GrantPermissionAllowed
	}
	return v1alpha1.GrantPermissionDenied
}

// isAccessCall reports whether a journaled call hits a tenant Access
// endpoint. The account organization lookup is account verification, not
// tenant work, and is excluded.
func isAccessCall(call cfstub.PublicCall) bool {
	if !strings.Contains(call.Path, "/access/") {
		return false
	}
	return call.Path != "/accounts/{id}/access/organizations"
}

func isServiceTokenCall(call cfstub.PublicCall) bool {
	return strings.Contains(call.Path, "/access/service_tokens")
}

// isAppMutationCall reports whether a call mutates remote Access application
// state, including token revocation and managed-tag cleanup.
func isAppMutationCall(call cfstub.PublicCall) bool {
	if call.Method != http.MethodPost && call.Method != http.MethodPut && call.Method != http.MethodDelete {
		return false
	}
	return strings.Contains(call.Path, "/access/apps") || strings.Contains(call.Path, "/access/tags")
}

func isServiceTokenMutationCall(call cfstub.PublicCall) bool {
	if call.Method != http.MethodPost && call.Method != http.MethodPut && call.Method != http.MethodDelete {
		return false
	}
	return isServiceTokenCall(call)
}
