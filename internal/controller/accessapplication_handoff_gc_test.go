package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

func handoffGCScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// accessApplicationTestClientBuilder mirrors the field index SetupWithManager
// installs on corev1.Secret. Every fake-client fixture that drives
// AccessApplicationReconciler.Reconcile must start from it: Reconcile lists
// handoff Secrets through the index, so a builder without it fails the way an
// unregistered index does against the real manager cache.
func accessApplicationTestClientBuilder(scheme *runtime.Scheme) *fakeclient.ClientBuilder {
	return fakeclient.NewClientBuilder().WithScheme(scheme).
		WithIndex(&corev1.Secret{}, accessApplicationHandoffOwnerIndex, accessHandoffOwnerIndexKeys(accessApplicationAUDNamespace))
}

func handoffGCClient(t *testing.T, objects ...client.Object) client.WithWatch {
	t.Helper()
	return accessApplicationTestClientBuilder(handoffGCScheme(t)).
		WithObjects(objects...).Build()
}

func handoffApplication(namespace, name string, uid types.UID) *v1alpha1.AccessApplication {
	return &v1alpha1.AccessApplication{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: uid}}
}

func audHandoff(application *v1alpha1.AccessApplication) *corev1.Secret {
	gatewayKey := types.NamespacedName{Namespace: application.Namespace, Name: "gateway"}
	key := accessAUDSecretKey(accessApplicationAUDNamespace, application, gatewayKey)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, Labels: map[string]string{
			v1alpha1.AccessApplicationAUDSecretLabel:  applicationAUDIdentityLabel(application),
			v1alpha1.AccessApplicationGatewayAUDLabel: "gateway",
		}},
		Data: map[string][]byte{
			v1alpha1.AccessApplicationAUDSecretKey:                   []byte("aud"),
			v1alpha1.AccessApplicationIDSecretKey:                    []byte("remote"),
			v1alpha1.AccessApplicationNamespacedNameSecretKey:        []byte(client.ObjectKeyFromObject(application).String()),
			v1alpha1.AccessApplicationUIDSecretKey:                   []byte(application.UID),
			v1alpha1.AccessApplicationGatewayNamespacedNameSecretKey: []byte(gatewayKey.String()),
			v1alpha1.AccessApplicationGatewayUIDSecretKey:            []byte("gateway-uid"),
			accessApplicationAUDReadyKey:                             []byte("true"),
		},
	}
}

func ledgerHandoff(application *v1alpha1.AccessApplication) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: accessApplicationAUDNamespace, Name: privateTunnelLedgerSecretName(application.UID),
			Labels: map[string]string{accessApplicationPrivateTunnelsLabel: application.Namespace + "--" + application.Name},
		},
		Data: map[string][]byte{accessApplicationPrivateTunnelsKey: []byte(`["tenant/tunnel"]`)},
	}
}

func secretExists(t *testing.T, reader client.Reader, secret *corev1.Secret) bool {
	t.Helper()
	err := reader.Get(context.Background(), client.ObjectKeyFromObject(secret), &corev1.Secret{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

// countingReader records authoritative reads so tests can prove the steady
// state never bypasses the cache.
type countingReader struct {
	client.Reader
	gets int
}

func (r *countingReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	r.gets++
	return r.Reader.Get(ctx, key, object, options...)
}

func TestReconcileCollectsHandoffsOfVanishedApplication(t *testing.T) {
	dead := handoffApplication("tenant", "app", "dead-uid")
	aud, ledger := audHandoff(dead), ledgerHandoff(dead)
	unrelated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: accessApplicationAUDNamespace, Name: "unrelated"}}
	kube := handoffGCClient(t, aud, ledger, unrelated)
	r := &AccessApplicationReconciler{Client: kube, APIReader: kube}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(dead)}); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, kube, aud) || secretExists(t, kube, ledger) {
		t.Fatal("handoff Secrets of a vanished AccessApplication survived its reconcile")
	}
	if !secretExists(t, kube, unrelated) {
		t.Fatal("an unrelated operator-namespace Secret was deleted")
	}
}

func TestReconcileCollectsOnlyPreviousIncarnationHandoffs(t *testing.T) {
	previous := handoffApplication("tenant", "app", "previous-uid")
	current := handoffApplication("tenant", "app", "current-uid")
	current.Finalizers = []string{v1alpha1.AccessApplicationFinalizer}
	current.DeletionTimestamp = &metav1.Time{Time: time.Unix(1, 0)}
	previousAUD, previousLedger := audHandoff(previous), ledgerHandoff(previous)
	currentAUD, currentLedger := audHandoff(current), ledgerHandoff(current)
	kube := handoffGCClient(t, previousAUD, previousLedger, currentAUD, currentLedger, current)
	r := &AccessApplicationReconciler{Client: kube, APIReader: kube}

	if err := r.collectOrphanedHandoffs(context.Background(), client.ObjectKeyFromObject(current), current); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, kube, previousAUD) || secretExists(t, kube, previousLedger) {
		t.Fatal("handoff Secrets of the previous incarnation survived")
	}
	if !secretExists(t, kube, currentAUD) || !secretExists(t, kube, currentLedger) {
		t.Fatal("handoff Secrets of the live incarnation were deleted while its finalizer still owns them")
	}
}

func TestHandoffCollectionConfirmsAbsenceAgainstTheAPIServer(t *testing.T) {
	live := handoffApplication("tenant", "app", "live-uid")
	aud, ledger := audHandoff(live), ledgerHandoff(live)
	cache := handoffGCClient(t, aud, ledger)
	apiServer := handoffGCClient(t, live)
	r := &AccessApplicationReconciler{Client: cache, APIReader: apiServer}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(live)}); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cache, aud) || !secretExists(t, cache, ledger) {
		t.Fatal("a lagging cache made a live application's handoffs look orphaned")
	}
}

func TestHandoffCollectionSteadyStateStaysInTheCache(t *testing.T) {
	live := handoffApplication("tenant", "app", "live-uid")
	kube := handoffGCClient(t, live, audHandoff(live), ledgerHandoff(live))
	reader := &countingReader{Reader: kube}
	r := &AccessApplicationReconciler{Client: kube, APIReader: reader}

	if err := r.collectOrphanedHandoffs(context.Background(), client.ObjectKeyFromObject(live), live); err != nil {
		t.Fatal(err)
	}
	if reader.gets != 0 {
		t.Fatalf("steady-state handoff collection made %d uncached reads", reader.gets)
	}
}

func TestLedgerCollectionResolvesAmbiguousLabels(t *testing.T) {
	// "a--b/c" and "a/b--c" share the ledger label "a--b--c".
	left := handoffApplication("a--b", "c", "left-uid")
	right := handoffApplication("a", "b--c", "right-uid")
	leftLedger := ledgerHandoff(left)
	deadLedger := ledgerHandoff(handoffApplication("a", "b--c", "dead-uid"))
	kube := handoffGCClient(t, left, leftLedger, deadLedger)
	r := &AccessApplicationReconciler{Client: kube, APIReader: kube}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(right)}); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, kube, leftLedger) {
		t.Fatal("the ledger of a live application with a colliding label was deleted")
	}
	if secretExists(t, kube, deadLedger) {
		t.Fatal("a ledger whose UID matches no candidate application survived")
	}
}

func TestHandoffCollectionSkipsSecretsWithoutVerifiableOwner(t *testing.T) {
	dead := handoffApplication("tenant", "app", "dead-uid")
	legacy := audHandoff(dead)
	legacy.Name = accessAUDSecretName(dead, types.NamespacedName{Namespace: "tenant", Name: "legacy"})
	legacy.Labels[v1alpha1.AccessApplicationAUDSecretLabel] = "tenant--app"
	delete(legacy.Data, v1alpha1.AccessApplicationUIDSecretKey)
	renamed := audHandoff(dead)
	renamed.Name = "aud-other-uid-renamed"
	relabeled := audHandoff(dead)
	relabeled.Name = accessAUDSecretName(dead, types.NamespacedName{Namespace: "tenant", Name: "relabeled"})
	relabeled.Labels[v1alpha1.AccessApplicationAUDSecretLabel] = "unrelated"
	elsewhere := audHandoff(dead)
	elsewhere.Namespace = "tenant"
	kube := handoffGCClient(t, legacy, renamed, relabeled, elsewhere)
	r := &AccessApplicationReconciler{Client: kube, APIReader: kube}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(dead)}); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []*corev1.Secret{legacy, renamed, relabeled, elsewhere} {
		if !secretExists(t, kube, secret) {
			t.Fatalf("Secret %s/%s without a verifiable handoff owner was deleted", secret.Namespace, secret.Name)
		}
		if requests := r.mapHandoffSecretToApplications(context.Background(), secret); len(requests) != 0 {
			t.Fatalf("Secret %s/%s without a verifiable handoff owner enqueued %v", secret.Namespace, secret.Name, requests)
		}
	}
}

func TestHandoffMapperEnqueuesVanishedOwners(t *testing.T) {
	r := &AccessApplicationReconciler{}
	dead := handoffApplication("tenant", "app", "dead-uid")
	if requests := r.mapHandoffSecretToApplications(context.Background(), audHandoff(dead)); len(requests) != 1 || requests[0].NamespacedName != client.ObjectKeyFromObject(dead) {
		t.Fatalf("AUD handoff of a vanished application enqueued %v", requests)
	}
	ambiguous := ledgerHandoff(handoffApplication("a", "b--c", "dead-uid"))
	got := map[types.NamespacedName]bool{}
	for _, request := range r.mapHandoffSecretToApplications(context.Background(), ambiguous) {
		got[request.NamespacedName] = true
	}
	if len(got) != 2 || !got[types.NamespacedName{Namespace: "a", Name: "b--c"}] || !got[types.NamespacedName{Namespace: "a--b", Name: "c"}] {
		t.Fatalf("ambiguous ledger enqueued %v, want both candidate owners", got)
	}
}
