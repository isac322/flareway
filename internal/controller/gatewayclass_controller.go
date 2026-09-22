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
	"context"
	"fmt"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	flarewayv1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/gatewayapi"
	gatewaystatus "github.com/isac322/flareway/internal/gatewayapi/status"
)

const (
	// GatewayControllerName is the Gateway API controller name implemented by Flareway.
	GatewayControllerName gatewayv1.GatewayController = gatewayapi.ControllerName

	gatewayClassConfigKind = "GatewayClassConfig"
)

// GatewayClassReconciler reconciles GatewayClass resources owned by Flareway.
type GatewayClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=gatewayclassconfigs,verbs=get;list;watch

// Reconcile validates a GatewayClass parametersRef and publishes Flareway's supported features.
func (r *GatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	gatewayClass := &gatewayv1.GatewayClass{}
	if err := r.Get(ctx, req.NamespacedName, gatewayClass); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if gatewayClass.Spec.ControllerName != GatewayControllerName {
		return ctrl.Result{}, nil
	}

	accepted, message, err := r.validateParametersRef(ctx, gatewayClass.Spec.ParametersRef)
	if err != nil {
		return ctrl.Result{}, err
	}

	conditionStatus := metav1.ConditionTrue
	reason := string(gatewayv1.GatewayClassReasonAccepted)
	if !accepted {
		conditionStatus = metav1.ConditionFalse
		reason = string(gatewayv1.GatewayClassReasonInvalidParameters)
	}

	updated := gatewayClass.DeepCopy()
	now := metav1.Now()
	updated.Status.Conditions = gatewaystatus.SetCondition(
		updated.Status.Conditions,
		now,
		gatewaystatus.NewCondition(
			string(gatewayv1.GatewayClassConditionStatusAccepted),
			conditionStatus,
			reason,
			message,
			updated.Generation,
			now,
		),
	)
	updated.Status.SupportedFeatures = supportedFeatures()

	if reflect.DeepEqual(gatewayClass.Status, updated.Status) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Patch(ctx, updated, client.MergeFrom(gatewayClass)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch GatewayClass status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *GatewayClassReconciler) validateParametersRef(
	ctx context.Context,
	ref *gatewayv1.ParametersReference,
) (bool, string, error) {
	if ref == nil {
		return true, "GatewayClass is accepted using built-in defaults", nil
	}
	if string(ref.Group) != flarewayv1alpha1.Group || string(ref.Kind) != gatewayClassConfigKind || ref.Namespace != nil {
		return false, "parametersRef must reference cluster-scoped flareway.bhyoo.com/GatewayClassConfig", nil
	}

	config := &flarewayv1alpha1.GatewayClassConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, config); err != nil {
		if apierrors.IsNotFound(err) {
			return false, fmt.Sprintf("GatewayClassConfig %q was not found", ref.Name), nil
		}
		return false, "", fmt.Errorf("get GatewayClassConfig %q: %w", ref.Name, err)
	}
	return true, fmt.Sprintf("GatewayClassConfig %q is valid", ref.Name), nil
}

func supportedFeatures() []gatewayv1.SupportedFeature {
	featureNames := gatewayapi.SupportedFeatures()
	features := make([]gatewayv1.SupportedFeature, len(featureNames))
	for i := range featureNames {
		features[i] = gatewayv1.SupportedFeature{Name: gatewayv1.FeatureName(featureNames[i])}
	}
	return features
}

// SetupWithManager registers the GatewayClass reconciler and its configuration watch.
func (r *GatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ownedGatewayClass := predicate.NewPredicateFuncs(func(object client.Object) bool {
		gatewayClass, ok := object.(*gatewayv1.GatewayClass)
		return ok && gatewayClass.Spec.ControllerName == GatewayControllerName
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{}, builder.WithPredicates(ownedGatewayClass, desiredStateChangedPredicate)).
		Watches(
			&flarewayv1alpha1.GatewayClassConfig{},
			handler.EnqueueRequestsFromMapFunc(r.gatewayClassesForConfig),
		).
		Complete(observedReconciler("gateway-class", r))
}

func (r *GatewayClassReconciler) gatewayClassesForConfig(
	ctx context.Context,
	object client.Object,
) []reconcile.Request {
	config, ok := object.(*flarewayv1alpha1.GatewayClassConfig)
	if !ok {
		return nil
	}

	classes := &gatewayv1.GatewayClassList{}
	if err := r.List(ctx, classes); err != nil {
		log.FromContext(ctx).Error(err, "list GatewayClasses for GatewayClassConfig", "gatewayClassConfig", config.Name)
		return nil
	}

	requests := make([]reconcile.Request, 0)
	for i := range classes.Items {
		gatewayClass := &classes.Items[i]
		if gatewayClass.Spec.ControllerName != GatewayControllerName ||
			gatewayClass.Spec.ParametersRef == nil ||
			!parametersReferenceMatches(gatewayClass.Spec.ParametersRef, config.Name) {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: gatewayClass.Name}})
	}
	return requests
}

func parametersReferenceMatches(ref *gatewayv1.ParametersReference, name string) bool {
	return string(ref.Group) == flarewayv1alpha1.Group &&
		string(ref.Kind) == gatewayClassConfigKind &&
		ref.Namespace == nil &&
		ref.Name == name
}
