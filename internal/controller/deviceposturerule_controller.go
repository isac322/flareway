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
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

const (
	devicePostureAccountIndex        = accessAccountIndex + ".devicePosture"
	devicePostureIntegrationRefIndex = ".spec.input.integrationRef"
)

// DevicePostureRuleReconciler manages Cloudflare Zero Trust posture rules.
type DevicePostureRuleReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceposturerules;devicepostureintegrations;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceposturerules,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceposturerules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceposturerules/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one DevicePostureRule with its Cloudflare posture rule.
func (r *DevicePostureRuleReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.DevicePostureRule)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DevicePostureRuleFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.DevicePostureRuleFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	operation := authz.Request{PlatformObject: true}
	if ref := object.Spec.Input.IntegrationRef; ref != nil && ref.ExternalID == "" && ref.ObjectRef != nil &&
		ref.ObjectRef.Namespace != "" && ref.ObjectRef.Namespace != object.Namespace {
		operation.DevicePostureIntegrationRef = true
	}
	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, operation, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, nil, object.Status.RuleID, metav1.ConditionFalse, "Pending", err.Error())
		return ctrl.Result{}, err
	}
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		id := object.Spec.ExternalRef.RuleID
		remote, getErr := api.GetDevicePostureRule(ctx, id)
		if getErr != nil {
			return r.finishRemoteError(ctx, object, getErr)
		}
		if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, &remote, id, metav1.ConditionFalse, "Conflict", "remote device posture rule name does not match expectation")
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, &remote, id, metav1.ConditionTrue, "Ready", "Device posture rule is observed")
	}
	if err = validateDevicePostureRuleSpec(&object.Spec); err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, nil, object.Status.RuleID, metav1.ConditionFalse, "Invalid", err.Error())
	}

	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	description := object.Spec.Description
	if description != "" {
		description += "\n"
	}
	description += name

	connectionID, err := r.resolveIntegrationID(ctx, object, account, api)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, nil, object.Status.RuleID, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	input := flarecloudflare.DevicePostureRuleInput{Name: name, Type: object.Spec.Type, Description: description, Schedule: object.Spec.Schedule, Expiration: object.Spec.Expiration, Match: object.Spec.Match, Input: object.Spec.Input, ConnectionID: connectionID}

	id := object.Status.RuleID
	var remote flarecloudflare.DevicePostureRule
	if id == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			id = object.Spec.ExternalRef.RuleID
			remote, err = api.GetDevicePostureRule(ctx, id)
			if err != nil {
				return r.finishRemoteError(ctx, object, err)
			}
			if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
				return ctrl.Result{}, r.patchStatus(ctx, object, &remote, id, metav1.ConditionFalse, "Conflict", "remote device posture rule name does not match adoption expectation")
			}
			if !devicePostureRuleMatches(input, remote) {
				remote, err = api.UpdateDevicePostureRule(ctx, id, input)
				if err != nil {
					return r.finishRemoteError(ctx, object, err)
				}
			}
		} else {
			remote, err = api.CreateDevicePostureRule(ctx, input)
			if err != nil {
				return r.finishRemoteError(ctx, object, err)
			}
			id = remote.ID
		}
	} else {
		if !object.Status.OwnershipVerified {
			return ctrl.Result{}, r.patchStatus(ctx, object, nil, id, metav1.ConditionFalse, "Conflict", "remote device posture rule ID is not verified as owned or adopted")
		}
		remote, err = api.GetDevicePostureRule(ctx, id)
		if err != nil {
			return r.finishRemoteError(ctx, object, err)
		}
		if !devicePostureRuleMatches(input, remote) {
			remote, err = api.UpdateDevicePostureRule(ctx, id, input)
			if err != nil {
				return r.finishRemoteError(ctx, object, err)
			}
		}
	}
	return ctrl.Result{}, r.patchStatus(ctx, object, &remote, id, metav1.ConditionTrue, "Ready", "Device posture rule is synchronized")
}

func (r *DevicePostureRuleReconciler) resolveIntegrationID(ctx context.Context, object *v1alpha1.DevicePostureRule, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI) (string, error) {
	ref := object.Spec.Input.IntegrationRef
	if ref == nil {
		return "", nil
	}
	if ref.ExternalID != "" {
		integrationAPI, ok := api.(flarecloudflare.DevicePostureIntegrationAPI)
		if !ok {
			return "", errors.New("the Cloudflare client does not support device posture integrations")
		}
		remote, err := integrationAPI.GetDevicePostureIntegration(ctx, ref.ExternalID)
		if err != nil {
			return "", fmt.Errorf("validate external DevicePostureIntegration: %w", err)
		}
		if expected, ok := devicePostureIntegrationTypeForRule(object.Spec.Type); ok && remote.Type != expected {
			return "", fmt.Errorf("the DevicePostureIntegration type %q is not valid for %s; want %q", remote.Type, object.Spec.Type, expected)
		}
		return ref.ExternalID, nil
	}
	if ref.ObjectRef == nil {
		return "", errors.New("input.integrationRef.objectRef is required when externalId is unset")
	}
	targetNamespace := ref.ObjectRef.Namespace
	if targetNamespace == "" {
		targetNamespace = object.Namespace
	}
	var integration v1alpha1.DevicePostureIntegration
	if err := r.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: ref.ObjectRef.Name}, &integration); err != nil {
		return "", err
	}
	if err := validateAccessReference(object.Namespace, targetNamespace, "DevicePostureIntegration", account.Name, integration.DeletionTimestamp, integration.Status.Conditions, integration.Spec.AccountRef.Name); err != nil {
		return "", err
	}
	if expected, ok := devicePostureIntegrationTypeForRule(object.Spec.Type); ok && integration.Spec.Type != expected {
		return "", fmt.Errorf("referenced DevicePostureIntegration type %q is not valid for %s; want %q", integration.Spec.Type, object.Spec.Type, expected)
	}
	if integration.Status.IntegrationID == "" {
		return "", errors.New("referenced DevicePostureIntegration is not ready")
	}
	return integration.Status.IntegrationID, nil
}

func devicePostureIntegrationTypeForRule(ruleType v1alpha1.DevicePostureRuleType) (v1alpha1.DevicePostureIntegrationType, bool) {
	switch ruleType {
	case v1alpha1.DevicePostureRuleTypeTanium, v1alpha1.DevicePostureRuleTypeTaniumS2S:
		return v1alpha1.DevicePostureIntegrationTypeTaniumS2S, true
	case v1alpha1.DevicePostureRuleTypeCrowdstrikeS2S:
		return v1alpha1.DevicePostureIntegrationTypeCrowdstrikeS2S, true
	case v1alpha1.DevicePostureRuleTypeIntune:
		return v1alpha1.DevicePostureIntegrationTypeIntune, true
	case v1alpha1.DevicePostureRuleTypeWorkspaceOne:
		return v1alpha1.DevicePostureIntegrationTypeWorkspaceOne, true
	case v1alpha1.DevicePostureRuleTypeKolide:
		return v1alpha1.DevicePostureIntegrationTypeKolide, true
	case v1alpha1.DevicePostureRuleTypeSentinelOneS2S:
		return v1alpha1.DevicePostureIntegrationTypeSentinelOneS2S, true
	case v1alpha1.DevicePostureRuleTypeCustomS2S:
		return v1alpha1.DevicePostureIntegrationTypeCustomS2S, true
	default:
		return "", false
	}
}

func devicePostureRuleMatches(input flarecloudflare.DevicePostureRuleInput, remote flarecloudflare.DevicePostureRule) bool {
	desiredInput := input.Input
	if input.ConnectionID != "" {
		desiredInput.IntegrationRef = &v1alpha1.DevicePostureIntegrationReference{ExternalID: input.ConnectionID}
	}
	return remote.Name == input.Name && remote.Type == input.Type && remote.Description == input.Description && remote.Schedule == input.Schedule && remote.Expiration == input.Expiration && slices.Equal(remote.Match, input.Match) && devicePostureInputsEqual(remote.Input, desiredInput)
}

func normalizeDevicePostureInput(value v1alpha1.DevicePostureInput) v1alpha1.DevicePostureInput {
	if len(value.AuthState) == 0 {
		value.AuthState = nil
	} else {
		value.AuthState = slices.Clone(value.AuthState)
		slices.Sort(value.AuthState)
	}
	if len(value.CheckDisks) == 0 {
		value.CheckDisks = nil
	} else {
		value.CheckDisks = slices.Clone(value.CheckDisks)
		slices.Sort(value.CheckDisks)
	}
	if len(value.ExtendedKeyUsage) == 0 {
		value.ExtendedKeyUsage = nil
	} else {
		value.ExtendedKeyUsage = slices.Clone(value.ExtendedKeyUsage)
		slices.Sort(value.ExtendedKeyUsage)
	}
	if len(value.SubjectAlternativeNames) == 0 {
		value.SubjectAlternativeNames = nil
	} else {
		value.SubjectAlternativeNames = slices.Clone(value.SubjectAlternativeNames)
		slices.Sort(value.SubjectAlternativeNames)
	}
	if value.Locations != nil {
		if len(value.Locations.Paths) == 0 && len(value.Locations.TrustStores) == 0 {
			value.Locations = nil
		} else {
			locations := *value.Locations
			locations.Paths = slices.Clone(locations.Paths)
			slices.Sort(locations.Paths)
			locations.TrustStores = slices.Clone(locations.TrustStores)
			slices.Sort(locations.TrustStores)
			value.Locations = &locations
		}
	}
	return value
}

func devicePostureInputsEqual(left, right v1alpha1.DevicePostureInput) bool {
	left = normalizeDevicePostureInput(left)
	right = normalizeDevicePostureInput(right)
	if (left.Score == nil) != (right.Score == nil) || left.Score != nil && left.Score.Cmp(*right.Score) != 0 {
		return false
	}
	if (left.TotalScore == nil) != (right.TotalScore == nil) || left.TotalScore != nil && left.TotalScore.Cmp(*right.TotalScore) != 0 {
		return false
	}
	if (left.ActiveThreats == nil) != (right.ActiveThreats == nil) || left.ActiveThreats != nil && left.ActiveThreats.Cmp(*right.ActiveThreats) != 0 {
		return false
	}
	if (left.UpdateWindowDays == nil) != (right.UpdateWindowDays == nil) || left.UpdateWindowDays != nil && left.UpdateWindowDays.Cmp(*right.UpdateWindowDays) != 0 {
		return false
	}
	left.Score, right.Score = nil, nil
	left.TotalScore, right.TotalScore = nil, nil
	left.ActiveThreats, right.ActiveThreats = nil, nil
	left.UpdateWindowDays, right.UpdateWindowDays = nil, nil
	return reflect.DeepEqual(left, right)
}

func validateDevicePostureRuleSpec(spec *v1alpha1.DevicePostureRuleSpec) error {
	fields := devicePostureInputFieldSet(spec.Input)
	var allowed, required []string
	switch spec.Type {
	case v1alpha1.DevicePostureRuleTypeGateway, v1alpha1.DevicePostureRuleTypeWARP:
	case v1alpha1.DevicePostureRuleTypeFile:
		allowed, required = []string{"operatingSystem", "path", "exists", "sha256", "thumbprint"}, []string{"operatingSystem", "path"}
	case v1alpha1.DevicePostureRuleTypeApplication, v1alpha1.DevicePostureRuleTypeSentinelOne, v1alpha1.DevicePostureRuleTypeCarbonBlack:
		allowed, required = []string{"operatingSystem", "path", "sha256", "thumbprint"}, []string{"operatingSystem", "path"}
	case v1alpha1.DevicePostureRuleTypeTanium, v1alpha1.DevicePostureRuleTypeTaniumS2S:
		allowed, required = []string{"integrationRef", "eidLastSeen", "operator", "riskLevel", "scoreOperator", "totalScore"}, []string{"integrationRef"}
	case v1alpha1.DevicePostureRuleTypeDiskEncryption:
		allowed = []string{"checkDisks", "requireAll"}
	case v1alpha1.DevicePostureRuleTypeSerialNumber:
		allowed, required = []string{"id"}, []string{"id"}
	case v1alpha1.DevicePostureRuleTypeFirewall:
		allowed, required = []string{"enabled", "operatingSystem"}, []string{"enabled", "operatingSystem"}
	case v1alpha1.DevicePostureRuleTypeOSVersion:
		allowed, required = []string{"operatingSystem", "operator", "version", "osDistroName", "osDistroRevision", "osVersionExtra"}, []string{"operatingSystem", "operator", "version"}
	case v1alpha1.DevicePostureRuleTypeDomainJoined:
		allowed, required = []string{"operatingSystem", "domain"}, []string{"operatingSystem"}
	case v1alpha1.DevicePostureRuleTypeClientCertificate:
		allowed, required = []string{"certificateId", "commonName"}, []string{"certificateId", "commonName"}
	case v1alpha1.DevicePostureRuleTypeClientCertificateV2:
		allowed, required = []string{"certificateId", "checkPrivateKey", "operatingSystem", "commonName", "extendedKeyUsage", "locations", "subjectAlternativeNames"}, []string{"certificateId", "checkPrivateKey", "operatingSystem"}
	case v1alpha1.DevicePostureRuleTypeAntivirus:
		allowed = []string{"updateWindowDays"}
	case v1alpha1.DevicePostureRuleTypeUniqueClientID:
		allowed, required = []string{"id", "operatingSystem"}, []string{"id", "operatingSystem"}
	case v1alpha1.DevicePostureRuleTypeKolide:
		allowed, required = []string{"integrationRef", "authState", "countOperator", "issueCount"}, []string{"integrationRef"}
	case v1alpha1.DevicePostureRuleTypeCrowdstrikeS2S:
		allowed, required = []string{"integrationRef", "lastSeen", "operator", "os", "overall", "sensorConfig", "state", "version", "versionOperator"}, []string{"integrationRef"}
	case v1alpha1.DevicePostureRuleTypeIntune, v1alpha1.DevicePostureRuleTypeWorkspaceOne:
		allowed, required = []string{"integrationRef", "complianceStatus"}, []string{"integrationRef", "complianceStatus"}
	case v1alpha1.DevicePostureRuleTypeSentinelOneS2S:
		allowed, required = []string{"integrationRef", "activeThreats", "infected", "isActive", "networkStatus", "operationalState", "operator"}, []string{"integrationRef"}
	case v1alpha1.DevicePostureRuleTypeCustomS2S:
		allowed, required = []string{"integrationRef", "operator", "score"}, []string{"integrationRef", "operator", "score"}
	default:
		return fmt.Errorf("unsupported device posture rule type %q", spec.Type)
	}
	for field := range fields {
		if !slices.Contains(allowed, field) {
			return fmt.Errorf("input.%s is not valid for %s", field, spec.Type)
		}
	}
	for _, field := range required {
		if !fields[field] {
			return fmt.Errorf("input.%s is required for %s", field, spec.Type)
		}
	}
	if ref := spec.Input.IntegrationRef; ref != nil {
		if (ref.ObjectRef == nil) == (ref.ExternalID == "") {
			return errors.New("input.integrationRef requires exactly one of objectRef or externalId")
		}
		if ref.ObjectRef != nil && ref.ObjectRef.Name == "" {
			return errors.New("input.integrationRef.objectRef.name is required")
		}
	}
	if err := validateDevicePosturePlatform(spec.Type, spec.Input.OperatingSystem); err != nil {
		return err
	}
	return validateDevicePostureEnums(spec)
}

func validateDevicePosturePlatform(ruleType v1alpha1.DevicePostureRuleType, platform v1alpha1.DevicePosturePlatform) error {
	if platform == "" {
		return nil
	}
	var allowed []v1alpha1.DevicePosturePlatform
	switch ruleType {
	case v1alpha1.DevicePostureRuleTypeFile, v1alpha1.DevicePostureRuleTypeApplication, v1alpha1.DevicePostureRuleTypeSentinelOne, v1alpha1.DevicePostureRuleTypeCarbonBlack, v1alpha1.DevicePostureRuleTypeClientCertificateV2:
		allowed = []v1alpha1.DevicePosturePlatform{v1alpha1.DevicePosturePlatformWindows, v1alpha1.DevicePosturePlatformLinux, v1alpha1.DevicePosturePlatformMac}
	case v1alpha1.DevicePostureRuleTypeFirewall:
		allowed = []v1alpha1.DevicePosturePlatform{v1alpha1.DevicePosturePlatformWindows, v1alpha1.DevicePosturePlatformMac}
	case v1alpha1.DevicePostureRuleTypeOSVersion, v1alpha1.DevicePostureRuleTypeDomainJoined:
		allowed = []v1alpha1.DevicePosturePlatform{v1alpha1.DevicePosturePlatformWindows}
	case v1alpha1.DevicePostureRuleTypeUniqueClientID:
		allowed = []v1alpha1.DevicePosturePlatform{v1alpha1.DevicePosturePlatformAndroid, v1alpha1.DevicePosturePlatformIOS, v1alpha1.DevicePosturePlatformChromeOS}
	default:
		return nil
	}
	if !slices.Contains(allowed, platform) {
		return fmt.Errorf("input.operatingSystem %q is not valid for %s", platform, ruleType)
	}
	return nil
}
func validateDevicePostureEnums(spec *v1alpha1.DevicePostureRuleSpec) error {
	input := spec.Input
	operators := []v1alpha1.DevicePostureOperator{v1alpha1.DevicePostureOperatorLessThan, v1alpha1.DevicePostureOperatorLessThanOrEqual, v1alpha1.DevicePostureOperatorGreaterThan, v1alpha1.DevicePostureOperatorGreaterThanOrEqual, v1alpha1.DevicePostureOperatorEqual}
	for name, value := range map[string]v1alpha1.DevicePostureOperator{"operator": input.Operator, "versionOperator": input.VersionOperator, "scoreOperator": input.ScoreOperator, "countOperator": input.CountOperator} {
		if value != "" && !slices.Contains(operators, value) {
			return fmt.Errorf("input.%s %q is invalid", name, value)
		}
	}
	platforms := []v1alpha1.DevicePosturePlatform{v1alpha1.DevicePosturePlatformWindows, v1alpha1.DevicePosturePlatformMac, v1alpha1.DevicePosturePlatformLinux, v1alpha1.DevicePosturePlatformAndroid, v1alpha1.DevicePosturePlatformIOS, v1alpha1.DevicePosturePlatformChromeOS}
	for i := range spec.Match {
		if !slices.Contains(platforms, spec.Match[i].Platform) {
			return fmt.Errorf("match[%d].platform %q is invalid", i, spec.Match[i].Platform)
		}
	}
	if input.ComplianceStatus != "" {
		intuneValues := []v1alpha1.DevicePostureComplianceStatus{v1alpha1.DevicePostureComplianceCompliant, v1alpha1.DevicePostureComplianceNonCompliant, v1alpha1.DevicePostureComplianceUnknown, v1alpha1.DevicePostureComplianceNotApplicable, v1alpha1.DevicePostureComplianceInGracePeriod, v1alpha1.DevicePostureComplianceError}
		workspaceValues := intuneValues[:3]
		allowed := intuneValues
		if spec.Type == v1alpha1.DevicePostureRuleTypeWorkspaceOne {
			allowed = workspaceValues
		}
		if !slices.Contains(allowed, input.ComplianceStatus) {
			return fmt.Errorf("input.complianceStatus %q is invalid for %s", input.ComplianceStatus, spec.Type)
		}
	}
	if input.NetworkStatus != "" && !slices.Contains([]v1alpha1.DevicePostureNetworkStatus{v1alpha1.DevicePostureNetworkConnected, v1alpha1.DevicePostureNetworkDisconnected, v1alpha1.DevicePostureNetworkDisconnecting, v1alpha1.DevicePostureNetworkConnecting}, input.NetworkStatus) {
		return fmt.Errorf("input.networkStatus %q is invalid", input.NetworkStatus)
	}
	if input.OperationalState != "" && !slices.Contains([]v1alpha1.DevicePostureOperationalState{v1alpha1.DevicePostureOperationalNotApplicable, v1alpha1.DevicePostureOperationalPartiallyDisabled, v1alpha1.DevicePostureOperationalAutomaticallyFullyDisabled, v1alpha1.DevicePostureOperationalFullyDisabled, v1alpha1.DevicePostureOperationalAutomaticallyPartiallyDisabled, v1alpha1.DevicePostureOperationalDisabledError, v1alpha1.DevicePostureOperationalDatabaseCorruption}, input.OperationalState) {
		return fmt.Errorf("input.operationalState %q is invalid", input.OperationalState)
	}
	if input.State != "" && !slices.Contains([]v1alpha1.DevicePostureState{v1alpha1.DevicePostureStateOnline, v1alpha1.DevicePostureStateOffline, v1alpha1.DevicePostureStateUnknown}, input.State) {
		return fmt.Errorf("input.state %q is invalid", input.State)
	}
	if input.RiskLevel != "" && !slices.Contains([]v1alpha1.DevicePostureRiskLevel{v1alpha1.DevicePostureRiskLow, v1alpha1.DevicePostureRiskMedium, v1alpha1.DevicePostureRiskHigh, v1alpha1.DevicePostureRiskCritical}, input.RiskLevel) {
		return fmt.Errorf("input.riskLevel %q is invalid", input.RiskLevel)
	}
	for i := range input.AuthState {
		if !slices.Contains([]v1alpha1.DevicePostureKolideAuthState{v1alpha1.DevicePostureKolideAuthGood, v1alpha1.DevicePostureKolideAuthNotified, v1alpha1.DevicePostureKolideAuthWillBlock, v1alpha1.DevicePostureKolideAuthBlocked}, input.AuthState[i]) {
			return fmt.Errorf("input.authState[%d] %q is invalid", i, input.AuthState[i])
		}
	}
	for i := range input.ExtendedKeyUsage {
		if !slices.Contains([]v1alpha1.DevicePostureExtendedKeyUsage{v1alpha1.DevicePostureExtendedKeyUsageClientAuth, v1alpha1.DevicePostureExtendedKeyUsageEmailProtection}, input.ExtendedKeyUsage[i]) {
			return fmt.Errorf("input.extendedKeyUsage[%d] %q is invalid", i, input.ExtendedKeyUsage[i])
		}
	}
	if input.Locations != nil {
		for i := range input.Locations.TrustStores {
			if !slices.Contains([]v1alpha1.DevicePostureTrustStore{v1alpha1.DevicePostureTrustStoreSystem, v1alpha1.DevicePostureTrustStoreUser}, input.Locations.TrustStores[i]) {
				return fmt.Errorf("input.locations.trustStores[%d] %q is invalid", i, input.Locations.TrustStores[i])
			}
		}
	}
	if input.Score != nil && (input.Score.Sign() < 0 || input.Score.CmpInt64(100) > 0) {
		return errors.New("input.score must be between 0 and 100")
	}
	if input.UpdateWindowDays != nil && input.UpdateWindowDays.Sign() < 0 {
		return errors.New("input.updateWindowDays must not be negative")
	}
	if input.ActiveThreats != nil && input.ActiveThreats.Sign() < 0 {
		return errors.New("input.activeThreats must not be negative")
	}
	return nil
}

func devicePostureInputFieldSet(value v1alpha1.DevicePostureInput) map[string]bool {
	fields := map[string]bool{}
	add := func(name string, present bool) {
		if present {
			fields[name] = true
		}
	}
	add("id", value.ID != "")
	add("integrationRef", value.IntegrationRef != nil)
	add("operatingSystem", value.OperatingSystem != "")
	add("path", value.Path != "")
	add("sha256", value.SHA256 != "")
	add("domain", value.Domain != "")
	add("version", value.Version != "")
	add("versionOperator", value.VersionOperator != "")
	add("operator", value.Operator != "")
	add("enabled", value.Enabled != nil)
	add("exists", value.Exists != nil)
	add("requireAll", value.RequireAll != nil)
	add("infected", value.Infected != nil)
	add("isActive", value.IsActive != nil)
	add("checkPrivateKey", value.CheckPrivateKey != nil)
	add("complianceStatus", value.ComplianceStatus != "")
	add("networkStatus", value.NetworkStatus != "")
	add("operationalState", value.OperationalState != "")
	add("state", value.State != "")
	add("riskLevel", value.RiskLevel != "")
	add("score", value.Score != nil)
	add("scoreOperator", value.ScoreOperator != "")
	add("totalScore", value.TotalScore != nil)
	add("activeThreats", value.ActiveThreats != nil)
	add("updateWindowDays", value.UpdateWindowDays != nil)
	add("lastSeen", value.LastSeen != "")
	add("eidLastSeen", value.EIDLastSeen != "")
	add("issueCount", value.IssueCount != "")
	add("countOperator", value.CountOperator != "")
	add("sensorConfig", value.SensorConfig != "")
	add("certificateId", value.CertificateID != "")
	add("commonName", value.CommonName != "")
	add("thumbprint", value.Thumbprint != "")
	add("os", value.OS != "")
	add("osDistroName", value.OSDistroName != "")
	add("osDistroRevision", value.OSDistroRevision != "")
	add("osVersionExtra", value.OSVersionExtra != "")
	add("overall", value.Overall != "")
	add("authState", len(value.AuthState) != 0)
	add("checkDisks", len(value.CheckDisks) != 0)
	add("extendedKeyUsage", len(value.ExtendedKeyUsage) != 0)
	add("locations", value.Locations != nil)
	add("subjectAlternativeNames", len(value.SubjectAlternativeNames) != 0)
	return fields
}

func (r *DevicePostureRuleReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.DevicePostureRule) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DevicePostureRuleFinalizer) {
		return nil
	}
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete && object.Status.RuleID != "" && object.Status.OwnershipVerified {
		api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteDevicePostureRule(ctx, object.Status.RuleID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.DevicePostureRuleFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *DevicePostureRuleReconciler) patchStatus(ctx context.Context, object *v1alpha1.DevicePostureRule, remote *flarecloudflare.DevicePostureRule, id string, status metav1.ConditionStatus, reason, message string) error {
	baseObject := object.DeepCopy()
	if remote != nil {
		object.Status.RuleID = id
		object.Status.OwnershipVerified = object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly
		object.Status.Observed = &v1alpha1.DevicePostureRuleObservedState{Name: remote.Name, Type: remote.Type, Description: remote.Description, Enabled: remote.Enabled, Schedule: remote.Schedule, Expiration: remote.Expiration, Match: remote.Match, Input: remote.Input}
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	if reflect.DeepEqual(baseObject.Status, object.Status) {
		return nil
	}
	return r.Status().Patch(ctx, object, client.MergeFrom(baseObject))
}

// finishRemoteError records the remote failure before returning it for retry.
// A missing remote object fails closed with Accepted=False; a transient error
// preserves an established Accepted=True so dependents are not torn down by a
// temporary Cloudflare outage. The remote argument stays nil so a failed call
// never stamps ownership or changes the recorded ID.
func (r *DevicePostureRuleReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.DevicePostureRule, err error) (ctrl.Result, error) {
	reason := "CloudflareError"
	if flarecloudflare.IsNotFound(err) {
		reason = "RemoteMissing"
	}
	conditions := []metav1.Condition{accessCondition(object.Generation, "Ready", metav1.ConditionFalse, reason, err.Error())}
	if reason == "RemoteMissing" || !metaConditionTrue(object.Status.Conditions, "Accepted") {
		conditions = append([]metav1.Condition{accessCondition(object.Generation, "Accepted", metav1.ConditionFalse, reason, err.Error())}, conditions...)
	}
	baseObject := object.DeepCopy()
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), conditions...)
	if !reflect.DeepEqual(baseObject.Status, object.Status) {
		if patchErr := r.Status().Patch(ctx, object, client.MergeFrom(baseObject)); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
	}
	return ctrl.Result{}, err
}

func (r *DevicePostureRuleReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the DevicePostureRule controller and dependency watches.
func (r *DevicePostureRuleReconciler) SetupWithManager(manager ctrl.Manager) error {
	indexer := manager.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &v1alpha1.DevicePostureRule{}, devicePostureAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.DevicePostureRule).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index DevicePostureRule accounts: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.DevicePostureRule{}, devicePostureIntegrationRefIndex, func(object client.Object) []string {
		rule := object.(*v1alpha1.DevicePostureRule)
		ref := rule.Spec.Input.IntegrationRef
		if ref == nil || ref.ObjectRef == nil || ref.ObjectRef.Name == "" {
			return nil
		}
		namespace := ref.ObjectRef.Namespace
		if namespace == "" {
			namespace = rule.Namespace
		}
		return []string{namespace + "/" + ref.ObjectRef.Name}
	}); err != nil {
		return fmt.Errorf("index DevicePostureRule integrations: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.DevicePostureRule{}).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.rulesForAccount)).Watches(&v1alpha1.DevicePostureIntegration{}, handler.EnqueueRequestsFromMapFunc(r.rulesForIntegration)).Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.rulesForNamespace)).Complete(observedReconciler("device-posture-rule", r))
}

func (r *DevicePostureRuleReconciler) rulesForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.DevicePostureRuleList
	if err := r.List(ctx, &list, client.MatchingFields{devicePostureAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	return devicePostureRuleRequests(list.Items)
}

func (r *DevicePostureRuleReconciler) rulesForIntegration(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.DevicePostureRuleList
	key := object.GetNamespace() + "/" + object.GetName()
	if err := r.List(ctx, &list, client.MatchingFields{devicePostureIntegrationRefIndex: key}); err != nil {
		return nil
	}
	return devicePostureRuleRequests(list.Items)
}

func (r *DevicePostureRuleReconciler) rulesForNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.DevicePostureRuleList
	if err := r.List(ctx, &list, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	return devicePostureRuleRequests(list.Items)
}

func devicePostureRuleRequests(items []v1alpha1.DevicePostureRule) []reconcile.Request {
	out := make([]reconcile.Request, len(items))
	for i := range items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: items[i].Namespace, Name: items[i].Name}}
	}
	return out
}
