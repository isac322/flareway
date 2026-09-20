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
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/gatewayapi"
	gatewaystatus "github.com/isac322/flareway/internal/gatewayapi/status"
)

func (r *AccessApplicationReconciler) resolvePolicies(ctx context.Context, application *v1alpha1.AccessApplication, account *v1alpha1.CloudflareAccount, remote AccessApplicationCloudflareClient) ([]string, error) {
	ids := make([]string, 0, len(application.Spec.Policies))
	var namespace corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: application.Namespace}, &namespace); err != nil {
		return nil, fmt.Errorf("get AccessApplication namespace: %w", err)
	}
	for _, reference := range application.Spec.Policies {
		if reference.ExternalRef != nil {
			policy, err := remote.GetAccessPolicy(ctx, reference.ExternalRef.PolicyID)
			if err != nil {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("external Access policy %q could not be resolved: %v", reference.ExternalRef.PolicyID, err)}
			}
			ids = append(ids, policy.ID)
			continue
		}
		if reference.PolicyRef == nil {
			return nil, accessValidationError{reason: "Invalid", message: "policy reference is empty"}
		}
		policyNamespace := reference.PolicyRef.Namespace
		if policyNamespace == "" {
			policyNamespace = application.Namespace
		}
		var policy v1alpha1.AccessPolicy
		if err := r.Get(ctx, types.NamespacedName{Namespace: policyNamespace, Name: reference.PolicyRef.Name}, &policy); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the AccessPolicy %s/%s was not found", policyNamespace, reference.PolicyRef.Name)}
			}
			return nil, fmt.Errorf("get AccessPolicy %s/%s: %w", policyNamespace, reference.PolicyRef.Name, err)
		}
		if policy.Spec.AccountRef.Name != account.Name {
			return nil, fmt.Errorf("the AccessPolicy %s/%s uses CloudflareAccount %q, want %q", policyNamespace, policy.Name, policy.Spec.AccountRef.Name, account.Name)
		}
		if policyNamespace != application.Namespace {
			allowed := false
			for _, grant := range account.Spec.Grants {
				selector, err := metav1.LabelSelectorAsSelector(&grant.NamespaceSelector)
				if err == nil && selector.Matches(labels.Set(namespace.Labels)) && grant.AccessPolicyRefs == v1alpha1.GrantPermissionAllowed {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, fmt.Errorf("the AccessPolicy %s/%s is not permitted by CloudflareAccount grants", policyNamespace, policy.Name)
			}
		}
		if policy.Status.PolicyID == "" || !gatewaystatus.ConditionTrue(policy.Status.Conditions, accessApplicationConditionAccepted) || !policy.DeletionTimestamp.IsZero() {
			return nil, fmt.Errorf("the AccessPolicy %s/%s is not accepted", policyNamespace, policy.Name)
		}
		policyID := policy.Status.PolicyID
		if effectiveManagementPolicy(policy.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
			observed, err := remote.GetAccessPolicy(ctx, policyID)
			if err != nil {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the AccessPolicy %s/%s remote policy could not be resolved: %v", policyNamespace, policy.Name, err)}
			}
			policyID = observed.ID
		}
		ids = append(ids, policyID)
	}
	return ids, nil
}
func (r *AccessApplicationReconciler) resolveIdentityProviders(ctx context.Context, application *v1alpha1.AccessApplication, account *v1alpha1.CloudflareAccount, remote AccessApplicationCloudflareClient) ([]string, error) {
	ids := make([]string, 0, len(application.Spec.Application.AllowedIDPRefs))
	for _, reference := range application.Spec.Application.AllowedIDPRefs {
		id, err := r.resolveIdentityProviderReference(ctx, application.Namespace, reference, account, remote)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (r *AccessApplicationReconciler) resolveIdentityProviderReference(
	ctx context.Context,
	namespace string,
	reference v1alpha1.AccessIdentityProviderReference,
	account *v1alpha1.CloudflareAccount,
	remote AccessApplicationCloudflareClient,
) (string, error) {
	if reference.ExternalID != "" {
		provider, err := remote.GetIdentityProvider(ctx, reference.ExternalID)
		if err != nil {
			return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("external IdentityProvider %q could not be resolved: %v", reference.ExternalID, err)}
		}
		return provider.ID, nil
	}
	var provider v1alpha1.IdentityProvider
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: reference.Name}, &provider); err != nil {
		if apierrors.IsNotFound(err) {
			return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the IdentityProvider %s/%s was not found", namespace, reference.Name)}
		}
		return "", fmt.Errorf("get IdentityProvider %s/%s: %w", namespace, reference.Name, err)
	}
	if !provider.DeletionTimestamp.IsZero() {
		return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the IdentityProvider %s/%s is deleting", namespace, provider.Name)}
	}
	if provider.Spec.AccountRef.Name != account.Name {
		return "", fmt.Errorf("the IdentityProvider %s/%s uses CloudflareAccount %q, want %q", namespace, provider.Name, provider.Spec.AccountRef.Name, account.Name)
	}
	if provider.Status.IDPID == "" || !gatewaystatus.ConditionTrue(provider.Status.Conditions, accessApplicationConditionAccepted) {
		return "", fmt.Errorf("the IdentityProvider %s/%s is not accepted", namespace, provider.Name)
	}
	providerID := provider.Status.IDPID
	if effectiveManagementPolicy(provider.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		observed, err := remote.GetIdentityProvider(ctx, providerID)
		if err != nil {
			return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the IdentityProvider %s/%s remote provider could not be resolved: %v", namespace, provider.Name, err)}
		}
		providerID = observed.ID
	}
	return providerID, nil
}

func (r *AccessApplicationReconciler) resolveApplicationSCIMConfig(
	ctx context.Context,
	application *v1alpha1.AccessApplication,
	account *v1alpha1.CloudflareAccount,
	remote AccessApplicationCloudflareClient,
) (*flarecloudflare.AccessSCIMConfigInput, error) {
	config := application.Spec.Application.SCIMConfig
	if config == nil {
		return nil, nil
	}
	idpID, err := r.resolveIdentityProviderReference(ctx, application.Namespace, config.IDPRef, account, remote)
	if err != nil {
		return nil, err
	}
	authentication, err := r.resolveSCIMAuthentication(ctx, application, account, config.Authentication)
	if err != nil {
		return nil, err
	}
	mappings := make([]flarecloudflare.AccessSCIMMapping, 0, len(config.Mappings))
	for _, mapping := range config.Mappings {
		var operations *flarecloudflare.AccessSCIMMappingOperations
		if mapping.Operations != nil {
			operations = &flarecloudflare.AccessSCIMMappingOperations{
				Create: mapping.Operations.Create,
				Update: mapping.Operations.Update,
				Delete: mapping.Operations.Delete,
			}
		}
		mappings = append(mappings, flarecloudflare.AccessSCIMMapping{
			Schema: mapping.Schema, Enabled: mapping.Enabled, Filter: mapping.Filter, Operations: operations,
			Strictness:       flarecloudflare.AccessSCIMMappingStrictness(mapping.Strictness),
			TransformJSONata: mapping.TransformJSONata,
		})
	}
	return &flarecloudflare.AccessSCIMConfigInput{
		IdentityProviderUID: idpID,
		RemoteURI:           config.RemoteURI,
		Authentication:      authentication,
		DeactivateOnDelete:  config.DeactivateOnDelete,
		Enabled:             config.Enabled,
		Mappings:            mappings,
	}, nil
}

func (r *AccessApplicationReconciler) resolveSCIMAuthentication(
	ctx context.Context,
	application *v1alpha1.AccessApplication,
	account *v1alpha1.CloudflareAccount,
	authentication *v1alpha1.AccessSCIMAuthentication,
) ([]flarecloudflare.AccessSCIMAuthenticationInput, error) {
	if authentication == nil {
		return nil, nil
	}
	if len(authentication.Multiple) > 0 {
		result := make([]flarecloudflare.AccessSCIMAuthenticationInput, 0, len(authentication.Multiple))
		for _, method := range authentication.Multiple {
			resolved, err := r.resolveSCIMAuthenticationMethod(ctx, application, account, method)
			if err != nil {
				return nil, err
			}
			result = append(result, resolved)
		}
		return result, nil
	}
	method := v1alpha1.AccessSCIMAuthenticationMethod{
		HTTPBasic: authentication.HTTPBasic, OAuthBearerToken: authentication.OAuthBearerToken,
		OAuth2: authentication.OAuth2, AccessServiceToken: authentication.AccessServiceToken,
	}
	resolved, err := r.resolveSCIMAuthenticationMethod(ctx, application, account, method)
	if err != nil {
		return nil, err
	}
	return []flarecloudflare.AccessSCIMAuthenticationInput{resolved}, nil
}

func (r *AccessApplicationReconciler) resolveSCIMAuthenticationMethod(
	ctx context.Context,
	application *v1alpha1.AccessApplication,
	account *v1alpha1.CloudflareAccount,
	method v1alpha1.AccessSCIMAuthenticationMethod,
) (flarecloudflare.AccessSCIMAuthenticationInput, error) {
	switch {
	case method.HTTPBasic != nil:
		password, err := r.readAccessApplicationSecret(ctx, application.Namespace, method.HTTPBasic.PasswordSecretRef)
		return flarecloudflare.AccessSCIMAuthenticationInput{
			Scheme: flarecloudflare.AccessSCIMAuthenticationSchemeHTTPBasic,
			User:   method.HTTPBasic.User, Password: password,
		}, err
	case method.OAuthBearerToken != nil:
		token, err := r.readAccessApplicationSecret(ctx, application.Namespace, method.OAuthBearerToken.TokenSecretRef)
		return flarecloudflare.AccessSCIMAuthenticationInput{
			Scheme: flarecloudflare.AccessSCIMAuthenticationSchemeOAuthBearerToken, Token: token,
		}, err
	case method.OAuth2 != nil:
		clientSecret, err := r.readAccessApplicationSecret(ctx, application.Namespace, method.OAuth2.ClientSecretRef)
		return flarecloudflare.AccessSCIMAuthenticationInput{
			Scheme:           flarecloudflare.AccessSCIMAuthenticationSchemeOAuth2,
			AuthorizationURL: method.OAuth2.AuthorizationURL, ClientID: method.OAuth2.ClientID,
			ClientSecret: clientSecret, TokenURL: method.OAuth2.TokenURL, Scopes: slices.Clone(method.OAuth2.Scopes),
		}, err
	case method.AccessServiceToken != nil:
		namespace := method.AccessServiceToken.ServiceTokenRef.Namespace
		if namespace == "" {
			namespace = application.Namespace
		}
		if err := authorizeAccessReference(ctx, r.Client, application.Namespace, namespace, account, "ServiceToken"); err != nil {
			return flarecloudflare.AccessSCIMAuthenticationInput{}, err
		}
		var token v1alpha1.ServiceToken
		if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: method.AccessServiceToken.ServiceTokenRef.Name}, &token); err != nil {
			if apierrors.IsNotFound(err) {
				return flarecloudflare.AccessSCIMAuthenticationInput{}, accessValidationError{
					reason: "TargetNotFound", message: fmt.Sprintf("the ServiceToken %s/%s was not found", namespace, method.AccessServiceToken.ServiceTokenRef.Name),
				}
			}
			return flarecloudflare.AccessSCIMAuthenticationInput{}, fmt.Errorf("get ServiceToken %s/%s: %w", namespace, method.AccessServiceToken.ServiceTokenRef.Name, err)
		}
		if token.Spec.AccountRef.Name != account.Name || token.Status.TokenID == "" || token.Status.ClientID == "" ||
			!gatewaystatus.ConditionTrue(token.Status.Conditions, accessApplicationConditionAccepted) || !token.DeletionTimestamp.IsZero() {
			return flarecloudflare.AccessSCIMAuthenticationInput{}, accessValidationError{
				reason: "TargetNotFound", message: fmt.Sprintf("the ServiceToken %s/%s is not accepted for CloudflareAccount %q", namespace, token.Name, account.Name),
			}
		}
		var secret corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: token.Spec.SecretRef.Name}, &secret); err != nil {
			return flarecloudflare.AccessSCIMAuthenticationInput{}, fmt.Errorf("get ServiceToken Secret %s/%s: %w", namespace, token.Spec.SecretRef.Name, err)
		}
		clientID := string(secret.Data[v1alpha1.ServiceTokenClientIDKey])
		clientSecret := string(secret.Data[v1alpha1.ServiceTokenClientSecretKey])
		if clientID == "" || clientSecret == "" || clientID != token.Status.ClientID {
			return flarecloudflare.AccessSCIMAuthenticationInput{}, accessValidationError{
				reason: "TargetNotFound", message: fmt.Sprintf("the ServiceToken Secret %s/%s does not contain the current credentials", namespace, token.Spec.SecretRef.Name),
			}
		}
		return flarecloudflare.AccessSCIMAuthenticationInput{
			Scheme:   flarecloudflare.AccessSCIMAuthenticationSchemeAccessServiceToken,
			ClientID: clientID, ClientSecret: clientSecret,
		}, nil
	default:
		return flarecloudflare.AccessSCIMAuthenticationInput{}, accessValidationError{reason: "Invalid", message: "the SCIM authentication method is empty"}
	}
}

func (r *AccessApplicationReconciler) readAccessApplicationSecret(ctx context.Context, namespace string, reference v1alpha1.AccessApplicationSecretKeyReference) (string, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: reference.Name}, &secret); err != nil {
		return "", fmt.Errorf("get Secret %s/%s for Access application: %w", namespace, reference.Name, err)
	}
	value, found := secret.Data[reference.Key]
	if !found || len(value) == 0 {
		return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the Secret %s/%s key %q is empty", namespace, reference.Name, reference.Key)}
	}
	return string(value), nil
}

type accessValidationError struct {
	reason  string
	message string
}

func (err accessValidationError) Error() string { return err.message }

func accessValidationReason(err error) string {
	var validation accessValidationError
	if errors.As(err, &validation) {
		return validation.reason
	}
	return "RefNotPermitted"
}

func remoteApplicationInput(
	application *v1alpha1.AccessApplication,
	destinations []gatewayapi.AccessDestination,
	policyIDs, idpIDs, customPageIDs []string,
	scimConfig *flarecloudflare.AccessSCIMConfigInput,
	ownerTag string,
) flarecloudflare.AccessApplicationInput {
	remoteDestinations := make([]flarecloudflare.AccessApplicationDestination, 0, len(destinations))
	domain := ""
	privateDomain := ""
	for _, destination := range destinations {
		protocol := flarecloudflare.AccessApplicationL4Protocol("")
		if destination.L4Protocol != nil {
			protocol = flarecloudflare.AccessApplicationL4Protocol(*destination.L4Protocol)
		}
		remoteDestinations = append(remoteDestinations, flarecloudflare.AccessApplicationDestination{
			Type: flarecloudflare.AccessApplicationDestinationType(destination.Type),
			URI:  destination.URI, Hostname: destination.Hostname, CIDR: destination.CIDR,
			PortRange: destination.PortRange, L4Protocol: protocol, VNetID: destination.VNetID,
			MCPServerID: destination.MCPServerID, WorkerID: destination.WorkerID,
		})
		if domain == "" && destination.Type == v1alpha1.AccessApplicationDestinationPublic {
			domain = destination.URI
		}
		if privateDomain == "" && destination.Type == v1alpha1.AccessApplicationDestinationPrivate && destination.Hostname != "" {
			privateDomain = destination.Hostname
		}
	}
	if domain == "" {
		domain = privateDomain
	}
	if domain == "" {
		domain = ownerTag + ".private.flareway.invalid"
	}
	policies := make([]flarecloudflare.AccessApplicationPolicyAttachment, len(policyIDs))
	for index, id := range policyIDs {
		policies[index] = flarecloudflare.AccessApplicationPolicyAttachment{ID: id, Precedence: int64(index + 1)}
	}
	applicationType := flarecloudflare.AccessApplicationType(application.Spec.Type)
	name := accessApplicationRemoteName(application)
	if applicationType == flarecloudflare.AccessApplicationTypeWARP {
		name = ""
	}
	var tags []string
	if applicationType != flarecloudflare.AccessApplicationTypeProxyEndpoint {
		tags = append([]string(nil), application.Spec.Application.Tags...)
		tags = append(tags, ownerTag, accessManagedTag)
		slices.Sort(tags)
		tags = slices.Compact(tags)
	}
	settings := application.Spec.Application
	input := flarecloudflare.AccessApplicationInput{
		Type:   applicationType,
		Domain: domain, Name: name, Destinations: remoteDestinations, Policies: policies, AllowedIDPs: slices.Clone(idpIDs),
		SessionDuration: settings.SessionDuration, AllowAuthenticateViaWARP: settings.AllowAuthenticateViaWARP,
		AllowIframe: settings.AllowIframe, SkipInterstitial: settings.SkipInterstitial,
		AutoRedirectToIdentity: settings.AutoRedirectToIdentity,
		AppLauncherVisible:     settings.AppLauncherVisible, ServiceAuth401Redirect: settings.ServiceAuth401Redirect,
		EnableBindingCookie: settings.EnableBindingCookie, EagerRedirectCookieSetting: settings.EagerRedirectCookieSetting,
		HTTPOnlyCookieAttribute: settings.HTTPOnlyCookieAttribute,
		SameSiteCookieAttribute: settings.SameSiteCookieAttribute, PathCookieAttribute: settings.PathCookieAttribute,
		OptionsPreflightBypass: settings.OptionsPreflightBypass, CORSHeaders: settings.CORSHeaders,
		ReadServiceTokensFromHeader: settings.ReadServiceTokensFromHeader,
		CustomDenyMessage:           settings.CustomDenyMessage, CustomDenyURL: settings.CustomDenyURL,
		CustomNonIdentityDenyURL: settings.CustomNonIdentityDenyURL,
		CustomPages:              slices.Clone(customPageIDs), Tags: tags, LogoURL: settings.LogoURL,
		UseClientlessIsolationAppLauncherURL: settings.UseClientlessIsolationAppLauncherURL,
		MFAConfig:                            mfaApplicationInput(settings.MFAConfig),
		OAuthConfiguration:                   oauthApplicationInput(settings.OAuthConfiguration),
		SCIMConfig:                           scimConfig,
	}
	if application.Spec.RDP != nil {
		input.TargetCriteria = make([]flarecloudflare.AccessApplicationTargetCriterion, 0, len(application.Spec.RDP.TargetCriteria))
		for _, criterion := range application.Spec.RDP.TargetCriteria {
			input.TargetCriteria = append(input.TargetCriteria, flarecloudflare.AccessApplicationTargetCriterion{
				Port: int64(criterion.Port), Protocol: flarecloudflare.AccessApplicationTargetProtocol(criterion.Protocol),
				TargetAttributes: cloneStringSliceMap(criterion.TargetAttributes),
			})
		}
	}
	return input
}

func mfaApplicationInput(value *v1alpha1.AccessApplicationMFAConfig) *flarecloudflare.AccessApplicationMFAConfig {
	if value == nil {
		return nil
	}
	authenticators := make([]flarecloudflare.AccessApplicationMFAAuthenticator, len(value.AllowedAuthenticators))
	for index := range value.AllowedAuthenticators {
		authenticators[index] = flarecloudflare.AccessApplicationMFAAuthenticator(value.AllowedAuthenticators[index])
	}
	return &flarecloudflare.AccessApplicationMFAConfig{
		AllowedAuthenticators: authenticators,
		Disabled:              value.MFADisabled,
		SessionDuration:       value.SessionDuration,
	}
}

func oauthApplicationInput(value *v1alpha1.AccessApplicationOAuthConfiguration) *flarecloudflare.AccessApplicationOAuthConfiguration {
	if value == nil {
		return nil
	}
	result := &flarecloudflare.AccessApplicationOAuthConfiguration{Enabled: value.Enabled}
	if value.DynamicClientRegistration != nil {
		result.DynamicClientRegistration = &flarecloudflare.AccessApplicationOAuthDynamicClientRegistration{
			Enabled:             value.DynamicClientRegistration.Enabled,
			AllowAnyOnLocalhost: value.DynamicClientRegistration.AllowAnyOnLocalhost,
			AllowAnyOnLoopback:  value.DynamicClientRegistration.AllowAnyOnLoopback,
			AllowedURIs:         slices.Clone(value.DynamicClientRegistration.AllowedURIs),
		}
	}
	if value.Grant != nil {
		result.Grant = &flarecloudflare.AccessApplicationOAuthGrant{
			AccessTokenLifetime: value.Grant.AccessTokenLifetime,
			SessionDuration:     value.Grant.SessionDuration,
		}
	}
	return result
}

func cloneStringSliceMap(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}
	result := make(map[string][]string, len(values))
	for key, value := range values {
		result[key] = slices.Clone(value)
	}
	return result
}

func accessApplicationMatchesInput(observed flarecloudflare.AccessApplication, desired flarecloudflare.AccessApplicationInput) bool {
	return flarecloudflare.AccessApplicationMatchesInput(observed, desired)
}

func accessApplicationInputFromObserved(observed flarecloudflare.AccessApplication) flarecloudflare.AccessApplicationInput {
	policies := make([]flarecloudflare.AccessApplicationPolicyAttachment, 0, len(observed.Policies))
	for _, policy := range observed.Policies {
		policies = append(policies, flarecloudflare.AccessApplicationPolicyAttachment{ID: policy.ID, Precedence: policy.Precedence})
	}
	return flarecloudflare.AccessApplicationInput{
		Type: observed.Type, Domain: observed.Domain, Name: observed.Name,
		Destinations: slices.Clone(observed.Destinations), Policies: policies, AllowedIDPs: slices.Clone(observed.AllowedIDPs),
		SessionDuration: observed.SessionDuration, AllowAuthenticateViaWARP: observed.AllowAuthenticateViaWARP,
		AllowIframe: observed.AllowIframe, SkipInterstitial: observed.SkipInterstitial,
		AutoRedirectToIdentity: observed.AutoRedirectToIdentity, AppLauncherVisible: observed.AppLauncherVisible,
		ServiceAuth401Redirect: observed.ServiceAuth401Redirect, EnableBindingCookie: observed.EnableBindingCookie,
		EagerRedirectCookieSetting: observed.EagerRedirectCookieSetting,
		HTTPOnlyCookieAttribute:    observed.HTTPOnlyCookieAttribute, SameSiteCookieAttribute: observed.SameSiteCookieAttribute,
		PathCookieAttribute: observed.PathCookieAttribute, OptionsPreflightBypass: observed.OptionsPreflightBypass,
		CORSHeaders: accessCORSHeadersFromObserved(observed.CORSHeaders), ReadServiceTokensFromHeader: observed.ReadServiceTokensFromHeader,
		CustomDenyMessage: observed.CustomDenyMessage, CustomDenyURL: observed.CustomDenyURL,
		CustomNonIdentityDenyURL: observed.CustomNonIdentityDenyURL, CustomPages: slices.Clone(observed.CustomPages),
		Tags: slices.Clone(observed.Tags), LogoURL: observed.LogoURL,
		UseClientlessIsolationAppLauncherURL: observed.UseClientlessIsolationAppLauncherURL,
		MFAConfig:                            observed.MFAConfig, OAuthConfiguration: observed.OAuthConfiguration,
		TargetCriteria:     slices.Clone(observed.TargetCriteria),
		AppLauncherLogoURL: observed.AppLauncherLogoURL, BackgroundColor: observed.BackgroundColor,
		FooterLinks: slices.Clone(observed.FooterLinks), HeaderBackgroundColor: observed.HeaderBackgroundColor,
		LandingPageDesign: observed.LandingPageDesign, SkipAppLauncherLoginPage: observed.SkipAppLauncherLoginPage,
	}
}

func accessCORSHeadersFromObserved(value *flarecloudflare.AccessApplicationCORSHeaders) *v1alpha1.AccessCORSHeaders {
	if value == nil {
		return nil
	}
	return &v1alpha1.AccessCORSHeaders{
		AllowAllHeaders: value.AllowAllHeaders, AllowAllMethods: value.AllowAllMethods,
		AllowAllOrigins: value.AllowAllOrigins, AllowCredentials: value.AllowCredentials,
		AllowedHeaders: slices.Clone(value.AllowedHeaders), AllowedMethods: slices.Clone(value.AllowedMethods),
		AllowedOrigins: slices.Clone(value.AllowedOrigins), MaxAge: value.MaxAge,
	}
}

func canonicalStrings(values []string) []string {
	result := slices.Clone(values)
	slices.Sort(result)
	return slices.Compact(result)
}

func cloneAccessL4Protocol(value *v1alpha1.AccessL4Protocol) *v1alpha1.AccessL4Protocol {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func accessApplicationRemoteName(application *v1alpha1.AccessApplication) string {
	if application.Spec.Application.Name != "" {
		return application.Spec.Application.Name
	}
	return application.Namespace + "/" + application.Name
}

func accessDestinationStatuses(destinations []gatewayapi.AccessDestination) []v1alpha1.AccessApplicationDestinationStatus {
	result := make([]v1alpha1.AccessApplicationDestinationStatus, 0, len(destinations))
	for _, destination := range destinations {
		result = append(result, v1alpha1.AccessApplicationDestinationStatus{
			Type: destination.Type, URI: destination.URI, Hostname: destination.Hostname, CIDR: destination.CIDR,
			PortRange: destination.PortRange, L4Protocol: cloneAccessL4Protocol(destination.L4Protocol),
			VNetID: destination.VNetID, MCPServerID: destination.MCPServerID, WorkerID: destination.WorkerID,
		})
	}
	return result
}

func mergeAccessCompilation(target *gatewayapi.AccessApplicationCompilation, source gatewayapi.AccessApplicationCompilation) {
	target.Destinations = append(target.Destinations, source.Destinations...)
	target.DataPlanes = append(target.DataPlanes, source.DataPlanes...)
	target.Bypass = append(target.Bypass, source.Bypass...)
	target.Ancestors = append(target.Ancestors, source.Ancestors...)
	target.OriginJWTEnforced = target.OriginJWTEnforced || source.OriginJWTEnforced
	if !source.Accepted {
		target.Accepted = false
		target.Reason = source.Reason
		target.Message = source.Message
	}
	dedupeAccessCompilation(target)
}

func dedupeAccessCompilation(compilation *gatewayapi.AccessApplicationCompilation) {
	slices.SortFunc(compilation.Destinations, func(left, right gatewayapi.AccessDestination) int {
		return strings.Compare(gatewayAccessDestinationKey(left), gatewayAccessDestinationKey(right))
	})
	compilation.Destinations = compactGatewayAccessDestinations(compilation.Destinations)
	slices.SortFunc(compilation.DataPlanes, func(left, right gatewayapi.AccessDataPlane) int {
		return strings.Compare(fmt.Sprintf("%s\x00%s\x00%s\x00%d", left.Tunnel, left.Listener, left.ProtectionDomain, left.EnvoyPort), fmt.Sprintf("%s\x00%s\x00%s\x00%d", right.Tunnel, right.Listener, right.ProtectionDomain, right.EnvoyPort))
	})
	compilation.DataPlanes = slices.Compact(compilation.DataPlanes)
	slices.SortFunc(compilation.Bypass, func(left, right gatewayapi.AccessBypass) int {
		return strings.Compare(left.Hostname+"\x00"+left.Path, right.Hostname+"\x00"+right.Path)
	})
	compilation.Bypass = slices.Compact(compilation.Bypass)
	slices.SortFunc(compilation.Ancestors, func(left, right gatewayapi.AccessAncestor) int {
		return strings.Compare(strings.Join([]string{left.Group, left.Kind, left.Namespace, left.Name}, "\x00"), strings.Join([]string{right.Group, right.Kind, right.Namespace, right.Name}, "\x00"))
	})
	compilation.Ancestors = slices.Compact(compilation.Ancestors)
}

func gatewayAccessDestinationKey(destination gatewayapi.AccessDestination) string {
	protocol := ""
	if destination.L4Protocol != nil {
		protocol = string(*destination.L4Protocol)
	}
	return strings.Join([]string{
		string(destination.Type), destination.URI, destination.Hostname, destination.CIDR, destination.PortRange,
		protocol, destination.VNetID, destination.MCPServerID, destination.WorkerID,
	}, "\x00")
}

func compactGatewayAccessDestinations(values []gatewayapi.AccessDestination) []gatewayapi.AccessDestination {
	if len(values) < 2 {
		return values
	}
	result := values[:0]
	lastKey := ""
	for index, value := range values {
		key := gatewayAccessDestinationKey(value)
		if index == 0 || key != lastKey {
			result = append(result, value)
			lastKey = key
		}
	}
	return result
}
