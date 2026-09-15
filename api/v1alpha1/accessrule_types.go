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

package v1alpha1

// AccessObjectReference selects a local managed object or a remote object ID.
// +kubebuilder:validation:XValidation:rule="has(self.name) != has(self.externalId)",message="exactly one of name or externalId is required"
type AccessObjectReference struct {
	Name       string `json:"name,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	ExternalID string `json:"externalId,omitempty"`
}

// AccessListRule matches members of a Cloudflare Access list.
// +kubebuilder:validation:XValidation:rule="has(self.listRef) != has(self.listId)",message="exactly one of listRef or listId is required"
type AccessListRule struct {
	ListRef *AccessObjectReference `json:"listRef,omitempty"`
	ListID  string                 `json:"listId,omitempty"`
}

// AccessEmailRule matches one email address.
type AccessEmailRule struct {
	Email string `json:"email"`
}

// AccessEmailDomainRule matches an email domain.
type AccessEmailDomainRule struct {
	Domain string `json:"domain"`
}

// AccessEveryoneRule matches everyone.
type AccessEveryoneRule struct{}

// AccessIPRule is part of the accessiprule configuration.
type AccessIPRule struct {
	IP string `json:"ip"`
}

// AccessCertificateRule is part of the accesscertificaterule configuration.
type AccessCertificateRule struct{}

// AccessCommonNameRule is part of the accesscommonnamerule configuration.
type AccessCommonNameRule struct {
	CommonName string `json:"commonName"`
}

// AccessGroupRule is part of the accessgrouprule configuration.
type AccessGroupRule struct {
	GroupRef AccessObjectReference `json:"groupRef"`
}

// AccessAzureADRule is part of the accessazureadrule configuration.
type AccessAzureADRule struct {
	ID                  string                `json:"id"`
	IdentityProviderRef AccessObjectReference `json:"identityProviderRef"`
}

// AccessGitHubOrganizationRule is part of the accessgithuborganizationrule configuration.
type AccessGitHubOrganizationRule struct {
	Name                string                `json:"name"`
	Team                string                `json:"team,omitempty"`
	IdentityProviderRef AccessObjectReference `json:"identityProviderRef"`
}

// AccessGSuiteRule is part of the accessgsuiterule configuration.
type AccessGSuiteRule struct {
	Email               string                `json:"email"`
	IdentityProviderRef AccessObjectReference `json:"identityProviderRef"`
}

// AccessOktaRule is part of the accessoktarule configuration.
type AccessOktaRule struct {
	Name                string                `json:"name"`
	IdentityProviderRef AccessObjectReference `json:"identityProviderRef"`
}

// AccessSAMLRule is part of the accesssamlrule configuration.
type AccessSAMLRule struct {
	AttributeName       string                `json:"attributeName"`
	AttributeValue      string                `json:"attributeValue"`
	IdentityProviderRef AccessObjectReference `json:"identityProviderRef"`
}

// AccessOIDCRule is part of the accessoidcrule configuration.
type AccessOIDCRule struct {
	ClaimName           string                `json:"claimName"`
	ClaimValue          string                `json:"claimValue"`
	IdentityProviderRef AccessObjectReference `json:"identityProviderRef"`
}

// AccessServiceTokenRule is part of the accessservicetokenrule configuration.
type AccessServiceTokenRule struct {
	TokenRef AccessObjectReference `json:"tokenRef"`
}

// AccessAnyValidServiceTokenRule is part of the accessanyvalidservicetokenrule configuration.
type AccessAnyValidServiceTokenRule struct{}

// AccessExternalEvaluationRule is part of the accessexternalevaluationrule configuration.
type AccessExternalEvaluationRule struct {
	EvaluateURL string `json:"evaluateUrl"`
	KeysURL     string `json:"keysUrl"`
}

// AccessGeoRule is part of the accessgeorule configuration.
type AccessGeoRule struct {
	CountryCode string `json:"countryCode"`
}

// AccessAuthMethodRule is part of the accessauthmethodrule configuration.
type AccessAuthMethodRule struct {
	AuthMethod string `json:"authMethod"`
}

// AccessDevicePostureRuleReference is part of the accessdeviceposturerulereference configuration.
type AccessDevicePostureRuleReference struct {
	RuleRef AccessObjectReference `json:"ruleRef"`
}

// AccessLoginMethodRule is part of the accessloginmethodrule configuration.
type AccessLoginMethodRule struct {
	IdentityProviderRef AccessObjectReference `json:"identityProviderRef"`
}

// AccessAuthContextRule is part of the accessauthcontextrule configuration.
type AccessAuthContextRule struct {
	ID                  string                `json:"id"`
	ACID                string                `json:"acId"`
	IdentityProviderRef AccessObjectReference `json:"identityProviderRef"`
}

// AccessLinkedAppTokenRule is part of the accesslinkedapptokenrule configuration.
type AccessLinkedAppTokenRule struct {
	AppID string `json:"appId"`
}

// AccessUserRiskLevel identifies a user risk level.
// +kubebuilder:validation:Enum=Low;Medium;High;Unscored
type AccessUserRiskLevel string

const (
	// AccessUserRiskLevelLow matches low-risk users.
	AccessUserRiskLevelLow AccessUserRiskLevel = "Low"
	// AccessUserRiskLevelMedium matches medium-risk users.
	AccessUserRiskLevelMedium AccessUserRiskLevel = "Medium"
	// AccessUserRiskLevelHigh matches high-risk users.
	AccessUserRiskLevelHigh AccessUserRiskLevel = "High"
	// AccessUserRiskLevelUnscored matches users without a risk score.
	AccessUserRiskLevelUnscored AccessUserRiskLevel = "Unscored"
)

// AccessUserRiskScoreRule matches one or more user risk levels.
type AccessUserRiskScoreRule struct {
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Levels []AccessUserRiskLevel `json:"levels"`
}

// AccessCloudflareAccountMemberRule is part of the accesscloudflareaccountmemberrule configuration.
type AccessCloudflareAccountMemberRule struct {
	AccountID string `json:"accountId,omitempty"`
}

// AccessRuleObservation is a compact, resolved Access rule representation used
// in status. It intentionally has no cross-field CEL validation.
type AccessRuleObservation struct {
	// +kubebuilder:validation:Enum=email;emailDomain;emailList;everyone;ip;ipList;certificate;commonName;group;azureAD;githubOrganization;gsuite;okta;saml;oidc;serviceToken;anyValidServiceToken;externalEvaluation;geo;authMethod;devicePosture;loginMethod;authContext;linkedAppToken;userRiskScore;cloudflareAccountMember
	// +kubebuilder:validation:MaxLength=32
	Kind string `json:"kind"`
	// +kubebuilder:validation:MaxLength=1024
	Value string `json:"value,omitempty"`
	// +kubebuilder:validation:MaxLength=1024
	Value2 string `json:"value2,omitempty"`
	// +kubebuilder:validation:MaxLength=1024
	Value3 string `json:"value3,omitempty"`
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:validation:items:MaxLength=16
	// +listType=atomic
	Values []string `json:"values,omitempty"`
	// +kubebuilder:validation:MaxLength=256
	ID string `json:"id,omitempty"`
	// +kubebuilder:validation:MaxLength=256
	IdentityProviderID string `json:"identityProviderId,omitempty"`
	// +kubebuilder:validation:MaxLength=256
	AccountID string `json:"accountId,omitempty"`
}

// AccessRule is a typed union of every reusable Access rule supported by Cloudflare.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:XValidation:rule="(has(self.email)?1:0)+(has(self.emailDomain)?1:0)+(has(self.emailList)?1:0)+(has(self.everyone)?1:0)+(has(self.ip)?1:0)+(has(self.ipList)?1:0)+(has(self.certificate)?1:0)+(has(self.commonName)?1:0)+(has(self.group)?1:0)+(has(self.azureAD)?1:0)+(has(self.githubOrganization)?1:0)+(has(self.gsuite)?1:0)+(has(self.okta)?1:0)+(has(self.saml)?1:0)+(has(self.oidc)?1:0)+(has(self.serviceToken)?1:0)+(has(self.anyValidServiceToken)?1:0)+(has(self.externalEvaluation)?1:0)+(has(self.geo)?1:0)+(has(self.authMethod)?1:0)+(has(self.devicePosture)?1:0)+(has(self.loginMethod)?1:0)+(has(self.authContext)?1:0)+(has(self.linkedAppToken)?1:0)+(has(self.userRiskScore)?1:0)+(has(self.cloudflareAccountMember)?1:0) == 1",message="exactly one Access rule field is required"
type AccessRule struct {
	Email                   *AccessEmailRule                   `json:"email,omitempty"`
	EmailDomain             *AccessEmailDomainRule             `json:"emailDomain,omitempty"`
	EmailList               *AccessListRule                    `json:"emailList,omitempty"`
	Everyone                *AccessEveryoneRule                `json:"everyone,omitempty"`
	IP                      *AccessIPRule                      `json:"ip,omitempty"`
	IPList                  *AccessListRule                    `json:"ipList,omitempty"`
	Certificate             *AccessCertificateRule             `json:"certificate,omitempty"`
	CommonName              *AccessCommonNameRule              `json:"commonName,omitempty"`
	Group                   *AccessGroupRule                   `json:"group,omitempty"`
	AzureAD                 *AccessAzureADRule                 `json:"azureAD,omitempty"`
	GitHubOrganization      *AccessGitHubOrganizationRule      `json:"githubOrganization,omitempty"`
	GSuite                  *AccessGSuiteRule                  `json:"gsuite,omitempty"`
	Okta                    *AccessOktaRule                    `json:"okta,omitempty"`
	SAML                    *AccessSAMLRule                    `json:"saml,omitempty"`
	OIDC                    *AccessOIDCRule                    `json:"oidc,omitempty"`
	ServiceToken            *AccessServiceTokenRule            `json:"serviceToken,omitempty"`
	AnyValidServiceToken    *AccessAnyValidServiceTokenRule    `json:"anyValidServiceToken,omitempty"`
	ExternalEvaluation      *AccessExternalEvaluationRule      `json:"externalEvaluation,omitempty"`
	Geo                     *AccessGeoRule                     `json:"geo,omitempty"`
	AuthMethod              *AccessAuthMethodRule              `json:"authMethod,omitempty"`
	DevicePosture           *AccessDevicePostureRuleReference  `json:"devicePosture,omitempty"`
	LoginMethod             *AccessLoginMethodRule             `json:"loginMethod,omitempty"`
	AuthContext             *AccessAuthContextRule             `json:"authContext,omitempty"`
	LinkedAppToken          *AccessLinkedAppTokenRule          `json:"linkedAppToken,omitempty"`
	UserRiskScore           *AccessUserRiskScoreRule           `json:"userRiskScore,omitempty"`
	CloudflareAccountMember *AccessCloudflareAccountMemberRule `json:"cloudflareAccountMember,omitempty"`
}
