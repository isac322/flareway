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

package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"k8s.io/apimachinery/pkg/api/resource"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// DevicePostureRuleAPI is part of the Flareway API.
type DevicePostureRuleAPI interface {
	CreateDevicePostureRule(context.Context, DevicePostureRuleInput) (DevicePostureRule, error)
	UpdateDevicePostureRule(context.Context, string, DevicePostureRuleInput) (DevicePostureRule, error)
	GetDevicePostureRule(context.Context, string) (DevicePostureRule, error)
	ListDevicePostureRules(context.Context) ([]DevicePostureRule, error)
	DeleteDevicePostureRule(context.Context, string) error
}

// DevicePostureIntegrationAPI is the account-scoped posture integration API.
type DevicePostureIntegrationAPI interface {
	CreateDevicePostureIntegration(context.Context, DevicePostureIntegrationInput) (DevicePostureIntegration, error)
	UpdateDevicePostureIntegration(context.Context, string, DevicePostureIntegrationInput) (DevicePostureIntegration, error)
	GetDevicePostureIntegration(context.Context, string) (DevicePostureIntegration, error)
	ListDevicePostureIntegrations(context.Context) ([]DevicePostureIntegration, error)
	DeleteDevicePostureIntegration(context.Context, string) error
}

// DevicePostureRuleInput is part of the Flareway API.
type DevicePostureRuleInput struct {
	Name         string
	Type         v1alpha1.DevicePostureRuleType
	Description  string
	Schedule     string
	Expiration   string
	Match        []v1alpha1.DevicePostureMatch
	Input        v1alpha1.DevicePostureInput
	ConnectionID string
}

// DevicePostureRule is the full mutable posture rule state returned by Cloudflare.
type DevicePostureRule struct {
	ID          string
	Name        string
	Type        v1alpha1.DevicePostureRuleType
	Description string
	Enabled     bool
	Schedule    string
	Expiration  string
	Match       []v1alpha1.DevicePostureMatch
	Input       v1alpha1.DevicePostureInput
}

// DevicePostureIntegrationInput contains public config and ephemeral credentials.
type DevicePostureIntegrationInput struct {
	Name               string
	Type               v1alpha1.DevicePostureIntegrationType
	Interval           string
	Config             v1alpha1.DevicePostureIntegrationConfig
	ClientSecret       string
	ClientKey          string
	AccessClientID     string
	AccessClientSecret string
}

// DevicePostureIntegration is the non-secret mutable integration state returned by Cloudflare.
type DevicePostureIntegration struct {
	ID       string
	Name     string
	Type     v1alpha1.DevicePostureIntegrationType
	Interval string
	Config   v1alpha1.DevicePostureIntegrationObservedConfig
}

// CreateDevicePostureRule is part of the Flareway API.
func (client *Client) CreateDevicePostureRule(ctx context.Context, input DevicePostureRuleInput) (DevicePostureRule, error) {
	params, err := devicePostureNewParams(client.accountID, input)
	if err != nil {
		return DevicePostureRule{}, err
	}
	result, err := client.sdk.ZeroTrust.Devices.Posture.New(ctx, params)
	if err != nil {
		return DevicePostureRule{}, fmt.Errorf("create device posture rule: %w", err)
	}
	return devicePostureRuleFromSDK(result), nil
}

// UpdateDevicePostureRule is part of the Flareway API.
func (client *Client) UpdateDevicePostureRule(ctx context.Context, id string, input DevicePostureRuleInput) (DevicePostureRule, error) {
	params, err := devicePostureUpdateParams(client.accountID, input)
	if err != nil {
		return DevicePostureRule{}, err
	}
	result, err := client.sdk.ZeroTrust.Devices.Posture.Update(ctx, id, params)
	if err != nil {
		return DevicePostureRule{}, fmt.Errorf("update device posture rule: %w", err)
	}
	return devicePostureRuleFromSDK(result), nil
}

// GetDevicePostureRule is part of the Flareway API.
func (client *Client) GetDevicePostureRule(ctx context.Context, id string) (DevicePostureRule, error) {
	result, err := client.sdk.ZeroTrust.Devices.Posture.Get(ctx, id, zero_trust.DevicePostureGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return DevicePostureRule{}, fmt.Errorf("get device posture rule: %w", err)
	}
	return devicePostureRuleFromSDK(result), nil
}

// ListDevicePostureRules is part of the Flareway API.
func (client *Client) ListDevicePostureRules(ctx context.Context) ([]DevicePostureRule, error) {
	pager := client.sdk.ZeroTrust.Devices.Posture.ListAutoPaging(ctx, zero_trust.DevicePostureListParams{AccountID: cloudflaresdk.F(client.accountID)})
	var result []DevicePostureRule
	for pager.Next() {
		value := pager.Current()
		result = append(result, devicePostureRuleFromSDK(&value))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list device posture rules: %w", err)
	}
	return result, nil
}

// DeleteDevicePostureRule is part of the Flareway API.
func (client *Client) DeleteDevicePostureRule(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Devices.Posture.Delete(ctx, id, zero_trust.DevicePostureDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete device posture rule: %w", err)
	}
	return nil
}

func devicePostureNewParams(accountID string, input DevicePostureRuleInput) (zero_trust.DevicePostureNewParams, error) {
	wireType, err := devicePostureRuleTypeToWire(input.Type)
	if err != nil {
		return zero_trust.DevicePostureNewParams{}, err
	}
	body, present, err := deviceInput(input.Type, input.Input, input.ConnectionID)
	if err != nil {
		return zero_trust.DevicePostureNewParams{}, err
	}
	params := zero_trust.DevicePostureNewParams{
		AccountID: cloudflaresdk.F(accountID),
		Name:      cloudflaresdk.F(input.Name),
		Type:      cloudflaresdk.F(zero_trust.DevicePostureNewParamsType(wireType)),
	}
	if input.Description != "" {
		params.Description = cloudflaresdk.F(input.Description)
	}
	if input.Schedule != "" {
		params.Schedule = cloudflaresdk.F(input.Schedule)
	}
	if input.Expiration != "" {
		params.Expiration = cloudflaresdk.F(input.Expiration)
	}
	if len(input.Match) != 0 {
		params.Match = cloudflaresdk.F(deviceMatches(input.Match))
	}
	if present {
		params.Input = cloudflaresdk.F[zero_trust.DeviceInputUnionParam](body)
	}
	return params, nil
}

func devicePostureUpdateParams(accountID string, input DevicePostureRuleInput) (zero_trust.DevicePostureUpdateParams, error) {
	wireType, err := devicePostureRuleTypeToWire(input.Type)
	if err != nil {
		return zero_trust.DevicePostureUpdateParams{}, err
	}
	body, present, err := deviceInput(input.Type, input.Input, input.ConnectionID)
	if err != nil {
		return zero_trust.DevicePostureUpdateParams{}, err
	}
	params := zero_trust.DevicePostureUpdateParams{
		AccountID: cloudflaresdk.F(accountID),
		Name:      cloudflaresdk.F(input.Name),
		Type:      cloudflaresdk.F(zero_trust.DevicePostureUpdateParamsType(wireType)),
	}
	if input.Description != "" {
		params.Description = cloudflaresdk.F(input.Description)
	}
	if input.Schedule != "" {
		params.Schedule = cloudflaresdk.F(input.Schedule)
	}
	if input.Expiration != "" {
		params.Expiration = cloudflaresdk.F(input.Expiration)
	}
	if len(input.Match) != 0 {
		params.Match = cloudflaresdk.F(deviceMatches(input.Match))
	}
	if present {
		params.Input = cloudflaresdk.F[zero_trust.DeviceInputUnionParam](body)
	}
	return params, nil
}

func devicePostureQuantityToFloat64(field string, value *resource.Quantity) (float64, error) {
	result, err := strconv.ParseFloat(value.AsDec().String(), 64)
	if err != nil {
		return 0, fmt.Errorf("convert device posture input.%s to a Cloudflare number: %w", field, err)
	}
	return result, nil
}

func devicePostureQuantityFromFloat64(value *float64) *resource.Quantity {
	if value == nil {
		return nil
	}
	result := resource.MustParse(strconv.FormatFloat(*value, 'f', -1, 64))
	return &result
}

func deviceMatches(values []v1alpha1.DevicePostureMatch) []zero_trust.DeviceMatchParam {
	result := make([]zero_trust.DeviceMatchParam, len(values))
	for i := range values {
		result[i] = zero_trust.DeviceMatchParam{Platform: cloudflaresdk.F(zero_trust.DeviceMatchPlatform(devicePosturePlatformToWire(values[i].Platform)))}
	}
	return result
}

func deviceInput(ruleType v1alpha1.DevicePostureRuleType, value v1alpha1.DevicePostureInput, connectionID string) (zero_trust.DeviceInputUnionParam, bool, error) {
	platform := devicePosturePlatformToWire(value.OperatingSystem)
	switch ruleType {
	case v1alpha1.DevicePostureRuleTypeGateway, v1alpha1.DevicePostureRuleTypeWARP:
		return nil, false, nil
	case v1alpha1.DevicePostureRuleTypeFile:
		body := zero_trust.FileInputParam{OperatingSystem: cloudflaresdk.F(zero_trust.FileInputOperatingSystem(platform)), Path: cloudflaresdk.F(value.Path)}
		if value.Exists != nil {
			body.Exists = cloudflaresdk.F(*value.Exists)
		}
		if value.SHA256 != "" {
			body.Sha256 = cloudflaresdk.F(value.SHA256)
		}
		if value.Thumbprint != "" {
			body.Thumbprint = cloudflaresdk.F(value.Thumbprint)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeApplication:
		body := zero_trust.DeviceInputTeamsDevicesApplicationInputRequestParam{OperatingSystem: cloudflaresdk.F(zero_trust.DeviceInputTeamsDevicesApplicationInputRequestOperatingSystem(platform)), Path: cloudflaresdk.F(value.Path)}
		if value.SHA256 != "" {
			body.Sha256 = cloudflaresdk.F(value.SHA256)
		}
		if value.Thumbprint != "" {
			body.Thumbprint = cloudflaresdk.F(value.Thumbprint)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeTanium, v1alpha1.DevicePostureRuleTypeTaniumS2S:
		body := zero_trust.TaniumInputParam{ConnectionID: cloudflaresdk.F(connectionID)}
		if value.EIDLastSeen != "" {
			body.EidLastSeen = cloudflaresdk.F(value.EIDLastSeen)
		}
		if value.Operator != "" {
			body.Operator = cloudflaresdk.F(zero_trust.TaniumInputOperator(devicePostureOperatorToWire(value.Operator)))
		}
		if value.RiskLevel != "" {
			body.RiskLevel = cloudflaresdk.F(zero_trust.TaniumInputRiskLevel(devicePostureRiskToWire(value.RiskLevel)))
		}
		if value.ScoreOperator != "" {
			body.ScoreOperator = cloudflaresdk.F(zero_trust.TaniumInputScoreOperator(devicePostureOperatorToWire(value.ScoreOperator)))
		}
		if value.TotalScore != nil {
			totalScore, err := devicePostureQuantityToFloat64("totalScore", value.TotalScore)
			if err != nil {
				return nil, false, err
			}
			body.TotalScore = cloudflaresdk.F(totalScore)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeDiskEncryption:
		body := zero_trust.DiskEncryptionInputParam{}
		if len(value.CheckDisks) != 0 {
			disks := make([]zero_trust.CarbonblackInputParam, len(value.CheckDisks))
			for i := range value.CheckDisks {
				disks[i] = zero_trust.CarbonblackInputParam(value.CheckDisks[i])
			}
			body.CheckDisks = cloudflaresdk.F(disks)
		}
		if value.RequireAll != nil {
			body.RequireAll = cloudflaresdk.F(*value.RequireAll)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeSerialNumber:
		return zero_trust.DeviceInputTeamsDevicesAccessSerialNumberListInputRequestParam{ID: cloudflaresdk.F(value.ID)}, true, nil
	case v1alpha1.DevicePostureRuleTypeSentinelOne:
		body := zero_trust.SentineloneInputParam{OperatingSystem: cloudflaresdk.F(zero_trust.SentineloneInputOperatingSystem(platform)), Path: cloudflaresdk.F(value.Path)}
		if value.SHA256 != "" {
			body.Sha256 = cloudflaresdk.F(value.SHA256)
		}
		if value.Thumbprint != "" {
			body.Thumbprint = cloudflaresdk.F(value.Thumbprint)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeCarbonBlack:
		body := zero_trust.DeviceInputTeamsDevicesCarbonblackInputRequestParam{OperatingSystem: cloudflaresdk.F(zero_trust.DeviceInputTeamsDevicesCarbonblackInputRequestOperatingSystem(platform)), Path: cloudflaresdk.F(value.Path)}
		if value.SHA256 != "" {
			body.Sha256 = cloudflaresdk.F(value.SHA256)
		}
		if value.Thumbprint != "" {
			body.Thumbprint = cloudflaresdk.F(value.Thumbprint)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeFirewall:
		if value.Enabled == nil {
			return nil, false, fmt.Errorf("firewall posture input requires enabled")
		}
		return zero_trust.FirewallInputParam{Enabled: cloudflaresdk.F(*value.Enabled), OperatingSystem: cloudflaresdk.F(zero_trust.FirewallInputOperatingSystem(platform))}, true, nil
	case v1alpha1.DevicePostureRuleTypeOSVersion:
		body := zero_trust.OSVersionInputParam{OperatingSystem: cloudflaresdk.F(zero_trust.OSVersionInputOperatingSystem(platform)), Operator: cloudflaresdk.F(zero_trust.OSVersionInputOperator(devicePostureOperatorToWire(value.Operator))), Version: cloudflaresdk.F(value.Version)}
		if value.OSDistroName != "" {
			body.OSDistroName = cloudflaresdk.F(value.OSDistroName)
		}
		if value.OSDistroRevision != "" {
			body.OSDistroRevision = cloudflaresdk.F(value.OSDistroRevision)
		}
		if value.OSVersionExtra != "" {
			body.OSVersionExtra = cloudflaresdk.F(value.OSVersionExtra)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeDomainJoined:
		body := zero_trust.DomainJoinedInputParam{OperatingSystem: cloudflaresdk.F(zero_trust.DomainJoinedInputOperatingSystem(platform))}
		if value.Domain != "" {
			body.Domain = cloudflaresdk.F(value.Domain)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeClientCertificate:
		return zero_trust.ClientCertificateInputParam{CertificateID: cloudflaresdk.F(value.CertificateID), Cn: cloudflaresdk.F(value.CommonName)}, true, nil
	case v1alpha1.DevicePostureRuleTypeClientCertificateV2:
		if value.CheckPrivateKey == nil {
			return nil, false, fmt.Errorf("device posture ClientCertificateV2 input requires checkPrivateKey")
		}
		body := zero_trust.DeviceInputTeamsDevicesClientCertificateV2InputRequestParam{CertificateID: cloudflaresdk.F(value.CertificateID), CheckPrivateKey: cloudflaresdk.F(*value.CheckPrivateKey), OperatingSystem: cloudflaresdk.F(zero_trust.DeviceInputTeamsDevicesClientCertificateV2InputRequestOperatingSystem(platform))}
		if value.CommonName != "" {
			body.Cn = cloudflaresdk.F(value.CommonName)
		}
		if len(value.ExtendedKeyUsage) != 0 {
			items := make([]zero_trust.DeviceInputTeamsDevicesClientCertificateV2InputRequestExtendedKeyUsage, len(value.ExtendedKeyUsage))
			for i := range value.ExtendedKeyUsage {
				items[i] = zero_trust.DeviceInputTeamsDevicesClientCertificateV2InputRequestExtendedKeyUsage(devicePostureExtendedKeyUsageToWire(value.ExtendedKeyUsage[i]))
			}
			body.ExtendedKeyUsage = cloudflaresdk.F(items)
		}
		if value.Locations != nil && (len(value.Locations.Paths) != 0 || len(value.Locations.TrustStores) != 0) {
			locations := zero_trust.DeviceInputTeamsDevicesClientCertificateV2InputRequestLocationsParam{}
			if len(value.Locations.Paths) != 0 {
				locations.Paths = cloudflaresdk.F(value.Locations.Paths)
			}
			if len(value.Locations.TrustStores) != 0 {
				stores := make([]zero_trust.DeviceInputTeamsDevicesClientCertificateV2InputRequestLocationsTrustStore, len(value.Locations.TrustStores))
				for i := range value.Locations.TrustStores {
					stores[i] = zero_trust.DeviceInputTeamsDevicesClientCertificateV2InputRequestLocationsTrustStore(devicePostureTrustStoreToWire(value.Locations.TrustStores[i]))
				}
				locations.TrustStores = cloudflaresdk.F(stores)
			}
			body.Locations = cloudflaresdk.F(locations)
		}
		if len(value.SubjectAlternativeNames) != 0 {
			body.SubjectAlternativeNames = cloudflaresdk.F(value.SubjectAlternativeNames)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeAntivirus:
		body := zero_trust.DeviceInputTeamsDevicesAntivirusInputRequestParam{}
		if value.UpdateWindowDays != nil {
			updateWindowDays, err := devicePostureQuantityToFloat64("updateWindowDays", value.UpdateWindowDays)
			if err != nil {
				return nil, false, err
			}
			body.UpdateWindowDays = cloudflaresdk.F(updateWindowDays)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeUniqueClientID:
		return zero_trust.UniqueClientIDInputParam{ID: cloudflaresdk.F(value.ID), OperatingSystem: cloudflaresdk.F(zero_trust.UniqueClientIDInputOperatingSystem(platform))}, true, nil
	case v1alpha1.DevicePostureRuleTypeKolide:
		body := zero_trust.KolideInputParam{ConnectionID: cloudflaresdk.F(connectionID)}
		if len(value.AuthState) != 0 {
			states := make([]zero_trust.KolideInputAuthState, len(value.AuthState))
			for i := range value.AuthState {
				states[i] = zero_trust.KolideInputAuthState(devicePostureKolideAuthToWire(value.AuthState[i]))
			}
			body.AuthState = cloudflaresdk.F(states)
		}
		if value.CountOperator != "" {
			body.CountOperator = cloudflaresdk.F(zero_trust.KolideInputCountOperator(devicePostureOperatorToWire(value.CountOperator)))
		}
		if value.IssueCount != "" {
			body.IssueCount = cloudflaresdk.F(value.IssueCount)
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeCrowdstrikeS2S:
		body := zero_trust.CrowdstrikeInputParam{ConnectionID: cloudflaresdk.F(connectionID)}
		if value.LastSeen != "" {
			body.LastSeen = cloudflaresdk.F(value.LastSeen)
		}
		if value.Operator != "" {
			body.Operator = cloudflaresdk.F(zero_trust.CrowdstrikeInputOperator(devicePostureOperatorToWire(value.Operator)))
		}
		if value.OS != "" {
			body.OS = cloudflaresdk.F(value.OS)
		}
		if value.Overall != "" {
			body.Overall = cloudflaresdk.F(value.Overall)
		}
		if value.SensorConfig != "" {
			body.SensorConfig = cloudflaresdk.F(value.SensorConfig)
		}
		if value.State != "" {
			body.State = cloudflaresdk.F(zero_trust.CrowdstrikeInputState(devicePostureStateToWire(value.State)))
		}
		if value.Version != "" {
			body.Version = cloudflaresdk.F(value.Version)
		}
		if value.VersionOperator != "" {
			body.VersionOperator = cloudflaresdk.F(zero_trust.CrowdstrikeInputVersionOperator(devicePostureOperatorToWire(value.VersionOperator)))
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeIntune:
		return zero_trust.IntuneInputParam{ComplianceStatus: cloudflaresdk.F(zero_trust.IntuneInputComplianceStatus(devicePostureComplianceToWire(value.ComplianceStatus))), ConnectionID: cloudflaresdk.F(connectionID)}, true, nil
	case v1alpha1.DevicePostureRuleTypeWorkspaceOne:
		return zero_trust.WorkspaceOneInputParam{ComplianceStatus: cloudflaresdk.F(zero_trust.WorkspaceOneInputComplianceStatus(devicePostureComplianceToWire(value.ComplianceStatus))), ConnectionID: cloudflaresdk.F(connectionID)}, true, nil
	case v1alpha1.DevicePostureRuleTypeSentinelOneS2S:
		body := zero_trust.SentineloneS2sInputParam{ConnectionID: cloudflaresdk.F(connectionID)}
		if value.ActiveThreats != nil {
			activeThreats, err := devicePostureQuantityToFloat64("activeThreats", value.ActiveThreats)
			if err != nil {
				return nil, false, err
			}
			body.ActiveThreats = cloudflaresdk.F(activeThreats)
		}
		if value.Infected != nil {
			body.Infected = cloudflaresdk.F(*value.Infected)
		}
		if value.IsActive != nil {
			body.IsActive = cloudflaresdk.F(*value.IsActive)
		}
		if value.NetworkStatus != "" {
			body.NetworkStatus = cloudflaresdk.F(zero_trust.SentineloneS2sInputNetworkStatus(devicePostureNetworkToWire(value.NetworkStatus)))
		}
		if value.OperationalState != "" {
			body.OperationalState = cloudflaresdk.F(zero_trust.SentineloneS2sInputOperationalState(devicePostureOperationalToWire(value.OperationalState)))
		}
		if value.Operator != "" {
			body.Operator = cloudflaresdk.F(zero_trust.SentineloneS2sInputOperator(devicePostureOperatorToWire(value.Operator)))
		}
		return body, true, nil
	case v1alpha1.DevicePostureRuleTypeCustomS2S:
		if value.Score == nil {
			return nil, false, fmt.Errorf("device posture CustomS2S input requires score")
		}
		score, err := devicePostureQuantityToFloat64("score", value.Score)
		if err != nil {
			return nil, false, err
		}
		return zero_trust.DeviceInputTeamsDevicesCustomS2sInputRequestParam{ConnectionID: cloudflaresdk.F(connectionID), Operator: cloudflaresdk.F(zero_trust.DeviceInputTeamsDevicesCustomS2sInputRequestOperator(devicePostureOperatorToWire(value.Operator))), Score: cloudflaresdk.F(score)}, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported device posture rule type %q", ruleType)
	}
}

func devicePostureRuleFromSDK(value *zero_trust.DevicePostureRule) DevicePostureRule {
	if value == nil {
		return DevicePostureRule{}
	}
	matches := make([]v1alpha1.DevicePostureMatch, len(value.Match))
	for i := range value.Match {
		matches[i].Platform = devicePosturePlatformFromWire(string(value.Match[i].Platform))
	}
	return DevicePostureRule{ID: value.ID, Name: value.Name, Type: devicePostureRuleTypeFromWire(string(value.Type)), Description: value.Description, Enabled: value.Enabled, Schedule: value.Schedule, Expiration: value.Expiration, Match: matches, Input: devicePostureInputFromSDK(value.Input)}
}

type devicePostureWireLocations struct {
	Paths       []string `json:"paths"`
	TrustStores []string `json:"trust_stores"`
}

type devicePostureWireInput struct {
	ID                      string                      `json:"id"`
	ConnectionID            string                      `json:"connection_id"`
	OperatingSystem         string                      `json:"operating_system"`
	Path                    string                      `json:"path"`
	SHA256                  string                      `json:"sha256"`
	Domain                  string                      `json:"domain"`
	Version                 string                      `json:"version"`
	VersionOperator         string                      `json:"versionOperator"`
	Operator                string                      `json:"operator"`
	Enabled                 *bool                       `json:"enabled"`
	Exists                  *bool                       `json:"exists"`
	RequireAll              *bool                       `json:"requireAll"`
	Infected                *bool                       `json:"infected"`
	IsActive                *bool                       `json:"is_active"`
	CheckPrivateKey         *bool                       `json:"check_private_key"`
	ComplianceStatus        string                      `json:"compliance_status"`
	NetworkStatus           string                      `json:"network_status"`
	OperationalState        string                      `json:"operational_state"`
	State                   string                      `json:"state"`
	RiskLevel               string                      `json:"risk_level"`
	Score                   *float64                    `json:"score"`
	ScoreOperator           string                      `json:"scoreOperator"`
	TotalScore              *float64                    `json:"total_score"`
	ActiveThreats           *float64                    `json:"active_threats"`
	UpdateWindowDays        *float64                    `json:"update_window_days"`
	LastSeen                string                      `json:"last_seen"`
	EIDLastSeen             string                      `json:"eid_last_seen"`
	IssueCount              string                      `json:"issue_count"`
	CountOperator           string                      `json:"countOperator"`
	SensorConfig            string                      `json:"sensor_config"`
	CertificateID           string                      `json:"certificate_id"`
	CommonName              string                      `json:"cn"`
	Thumbprint              string                      `json:"thumbprint"`
	OS                      string                      `json:"os"`
	OSDistroName            string                      `json:"os_distro_name"`
	OSDistroRevision        string                      `json:"os_distro_revision"`
	OSVersionExtra          string                      `json:"os_version_extra"`
	Overall                 string                      `json:"overall"`
	AuthState               []string                    `json:"auth_state"`
	CheckDisks              []string                    `json:"checkDisks"`
	ExtendedKeyUsage        []string                    `json:"extended_key_usage"`
	Locations               *devicePostureWireLocations `json:"locations"`
	SubjectAlternativeNames []string                    `json:"subject_alternative_names"`
}

func devicePostureInputFromSDK(value zero_trust.DeviceInput) v1alpha1.DevicePostureInput {
	var wire devicePostureWireInput
	if raw := value.JSON.RawJSON(); raw != "" {
		_ = json.Unmarshal([]byte(raw), &wire)
	}
	if wire.ID == "" {
		wire.ID = value.ID
	}
	if wire.ConnectionID == "" {
		wire.ConnectionID = value.ConnectionID
	}
	if wire.OperatingSystem == "" {
		wire.OperatingSystem = string(value.OperatingSystem)
	}
	if wire.Path == "" {
		wire.Path = value.Path
	}
	if wire.SHA256 == "" {
		wire.SHA256 = value.Sha256
	}
	if wire.Domain == "" {
		wire.Domain = value.Domain
	}
	if wire.Version == "" {
		wire.Version = value.Version
	}
	if wire.VersionOperator == "" {
		wire.VersionOperator = string(value.VersionOperator)
	}
	if wire.Operator == "" {
		wire.Operator = string(value.Operator)
	}
	if wire.ComplianceStatus == "" {
		wire.ComplianceStatus = string(value.ComplianceStatus)
	}
	if wire.NetworkStatus == "" {
		wire.NetworkStatus = string(value.NetworkStatus)
	}
	if wire.OperationalState == "" {
		wire.OperationalState = string(value.OperationalState)
	}
	if wire.State == "" {
		wire.State = string(value.State)
	}
	if wire.RiskLevel == "" {
		wire.RiskLevel = string(value.RiskLevel)
	}
	if wire.ScoreOperator == "" {
		wire.ScoreOperator = string(value.ScoreOperator)
	}
	if wire.CountOperator == "" {
		wire.CountOperator = string(value.CountOperator)
	}
	result := v1alpha1.DevicePostureInput{ID: wire.ID, OperatingSystem: devicePosturePlatformFromWire(wire.OperatingSystem), Path: wire.Path, SHA256: wire.SHA256, Domain: wire.Domain, Version: wire.Version, VersionOperator: devicePostureOperatorFromWire(wire.VersionOperator), Operator: devicePostureOperatorFromWire(wire.Operator), Enabled: wire.Enabled, Exists: wire.Exists, RequireAll: wire.RequireAll, Infected: wire.Infected, IsActive: wire.IsActive, CheckPrivateKey: wire.CheckPrivateKey, ComplianceStatus: devicePostureComplianceFromWire(wire.ComplianceStatus), NetworkStatus: devicePostureNetworkFromWire(wire.NetworkStatus), OperationalState: devicePostureOperationalFromWire(wire.OperationalState), State: devicePostureStateFromWire(wire.State), RiskLevel: devicePostureRiskFromWire(wire.RiskLevel), Score: devicePostureQuantityFromFloat64(wire.Score), ScoreOperator: devicePostureOperatorFromWire(wire.ScoreOperator), TotalScore: devicePostureQuantityFromFloat64(wire.TotalScore), ActiveThreats: devicePostureQuantityFromFloat64(wire.ActiveThreats), UpdateWindowDays: devicePostureQuantityFromFloat64(wire.UpdateWindowDays), LastSeen: wire.LastSeen, EIDLastSeen: wire.EIDLastSeen, IssueCount: wire.IssueCount, CountOperator: devicePostureOperatorFromWire(wire.CountOperator), SensorConfig: wire.SensorConfig, CertificateID: wire.CertificateID, CommonName: wire.CommonName, Thumbprint: wire.Thumbprint, OS: wire.OS, OSDistroName: wire.OSDistroName, OSDistroRevision: wire.OSDistroRevision, OSVersionExtra: wire.OSVersionExtra, Overall: wire.Overall, CheckDisks: wire.CheckDisks, SubjectAlternativeNames: wire.SubjectAlternativeNames}
	if wire.ConnectionID != "" {
		result.IntegrationRef = &v1alpha1.DevicePostureIntegrationReference{ExternalID: wire.ConnectionID}
	}
	for _, item := range wire.AuthState {
		result.AuthState = append(result.AuthState, devicePostureKolideAuthFromWire(item))
	}
	for _, item := range wire.ExtendedKeyUsage {
		result.ExtendedKeyUsage = append(result.ExtendedKeyUsage, devicePostureExtendedKeyUsageFromWire(item))
	}
	if wire.Locations != nil {
		result.Locations = &v1alpha1.DevicePostureCertificateLocations{Paths: wire.Locations.Paths}
		for _, item := range wire.Locations.TrustStores {
			result.Locations.TrustStores = append(result.Locations.TrustStores, devicePostureTrustStoreFromWire(item))
		}
	}
	return result
}

// CreateDevicePostureIntegration creates a third-party posture integration.
func (client *Client) CreateDevicePostureIntegration(ctx context.Context, input DevicePostureIntegrationInput) (DevicePostureIntegration, error) {
	config, err := devicePostureIntegrationNewConfig(input)
	if err != nil {
		return DevicePostureIntegration{}, err
	}
	wireType, err := devicePostureIntegrationTypeToWire(input.Type)
	if err != nil {
		return DevicePostureIntegration{}, err
	}
	result, err := client.sdk.ZeroTrust.Devices.Posture.Integrations.New(ctx, zero_trust.DevicePostureIntegrationNewParams{AccountID: cloudflaresdk.F(client.accountID), Config: cloudflaresdk.F[zero_trust.DevicePostureIntegrationNewParamsConfigUnion](config), Interval: cloudflaresdk.F(input.Interval), Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.DevicePostureIntegrationNewParamsType(wireType))})
	if err != nil {
		return DevicePostureIntegration{}, fmt.Errorf("create device posture integration: %w", err)
	}
	return devicePostureIntegrationFromSDK(result), nil
}

// UpdateDevicePostureIntegration updates a third-party posture integration.
func (client *Client) UpdateDevicePostureIntegration(ctx context.Context, id string, input DevicePostureIntegrationInput) (DevicePostureIntegration, error) {
	config, err := devicePostureIntegrationEditConfig(input)
	if err != nil {
		return DevicePostureIntegration{}, err
	}
	wireType, err := devicePostureIntegrationTypeToWire(input.Type)
	if err != nil {
		return DevicePostureIntegration{}, err
	}
	result, err := client.sdk.ZeroTrust.Devices.Posture.Integrations.Edit(ctx, id, zero_trust.DevicePostureIntegrationEditParams{AccountID: cloudflaresdk.F(client.accountID), Config: cloudflaresdk.F[zero_trust.DevicePostureIntegrationEditParamsConfigUnion](config), Interval: cloudflaresdk.F(input.Interval), Name: cloudflaresdk.F(input.Name), Type: cloudflaresdk.F(zero_trust.DevicePostureIntegrationEditParamsType(wireType))})
	if err != nil {
		return DevicePostureIntegration{}, fmt.Errorf("update device posture integration: %w", err)
	}
	return devicePostureIntegrationFromSDK(result), nil
}

// GetDevicePostureIntegration fetches one posture integration.
func (client *Client) GetDevicePostureIntegration(ctx context.Context, id string) (DevicePostureIntegration, error) {
	result, err := client.sdk.ZeroTrust.Devices.Posture.Integrations.Get(ctx, id, zero_trust.DevicePostureIntegrationGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return DevicePostureIntegration{}, fmt.Errorf("get device posture integration: %w", err)
	}
	return devicePostureIntegrationFromSDK(result), nil
}

// ListDevicePostureIntegrations lists posture integrations.
func (client *Client) ListDevicePostureIntegrations(ctx context.Context) ([]DevicePostureIntegration, error) {
	pager := client.sdk.ZeroTrust.Devices.Posture.Integrations.ListAutoPaging(ctx, zero_trust.DevicePostureIntegrationListParams{AccountID: cloudflaresdk.F(client.accountID)})
	var result []DevicePostureIntegration
	for pager.Next() {
		value := pager.Current()
		result = append(result, devicePostureIntegrationFromSDK(&value))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list device posture integrations: %w", err)
	}
	return result, nil
}

// DeleteDevicePostureIntegration deletes a posture integration.
func (client *Client) DeleteDevicePostureIntegration(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Devices.Posture.Integrations.Delete(ctx, id, zero_trust.DevicePostureIntegrationDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete device posture integration: %w", err)
	}
	return nil
}

func devicePostureIntegrationNewConfig(input DevicePostureIntegrationInput) (zero_trust.DevicePostureIntegrationNewParamsConfigUnion, error) {
	config := input.Config
	switch input.Type {
	case v1alpha1.DevicePostureIntegrationTypeWorkspaceOne:
		return zero_trust.DevicePostureIntegrationNewParamsConfigTeamsDevicesWorkspaceOneConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), AuthURL: cloudflaresdk.F(config.AuthURL), ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret)}, nil
	case v1alpha1.DevicePostureIntegrationTypeCrowdstrikeS2S:
		return zero_trust.DevicePostureIntegrationNewParamsConfigTeamsDevicesCrowdstrikeConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret), CustomerID: cloudflaresdk.F(config.CustomerID)}, nil
	case v1alpha1.DevicePostureIntegrationTypeUptycs:
		return zero_trust.DevicePostureIntegrationNewParamsConfigTeamsDevicesUptycsConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), ClientKey: cloudflaresdk.F(input.ClientKey), ClientSecret: cloudflaresdk.F(input.ClientSecret), CustomerID: cloudflaresdk.F(config.CustomerID)}, nil
	case v1alpha1.DevicePostureIntegrationTypeIntune:
		return zero_trust.DevicePostureIntegrationNewParamsConfigTeamsDevicesIntuneConfigRequest{ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret), CustomerID: cloudflaresdk.F(config.CustomerID)}, nil
	case v1alpha1.DevicePostureIntegrationTypeKolide:
		return zero_trust.DevicePostureIntegrationNewParamsConfigTeamsDevicesKolideConfigRequest{ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret)}, nil
	case v1alpha1.DevicePostureIntegrationTypeTaniumS2S:
		body := zero_trust.DevicePostureIntegrationNewParamsConfigTeamsDevicesTaniumConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), ClientSecret: cloudflaresdk.F(input.ClientSecret)}
		if input.AccessClientID != "" {
			body.AccessClientID = cloudflaresdk.F(input.AccessClientID)
		}
		if input.AccessClientSecret != "" {
			body.AccessClientSecret = cloudflaresdk.F(input.AccessClientSecret)
		}
		return body, nil
	case v1alpha1.DevicePostureIntegrationTypeSentinelOneS2S:
		return zero_trust.DevicePostureIntegrationNewParamsConfigTeamsDevicesSentineloneS2sConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), ClientSecret: cloudflaresdk.F(input.ClientSecret)}, nil
	case v1alpha1.DevicePostureIntegrationTypeCustomS2S:
		return zero_trust.DevicePostureIntegrationNewParamsConfigTeamsDevicesCustomS2sConfigRequest{AccessClientID: cloudflaresdk.F(input.AccessClientID), AccessClientSecret: cloudflaresdk.F(input.AccessClientSecret), APIURL: cloudflaresdk.F(config.APIURL)}, nil
	default:
		return nil, fmt.Errorf("unsupported device posture integration type %q", input.Type)
	}
}

func devicePostureIntegrationEditConfig(input DevicePostureIntegrationInput) (zero_trust.DevicePostureIntegrationEditParamsConfigUnion, error) {
	config := input.Config
	switch input.Type {
	case v1alpha1.DevicePostureIntegrationTypeWorkspaceOne:
		return zero_trust.DevicePostureIntegrationEditParamsConfigTeamsDevicesWorkspaceOneConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), AuthURL: cloudflaresdk.F(config.AuthURL), ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret)}, nil
	case v1alpha1.DevicePostureIntegrationTypeCrowdstrikeS2S:
		return zero_trust.DevicePostureIntegrationEditParamsConfigTeamsDevicesCrowdstrikeConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret), CustomerID: cloudflaresdk.F(config.CustomerID)}, nil
	case v1alpha1.DevicePostureIntegrationTypeUptycs:
		return zero_trust.DevicePostureIntegrationEditParamsConfigTeamsDevicesUptycsConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), ClientKey: cloudflaresdk.F(input.ClientKey), ClientSecret: cloudflaresdk.F(input.ClientSecret), CustomerID: cloudflaresdk.F(config.CustomerID)}, nil
	case v1alpha1.DevicePostureIntegrationTypeIntune:
		return zero_trust.DevicePostureIntegrationEditParamsConfigTeamsDevicesIntuneConfigRequest{ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret), CustomerID: cloudflaresdk.F(config.CustomerID)}, nil
	case v1alpha1.DevicePostureIntegrationTypeKolide:
		return zero_trust.DevicePostureIntegrationEditParamsConfigTeamsDevicesKolideConfigRequest{ClientID: cloudflaresdk.F(config.ClientID), ClientSecret: cloudflaresdk.F(input.ClientSecret)}, nil
	case v1alpha1.DevicePostureIntegrationTypeTaniumS2S:
		body := zero_trust.DevicePostureIntegrationEditParamsConfigTeamsDevicesTaniumConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), ClientSecret: cloudflaresdk.F(input.ClientSecret)}
		if input.AccessClientID != "" {
			body.AccessClientID = cloudflaresdk.F(input.AccessClientID)
		}
		if input.AccessClientSecret != "" {
			body.AccessClientSecret = cloudflaresdk.F(input.AccessClientSecret)
		}
		return body, nil
	case v1alpha1.DevicePostureIntegrationTypeSentinelOneS2S:
		return zero_trust.DevicePostureIntegrationEditParamsConfigTeamsDevicesSentineloneS2sConfigRequest{APIURL: cloudflaresdk.F(config.APIURL), ClientSecret: cloudflaresdk.F(input.ClientSecret)}, nil
	case v1alpha1.DevicePostureIntegrationTypeCustomS2S:
		return zero_trust.DevicePostureIntegrationEditParamsConfigTeamsDevicesCustomS2sConfigRequest{AccessClientID: cloudflaresdk.F(input.AccessClientID), AccessClientSecret: cloudflaresdk.F(input.AccessClientSecret), APIURL: cloudflaresdk.F(config.APIURL)}, nil
	default:
		return nil, fmt.Errorf("unsupported device posture integration type %q", input.Type)
	}
}

func devicePostureIntegrationFromSDK(value *zero_trust.Integration) DevicePostureIntegration {
	if value == nil {
		return DevicePostureIntegration{}
	}
	config := v1alpha1.DevicePostureIntegrationObservedConfig{APIURL: value.Config.APIURL, AuthURL: value.Config.AuthURL, ClientID: value.Config.ClientID}
	var extra struct {
		CustomerID string `json:"customer_id"`
	}
	if raw := value.Config.JSON.RawJSON(); raw != "" {
		_ = json.Unmarshal([]byte(raw), &extra)
		config.CustomerID = extra.CustomerID
	}
	return DevicePostureIntegration{ID: value.ID, Name: value.Name, Type: devicePostureIntegrationTypeFromWire(string(value.Type)), Interval: value.Interval, Config: config}
}

func devicePostureRuleTypeToWire(value v1alpha1.DevicePostureRuleType) (string, error) {
	switch value {
	case v1alpha1.DevicePostureRuleTypeFile:
		return "file", nil
	case v1alpha1.DevicePostureRuleTypeApplication:
		return "application", nil
	case v1alpha1.DevicePostureRuleTypeTanium:
		return "tanium", nil
	case v1alpha1.DevicePostureRuleTypeGateway:
		return "gateway", nil
	case v1alpha1.DevicePostureRuleTypeWARP:
		return "warp", nil
	case v1alpha1.DevicePostureRuleTypeDiskEncryption:
		return "disk_encryption", nil
	case v1alpha1.DevicePostureRuleTypeSerialNumber:
		return "serial_number", nil
	case v1alpha1.DevicePostureRuleTypeSentinelOne:
		return "sentinelone", nil
	case v1alpha1.DevicePostureRuleTypeCarbonBlack:
		return "carbonblack", nil
	case v1alpha1.DevicePostureRuleTypeFirewall:
		return "firewall", nil
	case v1alpha1.DevicePostureRuleTypeOSVersion:
		return "os_version", nil
	case v1alpha1.DevicePostureRuleTypeDomainJoined:
		return "domain_joined", nil
	case v1alpha1.DevicePostureRuleTypeClientCertificate:
		return "client_certificate", nil
	case v1alpha1.DevicePostureRuleTypeClientCertificateV2:
		return "client_certificate_v2", nil
	case v1alpha1.DevicePostureRuleTypeAntivirus:
		return "antivirus", nil
	case v1alpha1.DevicePostureRuleTypeUniqueClientID:
		return "unique_client_id", nil
	case v1alpha1.DevicePostureRuleTypeKolide:
		return "kolide", nil
	case v1alpha1.DevicePostureRuleTypeTaniumS2S:
		return "tanium_s2s", nil
	case v1alpha1.DevicePostureRuleTypeCrowdstrikeS2S:
		return "crowdstrike_s2s", nil
	case v1alpha1.DevicePostureRuleTypeIntune:
		return "intune", nil
	case v1alpha1.DevicePostureRuleTypeWorkspaceOne:
		return "workspace_one", nil
	case v1alpha1.DevicePostureRuleTypeSentinelOneS2S:
		return "sentinelone_s2s", nil
	case v1alpha1.DevicePostureRuleTypeCustomS2S:
		return "custom_s2s", nil
	default:
		return "", fmt.Errorf("unsupported device posture rule type %q", value)
	}
}

func devicePostureRuleTypeFromWire(value string) v1alpha1.DevicePostureRuleType {
	switch value {
	case "file":
		return v1alpha1.DevicePostureRuleTypeFile
	case "application":
		return v1alpha1.DevicePostureRuleTypeApplication
	case "tanium":
		return v1alpha1.DevicePostureRuleTypeTanium
	case "gateway":
		return v1alpha1.DevicePostureRuleTypeGateway
	case "warp":
		return v1alpha1.DevicePostureRuleTypeWARP
	case "disk_encryption":
		return v1alpha1.DevicePostureRuleTypeDiskEncryption
	case "serial_number":
		return v1alpha1.DevicePostureRuleTypeSerialNumber
	case "sentinelone":
		return v1alpha1.DevicePostureRuleTypeSentinelOne
	case "carbonblack":
		return v1alpha1.DevicePostureRuleTypeCarbonBlack
	case "firewall":
		return v1alpha1.DevicePostureRuleTypeFirewall
	case "os_version":
		return v1alpha1.DevicePostureRuleTypeOSVersion
	case "domain_joined":
		return v1alpha1.DevicePostureRuleTypeDomainJoined
	case "client_certificate":
		return v1alpha1.DevicePostureRuleTypeClientCertificate
	case "client_certificate_v2":
		return v1alpha1.DevicePostureRuleTypeClientCertificateV2
	case "antivirus":
		return v1alpha1.DevicePostureRuleTypeAntivirus
	case "unique_client_id":
		return v1alpha1.DevicePostureRuleTypeUniqueClientID
	case "kolide":
		return v1alpha1.DevicePostureRuleTypeKolide
	case "tanium_s2s":
		return v1alpha1.DevicePostureRuleTypeTaniumS2S
	case "crowdstrike_s2s":
		return v1alpha1.DevicePostureRuleTypeCrowdstrikeS2S
	case "intune":
		return v1alpha1.DevicePostureRuleTypeIntune
	case "workspace_one":
		return v1alpha1.DevicePostureRuleTypeWorkspaceOne
	case "sentinelone_s2s":
		return v1alpha1.DevicePostureRuleTypeSentinelOneS2S
	case "custom_s2s":
		return v1alpha1.DevicePostureRuleTypeCustomS2S
	default:
		return ""
	}
}

func devicePostureIntegrationTypeToWire(value v1alpha1.DevicePostureIntegrationType) (string, error) {
	switch value {
	case v1alpha1.DevicePostureIntegrationTypeWorkspaceOne:
		return "workspace_one", nil
	case v1alpha1.DevicePostureIntegrationTypeCrowdstrikeS2S:
		return "crowdstrike_s2s", nil
	case v1alpha1.DevicePostureIntegrationTypeUptycs:
		return "uptycs", nil
	case v1alpha1.DevicePostureIntegrationTypeIntune:
		return "intune", nil
	case v1alpha1.DevicePostureIntegrationTypeKolide:
		return "kolide", nil
	case v1alpha1.DevicePostureIntegrationTypeTaniumS2S:
		return "tanium_s2s", nil
	case v1alpha1.DevicePostureIntegrationTypeSentinelOneS2S:
		return "sentinelone_s2s", nil
	case v1alpha1.DevicePostureIntegrationTypeCustomS2S:
		return "custom_s2s", nil
	default:
		return "", fmt.Errorf("unsupported device posture integration type %q", value)
	}
}

func devicePostureIntegrationTypeFromWire(value string) v1alpha1.DevicePostureIntegrationType {
	switch value {
	case "workspace_one":
		return v1alpha1.DevicePostureIntegrationTypeWorkspaceOne
	case "crowdstrike_s2s":
		return v1alpha1.DevicePostureIntegrationTypeCrowdstrikeS2S
	case "uptycs":
		return v1alpha1.DevicePostureIntegrationTypeUptycs
	case "intune":
		return v1alpha1.DevicePostureIntegrationTypeIntune
	case "kolide":
		return v1alpha1.DevicePostureIntegrationTypeKolide
	case "tanium_s2s":
		return v1alpha1.DevicePostureIntegrationTypeTaniumS2S
	case "sentinelone_s2s":
		return v1alpha1.DevicePostureIntegrationTypeSentinelOneS2S
	case "custom_s2s":
		return v1alpha1.DevicePostureIntegrationTypeCustomS2S
	default:
		return ""
	}
}

func devicePosturePlatformToWire(value v1alpha1.DevicePosturePlatform) string {
	switch value {
	case v1alpha1.DevicePosturePlatformWindows:
		return "windows"
	case v1alpha1.DevicePosturePlatformMac:
		return "mac"
	case v1alpha1.DevicePosturePlatformLinux:
		return "linux"
	case v1alpha1.DevicePosturePlatformAndroid:
		return "android"
	case v1alpha1.DevicePosturePlatformIOS:
		return "ios"
	case v1alpha1.DevicePosturePlatformChromeOS:
		return "chromeos"
	default:
		return ""
	}
}
func devicePosturePlatformFromWire(value string) v1alpha1.DevicePosturePlatform {
	switch value {
	case "windows":
		return v1alpha1.DevicePosturePlatformWindows
	case "mac":
		return v1alpha1.DevicePosturePlatformMac
	case "linux":
		return v1alpha1.DevicePosturePlatformLinux
	case "android":
		return v1alpha1.DevicePosturePlatformAndroid
	case "ios":
		return v1alpha1.DevicePosturePlatformIOS
	case "chromeos":
		return v1alpha1.DevicePosturePlatformChromeOS
	default:
		return ""
	}
}
func devicePostureOperatorToWire(value v1alpha1.DevicePostureOperator) string {
	switch value {
	case v1alpha1.DevicePostureOperatorLessThan:
		return "<"
	case v1alpha1.DevicePostureOperatorLessThanOrEqual:
		return "<="
	case v1alpha1.DevicePostureOperatorGreaterThan:
		return ">"
	case v1alpha1.DevicePostureOperatorGreaterThanOrEqual:
		return ">="
	case v1alpha1.DevicePostureOperatorEqual:
		return "=="
	default:
		return ""
	}
}
func devicePostureOperatorFromWire(value string) v1alpha1.DevicePostureOperator {
	switch value {
	case "<":
		return v1alpha1.DevicePostureOperatorLessThan
	case "<=":
		return v1alpha1.DevicePostureOperatorLessThanOrEqual
	case ">":
		return v1alpha1.DevicePostureOperatorGreaterThan
	case ">=":
		return v1alpha1.DevicePostureOperatorGreaterThanOrEqual
	case "==":
		return v1alpha1.DevicePostureOperatorEqual
	default:
		return ""
	}
}
func devicePostureComplianceToWire(value v1alpha1.DevicePostureComplianceStatus) string {
	switch value {
	case v1alpha1.DevicePostureComplianceCompliant:
		return "compliant"
	case v1alpha1.DevicePostureComplianceNonCompliant:
		return "noncompliant"
	case v1alpha1.DevicePostureComplianceUnknown:
		return "unknown"
	case v1alpha1.DevicePostureComplianceNotApplicable:
		return "notapplicable"
	case v1alpha1.DevicePostureComplianceInGracePeriod:
		return "ingraceperiod"
	case v1alpha1.DevicePostureComplianceError:
		return "error"
	default:
		return ""
	}
}
func devicePostureComplianceFromWire(value string) v1alpha1.DevicePostureComplianceStatus {
	switch value {
	case "compliant":
		return v1alpha1.DevicePostureComplianceCompliant
	case "noncompliant":
		return v1alpha1.DevicePostureComplianceNonCompliant
	case "unknown":
		return v1alpha1.DevicePostureComplianceUnknown
	case "notapplicable":
		return v1alpha1.DevicePostureComplianceNotApplicable
	case "ingraceperiod":
		return v1alpha1.DevicePostureComplianceInGracePeriod
	case "error":
		return v1alpha1.DevicePostureComplianceError
	default:
		return ""
	}
}
func devicePostureNetworkToWire(value v1alpha1.DevicePostureNetworkStatus) string {
	switch value {
	case v1alpha1.DevicePostureNetworkConnected:
		return "connected"
	case v1alpha1.DevicePostureNetworkDisconnected:
		return "disconnected"
	case v1alpha1.DevicePostureNetworkDisconnecting:
		return "disconnecting"
	case v1alpha1.DevicePostureNetworkConnecting:
		return "connecting"
	default:
		return ""
	}
}
func devicePostureNetworkFromWire(value string) v1alpha1.DevicePostureNetworkStatus {
	switch value {
	case "connected":
		return v1alpha1.DevicePostureNetworkConnected
	case "disconnected":
		return v1alpha1.DevicePostureNetworkDisconnected
	case "disconnecting":
		return v1alpha1.DevicePostureNetworkDisconnecting
	case "connecting":
		return v1alpha1.DevicePostureNetworkConnecting
	default:
		return ""
	}
}
func devicePostureOperationalToWire(value v1alpha1.DevicePostureOperationalState) string {
	switch value {
	case v1alpha1.DevicePostureOperationalNotApplicable:
		return "na"
	case v1alpha1.DevicePostureOperationalPartiallyDisabled:
		return "partially_disabled"
	case v1alpha1.DevicePostureOperationalAutomaticallyFullyDisabled:
		return "auto_fully_disabled"
	case v1alpha1.DevicePostureOperationalFullyDisabled:
		return "fully_disabled"
	case v1alpha1.DevicePostureOperationalAutomaticallyPartiallyDisabled:
		return "auto_partially_disabled"
	case v1alpha1.DevicePostureOperationalDisabledError:
		return "disabled_error"
	case v1alpha1.DevicePostureOperationalDatabaseCorruption:
		return "db_corruption"
	default:
		return ""
	}
}
func devicePostureOperationalFromWire(value string) v1alpha1.DevicePostureOperationalState {
	switch value {
	case "na":
		return v1alpha1.DevicePostureOperationalNotApplicable
	case "partially_disabled":
		return v1alpha1.DevicePostureOperationalPartiallyDisabled
	case "auto_fully_disabled":
		return v1alpha1.DevicePostureOperationalAutomaticallyFullyDisabled
	case "fully_disabled":
		return v1alpha1.DevicePostureOperationalFullyDisabled
	case "auto_partially_disabled":
		return v1alpha1.DevicePostureOperationalAutomaticallyPartiallyDisabled
	case "disabled_error":
		return v1alpha1.DevicePostureOperationalDisabledError
	case "db_corruption":
		return v1alpha1.DevicePostureOperationalDatabaseCorruption
	default:
		return ""
	}
}
func devicePostureStateToWire(value v1alpha1.DevicePostureState) string {
	switch value {
	case v1alpha1.DevicePostureStateOnline:
		return "online"
	case v1alpha1.DevicePostureStateOffline:
		return "offline"
	case v1alpha1.DevicePostureStateUnknown:
		return "unknown"
	default:
		return ""
	}
}
func devicePostureStateFromWire(value string) v1alpha1.DevicePostureState {
	switch value {
	case "online":
		return v1alpha1.DevicePostureStateOnline
	case "offline":
		return v1alpha1.DevicePostureStateOffline
	case "unknown":
		return v1alpha1.DevicePostureStateUnknown
	default:
		return ""
	}
}
func devicePostureRiskToWire(value v1alpha1.DevicePostureRiskLevel) string {
	switch value {
	case v1alpha1.DevicePostureRiskLow:
		return "low"
	case v1alpha1.DevicePostureRiskMedium:
		return "medium"
	case v1alpha1.DevicePostureRiskHigh:
		return "high"
	case v1alpha1.DevicePostureRiskCritical:
		return "critical"
	default:
		return ""
	}
}
func devicePostureRiskFromWire(value string) v1alpha1.DevicePostureRiskLevel {
	switch value {
	case "low":
		return v1alpha1.DevicePostureRiskLow
	case "medium":
		return v1alpha1.DevicePostureRiskMedium
	case "high":
		return v1alpha1.DevicePostureRiskHigh
	case "critical":
		return v1alpha1.DevicePostureRiskCritical
	default:
		return ""
	}
}
func devicePostureKolideAuthToWire(value v1alpha1.DevicePostureKolideAuthState) string {
	switch value {
	case v1alpha1.DevicePostureKolideAuthGood:
		return "Good"
	case v1alpha1.DevicePostureKolideAuthNotified:
		return "Notified"
	case v1alpha1.DevicePostureKolideAuthWillBlock:
		return "Will Block"
	case v1alpha1.DevicePostureKolideAuthBlocked:
		return "Blocked"
	default:
		return ""
	}
}
func devicePostureKolideAuthFromWire(value string) v1alpha1.DevicePostureKolideAuthState {
	switch value {
	case "Good":
		return v1alpha1.DevicePostureKolideAuthGood
	case "Notified":
		return v1alpha1.DevicePostureKolideAuthNotified
	case "Will Block":
		return v1alpha1.DevicePostureKolideAuthWillBlock
	case "Blocked":
		return v1alpha1.DevicePostureKolideAuthBlocked
	default:
		return ""
	}
}
func devicePostureExtendedKeyUsageToWire(value v1alpha1.DevicePostureExtendedKeyUsage) string {
	switch value {
	case v1alpha1.DevicePostureExtendedKeyUsageClientAuth:
		return "clientAuth"
	case v1alpha1.DevicePostureExtendedKeyUsageEmailProtection:
		return "emailProtection"
	default:
		return ""
	}
}
func devicePostureExtendedKeyUsageFromWire(value string) v1alpha1.DevicePostureExtendedKeyUsage {
	switch value {
	case "clientAuth":
		return v1alpha1.DevicePostureExtendedKeyUsageClientAuth
	case "emailProtection":
		return v1alpha1.DevicePostureExtendedKeyUsageEmailProtection
	default:
		return ""
	}
}
func devicePostureTrustStoreToWire(value v1alpha1.DevicePostureTrustStore) string {
	switch value {
	case v1alpha1.DevicePostureTrustStoreSystem:
		return "system"
	case v1alpha1.DevicePostureTrustStoreUser:
		return "user"
	default:
		return ""
	}
}
func devicePostureTrustStoreFromWire(value string) v1alpha1.DevicePostureTrustStore {
	switch value {
	case "system":
		return v1alpha1.DevicePostureTrustStoreSystem
	case "user":
		return v1alpha1.DevicePostureTrustStoreUser
	default:
		return ""
	}
}
