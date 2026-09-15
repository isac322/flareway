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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestDevicePostureRuleMatchesEquivalentQuantities(t *testing.T) {
	t.Parallel()

	desired := v1alpha1.DevicePostureInput{
		Score:            devicePostureTestQuantity("42.5"),
		TotalScore:       devicePostureTestQuantity("90.25"),
		ActiveThreats:    devicePostureTestQuantity("1.5"),
		UpdateWindowDays: devicePostureTestQuantity("7.25"),
	}
	remoteInput := v1alpha1.DevicePostureInput{
		Score:            devicePostureTestQuantity("42500m"),
		TotalScore:       devicePostureTestQuantity("90250m"),
		ActiveThreats:    devicePostureTestQuantity("1500m"),
		UpdateWindowDays: devicePostureTestQuantity("7250m"),
	}
	input := flarecloudflare.DevicePostureRuleInput{
		Name: "rule", Type: v1alpha1.DevicePostureRuleTypeCustomS2S, Input: desired,
	}
	remote := flarecloudflare.DevicePostureRule{
		Name: "rule", Type: v1alpha1.DevicePostureRuleTypeCustomS2S, Input: remoteInput,
	}

	if !devicePostureRuleMatches(input, remote) {
		t.Fatal("numerically equivalent quantities reported drift")
	}
	remote.Input.Score = devicePostureTestQuantity("42.5001")
	if devicePostureRuleMatches(input, remote) {
		t.Fatal("different quantity did not report drift")
	}
}

func TestValidateDevicePostureRuleSpecRejectsInvalidQuantities(t *testing.T) {
	t.Parallel()

	integrationRef := &v1alpha1.DevicePostureIntegrationReference{ExternalID: "integration-id"}
	tests := []struct {
		name    string
		spec    v1alpha1.DevicePostureRuleSpec
		message string
	}{
		{
			name: "negative score",
			spec: v1alpha1.DevicePostureRuleSpec{
				Type:  v1alpha1.DevicePostureRuleTypeCustomS2S,
				Input: v1alpha1.DevicePostureInput{IntegrationRef: integrationRef, Operator: v1alpha1.DevicePostureOperatorEqual, Score: devicePostureTestQuantity("-0.001")},
			},
			message: "input.score must be between 0 and 100",
		},
		{
			name: "score over 100",
			spec: v1alpha1.DevicePostureRuleSpec{
				Type:  v1alpha1.DevicePostureRuleTypeCustomS2S,
				Input: v1alpha1.DevicePostureInput{IntegrationRef: integrationRef, Operator: v1alpha1.DevicePostureOperatorEqual, Score: devicePostureTestQuantity("100.0001")},
			},
			message: "input.score must be between 0 and 100",
		},
		{
			name: "negative active threats",
			spec: v1alpha1.DevicePostureRuleSpec{
				Type:  v1alpha1.DevicePostureRuleTypeSentinelOneS2S,
				Input: v1alpha1.DevicePostureInput{IntegrationRef: integrationRef, ActiveThreats: devicePostureTestQuantity("-0.1")},
			},
			message: "input.activeThreats must not be negative",
		},
		{
			name: "negative update window",
			spec: v1alpha1.DevicePostureRuleSpec{
				Type:  v1alpha1.DevicePostureRuleTypeAntivirus,
				Input: v1alpha1.DevicePostureInput{UpdateWindowDays: devicePostureTestQuantity("-0.5")},
			},
			message: "input.updateWindowDays must not be negative",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDevicePostureRuleSpec(&test.spec)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("validateDevicePostureRuleSpec() error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestValidateDevicePostureRuleSpecAcceptsQuantityBoundariesAndDecimals(t *testing.T) {
	t.Parallel()

	integrationRef := &v1alpha1.DevicePostureIntegrationReference{ExternalID: "integration-id"}
	specs := []v1alpha1.DevicePostureRuleSpec{
		{Type: v1alpha1.DevicePostureRuleTypeCustomS2S, Input: v1alpha1.DevicePostureInput{IntegrationRef: integrationRef, Operator: v1alpha1.DevicePostureOperatorEqual, Score: devicePostureTestQuantity("0")}},
		{Type: v1alpha1.DevicePostureRuleTypeCustomS2S, Input: v1alpha1.DevicePostureInput{IntegrationRef: integrationRef, Operator: v1alpha1.DevicePostureOperatorEqual, Score: devicePostureTestQuantity("100")}},
		{Type: v1alpha1.DevicePostureRuleTypeTanium, Input: v1alpha1.DevicePostureInput{IntegrationRef: integrationRef, TotalScore: devicePostureTestQuantity("90.25")}},
		{Type: v1alpha1.DevicePostureRuleTypeSentinelOneS2S, Input: v1alpha1.DevicePostureInput{IntegrationRef: integrationRef, ActiveThreats: devicePostureTestQuantity("0.25")}},
		{Type: v1alpha1.DevicePostureRuleTypeAntivirus, Input: v1alpha1.DevicePostureInput{UpdateWindowDays: devicePostureTestQuantity("7.5")}},
	}
	for i := range specs {
		if err := validateDevicePostureRuleSpec(&specs[i]); err != nil {
			t.Fatalf("spec[%d] rejected valid quantity: %v", i, err)
		}
	}
}

func devicePostureTestQuantity(value string) *resource.Quantity {
	quantity := resource.MustParse(value)
	return &quantity
}
