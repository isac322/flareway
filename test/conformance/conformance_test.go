//go:build conformance

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

package conformance

import (
	"path/filepath"
	"testing"

	"github.com/isac322/flareway/internal/gatewayapi"
	gatewayconformance "sigs.k8s.io/gateway-api/conformance"
	confv1 "sigs.k8s.io/gateway-api/conformance/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

var version = "dev"

func TestConformance(t *testing.T) {
	opts := gatewayconformance.DefaultOptions(t)
	opts.GatewayClassName = "flareway"
	opts.Mode = "default"
	opts.ConformanceProfiles = []suite.ConformanceProfileName{
		suite.GatewayHTTPConformanceProfileName,
	}
	opts.SupportedFeatures = gatewayapi.SupportedFeatures()
	opts.SkipTests = []string{}
	// Flareway v1 intentionally serializes Gateway reconciliation. Running
	// independent suite fixtures in parallel can starve the single worker;
	// serializing fixtures preserves every assertion without skipping tests.
	opts.DisableParallelTests = true
	opts.Implementation = confv1.Implementation{
		Organization: "isac322",
		Project:      "flareway",
		URL:          "https://github.com/isac322/flareway",
		Version:      version,
		Contact:      []string{"@isac322"},
	}
	if opts.ReportOutputPath == "" {
		opts.ReportOutputPath = filepath.Join(
			"..", "..", "conformance", "reports", "v1.6.2", "flareway",
			"standard-"+version+"-default-report.yaml",
		)
	}

	gatewayconformance.RunConformanceWithOptions(t, opts)
}
