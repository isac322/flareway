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

package freshness

// gradeByKind is the canonical freshness grade for every Cloudflare-backed
// resource kind, assigned by how directly a stale judgement affects a security
// or traffic outcome.
//
// This table is the single source of truth for two consumers that must agree:
// the reconciler gate, which decides how long a remote read may be skipped, and
// the drift sweep, which decides how often the remote is listed. If the sweep
// period exceeded the gate TTL, the operator would promise "drift is detected
// within T" while only looking every T', and the promise would be false for the
// difference. Deriving both from this table makes that mismatch impossible.
//
// Kinds absent from this table have no gate and no sweep. CloudflareAccount is
// deliberately absent: its remote calls are the resource's own liveness and
// authorization evidence rather than convergence reads.
var gradeByKind = map[string]Grade{
	// T1 — the authorization decision itself.
	"AccessApplication":           GradeAuthz,
	"AccessStandaloneApplication": GradeAuthz,
	"AccessPolicy":                GradeAuthz,
	"AccessGroup":                 GradeAuthz,
	"AccessCustomPage":            GradeAuthz,
	"AccessInfrastructureTarget":  GradeAuthz,
	"ServiceToken":                GradeAuthz,
	"IdentityProvider":            GradeAuthz,

	// T2 — the traffic path. Where requests are sent, and which requests the
	// edge admits at all.
	"CloudflareTunnel":       GradeTraffic,
	"DNSRecord":              GradeTraffic,
	"ZeroTrustGatewayPolicy": GradeTraffic,
	"ZeroTrustList":          GradeTraffic,
	"VirtualNetwork":         GradeTraffic,
	"NetworkRoute":           GradeTraffic,
	"HostnameRoute":          GradeTraffic,

	// T3 — indirect. Posture and device settings shape future sessions rather
	// than steering live traffic.
	"DeviceProfile":            GradeIndirect,
	"DevicePostureRule":        GradeIndirect,
	"DevicePostureIntegration": GradeIndirect,
	"DeviceSettings":           GradeIndirect,
	"ZeroTrustOrganization":    GradeIndirect,
	"WARPConnector":            GradeIndirect,
}

// GradeForKind returns the canonical grade for a resource kind. The second
// result is false for kinds that are neither gated nor swept; callers must not
// substitute a default, because guessing a grade here is exactly the mismatch
// this table exists to prevent.
func GradeForKind(kind string) (Grade, bool) {
	grade, found := gradeByKind[kind]
	return grade, found
}

// GradedKinds returns every kind carrying a canonical grade. Order is
// unspecified; callers that need determinism must sort.
func GradedKinds() []string {
	kinds := make([]string, 0, len(gradeByKind))
	for kind := range gradeByKind {
		kinds = append(kinds, kind)
	}
	return kinds
}
