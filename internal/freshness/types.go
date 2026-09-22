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

import (
	"fmt"
	"time"
)

// Grade is the freshness requirement of a remote read site (D1).
type Grade int

const (
	// GradeAlways (T0) is never gated: the remote is always read fresh.
	// Applies to reads before destructive writes, adoption/ownership claims,
	// inside WithTunnelLock, and ObserveOnly observation.
	GradeAlways Grade = iota

	// GradeAuthz (T1) covers authorization and access-control resources
	// (default 60s).
	GradeAuthz

	// GradeTraffic (T2) covers traffic routing and DNS records
	// (default 300s).
	GradeTraffic

	// GradeIndirect (T3) covers device settings and indirect resources
	// (default 1800s).
	GradeIndirect

	// GradeDisplay (T4) covers display-only observation such as connector
	// state (default 0: no periodic read).
	GradeDisplay
)

// String returns the grade's stable name for logs and metrics.
func (g Grade) String() string {
	switch g {
	case GradeAlways:
		return "Always(T0)"
	case GradeAuthz:
		return "Authz(T1)"
	case GradeTraffic:
		return "Traffic(T2)"
	case GradeIndirect:
		return "Indirect(T3)"
	case GradeDisplay:
		return "Display(T4)"
	default:
		return fmt.Sprintf("UnknownGrade(%d)", int(g))
	}
}

// Policy carries the per-grade cache TTL injected manager-wide via the
// --freshness-* flags (D1).
type Policy struct {
	Authz    time.Duration // --freshness-authz (default 60s)
	Traffic  time.Duration // --freshness-traffic (default 300s)
	Indirect time.Duration // --freshness-indirect (default 1800s)
	Display  time.Duration // --freshness-display (default 0)
}

// DefaultPolicy returns the recommended profile from D1.
func DefaultPolicy() Policy {
	return Policy{
		Authz:    60 * time.Second,
		Traffic:  300 * time.Second,
		Indirect: 1800 * time.Second,
		Display:  0,
	}
}

// TTL returns the freshness bound for grade g. GradeAlways and unknown
// grades return 0 so they can never open the gate (fail-closed).
func (p Policy) TTL(g Grade) time.Duration {
	switch g {
	case GradeAlways:
		return 0
	case GradeAuthz:
		return p.Authz
	case GradeTraffic:
		return p.Traffic
	case GradeIndirect:
		return p.Indirect
	case GradeDisplay:
		return p.Display
	default:
		return 0
	}
}

// Validate enforces the D1 invariants: no negative durations, and
// Authz <= Traffic <= Indirect among the enabled (positive) durations. A
// zero duration means "no periodic read" for that grade and is exempt from
// the ordering check — disabling a stricter grade never weakens a looser
// one.
func (p Policy) Validate() error {
	if p.Authz < 0 {
		return fmt.Errorf("invalid authz freshness duration %v: duration cannot be negative", p.Authz)
	}
	if p.Traffic < 0 {
		return fmt.Errorf("invalid traffic freshness duration %v: duration cannot be negative", p.Traffic)
	}
	if p.Indirect < 0 {
		return fmt.Errorf("invalid indirect freshness duration %v: duration cannot be negative", p.Indirect)
	}
	if p.Display < 0 {
		return fmt.Errorf("invalid display freshness duration %v: duration cannot be negative", p.Display)
	}

	if p.Authz > 0 && p.Traffic > 0 && p.Authz > p.Traffic {
		return fmt.Errorf("freshness invariant violation: Authz (%v) cannot be greater than Traffic (%v)", p.Authz, p.Traffic)
	}
	if p.Traffic > 0 && p.Indirect > 0 && p.Traffic > p.Indirect {
		return fmt.Errorf("freshness invariant violation: Traffic (%v) cannot be greater than Indirect (%v)", p.Traffic, p.Indirect)
	}
	if p.Authz > 0 && p.Indirect > 0 && p.Authz > p.Indirect {
		return fmt.Errorf("freshness invariant violation: Authz (%v) cannot be greater than Indirect (%v)", p.Authz, p.Indirect)
	}

	return nil
}

// Decision reports the outcome of a gate evaluation. The closed_* values
// match the flareway_gate_total metric labels in internal/observability;
// callers pass string(gate.Decision) to observability.ObserveGate.
type Decision string

const (
	// DecisionOpen reports an open gate: the remote read may be skipped.
	DecisionOpen Decision = "open"
	// DecisionClosedHash reports that appliedHash is empty, desiredHash is
	// empty, or they differ.
	DecisionClosedHash Decision = "closed_hash"
	// DecisionClosedTTL reports a non-positive grade TTL, a missing
	// appliedAt, or a snapshot age outside the TTL (including clock skew).
	DecisionClosedTTL Decision = "closed_ttl"
	// DecisionClosedInvalidated reports that the sweep invalidated this
	// object.
	DecisionClosedInvalidated Decision = "closed_invalidated"
	// DecisionNotGated reports GradeAlways (T0), which is not a gate
	// evaluation at all. It is deliberately not a registered metric label;
	// do not observe it.
	DecisionNotGated Decision = "not_gated"
)

// Gate is the result of a desired-hash gate evaluation.
type Gate struct {
	Open     bool          // true: the remote read may be skipped
	Requeue  time.Duration // when Open: interval until self-expiry
	Decision Decision      // why the gate closed; DecisionOpen when open
}
