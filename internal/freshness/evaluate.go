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

import "time"

// Evaluate judges the D2 gate conditions in a fixed order. Every doubt
// resolves to a closed gate (D5 fail-closed):
//
//  1. grade == GradeAlways (T0): closed — never gated at all
//     (DecisionNotGated).
//  2. TTL(grade) <= 0: closed — on-demand grades (T4) and unknown grades
//     have no cache (closed_ttl).
//  3. invalidated: closed — the sweep found drift (closed_invalidated).
//  4. appliedHash == "" || desiredHash == "" || appliedHash != desiredHash:
//     closed — never applied or desired state changed (closed_hash).
//  5. appliedAt.IsZero(): closed — no recorded apply time; callers pass the
//     zero Time for a nil status.appliedAt (C11) (closed_ttl).
//  6. age := now.Sub(appliedAt); age < 0 || age >= TTL: closed — clock skew
//     or snapshot older than the bound (closed_ttl).
//  7. otherwise: open, with Requeue = TTL - age (self-expiry, D10).
func (p Policy) Evaluate(grade Grade, appliedHash, desiredHash string, appliedAt, now time.Time, invalidated bool) Gate {
	// 1. T0 is never gated.
	if grade == GradeAlways {
		return Gate{Open: false, Decision: DecisionNotGated}
	}

	// 2. A non-positive TTL means no caching for this grade (T4 on-demand,
	// unknown grades fail closed via TTL == 0).
	ttl := p.TTL(grade)
	if ttl <= 0 {
		return Gate{Open: false, Decision: DecisionClosedTTL}
	}

	// 3. Sweep invalidation latch.
	if invalidated {
		return Gate{Open: false, Decision: DecisionClosedInvalidated}
	}

	// 4. Hash pair must exist and match.
	if appliedHash == "" || desiredHash == "" || appliedHash != desiredHash {
		return Gate{Open: false, Decision: DecisionClosedHash}
	}

	// 5. Never applied (nil status.appliedAt arrives as the zero Time).
	if appliedAt.IsZero() {
		return Gate{Open: false, Decision: DecisionClosedTTL}
	}

	// 6. Age must be inside the TTL. A negative age means the stamp is in
	// the future (clock skew); treat it as stale rather than trusting it.
	age := now.Sub(appliedAt)
	if age < 0 || age >= ttl {
		return Gate{Open: false, Decision: DecisionClosedTTL}
	}

	// 7. Open: requeue at self-expiry. age is in [0, ttl) so requeue is
	// strictly positive; the guard keeps that contract if the ordering
	// above ever changes.
	requeue := ttl - age
	if requeue <= 0 {
		return Gate{Open: false, Decision: DecisionClosedTTL}
	}

	return Gate{Open: true, Requeue: requeue, Decision: DecisionOpen}
}
