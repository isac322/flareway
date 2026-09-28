# Architecture decision records

Each record explains one decision that shapes how Flareway behaves: the problem, what was decided, and what that choice costs.

| ADR | Decision |
|---|---|
| [0001](0001-gateway-api-on-cloudflare.md) | Gateway API on Cloudflare Tunnel |
| [0002](0002-dns-sweep-zone-isolation.md) | Isolate DNS sweep failures per zone |
| [0003](0003-production-logging-defaults.md) | Production logging defaults |
| [0004](0004-tunnel-status-condition-ownership.md) | One field manager for tunnel conditions |
| [0005](0005-servicetoken-create-before-capture.md) | Journal ServiceToken create intent |
| [0006](0006-gateway-dataplane-rejection.md) | Report dataplane apply rejections |

## Format

Each record is one Markdown file named `NNNN-short-title.md`, numbered in the order it was written. It opens with a status line (`Proposed`, `Accepted`, or `Superseded by` another record) and then has these sections:

- Context: the problem and the constraints the decision had to respect.
- Decision: what Flareway does, stated precisely enough to check against the code.
- Consequences: what the decision makes easier, what it makes harder, and what operators see.
- Alternatives: the options considered and why each was rejected.

## When to add one

Add a record in the same pull request as a change that is hard to reverse or that a later contributor would otherwise have to reconstruct from the code: a new ownership or authorization rule, a change to what a status condition means, a failure mode that must fail closed, or a new default that operators depend on. Bug fixes and refactors that keep the documented behavior do not need one.

When a decision changes, write a new record and mark the old one `Superseded by` the new number. Existing records are not rewritten.
