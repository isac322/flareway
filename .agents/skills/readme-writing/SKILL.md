---
name: readme-writing
description: "Write or revise a repository README from repository evidence: build an evidence brief, map reader tasks, draft in reader order, run bounded editorial passes, and hand off to independent evaluation. Trigger: README authoring, rewriting, or restructuring for a software repository."
---

# README Writing

Use this skill when writing or substantially revising a repository
`README.md`. The README is the repository's entry-point contract: it answers
reader questions with claims the repository can prove, in the order readers
need them.

For this repository, load `references/flareway.md` first — it is the project
fact map (identity, selected assets, maturity, install path, doc links). For
the provenance of this method, read `references/research.md`. After drafting,
hand off to the independent evaluator in `../readme-evaluation/SKILL.md`; the
writer never scores its own draft.

Repository invariants (G0–G8) apply to every claim — see
`../../rules/flareway-invariants.md`. Reference them; do not restate them in
the README.

## Procedure

### 1. Build the evidence brief

Before writing prose, collect the facts the README may assert. Every
task-critical claim needs a repository source — a file, doc, manifest, or
report that proves it. Record, each with its source:

- **Identity** — one-sentence definition, name, tagline.
- **Maturity** — version, stability, known-unverified behavior, production
  stance.
- **Audience fit** — who benefits; who should not use it.
- **First safe action** — the least destructive command a new reader can run,
  its prerequisites, and its expected outcome.
- **Architecture** — the smallest accurate mental model.
- **Deeper docs** — install, operations, API reference, design,
  troubleshooting paths that exist.
- **Maintenance and license** — license file, contributing/security pointers
  that exist.

A claim with no source is deleted or rewritten, never shipped. Never invent
commands, flags, version numbers, release tags, contact channels, or
anecdotes.

### 2. Map reader tasks

Order the README by what each reader needs to decide, not by a fixed section
template:

- **Evaluator** (first screen): what it is, who it is for, maturity.
- **Operator**: prerequisites, first safe action, expected outcome, next
  step.
- **Developer**: minimal working example or a pointer to samples.
- **Contributor**: docs, conformance, license.

State fit and non-fit explicitly: a short "use it when / not when" beats a
feature list.

### 3. Draft in reader order

A workable default order: what it does → why it is useful → how it works →
first safe action → maturity and limits → where to go deeper → maintenance
and license. Adapt the order when the project demands it; the reader
questions stay the same. Keep the README an orientation portal: link to
install guides, API references, and design docs instead of copying their
content. Progressive disclosure — the decision-critical fact comes before
the detail, and detail lives behind links.

### 4. Bounded editorial passes

Run focused passes, each with one job. Stop when a pass finds nothing.

1. **Evidence** — every command, flag, name, number, and limitation still
   matches its source; nothing unsupported survived editing. Commands and
   captured output come from a real session, not an idealized one;
   copyable commands carry no shell-prompt prefix (`$`, `>`); every
   referenced local asset (screenshots, demo GIFs) exists in the
   repository. Anything the reader installs that runs background code,
   writes outside the project, opens ports, or makes network calls is
   disclosed next to the install step, with how to remove it.
2. **Value** — each section answers a reader question; delete sentences that
   only restate the heading.
3. **Clarity** — active voice, definite language, conditions before
   instructions ("To do X, run Y"), needless words removed. Prefer plain
   `is`/`are`/`has` or a concrete verb over dressed-up copulas ("serves
   as", "stands as", "features", "offers"). A heading that makes a claim
   or promises an outcome states it ("Refunds take 5–7 days", not "Refund
   information"); conventional navigational labels readers scan for
   (Documentation, License, Installation) stay labels.
4. **Slop** — remove staged openers ("In today's fast-paced…"), unsupported
   puffery ("seamless", "robust", "cutting-edge"), forced triads, not-X-but-Y
   scaffolding, repeated conclusions, chat leftovers — and the
   thought-leader register: false agency that hands abstractions human
   volition ("the data tells us", "the market rewards"), dramatic
   fragmentation and staccato drama ("X. And Y. And Z."), negative listing
   before the reveal ("Not a tool. Not a framework. A runtime."), emphasis
   crutches and Socratic posturing ("Full stop.", "Let that sink in."),
   and vague declaratives that assert importance without naming substance
   ("The implications are significant.").
5. **Voice** — technical vocabulary stays; no fake anecdotes, no manufactured
   numeric specificity, no mechanical word or punctuation bans.

Protected during every pass: commands, flags, paths, names, links, version
numbers, and stated limitations. An edit that changes any of them without
evidence is a defect, not a polish — but when repository evidence shows a
command or claim is wrong, correcting it is required, not prohibited.

### 5. Hand off to evaluation

Give the evaluator the draft plus the evidence brief. Fix the concrete
defects it reports; do not iterate to maximize a score. Keep fix rounds
bounded — when defects persist across rounds, re-examine the evidence
brief and the workflow around it; do not assume a single root cause.

## Guardrails

- **No fabrication** — commands, credentials, contact channels, release tags,
  performance numbers, or "ready in N minutes" promises.
- **No SEO machinery** — no keyword-density targets, no meta/schema tricks
  (a README cannot set them anyway), no ranking promises. Use natural domain
  terms because readers search for them, not to game an index. GitHub
  repository search and web search indexing are different systems; honest
  terms and structure serve the first, and the second is outside README
  control.
- **No AI-detector optimization** — detector scores are biased and unstable;
  edit for reader clarity, never to evade a classifier.
- **No readability-formula gates** — syllable formulas penalize required
  domain vocabulary. Sentence length is a heuristic to notice, not a gate.
- **Informative visuals only** — badges and images carry real information
  (CI state, license, architecture); no decorative AI-tool badges or unearned
  claims.
- **Public-repository scrub** — private hostnames, RFC 1918 and Tailscale
  `100.x` addresses, internal cluster/VLAN names, and credential prefixes
  (`sk-`, `ghp_`, `token_`, `Bearer`) never appear. This is invariant G8
  in `../../rules/flareway-invariants.md`; cite it, do not restate it.
- **Standalone** — the procedure must work without any global skill, tool,
  or plugin installed.

## References

- `references/flareway.md` — project fact map: identity, selected assets,
  maturity, install path, links, claims not to make. Load first for this
  repository.
- `references/research.md` — source ledger: what was investigated, adopted,
  rejected, and the limits of each source.
- `../readme-evaluation/SKILL.md` — the independent evaluation contract this
  skill hands off to.
