# README evaluation rubric

Single owner of the scoring rubric, hard checks, and reader questions for
`../../readme-writing/references/research.md` holds the evidence
ledger this rubric is applied against; do not duplicate it here.

This rubric is a local review convention. It is not a validated universal
measure of README quality, not a search ranking signal, and not a predictor of
reader success. Scores are ordinal judgments anchored to evidence, never
probabilities.

## Status vocabulary

Every check and answer uses exactly one status:

- `pass` — verified against cited evidence.
- `fail` — contradicted by evidence or a deterministic defect.
- `unknown` — insufficient evidence to decide. Never silently upgraded.
- `not-applicable` — genuinely irrelevant to this README, decided before
  evaluation begins and recorded with a reason. Required content that is
  missing is scored 0/1, never N/A.

## Hard checks

Hard checks gate the review. Each is reported with status and reason; a
`fail` on any hard check is a fatal defect that no dimension score can
compensate.

| # | Check | What fails it |
|---|-------|---------------|
| H1 | Task-critical claims are supported by repository evidence | A command, feature, path, version, or behavior the reader must rely on has no backing in the evidence snapshot, or contradicts it |
| H2 | No dangerous or unverifiable action is presented as safe | README invites running a copied/unknown command, applying placeholder manifests blindly, using credentials insecurely, silently changing production state, or an install/run step whose blast radius — background execution, writes outside the project, opened ports, network calls, or the removal path — is not disclosed where the reader acts |
| H3 | Prerequisites and expected outcome precede the action | The first task asks the reader to act before stating what must be installed/configured and what success looks like |
| H4 | Local destinations resolve and images carry alternatives | Broken local file/directory link or anchor; non-decorative image without alt text (empty alt requires manual purpose review, not automatic fail) |
| H5 | No known critical contradiction | README states something the repository evidence directly disproves (e.g. HA claims for a single-replica controller, production readiness for an experimental project) |
| H6 | Public-repository hygiene | README publishes private hostnames, internal addresses, or credential-looking strings; see rule://flareway-invariants G8 |

Scope discipline: `unknown` on a critical verification stays explicitly
unverified — source inspection is not a deployment test, and a rendered check
is not a live check. Name the verification scope separately:
documentation/static, rendered, or live deployment.

## Six dimensions

Six equal ordinal dimensions, each scored 0–3 against the anchors below.
Generic scale: 0 = missing or wrong; 1 = material gap; 2 = usable with no
critical omission; 3 = strong, traceable handling. Score against evidence,
not effort. Insufficient evidence for a dimension is `unknown`, never a
silent 3.

### D1 — Purpose and audience fit

- 0: No statement of what the project is or who it serves, or the statement
  is wrong.
- 1: Purpose exists but audience is vague, or fit/non-fit boundaries are
  absent so readers cannot self-select.
- 2: Clear purpose and a usable audience signal; a reader can decide whether
  the project applies to them.
- 3: Purpose, audience, and explicit non-fit cases are stated and traceable
  to repository evidence.

### D2 — First task and use path

- 0: No actionable first step, or the offered step is unsafe/wrong.
- 1: A first step exists but prerequisites, command context, expected
  outcome, or the next step after success are missing.
- 2: A safe first task with prerequisites, context, and expected outcome;
  reader can complete it without guessing.
- 3: The first task is the safest meaningful action, fully contextualized,
  and routes onward to deeper docs; the choice is justified by evidence.

### D3 — Technical fidelity, maturity and limitations

- 0: Technical claims are fabricated, or maturity is misrepresented (e.g.
  experimental presented as production-ready).
- 1: Mostly accurate but overstates maturity, omits known limitations, or
  blurs verified vs unverified behavior.
- 2: Claims match evidence; maturity and major limitations are stated
  honestly.
- 3: Every load-bearing claim is traceable; limitations, unsupported
  features, and verification scope are explicit and specific.

### D4 — Structure and findability

- 0: No navigable structure; a reader cannot locate tasks or docs.
- 1: Sections exist but ordering buries the reader's first questions, or
  progressive disclosure is absent (detail dumps where routes belong).
- 2: Logical order answering identity → use → depth; headings and links let
  a reader route to tasks and deeper docs.
- 3: Structure mirrors the reader task map; every section earns its place,
  and routes to deeper documentation are descriptive and complete.

### D5 — Prose clarity and useful specificity

- 0: Prose is unreadable, padded, or dominated by unsupported claims.
- 1: Readable but carries filler, staged openings, repeated conclusions,
  sales-style claims without evidence, or generated-prose tells: false
  agency, dramatic fragmentation, negative listing, emphasis crutches, or
  vague declaratives.
- 2: Direct prose; claims are specific and supported; no critical
  vagueness.
- 3: Every sentence carries information; technical vocabulary is preserved,
  specificity is real (not manufactured numbers), and tone is honest.
  Copulatives are direct (`is`/`are`/`has`, not `serves as`/`stands as`).
  A heading that makes a claim or promises an outcome states it
  ("Try it: render the manifests", not "Getting started"); conventional
  navigational labels readers scan for — Documentation, License,
  Installation — stay labels and are not a defect.

### D6 — Discovery and accessibility

- 0: Missing terms a reader would search for, or rendering is broken.
- 1: Some natural domain terms present but links are non-descriptive
  ("click here"), images lack alternatives, headings skip levels or
  collide as anchors, or rendering has gaps.
- 2: Natural domain vocabulary, descriptive link text, image alternatives,
  headings that increment one level at a time and stay unique enough to
  produce stable anchors (accessibility and intra-document linking, not
  style), and clean rendering.
- 3: Terminology matches how the audience actually searches and speaks;
  every link and image is accessible; rendering verified where in scope.

## Scoring and reporting

- Report the six-dimension vector. An optional sum `/18` may be reported as
  descriptive only — never as a probability, scientific metric, or SEO
  score.
- Review-ready convention: no known hard-check failures, scope and
  unknowns documented, every scored dimension ≥ 2. The total never
  compensates a fatal defect.
- N/A dimensions are excluded from the denominator transparently, with the
  pre-evaluation reason recorded.
- An `unknown` dimension is reported as `unknown` in the vector — never as
  0 and never dropped like N/A. While an applicable dimension is `unknown`,
  report no full total and no review-ready verdict; report the dimension as
  pending within the declared scope until the evidence is obtained.

## Reader-task check

The reviewer answers six preset questions as a fresh reader, citing the
exact README span (and linked source where the README routes outward) that
answers each:

1. What is this project, and who is it for?
2. What is the main thing it lets me do?
3. What is the first safe step, and what do I need before it?
4. What are its limits and readiness caveats?
5. Where do I go for deeper docs or help?
6. How is it maintained and licensed?

Report `answered/6`, list missing or `unknown` answers, and optionally note
required clicks. This measures document answerability, not real user success
or time.

## Comparison protocol

- Baseline and candidate are copied to anonymous scratch files; reviewers
  are independent of the writer and use the same rubric and evidence
  snapshot.
- Presentation order is reversed between reviewers (A/B then B/A) to blunt
  position bias.
- Ties and unresolved disagreements are allowed outcomes. Report full
  judgments and disagreements; never infer reliability from one pair, and
  never "improve" a document by filling keyword buckets.

## Challenge protocol

Before trusting a review pass, run the procedure against a scratch challenge
set with real negative controls:

- a broken local link;
- a removed experimental warning plus a false production promise;
- a missing prerequisite/context for the first task;
- repetitive sales prose;
- a clean control document.

Hard checks must catch the safety/correctness failures even when prose
scores high. Automated checking (`scripts/audit.py`) and semantic judging
have different detection coverage — run both. After fixes, re-check the
current document, not the earlier revision.

Two checks remain reviewer judgment; the deterministic helper cannot
perform them:

- Paragraph-permutation test: if sections can be reshuffled without the
  document reading as broken, cohesion is absent.
- Treadmill test: consecutive paragraphs restating one idea in new words.
