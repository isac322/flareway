# Research ledger — README writing method

Compiled 2026-09-18. This ledger records what was investigated for the
`readme-writing` skill, what was adopted from each source, what was rejected,
and the limits of the evidence. It is deliberately bounded: sources marked
**verified** were inspected at the primary source during this research;
sources marked **reported** were surveyed secondhand and not independently
re-read, so their claims are leads, not authority. The license column says
"not verified" wherever the license was not checked at the source — nothing
here is assumed MIT or CC by default.

## Scope ladder

The evidence behind this method widens in four tiers; each tier can prove
less than the one before it.

1. **README-specific sources** — GitHub's own docs, README-content studies,
   README-authoring skills. These support mechanical checks: a command
   exists, an asset resolves, a claim matches its source, a section answers
   a reader question.
2. **Documentation tooling and linters** — cursorrules, prompt files,
   doc generators. These support mechanical checks only where they state
   concrete constraints (no `$` prompt prefix, referenced files exist);
   their quality claims are unverified.
3. **General writing and plain-language standards** — Strunk, Google
   developer style, ISO 24495-1, AI-tell pattern catalogs. These support
   pattern checks (a tell is present or absent) but only ordinal judgment
   on quality: clearer or not, never a number.
4. **Judge and evaluation reliability research** — MT-Bench, detector-bias
   studies. These support only ordinal judgment and process design
   (position-swap, reference grounding); they cannot quantify README
   quality at all.

Tiers 1–2 justify pass/fail checks. Tiers 3–4 justify judgment calls and
comparisons — nothing in them licenses a score.

## Verified sources

| Source | License | Adopted | Rejected / limits |
|---|---|---|---|
| GitHub Docs — About READMEs <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes> | GitHub docs terms (CC-BY-4.0 docs) | The five reader questions (what it does, why useful, how to start, where to get help, who maintains) as the reader-task map; relative links; README scope | Platform mechanics only — GitHub defines rendering and truncation, not a quality score |
| Google — Creating helpful, people-first content <https://developers.google.com/search/docs/fundamentals/creating-helpful-content> | Site terms | Write for the reader's task, show evidence, know the audience; no preferred word count exists | Search-engine guidance, not a GitHub ranking experiment; do not turn into keyword rules |
| Google developer style — highlights <https://developers.google.com/style/highlights> | CC-BY-4.0 | Active voice, direct address, conditions before instructions, descriptive link text, alt text | Style guidance, not gates; the guide itself says depart when it improves content |
| Agent Skills specification <https://agentskills.io/specification> | not verified | `name`/`description` frontmatter shape; progressive loading via `references/` | Spec governs skill packaging, not README content |
| KieranGao `general-readme-skill` <https://github.com/KieranGao/general-readme-skill/blob/main/SKILL.md> | not verified | Evidence scan before writing; no-fabrication rule | Rejected: mandatory centered HTML, AI-tool badges, a diagram for every project, a fixed 12-section template |
| addyosmani `documentation-and-adrs` <https://github.com/addyosmani/agent-skills/blob/main/skills/documentation-and-adrs/SKILL.md> | not verified | Follow existing repo conventions first; document reasons, not just structure | Rejected: `npm run dev`-style quickstart as universal model; mandatory ADR expansion |
| coreyhaines31 `copy-editing` <https://github.com/coreyhaines31/marketingskills/blob/main/skills/copy-editing/SKILL.md> | MIT (LICENSE verified) | Focused single-purpose editorial passes (clarity, so-what, prove-it, specificity) | Rejected: heightened-emotion sweep, zero-risk promises, manufactured numeric specificity, 3–5 persona panels looping to 8+/10. Its 25-word sentence figure is a heuristic, not a gate |
| coreyhaines31 `copywriting` / `seo-audit` (same repo, MIT verified) | MIT (LICENSE verified) | Problem-first framing, specificity over vagueness; README-applicable on-page items: heading hierarchy, descriptive anchors, image alt | Rejected for README: robots.txt, sitemaps, meta/OG tags, JSON-LD, Core Web Vitals, hreflang — GitHub controls `<head>` and infrastructure; no conversion/CTA copy |
| Prana et al., *Categorizing the Content of GitHub README Files* <https://arxiv.org/abs/1802.06997> | open access (EMSE 2019) | Predictable section semantics help readers find information (4,226 sections / 393 repos annotated; 20 professionals found labeled sections helpful) | Classifier F1 .746 measures classification, not README quality; do not reconstruct the 8 categories as a mandatory checklist; "helpful" ≠ measured speedup |
| Venigalla & Chimalakonda, README–popularity study <https://arxiv.org/abs/2206.10772> | arXiv | Structural hygiene (lists, links, images) correlates with popularity | Association, not causation; stars are not a quality label — no star optimization |
| Liang et al., GPT-detector bias <https://arxiv.org/abs/2304.02819> | arXiv | AI detectors are biased (non-native writers) and unstable — never optimize for them | Detector limitation is not a humanizer quality metric |
| Zheng et al., MT-Bench <https://arxiv.org/html/2306.05685v4> | arXiv perpetual (not CC-BY) | Position-swap in pairwise comparison; reference grounding for judges | Chat-output findings do not validate a README score; self-enhancement evidence inconclusive; no benchmark rates copied |
| gannonh `skills` — readme <https://github.com/gannonh/skills/blob/main/skills/readme/SKILL.md> | MIT (LICENSE verified) | Blast-radius disclosure next to install (background code, writes outside the project, ports, network calls) plus removal steps; real-session command capture | Rejected: absolute ban on problem/solution framing — a short problem statement aids evaluation |
| thatrebeccarae `claude-marketing` — github-readme <https://github.com/thatrebeccarae/claude-marketing/blob/main/integrations/cursor/github-readme.mdc> | MIT (LICENSE verified) | PII/infrastructure scrub list (private hostnames, RFC 1918 and Tailscale `100.x`, cluster/VLAN names, credential prefixes) | Rejected: 0–100 weighted audit scoring; per-type section-requirement matrix; SEO/discoverability items outside README scope |
| PatrickJS `awesome-cursorrules` — readme-best-practices <https://github.com/PatrickJS/awesome-cursorrules/blob/main/rules/readme-best-practices-cursorrules-prompt-file.mdc> | CC0-1.0 (LICENSE verified) | No `$` prompt prefix on copyable commands; verify referenced local assets exist | Rejected: landing-page framing over technical contract |
| 0x0w1 `jig` — readme <https://github.com/0x0w1/jig/blob/main/skills/readme/SKILL.md> | MIT (LICENSE verified) | Explicit drift check when revising an existing README — covered by the Evidence pass | Rejected: dependency on a local `.jig/readme.md` config profile |
| hardikpandya `stop-slop` <https://github.com/hardikpandya/stop-slop> | not verified | Thought-leader tells for the Slop pass: false agency, dramatic fragmentation, negative listing, emphasis crutches, vague declaratives | Rejected: phrase catalog treated as a banlist — patterns are judgment cues, not mechanical bans |
| Aboudjem `humanizer-skill` <https://github.com/Aboudjem/humanizer-skill> | not verified | None adopted — permutation test, treadmill effect, symbolic gloss overlap existing Value/Clarity checks | Rejected: 55-pattern taxonomy as a checklist; catalog kept as reference only |
| danyuchn `iso-24495-skill` <https://github.com/danyuchn/iso-24495-skill> | not verified | Informative headings (message over topic label), ISO 24495-1 principle | Rejected: sentence/paragraph length caps as gates — tripwires at most, per the no-formula-gates rule |
| testdouble `han` — readability rule <https://github.com/testdouble/han> | not verified | None adopted — section-level BLUF and fidelity-first simplification already covered by the Value pass and protected-claims rule | Rejected: constrained em-dash placement — a mechanical punctuation rule |
| Wikipedia:Signs of AI writing (live 2026 page) <https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing> | not verified | Copulative avoidance ("serves as", "stands as", "features", "offers" → `is`/`are`/`has` or a concrete verb) | Rejected: 2023-era historical tells (refusals, token cut-offs, safety disclaimers) that frontier models no longer emit — not worth gate cycles; supersedes the installed late-2025 snapshot |

Inspected and rejected wholesale: `sickn33/agentic-awesome-skills` readme
(rigid monolithic web-app section template), `statelyai/skills` readme
(symbolic HTML-comment pollution of published Markdown),
`dmlin7777777/biane` (origin-story/sales framing for skill marketing
pages), `salihcantekin/awesome-agent-skills` readme-generator (boilerplate,
no concrete constraints), `NPC-Worldwide/npcsh` technical-writing and
`CiscoDevNet/essentials` write-readme (no adoption beyond existing
coverage; dogmatic example-first ordering rejected).

## Reported, not verified

Surveyed in research passes; treated as leads. Do not cite their numbers as
fact.

- **Make a README** (makeareadme.com) — section menu and "smallest runnable
  example first"; license not verified.
- **Standard Readme spec** (RichardLitt/standard-readme) — progressive
  disclosure rationale, ordered sections, zero broken links; license
  reported MIT/CC-BY-4.0, not verified.
- **ZJunCher `ai-readme-skill`** — code-scan grounding, honest TODO markers;
  license not verified.
- **Microsoft Writing Style Guide — scannable content** — front-load key
  information (F-pattern), 3–7-line paragraphs; license not verified. The
  "30-second rule" is not in the source — rejected.
- **Diátaxis** (diataxis.fr) — separate tutorial/how-to/reference/explanation
  concerns; README as portal is a design choice, not a Diátaxis rule.
  License not verified.
- **W3C WAI writing tips** — descriptive link text, heading outlines,
  informative vs decorative alt text. W3C document license.
- **`humanizer` / `writing-clearly-and-concisely` global skills** — AI-tell
  patterns (staged openers, forced triads, puffery) and Strunk's omit-
  needless-words/active-voice. Synthesized into the editorial passes; the
  skills are optional references, not prerequisites. Rejected: mechanical
  em-dash ban.
- **`epoko77-ai/im-not-ai`** — fidelity-first, span-grounded editing,
  change-rate gate. MIT reported; Korean translation-ese focus limits direct
  reuse.
- **Aghajani et al. (ICSE 2019), Kumar et al. (2024), Redish (2000),
  Krippendorff (2011), Wang et al. (2023), Kim et al. (2023)** — cited by
  research passes for documentation-defect taxonomies, readability-formula
  critique, and judge reliability. Not read at primary source; their
  specific figures are not adopted. The contract's own rules (no Flesch
  gate, no fake kappa/alpha, no unverified stats) stand on their own.

## Synthesis

The skill combines: the GitHub reader questions (task map), people-first
evidence discipline (evidence brief), portal/progressive-disclosure ordering
(draft), focused editorial passes (copy-editing + Strunk + AI-tell patterns),
and a hard no-fabrication boundary (KieranGao + project invariants). Anything
a source could not prove — licenses, statistics, universal templates — is
recorded as unverified rather than adopted.
