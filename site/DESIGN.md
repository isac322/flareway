---
name: Flareway
description: A nautical chart drawn for a tunnel operator — cream chart paper, navy ink, and one orange channel that pours out of the logo's open door.
colors:
  # --- light theme (default) ---
  chart-paper: "#fffaf2"
  ink-navy: "#172b4d"
  ink-muted: "#52627a"
  hairline: "#e3daca"
  hairline-soft: "#efe6d6"
  panel: "#ffffff"
  land-tint: "#fdf6ec"
  warm-tint: "#fcebd9"
  cool-tint: "#eef2f8"
  channel-orange: "#e77b35"
  orange-ink: "#b5541c"
  ink-deep: "#0f1f3a"
  # --- code panels (navy in both themes) ---
  code-panel: "#172b4d"
  code-ink: "#e6edf3"
  code-key: "#f5d3b8"
  code-dim: "#a9b5c8"
  code-gutter: "#7f8fa8"
  code-highlight: "rgb(231 123 53 / 0.16)"
  kind-glow: "#f4b585"
  # --- dark theme (data-theme="dark" or OS dark without a light choice) ---
  night-paper: "#161b22"
  night-ink: "#e6edf3"
  night-muted: "#9aa7bc"
  night-hairline: "#2e3644"
  night-hairline-soft: "#232a35"
  night-panel: "#1c2129"
  night-tint: "#1a1f2a"
  night-warm: "#2a2118"
  night-cool: "#1d222b"
typography:
  display:
    fontFamily: "Schibsted Grotesk Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(2.35rem, 1.1rem + 3.1vw, 3.6rem)"
    fontWeight: 700
    lineHeight: 1.04
    letterSpacing: "-0.03em"
  headline:
    fontFamily: "Schibsted Grotesk Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(1.9rem, 1.2rem + 2vw, 2.75rem)"
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "-0.028em"
  title:
    fontFamily: "Schibsted Grotesk Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 650
    lineHeight: 1.35
    letterSpacing: "-0.01em"
  body:
    fontFamily: "Schibsted Grotesk Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: 1.6
  lede:
    fontFamily: "Schibsted Grotesk Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(1.05rem, 0.98rem + 0.3vw, 1.2rem)"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Schibsted Grotesk Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 500
  label-sm:
    fontFamily: "Schibsted Grotesk Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 500
  mono-label:
    fontFamily: "JetBrains Mono Variable, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "13px"
    fontWeight: 500
  mono-voice:
    fontFamily: "JetBrains Mono Variable, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "clamp(1.5rem, 1.1rem + 1.2vw, 2rem)"
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  note:
    fontFamily: "Alegreya, Georgia, serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.4
  code:
    fontFamily: "JetBrains Mono Variable, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "13.5px"
    fontWeight: 400
    lineHeight: 1.62
rounded:
  xs: "4px"
  sm: "5px"
  md: "6px"
  lg: "8px"
  xl: "10px"
  2xl: "12px"
  3xl: "14px"
  4xl: "16px"
  pill: "999px"
spacing:
  gutter: "clamp(20px, 4vw, 48px)"
  section: "clamp(64px, 9vw, 112px)"
  section-head-gap: "clamp(32px, 4vw, 52px)"
  split-gap: "clamp(32px, 5vw, 72px)"
  star-section: "clamp(80px, 11vw, 144px)"
components:
  button-primary:
    backgroundColor: "{colors.ink-navy}"
    textColor: "{colors.chart-paper}"
    rounded: "{rounded.xl}"
    padding: "0 22px 0 40px"
    height: "48px"
    typography: "{typography.label}"
  button-primary-hover:
    backgroundColor: "{colors.ink-deep}"
    textColor: "{colors.chart-paper}"
  button-secondary:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink-navy}"
    rounded: "{rounded.xl}"
    padding: "0 22px"
    height: "48px"
    typography: "{typography.label}"
  button-star:
    backgroundColor: "{colors.ink-navy}"
    textColor: "{colors.chart-paper}"
    rounded: "{rounded.2xl}"
    padding: "0 34px 0 28px"
    height: "64px"
  nav-tab:
    textColor: "{colors.ink-muted}"
    rounded: "{rounded.lg}"
    padding: "8px 12px"
    typography: "{typography.label}"
  nav-tab-hover:
    backgroundColor: "{colors.land-tint}"
    textColor: "{colors.ink-navy}"
  gh-button:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink-navy}"
    rounded: "{rounded.lg}"
    padding: "0 12px"
    height: "36px"
    typography: "{typography.label-sm}"
  chip-origin:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink-navy}"
    rounded: "{rounded.pill}"
    padding: "4px 12px"
    typography: "{typography.mono-label}"
  figure-card:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.4xl}"
    padding: "clamp(14px, 1.8vw, 24px)"
  lockup-plate:
    backgroundColor: "{colors.panel}"
    padding: "clamp(18px, 2.2vw, 28px) clamp(20px, 2.4vw, 30px) 12px"
  code-panel:
    backgroundColor: "{colors.code-panel}"
    textColor: "{colors.code-ink}"
    rounded: "{rounded.4xl}"
    padding: "12px 0 14px"
    typography: "{typography.code}"
  aside-note:
    backgroundColor: "{colors.cool-tint}"
    textColor: "{colors.ink-navy}"
    rounded: "{rounded.xl}"
    padding: "16px 18px"
---

# Design System: Flareway

## Overview

**Creative North Star: "The Charted Passage"**

The logo's door is the product, and the page is drawn like a nautical chart that proves it. A single saturated orange channel pours out of the mark's open doorway, doglegs at 18°, crosses a sealed ink coastline through a doorway, and runs down the left gutter as the spine of the whole page — through a doorway notch in every section divider — until it ends at the star door. Cream chart paper, navy ink, fine hachured land, and dashed fairway limits do the work that gradients, bento grids, and neon hero art do elsewhere.

Density is deliberate and editorial: a 1240px column, split grids that pair flat copy with drawn evidence (the mechanism diagram, real YAML, the fail-closed gates), and quiet hairline rules instead of filled cards. The type system is one confident grotesk carrying everything, a mono reserved for code and the terse "without Flareway" voice, and a small serif italic used strictly as the chart's annotation hand. Motion is a short load-time choreography — the door swings, the channel draws, a request rides in — and every animation collapses to its final state under `prefers-reduced-motion`.

The dark theme is the same chart re-inked for night watch: deep navy paper, pale ink, the same orange channel. Code panels stay navy in both themes — the YAML lives belowdecks regardless of the weather.

**Key Characteristics:**
- One orange channel, drawn as a line, is the only saturated element on the page.
- The doorway motif (two jamb ticks + an orange leaf skewed 18°) marks every "current" or "open" state: active tab, CTA, section dividers, sidebar, gates.
- Flat surfaces with hairline separation; a single ambient shadow reserved for code panels and the closing star CTA.
- Schibsted Grotesk everywhere; JetBrains Mono for code and technical voice; Alegreya italic only as chart annotation.
- Proof over decoration: diagrams, real manifests, and conformance numbers replace testimonials and icon grids.

## Colors

A two-ink system — navy does the talking, orange does the drawing — on warm chart paper, with a full night-chart inversion and a self-contained navy code palette.

### Primary
- **Channel Orange** (#e77b35): the brand's graphic orange. The drawn channel, door leaves, the mark's cloud, star icons, underline accents, the route line lists branch from, and the caret/selection accents. Graphics only on light grounds — never text, never fills behind content.

### Secondary
- **Orange Ink** (#b5541c): the same hue darkened to clear WCAG AA as text. Doc-link accents, caution-aside titles, and the star icon's stroke. In the dark theme the raw Channel Orange is light enough to take this role itself.

### Neutral
- **Chart Paper** (#fffaf2): the warm cream ground every surface floats on.
- **Navy Ink** (#172b4d): all primary text, coastlines, jamb ticks, fairway limits, primary-button fill, and the code panel's ground.
- **Muted Ink** (#52627a): secondary text, captions, tab labels at rest, dashed swing arcs.
- **Hairline** (#e3daca) / **Hairline Soft** (#efe6d6): the two weights of rule — section dividers, card and table borders, and the quieter inner gridlines.
- **Panel White** (#ffffff): figures, code-file bars' counterparts, buttons, chips — the freshest paper on the chart.
- **Land Tint** (#fdf6ec): hachured land and hover fills on tabs and sidebar items.
- **Warm Tint** (#fcebd9): selection background and the tip/caution family of tints.
- **Cool Tint** (#eef2f8): the single cold counterpoint — Cloudflare's edge zone in diagrams, inline-code background, note asides.
- **Ink Deep** (#0f1f3a): primary-button hover, a darker dip of the same navy.

### Dark theme (night chart)
The same roles remapped: **Night Paper** (#161b22) ground, **Night Ink** (#e6edf3) text, **Night Muted** (#9aa7bc), **Night Panel** (#1c2129), and the tint/hairline family stepped darker (#232a35–#2e3644). Buttons invert: paper-colored fill with night-paper text. Orange Ink's role reverts to raw Channel Orange.

### Code palette
Code panels are navy in both themes: **Code Panel** (#172b4d) ground, **Code Ink** (#e6edf3) values, **Code Key** (#f5d3b8) YAML keys, **Code Dim** (#a9b5c8) punctuation and file bars, **Code Gutter** (#7f8fa8) line numbers, **Kind Glow** (#f4b585) `kind:` values, and a translucent Channel Orange line highlight (rgb(231 123 53 / 0.16)).

### Named Rules
**The Graphics-Only Orange Rule.** On light grounds, saturated orange never renders text, backgrounds, or focus rings; anything needing orange words uses Orange Ink. In the dark theme the raw orange may be text. Focus outlines are always ink.

**The One Channel Rule.** There is exactly one accent hue, and it earns its rarity: the channel, the leaf, the star. If an element isn't part of the passage, it stays navy on paper.

## Typography

**Display Font:** Schibsted Grotesk Variable (with ui-sans-serif/system-ui fallback)
**Body Font:** Schibsted Grotesk Variable — one family carries every role from hero to footer legal
**Mono Font:** JetBrains Mono Variable — code, counts, and the terse technical voice
**Annotation Font:** Alegreya italic 400 — chart notes and plate captions only

**Character:** a confident modern grotesk set tight (-0.03em at display sizes) and left to breathe at body (17px / 1.6). The mono is technical evidence, the italic a hand-drawn note in the margin — three voices with sharply separated jobs.

### Hierarchy
- **Display** (700, clamp 2.35–3.6rem, lh 1.04, -0.03em): the hero H1 only; max 15ch.
- **Headline** (700, clamp 1.9–2.75rem, lh 1.08, -0.028em): section H2s; 18–22ch measures; the star section stretches to 3.2rem.
- **Title** (650, 17px, lh 1.35, -0.01em): H3s, output rows, footer group heads.
- **Lede** (400, clamp 1.05–1.2rem, lh 1.55): section intros, muted ink, 46–58ch.
- **Body** (400, 17px, lh 1.6): prose; docs hold a 70ch measure.
- **Label** (500–600, 14–15.5px): tabs, buttons, proof-strip labels, footer nav. No uppercase, no letter-spacing.
- **Mono Voice** (500, clamp 1.5–2rem, lh 1.2, -0.02em): the "running cloudflared alone" list — mono as a display voice, not just code.
- **Note** (Alegreya italic, 400–500, 15–16.5px): chart annotations, plate caption, kinds note. Never UI text.
- **Code** (400, 13.5px / 1.62 panel, 0.88em inline): JetBrains Mono, ligatures off.

### Named Rules
**The Chart Voice Rule.** Alegreya italic speaks only from the drawing — annotations, the cartouche plate caption. Headings, labels, and buttons never set it, and no other serif appears.

**The Tabular Counts Rule.** `tabular-nums` applies to counted digits ("37/37", star counts, line numbers) and never to digits inside names like "Apache-2.0".

## Layout

A single 1240px column (`--fw-landing-wrap`) with fluid gutters (clamp 20–48px) carries everything. The hero splits roughly 45/55: cartouche plate on hachured land left, flat intro right. Interior sections use split grids (≈1.04fr/1fr variants) separated by a consistent clamp(64px, 9vw, 112px) rhythm; the star closing room widens to 144px of air.

The orange channel is the page's left-gutter spine, computed live by `landing-chart.ts` from the real layout — 12px wide, widening to 22px above 1321px — and rebuilt on resize. Under 640px it pins to the left edge and content insets to keep ≥20px clear of the inner fairway limit. Two-way splits stack under 1060px; tabs become a horizontal scroller; the doorway between the Why columns is removed. Docs prose holds a 65–75ch measure while code, tables, and figures take the full column.

**The Spine Rule.** Content never crosses the channel. Divider rules are drawn so the channel passes through a doorway; on narrow screens the gutter is reserved space, not overlap.

## Elevation & Depth

Flat by conviction: separation comes from paper tones and 1px hairlines, not lift. One ambient shadow exists — a soft navy drop (`0 1px 2px rgb(23 43 77 / 0.06), 0 12px 32px -12px rgb(23 43 77 / 0.18)`) reserved for the code panel and the star CTA, the two places the page literally goes below the surface. The dark theme trades it for a hairline border and a deeper black shadow token that stays unused at rest.

Depth otherwise comes from the chart itself: the underlay draws land behind content, the overlay draws the channel above the rules it crosses, and the lockup plate frames the mark with an ink border plus an inset hairline (a double-rule plate, `inset 0 0 0 4px panel / 5px hairline`).

### Shadow Vocabulary
- **Panel lift (light)** (`0 1px 2px rgb(23 43 77 / 0.06), 0 12px 32px -12px rgb(23 43 77 / 0.18)`): code panel, star CTA.
- **Panel lift (dark)** (`0 1px 2px rgb(0 0 0 / 0.3), 0 16px 40px -16px rgb(0 0 0 / 0.6)`): same roles; code panels additionally take a hairline and drop the shadow.

**The Belowdecks Rule.** Elevation marks a change of medium — the navy code well, the room behind the star door — never a resting state. Nothing hovers.

## Shapes

**The Doorway Motif Rule.** Every "passage" or "current" marker is the same figure: two short ink jamb ticks bracketing a gap, with an orange door leaf skewed 18° (`--fw-door-slant`) on its hinge. It appears as the active-tab notch in the header rule, the primary button's notch with a leaf that swings wider on hover, the gap-and-jambs divider the channel passes through, the sidebar's current-page glyph, the fail-closed gate marks, and the column-door in Why.

Radii are calm and scaled to size: 4px focus corners, 5px inline code, 6px small controls, 8px header chrome and tabs, 10px buttons and asides, 12–16px figures and code panels, a true pill only for the origin chips. The lockup plate is deliberately square — a chart cartouche has corners, not radii.

## Components

### Buttons
- **Shape:** gently rounded (10px; 12px for the star CTA).
- **Primary:** navy fill, paper text, 48px tall, `0 22px 0 40px` padding — the extra left room holds the signature: a paper-colored doorway notch in the bottom edge with an orange leaf that skews open 18° on hover/focus, while the arrow nudges 3px right.
- **Secondary / Ghost:** panel white, ink text, 1px hairline border that darkens to muted ink on hover.
- **Tertiary:** an underlined muted-ink link (15px) whose underline turns orange on hover — the only state change it needs.
- **Star CTA:** the closing button — 64px tall, navy, a rotating orange star icon, and the live star count separated by a hairline.
- **All buttons:** `:active` presses 1px down; transitions run on the shared `cubic-bezier(0.16, 1, 0.3, 1)` ease.

### Navigation
- Sticky 64px header: translucent paper (86% + `backdrop-filter: blur(10px) saturate(1.4)` — the only translucency in the system), hairline bottom rule, lockup left, tabs center, GitHub pill right.
- Tabs are quiet text (15px, muted ink); the current tab darkens to ink 600 and wears the doorway notch + swung-open leaf on the header's bottom rule. Hover is a land-tint wash on an 8px rounded hit area.
- GitHub pill: 36px hairline button with mark, label, and a star affordance separated by a hairline; the star icon tilts −12° on hover.
- Docs sidebar: current page is marked by the doorway glyph in the gutter — never a filled pill or colored bar.

### Code Panels
- Navy in both themes, 16px radius, the system's one shadow (light only), mono 13.5/1.62.
- File bars carry a mono filename and a small copy chip (6px radius, hairline) that flips to Code Key when done.
- Lines have a 44px right-aligned gutter of tabular numbers; a highlighted line shows a translucent orange wash with a 3px orange bar at its left edge.
- Shell prompts render as `$` in the gutter; YAML keys take Code Key, values Code Ink, `kind:` values Kind Glow.

### Cards / Containers
- **Figure card:** white panel, 16px radius, 1px hairline, clamp(14–24px) padding; a caption row under a soft hairline with a mono figure ratio.
- **Lockup plate:** white, square corners, 1px ink border with an inset 4px hairline — the double-rule cartouche frame; an Alegreya italic caption right-aligned in the foot so the channel clears it.
- **Variants table:** a 1px ink-outlined ledger — 3-column grid of soft hairlines, mono kind names, muted descriptions.
- **Asides (docs):** 10px radius hairline panels; variant shows in tint (cool = note, land = tip, warm = caution) with the accent reserved for caution's title and icon.

### Chips
- **Origin chips:** true pills (999px), 1px hairline, mono 13px — used for Direct-mode origin types only.

### Proof & Lists
- **Proof strip:** a hairline-topped 3-column row — bold ink values over muted labels, vertical hairlines between, tabular counts, hover underlines in orange.
- **Gates (fail-closed):** two gate marks in series on one dashed ink limit — jamb-ticked doorways whose leaves stay shut; guarantees are a dt/dd ledger under an ink top rule.
- **Kinds list:** items branch off a 2px orange route line with 1px ink stubs — the route line, not a list border.

### The Channel Chart (signature)
Two live SVG layers frame the page: an underlay (hachured land at 0.7px/20% ink, a 1.6px ink coastline, contour hairlines, Alegreya notes) and an overlay (the orange channel, dashed 1.4px fairway limits, jamb ticks, swing arcs, gate crosses). Geometry derives from the rendered DOM and rebuilds on resize; the page reads fully without it.

### Docs specifics
- Prose links: ink text on a 1.5px orange underline that darkens to ink on hover.
- Tables: hairline rows, an ink-underlined header, tabular numerals, land-tint row hover.
- Pagination cards and the search trigger share the 8–10px hairline-on-panel treatment, no shadows.

## Do's and Don'ts

### Do:
- **Do** draw the doorway motif — jambs + 18° orange leaf — for current/open states instead of pills, filled backgrounds, or colored side bars.
- **Do** keep code panels navy in both themes; the code palette is a separate weather system.
- **Do** separate ink text from orange graphics; reach for Orange Ink (#b5541c) the moment orange must be read, not seen.
- **Do** use hairlines (Hairline / Hairline Soft) for all separation; reserve the single shadow for belowdecks surfaces.
- **Do** render the lockup and mark from the brand vectors (`src/components/brand/paths.ts`); the wordmark is an outline, never re-typeset.
- **Do** honor `prefers-reduced-motion` and `prefers-color-scheme`; under reduced motion every leaf is drawn open and every line drawn complete.
- **Do** keep buttons 48px tall, ink focus outlines 2px with a 3px offset, and prose measures at 46–75ch.

### Don't:
- **Don't** put saturated orange in text, filled backgrounds, or focus rings on light grounds — it is a graphic channel, not ink.
- **Don't** add eyebrow/kicker labels above headings; the system speaks in H2 + lede.
- **Don't** introduce a second accent hue, gradients on content surfaces, or hard offset shadows; translucency belongs to the sticky header only.
- **Don't** set UI text, labels, or headings in Alegreya — it is the chart's annotation hand only.
- **Don't** restyle, re-proportion, or re-color the fixed logo mark or wordmark, and never combine the Kubernetes Gateway API and Cloudflare logos (brand commitment).
- **Don't** mark current nav or sidebar items with filled pills or accent backgrounds — the doorway glyph is the convention.
- **Don't** invent testimonials, metrics, or status disclaimers; proof is drawn from the repo, never fabricated.
