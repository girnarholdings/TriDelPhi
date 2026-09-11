---
name: TriDelPhi
description: Transit-wayfinding identity for the homepage and Manual Setup Studio chrome.
colors:
  bg: "#0b1730"
  surface: "#122440"
  ink: "#f6f8fc"
  muted: "#b7c8df"
  line: "#3a506c"
  manual: "#f6c550"
  cloud: "#64c5d7"
  manual-ink: "#17243b"
  cloud-ink: "#12243a"
  section: "#f2f5fa"
  section-ink: "#142641"
  section-muted: "#40536c"
  light-bg: "#f6f8fc"
  light-surface: "#e9eff8"
  light-ink: "#12243d"
  light-muted: "#455b77"
  light-line: "#b7c4d5"
  light-manual: "#805800"
  light-cloud: "#08687c"
  light-action-ink: "#ffffff"
  light-section: "#e6edf7"
  setup-bg3: "#1c3150"
  setup-line2: "#58718e"
  setup-faint: "#a4b8d2"
  setup-soft: "rgba(246,197,80,.12)"
  setup-light-line2: "#a5b5c9"
  setup-light-soft: "rgba(128,88,0,.08)"
typography:
  display:
    fontFamily: "Barlow, \"Arial Narrow\", sans-serif"
    fontSize: "clamp(3rem,5vw,4.8rem)"
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "-.015em"
  headline:
    fontFamily: "Barlow, \"Arial Narrow\", sans-serif"
    fontSize: "clamp(2.1rem,3.4vw,3.1rem)"
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "-.015em"
  title:
    fontFamily: "Barlow, \"Arial Narrow\", sans-serif"
    fontSize: "1.9rem"
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "-.015em"
  body:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", sans-serif"
    fontSize: "1rem"
    lineHeight: 1.65
  route-label:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", sans-serif"
    fontSize: ".875rem"
    lineHeight: 1.4
  setup-heading:
    fontFamily: "Barlow, \"Arial Narrow\", sans-serif"
    fontSize: "42px"
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: "-.012em"
  setup-body:
    fontFamily: "system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "16px"
    lineHeight: 1.6
  setup-field:
    fontFamily: "ui-monospace, \"SF Mono\", \"JetBrains Mono\", Menlo, Consolas, monospace"
    fontSize: "16px"
rounded:
  route-action: "3px"
  panel: "4px"
  setup-field: "10px"
  setup-button: "11px"
  setup-choice: "12px"
  station: "50%"
spacing:
  inline-small: ".5rem"
  inline: "1rem"
  panel: "1.5rem"
  column-small: "2rem"
  section-mobile: "3rem"
  section: "4.75rem"
components:
  manual-action:
    backgroundColor: "{colors.manual}"
    textColor: "{colors.manual-ink}"
    rounded: "{rounded.route-action}"
    padding: ".7rem 1rem"
  cloud-action:
    backgroundColor: "{colors.cloud}"
    textColor: "{colors.cloud-ink}"
    rounded: "{rounded.route-action}"
    padding: ".7rem 1rem"
  theme-button:
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: ".55rem .85rem"
  setup-primary:
    backgroundColor: "{colors.manual}"
    textColor: "{colors.bg}"
    rounded: "{rounded.setup-button}"
    padding: "12px 16px"
  setup-secondary:
    backgroundColor: "{colors.setup-bg3}"
    textColor: "{colors.ink}"
    rounded: "{rounded.setup-button}"
    padding: "12px 16px"
  setup-field:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.ink}"
    typography: "{typography.setup-field}"
    rounded: "{rounded.setup-field}"
    padding: "11px 12px"
    width: "100%"
  setup-choice:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.ink}"
    rounded: "{rounded.setup-choice}"
    padding: "12px 14px"
  command:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    padding: "{spacing.panel}"
  route-symbol:
    rounded: "{rounded.station}"
    width: "1.85rem"
    height: "1.85rem"
---

# Design System: TriDelPhi

## Overview

**Creative North Star: "Transit Wayfinding"**

Transit wayfinding gives TriDelPhi a clear, practical identity: midnight signage, porcelain type, amber manual routes, and cyan cloud routes. Condensed headings and ordinary sentence-case explanations make a technical choice readable without theatrical security imagery.

The built world is flat and directional. Ruled divisions, station circles, and short angled tracks organize information; color identifies a destination rather than claiming a security result. This record covers the homepage and shared Manual Setup Studio chrome, with existing setup controls recorded as local variants—not a redesign mandate for the portal or cloudserver UI.

**Key Characteristics:**

- Condensed Barlow headings with system-sans reading text.
- Amber manual identity and cyan cloud identity in both themes.
- Flat ruled surfaces, circular stations, and restrained state feedback.
- Existing setup controls retain their own geometry and focus treatment.

Evidence: `site/index.html`, `site/assets/site.css`, `site/assets/site.js`, `site/setup.html`, and `site/assets/mark.svg`; checked against the supplied final desktop, mobile, light, setup-desktop, and setup-mobile captures in `.impeccable/review/`. Product authority is `PRODUCT.md`; page composition and the approved direction remain in `.impeccable/surfaces/site-index-html.md`. This is a post-build record, not a seed.

## Colors

The palette pairs cool structural neutrals with warm manual and cool cloud route accents. Frontmatter holds the exact source values; default keys describe dark mode and light-prefixed keys describe overrides.

### Primary

- **Manual Amber** (`manual`): manual-route text, track, action, and setup selection/focus. Light mode uses `light-manual` for legibility on pale surfaces.
- **Manual Action Ink** (`manual-ink`): homepage amber action text; setup primary buttons instead use the current `bg`.

### Secondary

- **Cloud Cyan** (`cloud`): cloud-route text, track, action, homepage focus, and disclosure markers. Light mode uses `light-cloud`.
- **Cloud Action Ink** (`cloud-ink`): dark homepage cyan action text. Both light homepage actions use `light-action-ink`.

### Neutral

- **Midnight Signage / Porcelain Ink** (`bg`, `ink`): canvas and main type.
- **Raised Navy / Muted Blue / Rule Blue** (`surface`, `muted`, `line`): command panels, supporting text, dividers.
- **Reading Paper** (`section`, `section-ink`, `section-muted`): the contrasting coverage section, including in dark mode.
- Light mappings replace bg, surface, ink, muted, line, manual, cloud, both action inks, section, and section-ink; section-muted stays unchanged. The light section-ink equals light-ink.
- Setup uses `bg2` for surface, `mute` for muted, `grn`/`grn-ink`/`u`/`p` for manual, and `e` for cloud. These legacy variable names do not signify a green identity. Setup-only bg3, line2, faint, and soft-selection colors are recorded separately. Light bg3 is white; light faint equals light-muted.

**The Destination Color Rule.** Amber identifies manual setup; cyan identifies cloud scanning. Neither route color is a safety verdict.

The sidecar’s synthesized eight-step OKLCH ramps are swatch-preview extensions only, not extra shipped palette tokens.

## Typography

**Display Font:** Barlow, backed by the bundled Barlow Semi Condensed Bold TTF, then Arial Narrow and sans-serif.
**Body Font:** system UI; homepage fallback includes Segoe UI, setup includes Helvetica Neue and Arial.
**Label/Mono Font:** native monospace for code; setup additionally names SF Mono, JetBrains Mono, Menlo, and Consolas. These are fallback names, not bundled fonts.

The hierarchy is condensed and confident without uppercase promotional labels. The normative ramp is in frontmatter: display for h1, headline for h2, title for route h3, body for explanation, route-label for station captions. The homepage lead is larger (1.3rem / 1.55), with a 34ch measure. Paragraphs cap at 68ch; introduction support text at 39ch. Setup uses its separate heading and body roles; field text is monospace.

**The Display Has a Job Rule.** Use the bundled Barlow bold face for headings and the wordmark; keep explanations and controls in the surface’s system-sans stack.

## Layout

Homepage containers use `min(100% - 4rem,1280px)`. Repeated desktop sections share a 1fr / 1.14fr grid and `clamp(2rem,5vw,5rem)` gap. At 1000px the hero becomes .9fr / 1.1fr with a 2rem gap and h1 becomes 4.4rem. At 760px containers become `min(100% - 2.5rem,600px)`; sections stack, navigation wraps onto its own row, and h1 uses `clamp(3.25rem,10vw,4.75rem)`. The final mobile hero gap is 2rem. Repeated section spacing and compact panel spacing are frontmatter roles, not an invented universal scale.

Setup retains a 1080px maximum container with at least 20px safe-area-aware inline padding, a .95fr / 1.05fr studio grid and 36px gap. At 900px it stacks and output ceases to be sticky. Its heading drops to 30px at 640px. At 560px the header becomes static, the rail inset shrinks from 46px to 40px, output padding becomes 16px, and code height caps at 300px instead of 380px. Otherwise the header is sticky at top 0 and output at 78px. These are setup-local constraints.

Long prose, links, and filenames wrap; homepage commands wrap anywhere, while setup generated code remains an internally scrolling preformatted artifact.

## Elevation & Depth

There are no box shadows. Borders and solid tonal fills distinguish sections, command containers, and existing setup panels. Sticky setup chrome is positional layering, not floating-card styling.

**The Flat Signage Rule.** Use borders and tonal surfaces for separation; the shipped system has no box-shadow vocabulary.

Homepage station fill transitions in .18s ease-out on hover or focus-within. Route actions move down 1px on active. Setup retains .15s choice feedback, .2s border feedback, .3s folding and marker pop, and filename-change wash. Reduced-motion rules remove transitions and animations; homepage also removes the active translation. These are feedback, not decorative continuous motion.

## Shapes

The homepage uses nearly square action corners, square command containers, thin rules, circular letter stations, and SVG tracks with 45-degree bends. The existing brand mark combines two colored triangular routes and porcelain station dots on a navy rounded square; use the asset rather than a typed substitute.

Setup retains small-corner outer panels but more rounded fields, choice cards, and buttons. The frontmatter radius roles deliberately preserve these differences. A station letter is a labeled route identifier, not an improvised icon; directional and control icons use SVG paths.

## Components

### Buttons

Homepage manual and cloud actions are full-width flex links with destination color, contrasting ink, a right-aligned SVG arrow, minimum height 48px, and the route-action radius. Hover underlines; active translates; keyboard focus uses a 3px cyan outline offset 5px. The coverage section instead uses its dark teal focus color.

The homepage theme button is transparent, line-bordered, minimum height 44px, and fills with surface on hover. Setup’s theme button uses bg2, line2, and bg3 on hover. Shared JavaScript reveals the otherwise hidden control, labels the destination theme, honors system preference until explicitly selected, and persists `tridelphi-theme` when storage permits.

Setup primary and secondary actions use the retained setup-button radius. Primary uses manual on bg-colored text; secondary uses bg3 and ink. Hover changes the border to manual. The create link is disabled at .5 opacity and has no href until a valid owner/repository exists. Copy feedback is announced through a status region; snippets are visual controls, not a replacement for that JavaScript.

### Cards / Containers

The homepage command container is square, surface-filled, line-bordered, and padded with the panel spacing role. It is not a generic promotional card. Setup choice cards use bg, line2, and the setup-choice radius; selected cards use soft manual fill and a 2px manual border with padding reduced by 1px to avoid a size shift. Setup outer rungs and output retain the smaller panel radius.

### Inputs / Fields

Setup text fields use bg, ink, line2, monospace, and the setup-field radius. Placeholder text uses faint; caret uses manual. Focus is a 2px manual outline offset 2px, with the existing focus radius of 6px. Radio choice focus outlines its visible card. The repository field reports invalid format through aria-invalid and a live status message; no new red error token is implied. Native range, checkbox, and select controls remain native; range and checkbox accent is manual.

### Navigation

Homepage navigation is inline, sentence case, with destination-colored studio links and underlined hover. On mobile it wraps below the brand and theme control. Setup retains its All studios backlink, cloud link, and wrapping theme control. There is no fabricated active-page pill or chip system.

### Route directory and disclosures

Each route has a circular letter identifier, title link, explanation, SVG track, three textual stations, action, and visible requirements. Hover or focus-within fills its stations; the steps remain readable without motion. The sidecar includes the actual manual track path as the signature sample, not a simulated network.

Homepage questions use native details/summary with thin rules, cyan disclosure markers, and muted expanded prose. Setup retains its rung expansion and optional dashed-rule disclosures; these are not new homepage patterns.

The sidecar contains ten source-derived, ds-prefixed visual samples. Custom properties remain live-bound with literal source fallbacks for isolated previews. SVG paths are inline, typography is explicit, and real hover/focus/active or selected/disabled states are retained. No framework or application runtime is required for their visual rendering; generator, clipboard, and theme behavior still belong to the site scripts.

## Do's and Don'ts

### Do:

- Do retain text labels alongside route color and station symbols.
- Do keep requirements and limitations readable next to the action they qualify.
- Do preserve both theme mappings and the surface-specific focus outlines.
- Do retain the actual setup control geometry and generated-file review flow.

### Don't:

- Don't turn the manual and cloud alternatives into consecutive steps.
- Don't add glow, fake monitoring, city backdrops, or ornamental dashboards.
- Don't promote retained setup-only styling into a universal homepage component.
- Don't apply this record to the portal or cloudserver interface.

The final setup pass aligns code output with the theme’s background and text tokens, replaces the old “next rungs” instructions with plain-language additional checks, and makes collapsed controls inert. The generator remains local and requires explicit review before committing. The corrected share-card mark matches the site’s amber/cyan triangle and passed the finish review.
