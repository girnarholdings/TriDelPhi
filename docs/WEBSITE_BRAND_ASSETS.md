# Website identity and asset provenance

The owner selected the transit-wayfinding direction and a code-first build on
2026-09-10. The website keeps two distinct routes: amber Manual Setup Studio and
cyan Cloud Scan Studio on midnight navy, with an accessible light theme.

- `site/assets/mark.svg` and `site/favicon.svg`: original code-native triangular
  route mark, authored for this redesign. No external icon library.
- `site/assets/fonts/barlow-semi-condensed-bold.ttf`: Barlow Semi Condensed Bold,
  from https://github.com/google/fonts/tree/main/ofl/barlowsemicondensed, distributed
  under the included `site/assets/fonts/OFL.txt`. Self-hosted; no Google Fonts
  request is made by a visitor.
- `site/og-studios.png`: generated with the built-in image-generation tool,
  1734 × 907 pixels. Original and corrective prompts below; the final editing
  prompt is embedded in PNG text metadata. The corrective edit aligns its logo
  with the website's vector mark without changing the layout or wording.
- `site/og-card.png`: previous repository sharing image, retained so old links
  remain usable. Its known repository origin is embedded as metadata; original
  authorship is unknown. Current page metadata uses the new versioned image.

Canonical URLs are `https://tridelphi.com/` and
`https://tridelphi.com/setup.html`. Social image URL:
`https://tridelphi.com/og-studios.png`. It becomes available publicly after the
homepage PR is merged and the GitHub Pages deployment succeeds. Social platforms
may keep an older preview until they scrape the page again.

## Exact share-card prompt

```text
Use case: ads-marketing
Asset type: ONE finished landscape social sharing brand card for TriDelPhi, approximately 1.91:1, target 1536x804 or a suitable nearby landscape resolution.
Primary request: A cohesive, polished transit-wayfinding-inspired typographic share card for a code-checking product. This is the final flat artwork itself, not a screenshot, webpage comp, device mockup, or presentation of a design.
Scene/backdrop: Edge-to-edge solid midnight navy #0B1730.
Style/medium: Clean flat solid-color artwork, precise geometric linework, confident editorial typography. Bold condensed sans-serif like Barlow Semi Condensed; crisp porcelain white #F6F8FC lettering. Strong legibility at small social previews.
Composition/framing: Generous safe margins on every side. Large brand name and prominent headline with clear hierarchy in the upper portion; carefully composed transit route motif and supporting studio labels below. Keep type unobstructed and spacing generous. Footer clearly readable near the bottom. A small simple open triangular mark beside the brand is optional.
Route motif: Exactly two clean route lines, one amber #F6C550 and one cyan #64C5D7, with deliberate 45-degree bends and white station circles, visually connecting the studio labels as a coherent wayfinding system. Uniform stroke widths, restrained number of stations, no tangles, no arrows needed.
Text (verbatim, each exactly once, no additional text):
"TriDelPhi"
"Two ways to check your code."
"Manual Setup Studio"
"Cloud Scan Studio"
"tridelphi.com"
Text accuracy: Brand capitalization is exactly TriDelPhi (T-r-i-D-e-l-P-h-i). Preserve exact spelling, capitalization, and final period in headline. Headline may wrap naturally over two lines. Supporting labels must remain readily readable.
Constraints: Use only the navy, porcelain white, amber, and cyan palette. Solid flat fills, no texture. No robots, shields, AI imagery, fake security scores, glow, gradients, shadows, 3D, photos, fake UI, buttons, browser chrome, watermark, or extra copy. Deliver just one complete brand sharecard.
```

## Exact corrective editing prompt

```text
Use case: precise-object-edit
Asset type: ads-marketing landscape social sharecard for TriDelPhi.
Input image 1: EDIT TARGET, the existing complete TriDelPhi sharecard. Edit this image, do not redesign or generate a new composition.
Primary request: Replace ONLY the thick white triangular logo beside the TriDelPhi wordmark at the upper left with the exact outlined amber/cyan triangular route mark described below. Keep its position and comparable visual footprint beside the wordmark. Remove the old white triangle completely.
Exact replacement geometry from the brand SVG, in a local 48 by 48 coordinate system, scaled uniformly to fit the existing logo area: amber path M24 9 L7 38 H24, fill none, stroke #F6C550, stroke-width 4, stroke-linejoin round. Cyan path M24 9 L41 38 H24, fill none, stroke #64C5D7, stroke-width 4, stroke-linejoin round. Porcelain-white #F6F8FC filled station circles centered at (24,9) and (24,38), each radius 3. Thus left sloping side and left half of the base are amber; right sloping side and right half of the base are cyan; a white dot at the apex and another at bottom center. Interior remains midnight navy, with no thick white triangle. Scale strokes and dots proportionally with the 48-unit mark. The SVG background is #0B1730; blend that background into the existing navy, with no visible tile or badge.
Preservation constraints: Change only the logo region. Preserve ALL existing text exactly, including capitalization, punctuation, typography, weight, size, kerning, positions and line breaks: "TriDelPhi", "Two ways to check your code.", "Manual Setup Studio", "Cloud Scan Studio", "tridelphi.com". Preserve the whole layout, canvas aspect ratio, framing, margins, navy background, porcelain-white type, both long amber and cyan transit routes, their bends, station rings, studio labels and footer. Do not move, redraw, restyle, or recolor anything outside the logo region. Preserve original resolution 1734x907 if supported.
Avoid: filled triangle, white triangle outline, additional marks, additional text, gradients, glow, shadows, 3D, mockups, UI, or any extra variants. Return ONE edited image only.
```
