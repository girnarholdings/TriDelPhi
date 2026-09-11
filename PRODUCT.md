# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

First-time programmers and AI-assisted developers with little security experience.
They need understandable checks before using unfamiliar code or shipping changes.

## Product Purpose

TriDelPhi is a free, open-source static security tool. The website helps beginners
choose between Manual Setup Studio and Cloud Scan Studio without confusing those
alternatives with sequential steps.

## Operating Context

The main website is static HTML on GitHub Pages at https://tridelphi.com/.
Manual Setup Studio generates a GitHub Actions workflow in the browser for the
user to review and commit. Cloud Scan Studio at https://scan.tridelphi.com/
requires GitHub App authorization and installation and uses the visitor's own
GitHub Codespace. These existing tools must keep working during the redesign.

## Capabilities and Constraints

Native checks inspect unfamiliar code, GitHub Actions risks, and application
exposure. Static results are not proof of safety or an antivirus replacement.
The cloud flow creates a scanner workspace; uploading an archive and running
the scan still require steps inside that workspace. GitHub allowances and charges
belong to the visitor; do not promise unconditional free compute.
No source is retained by the portal by default. Training contributions must be
explicitly donated, reviewed, and redacted; do not present a future donation
workflow as an existing feature. Never enable paid services without approval.

## Brand Commitments

Keep the TriDelPhi name. Use plain language and remove generic AI imagery,
inflated claims, and confusing metaphors. The owner approved a full visual
refresh, new colors and brand assets, and updated favicon and social metadata.

## Evidence on Hand

Source, tests, documentation, and working studio interfaces in this repository.
No supplied customer testimonials, independent benchmarks, or safety guarantees.

## Product Principles

- Explain what a check does and what it cannot establish.
- Make the two studio choices immediately understandable.
- Keep strong security boundaries behind simple controls.
- Preserve existing functionality and review changes before publishing.
