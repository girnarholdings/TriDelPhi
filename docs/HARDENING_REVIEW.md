# Beginner-safety hardening review

Reviewed 2026-09-03. This records the implementation of the August 31 briefing
and the follow-up review. It is a review record, not a security certification.

## What changed

| Surface | Implemented protection | Main regression coverage |
|---|---|---|
| Core detection | Structural authorization guards; typed job/output/artifact channels; bracket references; conservative reusable permissions and unknown semantics | `test_new_detectors`, `test_followup_hardening`, `test_github_semantics_matrix`, red-team corpus |
| Scan coverage | Bounded files, entries, bytes, jobs and parsed structure; JSONC handling; visible partial/unknown status rather than a green result | `test_preflight`, `test_expose`, `test_structure`, `test_followup_hardening` |
| Archives and downloads | Component-aware containment; reject links/special files/duplicate paths; bounded extraction and tar enumeration; HTTPS host/redirect allowlists; capped registry downloads and digest checks | `test_preflight`, `test_containment_regressions` |
| npm pre-install audit | Direct public-registry HTTPS download; no npm process or lifecycle execution; SHA-512/SHA-256 required | `test_preflight`; live download/digest/extraction check of `is-number@7.0.0` |
| Reports and gates | Shared live-result policy; strict SARIF normalization and bounded fields; escaped paths/mentions; external fingerprints/baselines that never waive a new secret | baseline, ladder, SARIF, checklist and L4–L7 adversarial tests |
| L7 trust | Strict atomic lock writes, source enumeration, stale/new publisher handling and explicit replacement consent; removed unsupported universal-provenance claims | `test_verify_l7`, `test_verify_l7_adversarial` |
| Processes and writes | Bounded subprocess capture/timeouts; atomic no-follow output helpers; fixer path validation; no target-provided installer execution | `test_subprocessutil`, `test_guard`, `test_privatize`, `test_followup_hardening` |
| Actions and fix bot | Runner-temp report transport; no attacker report in command outputs; isolated Python helpers; fresh artifact readiness; live write-permission authorization for every fix request; no persisted credentials in scan templates | `test_init`, generated YAML/shell checks |
| Hosted Worker | WebCrypto HMAC verification, strict signatures/payloads, body cap, durable replay/rate state, bounded logs, no deployable example secret | 37 Worker checks |
| Beginner setup | Clear three-door onboarding, partial/unknown explanations, accessible controls/contrast, safer generated YAML, single-sourced site release data | `test_setup_site`, `test_release_pin`, browser walkthrough |
| Ongoing maintenance | Evidence-backed agent table and scheduled review; GitHub semantics matrix; packaged runtime data checks | agent-signal tests, CI matrix and clean-wheel job |

The fix-bot guidance now warns that ordinary workflows do not automatically run
after a `GITHUB_TOKEN` push. Users must get fresh checks on the new commit, not
merge based on stale checks. This follows [GitHub's trigger documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
The npm download path uses the [public registry metadata API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md), and the Worker delegates HMAC checking to [WebCrypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/).

## Validation and release gate

- Full local Python 3.12 suite, Ruff, generated YAML/shell checks and wheel build
  are required before pushing. Exact final counts are recorded in the PR.
- Offline adversarial sweep: 109/109 attack cases detected, 11/11 benign controls
  clean. These are synthetic patterns, not a measured real-world detection rate.
- Worker: 37 checks across signature, request, routing and durable-state tests.
- Core self-scan: no critical or warning findings; six advisory notes.
- Offline L7 self-check: 38 third-party action references, no lock errors/notes.
- CI additionally covers Python 3.11/3.12/3.13 and the Linux-only pinned scanners.
  Local optional-scanner skips are not counted as passes. CI must pass before merge.

## Remaining limits and deeper review

1. **A clean scan is not proof of safety.** Static patterns do not execute code,
   inspect live cloud permissions, replace a penetration test, or fully interpret
   every GitHub expression. Dynamic refs, remote reusable workflows, environment
   settings and unknown agent behavior need human review.
2. **L7 records source pins, not publisher authenticity.** It cannot prove remote
   ownership, signed subject binding or freshness offline. A future signed-evidence
   consumer needs real fixtures and a separate protocol review before new claims.
3. **Resource bounds are defense in depth, not an OS sandbox.** Third-party
   scanners can write files outside their captured output; parser/decompressor
   internals allocate before post-parse checks. Concurrent hostile filesystem
   mutation is not fully contained by path rechecks. Scan hostile projects in an
   isolated, disposable, least-privileged runner with disk/memory/time quotas.
4. **Public registry downloads only.** Private npm registries and packages lacking
   strong integrity metadata are deliberately unsupported. Registry digests bind
   bytes to metadata, not to a trustworthy author. Network timeouts are socket
   timeouts, not a total deadline against every slow response.
5. **Build and obfuscation commands execute code.** Unlike a static scan, an app's
   build or an explicitly approved privatize smoke/build command runs the target.
   Do not give such jobs production secrets or unnecessary write permissions.
6. **Hosted behavior still needs deployment validation.** Worker tests use a
   Durable Object test double; production Cloudflare quotas, storage failures and
   webhook retry operations need staging checks. A stolen Actions-write token can
   perform more than dispatch, even though this Worker only dispatches scans.
7. **Release adoption is separate from this PR.** Existing generated workflows
   retain their released SHA pin. After merge, follow `docs/RELEASES.md` to publish
   and update pins; do not advertise an unmerged branch as a trusted release.
8. **Accessibility/user comprehension needs real-user testing.** Automated
   contrast/control checks and browser smoke tests do not replace keyboard and
   screen-reader testing across devices or onboarding sessions with beginners.

No known failing regression is intentionally hidden by this review. These limits
are explicit boundaries for maintainers, not reasons to turn off protective gates.
