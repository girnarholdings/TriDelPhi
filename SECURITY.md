# Security Policy

TriDelPhi is a security tool, so it holds itself to the bar it enforces —
this repo runs its own full ladder (`tridelphi . --level 3 --offline`) as a
required CI check on every pull request.

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting** for this repository
(Security tab → "Report a vulnerability"). Do not open a public issue for
anything you believe is exploitable.

Include what you can of: the affected component (core analyzer, ladder
orchestration, composite action, installer script, Cloudflare Worker), a
reproduction, and the impact you see. You can expect an acknowledgement
within a week.

## Scope notes for researchers

* The wrapped scanners (gitleaks, osv-scanner, zizmor, scorecard, semgrep)
  are separate projects — report their bugs upstream. A TriDelPhi bug is one
  where *our* orchestration mishandles their output: the containment gate in
  `tridelphi/orchestrate.py::sarif_shape_error`, URI normalization, severity
  accounting, or the installer's pin/checksum verification.
* The threat model treats scanner output as attacker-influenced. Anything
  that lets a scanned repository crash the scan, corrupt the merged SARIF,
  smuggle a path outside the scanned root, or bypass the gate is in scope
  and very much welcome.
* `tests/` deliberately contains inert, synthetic credential-shaped strings
  and malicious workflow fixtures. They are test payloads, not leaks.

## Supply chain

Release binaries the installer fetches are pinned by version and verified
against upstream digests (checksums file, SLSA provenance, or PyPI hashes).
A checksum mismatch is a hard failure by design.
