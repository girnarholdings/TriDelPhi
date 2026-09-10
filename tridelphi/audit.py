"""One offline command for the three native static scanners.

No package installation, repository hooks, external analyzers, or network calls.
Archive extraction uses the pre-install scanner's bounded extractor. Reports
are returned to the caller only; this module has no telemetry or upload client.
"""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from . import __version__
from .api import AnalysisError, analyze
from .expose import analyze_exposure
from .preflight import analyze_preflight, extract_archive

_ARCHIVES = (".zip", ".whl", ".tgz", ".tar.gz", ".tar", ".tar.bz2", ".tar.xz")
_SCOPE = (
    "Native static checks for install-time risks, GitHub/agent automation, and "
    "data exposure. No code was executed or installed. External scanners, live "
    "vulnerability databases, compiled malware and device monitoring are not included. "
    "No findings is not proof of safety."
)


def audit_directory(root: Path) -> dict:
    core = analyze(root)
    preflight = analyze_preflight(root, tool_version=__version__)
    exposure = analyze_exposure(root, tool_version=__version__, run_semgrep=False)
    findings = [
        {"engine": "automation", "rule": f.rule_id, "severity": f.severity,
         "where": f"{f.primary_position.file}:{f.primary_position.line}",
         "message": f.message, "fix": f.remediation.rendered if f.remediation else "Review this finding."}
        for f in core.findings
    ]
    for engine, result in (("install", preflight), ("exposure", exposure)):
        findings.extend({"engine": engine, "rule": f.rule, "severity": f.severity,
                         "where": f.where, "message": f.message, "fix": f.fix}
                        for f in result.findings)
    severity_order = {"critical": 0, "warning": 1, "note": 2}
    findings.sort(key=lambda f: (severity_order[f["severity"]], f["engine"], f["where"], f["rule"]))
    complete = not core.diagnostics and not preflight.truncated and exposure.coverage.complete
    capped = len(findings) > 1000
    return {
        "schemaVersion": 1, "toolVersion": __version__, "scope": _SCOPE,
        "status": "partial" if not complete or capped else ("findings" if findings else "no-known-findings"),
        "complete": complete and not capped,
        "counts": {s: sum(f["severity"] == s for f in findings) for s in severity_order},
        "engines": {
            "automation": {"complete": not core.diagnostics, "files": core.files_scanned,
                           "suppressed": core.suppressed,
                           "diagnostics": [{"where": d.path, "message": d.message}
                                           for d in core.diagnostics]},
            "install": {"complete": not preflight.truncated, "files": preflight.files_examined},
            "exposure": exposure.coverage.as_dict(),
        },
        "findingsTruncated": capped, "findings": findings[:1000],
    }


def _safe(text: str) -> str:
    # Untrusted file names/messages must not inject terminal escape sequences.
    return "".join(c if c.isprintable() or c == "\n" else f"\\u{ord(c):04x}" for c in text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run all three native TriDelPhi static checks offline.")
    parser.add_argument("target", nargs="?", default=".", help="directory or ZIP/library archive")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        target = Path(args.target)
        if target.is_symlink():
            raise ValueError("Choose a real directory or archive, not a symbolic link.")
        with tempfile.TemporaryDirectory(prefix="tridelphi-audit-") as temporary:
            if target.is_dir():
                root = target
            elif target.is_file() and target.name.lower().endswith(_ARCHIVES):
                root = extract_archive(target, Path(temporary) / "source")
            else:
                raise ValueError("Choose a directory or a supported source archive, not an installer or URL.")
            report = audit_directory(root)
    except (AnalysisError, ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"TriDelPhi could not complete the scan: {_safe(str(exc))}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        titles = {"partial": "Scan incomplete — do not treat this as a pass.",
                  "findings": "Scan finished — review the findings below.",
                  "no-known-findings": "No known issues found in these checks — not a safety guarantee."}
        print(titles[report["status"]])
        print(_SCOPE)
        print("\n" + ", ".join(f"{count} {severity}" for severity, count in report["counts"].items()))
        suppressed = report["engines"]["automation"]["suppressed"]
        if suppressed:
            print(f"{suppressed} automation findings were suppressed by comments in the project; review those exceptions.")
        for finding in report["findings"]:
            print(_safe(f"\n[{finding['severity']}] {finding['where']} ({finding['rule']})\n"
                        f"{finding['message']}\nWhat to do: {finding['fix']}"))
        if not report["complete"]:
            print("\nSome checks hit limits or could not read files. Use --format json for coverage details.")
    if not report["complete"]:
        return 2
    return 1 if report["counts"]["critical"] or report["counts"]["warning"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
