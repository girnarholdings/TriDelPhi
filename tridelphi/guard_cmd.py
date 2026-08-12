"""`tridelphi guard` — find it, explain it, and fix it, with your say-so.

The scan and the fix plan already exist; guard closes the loop. For every
finding it shows the exact solution, then asks one question: fix it now?

    [y] apply the automatic fix        (only where one exists)
    [c] comment out the offending step
    [d] disable this workflow file     (rename to .yml.disabled — reversible)
    [s] skip                           [q] quit

Consent is per finding and nothing is edited without it. Every accepted edit
goes through `apply.py`'s verify-or-rollback contract: the file is changed only
if a fresh scan proves the finding cleared; otherwise the original bytes come
back and guard says so. `--yes` is the non-interactive spelling: it applies the
automatic fixers only — it never comments out or disables anything, because
those change what your CI does and deserve a human eye.

With `--level N` the wrapped rungs run too. Their findings come from tools we
do not control, so guard does not pretend to auto-fix them — it prints each
tool's result with the exact next step a person should take.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

from .api import AnalysisError, analyze
from .apply import AUTO_FIXABLE, apply_action, finding_key
from .fix_cmd import _cost, _plan_order
from .model import Finding

__all__ = ["run_guard"]

_RULE = "─" * 62

# The exact next step for each wrapped rung, in plain language. These tools'
# findings are not ours to auto-edit; the value we add is the translation.
_EXTERNAL_ADVICE = {
    "gitleaks": (
        "A committed password/key cannot be fixed by deleting the line — it is "
        "already in your git history. Rotate the credential (make a new one, "
        "revoke the old), then remove it from the file and store it in "
        "Settings → Secrets instead."
    ),
    "osv-scanner": (
        "A known-broken dependency is fixed by upgrading: bump the version in "
        "your lockfile/manifest to the fixed release named in the finding, "
        "reinstall, and re-run the scan."
    ),
    "zizmor": (
        "These are workflow-hardening findings. Most are one-line changes; "
        "zizmor's message names the file and line."
    ),
    "scorecard": (
        "These are repository-settings improvements (branch protection, "
        "review requirements). They are changed in GitHub Settings, not in "
        "files — the check name tells you which page."
    ),
    "semgrep": (
        "These are code patterns in your application source. Each message "
        "names the file, line and pattern; fix the code or add a reviewed "
        "ignore comment if it is a false positive."
    ),
}


def _prompt(*, has_auto: bool, stream: TextIO, out: TextIO) -> str:
    options = []
    if has_auto:
        options.append("[y] fix it now")
    options += ["[c] comment out the step", "[d] disable this workflow", "[s] skip", "[q] quit"]
    print("  " + "   ".join(options), file=out)
    print("  > ", end="", file=out, flush=True)
    line = stream.readline()
    if not line:  # EOF — treat as quit, never guess consent
        return "q"
    return line.strip().lower()[:1] or "s"


def _card(finding: Finding, index: int, total: int, out: TextIO) -> None:
    rem = finding.remediation
    _rank, label = _cost(finding)
    print(_RULE, file=out)
    print(
        f"  {index}/{total} · {finding.severity.upper()} · {label}",
        file=out,
    )
    print(
        f'  {finding.primary_position.file}:{finding.primary_position.line}   '
        f'job "{finding.context.job_id}"',
        file=out,
    )
    print(file=out)
    if rem is not None:
        for ln in rem.rendered.split("\n"):
            print(f"  {ln}" if ln.strip() else "", file=out)
        print(f"\n  Trade-off: {rem.breaks}", file=out)
    else:
        print(f"  {finding.message}", file=out)
    print(file=out)


# The optional tooling, what each one buys, and which installer provides it.
# Everything here is optional by design: the Rule-of-Two core is native and
# needs none of it. What the absence costs you is a rung reporting "not run",
# which reads like a clean result — so it is worth saying out loud.
_OPTIONAL_TOOLS: tuple[tuple[str, str, str], ...] = (
    ("gitleaks", "secrets committed to the tree (--level 1)", "ladder"),
    ("osv-scanner", "known-vulnerable dependencies (--level 2)", "ladder"),
    ("zizmor", "workflow hardening lint (--level 3)", "ladder"),
    ("scorecard", "repository posture (--level 4)", "ladder"),
    ("semgrep", "risky code patterns (--level 5)", "ladder"),
    ("javascript-obfuscator", "`tridelphi privatize`", "privatize"),
)

_INSTALLERS = {
    "ladder": ("scripts/install-ladder.sh", "5"),
    "privatize": ("scripts/install-privatize.sh", ""),
}


def _missing_tools() -> list[tuple[str, str, str]]:
    import shutil

    return [t for t in _OPTIONAL_TOOLS if shutil.which(t[0]) is None]


def _offer_missing_tools(root: Path, *, yes: bool, stream: TextIO, out: TextIO) -> None:
    """Name what is missing, and offer to fetch it — never silently.

    Downloading and running binaries is a different class of act from editing a
    workflow file, so it is not covered by `-y` and is never done without an
    explicit yes. That is also why this offers rather than auto-installs: a tool
    whose banner promises it "ran entirely on your machine, nothing uploaded"
    cannot quietly reach out to the network on your behalf.

    The installers live in `scripts/`, which the published wheel does not ship,
    so the offer only appears when guard is run from a checkout that has them.
    """
    missing = _missing_tools()
    if not missing:
        return

    print("  Optional tools not installed:", file=out)
    for name, why, _kind in missing:
        print(f"    · {name:<22} {why}", file=out)

    kinds = {kind for _n, _w, kind in missing}
    available = {k: root / _INSTALLERS[k][0] for k in kinds if (root / _INSTALLERS[k][0]).is_file()}
    if not available:
        print(
            "\n  What they check is skipped — a missing tool, not a clean result.\n"
            "  Install them with the pinned, checksum-verified scripts from the\n"
            "  TriDelPhi repository (scripts/install-ladder.sh).\n",
            file=out,
        )
        return

    if yes:
        # -y means "apply the fixes without asking", not "fetch and run binaries".
        print(
            "\n  Skipping install: -y covers applying fixes, not downloading tools.\n"
            "  Run `bash scripts/install-ladder.sh 5 ~/.local/bin` when you want them.\n",
            file=out,
        )
        return

    print(
        "\n  These install from pinned versions, each verified against a recorded\n"
        "  checksum before use. Install them now? [y/N] ",
        end="",
        file=out,
        flush=True,
    )
    answer = (stream.readline() or "").strip().lower()
    if answer not in ("y", "yes"):
        print("\n  Left alone. What they check will be skipped.\n", file=out)
        return

    import subprocess

    dest = Path.home() / ".local" / "bin"
    dest.mkdir(parents=True, exist_ok=True)
    for kind, script in sorted(available.items()):
        arg = _INSTALLERS[kind][1]
        cmd = ["bash", str(script)] + ([arg] if arg else []) + [str(dest)]
        print(f"  running {' '.join(cmd[1:])}", file=out)
        try:
            completed = subprocess.run(cmd, cwd=str(root), check=False)
        except OSError as exc:
            print(f"  could not run the installer: {exc}", file=out)
            continue
        if completed.returncode != 0:
            print(f"  {script.name} failed; nothing was changed by it.", file=out)

    still = [n for n, _w, _k in _missing_tools()]
    if still:
        print(f"\n  Still missing: {', '.join(still)}.", file=out)
        print(f"  If they installed to {dest}, add it to PATH:", file=out)
        print(f'      export PATH="{dest}:$PATH"\n', file=out)
    else:
        print("\n  All tools present.\n", file=out)


def _gating(findings, include_warnings: bool) -> list[Finding]:
    wanted = ("critical", "warning") if include_warnings else ("critical",)
    return sorted((f for f in findings if f.severity in wanted), key=_plan_order)


def run_guard(
    path: str,
    *,
    yes: bool = False,
    include_warnings: bool = False,
    level: int | None = None,
    offline: bool = False,
    input_stream: TextIO | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    input_stream = input_stream or sys.stdin
    root = Path(path)

    try:
        result = analyze(root)
    except AnalysisError as exc:
        print(f"tridelphi: {exc}", file=err)
        return 2

    todo = _gating(result.findings, include_warnings)
    total = len(todo)
    print(f"tridelphi guard · {root.resolve().name or path}", file=out)
    # Before showing findings, say what this machine can and cannot check. A
    # rung that reports "not run" because its tool is absent looks identical to
    # a rung that ran and found nothing, and that is the wrong thing to leave a
    # person believing.
    print(file=out)
    _offer_missing_tools(root, yes=yes, stream=input_stream, out=out)
    if not todo:
        print("\n  Nothing to fix — no job holds all three powers.\n", file=out)
    else:
        print(
            f"\n  {total} finding{'s' if total != 1 else ''}. For each one: the exact "
            "solution, and the choice is yours.\n"
            "  Every accepted edit is re-scanned before it sticks; if the fix does "
            "not verify, your file comes back untouched.\n",
            file=out,
        )

    handled = 0
    skipped: set[tuple[str, str, str]] = set()
    quit_early = False
    index = 0
    while not quit_early:
        todo = [f for f in _gating(analyze(root).findings, include_warnings)
                if finding_key(f) not in skipped]
        if not todo:
            break
        finding = todo[0]
        index += 1
        kind = finding.remediation.kind if finding.remediation else ""
        has_auto = kind in AUTO_FIXABLE
        _card(finding, index, total, out)

        if yes:
            choice = "y" if has_auto else "s"
        else:
            choice = _prompt(has_auto=has_auto, stream=input_stream, out=out)

        if choice == "q":
            quit_early = True
            skipped.add(finding_key(finding))
            continue
        if choice == "s" or (choice == "y" and not has_auto):
            skipped.add(finding_key(finding))
            print("  ↷ skipped\n", file=out)
            continue

        action = {"y": "fix", "c": "comment-out", "d": "disable"}.get(choice)
        if action is None:
            skipped.add(finding_key(finding))
            print("  ↷ unrecognised choice — skipped\n", file=out)
            continue

        outcome = apply_action(root, finding, action)
        if outcome.status == "applied":
            handled += 1
            print(f"  ✓ {outcome.detail}\n", file=out)
        else:
            skipped.add(finding_key(finding))
            print(f"  ✗ {outcome.detail}\n", file=out)

    # ----- wrapped rungs: translate, don't pretend to auto-fix -------------
    if level is not None:
        from .ladder import run_ladder

        print(_RULE, file=out)
        print(f"  Ladder rungs up to L{level}:", file=out)
        for ext in run_ladder(str(root), level=level, offline=offline):
            if ext.diagnostic is not None:
                print(f"  · {ext.spec.name}: {ext.diagnostic.message}", file=out)
                continue
            counts = ext.severity_counts
            worth = sum(counts.values())
            if not worth:
                print(f"  · {ext.spec.name}: all clear", file=out)
                continue
            print(f"  · {ext.spec.name}: {worth} finding{'s' if worth != 1 else ''}", file=out)
            advice = _EXTERNAL_ADVICE.get(ext.spec.name)
            if advice:
                print(f"      Do this: {advice}", file=out)

    # ----- the verdict is the fresh state, not the session log -------------
    remaining = _gating(analyze(root).findings, include_warnings=False)
    print(_RULE, file=out)
    if handled:
        print(f"  {handled} fix{'es' if handled != 1 else ''} applied and verified.", file=out)
    if remaining:
        print(
            f"  {len(remaining)} critical{'s' if len(remaining) != 1 else ''} still "
            "open — run `tridelphi fix` for the written plan.\n",
            file=out,
        )
        return 1
    print("  No criticals remain. You're good.\n", file=out)
    return 0
