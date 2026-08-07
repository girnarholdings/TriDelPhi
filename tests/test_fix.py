"""`tridelphi fix` — the remediation-plan view.

The plan is read-only (it must never edit a file), ordered cheapest-first, and
exports to Markdown that pastes cleanly into a pull request. These tests pin all
three properties plus the exit-code contract.
"""

from __future__ import annotations

import io
from pathlib import Path

from tridelphi.fix_cmd import _COST, _cost, _md_segments, run_fix

FIX = Path(__file__).resolve().parent / "fixtures"


def _run(path, **kw) -> tuple[int, str]:
    out = io.StringIO()
    err = io.StringIO()
    code = run_fix(str(path), out=out, err=err, **kw)
    return code, out.getvalue()


def test_critical_plan_exits_one_and_names_the_change():
    code, text = _run(FIX / "malicious" / "pwn-request-target")
    assert code == 1, "a repo with a critical must exit 1 so CI can gate on it"
    assert "fix plan" in text
    assert "strip U" in text
    assert "integration.yml:9" in text  # the exact line to change
    assert "Trade-off:" in text


def test_clean_repo_exits_zero_with_nothing_to_fix():
    code, text = _run(FIX / "clean" / "hardened-agent")
    assert code == 0
    assert "Nothing to fix" in text


def test_markdown_is_paste_ready_with_fenced_yaml():
    code, md = _run(FIX / "malicious" / "issue-to-write-token", markdown=True)
    assert code == 1
    assert md.startswith("# TriDelPhi fix plan")
    # the env-indirect remediation carries a YAML snippet; it must survive the
    # paste as a fenced code block, not as mangled prose.
    assert "```yaml" in md
    assert "UNTRUSTED_INPUT" in md
    assert "> **Trade-off:**" in md


def test_warnings_are_opt_in_and_do_not_gate():
    quiet_code, quiet = _run(FIX / "two_cap" / "up-no-egress")
    assert quiet_code == 0
    assert "Nothing to fix" in quiet  # a two-power near-miss is not critical

    verbose_code, verbose = _run(FIX / "two_cap" / "up-no-egress", include_warnings=True)
    assert verbose_code == 0, "a warning must never make fix exit non-zero"
    assert "strip U" in verbose


def test_plan_is_read_only():
    """The command must not mutate the repository it plans against."""
    target = FIX / "malicious" / "pwn-request-target"
    before = {p: p.stat().st_mtime_ns for p in target.rglob("*") if p.is_file()}
    _run(target, markdown=True)
    _run(target)
    after = {p: p.stat().st_mtime_ns for p in target.rglob("*") if p.is_file()}
    assert before == after, "fix edited files — it must be read-only"


def test_cost_orders_one_line_changes_before_restructures():
    assert _COST["env-indirect"][0] < _COST["split-job"][0]
    assert _COST["drop-untrusted-ref"][0] < _COST["move-secret"][0]


def test_md_segments_splits_prose_from_code():
    rendered = "Do this thing.\n    env:\n      X: y\nThen that."
    segs = _md_segments(rendered)
    assert segs[0] == "Do this thing."
    assert segs[1] == "```yaml\nenv:\n  X: y\n```"
    assert segs[2] == "Then that."


def test_cost_falls_back_for_unknown_kind():
    from tridelphi.api import analyze

    result = analyze(str(FIX / "malicious" / "pwn-request-target"))
    finding = next(f for f in result.findings if f.severity == "critical")
    assert _cost(finding)[1] in {"one-line change", "small change", "restructure"}
