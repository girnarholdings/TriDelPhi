"""The fixers behind `tridelphi guard` — edits that must prove themselves.

Every fixer here follows the same contract, and it is the whole point:

    snapshot -> transform -> re-analyze -> verified clean, or rolled back.

No edit survives unless a fresh scan shows the targeted finding actually
cleared. A fixer that "probably worked" is worse than no fixer — the user just
told us to touch their CI, and the one unforgivable outcome is leaving the file
both changed *and* still vulnerable. Rollback restores the exact original
bytes.

Three findings get automatic fixes (the ones whose remediation is mechanical):

    env-indirect        hoist every injected ``${{ }}`` expression in the step
                        into a step ``env:`` var and quote it in the script
    drop-untrusted-ref  remove the ``ref:``/``repository:`` inputs that point a
                        checkout at the pull request head
    narrow-trigger      insert the author_association job gate the remediation
                        recommends (the detectors honour it — see
                        ``detect_guards.has_strong_association_gate``)

Two generic actions work on any finding with a known location:

    comment-out         neutralise the offending step by commenting it out
    disable-workflow    rename ``x.yml`` to ``x.yml.disabled`` so neither
                        GitHub nor TriDelPhi runs it (reversible by renaming
                        back)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .api import analyze
from .model import Finding
from .render import SEVERITY_ORDER

__all__ = [
    "AUTO_FIXABLE",
    "FixResult",
    "apply_action",
    "finding_key",
]

_BACKTICKED = re.compile(r"`([^`]+)`")
_STEP_DASH = re.compile(r"^(\s*)-\s")

# A workflow file read whole into memory before editing. Real ones are small; a
# file past this cap is not one we should slurp. 8 MiB matches the scanner's
# other readers.
_MAX_WORKFLOW_BYTES = 8 * 1024 * 1024


def _read_workflow(path: Path) -> str | None:
    """Read a workflow file to edit, refusing an implausibly large one."""
    try:
        if path.stat().st_size > _MAX_WORKFLOW_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


@dataclass(frozen=True, slots=True)
class FixResult:
    status: Literal["applied", "failed", "unavailable"]
    action: str
    detail: str
    files_changed: tuple[str, ...] = ()


def finding_key(finding: Finding) -> tuple[str, str, str]:
    """The identity a fix must clear: rule on job in workflow."""
    return (finding.rule_id, finding.context.workflow_file, finding.context.job_id)


# ---------------------------------------------------------------------------
# span finding — line-based, anchored on the positions the detectors recorded
# ---------------------------------------------------------------------------


def _job_span(lines: list[str], job_id: str) -> tuple[int, int] | None:
    """[start, end) of the job's block, found from the ``jobs:`` section."""
    jobs_at = next(
        (i for i, ln in enumerate(lines) if re.match(r"^jobs:\s*(#.*)?$", ln)), None
    )
    if jobs_at is None:
        return None
    start = None
    indent = None
    for i in range(jobs_at + 1, len(lines)):
        m = re.match(rf"^(\s+){re.escape(job_id)}:\s*(#.*)?$", lines[i])
        if m:
            start, indent = i, len(m.group(1))
            break
    if start is None:
        return None
    end = len(lines)
    for i in range(start + 1, len(lines)):
        ln = lines[i]
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent and not ln.lstrip().startswith("#"):
            end = i
            break
    return start, end


def _step_span(lines: list[str], anchor: int) -> tuple[int, int] | None:
    """[start, end) of the step containing 0-indexed line ``anchor``.

    Anchored on the ``steps:`` key so that ``- item`` lines inside literal
    ``run: |`` blocks (which sit at deeper indentation) are never mistaken for
    step boundaries.
    """
    steps_at = None
    for i in range(anchor, -1, -1):
        if re.match(r"^\s*steps:\s*(#.*)?$", lines[i]):
            steps_at = i
            break
    if steps_at is None:
        return None
    steps_indent = len(lines[steps_at]) - len(lines[steps_at].lstrip())
    # The first item line below `steps:` fixes the dash column for the block.
    dash_indent = None
    starts: list[int] = []
    for i in range(steps_at + 1, len(lines)):
        ln = lines[i]
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= steps_indent and not ln.lstrip().startswith("#"):
            break  # left the steps block
        m = _STEP_DASH.match(ln)
        if m is None:
            continue
        if dash_indent is None:
            dash_indent = len(m.group(1))
        if len(m.group(1)) == dash_indent:
            starts.append(i)
    if not starts:
        return None
    start = max((s for s in starts if s <= anchor), default=None)
    if start is None:
        return None
    later = [s for s in starts if s > start]
    end = later[0] if later else None
    if end is None:
        end = len(lines)
        for i in range(start + 1, len(lines)):
            ln = lines[i]
            if ln.strip() and (len(ln) - len(ln.lstrip())) <= steps_indent and not ln.lstrip().startswith("#"):
                end = i
                break
    return start, end


# ---------------------------------------------------------------------------
# transforms — pure text -> text | None (None = cannot apply here)
# ---------------------------------------------------------------------------


def _var_name(path: str, taken: set[str]) -> str:
    """`github.event.issue.body` -> `ISSUE_BODY` (collision-safe)."""
    segments = [s for s in re.split(r"[^A-Za-z0-9]+", path) if s]
    base = "_".join(s.upper() for s in segments[-2:]) or "UNTRUSTED_INPUT"
    name, n = base, 1
    while name in taken:
        n += 1
        name = f"{base}_{n}"
    taken.add(name)
    return name


def _injected_tokens(finding: Finding) -> list[str]:
    """Every ``${{ … }}`` expression the U hits identified, deduplicated."""
    tokens: list[str] = []
    for hit in finding.hits:
        if hit.capability != "U" or hit.kind != "expression-injection":
            continue
        m = _BACKTICKED.search(hit.reason)
        if m and m.group(1).startswith("${{") and m.group(1) not in tokens:
            tokens.append(m.group(1))
    return tokens


def _fix_env_indirect(text: str, finding: Finding) -> str | None:
    """Hoist every injected expression in the step into env indirection.

    Fixing only the token the remediation names would leave sibling injections
    behind and fail verification, so all expression-injection hits in the step
    are hoisted together — that is what the re-scan demands.
    """
    tokens = _injected_tokens(finding)
    pos = finding.remediation.target_position if finding.remediation else None
    if not tokens or pos is None:
        return None
    lines = text.split("\n")
    span = _step_span(lines, pos.line - 1)
    if span is None:
        return None
    start, end = span
    step = lines[start:end]

    run_rel = next(
        (i for i, ln in enumerate(step) if re.match(r"^\s*(-\s+)?run:", ln)), None
    )
    if run_rel is None:
        return None
    key_indent = None
    for ln in step:
        m = re.match(r"^(\s*)(?!-)[A-Za-z_-]+:", ln)
        if m:
            key_indent = m.group(1)
            break
    if key_indent is None:
        m = _STEP_DASH.match(step[0])
        key_indent = " " * (len(m.group(1)) + 2) if m else "        "

    taken: set[str] = set()
    env_lines: list[str] = []
    for token in tokens:
        path = token[3:-2].strip()  # strip `${{` and `}}`
        var = _var_name(path, taken)
        for i, ln in enumerate(step):
            while token in ln:
                at = ln.index(token)
                # Inside an open double-quoted string (odd count of `"` before
                # the token) the var is already protected; elsewhere, quote it
                # so attacker text never word-splits.
                inside = ln[:at].count('"') % 2 == 1 or (at and ln[at - 1] == "'")
                repl = f"${var}" if inside else f'"${var}"'
                ln = ln[:at] + repl + ln[at + len(token):]
            step[i] = ln
        env_lines.append(f"{key_indent}  {var}: {token}")

    env_rel = next((i for i, ln in enumerate(step) if re.match(r"^\s*env:\s*$", ln)), None)
    if env_rel is not None:
        step[env_rel + 1 : env_rel + 1] = env_lines
    else:
        step[run_rel:run_rel] = [f"{key_indent}env:", *env_lines]

    return "\n".join(lines[:start] + step + lines[end:])


_HEAD_REF = re.compile(
    r"^\s*(ref|repository):\s*.*(github\.event\.pull_request\.head|github\.head_ref)"
)


def _fix_drop_ref(text: str, finding: Finding) -> str | None:
    """Remove the checkout inputs that resolve to the pull request head.

    `repository:` goes with `ref:` — dropping only the ref while keeping the
    fork's repository would still fetch code a stranger controls. An emptied
    `with:` block is removed so the YAML stays valid.
    """
    lines = text.split("\n")
    span = _job_span(lines, finding.context.job_id)
    if span is None:
        return None
    start, end = span
    keep: list[str] = []
    dropped = False
    for i in range(start, end):
        if _HEAD_REF.match(lines[i]):
            dropped = True
            continue
        keep.append(lines[i])
    if not dropped:
        return None
    # Remove any `with:` left with no children.
    cleaned: list[str] = []
    for i, ln in enumerate(keep):
        m = re.match(r"^(\s*)with:\s*$", ln)
        if m:
            indent = len(m.group(1))
            nxt = next((k for k in keep[i + 1 :] if k.strip()), "")
            if not nxt or (len(nxt) - len(nxt.lstrip())) <= indent:
                continue
        cleaned.append(ln)
    return "\n".join(lines[:start] + cleaned + lines[end:])


# Which event payload the association gate must vet, by trigger.
_ASSOCIATION_CONTEXT = (
    ("issue_comment", "github.event.comment.author_association"),
    ("pull_request_review_comment", "github.event.comment.author_association"),
    ("discussion_comment", "github.event.comment.author_association"),
    ("issues", "github.event.issue.author_association"),
    ("pull_request_target", "github.event.pull_request.author_association"),
    ("pull_request", "github.event.pull_request.author_association"),
)


def _fix_narrow_trigger(text: str, finding: Finding) -> str | None:
    """Insert the author_association job gate the remediation recommends."""
    lines = text.split("\n")
    span = _job_span(lines, finding.context.job_id)
    if span is None:
        return None
    start, end = span
    body = [ln for ln in lines[start + 1 : end] if ln.strip()]
    if not body:
        return None
    if any(re.match(r"^\s*if:", ln) for ln in body):
        return None  # an existing gate is logic we must not clobber
    child_indent = " " * (len(body[0]) - len(body[0].lstrip()))
    association = next(
        (ctx for trig, ctx in _ASSOCIATION_CONTEXT if trig in finding.context.triggers),
        "github.event.comment.author_association",
    )
    gate = (
        f"{child_indent}if: contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), {association})"
    )
    return "\n".join([*lines[:start + 1], gate, *lines[start + 1:end], *lines[end:]])


def _comment_out_step(text: str, finding: Finding) -> str | None:
    """Neutralise the offending step: comment it out with a signed marker."""
    pos = finding.remediation.target_position if finding.remediation else None
    pos = pos or finding.primary_position
    lines = text.split("\n")
    span = _step_span(lines, pos.line - 1)
    if span is None:
        # Fall back to a step-level hit if the primary anchor is the job line.
        for hit in finding.hits:
            if hit.position.file == finding.context.workflow_file:
                span = _step_span(lines, hit.position.line - 1)
                if span is not None:
                    break
    if span is None:
        return None
    start, end = span
    indent = " " * (len(lines[start]) - len(lines[start].lstrip()))
    marker = (
        f"{indent}# tridelphi: step disabled ({finding.rule_id}) — fix it, then "
        "delete these comment markers to re-enable"
    )
    body = [f"{indent}# {ln.lstrip()}" if ln.strip() else ln for ln in lines[start:end]]
    return "\n".join([*lines[:start], marker, *body, *lines[end:]])


# ---------------------------------------------------------------------------
# the engine — snapshot, transform, verify, or roll back
# ---------------------------------------------------------------------------

_TRANSFORMS = {
    "env-indirect": _fix_env_indirect,
    "drop-untrusted-ref": _fix_drop_ref,
    "narrow-trigger": _fix_narrow_trigger,
}

AUTO_FIXABLE = frozenset(_TRANSFORMS)


def _verify_cleared(repo_root: Path, finding: Finding) -> bool:
    """A fix counts only if the same finding no longer appears at its severity."""
    key = finding_key(finding)
    rank = SEVERITY_ORDER[finding.severity]
    fresh = analyze(repo_root)
    return not any(
        finding_key(f) == key and SEVERITY_ORDER[f.severity] <= rank
        for f in fresh.findings
    )


def apply_action(repo_root: str | Path, finding: Finding, action: str) -> FixResult:
    """Apply one action to one finding, verified or rolled back.

    ``action`` is ``"fix"`` (the kind-specific automatic fix), ``"comment-out"``
    or ``"disable"``.
    """
    root = Path(repo_root)
    workflow = root / finding.context.workflow_file

    if action == "disable":
        target = workflow.with_name(workflow.name + ".disabled")
        original = _read_workflow(workflow)
        if original is None:
            return FixResult("failed", action, "workflow file is missing or too large to read")
        header = (
            "# tridelphi: workflow disabled — rename back to "
            f"{workflow.name} to re-enable\n"
        )
        target.write_text(header + original, encoding="utf-8", newline="\n")
        workflow.unlink()
        if _verify_cleared(root, finding):
            return FixResult(
                "applied",
                action,
                f"renamed to {target.name}; GitHub no longer runs it",
                (finding.context.workflow_file,),
            )
        target.unlink()
        workflow.write_text(original, encoding="utf-8", newline="\n")
        return FixResult("failed", action, "disabling did not clear the finding; restored")

    if action == "fix":
        kind = finding.remediation.kind if finding.remediation else ""
        transform = _TRANSFORMS.get(kind)
        if transform is None:
            return FixResult(
                "unavailable", action, f"no automatic fix for `{kind or 'this finding'}`"
            )
    elif action == "comment-out":
        transform = _comment_out_step
    else:
        return FixResult("unavailable", action, f"unknown action `{action}`")

    original = _read_workflow(workflow)
    if original is None:
        return FixResult("unavailable", action, "workflow file is missing or too large to read")
    changed = transform(original, finding)
    if changed is None or changed == original:
        return FixResult(
            "unavailable", action, "could not locate an unambiguous edit site"
        )
    workflow.write_text(changed, encoding="utf-8", newline="\n")
    if _verify_cleared(root, finding):
        return FixResult(
            "applied",
            action,
            "edited and re-scanned — the finding is gone",
            (finding.context.workflow_file,),
        )
    workflow.write_text(original, encoding="utf-8", newline="\n")
    return FixResult(
        "failed",
        action,
        "the edit did not clear the finding on re-scan; original file restored",
    )
