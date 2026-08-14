"""L7 — trust. ``tridelphi verify``: the consumer half of L6.

L1-L5 ask "is the content bad?" and L6 *emits* signed evidence. L7 asks the one
question nothing below it asks: **is what I consume actually pinned to who it
claims to be, and has that changed since I accepted it?**

Two things happen here, in descending order of how much you can rely on them
today:

* **The trust-lock pawl (always on, fully offline, the headline).** Every
  third-party ``uses:`` you consume is recorded — from workflows *and* from
  action definitions (``action.yml``, ``.github/actions/*/action.yml``), since
  a published composite action ships its dependencies to everyone who uses it
  — action, the ref you
  wrote, and the commit SHA it is pinned to — in ``.tridelphi/trust.lock``.
  On a later run, an action whose pinned SHA *changed under the same ref*, or
  whose owner changed (a repo transfer), fails the gate. This is the pawl that
  catches the tj-actions class: SHA-pinning defeats tag *mutation*, but a
  trust-lock on the resolved identity defeats the *transfer / takeover* case
  that pinning cannot see. It needs no network and no crypto — just the diff
  between what you locked and what the workflow says now.

* **Upstream build provenance (opportunistic, wraps `gh attestation verify`).**
  Where an action publishes SLSA provenance and the ``gh`` CLI is present and
  online, we verify it. In 2026 most actions publish none, so this is reported
  honestly at ``note`` level — real signal where it exists, never inflated into
  a warning the user cannot act on. Absent tool or network: skipped with a
  diagnostic, exactly like the ladder's other wrapped rungs.

Severity, following core's actionable-vs-informational split:

* **error** — a trust-lock regression (a locked action now resolves to a
  different SHA or owner), or provenance that is present but *fails* verification.
* **note** — an action not yet in the lock (unverified, informational), or one
  with no upstream provenance published at all.

Determinism: results are sorted and carry no timestamp, so a fixed repo + lock
produce byte-identical SARIF. Drift is a diff in the committed lock file, not a
wall-clock event — drift-as-a-diff, not drift-as-a-service.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .orchestrate import sarif_shape_error

__all__ = [
    "TRUST_LOCK_PATH",
    "ActionRef",
    "enumerate_uses",
    "run_verify",
    "verify_to_sarif",
]

# A workflow file and the trust-lock are both read whole into memory. They are
# small by construction, so a file past this cap is not a real one — reading it
# would only serve a memory-exhaustion attempt. 8 MiB matches the exposure
# reader's cap; over it we skip the file rather than swallow it.
_MAX_READ_BYTES = 8 * 1024 * 1024


def _read_text_bounded(path: Path) -> str | None:
    """Read ``path`` as UTF-8, but refuse anything larger than ``_MAX_READ_BYTES``."""
    try:
        if path.stat().st_size > _MAX_READ_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

TRUST_LOCK_PATH = ".tridelphi/trust.lock"
_VERIFY_DOCS = "https://girnarholdings.github.io/TriDelPhi/#l7"

# owner/repo(/subpath)@ref — the shape of a marketplace/third-party `uses:`.
# Local (`./…`) and docker (`docker://…`) uses are handled separately.
_USES_RE = re.compile(r"^([\w.-]+)/([\w.-]+)((?:/[\w.-]+)*)@(.+)$")
# A 40-hex commit SHA is the only ref shape SHA-pinning produces.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ActionRef:
    """One ``uses:`` reference to a third-party action."""

    owner: str
    repo: str
    subpath: str  # "" or "/path/to/subaction"
    ref: str  # what was written after @ — a SHA if pinned, else a tag/branch
    # Repo-relative path of the file the `uses:` was found in. Named `workflow`
    # for history; it is now any consuming file — a workflow OR an action
    # definition (action.yml, .github/actions/*/action.yml).
    workflow: str
    line: int  # 1-indexed line of the `uses:` in that file

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}{self.subpath}"

    @property
    def pinned_sha(self) -> str | None:
        return self.ref if _SHA_RE.match(self.ref) else None

    @property
    def lock_key(self) -> str:
        """Identity independent of the pin, so a SHA change is a diff not a new
        entry. Subpath included: two subactions of one repo lock separately.

        Lower-cased: GitHub resolves ``owner/repo`` case-insensitively (repo
        routing does not distinguish ``Actions/checkout`` from
        ``actions/checkout``), so the lock key must not either. Otherwise an
        attacker can evade the pawl for free: change the case of a `uses:`
        line and its SHA in the same PR, and a case-sensitive key would treat
        the locked action as brand new — downgrading what should be a gating
        ``trust-lock-regression`` error to a non-gating ``unlocked-action``
        note. Matching GitHub's own case-insensitivity here is what keeps a
        tampered casing from being a way to launder a takeover as "unseen
        before" instead of "changed"."""
        return self.slug.lower()


def _uses_value(line: str) -> str | None:
    """Extract the ``uses:`` value from a raw workflow line, or None.

    Deliberately a line-level scan rather than a full YAML load: verify runs on
    the raw file so it can report exact line numbers and so a workflow that our
    strict parser would reject still gets its actions checked.
    """
    stripped = line.strip()
    if stripped.startswith("#"):
        return None
    m = re.match(r"^-?\s*uses:\s*(.+?)\s*(?:#.*)?$", stripped)
    if not m:
        return None
    value = m.group(1).strip().strip("'\"")
    return value or None


# A bare `uses:` key with nothing after the colon (besides a comment) — the
# shape whose value YAML folds onto the next line.
_BARE_USES_KEY_RE = re.compile(r"^-?\s*uses:\s*(?:#.*)?$")


def _folded_uses_value(lines: list[str], key_idx: int) -> str | None:
    """Handle `uses:` value folded onto the very next line — plain, valid
    YAML that GitHub Actions parses identically to the single-line form:

        - uses:
            actions/checkout@<sha>

    is the same action reference as `- uses: actions/checkout@<sha>`. A
    same-line-only scan misses it entirely — not as an "unlocked" note, but
    invisibly, with no finding at all — which makes it a way to place a
    third-party action completely outside the pawl's view. Handles only the
    direct one-line fold (the realistic shape); deeper multi-line YAML
    folding remains out of the line-scan's stated scope.
    """
    key_line = lines[key_idx]
    if not _BARE_USES_KEY_RE.match(key_line.strip()):
        return None
    if key_idx + 1 >= len(lines):
        return None
    nxt = lines[key_idx + 1]
    nxt_stripped = nxt.strip()
    if not nxt_stripped or nxt_stripped.startswith(("#", "-")):
        return None
    key_indent = len(key_line) - len(key_line.lstrip(" "))
    nxt_indent = len(nxt) - len(nxt.lstrip(" "))
    if nxt_indent <= key_indent:
        return None  # not a continuation — a sibling key or dedented content
    m = re.match(r"^(.+?)\s*(?:#.*)?$", nxt_stripped)
    if not m:
        return None
    value = m.group(1).strip().strip("'\"")
    return value or None


def _uses_sources(root: Path) -> list[Path]:
    """Every file that can consume a third-party action.

    Workflows are the obvious half. The other half is **action definitions** —
    ``action.yml`` at the repo root, and composite actions under
    ``.github/actions/``. Those consume actions exactly like a workflow does,
    and a repo that *publishes* one ships its dependencies to every consumer;
    leaving them unlocked meant the pawl watched this project's own workflows
    while its published action's dependencies could be swapped unseen.
    """
    sources: list[Path] = []
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        sources += sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml"))
    for name in ("action.yml", "action.yaml"):
        candidate = root / name
        if candidate.is_file():
            sources.append(candidate)
    actions_dir = root / ".github" / "actions"
    if actions_dir.is_dir():
        sources += sorted(actions_dir.glob("*/action.yml"))
        sources += sorted(actions_dir.glob("*/action.yaml"))
    return sources


def enumerate_uses(repo_root: str | Path) -> list[ActionRef]:
    """Every third-party ``uses:`` this repo consumes, deterministically.

    Covers workflows *and* action definitions (see ``_uses_sources``). Local
    (``./``) and docker (``docker://``) uses are excluded: neither has a
    publisher identity to lock. Results are sorted by (slug, file, line) so the
    output order never depends on the filesystem.
    """
    root = Path(repo_root)
    refs: list[ActionRef] = []
    for source in _uses_sources(root):
        text = _read_text_bounded(source)
        if text is None:
            continue
        rel = source.relative_to(root).as_posix()
        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            value = _uses_value(line)
            if value is None:
                value = _folded_uses_value(lines, i - 1)
            if value is None or value.startswith(("./", "docker://")):
                continue
            m = _USES_RE.match(value)
            if not m:
                continue
            owner, repo, subpath, ref = m.groups()
            refs.append(ActionRef(owner, repo, subpath, ref, rel, i))
    refs.sort(key=lambda r: (r.slug, r.workflow, r.line))
    return refs


def _load_lock(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        return {}
    text = _read_text_bounded(path)
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    entries = data.get("actions") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        return {}
    clean: dict[str, dict[str, str]] = {}
    for key, entry in entries.items():
        if isinstance(key, str) and isinstance(entry, dict):
            sha = entry.get("sha")
            owner = entry.get("owner")
            if isinstance(sha, str) and isinstance(owner, str):
                # Normalized the same way as ActionRef.lock_key: a lock file
                # is attacker-influenceable too (committed to a repo a PR can
                # edit), and if the on-disk key casing diverged from what a
                # correctly-pinned workflow now computes, a real regression
                # would fail to match this entry and read as "unlocked" (a
                # note) instead of "changed" (an error) — the same gate
                # bypass in the other direction.
                clean[key.lower()] = {"sha": sha, "owner": owner}
    return clean


def _write_lock(path: Path, refs: list[ActionRef]) -> int:
    """Record today's pinned identities. One entry per action slug; an action
    used at several pins would be ambiguous, so the first (sorted) pin wins and
    the rest are recorded as-seen — but in practice a repo pins one SHA."""
    actions: dict[str, dict[str, str]] = {}
    for ref in refs:
        if ref.lock_key in actions:
            continue
        actions[ref.lock_key] = {"owner": ref.owner, "sha": ref.pinned_sha or ref.ref}
    document = {
        "_comment": (
            "TriDelPhi L7 trust-lock. Records the owner and pinned SHA of each "
            "third-party action. A change here on a later run fails the gate: "
            "review it — a repo transfer or takeover looks exactly like this."
        ),
        "actions": dict(sorted(actions.items())),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    return len(actions)


def _relock(
    path: Path, refs: list[ActionRef], lock: dict[str, dict[str, str]]
) -> tuple[int, list[str], list[str]]:
    """Re-lock the pins that moved, *without* blessing a change of hands.

    The pawl fires on any pin that is not what was recorded. Usually that is an
    intentional update — a dependency bot, or the maintainer — and the honest
    on-ramp back to green is to re-verify and re-record. But the one shape the
    lock exists to catch is a change of *owner*: a repo transfer or takeover
    looks exactly like a routine bump, and no amount of re-locking makes that
    safe to wave through. So an owner change refuses the whole operation and
    writes nothing — a partial re-lock while a takeover signal is live would
    bless the rest of the file under the same click.

    Returns ``(written, changed, refused, takeover)``; ``written`` is 0 when
    refused, and ``takeover`` distinguishes the change-of-owner refusal (which
    is a security signal) from a merely unrepresentable pin split.
    """
    owner_changes = [
        f"{ref.slug}: locked under owner '{lock[ref.lock_key]['owner']}' but now "
        f"resolves to '{ref.owner}'"
        for ref in refs
        if (entry := lock.get(ref.lock_key)) is not None
        and entry["owner"].lower() != ref.owner.lower()
    ]
    refused = list(owner_changes)

    # One action pinned to two different SHAs cannot be represented in the lock
    # (one entry per slug), so re-locking it would report success and leave the
    # gate red — the worst outcome: a green message over a broken state. Name
    # the split instead, with both pins, so it can actually be resolved.
    pins: dict[str, dict[str, list[str]]] = {}
    for ref in refs:
        pins.setdefault(ref.lock_key, {}).setdefault(ref.pinned_sha or ref.ref, []).append(
            f"{ref.workflow}:{ref.line}"
        )
    for key, by_sha in sorted(pins.items()):
        if len(by_sha) > 1:
            spread = "; ".join(
                f"{sha[:12]}… at {', '.join(sorted(where))}" for sha, where in sorted(by_sha.items())
            )
            refused.append(
                f"{key} is pinned to {len(by_sha)} different versions ({spread}). "
                "Pin it to one, then re-lock."
            )
    if refused:
        return 0, [], sorted(set(refused)), bool(owner_changes)

    changed: list[str] = []
    seen: set[str] = set()
    for ref in sorted(refs, key=lambda r: r.lock_key):
        if ref.lock_key in seen:
            continue
        seen.add(ref.lock_key)
        current = ref.pinned_sha or ref.ref
        entry = lock.get(ref.lock_key)
        if entry is None:
            changed.append(f"{ref.slug}: newly locked at {current[:12]}…")
        elif entry["sha"] != current:
            changed.append(f"{ref.slug}: {entry['sha'][:12]}… → {current[:12]}…")
    if not changed:
        return 0, [], [], False
    return _write_lock(path, refs), changed, [], False


@dataclass(frozen=True)
class VerifyFinding:
    level: str  # "error" | "note"
    rule: str  # short rule id suffix
    ref: ActionRef
    message: str


def _check_against_lock(
    refs: list[ActionRef], lock: dict[str, dict[str, str]]
) -> list[VerifyFinding]:
    findings: list[VerifyFinding] = []
    for ref in refs:
        locked = lock.get(ref.lock_key)
        if locked is None:
            findings.append(
                VerifyFinding(
                    "note",
                    "unlocked-action",
                    ref,
                    f"{ref.slug} is not in the trust-lock yet. Run "
                    "`tridelphi verify --write-trust-lock` to record its current "
                    "identity, after confirming it is the action you expect.",
                )
            )
            continue
        if locked["owner"].lower() != ref.owner.lower():
            findings.append(
                VerifyFinding(
                    "error",
                    "signer-owner-changed",
                    ref,
                    f"{ref.slug} was locked under owner '{locked['owner']}' but now "
                    f"resolves to '{ref.owner}'. A repo transfer or takeover looks "
                    "exactly like this — verify before updating the lock.",
                )
            )
            continue
        current = ref.pinned_sha or ref.ref
        if locked["sha"] != current:
            findings.append(
                VerifyFinding(
                    "error",
                    "trust-lock-regression",
                    ref,
                    f"{ref.slug} was locked to {locked['sha'][:12]}… but the workflow "
                    f"now pins {current[:12]}…. If you intended this bump, re-run "
                    "--write-trust-lock; if not, this is the change SHA-pinning "
                    "cannot catch.",
                )
            )
    return findings


def _gh_available() -> str | None:
    return shutil.which("gh")


def _verify_provenance(
    refs: list[ActionRef], *, offline: bool, out
) -> tuple[list[VerifyFinding], str | None]:
    """Opportunistically verify upstream SLSA provenance via `gh attestation
    verify`. Returns (findings, diagnostic). Sparse coverage in 2026 is the
    expected case, reported at note level, never inflated."""
    if offline:
        return [], "provenance verification needs the network; skipped (offline)"
    gh = _gh_available()
    if gh is None:
        return [], (
            "the `gh` CLI is not installed, so upstream provenance was not verified; "
            "the trust-lock pawl still ran. Install gh to add SLSA verification."
        )
    findings: list[VerifyFinding] = []
    # Deduplicate by pinned identity — one verify call per unique action@sha.
    seen: set[tuple[str, str]] = set()
    for ref in refs:
        sha = ref.pinned_sha
        if sha is None:
            continue
        key = (ref.slug, sha)
        if key in seen:
            continue
        seen.add(key)
        # `gh attestation verify` against the action's repo. A non-zero exit
        # means "no verifiable provenance" far more often than "verification
        # failed" in 2026, so we report absence at note, not error.
        try:
            completed = subprocess.run(
                [gh, "attestation", "verify", f"oci://ghcr.io/{ref.slug}", "--repo", ref.slug],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode != 0:
            findings.append(
                VerifyFinding(
                    "note",
                    "no-provenance",
                    ref,
                    f"{ref.slug} publishes no verifiable build provenance (base rate "
                    "in 2026). Not your fault and not yet fixable — informational.",
                )
            )
    return findings, None


def verify_to_sarif(findings: list[VerifyFinding], *, tool_version: str) -> dict[str, Any]:
    """Render verify findings as one SARIF run, through the shared shape gate."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in sorted(findings, key=lambda f: (f.rule, f.ref.slug, f.ref.workflow, f.ref.line)):
        rule_id = f"tridelphi-verify/{f.rule}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": f.rule.replace("-", ""),
                "shortDescription": {"text": f"L7 trust: {f.rule}"},
                "helpUri": _VERIFY_DOCS,
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": f.level,
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.ref.workflow},
                            "region": {"startLine": f.ref.line},
                        }
                    }
                ],
            }
        )
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tridelphi-verify",
                        "semanticVersion": tool_version,
                        "informationUri": _VERIFY_DOCS,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return document


def run_verify(
    repo_root: str | Path = ".",
    *,
    trust_lock: str | None = None,
    write_lock: bool = False,
    relock: bool = False,
    offline: bool = False,
    fail_on: str = "critical",
    tool_version: str = "0",
    out=None,
    err=None,
) -> tuple[int, dict[str, Any] | None]:
    """Verify trust roots. Returns (exit_code, sarif_or_None).

    Exit codes mirror the gate: 0 pass, 1 findings at/above ``fail_on``, 2 an
    execution problem. When ``write_lock`` is set, records the lock and returns
    0 with no SARIF.
    """
    out = out or sys.stdout
    err = err or sys.stderr
    root = Path(repo_root)
    if not root.is_dir():
        print(f"tridelphi: {root} is not a directory", file=err)
        return 2, None

    lock_path = Path(trust_lock) if trust_lock else root / TRUST_LOCK_PATH
    refs = enumerate_uses(root)

    if write_lock:
        count = _write_lock(lock_path, refs)
        print(f"wrote {count} action identit{'y' if count == 1 else 'ies'} to {lock_path}", file=out)
        return 0, None

    if relock:
        written, changed, refused, takeover = _relock(
            lock_path, refs, _load_lock(lock_path)
        )
        if refused:
            headline = (
                "refusing to re-lock — an action changed hands, which is what this "
                "lock exists to catch:"
                if takeover
                else "refusing to re-lock — the pins cannot be recorded as they stand:"
            )
            print(f"tridelphi: {headline}", file=err)
            for line in refused:
                print(f"  {line}", file=err)
            if takeover:
                print(
                    "  Confirm the action is still the one you trust, then record it "
                    "deliberately with `tridelphi verify --write-trust-lock`.",
                    file=err,
                )
            return 1, None
        if not changed:
            print("trust-lock already matches every pinned action — nothing to re-lock", file=out)
            return 0, None
        print(f"re-locked {len(changed)} action identit{'y' if len(changed) == 1 else 'ies'}:",
              file=out)
        for line in changed:
            print(f"  {line}", file=out)
        print(f"wrote {written} entr{'y' if written == 1 else 'ies'} to {lock_path}", file=out)
        return 0, None

    lock = _load_lock(lock_path)
    findings = _check_against_lock(refs, lock)
    provenance, diagnostic = _verify_provenance(refs, offline=offline, out=out)
    if diagnostic is not None:
        print(f"tridelphi: {diagnostic}", file=err)
    findings.extend(provenance)

    document = verify_to_sarif(findings, tool_version=tool_version)
    defect = sarif_shape_error(document)
    if defect is not None:  # pragma: no cover - converter and gate out of sync
        print(f"tridelphi: verify produced {defect}", file=err)
        return 2, None

    errors = sum(1 for f in findings if f.level == "error")
    notes = sum(1 for f in findings if f.level == "note")
    print(
        f"L7 trust: {len(refs)} third-party action{'s' if len(refs) != 1 else ''} · "
        f"{errors} error{'s' if errors != 1 else ''}, {notes} note{'s' if notes != 1 else ''}",
        file=out,
    )
    if not lock:
        print(
            "  no trust-lock yet — run `tridelphi verify --write-trust-lock` to arm the pawl",
            file=out,
        )

    from .render import SEVERITY_ORDER

    if fail_on == "none":
        return 0, document
    threshold = SEVERITY_ORDER[fail_on]
    level_to_sev = {"error": "critical", "note": "note"}
    if any(SEVERITY_ORDER[level_to_sev[f.level]] <= threshold for f in findings):
        return 1, document
    return 0, document
