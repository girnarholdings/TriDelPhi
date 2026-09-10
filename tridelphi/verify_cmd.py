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
  Once the lock exists, a changed pin or newly introduced publisher fails the
  gate until a reviewer deliberately re-locks it. A simultaneous removal and
  addition is treated as a possible publisher replacement and cannot be
  auto-relocked. This is an offline source-diff pawl: it does not resolve
  GitHub redirects, prove publisher ownership, or certify that a commit is safe.

* **Upstream build provenance (explicitly out of scope for source refs).** A
  ``uses: owner/repo@sha`` consumes repository source at a commit; it is not an
  OCI image or release artifact with a subject digest. TriDelPhi therefore does
  not feed a fabricated ``oci://ghcr.io/owner/repo`` subject to ``gh
  attestation verify``. The offline lock is the enforceable claim here. Future
  artifact verification must begin from an actual downloaded subject.

Severity, following core's actionable-vs-informational split:

* **error** — a trust-lock regression, an unreviewed action after the lock has
  been armed, an unreadable source, or an invalid lock.
* **note** — an action not yet in the lock when no lock exists (onboarding).

Determinism: results are sorted and carry no timestamp, so a fixed repo + lock
produce byte-identical SARIF. Drift is a diff in the committed lock file, not a
wall-clock event — drift-as-a-diff, not drift-as-a-service.
"""

from __future__ import annotations

import json
import re
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from .fsutil import atomic_write_text
from .orchestrate import sarif_shape_error
from .severity import SARIF_LEVEL_TO_SEVERITY, should_fail
from .structure import structure_error

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
_MAX_SOURCE_ENTRIES = 10_000
_MAX_SOURCE_FILES = 5_000


def _read_text_bounded(path: Path) -> str | None:
    """Read ``path`` as UTF-8, but refuse anything larger than ``_MAX_READ_BYTES``."""
    try:
        if path.stat().st_size > _MAX_READ_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _repo_path_has_symlink(root: Path, path: Path) -> bool:
    """Reject a repo-relative path if any component redirects through a link."""

    try:
        relative = path.relative_to(root)
    except ValueError:
        return path.is_symlink()
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False

TRUST_LOCK_PATH = ".tridelphi/trust.lock"
_VERIFY_DOCS = "https://girnarholdings.github.io/TriDelPhi/#l7"

# owner/repo(/subpath)@ref — the shape of a marketplace/third-party `uses:`.
# Local (`./…`) and docker (`docker://…`) uses are handled separately.
_USES_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/"
    r"([A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?)"
    r"((?:/[A-Za-z0-9_.-]+)*)@([^\s@]{1,200})$",
    re.ASCII,
)
_OWNER_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$", re.ASCII
)
# A 40-hex commit SHA is the only ref shape SHA-pinning produces.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE | re.ASCII)


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
        return self.ref.lower() if _SHA_RE.match(self.ref) else None

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
        tampered casing from being a way to launder a pin regression as "unseen
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


def _uses_candidates(root: Path) -> tuple[list[Path], list[tuple[str, str]]]:
    """Potential executable YAML inputs plus sources that cannot be inspected."""
    candidates: list[Path] = []
    problems: list[tuple[str, str]] = []

    def entries(directory: Path, label: str) -> list[Path]:
        try:
            visible: list[Path] = []
            for index, item in enumerate(directory.iterdir(), start=1):
                if index > _MAX_SOURCE_ENTRIES:
                    problems.append(
                        (label, f"source discovery exceeded {_MAX_SOURCE_ENTRIES} directory entries")
                    )
                    break
                visible.append(item)
            return sorted(visible, key=lambda path: path.name)
        except OSError:
            problems.append((label, "source directory could not be enumerated"))
            return []

    workflows = root / ".github" / "workflows"
    github_dir = root / ".github"
    if github_dir.is_symlink():
        problems.append((".github", "GitHub metadata directory is a symlink"))
    elif workflows.is_symlink():
        problems.append((".github/workflows", "workflow directory is a symlink"))
    elif workflows.is_dir():
        candidates.extend(
            path for path in entries(workflows, ".github/workflows")
            if path.suffix in {".yml", ".yaml"}
        )
    for name in ("action.yml", "action.yaml"):
        candidate = root / name
        if candidate.exists() or candidate.is_symlink():
            candidates.append(candidate)
    actions_dir = root / ".github" / "actions"
    if github_dir.is_symlink():
        pass
    elif actions_dir.is_symlink():
        problems.append((".github/actions", "local actions directory is a symlink"))
    elif actions_dir.is_dir():
        for action_dir in entries(actions_dir, ".github/actions"):
            relative = action_dir.relative_to(root).as_posix()
            if action_dir.is_symlink():
                problems.append((relative, "local action path is a symlink"))
                continue
            try:
                is_directory = action_dir.is_dir()
            except OSError:
                problems.append((relative, "local action path could not be inspected"))
                continue
            if not is_directory:
                continue
            for name in ("action.yml", "action.yaml"):
                source = action_dir / name
                if source.exists() or source.is_symlink():
                    candidates.append(source)
    unique = list(dict.fromkeys(candidates))
    if len(unique) > _MAX_SOURCE_FILES:
        problems.append(
            (".github", f"more than {_MAX_SOURCE_FILES} executable action sources were found")
        )
        unique = unique[:_MAX_SOURCE_FILES]
    return unique, problems


def _uses_sources(root: Path) -> list[Path]:
    """Every file that can consume a third-party action.

    Workflows are the obvious half. The other half is **action definitions** —
    ``action.yml`` at the repo root, and composite actions under
    ``.github/actions/``. Those consume actions exactly like a workflow does,
    and a repo that *publishes* one ships its dependencies to every consumer;
    leaving them unlocked meant the pawl watched this project's own workflows
    while its published action's dependencies could be swapped unseen.
    """
    candidates, _problems = _uses_candidates(root)
    return [path for path in candidates if path.is_file() and not path.is_symlink()]


def _uses_source_problems(root: Path) -> list[tuple[str, str]]:
    candidates, problems = _uses_candidates(root)
    for path in candidates:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = path.name
        if path.is_symlink():
            problems.append((relative, "executable action source is a symlink"))
            continue
        try:
            stat_result = path.stat()
        except OSError as exc:
            problems.append((relative, f"executable action source cannot be read: {exc}"))
            continue
        if not path.is_file():
            problems.append((relative, "executable action source is not a regular file"))
        elif stat_result.st_size > _MAX_READ_BYTES:
            problems.append((relative, "executable action source exceeds the 8 MiB safety limit"))
    return sorted(set(problems))


def _mapping_uses(mapping: Any) -> tuple[str, int] | None:
    if not isinstance(mapping, dict) or "uses" not in mapping:
        return None
    value = mapping.get("uses")
    if not isinstance(value, str) or not value.strip():
        return None
    line = 1
    with suppress(AttributeError, KeyError, TypeError):
        line = int(mapping.lc.key("uses")[0]) + 1
    return value.strip(), line


def _structured_uses(text: str, *, action_definition: bool) -> list[tuple[str, int]] | None:
    """Executable `uses:` nodes from valid YAML, including flow mappings."""

    yaml = YAML(typ="rt")
    yaml.allow_duplicate_keys = False
    try:
        document = yaml.load(text)
    except (YAMLError, ValueError, RecursionError):
        return None
    if structure_error(document) is not None:
        return None
    if not isinstance(document, dict):
        return []
    entries: list[tuple[str, int]] = []
    if action_definition:
        runs = document.get("runs")
        steps = runs.get("steps") if isinstance(runs, dict) else None
        for step in steps if isinstance(steps, list) else []:
            if (entry := _mapping_uses(step)) is not None:
                entries.append(entry)
        return entries
    jobs = document.get("jobs")
    for job in jobs.values() if isinstance(jobs, dict) else []:
        if not isinstance(job, dict):
            continue
        if (entry := _mapping_uses(job)) is not None:
            entries.append(entry)
        steps = job.get("steps")
        for step in steps if isinstance(steps, list) else []:
            if (entry := _mapping_uses(step)) is not None:
                entries.append(entry)
    return entries


def _raw_uses(text: str):
    """Best-effort fallback for malformed YAML that core reports separately."""

    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        value = _uses_value(line)
        if value is None:
            value = _folded_uses_value(lines, index - 1)
        if value is not None:
            yield value, index


def _uses_entries(root: Path):
    """Executable non-local uses values with their exact source location."""

    for source in _uses_sources(root):
        text = _read_text_bounded(source)
        if text is None:
            continue
        rel = source.relative_to(root).as_posix()
        action_definition = source.name in {"action.yml", "action.yaml"} and not rel.startswith(
            ".github/workflows/"
        )
        structured = _structured_uses(text, action_definition=action_definition)
        entries = structured if structured is not None else list(_raw_uses(text))
        for value, line in entries:
            if value.startswith(("./", "docker://")):
                continue
            yield value, rel, line


def _parse_action_ref(value: str, workflow: str, line: int) -> ActionRef | None:
    match = _USES_RE.fullmatch(value)
    if match is None:
        return None
    owner, repo, subpath, ref = match.groups()
    if any(segment in {".", ".."} for segment in subpath.split("/") if segment):
        return None
    return ActionRef(owner, repo, subpath, ref, workflow, line)


def enumerate_uses(repo_root: str | Path) -> list[ActionRef]:
    """Every third-party ``uses:`` this repo consumes, deterministically.

    Covers workflows *and* action definitions (see ``_uses_sources``). Local
    (``./``) and docker (``docker://``) uses are excluded: neither has a
    publisher identity to lock. Results are sorted by (slug, file, line) so the
    output order never depends on the filesystem.
    """
    root = Path(repo_root)
    refs: list[ActionRef] = []
    for value, rel, line in _uses_entries(root):
        ref = _parse_action_ref(value, rel, line)
        if ref is not None:
            refs.append(ref)
    refs.sort(key=lambda r: (r.slug, r.workflow, r.line))
    return refs


@dataclass(frozen=True)
class LockState:
    entries: dict[str, dict[str, str]]
    errors: tuple[str, ...] = ()


def _load_lock_state(path: Path, *, repo_root: Path | None = None) -> LockState:
    if (repo_root is not None and _repo_path_has_symlink(repo_root, path)) or path.is_symlink():
        return LockState({}, ("trust-lock is not a regular file",))
    if not path.exists():
        return LockState({})
    if not path.is_file():
        return LockState({}, ("trust-lock is not a regular file",))
    text = _read_text_bounded(path)
    if text is None:
        return LockState({}, ("trust-lock could not be read within the size limit",))
    try:
        pairs = json.loads(text, object_pairs_hook=lambda value: value)
    except (ValueError, RecursionError):
        return LockState({}, ("trust-lock is not valid JSON",))
    if not isinstance(pairs, list) or any(not isinstance(item, tuple) for item in pairs):
        return LockState({}, ("trust-lock root is not an object",))
    errors: list[str] = []
    top: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str):
            errors.append("trust-lock contains a non-text key")
            continue
        if key in top:
            errors.append(f"trust-lock repeats top-level key `{key}`")
        top[key] = value
    schema = top.get("version", 1)
    if schema != 1:
        errors.append(f"trust-lock version `{schema}` is not supported")
    entries = top.get("actions")
    if not isinstance(entries, list) or any(not isinstance(item, tuple) for item in entries):
        return LockState({}, tuple(sorted(set([*errors, "trust-lock has no actions object"]))))
    if len(entries) > 10_000:
        return LockState({}, tuple(sorted(set([*errors, "trust-lock has too many actions"]))))
    clean: dict[str, dict[str, str]] = {}
    for key, entry_pairs in entries:
        if not isinstance(key, str) or not isinstance(entry_pairs, list):
            errors.append("trust-lock contains a malformed action entry")
            continue
        normal_key = key.lower()
        if normal_key in clean:
            errors.append(f"trust-lock repeats action `{key}` (case-insensitive)")
            continue
        entry: dict[str, Any] = {}
        for field, value in entry_pairs:
            if field in entry:
                errors.append(f"trust-lock action `{key}` repeats field `{field}`")
            entry[field] = value
        sha = entry.get("sha")
        owner = entry.get("owner")
        if not isinstance(owner, str) or not _OWNER_RE.fullmatch(owner):
            errors.append(f"trust-lock action `{key}` contains an invalid owner")
            continue
        if not _USES_RE.fullmatch(f"{key}@{'0' * 40}"):
            errors.append(f"trust-lock action key `{key}` is invalid")
            continue
        if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
            errors.append(f"trust-lock action `{key}` does not contain a full commit SHA")
            continue
        clean[normal_key] = {"sha": sha.lower(), "owner": owner}
    return LockState(clean, tuple(sorted(set(errors))))


def _load_lock(path: Path) -> dict[str, dict[str, str]]:
    """Compatibility helper used by tests and re-lock internals."""

    return _load_lock_state(path).entries


def _write_lock(path: Path, refs: list[ActionRef]) -> int:
    """Record today's pinned identities. One entry per action slug; an action
    used at several pins would be ambiguous, so the first (sorted) pin wins and
    the rest are recorded as-seen — but in practice a repo pins one SHA."""
    actions: dict[str, dict[str, str]] = {}
    for ref in refs:
        if ref.lock_key in actions:
            continue
        if ref.pinned_sha is None:
            raise ValueError(f"{ref.slug}@{ref.ref} is not pinned to a full commit SHA")
        actions[ref.lock_key] = {"owner": ref.owner, "sha": ref.pinned_sha}
    document = {
        "_comment": (
            "TriDelPhi L7 trust-lock. Records the owner path and pinned SHA written "
            "for each third-party action. Later source changes require review; this "
            "offline file does not resolve publisher ownership or prove safety."
        ),
        "version": 1,
        "actions": dict(sorted(actions.items())),
    }
    atomic_write_text(
        path,
        json.dumps(document, indent=2) + "\n",
        create_parent=True,
        mode=0o644,
    )
    return len(actions)


def _relock(
    path: Path, refs: list[ActionRef], lock: dict[str, dict[str, str]]
) -> tuple[int, list[str], list[str], bool]:
    """Re-lock moved pins without guessing across a publisher replacement.

    The pawl fires on any pin that is not what was recorded. Usually that is an
    intentional update — a dependency bot, or the maintainer — and the honest
    on-ramp back to green is to re-verify and re-record. But the one shape the
    lock also refuses when one change removes a locked action identity and adds
    a new one. Offline source inspection cannot prove whether that pair is an
    unrelated add/remove or a publisher replacement, so the safer path is a
    deliberate full lock rewrite after human review.

    Returns ``(written, changed, refused, identity_change)``; ``written`` is 0
    when refused. ``identity_change`` distinguishes an ambiguous publisher
    replacement from a merely unrepresentable pin split.
    """
    refused = _pin_refusals(refs)
    identity_changes = [
        f"{ref.slug}: the lock records owner '{lock[ref.lock_key]['owner']}' but "
        f"the source path says '{ref.owner}'"
        for ref in refs
        if (entry := lock.get(ref.lock_key)) is not None
        and entry["owner"].lower() != ref.owner.lower()
    ]
    refused.extend(identity_changes)

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
    current_keys = {ref.lock_key for ref in refs}
    stale = sorted(set(lock) - current_keys)
    introduced = sorted(current_keys - set(lock))
    if stale and introduced:
        identity_changes.append(
            "the same change removes locked action(s) "
            f"{', '.join(stale)} and introduces {', '.join(introduced)}; "
            "TriDelPhi cannot prove whether this is a publisher replacement"
        )
        refused.extend(identity_changes[-1:])
    if refused:
        return 0, [], sorted(set(refused)), bool(identity_changes)

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
    for key in stale:
        changed.append(f"{key}: removed stale lock entry")
    if not changed:
        return 0, [], [], False
    return _write_lock(path, refs), changed, [], False


@dataclass(frozen=True)
class VerifyFinding:
    level: str  # "error" | "warning" | "note"
    rule: str  # short rule id suffix
    ref: ActionRef
    message: str


def _check_against_lock(
    refs: list[ActionRef], lock: dict[str, dict[str, str]]
) -> list[VerifyFinding]:
    findings: list[VerifyFinding] = []
    for ref in refs:
        if ref.pinned_sha is None:
            findings.append(
                VerifyFinding(
                    "error",
                    "unpinned-action",
                    ref,
                    f"{ref.slug}@{ref.ref} is mutable. Pin it to a full 40-character "
                    "commit SHA before recording trust; tags and branches can move.",
                )
            )
            continue
        locked = lock.get(ref.lock_key)
        if locked is None:
            level = "error" if lock else "note"
            rule = "unreviewed-action" if lock else "unlocked-action"
            message = (
                f"{ref.slug} is not in the existing trust-lock. A new or replaced "
                "publisher must be reviewed and recorded with `tridelphi verify "
                "--relock` before L7 can pass."
                if lock
                else f"{ref.slug} is not in the trust-lock yet. Run "
                "`tridelphi verify --write-trust-lock` to record its current "
                "identity, after confirming it is the action you expect."
            )
            findings.append(
                VerifyFinding(
                    level,
                    rule,
                    ref,
                    message,
                )
            )
            continue
        if locked["owner"].lower() != ref.owner.lower():
            findings.append(
                VerifyFinding(
                    "error",
                    "recorded-owner-changed",
                    ref,
                    f"{ref.slug} has owner '{locked['owner']}' in the lock but its "
                    f"source path says '{ref.owner}'. The lock and repository "
                    "disagree, so review both before replacing the lock.",
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
                    "--relock after review; if not, restore the recorded pin. The "
                    "lock makes source pin changes explicit; it does not inspect "
                    "remote tag movement.",
                )
            )
    return findings


def _pin_refusals(refs: list[ActionRef]) -> list[str]:
    refused = [
        f"{ref.slug}@{ref.ref} is mutable; pin it to a full commit SHA first"
        for ref in refs
        if ref.pinned_sha is None
    ]
    pins: dict[str, set[str]] = {}
    for ref in refs:
        if ref.pinned_sha is not None:
            pins.setdefault(ref.lock_key, set()).add(ref.pinned_sha)
    refused.extend(
        f"{key} is consumed at more than one SHA; use one reviewed pin"
        for key, values in sorted(pins.items())
        if len(values) > 1
    )
    return refused


def _synthetic_ref(workflow: str, line: int = 1, slug: str = "trust/lock") -> ActionRef:
    owner, _, repo = slug.partition("/")
    return ActionRef(owner or "trust", repo or "lock", "", "0" * 40, workflow, line)


def _state_findings(
    root: Path,
    refs: list[ActionRef],
    lock_path: Path,
    state: LockState,
) -> list[VerifyFinding]:
    findings: list[VerifyFinding] = []
    lock_where = (
        lock_path.relative_to(root).as_posix()
        if lock_path.is_relative_to(root)
        else lock_path.name
    )
    for error in state.errors:
        findings.append(
            VerifyFinding("error", "invalid-trust-lock", _synthetic_ref(lock_where), error)
        )
    for workflow, problem in _uses_source_problems(root):
        findings.append(
            VerifyFinding(
                "error",
                "unreadable-action-source",
                _synthetic_ref(workflow, slug="unknown/action"),
                f"{problem}. TriDelPhi cannot prove that every consumed action is "
                "covered by the trust-lock, so L7 fails closed.",
            )
        )
    current = {ref.lock_key for ref in refs}
    for stale in sorted(set(state.entries) - current):
        findings.append(
            VerifyFinding(
                "warning",
                "stale-trust-lock-entry",
                _synthetic_ref(lock_where, slug=stale),
                f"{stale} remains in the trust-lock but is no longer consumed. "
                "Review the removal, then run `tridelphi verify --relock` to prune it.",
            )
        )
    for value, workflow, line in _uses_entries(root):
        if _parse_action_ref(value, workflow, line) is None:
            safe = "".join(char if char.isprintable() else "?" for char in value)[:160]
            findings.append(
                VerifyFinding(
                    "warning",
                    "unresolved-action-reference",
                    _synthetic_ref(workflow, line, "unknown/action"),
                    f"`uses: {safe}` is neither a strict owner/repository action "
                    "reference nor a local/docker action. It was not locked; verify "
                    "the workflow syntax and publisher manually.",
                )
            )
    return findings


def _verify_provenance(
    refs: list[ActionRef], *, offline: bool, out
) -> tuple[list[VerifyFinding], str | None]:
    """Explain why source action refs have no artifact subject to verify."""
    if offline:
        return [], "offline mode: trust-lock verification ran; no network checks were attempted"
    return [], (
        "source-based GitHub actions have no downloaded artifact subject to pass to "
        "`gh attestation verify`; the offline owner + commit-SHA trust-lock is the "
        "enforced L7 claim"
    )


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
    confirm_write: bool = False,
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
    if root.is_symlink() or not root.is_dir():
        print(f"tridelphi: {root} is not a directory", file=err)
        return 2, None

    lock_path = Path(trust_lock) if trust_lock else root / TRUST_LOCK_PATH
    refs = enumerate_uses(root)
    source_problems = _uses_source_problems(root)

    if write_lock:
        if source_problems:
            print("tridelphi: refusing to write an incomplete trust-lock:", file=err)
            for where, problem in source_problems:
                print(f"  {where}: {problem}", file=err)
            return 1, None
        refused = _pin_refusals(refs)
        if refused:
            print("tridelphi: refusing to write trust-lock:", file=err)
            for reason in refused:
                print(f"  {reason}", file=err)
            return 1, None
        if lock_path.exists() and not confirm_write:
            print(
                f"tridelphi: {lock_path} already exists; use `--relock` for reviewed "
                "pin updates, or add `--yes --write-trust-lock` to replace it deliberately",
                file=err,
            )
            return 2, None
        try:
            count = _write_lock(lock_path, refs)
        except (OSError, ValueError) as exc:
            print(f"tridelphi: could not write trust-lock: {exc}", file=err)
            return 2, None
        print(f"wrote {count} action identit{'y' if count == 1 else 'ies'} to {lock_path}", file=out)
        return 0, None

    if relock:
        if source_problems:
            print("tridelphi: refusing to re-lock while action sources are unreadable:", file=err)
            for where, problem in source_problems:
                print(f"  {where}: {problem}", file=err)
            return 1, None
        state = _load_lock_state(lock_path, repo_root=root)
        if state.errors:
            print("tridelphi: refusing to re-lock an invalid trust-lock:", file=err)
            for reason in state.errors:
                print(f"  {reason}", file=err)
            return 1, None
        try:
            written, changed, refused, identity_change = _relock(
                lock_path, refs, state.entries
            )
        except (OSError, ValueError) as exc:
            print(f"tridelphi: could not re-lock: {exc}", file=err)
            return 2, None
        if refused:
            headline = (
                "refusing to re-lock — publisher identity changed or is ambiguous:"
                if identity_change
                else "refusing to re-lock — the pins cannot be recorded as they stand:"
            )
            print(f"tridelphi: {headline}", file=err)
            for line in refused:
                print(f"  {line}", file=err)
            if identity_change:
                print(
                    "  Review every removed and introduced publisher, then replace "
                    "the lock deliberately with `tridelphi verify "
                    "--write-trust-lock --yes`.",
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

    state = _load_lock_state(lock_path, repo_root=root)
    lock = state.entries
    findings = _state_findings(root, refs, lock_path, state)
    findings.extend(_check_against_lock(refs, lock))
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
    warnings = sum(1 for f in findings if f.level == "warning")
    notes = sum(1 for f in findings if f.level == "note")
    print(
        f"L7 trust: {len(refs)} third-party action{'s' if len(refs) != 1 else ''} · "
        f"{errors} error{'s' if errors != 1 else ''}, "
        f"{warnings} warning{'s' if warnings != 1 else ''}, "
        f"{notes} note{'s' if notes != 1 else ''}",
        file=out,
    )
    if not lock and not state.errors:
        print(
            "  no trust-lock yet — run `tridelphi verify --write-trust-lock` to arm the pawl",
            file=out,
        )

    # The shared map covers every SARIF level, so a future `warning`-level
    # trust finding gates correctly instead of raising KeyError.
    if should_fail((SARIF_LEVEL_TO_SEVERITY.get(f.level, "warning") for f in findings), fail_on):
        return 1, document
    return 0, document
