"""Repo on disk -> ExecutionContext list.

Produces contexts; never judges them. Everything a detector needs that is not
inside a job body — workflow-level ``env:`` and ``permissions:``, the resolved
trigger set, the agent-config inventory, whether the checkout is untrusted — is
resolved here, because the detectors are forbidden from reading files and would
otherwise have no legal way to see it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from .jsonutil import loads_jsonc
from .model import (
    AgentConfigFile,
    Diagnostic,
    ExecutionContext,
    McpServer,
    Position,
    RepoInventory,
)
from .steps import iter_steps, uses_name
from .structure import structure_error
from .tables import Tables
from .yamlnode import YamlNode

__all__ = ["ParseOutcome", "parse_repo"]

_WORKFLOW_SUFFIXES = (".yml", ".yaml")
_MAX_READ_BYTES = 8 * 1024 * 1024
_MAX_WORKFLOW_FILES = 5_000
_MAX_WORKFLOW_ENTRIES = 100_000
_MAX_JOBS_PER_WORKFLOW = 10_000
_MAX_STEPS_PER_JOB = 20_000
_MAX_CONTEXTS = 50_000
_MAX_INVENTORY_ENTRIES = 100_000
_MAX_INVENTORY_FILES = 5_000
_MAX_INVENTORY_BYTES = 32 * 1024 * 1024
_GLOBAL_WALK_SKIP = frozenset(
    {".git", ".hg", ".svn", ".tox", ".venv", "node_modules", "vendor"}
)


class ParseOutcome:
    __slots__ = ("contexts", "diagnostics", "files_scanned", "inventory")

    def __init__(
        self,
        contexts: tuple[ExecutionContext, ...],
        diagnostics: tuple[Diagnostic, ...],
        files_scanned: int,
        inventory: RepoInventory,
    ) -> None:
        self.contexts = contexts
        self.diagnostics = diagnostics
        self.files_scanned = files_scanned
        self.inventory = inventory


def _rel(root: Path, path: Path) -> str:
    """Repo-relative POSIX path. Normalised once, here, so nothing downstream
    leaks a platform separator into SARIF."""
    return path.relative_to(root).as_posix()


def _has_symlink_component(root: Path, path: Path) -> bool:
    """True when any repo-relative component, including ``path``, is a link."""

    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    if current.is_symlink():
        return True
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _read_text(root: Path, path: Path) -> str | None:
    try:
        if _has_symlink_component(root, path) or not path.is_file():
            return None
        if path.stat(follow_symlinks=False).st_size > _MAX_READ_BYTES:
            return None
        return path.read_text("utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# repo inventory
# ---------------------------------------------------------------------------


def _bounded_files(
    root: Path,
    target: Path,
    *,
    filename: str | None = None,
    prune_common: bool = False,
) -> tuple[list[Path], list[Diagnostic]]:
    """Walk a configuration directory without following links or hanging on junk.

    Agent instructions are attacker-controlled input, so discovery itself must
    have the same fail-visible resource limits as file reads. The returned
    diagnostics become ordinary parse findings instead of a silent blind spot.
    """

    diagnostics: list[Diagnostic] = []
    if _has_symlink_component(root, target):
        rel = _rel(root, target)
        return [], [Diagnostic(rel, "configuration path is a symlink and was not followed", "warning")]
    try:
        if not target.is_dir():
            return [], []
    except OSError:
        return [], [Diagnostic(_rel(root, target), "configuration path could not be inspected", "warning")]

    found: list[Path] = []
    entries_seen = 0
    stack = [target]
    unreadable_reported = False
    while stack:
        current = stack.pop()
        try:
            entries: list[Path] = []
            for entry in current.iterdir():
                entries_seen += 1
                if entries_seen > _MAX_INVENTORY_ENTRIES:
                    diagnostics.append(
                        Diagnostic(
                            _rel(root, target),
                            f"configuration discovery exceeded {_MAX_INVENTORY_ENTRIES} entries and was capped",
                            "warning",
                        )
                    )
                    return found, diagnostics
                entries.append(entry)
            entries.sort(key=lambda path: path.name)
        except OSError:
            if not unreadable_reported:
                diagnostics.append(
                    Diagnostic(
                        _rel(root, target),
                        "part of the configuration tree could not be inspected",
                        "warning",
                    )
                )
                unreadable_reported = True
            continue

        directories: list[Path] = []
        for entry in entries:
            if entry.is_symlink():
                if filename is None or entry.name == filename:
                    found.append(entry)  # caller reports the refused link
            elif entry.is_dir():
                if not prune_common or entry.name not in _GLOBAL_WALK_SKIP:
                    directories.append(entry)
            elif entry.is_file() and (filename is None or entry.name == filename):
                found.append(entry)
            if len(found) > _MAX_INVENTORY_FILES:
                diagnostics.append(
                    Diagnostic(
                        _rel(root, target),
                        f"configuration discovery found more than {_MAX_INVENTORY_FILES} files and was capped",
                        "warning",
                    )
                )
                return found[:_MAX_INVENTORY_FILES], diagnostics
        stack.extend(reversed(directories))
    return found, diagnostics


def _collect_agent_configs(
    root: Path, tables: Tables
) -> tuple[tuple[AgentConfigFile, ...], tuple[Diagnostic, ...]]:
    found: list[AgentConfigFile] = []
    diagnostics: list[Diagnostic] = []
    loaded_bytes = 0

    def add(path: Path, kind: str) -> bool:
        nonlocal loaded_bytes
        if _has_symlink_component(root, path):
            diagnostics.append(
                Diagnostic(_rel(root, path), "agent instruction file is a symlink and was not read", "warning")
            )
            return True
        try:
            size = path.stat(follow_symlinks=False).st_size
        except OSError:
            diagnostics.append(
                Diagnostic(_rel(root, path), "agent instruction file could not be inspected", "warning")
            )
            return True
        if size > _MAX_READ_BYTES:
            diagnostics.append(
                Diagnostic(_rel(root, path), "agent instruction file exceeds the 8 MiB safety limit", "warning")
            )
            return True
        if loaded_bytes + size > _MAX_INVENTORY_BYTES:
            diagnostics.append(
                Diagnostic(
                    _rel(root, path),
                    "agent instruction inventory exceeded the 32 MiB total safety limit",
                    "warning",
                )
            )
            return False
        text = _read_text(root, path)
        if text is None:
            diagnostics.append(
                Diagnostic(_rel(root, path), "agent instruction file could not be read", "warning")
            )
            return True
        loaded_bytes += size
        found.append(AgentConfigFile(_rel(root, path), kind, text))
        return True

    groups = tables.section("agent_signals", "instruction_files", {}) or {}
    capacity = True
    for kind in sorted(groups):
        for rel in groups[kind]:
            target = root / rel
            if target.is_symlink():
                capacity = add(target, kind) and capacity
            elif target.is_dir():
                children, issues = _bounded_files(root, target)
                diagnostics.extend(issues)
                for child in children:
                    if not add(child, kind):
                        capacity = False
                        break
            elif target.is_file() and not add(target, kind):
                capacity = False
            if not capacity:
                break
        if not capacity:
            break
    # Claude Code reads CLAUDE.md hierarchically, so nested copies matter too.
    nested_files, issues = _bounded_files(root, root, filename="CLAUDE.md", prune_common=True)
    diagnostics.extend(issues)
    for nested in nested_files:
        rel = _rel(root, nested)
        if rel != "CLAUDE.md" and ".git/" not in rel and not add(nested, "claude_md"):
            break
    unique = {(item.path, item.kind): item for item in found}
    return (
        tuple(sorted(unique.values(), key=lambda c: (c.path, c.kind))),
        tuple(diagnostics),
    )


def _collect_hook_configs(
    root: Path, tables: Tables
) -> tuple[tuple[AgentConfigFile, ...], tuple[Diagnostic, ...]]:
    hook_keys = tables.tuple_of("agent_signals", "hook_keys")
    found: list[AgentConfigFile] = []
    diagnostics: list[Diagnostic] = []
    loaded_bytes = 0
    for rel in tables.tuple_of("agent_signals", "hook_files"):
        target = root / rel
        candidates: Iterable[Path]
        if _has_symlink_component(root, target):
            diagnostics.append(
                Diagnostic(_rel(root, target), "agent hook path is a symlink and was not read", "warning")
            )
            continue
        if target.is_dir():
            walked, issues = _bounded_files(root, target)
            diagnostics.extend(issues)
            candidates = walked
        elif target.is_file():
            candidates = (target,)
        else:
            continue
        for path in candidates:
            if _has_symlink_component(root, path):
                diagnostics.append(
                    Diagnostic(_rel(root, path), "agent hook file is a symlink and was not read", "warning")
                )
                continue
            try:
                size = path.stat(follow_symlinks=False).st_size
            except OSError:
                diagnostics.append(
                    Diagnostic(_rel(root, path), "agent hook file could not be inspected", "warning")
                )
                continue
            if size > _MAX_READ_BYTES:
                diagnostics.append(
                    Diagnostic(_rel(root, path), "agent hook file exceeds the 8 MiB safety limit", "warning")
                )
                continue
            if loaded_bytes + size > _MAX_INVENTORY_BYTES:
                diagnostics.append(
                    Diagnostic(
                        _rel(root, path),
                        "agent hook inventory exceeded the 32 MiB total safety limit",
                        "warning",
                    )
                )
                return tuple(sorted(found, key=lambda c: c.path)), tuple(diagnostics)
            text = _read_text(root, path)
            if text is None:
                diagnostics.append(
                    Diagnostic(_rel(root, path), "agent hook file could not be read", "warning")
                )
                continue
            loaded_bytes += size
            if any(k in text for k in hook_keys) or path.parent.name == ".husky":
                found.append(AgentConfigFile(_rel(root, path), "hook", text))
    return tuple(sorted(found, key=lambda c: c.path)), tuple(diagnostics)


def _collect_mcp(root: Path, tables: Tables) -> tuple[tuple[McpServer, ...], tuple[str, ...]]:
    markers = tables.tuple_of("agent_signals", "mcp_write_markers")
    servers: list[McpServer] = []
    unknown: list[str] = []
    for rel in tables.tuple_of("agent_signals", "mcp_files"):
        path = root / rel
        if _has_symlink_component(root, path):
            unknown.append(_rel(root, path))
            continue
        if not path.is_file():
            continue
        text = _read_text(root, path)
        if text is None:
            unknown.append(_rel(root, path))
            continue
        try:
            doc = loads_jsonc(text)
        except (ValueError, TypeError, RecursionError):
            unknown.append(_rel(root, path))
            continue
        if structure_error(doc, max_nodes=100_000, max_collection_items=20_000) or not isinstance(doc, dict):
            unknown.append(_rel(root, path))
            continue
        block = doc.get("mcpServers") or doc.get("servers") or {}
        if not isinstance(block, dict):
            unknown.append(_rel(root, path))
            continue
        for name in sorted(block):
            if not isinstance(block[name], dict):
                unknown.append(_rel(root, path))
                continue
            spec = block[name]
            remote = bool(spec.get("url") or spec.get("type") in {"http", "sse"})
            try:
                blob = json.dumps(spec).lower()
            except (TypeError, ValueError, RecursionError):
                unknown.append(_rel(root, path))
                continue
            write_capable = remote or any(m in blob for m in markers)
            detail = (
                "remote server; its tool set cannot be enumerated offline, so it is "
                "treated as write-capable and as a source of untrusted content"
                if remote
                else "declares tools whose names imply state change"
            )
            servers.append(McpServer(name, _rel(root, path), remote, write_capable, detail))
    return tuple(servers), tuple(sorted(set(unknown)))


def _collect_codeowners(root: Path) -> tuple[str, ...]:
    for rel in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        path = root / rel
        if path.is_file():
            text = _read_text(root, path) or ""
            patterns = []
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line.split()[0])
            return tuple(patterns)
    return ()


def build_inventory(root: Path, tables: Tables) -> tuple[RepoInventory, tuple[Diagnostic, ...]]:
    mcp_servers, unknown_config_paths = _collect_mcp(root, tables)
    agent_configs, agent_diagnostics = _collect_agent_configs(root, tables)
    hook_configs, hook_diagnostics = _collect_hook_configs(root, tables)
    return (
        RepoInventory(
            root=str(root),
            agent_configs=agent_configs,
            mcp_servers=mcp_servers,
            hook_configs=hook_configs,
            codeowners_paths=_collect_codeowners(root),
            unknown_config_paths=unknown_config_paths,
        ),
        (*agent_diagnostics, *hook_diagnostics),
    )


# ---------------------------------------------------------------------------
# workflow parsing
# ---------------------------------------------------------------------------


def _resolve_triggers(on_node: YamlNode | None) -> tuple[str, ...]:
    """``on:`` is a string, a list, or a mapping. All three shapes appear in the
    wild and the U detector must not re-derive this."""
    if on_node is None:
        return ()
    value = on_node.value
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(sorted(str(v) for v in value if isinstance(v, str)))
    if isinstance(value, dict):
        return tuple(sorted(str(k) for k in value))
    return ()


def _fork_reachable(triggers: tuple[str, ...], on_node: YamlNode | None, tables: Tables) -> bool:
    reachable = set(tables.tuple_of("triggers", "fork_reachable"))
    fork_types = set(tables.tuple_of("triggers", "fork_pr_types"))
    for trigger in triggers:
        if trigger not in reachable:
            continue
        if trigger in {"pull_request", "pull_request_target"} and on_node is not None:
            spec = on_node.get(trigger)
            if spec is not None and spec.is_mapping():
                types_node = spec.get("types")
                if types_node is not None and types_node.value:
                    declared = {str(t.value) for t in types_node.seq()}
                    if not (declared & fork_types):
                        continue
        return True
    return False


_PERMISSION_SCOPES_WRITE = {"write", "write-all"}


def _permissions_map(node: YamlNode | None) -> dict[str, str] | None:
    if node is None:
        return None
    value = node.value
    if isinstance(value, str):
        if value == "write-all":
            return {"__all__": "write"}
        if value in {"read-all", "none"}:
            return {"__all__": "read"}
        return {"__all__": value}
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return None


def _effective_permissions(
    job: YamlNode,
    workflow: YamlNode,
    triggers: tuple[str, ...],
    tables: Tables,
    assume_default: str,
) -> tuple[dict[str, str], str, Position | None]:
    """job -> workflow -> repo default, with the platform override applied.

    A fork ``pull_request`` run receives a read-only token and no repository
    secrets regardless of repository configuration. That is a platform
    guarantee, not an assumption, and skipping it is what makes a scanner emit
    critical findings on every fork-PR CI job in existence.
    """
    job_perms = job.get("permissions")
    resolved = _permissions_map(job_perms)
    if resolved is not None:
        return resolved, "job", job_perms.position() if job_perms else None

    wf_perms = workflow.get("permissions")
    resolved = _permissions_map(wf_perms)
    if resolved is not None:
        return resolved, "workflow", wf_perms.position() if wf_perms else None

    privileged = set(tables.tuple_of("triggers", "privileged_untrusted"))
    if triggers and not (set(triggers) & privileged) and set(triggers) <= {"pull_request"}:
        return {"__all__": "read"}, "platform-fork-pr-read-only", None

    source = "assumed-default-write" if assume_default == "write" else "assumed-default-read"
    return {"__all__": assume_default}, source, None


def grants_write(permissions: dict[str, str]) -> tuple[str, str] | None:
    for scope in sorted(permissions):
        value = permissions[scope]
        if value in _PERMISSION_SCOPES_WRITE:
            return scope, value
        if scope == "id-token" and value == "write":
            return scope, value
    return None


_CHECKOUT_ACTIONS = ("actions/checkout",)

# A `run:` step can pull the pull request's own code into the tree without using
# `actions/checkout` at all — `gh pr checkout N`, or `git fetch origin
# pull/N/head` then a checkout. On a privileged trigger (pull_request_target /
# workflow_run / issue_comment) the default `actions/checkout` resolves to the
# safe base branch, so a job that then does this in a shell step silently
# re-introduces the attacker's tree that the safe-default logic assumed absent.
# These markers are deliberately specific to keep false positives near zero.
_PR_CHECKOUT_CLI = ("gh pr checkout", "hub pr checkout")
# A git command that fetches, and a PR head/merge refspec. Kept as two separate
# linear searches (no nested `.*?`) so a long hostile `run:` block cannot cause
# catastrophic backtracking. The refspec — `pull/<n>/head` or `.../merge`, the
# `<n>` possibly a `${{ … }}` expression with spaces — is what makes it a PR
# checkout rather than an ordinary `git pull origin main`.
_GIT_FETCH_RE = re.compile(r"git\s+(?:fetch|pull)\b", re.IGNORECASE)
_PR_REFSPEC_RE = re.compile(r"(?:refs/)?pull/[^\n]*?/(?:head|merge)\b", re.IGNORECASE)


def _run_fetches_pull_request(run_text: str) -> bool:
    """Does this shell command pull the PR's own code into the working tree?"""
    if not run_text:
        return False
    if any(cli in run_text for cli in _PR_CHECKOUT_CLI):
        return True
    return bool(_GIT_FETCH_RE.search(run_text) and _PR_REFSPEC_RE.search(run_text))


def _job_skips_fork_pull_requests(job: YamlNode) -> bool:
    """Does the job refuse fork pull requests before acting on their code?

    A job that checks ``isCrossRepository`` and skips forks (the pattern our own
    fix bot uses, and the one we recommend) only ever fetches *same-repo* PR
    branches — code authored by someone who already has write access, i.e. not
    untrusted. Because the workflow file itself is trusted (it runs from the base
    branch, which an attacker's PR cannot modify), a fork-guard expressed in it
    is a signal we can rely on — the same reasoning under
    ``has_strong_association_gate``.
    """
    for step in iter_steps(job):
        run_node = step.get("run")
        if run_node is not None and "isCrossRepository" in (run_node.text or ""):
            return True
    return False


def _resolve_untrusted_worktree(
    job: YamlNode, triggers: tuple[str, ...], fork_reachable: bool, tables: Tables
) -> tuple[bool, str]:
    """Does this job's working tree contain code chosen by an untrusted party?

    This is the field the whole agent-ingress finding turns on, and getting its
    direction right is the difference between flagging the exploit and flagging
    the recommended mitigation. ``actions/checkout`` with no ``ref:`` resolves to
    the base branch under ``pull_request_target`` and to the default branch under
    ``workflow_run`` — both safe. Under ``pull_request`` the default checkout is
    the PR merge ref, which is attacker code.
    """
    untrusted_refs = tables.tuple_of("untrusted_expressions", "untrusted_refs")

    # A shell step that fetches the PR's own code makes the tree untrusted no
    # matter how actions/checkout resolved — so this takes precedence over the
    # checkout-ref logic below (which would otherwise read the base checkout as
    # safe and stop). This is the pwn-request shape that hides in a `run:` block.
    # Exception: a job that first refuses fork pull requests only ever fetches
    # same-repo (write-access-authored) branches, which are not untrusted.
    if not _job_skips_fork_pull_requests(job):
        for step in iter_steps(job):
            run_node = step.get("run")
            if run_node is not None and _run_fetches_pull_request(run_node.text or ""):
                return True, "a run step fetches the pull request's own code into the tree"

    for step in iter_steps(job):
        name = uses_name(step)
        if not any(name == c or name.startswith(c) for c in _CHECKOUT_ACTIONS):
            continue
        with_node = step.get("with")
        ref_node = with_node.get("ref") if with_node is not None else None
        ref_text = ref_node.text if ref_node is not None else ""
        if ref_text:
            if any(marker in ref_text for marker in untrusted_refs):
                return True, f"checkout resolves to `{ref_text.strip()}`"
            # A safe checkout does not make later checkouts safe. Keep walking:
            # a common workflow checks out the base branch first, then replaces
            # it with attacker-controlled PR code in a later step.
            continue
        if "pull_request" in triggers:
            return True, "checkout of the pull request merge ref on `pull_request`"
        # pull_request_target / workflow_run default to base, which is the
        # documented safe configuration.
        continue
    # No checkout (or only safe checkouts): the runner never receives
    # attacker-chosen code through this path.
    return False, ""


def _job_needs(job: YamlNode) -> tuple[str, ...]:
    node = job.get("needs")
    if node is None:
        return ()
    if isinstance(node.value, str):
        return (node.value,)
    if isinstance(node.value, (list, tuple)):
        return tuple(str(v) for v in node.value)
    return ()


def _runs_on(job: YamlNode) -> tuple[str, ...]:
    node = job.get("runs-on")
    if node is None:
        return ()
    if isinstance(node.value, str):
        return (node.value,)
    if isinstance(node.value, (list, tuple)):
        return tuple(str(v) for v in node.value)
    if isinstance(node.value, dict):
        labels = node.value.get("labels")
        if isinstance(labels, str):
            return (labels,)
        if isinstance(labels, (list, tuple)):
            return tuple(str(v) for v in labels)
        group = node.value.get("group")
        return (str(group),) if group else ()
    return ()


def _semantic_unknowns(job: YamlNode) -> tuple[str, ...]:
    """GitHub features whose effective security state requires runtime settings.

    The static model stays conservative, but the report must distinguish an
    observed-safe fact from a value we could not resolve offline.
    """

    unknowns: list[str] = []
    needs = job.get("needs")
    if needs is not None and any("${{" in text for text in _node_scalar_texts(needs)):
        unknowns.append("dynamic `needs` dependencies")
    runs_on = job.get("runs-on")
    if runs_on is not None and any("${{" in text for text in _node_scalar_texts(runs_on)):
        unknowns.append("dynamic `runs-on` labels")
    strategy = job.get("strategy")
    if strategy is not None and strategy.is_mapping() and strategy.get("matrix") is not None:
        unknowns.append("matrix legs are analyzed as one conservative job definition")
    environment = job.get("environment")
    if environment is not None:
        unknowns.append("environment approvals and secret rules live in repository settings")
    checkout_refs = []
    for step in iter_steps(job):
        if not uses_name(step).startswith("actions/checkout"):
            continue
        with_node = step.get("with")
        ref = with_node.get("ref") if with_node is not None else None
        if ref is not None and "${{" in ref.text:
            checkout_refs.append(ref.text)
    if any(
        not any(marker in ref for marker in ("github.event.pull_request", "github.event.workflow_run"))
        for ref in checkout_refs
    ):
        unknowns.append("a dynamic checkout ref is not one of TriDelPhi's modeled event refs")
    return tuple(unknowns)


_PERMISSION_RANK = {"none": 0, "read": 1, "write": 2}


def _permission_value(permissions: dict[str, str], scope: str) -> str:
    if scope in permissions:
        return permissions[scope]
    if "__all__" in permissions:
        return permissions["__all__"]
    return "none"


def _intersect_permissions(
    caller: ExecutionContext, callee: ExecutionContext
) -> tuple[dict[str, str], str, Position | None]:
    """Apply GitHub's reusable-workflow rule: permissions can only decrease."""

    # No callee declaration means the caller's token reaches the callee as-is;
    # the called workflow does not get a fresh repository-default grant.
    if callee.permissions_source.startswith("assumed"):
        return (
            dict(caller.effective_permissions),
            caller.permissions_source,
            caller.permissions_position,
        )

    left = dict(caller.effective_permissions)
    right = dict(callee.effective_permissions)
    scopes = (set(left) | set(right)) - {"__all__"}
    if not scopes and "__all__" in left and "__all__" in right:
        scopes = {"__all__"}
    merged: dict[str, str] = {}
    for scope in sorted(scopes):
        caller_value = _permission_value(left, scope)
        callee_value = _permission_value(right, scope)
        caller_rank = _PERMISSION_RANK.get(caller_value, 0)
        callee_rank = _PERMISSION_RANK.get(callee_value, 0)
        rank = min(caller_rank, callee_rank)
        if rank:
            merged[scope] = "write" if rank == 2 else "read"
    assumed = caller.permissions_source.startswith("assumed")
    source = (
        f"assumed-caller-capped-by-{callee.permissions_source}"
        if assumed
        else f"caller-capped-by-{callee.permissions_source}"
    )
    return merged, source, callee.permissions_position or caller.permissions_position


def _node_scalar_texts(node: YamlNode):
    if isinstance(node.value, str):
        yield node.value
    elif isinstance(node.value, dict):
        for _, child in node.items():
            yield from _node_scalar_texts(child)
    elif isinstance(node.value, (list, tuple)):
        for child in node.seq():
            yield from _node_scalar_texts(child)


def _discover_workflows(root: Path) -> list[Path]:
    wf_dir = root / ".github" / "workflows"
    if wf_dir.is_symlink() or not wf_dir.is_dir():
        return []
    # Filesystem order is not sorted; determinism requires an explicit sort on
    # the normalised relative path. Bound the directory *before* collecting it:
    # a checkout can contain millions of irrelevant names beside one workflow.
    discovered: list[Path] = []
    for index, path in enumerate(wf_dir.iterdir(), start=1):
        if index > _MAX_WORKFLOW_ENTRIES:
            raise OSError(
                f"workflow discovery exceeded {_MAX_WORKFLOW_ENTRIES} directory entries"
            )
        if (path.is_symlink() or path.is_file()) and path.suffix in _WORKFLOW_SUFFIXES:
            discovered.append(path)
            if len(discovered) > _MAX_WORKFLOW_FILES:
                break
    return sorted(discovered, key=lambda p: p.relative_to(root).as_posix())


def parse_repo(
    root: Path,
    tables: Tables,
    *,
    assume_default_permissions: str = "write",
) -> ParseOutcome:
    inventory, inventory_diagnostics = build_inventory(root, tables)
    contexts: list[ExecutionContext] = []
    diagnostics: list[Diagnostic] = list(inventory_diagnostics)
    workflow_dir = root / ".github" / "workflows"
    if (root / ".github").is_symlink() or workflow_dir.is_symlink():
        diagnostics.append(
            Diagnostic(
                ".github/workflows",
                "workflow directory is symlinked and was not followed",
                "warning",
            )
        )
        files = []
    else:
        try:
            discovered = _discover_workflows(root)
        except OSError as exc:
            detail = str(exc).strip()
            diagnostics.append(
                Diagnostic(
                    ".github/workflows",
                    detail or "workflow directory could not be enumerated",
                    "warning",
                )
            )
            discovered = []
        files = discovered[:_MAX_WORKFLOW_FILES]
        if len(discovered) > _MAX_WORKFLOW_FILES:
            diagnostics.append(
                Diagnostic(
                    ".github/workflows",
                    f"more than {_MAX_WORKFLOW_FILES} workflow files; scan capped",
                    "warning",
                )
            )

    for path in files:
        if len(contexts) >= _MAX_CONTEXTS:
            diagnostics.append(
                Diagnostic(
                    ".github/workflows",
                    f"repository job limit {_MAX_CONTEXTS:,} reached; remaining workflows not scanned",
                    "warning",
                )
            )
            break
        rel = _rel(root, path)
        source = _read_text(root, path)
        if source is None:
            diagnostics.append(Diagnostic(rel, "file could not be read", "warning"))
            continue
        yaml = YAML(typ="rt")
        try:
            doc = yaml.load(source)
        except YAMLError as exc:
            first = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
            diagnostics.append(Diagnostic(rel, f"YAML parse error: {first}", "warning"))
            continue
        except Exception as exc:  # defensive: a malformed file must never abort the scan
            diagnostics.append(Diagnostic(rel, f"unreadable workflow: {exc.__class__.__name__}", "warning"))
            continue

        if defect := structure_error(doc):
            diagnostics.append(Diagnostic(rel, f"workflow structure refused: {defect}", "warning"))
            continue

        if not isinstance(doc, dict):
            diagnostics.append(Diagnostic(rel, "not a workflow mapping", "warning"))
            continue

        workflow = YamlNode.root(doc, rel, source)
        on_node = workflow.get("on") or workflow.get(True)
        triggers = _resolve_triggers(on_node)
        fork = _fork_reachable(triggers, on_node, tables)
        jobs_node = workflow.get("jobs")
        if jobs_node is None or not jobs_node.is_mapping():
            diagnostics.append(Diagnostic(rel, "no jobs mapping", "warning"))
            continue
        if len(jobs_node.value) > _MAX_JOBS_PER_WORKFLOW:
            diagnostics.append(
                Diagnostic(
                    rel,
                    f"workflow has more than {_MAX_JOBS_PER_WORKFLOW:,} jobs; scan refused",
                    "warning",
                )
            )
            continue

        wf_env = workflow.get("env")

        for job_id, job in jobs_node.items():
            steps = job.get("steps") if job.is_mapping() else None
            if steps is not None and isinstance(steps.value, (list, tuple)) and len(steps.value) > _MAX_STEPS_PER_JOB:
                diagnostics.append(
                    Diagnostic(
                        rel,
                        f"job `{job_id}` has more than {_MAX_STEPS_PER_JOB:,} steps; job refused",
                        "warning",
                    )
                )
                continue
            if len(contexts) >= _MAX_CONTEXTS:
                diagnostics.append(
                    Diagnostic(
                        ".github/workflows",
                        f"repository has more than {_MAX_CONTEXTS:,} jobs; scan capped",
                        "warning",
                    )
                )
                break
            if job.value is None:
                job = YamlNode(
                    {}, rel, tuple(source.splitlines()), parent=jobs_node.value, key=job_id
                )
            perms, perms_source, perms_pos = _effective_permissions(
                job, workflow, triggers, tables, assume_default_permissions
            )
            reusable = job.get("uses")
            untrusted, reason = _resolve_untrusted_worktree(job, triggers, fork, tables)
            secrets_node = job.get("secrets")
            secrets_inherit = bool(
                secrets_node is not None and str(secrets_node.value).strip() == "inherit"
            )
            if_node = job.get("if")
            contexts.append(
                ExecutionContext(
                    workflow_file=rel,
                    job_id=str(job_id),
                    position=job.position(),
                    triggers=triggers,
                    fork_reachable=fork,
                    effective_permissions=perms,
                    permissions_source=perms_source,
                    permissions_position=perms_pos,
                    repo=inventory,
                    body=job,
                    workflow_env=wf_env,
                    needs=_job_needs(job),
                    runs_on=_runs_on(job),
                    job_if=if_node.text if if_node is not None else None,
                    is_reusable_call=reusable is not None,
                    secrets_inherit=secrets_inherit,
                    called_workflow=reusable.text if reusable is not None else None,
                    untrusted_worktree=untrusted,
                    untrusted_worktree_reason=reason,
                    semantic_unknowns=_semantic_unknowns(job),
                )
            )

    contexts = _inline_local_reusable(contexts, root, tables, diagnostics)
    return ParseOutcome(
        tuple(contexts), tuple(sorted(diagnostics, key=lambda d: d.sort_key)), len(files), inventory
    )


def _inline_local_reusable(
    contexts: list[ExecutionContext],
    root: Path,
    tables: Tables,
    diagnostics: list[Diagnostic],
) -> list[ExecutionContext]:
    """Fold local reusable workflows into their caller.

    A caller job has no ``steps:`` at all, so its egress and privilege live
    entirely in the callee. The callee's own trigger is ``workflow_call``, which
    looks trusted in isolation. Read separately both are clean; the chain is not.
    """
    by_file: dict[str, list[ExecutionContext]] = {}
    for ctx in contexts:
        by_file.setdefault(ctx.workflow_file, []).append(ctx)

    result: list[ExecutionContext] = []
    for ctx in contexts:
        if len(result) >= _MAX_CONTEXTS:
            diagnostics.append(
                Diagnostic(
                    ".github/workflows",
                    f"reusable-workflow expansion exceeded {_MAX_CONTEXTS:,} jobs; scan capped",
                    "warning",
                )
            )
            break
        if not ctx.is_reusable_call or not ctx.called_workflow:
            result.append(ctx)
            continue
        target = ctx.called_workflow.strip()
        if not target.startswith("./"):
            result.append(ctx)
            continue
        callee_rel = target[2:]
        callees = by_file.get(callee_rel)
        if not callees:
            result.append(ctx)
            continue
        for callee in callees:
            if len(result) >= _MAX_CONTEXTS:
                diagnostics.append(
                    Diagnostic(
                        ctx.workflow_file,
                        f"reusable-workflow expansion exceeded {_MAX_CONTEXTS:,} jobs; scan capped",
                        "warning",
                    )
                )
                break
            merged_perms, merged_source, merged_position = _intersect_permissions(ctx, callee)
            if ctx.secrets_inherit:
                merged_perms.setdefault("__inherited__", "write")
            result.append(
                ExecutionContext(
                    workflow_file=ctx.workflow_file,
                    job_id=f"{ctx.job_id} -> {callee_rel}::{callee.job_id}",
                    position=ctx.position,
                    triggers=ctx.triggers,
                    fork_reachable=ctx.fork_reachable,
                    effective_permissions=merged_perms,
                    permissions_source=merged_source,
                    permissions_position=merged_position,
                    repo=ctx.repo,
                    body=callee.body,
                    workflow_env=callee.workflow_env,
                    needs=ctx.needs,
                    runs_on=callee.runs_on,
                    job_if=ctx.job_if,
                    is_reusable_call=False,
                    secrets_inherit=ctx.secrets_inherit,
                    called_workflow=callee_rel,
                    untrusted_worktree=callee.untrusted_worktree or ctx.untrusted_worktree,
                    untrusted_worktree_reason=callee.untrusted_worktree_reason
                    or ctx.untrusted_worktree_reason,
                    semantic_unknowns=tuple(sorted(set(ctx.semantic_unknowns + callee.semantic_unknowns))),
                )
            )
        if len(result) < _MAX_CONTEXTS:
            result.append(ctx)
        else:
            diagnostics.append(
                Diagnostic(
                    ctx.workflow_file,
                    f"reusable-workflow expansion exceeded {_MAX_CONTEXTS:,} jobs; scan capped",
                    "warning",
                )
            )
            break
    return result
