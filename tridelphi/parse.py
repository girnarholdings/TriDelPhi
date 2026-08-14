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

from .model import (
    AgentConfigFile,
    Diagnostic,
    ExecutionContext,
    McpServer,
    Position,
    RepoInventory,
)
from .tables import Tables
from .yamlnode import YamlNode

__all__ = ["ParseOutcome", "parse_repo"]

_WORKFLOW_SUFFIXES = (".yml", ".yaml")


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


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text("utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# repo inventory
# ---------------------------------------------------------------------------


def _collect_agent_configs(root: Path, tables: Tables) -> tuple[AgentConfigFile, ...]:
    found: list[AgentConfigFile] = []
    groups = tables.section("agent_signals", "instruction_files", {}) or {}
    for kind in sorted(groups):
        for rel in groups[kind]:
            target = root / rel
            if target.is_dir():
                for child in sorted(target.rglob("*")):
                    if child.is_file():
                        text = _read_text(child)
                        if text is not None:
                            found.append(AgentConfigFile(_rel(root, child), kind, text))
            elif target.is_file():
                text = _read_text(target)
                if text is not None:
                    found.append(AgentConfigFile(_rel(root, target), kind, text))
    # Claude Code reads CLAUDE.md hierarchically, so nested copies matter too.
    for nested in sorted(root.rglob("CLAUDE.md")):
        rel = _rel(root, nested)
        if rel != "CLAUDE.md" and ".git/" not in rel:
            text = _read_text(nested)
            if text is not None:
                found.append(AgentConfigFile(rel, "claude_md", text))
    return tuple(sorted(found, key=lambda c: c.path))


def _collect_hook_configs(root: Path, tables: Tables) -> tuple[AgentConfigFile, ...]:
    hook_keys = tables.tuple_of("agent_signals", "hook_keys")
    found: list[AgentConfigFile] = []
    for rel in tables.tuple_of("agent_signals", "hook_files"):
        target = root / rel
        candidates: Iterable[Path]
        if target.is_dir():
            candidates = (p for p in sorted(target.rglob("*")) if p.is_file())
        elif target.is_file():
            candidates = (target,)
        else:
            continue
        for path in candidates:
            text = _read_text(path)
            if text is None:
                continue
            if any(k in text for k in hook_keys) or path.parent.name == ".husky":
                found.append(AgentConfigFile(_rel(root, path), "hook", text))
    return tuple(sorted(found, key=lambda c: c.path))


def _collect_mcp(root: Path, tables: Tables) -> tuple[McpServer, ...]:
    markers = tables.tuple_of("agent_signals", "mcp_write_markers")
    servers: list[McpServer] = []
    for rel in tables.tuple_of("agent_signals", "mcp_files"):
        path = root / rel
        if not path.is_file():
            continue
        text = _read_text(path)
        if text is None:
            continue
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            continue
        block = doc.get("mcpServers") or doc.get("servers") or {}
        if not isinstance(block, dict):
            continue
        for name in sorted(block):
            spec = block[name] if isinstance(block[name], dict) else {}
            remote = bool(spec.get("url") or spec.get("type") in {"http", "sse"})
            blob = json.dumps(spec).lower()
            write_capable = remote or any(m in blob for m in markers)
            detail = (
                "remote server; its tool set cannot be enumerated offline, so it is "
                "treated as write-capable and as a source of untrusted content"
                if remote
                else "declares tools whose names imply state change"
            )
            servers.append(McpServer(name, _rel(root, path), remote, write_capable, detail))
    return tuple(servers)


def _collect_codeowners(root: Path) -> tuple[str, ...]:
    for rel in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        path = root / rel
        if path.is_file():
            text = _read_text(path) or ""
            patterns = []
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line.split()[0])
            return tuple(patterns)
    return ()


def build_inventory(root: Path, tables: Tables) -> RepoInventory:
    return RepoInventory(
        root=str(root),
        agent_configs=_collect_agent_configs(root, tables),
        mcp_servers=_collect_mcp(root, tables),
        hook_configs=_collect_hook_configs(root, tables),
        codeowners_paths=_collect_codeowners(root),
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
    steps = job.get("steps")
    if steps is None:
        return False
    for step in steps.seq():
        run_node = step.get("run")
        if run_node is not None and "isCrossRepository" in (run_node.text or ""):
            return True
    return False


def _uses_name(step: YamlNode) -> str:
    uses = step.get("uses")
    if uses is None:
        return ""
    text = uses.text
    return text.split("@", 1)[0].strip()


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
    steps = job.get("steps")
    if steps is None:
        return False, ""

    # A shell step that fetches the PR's own code makes the tree untrusted no
    # matter how actions/checkout resolved — so this takes precedence over the
    # checkout-ref logic below (which would otherwise read the base checkout as
    # safe and stop). This is the pwn-request shape that hides in a `run:` block.
    # Exception: a job that first refuses fork pull requests only ever fetches
    # same-repo (write-access-authored) branches, which are not untrusted.
    if not _job_skips_fork_pull_requests(job):
        for step in steps.seq():
            run_node = step.get("run")
            if run_node is not None and _run_fetches_pull_request(run_node.text or ""):
                return True, "a run step fetches the pull request's own code into the tree"

    for step in steps.seq():
        name = _uses_name(step)
        if not any(name == c or name.startswith(c) for c in _CHECKOUT_ACTIONS):
            continue
        with_node = step.get("with")
        ref_node = with_node.get("ref") if with_node is not None else None
        ref_text = ref_node.text if ref_node is not None else ""
        if ref_text:
            if any(marker in ref_text for marker in untrusted_refs):
                return True, f"checkout resolves to `{ref_text.strip()}`"
            return False, ""
        if "pull_request" in triggers:
            return True, "checkout of the pull request merge ref on `pull_request`"
        # pull_request_target / workflow_run default to base, which is the
        # documented safe configuration.
        return False, ""

    if fork_reachable and "pull_request" in triggers:
        return False, ""
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


def _discover_workflows(root: Path) -> list[Path]:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    # Filesystem order is not sorted; determinism requires an explicit sort on
    # the normalised relative path.
    return sorted(
        (p for p in wf_dir.iterdir() if p.is_file() and p.suffix in _WORKFLOW_SUFFIXES),
        key=lambda p: p.relative_to(root).as_posix(),
    )


def parse_repo(
    root: Path,
    tables: Tables,
    *,
    assume_default_permissions: str = "write",
) -> ParseOutcome:
    inventory = build_inventory(root, tables)
    contexts: list[ExecutionContext] = []
    diagnostics: list[Diagnostic] = []
    files = _discover_workflows(root)

    for path in files:
        rel = _rel(root, path)
        source = _read_text(path)
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

        wf_env = workflow.get("env")

        for job_id, job in jobs_node.items():
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
            merged_perms = dict(callee.effective_permissions)
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
                    permissions_source=callee.permissions_source,
                    permissions_position=callee.permissions_position,
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
                )
            )
        result.append(ctx)
    return result
