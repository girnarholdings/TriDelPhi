"""P — privilege.

Every hit records whether it was *observed* (written in the file) or *assumed*
(inferred from a repository default we cannot see offline). Only observed
privilege can carry a finding to critical: guessing that a repo grants write and
then declaring the result critical is how a scanner ends up flagging every job it
sees.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from .model import CapabilityHit, ExecutionContext
from .parse import grants_write
from .tables import Tables
from .yamlnode import YamlNode

__all__ = ["detect"]

# Dot form, bracket form with a literal, and bracket form with an expression.
_SECRET_REF = re.compile(
    r"secrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[\s*['\"]([^'\"]+)['\"]\s*\]|\[([^\]]+)\])"
)


def _secret_names(text: str) -> list[str]:
    names = []
    for match in _SECRET_REF.finditer(text or ""):
        name = match.group(1) or match.group(2) or match.group(3)
        if name:
            names.append(name.strip())
    return names


def _walk_scalars(node: YamlNode) -> Iterator[YamlNode]:
    if node is None:
        return
    value = node.value
    if isinstance(value, str):
        yield node
    elif isinstance(value, dict):
        for _, child in node.items():
            yield from _walk_scalars(child)
    elif isinstance(value, (list, tuple)):
        for child in node.seq():
            if child is not node:
                yield from _walk_scalars(child)


def attacker_reachable_privilege(context: ExecutionContext, tables: Tables) -> bool:
    """Can an untrusted party actually reach this job's credentials?

    On a ``pull_request`` run originating in a fork, GitHub withholds repository
    secrets and forces ``GITHUB_TOKEN`` to read-only — regardless of the
    ``permissions:`` block or any repository setting. So a workflow whose only
    untrusted entry point is ``pull_request`` has no attacker-reachable
    privilege, even when it declares write scopes for its ``push`` runs.

    This single predicate is the difference between a usable tool and one that
    emits CRITICAL on every fork-PR CI job on GitHub, GitHub's own recommended
    CodeQL workflow included. It is a platform guarantee, not a heuristic.

    A same-repo branch pull request does receive the declared permissions, but
    its author already has write access and needs no exploit.
    """
    if not context.fork_reachable:
        return True
    privileged = set(tables.tuple_of("triggers", "privileged_untrusted"))
    return bool(set(context.triggers) & privileged)


def _scan_secrets(context: ExecutionContext, tables: Tables) -> Iterator[CapabilityHit]:
    seen: set[str] = set()
    sources = [context.body]
    if context.workflow_env is not None:
        sources.append(context.workflow_env)
    attacker_reachable = attacker_reachable_privilege(context, tables)
    for source in sources:
        for scalar in _walk_scalars(source):
            for name in _secret_names(scalar.text):
                if name == "GITHUB_TOKEN" or name in seen:
                    continue
                seen.add(name)
                scope = "workflow-level `env:`" if source is context.workflow_env else "this job"
                if attacker_reachable:
                    reason = f"`secrets.{name}` is available to {scope}"
                else:
                    reason = (
                        f"`secrets.{name}` is referenced by {scope}, but GitHub withholds "
                        "repository secrets from fork pull requests — reachable only "
                        "from a branch pull request by someone with write access"
                    )
                yield CapabilityHit(
                    capability="P",
                    kind="secret-reference",
                    reason=reason,
                    position=scalar.find_substring(name),
                    observed=attacker_reachable,
                )

    if context.secrets_inherit:
        yield CapabilityHit(
            capability="P",
            kind="secrets-inherit",
            reason=(
                "`secrets: inherit` passes every repository and organisation secret "
                "to the called workflow"
            ),
            position=context.position,
        )


def _scan_permissions(context: ExecutionContext) -> Iterator[CapabilityHit]:
    granted = grants_write(dict(context.effective_permissions))
    if granted is None:
        return
    scope, value = granted
    assumed = context.permissions_source.startswith("assumed")
    if scope == "__all__":
        detail = f"the token holds `{value}` across all scopes"
    elif scope == "__inherited__":
        detail = "the called workflow inherits caller credentials"
    else:
        detail = f"`{scope}: {value}` is granted"

    if assumed:
        reason = (
            f"privilege is ASSUMED, not observed: this job declares no `permissions:` "
            f"block, so we fall back to the repository default and {detail}. Declaring "
            f"`permissions: contents: read` removes the ambiguity and hardens the job"
        )
    elif context.permissions_source == "platform-fork-pr-read-only":
        return
    else:
        reason = f"{detail} ({context.permissions_source}-level `permissions:`)"

    yield CapabilityHit(
        capability="P",
        kind="permissions" if not assumed else "assumed-permissions",
        reason=reason,
        position=context.permissions_position or context.position,
        observed=not assumed,
    )


def _scan_runner(context: ExecutionContext, tables: Tables) -> Iterator[CapabilityHit]:
    """A self-hosted runner is itself the privileged asset.

    Non-ephemeral runners persist between jobs, so untrusted code executing on
    one reaches other jobs' caches, credentials and network position. This is one
    of the highest-severity real Actions findings and it has no natural home in
    a secrets-and-permissions view of privilege.
    """
    hosted = set(tables.tuple_of("triggers", "hosted_runner_labels"))
    labels = [label for label in context.runs_on if not label.startswith("${{")]
    if not labels:
        return
    if any(label in hosted for label in labels):
        return
    # Any concrete label that is not a known hosted-runner label is treated as
    # self-hosted — explicit `self-hosted` and bare custom labels alike.
    node = context.body.get("runs-on")
    yield CapabilityHit(
        capability="P",
        kind="self-hosted-runner",
        reason=(
            f"the job runs on a self-hosted runner (`{', '.join(labels)}`); the "
            "runner itself is the privileged asset, and compromise persists "
            "across jobs"
        ),
        position=node.value_position() if node is not None else context.position,
    )


def _scan_mcp(context: ExecutionContext, tables: Tables) -> Iterator[CapabilityHit]:
    from .detect_agent_ingress import agent_steps

    agents = list(agent_steps(context, tables))
    if not agents:
        return
    for server in context.repo.mcp_servers:
        if not server.write_capable:
            continue
        yield CapabilityHit(
            capability="P",
            kind="mcp-write-tools",
            reason=f"MCP server `{server.name}` is write-capable — {server.detail}",
            position=agents[0].node.position(),
        )


def detect(context: ExecutionContext, tables: Tables) -> list[CapabilityHit]:
    hits: list[CapabilityHit] = []
    hits.extend(_scan_secrets(context, tables))
    hits.extend(_scan_permissions(context))
    hits.extend(_scan_runner(context, tables))
    hits.extend(_scan_mcp(context, tables))
    return sorted(hits, key=lambda h: h.sort_key)
