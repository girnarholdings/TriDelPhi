"""U via an AI agent — the finding class that justifies the tool.

The claim is *reachability*, not filenames: an agent-invoking step executing over
a working tree derived from an untrusted ref is an untrusted-ingress path, and it
stays one whether or not a known instruction filename is present. The dominant
real attack has no agent-config file in it at all — the injection is a comment in
a source file the agent was asked to review.

What makes this hard to copy, and what has to be maintained, is the restore
table: each agent action neutralises a different set of paths. ``claude-code-action``
restores eight paths from base, so a ``CLAUDE.md`` finding against it is a false
positive while an ``AGENTS.md`` finding against it is real. Getting that
distinction right is the whole difference between this and a filename grep.
"""

from __future__ import annotations

from typing import Iterator

from .model import CapabilityHit, ExecutionContext
from .tables import Tables
from .yamlnode import YamlNode

__all__ = ["detect", "agent_steps", "AgentStep"]


class AgentStep:
    __slots__ = ("node", "spec", "invocation")

    def __init__(self, node: YamlNode, spec: dict | None, invocation: str) -> None:
        self.node = node
        self.spec = spec or {}
        self.invocation = invocation

    @property
    def display(self) -> str:
        return self.spec.get("display") or self.invocation or "an AI agent"

    def restores(self) -> tuple[str, ...]:
        return tuple(self.spec.get("restores_from_base") or ())

    def covers(self, path: str) -> bool:
        """Is ``path`` replaced with base-branch content before the agent reads it?"""
        for restored in self.restores():
            if restored.endswith("/"):
                if path == restored.rstrip("/") or path.startswith(restored):
                    return True
            elif path == restored:
                return True
        return False


def _uses_name(step: YamlNode) -> str:
    uses = step.get("uses")
    return uses.text.split("@", 1)[0].strip() if uses is not None else ""


def agent_steps(context: ExecutionContext, tables: Tables) -> Iterator[AgentStep]:
    agents = tables.section("agent_signals", "agents", []) or []
    invocations = tables.tuple_of("agent_signals", "run_invocations")
    steps = context.body.get("steps")
    if steps is None:
        return
    for step in steps.seq():
        if not step.is_mapping():
            continue
        name = _uses_name(step)
        if name:
            for spec in agents:
                for prefix in spec.get("uses_prefixes") or ():
                    if name == prefix or name.startswith(prefix):
                        yield AgentStep(step, dict(spec), name)
                        break
                else:
                    continue
                break
        run = step.get("run")
        if run is not None and run.text:
            for invocation in invocations:
                if invocation in run.text:
                    yield AgentStep(step, None, invocation)
                    break


def _pr_writable_configs(context: ExecutionContext, agent: AgentStep):
    for config in context.repo.agent_configs:
        if not agent.covers(config.path):
            yield config


def _prompt_injection(context: ExecutionContext, tables: Tables) -> list[CapabilityHit]:
    """Untrusted event data interpolated into an agent's prompt.

    An agent follows what it reads, so a prompt input is an interpreter sink in
    the same sense a ``run:`` block is. This is the Prompt-to-Agent class, and it
    is invisible to a YAML linter: nothing here is shell metacharacters, the
    injection is semantic.
    """
    from .detect_untrusted import expression_paths, matches_untrusted_path

    patterns = tables.tuple_of("untrusted_expressions", "paths")
    prompt_inputs = tables.tuple_of("agent_signals", "prompt_inputs")
    hits: list[CapabilityHit] = []

    for agent in agent_steps(context, tables):
        with_node = agent.node.get("with")
        if with_node is None or not with_node.is_mapping():
            continue
        for key in prompt_inputs:
            node = with_node.get(key)
            if node is None or not node.text:
                continue
            for path in expression_paths(node.text):
                if matches_untrusted_path(path, patterns):
                    hits.append(
                        CapabilityHit(
                            capability="U",
                            kind="agent-prompt-injection",
                            reason=(
                                f"`${{{{ {path} }}}}` is interpolated into "
                                f"{agent.display}'s `{key}` input; the agent treats "
                                "that text as instructions, so anyone who can write "
                                "it can redirect the agent"
                            ),
                            position=node.find_substring(path.split(".")[-1]),
                        )
                    )
    return hits


def detect(context: ExecutionContext, tables: Tables) -> list[CapabilityHit]:
    hits: list[CapabilityHit] = _prompt_injection(context, tables)
    if not context.untrusted_worktree:
        # An agent reading base-branch instructions is the hardened pattern. It
        # is not a finding, and saying so is what keeps the tool installed.
        return sorted(hits, key=lambda h: h.sort_key)

    for agent in agent_steps(context, tables):
        hits.append(
            CapabilityHit(
                capability="U",
                kind="agent-untrusted-worktree",
                reason=(
                    f"{agent.display} runs against a working tree containing pull "
                    f"request code ({context.untrusted_worktree_reason}), so the "
                    "files it reads and summarises are chosen by the PR author"
                ),
                position=agent.node.position(),
            )
        )

        exposed = list(_pr_writable_configs(context, agent))
        if exposed:
            paths = ", ".join(f"`{c.path}`" for c in exposed[:3])
            extra = f" (+{len(exposed) - 3} more)" if len(exposed) > 3 else ""
            restored = agent.restores()
            note = ""
            if restored:
                note = (
                    f" {agent.display} restores {len(restored)} paths from the base "
                    "branch, but these are outside that set"
                )
            hits.append(
                CapabilityHit(
                    capability="U",
                    kind="agent-config-ingress",
                    reason=(
                        f"instruction files {paths}{extra} come from the pull request "
                        f"head and are read as authoritative direction by "
                        f"{agent.display}.{note}"
                    ),
                    position=agent.node.position(),
                )
            )

        for server in context.repo.mcp_servers:
            if agent.covers(server.path):
                continue
            if server.write_capable:
                hits.append(
                    CapabilityHit(
                        capability="U",
                        kind="agent-mcp-ingress",
                        reason=(
                            f"MCP server `{server.name}` (`{server.path}`) is reachable "
                            f"from the pull request head; {server.detail}"
                        ),
                        position=agent.node.position(),
                    )
                )

    return sorted(hits, key=lambda h: h.sort_key)


def detect_hook_execution(context: ExecutionContext, tables: Tables) -> list[CapabilityHit]:
    """Agent hook config on an untrusted tree — direct execution, no model involved.

    Reported unconditionally rather than through the U/P/E intersection: a
    ``PreToolUse`` hook added by a fork PR runs a shell command, so there is no
    prompt to harden and no credential requirement for it to matter.
    """
    if not context.untrusted_worktree or not context.repo.hook_configs:
        return []
    if not any(True for _ in agent_steps(context, tables)):
        return []
    hits = []
    for hook in context.repo.hook_configs:
        hits.append(
            CapabilityHit(
                capability="U",
                kind="agent-hook-execution",
                reason=(
                    f"`{hook.path}` configures a shell command that runs on agent "
                    "lifecycle events, and it comes from the pull request head"
                ),
                position=context.position,
            )
        )
    return sorted(hits, key=lambda h: h.sort_key)
