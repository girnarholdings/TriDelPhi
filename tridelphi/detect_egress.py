"""E — egress and state change, graded rather than narrowed.

Detection stays deliberately broad: on a hosted runner an unrestricted shell
*is* network access, and ``run: node build.js`` where the script fetches is
invisible to any pattern. Narrowing E only produces false negatives, and E alone
never emits a finding.

What the tier buys is ranking and honest remediation. ``E2`` marks an observed
egress primitive, so the tool can say "the only egress here is one
upload-artifact step" and mean it, instead of "your job has a shell".
"""

from __future__ import annotations

from typing import Iterator

from .model import CapabilityHit, ExecutionContext
from .tables import Tables
from .yamlnode import YamlNode

__all__ = ["detect", "highest_tier"]


def _uses_name(step: YamlNode) -> str:
    uses = step.get("uses")
    return uses.text.split("@", 1)[0].strip() if uses is not None else ""


def _iter_steps(context: ExecutionContext) -> Iterator[YamlNode]:
    steps = context.body.get("steps")
    if steps is None:
        return
    for step in steps.seq():
        if step.is_mapping():
            yield step


def detect(context: ExecutionContext, tables: Tables) -> list[CapabilityHit]:
    hits: list[CapabilityHit] = []
    network = tables.tuple_of("egress", "network_commands")
    state = tables.tuple_of("egress", "state_change_commands")
    egress_actions = tables.tuple_of("egress", "egress_actions")
    read_only = tables.tuple_of("egress", "read_only_actions")

    for step in _iter_steps(context):
        run = step.get("run")
        if run is not None and run.text:
            matched = False
            for command in (*network, *state):
                if command in run.text:
                    hits.append(
                        CapabilityHit(
                            capability="E",
                            kind="network-command",
                            reason=f"`{command}` in a run block reaches the network or mutates outside state",
                            position=run.find_substring(command),
                            tier="E2",
                        )
                    )
                    matched = True
                    break
            if not matched:
                hits.append(
                    CapabilityHit(
                        capability="E",
                        kind="shell",
                        reason=(
                            "a `run:` step provides an unrestricted shell, which on a "
                            "hosted runner means unrestricted network access"
                        ),
                        position=run.value_position(),
                        tier="E1",
                    )
                )

        name = _uses_name(step)
        if not name:
            continue
        if any(name == a or name.startswith(a) for a in egress_actions):
            hits.append(
                CapabilityHit(
                    capability="E",
                    kind="egress-action",
                    reason=f"`{name}` publishes, deploys or moves data off the runner",
                    position=step.position(),
                    tier="E2",
                )
            )
        elif not any(name == a or name.startswith(a) for a in read_only):
            hits.append(
                CapabilityHit(
                    capability="E",
                    kind="third-party-action",
                    reason=(
                        f"`{name}` is a third-party action; its code runs on the runner "
                        "with full network access"
                    ),
                    position=step.position(),
                    tier="E1",
                )
            )

    from .detect_agent_ingress import agent_steps

    for agent in agent_steps(context, tables):
        tools = agent.spec.get("network_tools") or ()
        with_node = agent.node.get("with")
        declared = ""
        if with_node is not None:
            for key in ("allowed_tools", "allowedTools", "claude_args", "settings"):
                node = with_node.get(key)
                if node is not None and node.text:
                    declared += node.text
        enabled = [t for t in tools if t in declared] or list(tools)
        if enabled:
            hits.append(
                CapabilityHit(
                    capability="E",
                    kind="agent-network-tools",
                    reason=(
                        f"{agent.display} can use {', '.join(sorted(enabled)[:3])}, which "
                        "reach the shell or the network"
                    ),
                    position=agent.node.position(),
                    tier="E2",
                )
            )

    return sorted(hits, key=lambda h: h.sort_key)


def highest_tier(hits: list[CapabilityHit]) -> str:
    tiers = [h.tier for h in hits if h.capability == "E" and h.tier]
    if "E2" in tiers:
        return "E2"
    if "E1" in tiers:
        return "E1"
    return "E0"
