"""Intersection, cross-job propagation, and the cheapest fix.

Three rules govern what comes out of here, and each exists because its absence
produced a specific fatal outcome in review:

* **Assumed privilege never reaches critical.** Otherwise every job in a repo
  that has not adopted explicit ``permissions:`` is critical.
* **Holding exactly two capabilities is compliant.** The Agents Rule of Two says
  *at most two*. Warning on the compliant state contradicts the framework the
  tool is built on. Warnings signal *proximity* — a third capability one small
  edit away — not presence.
* **Egress never gates.** It is true for almost every job, so it ranks findings
  rather than admitting them.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from . import detect_agent_ingress, detect_egress, detect_guards, detect_privilege, detect_untrusted
from .detect_untrusted import expression_paths, matches_untrusted_path
from .model import (
    CapabilityHit,
    ExecutionContext,
    Finding,
    Position,
    Remediation,
)
from .tables import Tables

__all__ = ["evaluate_all"]

_AGENT_KINDS = {"agent-config-ingress", "agent-untrusted-worktree", "agent-mcp-ingress"}

# Privilege that does not depend on GITHUB_TOKEN or repository secrets, and so
# survives the fork-pull_request platform cap.
_TOKEN_INDEPENDENT_P = {"self-hosted-runner"}

_RULE_FOR_U_KIND = {
    "agent-prompt-injection": "tridelphi/agent-prompt-injection",
    "agent-config-ingress": "tridelphi/agent-config-ingress",
    "agent-untrusted-worktree": "tridelphi/agent-config-ingress",
    "agent-mcp-ingress": "tridelphi/agent-config-ingress",
    "untrusted-checkout": "tridelphi/untrusted-checkout-privileged-egress",
    "expression-injection": "tridelphi/expression-injection-privileged",
    "expression-injection-via-env": "tridelphi/expression-injection-privileged",
    "env-file-injection": "tridelphi/env-file-injection",
    "upstream-artifact": "tridelphi/workflow-run-upstream-execution",
    "cross-job-flow": "tridelphi/cross-job-untrusted-flow",
    "cross-job-artifact": "tridelphi/cross-job-untrusted-flow",
}

# Most specific wins, so an agent finding is never reported as a generic one.
_U_KIND_PRIORITY = (
    "agent-config-ingress",
    "agent-prompt-injection",
    "agent-untrusted-worktree",
    "agent-mcp-ingress",
    "upstream-artifact",
    "cross-job-flow",
    "cross-job-artifact",
    "env-file-injection",
    "untrusted-checkout",
    "expression-injection",
    "expression-injection-via-env",
)


def _pick_rule(u_hits: Sequence[CapabilityHit]) -> str:
    kinds = {h.kind for h in u_hits}
    for kind in _U_KIND_PRIORITY:
        if kind in kinds:
            return _RULE_FOR_U_KIND[kind]
    return "tridelphi/untrusted-checkout-privileged-egress"


def _primary(u_hits: Sequence[CapabilityHit], context: ExecutionContext) -> Position:
    kinds = {h.kind: h for h in u_hits}
    for kind in _U_KIND_PRIORITY:
        if kind in kinds:
            return kinds[kind].position
    return context.position


# ---------------------------------------------------------------------------
# cross-job taint
# ---------------------------------------------------------------------------


def _tainted_outputs(context: ExecutionContext, u_hits: Sequence[CapabilityHit], tables: Tables) -> tuple[str, ...]:
    """Job outputs whose values derive from attacker-controlled input."""
    if not u_hits:
        return ()
    outputs = context.body.get("outputs")
    if outputs is None or not outputs.is_mapping():
        return ()
    patterns = tables.tuple_of("untrusted_expressions", "paths")
    tainted = []
    for name, node in outputs.items():
        text = node.text
        if not text:
            continue
        if any(matches_untrusted_path(p, patterns) for p in expression_paths(text)):
            tainted.append(str(name))
            continue
        # `steps.<id>.outputs.<x>` referencing a step that consumed untrusted
        # input in the same job.
        if "steps." in text and u_hits:
            tainted.append(str(name))
    return tuple(sorted(set(tainted)))


# A job whose worktree holds pull request code (these U kinds) can pack that
# attacker-authored code into an uploaded artifact. Expression-injection is a
# shell-exec issue, not a file-on-disk one, so it is deliberately excluded.
_WORKTREE_U_KINDS = ("untrusted-checkout", "agent-untrusted-worktree")


def _uses_position(context: ExecutionContext, markers: tuple[str, ...]) -> Position | None:
    """Position of the first step whose ``uses:`` matches one of ``markers``."""
    steps = context.body.get("steps")
    if steps is None:
        return None
    for step in steps.seq():
        if not step.is_mapping():
            continue
        uses = step.get("uses")
        if uses is None or not uses.text:
            continue
        name = uses.text.split("@", 1)[0].strip()
        if any(name == m or name.startswith(m) for m in markers):
            return step.position()
    return None


def _tainted_artifact_upload(
    context: ExecutionContext, u_hits: Sequence[CapabilityHit], tables: Tables
) -> Position | None:
    """If this job runs pull request code *and* uploads an artifact, return the
    upload step's position. The artifact then carries attacker-authored files to
    any downstream job that downloads it."""
    if not any(h.kind in _WORKTREE_U_KINDS for h in u_hits):
        return None
    return _uses_position(context, tables.tuple_of("egress", "artifact_producers"))


def _cross_job_hits(
    context: ExecutionContext,
    upstream: dict[str, tuple[ExecutionContext, tuple[str, ...], Position | None]],
    tables: Tables,
) -> list[CapabilityHit]:
    """U inherited from a ``needs:`` dependency — through a tainted job output,
    or through an artifact built from pull request code.

    Neither job is a finding read alone. This is the composition that per-file
    analysis structurally cannot reach.
    """
    if not context.needs:
        return []
    hits: list[CapabilityHit] = []
    body_text = _body_text(context)
    download_pos: Position | None = None
    download_checked = False
    tainted_uploader: str | None = None
    for dep in context.needs:
        entry = upstream.get(f"{context.workflow_file}::{dep}")
        if not entry:
            continue
        _dep_ctx, tainted, artifact_pos = entry
        for output in tainted:
            reference = f"needs.{dep}.outputs.{output}"
            if reference in body_text:
                hits.append(
                    CapabilityHit(
                        capability="U",
                        kind="cross-job-flow",
                        reason=(
                            f"attacker-controlled input reaches this job through "
                            f"`{reference}` — job `{dep}` interpolates untrusted event "
                            "data into that output"
                        ),
                        position=context.position,
                    )
                )
        # Artifact channel: the upstream job packed pull request code into an
        # artifact. If this job downloads one, that code crosses the boundary.
        if artifact_pos is not None and tainted_uploader is None:
            if not download_checked:
                download_pos = _uses_position(context, tables.tuple_of("egress", "artifact_consumers"))
                download_checked = True
            if download_pos is not None:
                tainted_uploader = dep
    if tainted_uploader is not None and download_pos is not None:
        hits.append(
            CapabilityHit(
                capability="U",
                kind="cross-job-artifact",
                reason=(
                    f"job `{tainted_uploader}` checked out pull request code and "
                    f"uploaded an artifact; this job downloads that artifact, so "
                    "attacker-authored files reach it across the job boundary"
                ),
                position=download_pos,
            )
        )
    return hits


def _body_text(context: ExecutionContext) -> str:
    import json

    try:
        return json.dumps(context.body.value, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return str(context.body.value)


# ---------------------------------------------------------------------------
# remediation
# ---------------------------------------------------------------------------


def _remediation(
    context: ExecutionContext,
    u_hits: Sequence[CapabilityHit],
    p_hits: Sequence[CapabilityHit],
    e_hits: Sequence[CapabilityHit],
) -> Remediation | None:
    """Name one capability to strip, the token that carries it, and what breaks.

    Ordering is by removal cost, not by capability letter. Egress is usually
    load-bearing, so it is proposed only when it is a single identifiable step.
    """
    u_kinds = {h.kind: h for h in u_hits}

    # 0. Environment-file injection: the value must not reach the env file at all.
    hit = u_kinds.get("env-file-injection")
    if hit is not None:
        token = _quoted_token(hit.reason)
        return Remediation(
            strip="U",
            kind="drop-env-file-write",
            target=token,
            target_position=hit.position,
            breaks="later steps stop reading the value as an env var — pass it explicitly instead",
            rendered=(
                f"Strip untrusted input. {token} is written into a GitHub environment "
                f"file at {_loc(hit.position)}, where it persists as a variable later "
                "steps execute (NODE_OPTIONS, PATH, LD_PRELOAD). Do not put untrusted "
                "data in $GITHUB_ENV / $GITHUB_OUTPUT / $GITHUB_PATH. If a later step "
                "needs the value, hand it over through a quoted step-scoped `env:` and "
                "read it with `\"$VAR\"` — never through the environment file."
            ),
        )

    # 1. Expression injection has a one-line fix that breaks nothing.
    hit = u_kinds.get("expression-injection")
    if hit is not None:
        token = _quoted_token(hit.reason)
        return Remediation(
            strip="U",
            kind="env-indirect",
            target=token,
            target_position=hit.position,
            breaks="nothing — the value stays available to the script",
            rendered=(
                f"Strip untrusted input. {token} is interpolated directly into the "
                f"shell at {_loc(hit.position)}. Pass it through the environment "
                "instead:\n"
                f"    env:\n"
                f"      UNTRUSTED_INPUT: {token}\n"
                f"    run: ./script.sh \"$UNTRUSTED_INPUT\"\n"
                "The value stays available to your script; shell expansion of "
                "attacker text does not. This alone drops the job to a compliant "
                "2-of-3 — the token and the trigger can stay as they are."
            ),
        )

    # 2. An untrusted checkout under a privileged trigger: drop the ref.
    hit = u_kinds.get("untrusted-checkout") or u_kinds.get("agent-untrusted-worktree")
    if hit is not None and "pull_request_target" in context.triggers:
        return Remediation(
            strip="U",
            kind="drop-untrusted-ref",
            target="actions/checkout ref",
            target_position=hit.position,
            breaks="the job stops seeing the PR's code — move that work to a `pull_request` job",
            rendered=(
                f"Strip untrusted input. This job runs on `pull_request_target`, which "
                f"grants secrets, and explicitly checks out pull request code at "
                f"{_loc(hit.position)}. Remove the `ref:` input so the checkout returns "
                "to the base branch (the default, and the reason "
                "`pull_request_target` exists). If the job genuinely needs the PR's "
                "code, run that part on `pull_request` — where GitHub withholds "
                "secrets — and hand results to a privileged `workflow_run` job that "
                "does not execute them."
            ),
        )

    # 2b. A self-hosted runner executing fork code: the runner is the exposure,
    # and no permissions change fixes it.
    runner = next((h for h in p_hits if h.kind == "self-hosted-runner"), None)
    if runner is not None and u_kinds:
        return Remediation(
            strip="P",
            kind="narrow-runner",
            target="the self-hosted runner",
            target_position=runner.position,
            breaks="builds needing the self-hosted toolchain must move or gate on approval",
            rendered=(
                f"Strip privilege. This job executes pull request code on a "
                f"self-hosted runner at {_loc(runner.position)}. No `permissions:` "
                "change helps — the runner itself is what the attacker gets. Either "
                "move fork pull requests to a GitHub-hosted runner:\n"
                "    runs-on: ${{ github.event.pull_request.head.repo.fork "
                "&& 'ubuntu-latest' || 'self-hosted' }}\n"
                "or require approval for outside contributors under Settings → "
                "Actions → Fork pull request workflows. If the runner must stay, "
                "make it ephemeral so compromise cannot persist between jobs."
            ),
        )

    # 3. Agent prompt injection: the prompt is the sink, not the shell.
    hit = u_kinds.get("agent-prompt-injection")
    if hit is not None:
        return Remediation(
            strip="U",
            kind="narrow-trigger",
            target=_quoted_token(hit.reason),
            target_position=hit.position,
            breaks="drive-by contributors stop being able to invoke the agent",
            rendered=(
                f"Strip untrusted input. {_quoted_token(hit.reason)} is placed in the "
                f"agent's prompt at {_loc(hit.position)}, and the agent obeys what it "
                "reads. Escaping does not help — the injection is semantic, not "
                "syntactic. Gate the job on the commenter's association so only "
                "trusted accounts can reach it:\n"
                "    if: contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), "
                "github.event.comment.author_association)\n"
                "That keeps the feature for maintainers and removes untrusted ingress "
                "entirely. Removing the secret instead would break the agent step."
            ),
        )

    # 4. Agent over untrusted tree: split the privileged half out.
    hit = u_kinds.get("agent-config-ingress") or u_kinds.get("agent-untrusted-worktree")
    if hit is not None:
        secret = next((h for h in p_hits if h.kind == "secret-reference" and h.observed), None)
        target = _quoted_token(secret.reason) if secret else "the agent's credentials"
        return Remediation(
            strip="P",
            kind="split-job",
            target=target,
            target_position=secret.position if secret else hit.position,
            breaks="the agent can no longer write back directly — it posts results through a second job",
            rendered=(
                f"Strip privilege. The agent at {_loc(hit.position)} reads files chosen "
                f"by the PR author, and this job also holds {target}. Move the "
                "credential-holding work into a separate job that does not run the "
                "agent, and pass the agent's output between them as an artifact. The "
                "agent keeps its review capability; a successful injection no longer "
                "has a credential to reach for. Narrowing the trigger is the "
                "alternative, but it also removes the feature for external "
                "contributors, which is usually the point of the workflow."
            ),
        )

    # 4. Upstream artifact execution.
    hit = u_kinds.get("upstream-artifact")
    if hit is not None:
        return Remediation(
            strip="U",
            kind="drop-step",
            target="the artifact download",
            target_position=hit.position,
            breaks="the privileged job loses access to upstream build output",
            rendered=(
                f"Strip untrusted input. The download at {_loc(hit.position)} pulls "
                "state built by a run that executed pull request code, and this job "
                "then executes it while holding credentials. Consume only inert data "
                "from that artifact (a number, a status string) and never a script, "
                "archive, or binary. If the artifact must be executed, do it in the "
                "unprivileged upstream workflow instead."
            ),
        )

    # 4b. Cross-job artifact execution: an upstream job packed pull request code
    # into an artifact this privileged job downloads.
    hit = u_kinds.get("cross-job-artifact")
    if hit is not None:
        return Remediation(
            strip="U",
            kind="drop-step",
            target="the artifact download",
            target_position=hit.position,
            breaks="this job loses the upstream artifact — treat its contents as data, not code",
            rendered=(
                f"Strip untrusted input. The download at {_loc(hit.position)} pulls an "
                "artifact built by a job that checked out pull request code, and this "
                "job holds credentials. Never execute a downloaded artifact "
                "(script, archive, binary, or `node_modules`): consume only inert data "
                "from it. If the artifact must run, build and run it in the same "
                "unprivileged job that produced it, and pass only a result forward."
            ),
        )

    # 5. Fall back to the observed secret.
    secret = next((h for h in p_hits if h.observed and h.kind == "secret-reference"), None)
    if secret is not None:
        token = _quoted_token(secret.reason)
        return Remediation(
            strip="P",
            kind="move-secret",
            target=token,
            target_position=secret.position,
            breaks="any step in this job that used the credential",
            rendered=(
                f"Strip privilege. {token} is available to this job at "
                f"{_loc(secret.position)} while attacker-controlled input reaches it. "
                "Move the steps that need the credential into a separate job on a "
                "trusted trigger, or replace the static secret with OIDC "
                "(`permissions: id-token: write`) scoped to the branch that is "
                "allowed to deploy."
            ),
        )

    # 6. Egress last, and only when it is one identifiable step.
    e2 = [h for h in e_hits if h.tier == "E2"]
    if len(e2) == 1:
        hit = e2[0]
        return Remediation(
            strip="E",
            kind="drop-step",
            target=_quoted_token(hit.reason),
            target_position=hit.position,
            breaks="whatever consumes that step's output",
            rendered=(
                f"Strip egress. The only egress primitive in this job is "
                f"{_quoted_token(hit.reason)} at {_loc(hit.position)}. Remove it, or "
                "guard it with "
                "`if: github.event.pull_request.head.repo.full_name == github.repository` "
                "so pull requests from forks cannot reach it."
            ),
        )
    return None


def _quoted_token(reason: str) -> str:
    start = reason.find("`")
    if start == -1:
        return reason.split(" ")[0]
    end = reason.find("`", start + 1)
    return reason[start : end + 1] if end != -1 else reason[start:]


def _loc(position: Position) -> str:
    return f"{position.file}:{position.line}"


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def _workflow_has_secret(contexts: Iterable[ExecutionContext], workflow_file: str, tables: Tables) -> str | None:
    for ctx in contexts:
        if ctx.workflow_file != workflow_file:
            continue
        for hit in detect_privilege.detect(ctx, tables):
            if hit.kind == "secret-reference":
                return _quoted_token(hit.reason)
    return None


def evaluate_all(contexts: Sequence[ExecutionContext], tables: Tables) -> list[Finding]:
    per_context: dict[str, tuple[list[CapabilityHit], list[CapabilityHit], list[CapabilityHit]]] = {}
    upstream: dict[str, tuple[ExecutionContext, tuple[str, ...], Position | None]] = {}

    for ctx in contexts:
        u = detect_untrusted.detect(ctx, tables)
        u += detect_agent_ingress.detect(ctx, tables)
        p = detect_privilege.detect(ctx, tables)
        e = detect_egress.detect(ctx, tables)
        per_context[ctx.label] = (u, p, e)
        upstream[ctx.label] = (
            ctx,
            _tainted_outputs(ctx, u, tables),
            _tainted_artifact_upload(ctx, u, tables),
        )

    findings: list[Finding] = []
    for ctx in contexts:
        u, p, e = per_context[ctx.label]
        u = sorted(u + _cross_job_hits(ctx, upstream, tables), key=lambda h: h.sort_key)

        hooks = detect_agent_ingress.detect_hook_execution(ctx, tables)
        if hooks:
            findings.append(
                _make(
                    "tridelphi/agent-hook-execution",
                    "critical",
                    ctx,
                    tuple(hooks + p + e),
                    hooks[0].position,
                    (
                        f"Job `{ctx.job_id}` runs an AI agent over a pull-request "
                        "working tree that carries executable hook configuration. A "
                        "fork can add a lifecycle hook and obtain direct command "
                        "execution — no model, and no prompt hardening, is involved."
                    ),
                    _remediation(ctx, hooks, p, e),
                )
            )

        # A removed guardrail is not a held capability, so it is reported on its
        # own rather than folded into the U/P/E join. It enlarges the blast
        # radius of every other finding in this job.
        overbroad = detect_agent_ingress.detect_overbroad_tools(ctx, tables)
        if overbroad:
            findings.append(
                _make(
                    "tridelphi/agent-overbroad-tools",
                    "warning",
                    ctx,
                    tuple(overbroad),
                    overbroad[0].position,
                    (
                        f"Job `{ctx.job_id}` runs an AI agent with a guardrail "
                        f"disabled: {overbroad[0].reason.split('is configured with ')[-1]}"
                        if "is configured with " in overbroad[0].reason
                        else f"Job `{ctx.job_id}` runs an AI agent with a guardrail disabled."
                    ),
                    Remediation(
                        strip="P",
                        kind="narrow-tools",
                        target=_quoted_token(overbroad[0].reason),
                        target_position=overbroad[0].position,
                        breaks="contributors outside the allowlist can no longer invoke the agent",
                        rendered=(
                            f"Strip privilege. {_quoted_token(overbroad[0].reason)} at "
                            f"{_loc(overbroad[0].position)} turns off a guardrail rather "
                            "than granting a capability, so a successful injection meets "
                            "no boundary. Name the accounts allowed to trigger it instead "
                            "of accepting any:\n"
                            "    if: contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), "
                            "github.event.comment.author_association)\n"
                            "and grant the narrowest tool set the task actually needs "
                            "rather than skipping permission checks."
                        ),
                    ),
                )
            )

        # A spoofable actor guard is a false sense of authorization, not a held
        # capability, so it is reported standalone like the overbroad-tools case.
        weak_guards = detect_guards.detect(ctx, tables)
        if weak_guards:
            findings.append(
                _make(
                    "tridelphi/weak-actor-guard",
                    "warning",
                    ctx,
                    tuple(weak_guards),
                    weak_guards[0].position,
                    (
                        f"Job `{ctx.job_id}` is reachable by an outside party and gated "
                        "only by a `github.actor` check, which is spoofable and is not an "
                        "authorization check."
                    ),
                    Remediation(
                        strip="P",
                        kind="strong-guard",
                        target="`github.actor` guard",
                        target_position=weak_guards[0].position,
                        breaks="nothing for real maintainers — it only stops spoofed identities",
                        rendered=(
                            f"Strip privilege. The guard at {_loc(weak_guards[0].position)} "
                            "trusts `github.actor`, which the Dependabot confused-deputy "
                            "trick and forged git identities defeat. Gate on the event's "
                            "association instead:\n"
                            "    if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), "
                            "github.event.comment.author_association)\n"
                            "or check the caller's real repository permission with a "
                            "permission-lookup action. Actor identity is not authorization."
                        ),
                    ),
                )
            )

        has_u, has_e = bool(u), bool(e)
        observed_p = [h for h in p if h.observed]
        assumed_p = [h for h in p if not h.observed]

        # Token- and secret-derived privilege is unreachable to a fork attacker
        # on a `pull_request`-only workflow. A self-hosted runner is different:
        # the fork's code executes on it regardless of what the token can do, so
        # that hit always participates in the join.
        if not detect_privilege.attacker_reachable_privilege(ctx, tables):
            observed_p = [h for h in observed_p if h.kind in _TOKEN_INDEPENDENT_P]
            assumed_p = [h for h in assumed_p if h.kind in _TOKEN_INDEPENDENT_P]

        has_p_observed, has_p_assumed = bool(observed_p), bool(assumed_p)

        if has_u and has_p_observed and has_e:
            rule_id = _pick_rule(u)
            findings.append(
                _make(
                    rule_id,
                    "critical",
                    ctx,
                    tuple(u + observed_p + e),
                    _primary(u, ctx),
                    _critical_message(ctx, u, observed_p, e),
                    _remediation(ctx, u, observed_p, e),
                )
            )
        elif has_u and has_p_assumed and has_e:
            findings.append(
                _make(
                    "tridelphi/assumed-privilege-intersection",
                    "warning",
                    ctx,
                    tuple(u + assumed_p + e),
                    _primary(u, ctx),
                    (
                        f"Job `{ctx.job_id}` has untrusted ingress and egress, and its "
                        "privilege is assumed from an unknown repository default rather "
                        "than declared. Add `permissions: contents: read` to this job to "
                        "remove the ambiguity and harden it in one line."
                    ),
                    Remediation(
                        strip="P",
                        kind="add-permissions",
                        target="`permissions:`",
                        target_position=ctx.position,
                        breaks="nothing, unless a step actually needs write scope",
                        rendered=(
                            f"Strip privilege. This job declares no `permissions:` block "
                            f"at {_loc(ctx.position)}, so its token falls back to the "
                            "repository default — which we cannot read offline and must "
                            "assume grants write. Declare it explicitly:\n"
                            "    permissions:\n"
                            "      contents: read\n"
                            "That both removes this finding and caps the blast radius if "
                            "the untrusted input above is ever exploited. If a step does "
                            "need write, grant only that scope and this finding will "
                            "re-appear at critical, where it belongs."
                        ),
                    ),
                )
            )
        elif has_u and (has_p_observed or has_p_assumed) and not has_e:
            findings.append(
                _make(
                    "tridelphi/near-miss-missing-egress",
                    "warning",
                    ctx,
                    tuple(u + p),
                    _primary(u, ctx),
                    (
                        f"Job `{ctx.job_id}` holds untrusted ingress and privilege but no "
                        "egress primitive. Adding a single `run:` step completes the "
                        "chain, and that addition is easy to miss in review."
                    ),
                    _remediation(ctx, u, p, e),
                )
            )
        elif has_u and has_e and not (has_p_observed or has_p_assumed):
            secret = _workflow_has_secret(contexts, ctx.workflow_file, tables)
            if secret:
                findings.append(
                    _make(
                        "tridelphi/near-miss-reachable-secret",
                        "warning",
                        ctx,
                        tuple(u + e),
                        _primary(u, ctx),
                        (
                            f"Job `{ctx.job_id}` holds untrusted ingress and egress but no "
                            f"credentials of its own. {secret} is defined elsewhere in "
                            "this workflow file, so one line brings it into scope."
                        ),
                        _remediation(ctx, u, p, e),
                    )
                )
        elif has_p_observed and has_e and not has_u:
            # Rule of Two compliant: exactly two capabilities, and no ingress
            # mechanism reaches this job. A deploy job holding a credential and a
            # shell is the definition of shipping software, and an agent job
            # reading base-branch instructions is the hardened pattern. Warning
            # on either means warning every repo for working correctly, and the
            # cheapest fix would be "nothing" — which is not a finding.
            reachable = (
                "This workflow is reachable from a fork, so confirm the trigger set "
                "stays trusted."
                if ctx.fork_reachable
                else "The trigger set is trusted."
            )
            findings.append(
                _make(
                    "tridelphi/privileged-trusted-context",
                    "note",
                    ctx,
                    tuple(observed_p + e),
                    ctx.position,
                    (
                        f"Job `{ctx.job_id}` holds privilege and egress but no untrusted "
                        f"input reaches it. This is compliant with the Agents Rule of "
                        f"Two. {reachable}"
                    ),
                    None,
                )
            )

        if ctx.is_reusable_call and ctx.called_workflow and not ctx.called_workflow.startswith("./"):
            findings.append(
                _make(
                    "tridelphi/unresolved-context",
                    "note",
                    ctx,
                    (),
                    ctx.position,
                    (
                        f"Job `{ctx.job_id}` calls remote reusable workflow "
                        f"`{ctx.called_workflow}`. Its contents are not on disk, so any "
                        "capability inside it is invisible to an offline scan."
                    ),
                    None,
                )
            )

    return sorted(findings, key=lambda f: f.sort_key)


def _critical_message(
    ctx: ExecutionContext,
    u: Sequence[CapabilityHit],
    p: Sequence[CapabilityHit],
    e: Sequence[CapabilityHit],
) -> str:
    tier = detect_egress.highest_tier(list(e))
    tier_text = {
        "E2": "an observed egress primitive",
        "E1": "an unrestricted shell",
        "E0": "no shell",
    }[tier]
    return (
        f"Job `{ctx.job_id}` holds all three capabilities. "
        f"Untrusted input: {u[0].reason}. "
        f"Privilege: {p[0].reason}. "
        f"Egress: {e[0].reason} ({tier_text}). "
        "Any one of the three being removed breaks the chain."
    )


def _make(
    rule_id: str,
    severity: str,
    context: ExecutionContext,
    hits: tuple[CapabilityHit, ...],
    primary: Position,
    message: str,
    remediation: Remediation | None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        context=context,
        hits=tuple(sorted(hits, key=lambda h: h.sort_key)),
        primary_position=primary,
        message=message,
        remediation=remediation,
    )
