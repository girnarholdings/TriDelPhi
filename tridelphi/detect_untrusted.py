"""U — untrusted ingress.

A dangerous trigger is a precondition, never a source. U fires only when
attacker-controlled bytes have a path into the job: interpolation into an
interpreter, a checkout of untrusted code, consumption of upstream state, or an
agent operating over an untrusted tree (see :mod:`detect_agent_ingress`).

Getting this wrong in the permissive direction is not a tuning problem. Trigger-
implies-U makes the tool emit findings on the most common workflow on GitHub.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from .model import CapabilityHit, ExecutionContext
from .steps import iter_steps, uses_name
from .tables import Tables
from .yamlnode import YamlNode

__all__ = ["detect", "expression_paths", "matches_untrusted_path", "untrusted_references"]

_EXPR = re.compile(r"\$\{\{(.+?)\}\}", re.DOTALL)


def expression_paths(text: str) -> list[str]:
    """Every context path referenced inside ``${{ }}`` in ``text``."""
    out: list[str] = []
    for match in _EXPR.finditer(text or ""):
        inner = match.group(1)
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_.\[\]'\"*-]*", inner):
            token = token.strip()
            if token.startswith(("github.", "needs.", "inputs.", "env.", "steps.")):
                out.append(token)
    return out


def matches_untrusted_path(path: str, patterns: tuple[str, ...]) -> str | None:
    """Match a context path against the table, honouring ``*`` segments.

    GitHub's object-filter syntax means ``github.event.*.body`` is a real
    injection path; a flat string comparison misses it.
    """
    normalised = path.replace("['", ".").replace("']", "").replace('["', ".").replace('"]', "")
    parts = normalised.split(".")
    for pattern in patterns:
        pat_parts = pattern.split(".")
        if len(pat_parts) != len(parts):
            continue
        # A `*` on either side matches one segment: `github.event.*.body` in the
        # workflow is an object filter, and `commits.*.message` in the table is a
        # wildcard over array elements. Both must match a concrete path.
        if all(p == "*" or q == "*" or p == q for p, q in zip(pat_parts, parts, strict=True)):
            return pattern
    return None


# A whole object serialised into text: `toJSON(github.event)` renders every
# attacker-written title and body inside it. GitHub function names are
# case-insensitive.
_TO_JSON = re.compile(r"\btoJSON\s*\(\s*([A-Za-z_][A-Za-z0-9_.\[\]'\"*-]*)\s*\)", re.IGNORECASE)


def _normalise_path(path: str) -> str:
    return path.replace("['", ".").replace("']", "").replace('["', ".").replace('"]', "")


def _contains_untrusted(obj: str, patterns: tuple[str, ...]) -> str | None:
    """The first table path that lies inside the serialised object ``obj``."""
    prefix = _normalise_path(obj).rstrip(".") + "."
    return next((pattern for pattern in patterns if pattern.startswith(prefix)), None)


def untrusted_references(text: str, patterns: tuple[str, ...]) -> list[tuple[str, str]]:
    """``(path, table pattern)`` for every attacker-controlled value in ``${{ }}``.

    A leaf such as ``github.event.issue.title`` matches the table directly. An
    object serialised whole — ``toJSON(github.event)``, a common debugging
    line — carries every untrusted field beneath it, and matched nothing while
    only leaves were compared: ``echo '${{ toJSON(github.event) }}'`` ran an
    issue title containing a quote through the shell unseen.
    """
    found: list[tuple[str, str]] = []
    for match in _EXPR.finditer(text or ""):
        inner = match.group(1)
        for path in expression_paths(match.group(0)):
            pattern = matches_untrusted_path(path, patterns)
            if pattern:
                found.append((path, pattern))
        for obj in _TO_JSON.findall(inner):
            pattern = _contains_untrusted(obj, patterns)
            if pattern:
                found.append((obj, pattern))
    return found


def _reexpands(run_text: str, var_name: str, markers: tuple[str, ...]) -> bool:
    """Does this run block defeat the env-indirection mitigation?"""
    if any(marker in run_text for marker in markers):
        return True
    return bool(re.search(rf"\$\{{?{re.escape(var_name)}\b", run_text)) and "eval" in run_text


def _scan_interpreter_sinks(
    context: ExecutionContext, tables: Tables
) -> Iterator[CapabilityHit]:
    patterns = tables.tuple_of("untrusted_expressions", "paths")
    markers = tables.tuple_of("untrusted_expressions", "env_reexpansion_markers")
    sinks = tables.section("untrusted_expressions", "interpreter_sinks", {}) or {}

    env_files = tables.tuple_of("untrusted_expressions", "env_file_targets")

    # A strong author_association job gate means only trusted accounts can make
    # this job run at all — but it vets one author: the one whose object it
    # names. Text written by that author is no longer stranger-writable; the
    # rest of the payload still is (see ``vetted_event_prefixes``). This is the
    # remediation rule.py recommends, and honouring exactly its scope is what
    # makes that advice turn the scan green without hiding the issue a trusted
    # commenter happens to act on. Env-file writes and re-expansion keep firing
    # as defence in depth.
    from .detect_guards import is_vetted, vetted_event_prefixes

    vetted = vetted_event_prefixes(context)

    # Workflow- and job-level `env:` reach every step; a job value overrides a
    # workflow one, so a safe override clears an untrusted inherited value.
    inherited: dict[str, tuple[str, YamlNode]] = {}
    for scope in (context.workflow_env, context.body.get("env")):
        if scope is None or not scope.is_mapping():
            continue
        for var, val in scope.items():
            refs = untrusted_references(val.text, patterns) if val.text else []
            if refs:
                inherited[str(var)] = (refs[0][0], val)
            else:
                inherited.pop(str(var), None)
    reported_inherited: set[str] = set()

    for step in iter_steps(context.body):
        run = step.get("run")
        if run is not None and run.text:
            for path, _pattern in untrusted_references(run.text, patterns):
                if not is_vetted(path, vetted):
                    yield CapabilityHit(
                        capability="U",
                        kind="expression-injection",
                        reason=(
                            f"`${{{{ {path} }}}}` is interpolated into a shell command; "
                            "the value is attacker-controlled and expansion happens "
                            "before the shell runs"
                        ),
                        position=run.find_substring(path.split(".")[-1]),
                    )
            # Environment-file injection: writing attacker text into $GITHUB_ENV,
            # $GITHUB_OUTPUT or $GITHUB_PATH lets it set variables like
            # NODE_OPTIONS that later steps execute — the Google/Apache class.
            # A hit only when an untrusted expression lands on a line writing to
            # one of those files.
            for line in run.text.splitlines():
                if not any(target in line for target in env_files):
                    continue
                refs = untrusted_references(line, patterns)
                if refs:
                    path = refs[0][0]
                    yield CapabilityHit(
                        capability="U",
                        kind="env-file-injection",
                        reason=(
                            f"`${{{{ {path} }}}}` is written into a GitHub "
                            "environment file; attacker text there sets variables "
                            "(NODE_OPTIONS, PATH…) that later privileged steps run"
                        ),
                        position=run.find_substring(path.split(".")[-1]),
                    )

        name = uses_name(step)
        sink_inputs = sinks.get(name)
        if sink_inputs and isinstance(sink_inputs, list):
            with_node = step.get("with")
            if with_node is not None:
                for key in sink_inputs:
                    node = with_node.get(key)
                    if node is None or not node.text:
                        continue
                    for path, _pattern in untrusted_references(node.text, patterns):
                        if not is_vetted(path, vetted):
                            yield CapabilityHit(
                                capability="U",
                                kind="expression-injection",
                                reason=(
                                    f"`${{{{ {path} }}}}` is interpolated into "
                                    f"`{name}` input `{key}`, which is executed as script"
                                ),
                                position=node.value_position(),
                            )

        # env: indirection is GitHub's documented mitigation. It only becomes a
        # hit when the run body re-expands the variable.
        env_node = step.get("env")
        if env_node is not None and env_node.is_mapping() and run is not None:
            for var, val in env_node.items():
                if not val.text:
                    continue
                for path, _pattern in untrusted_references(val.text, patterns):
                    if _reexpands(run.text, str(var), markers):
                        yield CapabilityHit(
                            capability="U",
                            kind="expression-injection-via-env",
                            reason=(
                                f"`{var}` carries attacker-controlled "
                                f"`${{{{ {path} }}}}` and the run block re-expands it "
                                "rather than quoting it"
                            ),
                            position=val.value_position(),
                        )

        # The same laundering through an inherited variable. A step's own
        # `env:` shadows the name. Because the variable reaches every step, a
        # hit also needs this step to reference it — not merely to contain a
        # re-expansion primitive somewhere.
        if run is not None and run.text and inherited:
            shadowed = (
                {str(k) for k in env_node.value}
                if env_node is not None and env_node.is_mapping()
                else set()
            )
            for var, (path, val) in inherited.items():
                if var in shadowed or var in reported_inherited:
                    continue
                if re.search(rf"\$\{{?{re.escape(var)}\b", run.text) and _reexpands(
                    run.text, var, markers
                ):
                    reported_inherited.add(var)
                    yield CapabilityHit(
                        capability="U",
                        kind="expression-injection-via-env",
                        reason=(
                            f"`{var}` is set from attacker-controlled "
                            f"`${{{{ {path} }}}}` for every step, and a run block "
                            "re-expands it rather than quoting it"
                        ),
                        position=val.value_position(),
                    )


def _scan_untrusted_checkout(context: ExecutionContext) -> Iterator[CapabilityHit]:
    if not context.untrusted_worktree:
        return
    yield CapabilityHit(
        capability="U",
        kind="untrusted-checkout",
        reason=(
            f"the working tree contains pull request code — "
            f"{context.untrusted_worktree_reason}"
        ),
        position=context.position,
    )


def _scan_upstream_consumption(
    context: ExecutionContext, tables: Tables
) -> Iterator[CapabilityHit]:
    """``workflow_run`` is U only when the job consumes what the upstream run built.

    Without this the officially recommended hardening pattern — do untrusted work
    on `pull_request`, do privileged work on `workflow_run` — is flagged
    critical, and the acceptance test can never go green.
    """
    if "workflow_run" not in context.triggers:
        return
    consumers = tables.tuple_of("egress", "upstream_consumers")
    for step in iter_steps(context.body):
        name = uses_name(step)
        if name and any(name == c or name.startswith(c) for c in consumers):
            yield CapabilityHit(
                capability="U",
                kind="upstream-artifact",
                reason=(
                    f"`{name}` downloads state produced by the triggering run, which "
                    "executed attacker-controlled code"
                ),
                position=step.position(),
            )
            continue
        run = step.get("run")
        if run is not None and run.text:
            for marker in consumers:
                if " " in marker and marker in run.text:
                    yield CapabilityHit(
                        capability="U",
                        kind="upstream-artifact",
                        reason=f"`{marker}` pulls state produced by the triggering run",
                        position=run.find_substring(marker),
                    )
                    break


def detect(context: ExecutionContext, tables: Tables) -> list[CapabilityHit]:
    hits: list[CapabilityHit] = []
    hits.extend(_scan_interpreter_sinks(context, tables))
    hits.extend(_scan_untrusted_checkout(context))
    hits.extend(_scan_upstream_consumption(context, tables))
    return sorted(hits, key=lambda h: h.sort_key)
