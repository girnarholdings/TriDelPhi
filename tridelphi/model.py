"""The frozen domain model.

Every field here is load-bearing for a detector that is contractually forbidden
from reading files itself. Ordering constraints worth knowing before editing:

* No ``set``/``frozenset`` on any field. ``str``-set iteration order is
  ``PYTHONHASHSEED``-randomised, and a reason string built by joining a set is
  non-deterministic across processes.
* ``body`` is ``compare=False`` — ``frozen=True`` synthesises ``__hash__`` from
  every field, and a ruamel ``CommentedMap`` is unhashable. It also makes two
  structurally identical jobs in different files compare equal, which silently
  collapses findings in any dedup pass.
* No ``Optional`` may appear in a sort key; ``None`` raises on comparison rather
  than sorting last.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .yamlnode import YamlNode

Capability = Literal["U", "P", "E"]
Severity = Literal["critical", "warning", "note"]
EgressTier = Literal["E0", "E1", "E2"]

__all__ = [
    "RULES",
    "AgentConfigFile",
    "AnalysisResult",
    "Capability",
    "CapabilityHit",
    "Diagnostic",
    "EgressTier",
    "ExecutionContext",
    "Finding",
    "McpServer",
    "Position",
    "Remediation",
    "RepoInventory",
    "RuleSpec",
    "Severity",
    "rule_by_id",
]


@dataclass(frozen=True, slots=True)
class Position:
    """A source location. Lines and columns are 1-indexed.

    ruamel's ``.lc`` is 0-indexed and SARIF declares ``startLine`` with
    ``minimum: 1``, so the conversion happens exactly once — in
    :meth:`YamlNode.position` — and is asserted here.
    """

    file: str
    line: int
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    snippet: str | None = None

    def __post_init__(self) -> None:
        if self.line < 1:
            raise ValueError(f"Position.line is 1-indexed, got {self.line}")
        if self.column is not None and self.column < 1:
            raise ValueError(f"Position.column is 1-indexed, got {self.column}")

    @property
    def sort_key(self) -> tuple[str, int, int]:
        return (self.file, self.line, self.column or 0)


@dataclass(frozen=True, slots=True)
class CapabilityHit:
    """One independent piece of evidence that a context holds a capability.

    ``observed`` is the difference between "the file says so" and "we assumed a
    repository default we cannot see offline". An assumed hit can never carry a
    finding to critical.
    """

    capability: Capability
    kind: str
    reason: str
    position: Position
    observed: bool = True
    tier: EgressTier | None = None

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (self.position.sort_key, self.capability, self.kind, self.reason)


@dataclass(frozen=True, slots=True)
class AgentConfigFile:
    path: str
    kind: str
    text: str


@dataclass(frozen=True, slots=True)
class McpServer:
    name: str
    path: str
    remote: bool
    write_capable: bool
    detail: str


@dataclass(frozen=True, slots=True)
class RepoInventory:
    """Repo-level facts the per-job detectors may consult.

    Without this the agent-ingress detector has no legal way to read its own
    inputs: it is forbidden from parsing files, and the files it needs are not
    inside any job body.
    """

    root: str
    agent_configs: tuple[AgentConfigFile, ...] = ()
    mcp_servers: tuple[McpServer, ...] = ()
    hook_configs: tuple[AgentConfigFile, ...] = ()
    codeowners_paths: tuple[str, ...] = ()

    def config_kinds(self) -> tuple[str, ...]:
        return tuple(sorted({c.kind for c in self.agent_configs}))


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """One GitHub Actions job, resolved against its workflow.

    The job is the unit of analysis in v1: steps are too fine without a
    data-flow model, workflows too coarse. A ``strategy.matrix`` collapses to
    the job *definition* rather than expanding — deliberate, documented, and
    revisited when per-leg capabilities diverge in practice.
    """

    workflow_file: str
    job_id: str
    position: Position
    triggers: tuple[str, ...]
    fork_reachable: bool
    effective_permissions: Mapping[str, str]
    permissions_source: str
    repo: RepoInventory
    body: YamlNode = field(compare=False, repr=False)
    workflow_env: YamlNode | None = field(default=None, compare=False, repr=False)
    permissions_position: Position | None = None
    needs: tuple[str, ...] = ()
    runs_on: tuple[str, ...] = ()
    job_if: str | None = None
    is_reusable_call: bool = False
    secrets_inherit: bool = False
    called_workflow: str | None = None
    untrusted_worktree: bool = False
    untrusted_worktree_reason: str = ""

    @property
    def label(self) -> str:
        return f"{self.workflow_file}::{self.job_id}"


@dataclass(frozen=True, slots=True)
class Remediation:
    """The cheapest capability to strip, structured.

    Prose was the wrong type: ``rule.py`` authored it, ``sarif.py`` rendered it
    and ``test_thesis.py`` asserted on it, so a copy-edit reddened the
    acceptance test. Tests now assert ``strip``; only ``rendered`` is prose.
    """

    strip: Capability
    kind: str
    target: str
    target_position: Position | None
    rendered: str
    breaks: str
    confidence: Literal["high", "low"] = "high"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    context: ExecutionContext
    hits: tuple[CapabilityHit, ...]
    primary_position: Position
    message: str
    remediation: Remediation | None = None

    @property
    def sort_key(self) -> tuple[Any, ...]:
        # job_id is a required tiebreaker: YAML anchors let two jobs share one
        # body object, so positions inside them collide.
        return (
            self.primary_position.file,
            self.primary_position.line,
            self.primary_position.column or 0,
            self.rule_id,
            self.context.job_id,
        )

    def capabilities(self) -> tuple[Capability, ...]:
        return tuple(sorted({h.capability for h in self.hits}))


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """A non-fatal problem. Never a crash, never silence.

    A workflow we cannot parse is emitted rather than skipped: silent skipping
    is a bypass, since anyone able to choke the parser becomes invisible.
    """

    path: str
    message: str
    severity: Literal["error", "warning"] = "warning"
    position: Position | None = None

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.path, self.message)


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    findings: tuple[Finding, ...]
    diagnostics: tuple[Diagnostic, ...]
    contexts_scanned: int
    files_scanned: int
    suppressed: int = 0


@dataclass(frozen=True, slots=True)
class RuleSpec:
    id: str
    name: str
    short_description: str
    full_description: str
    help_uri: str
    default_level: Literal["error", "warning", "note"]


_HELP = "https://github.com/girnarholdings/TriDelPhi/blob/main/docs/RULES.md"

RULES: tuple[RuleSpec, ...] = (
    RuleSpec(
        id="tridelphi/agent-config-ingress",
        name="AgentConfigIngress",
        short_description="AI agent runs against an attacker-controlled working tree while holding privilege",
        full_description=(
            "An agent-invoking step executes over a working tree derived from an "
            "untrusted ref, so the instructions the agent follows are chosen by "
            "whoever opened the pull request. The job also holds credentials and "
            "can reach the network, which turns prompt injection into code "
            "execution with those credentials. Detection accounts for what each "
            "agent action restores from the base branch: anthropics/claude-code-action "
            "restores a fixed set of paths, so files outside that set (AGENTS.md, "
            ".cursor/rules, package manager config) remain attacker-controlled."
        ),
        help_uri=f"{_HELP}#agent-config-ingress",
        default_level="error",
    ),
    RuleSpec(
        id="tridelphi/agent-prompt-injection",
        name="AgentPromptInjection",
        short_description="Attacker-controlled text is interpolated into a privileged agent's prompt",
        full_description=(
            "Untrusted event data — an issue body, a comment, a pull request title "
            "— is interpolated into an AI agent's prompt in a job that also holds "
            "credentials and can reach the network. The agent treats that text as "
            "instructions, so anyone who can write a comment can redirect it. This "
            "is a semantic injection: there are no shell metacharacters to escape "
            "and no YAML linter sees anything wrong."
        ),
        help_uri=f"{_HELP}#agent-prompt-injection",
        default_level="error",
    ),
    RuleSpec(
        id="tridelphi/agent-hook-execution",
        name="AgentHookExecution",
        short_description="Agent hook configuration executes shell from an untrusted checkout",
        full_description=(
            "A .claude/settings.json hook runs a shell command whenever the agent "
            "reaches a lifecycle event. When the working tree comes from an "
            "untrusted ref, a pull request can add or edit that hook and obtain "
            "direct command execution with no language model in the loop. This is "
            "not prompt injection and no prompt hardening mitigates it."
        ),
        help_uri=f"{_HELP}#agent-hook-execution",
        default_level="error",
    ),
    RuleSpec(
        id="tridelphi/untrusted-checkout-privileged-egress",
        name="UntrustedCheckoutPrivilegedEgress",
        short_description="Privileged job checks out and runs attacker-controlled code",
        full_description=(
            "The job resolves a checkout to a pull request head on a trigger that "
            "grants access to secrets, then executes code from that checkout. This "
            "is the classic pwn-request shape: the attacker supplies the code and "
            "the workflow supplies the credentials."
        ),
        help_uri=f"{_HELP}#untrusted-checkout-privileged-egress",
        default_level="error",
    ),
    RuleSpec(
        id="tridelphi/expression-injection-privileged",
        name="ExpressionInjectionPrivileged",
        short_description="Attacker-controlled expression reaches an interpreter in a privileged job",
        full_description=(
            "An untrusted github.event expression is interpolated directly into a "
            "shell or script body in a job that also holds credentials and egress. "
            "Interpolation happens before the shell runs, so the attacker's text "
            "becomes part of the command."
        ),
        help_uri=f"{_HELP}#expression-injection-privileged",
        default_level="error",
    ),
    RuleSpec(
        id="tridelphi/workflow-run-upstream-execution",
        name="WorkflowRunUpstreamExecution",
        short_description="Privileged workflow_run job consumes state produced by an untrusted run",
        full_description=(
            "A workflow_run job downloads artifacts or checks out a ref produced by "
            "the triggering workflow, which ran against attacker-controlled code, "
            "and then executes it while holding credentials. workflow_run is the "
            "recommended pattern for privileged post-processing, but only when the "
            "privileged job does not execute upstream output."
        ),
        help_uri=f"{_HELP}#workflow-run-upstream-execution",
        default_level="error",
    ),
    RuleSpec(
        id="tridelphi/cross-job-untrusted-flow",
        name="CrossJobUntrustedFlow",
        short_description="Untrusted value flows through job outputs into a privileged job",
        full_description=(
            "One job interpolates attacker-controlled input into an output, and a "
            "downstream job consuming that output holds credentials and egress. "
            "Neither job is dangerous read alone, which is why per-file analysis "
            "misses this shape entirely."
        ),
        help_uri=f"{_HELP}#cross-job-untrusted-flow",
        default_level="error",
    ),
    RuleSpec(
        id="tridelphi/assumed-privilege-intersection",
        name="AssumedPrivilegeIntersection",
        short_description="Untrusted ingress and egress, with privilege assumed from repository defaults",
        full_description=(
            "The job has observed untrusted ingress and egress, but its privilege "
            "is inferred from an unknown repository default rather than read from "
            "the file. Declaring permissions explicitly both removes the ambiguity "
            "and hardens the job."
        ),
        help_uri=f"{_HELP}#assumed-privilege-intersection",
        default_level="warning",
    ),
    RuleSpec(
        id="tridelphi/near-miss-missing-egress",
        name="NearMissMissingEgress",
        short_description="Untrusted ingress and privilege, one run step away from critical",
        full_description=(
            "The job holds untrusted ingress and credentials but currently has no "
            "egress primitive. Adding a single run step completes the chain, and "
            "that addition is easy to miss in review."
        ),
        help_uri=f"{_HELP}#near-miss-missing-egress",
        default_level="warning",
    ),
    RuleSpec(
        id="tridelphi/near-miss-reachable-secret",
        name="NearMissReachableSecret",
        short_description="Untrusted ingress and egress, with a secret reachable in the same workflow",
        full_description=(
            "The job holds untrusted ingress and egress but no credentials of its "
            "own. A secret is defined elsewhere in the same workflow file, so a "
            "one-line edit brings it into scope."
        ),
        help_uri=f"{_HELP}#near-miss-reachable-secret",
        default_level="warning",
    ),
    RuleSpec(
        id="tridelphi/privileged-trusted-context",
        name="PrivilegedTrustedContext",
        short_description="Privilege and egress on a trusted trigger (Rule of Two compliant)",
        full_description=(
            "The job holds credentials and egress but no untrusted ingress reaches "
            "it. This is the expected shape of a deploy or release job and is "
            "compliant with the Agents Rule of Two. Reported only so the trigger "
            "set can be confirmed to stay trusted."
        ),
        help_uri=f"{_HELP}#privileged-trusted-context",
        default_level="note",
    ),
    RuleSpec(
        id="tridelphi/unresolved-context",
        name="UnresolvedContext",
        short_description="A referenced workflow or action could not be read offline",
        full_description=(
            "The job delegates to a remote reusable workflow. Its contents are not "
            "on disk, so capabilities inside it are invisible to an offline scan. "
            "Reported rather than ignored, because silence in a security tool is "
            "indistinguishable from safety."
        ),
        help_uri=f"{_HELP}#unresolved-context",
        default_level="note",
    ),
    RuleSpec(
        id="tridelphi/parse-error",
        name="ParseError",
        short_description="A workflow file could not be parsed",
        full_description=(
            "The file is not valid YAML, or is not shaped like a workflow. It was "
            "skipped. Reported as a finding because a file the scanner cannot read "
            "is a blind spot, and anyone able to choke the parser would otherwise "
            "become invisible."
        ),
        help_uri=f"{_HELP}#parse-error",
        default_level="warning",
    ),
)

_RULES_BY_ID = {r.id: r for r in RULES}


def rule_by_id(rule_id: str) -> RuleSpec:
    try:
        return _RULES_BY_ID[rule_id]
    except KeyError:  # pragma: no cover - guarded by test_rules_registry
        raise KeyError(f"rule {rule_id!r} is not in the RULES registry") from None
