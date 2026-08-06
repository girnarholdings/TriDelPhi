# Rules

Every rule id is anchored here; `tridelphi --explain <rule>` prints the same
text at a terminal.

Severity in TriDelPhi has three levels. SARIF has no `critical`, so it maps to
`error` and the true severity travels in the result's property bag.

| Rule | Level | What it means |
|---|---|---|
| [`tridelphi/agent-config-ingress`](#agent-config-ingress) | `error` | AI agent runs against an attacker-controlled working tree while holding privilege |
| [`tridelphi/agent-prompt-injection`](#agent-prompt-injection) | `error` | Attacker-controlled text is interpolated into a privileged agent's prompt |
| [`tridelphi/agent-hook-execution`](#agent-hook-execution) | `error` | Agent hook configuration executes shell from an untrusted checkout |
| [`tridelphi/untrusted-checkout-privileged-egress`](#untrusted-checkout-privileged-egress) | `error` | Privileged job checks out and runs attacker-controlled code |
| [`tridelphi/expression-injection-privileged`](#expression-injection-privileged) | `error` | Attacker-controlled expression reaches an interpreter in a privileged job |
| [`tridelphi/workflow-run-upstream-execution`](#workflow-run-upstream-execution) | `error` | Privileged workflow_run job consumes state produced by an untrusted run |
| [`tridelphi/cross-job-untrusted-flow`](#cross-job-untrusted-flow) | `error` | Untrusted value flows through job outputs into a privileged job |
| [`tridelphi/assumed-privilege-intersection`](#assumed-privilege-intersection) | `warning` | Untrusted ingress and egress, with privilege assumed from repository defaults |
| [`tridelphi/near-miss-missing-egress`](#near-miss-missing-egress) | `warning` | Untrusted ingress and privilege, one run step away from critical |
| [`tridelphi/near-miss-reachable-secret`](#near-miss-reachable-secret) | `warning` | Untrusted ingress and egress, with a secret reachable in the same workflow |
| [`tridelphi/privileged-trusted-context`](#privileged-trusted-context) | `note` | Privilege and egress on a trusted trigger (Rule of Two compliant) |
| [`tridelphi/unresolved-context`](#unresolved-context) | `note` | A referenced workflow or action could not be read offline |
| [`tridelphi/parse-error`](#parse-error) | `warning` | A workflow file could not be parsed |

## agent-config-ingress

`tridelphi/agent-config-ingress` · default level `error`

**AI agent runs against an attacker-controlled working tree while holding privilege**

An agent-invoking step executes over a working tree derived from an untrusted ref, so the instructions the agent follows are chosen by whoever opened the pull request. The job also holds credentials and can reach the network, which turns prompt injection into code execution with those credentials. Detection accounts for what each agent action restores from the base branch: anthropics/claude-code-action restores a fixed set of paths, so files outside that set (AGENTS.md, .cursor/rules, package manager config) remain attacker-controlled.

## agent-prompt-injection

`tridelphi/agent-prompt-injection` · default level `error`

**Attacker-controlled text is interpolated into a privileged agent's prompt**

Untrusted event data — an issue body, a comment, a pull request title — is interpolated into an AI agent's prompt in a job that also holds credentials and can reach the network. The agent treats that text as instructions, so anyone who can write a comment can redirect it. This is a semantic injection: there are no shell metacharacters to escape and no YAML linter sees anything wrong.

## agent-hook-execution

`tridelphi/agent-hook-execution` · default level `error`

**Agent hook configuration executes shell from an untrusted checkout**

A .claude/settings.json hook runs a shell command whenever the agent reaches a lifecycle event. When the working tree comes from an untrusted ref, a pull request can add or edit that hook and obtain direct command execution with no language model in the loop. This is not prompt injection and no prompt hardening mitigates it.

## untrusted-checkout-privileged-egress

`tridelphi/untrusted-checkout-privileged-egress` · default level `error`

**Privileged job checks out and runs attacker-controlled code**

The job resolves a checkout to a pull request head on a trigger that grants access to secrets, then executes code from that checkout. This is the classic pwn-request shape: the attacker supplies the code and the workflow supplies the credentials.

## expression-injection-privileged

`tridelphi/expression-injection-privileged` · default level `error`

**Attacker-controlled expression reaches an interpreter in a privileged job**

An untrusted github.event expression is interpolated directly into a shell or script body in a job that also holds credentials and egress. Interpolation happens before the shell runs, so the attacker's text becomes part of the command.

## workflow-run-upstream-execution

`tridelphi/workflow-run-upstream-execution` · default level `error`

**Privileged workflow_run job consumes state produced by an untrusted run**

A workflow_run job downloads artifacts or checks out a ref produced by the triggering workflow, which ran against attacker-controlled code, and then executes it while holding credentials. workflow_run is the recommended pattern for privileged post-processing, but only when the privileged job does not execute upstream output.

## cross-job-untrusted-flow

`tridelphi/cross-job-untrusted-flow` · default level `error`

**Untrusted value flows through job outputs into a privileged job**

One job interpolates attacker-controlled input into an output, and a downstream job consuming that output holds credentials and egress. Neither job is dangerous read alone, which is why per-file analysis misses this shape entirely.

## assumed-privilege-intersection

`tridelphi/assumed-privilege-intersection` · default level `warning`

**Untrusted ingress and egress, with privilege assumed from repository defaults**

The job has observed untrusted ingress and egress, but its privilege is inferred from an unknown repository default rather than read from the file. Declaring permissions explicitly both removes the ambiguity and hardens the job.

## near-miss-missing-egress

`tridelphi/near-miss-missing-egress` · default level `warning`

**Untrusted ingress and privilege, one run step away from critical**

The job holds untrusted ingress and credentials but currently has no egress primitive. Adding a single run step completes the chain, and that addition is easy to miss in review.

## near-miss-reachable-secret

`tridelphi/near-miss-reachable-secret` · default level `warning`

**Untrusted ingress and egress, with a secret reachable in the same workflow**

The job holds untrusted ingress and egress but no credentials of its own. A secret is defined elsewhere in the same workflow file, so a one-line edit brings it into scope.

## privileged-trusted-context

`tridelphi/privileged-trusted-context` · default level `note`

**Privilege and egress on a trusted trigger (Rule of Two compliant)**

The job holds credentials and egress but no untrusted ingress reaches it. This is the expected shape of a deploy or release job and is compliant with the Agents Rule of Two. Reported only so the trigger set can be confirmed to stay trusted.

## unresolved-context

`tridelphi/unresolved-context` · default level `note`

**A referenced workflow or action could not be read offline**

The job delegates to a remote reusable workflow. Its contents are not on disk, so capabilities inside it are invisible to an offline scan. Reported rather than ignored, because silence in a security tool is indistinguishable from safety.

## parse-error

`tridelphi/parse-error` · default level `warning`

**A workflow file could not be parsed**

The file is not valid YAML, or is not shaped like a workflow. It was skipped. Reported as a finding because a file the scanner cannot read is a blind spot, and anyone able to choke the parser would otherwise become invisible.

