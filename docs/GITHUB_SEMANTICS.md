# GitHub Actions semantics TriDelPhi models

This is the security contract behind the parser. It separates facts GitHub
enforces from repository settings TriDelPhi cannot see offline. The executable
version is `tests/test_github_semantics_matrix.py`; a change to this table needs
a matching test.

## Trigger and credential matrix

| Context | Attacker-controlled code/data can reach it? | Token/secrets available to a fork attacker? | TriDelPhi treatment |
|---|---:|---:|---|
| fork `pull_request` | yes | repository secrets withheld; token read-only | U is observed; token-derived P is not co-reachable |
| same-repo `pull_request` | branch code is present | declared token scopes apply, but the author already has write access | not treated as a drive-by fork boundary |
| `pull_request_target` | event data is untrusted; default checkout is the base branch | privileged token/secrets may be available | checking out/fetching the PR head creates U next to P |
| `issue_comment` | comment body and related PR metadata are untrusted | declared/default privilege may be available | untrusted interpreter/agent use is U |
| `workflow_run` | upstream metadata/artifacts are untrusted channels | follow-up workflow may be privileged | downloaded content is safe only while treated as inert data |
| `workflow_call` | inherits the caller's reachability | called permissions can only reduce the caller token | local callees are inlined; caller/callee permissions are intersected |
| `push` / manual dispatch | trusted unless another modeled ingress is present | declared/default privilege applies | no U is invented merely from the trigger |

## Permission resolution

1. A job `permissions:` block overrides the workflow block.
2. A workflow block overrides the repository default.
3. An absent repository default is an **assumption**, never observed privilege.
4. Fork `pull_request` platform restrictions are applied when deciding whether
   token- or secret-derived privilege can coexist with untrusted ingress.
5. A local reusable workflow receives the caller token. A callee declaration
   can downgrade it but cannot add a scope the caller did not grant.
6. `secrets: inherit` is explicit privilege, subject to the same fork
   co-reachability rules.

## Checkout, runners, data flow, and unknowns

- Default `actions/checkout` on `pull_request` receives PR code. On
  `pull_request_target` and `workflow_run`, the default is the trusted base or
  default branch. An explicit PR ref or a shell `git fetch` can make it
  untrusted again.
- Concrete non-hosted runner labels are privileged assets. Dynamic `runs-on`
  expressions are reported as **unknown**, not guessed safe or self-hosted.
- Known job outputs and artifact names form typed cross-job channels. Dynamic
  names, dynamic `needs`, and unresolved remote reusable workflows remain
  visible unknowns.
- Matrix legs are analyzed as one conservative job definition. Environment
  approvals, deployment branch rules, and environment secrets live in GitHub
  settings and are therefore reported as unknown offline.

TriDelPhi is not a second GitHub Actions interpreter. When a runtime value or
repository setting cannot be proven from committed files, the beginner-facing
report must say **unknown** or **not run** rather than convert uncertainty into a
green check.
