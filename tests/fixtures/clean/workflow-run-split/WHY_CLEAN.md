# The split pattern GitHub recommends

Untrusted work runs on `pull_request` with no secrets; privileged work runs on
`workflow_run` with write scope. The privileged job posts a comment and never
downloads or executes anything the untrusted run produced.

This fixture is why `workflow_run` cannot be a dangerous trigger on its own. The
original spec listed it as one *and* mandated this fixture produce zero findings
— a contradiction that made the acceptance test unsatisfiable by construction.

Resolution: `workflow_run` confers untrusted ingress only when the job consumes
upstream state (`download-artifact`, `gh run download`, or a checkout of
`workflow_run.head_sha`). This job consumes only `conclusion`, which is a
platform-generated enum. Clean.
