# U + P, no egress — the genuine near-miss

The job checks out pull request code (**U**) and has `secrets.PREVIEW_TOKEN` in
scope (**P**), on `pull_request_target` where secrets really are available to an
outside contributor. It has no `run:` step, and both actions it uses are in the
read-only set, so there is no egress primitive (**E0**).

Nothing is exploitable today. Adding one `run:` line makes it critical, and that
line is easy to wave through in review — which is exactly what a proximity
warning is for.

Note the `actions/cache` key interpolating `github.head_ref`: that is a **data**
sink, not an interpreter, so it must not produce an injection finding. A
detector that scans every `with:` input undifferentiated flags it.

Expected: WARNING under `tridelphi/near-miss-missing-egress`. The named strip is
`U` — dropping the `ref:` is cheaper than removing the secret, and on
`pull_request_target` the bare checkout is the documented safe default.
