# The most common workflow on GitHub

`on: [push, pull_request]`, a checkout, and `npm test`. No `permissions:` block,
so a scanner that assumes the repository default is write-all sees U + P + E and
emits CRITICAL — on a job with no secrets and a read-only token.

Two facts make this clean, and both are platform guarantees rather than
assumptions:

1. For `pull_request` from a fork, `GITHUB_TOKEN` is read-only and repository
   secrets are withheld regardless of repository settings.
2. Nothing here interpolates untrusted input into an interpreter. The trigger is
   a precondition; there is no ingress mechanism.

This fixture is the regression test for the single worst failure mode: a tool
that flags the modal job on GitHub gets uninstalled in five minutes and never
demonstrates the finding it exists for.
