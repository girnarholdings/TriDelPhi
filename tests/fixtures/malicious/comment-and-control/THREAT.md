# Comment-and-Control

Mirrors the CSA "Comment and Control" disclosure (Apr 2026).

Any GitHub account can comment on any public issue. The comment body is
interpolated straight into the agent's prompt, the job holds an API key and a
write-scoped token, and the agent is started with `Bash` and `WebFetch` enabled.

- **U** `github.event.comment.body` reaches an interpreter, and the agent runs
  on a trigger any outsider can fire.
- **P** `secrets.ANTHROPIC_API_KEY` plus `contents: write`.
- **E** the agent's own `Bash`/`WebFetch` tools.

Expected: one CRITICAL. `issue_comment` is in the privileged-untrusted set, so
secrets really are available to the attacker here.
