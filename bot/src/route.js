// Routing — the Worker's entire brain, kept pure so it can be tested without a
// network, a token, or a Worker runtime.
//
// The split this file enforces: the **control plane** (this Worker) decides
// *whether* something should run and *for which repository*. The **execution
// plane** (GitHub Actions) does the work, because it is the only side that can
// check out a repository and run a Python analyzer.
//
// Consequences that matter, and are the point of the separation:
//   · the Worker never needs `contents` access — it reads no files, ever;
//   · it reads a handful of payload fields and ignores the rest, so a change in
//     an unrelated corner of GitHub's schema cannot alter its behaviour;
//   · every rejection is a named reason, so the log says why rather than going
//     quiet.

// Pull-request activity worth a fresh scan. Anything else (labels, assignees,
// draft toggles, edits to the description) changes no code and must not burn a
// runner minute.
const SCAN_ACTIONS = new Set(["opened", "synchronize", "reopened", "ready_for_review"]);

/** Parse "owner/repo, owner/other" into a lower-cased Set. */
export function parseAllowlist(raw) {
  return new Set(
    String(raw || "")
      .split(/[,\s]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

/**
 * Decide what a delivery should cause. Pure: no I/O, no clock, no randomness.
 *
 * Returns `{ act, reason, owner, repo, ref, pr }` where `act` is one of
 * "scan" | "fix" | "ignore". Callers dispatch only on the first two.
 */
export function route(eventType, payload, { allowlist } = {}) {
  const ignore = (reason) => ({ act: "ignore", reason });

  const repository = payload?.repository;
  const owner = repository?.owner?.login;
  const repo = repository?.name;
  if (!owner || !repo) return ignore("payload names no repository");

  // Fail closed. A hosted bot with no allowlist would dispatch into any
  // repository whose webhook happens to carry the shared secret; for a security
  // tool that default is indefensible, so an unset allowlist dispatches nothing
  // and says so instead of quietly serving everyone.
  const allowed = allowlist instanceof Set ? allowlist : parseAllowlist(allowlist);
  if (allowed.size === 0) return ignore("no ALLOWED_REPOS configured; refusing to dispatch");
  if (!allowed.has(`${owner}/${repo}`.toLowerCase())) return ignore(`${owner}/${repo} is not allowlisted`);

  if (eventType === "pull_request") {
    if (!SCAN_ACTIONS.has(payload.action)) return ignore(`pull_request.${payload.action} changes no code`);
    const pr = payload.pull_request;
    if (!pr?.number) return ignore("pull_request has no number");
    if (pr.draft && payload.action !== "ready_for_review") return ignore("pull request is a draft");
    // Fork pull requests are deliberately not dispatched. A dispatched run
    // checks the pull request out and then runs the repository's own action
    // from that same tree, so a fork's code would execute with the job's write
    // scopes. The `pull_request` trigger already scans forks with a read-only
    // token, which is where a stranger's code belongs. The workflow refuses
    // these too; catching it here just avoids burning a run to be told so.
    // Fail closed: a MISSING head repo (a deleted fork) is treated as a fork,
    // not as same-repo. Requiring a positive same-repo match means an absent or
    // unexpected head can never be mistaken for a trusted branch.
    const headRepo = pr.head?.repo?.full_name;
    const thisRepo = repository.full_name || `${owner}/${repo}`;
    if (!headRepo || headRepo.toLowerCase() !== String(thisRepo).toLowerCase()) {
      return ignore("pull request is from a fork (or a deleted fork); the pull_request trigger scans it read-only");
    }
    return {
      act: "scan",
      reason: `pull_request.${payload.action}`,
      owner,
      repo,
      pr: pr.number,
      // workflow_dispatch needs a ref that exists in THIS repository. A fork's
      // head branch does not, so dispatch against the base branch and let the
      // run check the pull request out by number.
      ref: pr.base?.ref || repository.default_branch || "main",
    };
  }

  if (eventType === "issue_comment") {
    // Fix requests are handled ENTIRELY by the in-repo `tridelphi-fix.yml`
    // workflow, which triggers on the issue_comment event directly and gates on
    // the comment body plus author_association (and re-verifies write access).
    // The control plane deliberately stays out of the fix path: a
    // workflow_dispatch would run the fix job WITHOUT that comment-body trust
    // gate, so dispatching fixes from here would be a way to bypass it. That is
    // also why tridelphi-fix.yml has no workflow_dispatch trigger.
    return ignore("fix requests are handled by the in-repo issue_comment workflow, not the control plane");
  }

  return ignore(`${eventType || "unknown"} is not an event this bot acts on`);
}

export { SCAN_ACTIONS };
