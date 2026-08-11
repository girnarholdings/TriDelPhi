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

// The typed request that also drives the in-repo fix bot. Matching the same
// phrase keeps one vocabulary across both entry points.
const FIX_PHRASE = "tridelphi fix";

// Comment authors GitHub itself vouches for as already trusted by the repo.
// This mirrors the fix workflow's own gate rather than inventing a second,
// looser rule — two different answers to "who is trusted" is how gaps appear.
const TRUSTED_ASSOCIATIONS = new Set(["OWNER", "MEMBER", "COLLABORATOR"]);

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
    if (payload.action !== "created") return ignore(`issue_comment.${payload.action} is not a new request`);
    const issue = payload.issue;
    if (!issue?.pull_request) return ignore("comment is on an issue, not a pull request");
    const body = String(payload.comment?.body || "");
    if (!body.toLowerCase().includes(FIX_PHRASE)) return ignore("comment does not request a fix");
    if (!TRUSTED_ASSOCIATIONS.has(payload.comment?.author_association)) {
      return ignore(`comment author is ${payload.comment?.author_association || "unknown"}, not a maintainer`);
    }
    return {
      act: "fix",
      reason: "issue_comment requesting fix",
      owner,
      repo,
      pr: issue.number,
      ref: repository.default_branch || "main",
    };
  }

  return ignore(`${eventType || "unknown"} is not an event this bot acts on`);
}

export { SCAN_ACTIONS, FIX_PHRASE, TRUSTED_ASSOCIATIONS };
