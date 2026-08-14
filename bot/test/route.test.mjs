// Routing tests. The Worker decides *whether* to spend a runner minute and
// *whose* repository to spend it on, so these are the rules worth pinning down.
// Pure functions, no network, no wrangler: `node test/route.test.mjs`.

import assert from "node:assert";
import { parseAllowlist, route } from "../src/route.js";

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`  ok  ${name}`);
}

const ALLOW = parseAllowlist("acme/demo");
const repository = { name: "demo", full_name: "acme/demo", owner: { login: "acme" }, default_branch: "main" };

// Merge nested overrides rather than replacing them: spreading `over` last
// would clobber the whole pull_request object and silently drop its number,
// which makes every case look like a refusal for the wrong reason.
// Default is a same-repo PR (head.repo == the repo). Fork/deleted-fork cases
// override `pull_request.head`.
const prEvent = ({ pull_request, ...rest } = {}) => ({
  action: "opened",
  repository,
  ...rest,
  pull_request: {
    number: 7,
    base: { ref: "main" },
    head: { repo: { full_name: "acme/demo" } },
    ...pull_request,
  },
});

const commentEvent = ({ comment, ...rest } = {}) => ({
  action: "created",
  repository,
  issue: { number: 12, pull_request: { url: "..." } },
  ...rest,
  comment: { body: "please tridelphi fix this", author_association: "OWNER", ...comment },
});

// --- the allowlist is the blast radius -------------------------------------

await test("refuses to dispatch when no allowlist is configured", async () => {
  const d = route("pull_request", prEvent(), { allowlist: parseAllowlist("") });
  assert.equal(d.act, "ignore");
  assert.match(d.reason, /no ALLOWED_REPOS/);
});

await test("refuses a repository that is not allowlisted", async () => {
  const other = { ...prEvent(), repository: { name: "elsewhere", owner: { login: "stranger" } } };
  const d = route("pull_request", other, { allowlist: ALLOW });
  assert.equal(d.act, "ignore");
  assert.match(d.reason, /not allowlisted/);
});

await test("allowlist matching is case-insensitive", async () => {
  const d = route("pull_request", prEvent(), { allowlist: parseAllowlist("ACME/Demo") });
  assert.equal(d.act, "scan");
});

// --- only spend a runner minute on events that changed code ----------------

await test("scans on opened, synchronize, reopened", async () => {
  for (const action of ["opened", "synchronize", "reopened"]) {
    const d = route("pull_request", prEvent({ action }), { allowlist: ALLOW });
    assert.equal(d.act, "scan", action);
    assert.equal(d.pr, 7);
  }
});

await test("ignores pull-request noise that changes no code", async () => {
  for (const action of ["labeled", "assigned", "edited", "closed"]) {
    const d = route("pull_request", prEvent({ action }), { allowlist: ALLOW });
    assert.equal(d.act, "ignore", action);
  }
});

await test("ignores a draft until it is marked ready", async () => {
  const draft = route("pull_request", prEvent({ pull_request: { draft: true } }), { allowlist: ALLOW });
  assert.equal(draft.act, "ignore");
  const ready = route(
    "pull_request",
    prEvent({ action: "ready_for_review", pull_request: { draft: true } }),
    { allowlist: ALLOW },
  );
  assert.equal(ready.act, "scan");
});

// --- the dispatch must be able to find the pull request --------------------

await test("dispatches against the base branch, carrying the PR number", async () => {
  // A fork's head branch does not exist in this repository, so the ref must be
  // the base; the number is what lets the run check the right tree out.
  const d = route("pull_request", prEvent({ pull_request: { base: { ref: "release" } } }), { allowlist: ALLOW });
  assert.equal(d.ref, "release");
  assert.equal(d.pr, 7);
});

await test("refuses to dispatch a fork's pull request", async () => {
  // A dispatched run checks the PR out and then runs `uses: ./` from that same
  // tree, so a fork's code would execute with the job's write scopes. The
  // pull_request trigger scans forks with a read-only token instead.
  const fork = prEvent({ pull_request: { head: { repo: { full_name: "stranger/demo" } } } });
  const d = route("pull_request", fork, { allowlist: ALLOW });
  assert.equal(d.act, "ignore");
  assert.match(d.reason, /fork/);
});

await test("still dispatches a branch of the same repository", async () => {
  const own = prEvent({ pull_request: { head: { repo: { full_name: "acme/demo" } } } });
  assert.equal(route("pull_request", own, { allowlist: ALLOW }).act, "scan");
});

await test("treats a deleted fork (null head repo) as a fork, not same-repo", async () => {
  // When the source fork is deleted, head.repo is null. Fail closed rather than
  // let a missing head be mistaken for a trusted branch.
  const deleted = prEvent({ pull_request: { head: { repo: null } } });
  const d = route("pull_request", deleted, { allowlist: ALLOW });
  assert.equal(d.act, "ignore");
  assert.match(d.reason, /fork/);
});

// --- the control plane never dispatches fixes ------------------------------

await test("never dispatches a fix — the in-repo workflow owns that path", async () => {
  // A workflow_dispatch of the fix job would run WITHOUT the comment-body trust
  // gate the issue_comment workflow enforces, so the Worker must never route a
  // fix. Every issue_comment — maintainer or not, created or edited — is left
  // to the native workflow.
  const cases = [
    commentEvent(),
    commentEvent({ action: "edited" }),
    commentEvent({ comment: { author_association: "NONE" } }),
    commentEvent({ comment: { body: "<!--tridelphi-fix--> [x]", author_association: "NONE" } }),
  ];
  for (const ev of cases) {
    const d = route("issue_comment", ev, { allowlist: ALLOW });
    assert.equal(d.act, "ignore");
    assert.match(d.reason, /in-repo issue_comment workflow/);
  }
});

// --- malformed input must be a named refusal, never a throw ----------------

await test("survives payloads missing the fields it reads", async () => {
  for (const bad of [{}, { repository: {} }, { repository: { owner: {} } }, null]) {
    const d = route("pull_request", bad, { allowlist: ALLOW });
    assert.equal(d.act, "ignore");
    assert.ok(d.reason);
  }
});

await test("ignores event types the bot does not act on", async () => {
  for (const ev of ["push", "star", "", undefined]) {
    const d = route(ev, prEvent(), { allowlist: ALLOW });
    assert.equal(d.act, "ignore", String(ev));
  }
});

console.log(`\n${passed} tests passed`);
