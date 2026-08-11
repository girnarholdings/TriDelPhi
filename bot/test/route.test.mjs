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
const repository = { name: "demo", owner: { login: "acme" }, default_branch: "main" };

// Merge nested overrides rather than replacing them: spreading `over` last
// would clobber the whole pull_request object and silently drop its number,
// which makes every case look like a refusal for the wrong reason.
const prEvent = ({ pull_request, ...rest } = {}) => ({
  action: "opened",
  repository,
  ...rest,
  pull_request: { number: 7, base: { ref: "main" }, ...pull_request },
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

// --- the fix path carries the same trust rule as the in-repo workflow ------

await test("routes a maintainer's fix request", async () => {
  const d = route("issue_comment", commentEvent(), { allowlist: ALLOW });
  assert.equal(d.act, "fix");
  assert.equal(d.pr, 12);
});

await test("refuses a fix request from an untrusted commenter", async () => {
  for (const who of ["NONE", "FIRST_TIME_CONTRIBUTOR", "CONTRIBUTOR", undefined]) {
    const d = route("issue_comment", commentEvent({ comment: { author_association: who } }), { allowlist: ALLOW });
    assert.equal(d.act, "ignore", String(who));
    assert.match(d.reason, /not a maintainer/);
  }
});

await test("ignores a fix phrase on a plain issue, not a pull request", async () => {
  const onIssue = { ...commentEvent(), issue: { number: 3 } };
  const d = route("issue_comment", onIssue, { allowlist: ALLOW });
  assert.equal(d.act, "ignore");
  assert.match(d.reason, /not a pull request/);
});

await test("ignores an edited comment on the dispatch path", async () => {
  // Editing is how a checkbox tick arrives; that path is handled inside the
  // repository by the fix workflow, which re-verifies write access. The Worker
  // deliberately does not widen its own trigger to match.
  const d = route("issue_comment", commentEvent({ action: "edited" }), { allowlist: ALLOW });
  assert.equal(d.act, "ignore");
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
