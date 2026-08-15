# OSS landscape — what exists, what we take, what we build

Prewalk for `tridelphi core`. Every claim here was checked against the live
project (Aug 2026), not from memory. The question this answers: **where is the
prior art, and what is genuinely ours?**

---

## 1. The one-line placement

`tridelphi core` is a **static "Agents Rule of Two" checker for CI jobs.**

Meta's [Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/)
(Oct 2025) says an agent may hold at most two of: untrusted input, sensitive
data/credentials, state change or external communication. Our U/P/E triad is
exactly that framing, applied to a GitHub Actions job as the unit of analysis
instead of a running agent. Microsoft's June 2026 write-up applied Rule of Two to
the Claude Code GitHub Action case specifically.

That matters for positioning: the rule is already a recognized, cited framework
with a name people know. **Nobody has shipped a static analyzer that enforces it
over a repo.** We are not inventing a heuristic — we are mechanizing an accepted
one. That is a much easier sell than "our proprietary risk score."

---

## 2. Prior art, ranked by how much it overlaps us

| Project | Lang / License | What it does | Overlap with `core` |
|---|---|---|---|
| [zizmor](https://github.com/zizmorcore/zizmor) | Rust / **MIT** | 40 audits over Actions YAML, SARIF out, offline by default | **Highest.** Per-rule, per-file. No cross-capability join. |
| [poutine](https://github.com/boostsecurityio/poutine) | Go / **Apache-2.0** | Multi-platform build-pipeline scanner, Rego rules, SARIF, build-dep SBOM | Medium. Rego rule engine is a real architectural idea for us. |
| [Raven](https://github.com/CycodeLabs/raven) | Python / Apache-2.0 | Downloads workflows org-wide, loads into **Neo4j**, runs graph queries | **Conceptually closest.** Actual graph model. But needs a DB + network. |
| [octoscan](https://github.com/synacktiv/octoscan) | Go / — | Offline static scanner: expression injection, dangerous checkout, `GITHUB_ENV` writes, shellcheck on `run:` | Medium. Closest to our offline posture. |
| [gato-x](https://github.com/AdnaneKhan/gato-x) | Python / — | Offensive: Pwn Requests, Actions Injection, TOCTOU, self-hosted runner takeover, cross-repo | Low-medium. Requires a token; it's a red-team tool. |
| [actionlint](https://github.com/rhysd/actionlint) | Go / **MIT** | General workflow linter with the best-maintained untrusted-input table | Low overlap, **high value as a data source.** |

### What none of them do — verified

I pulled zizmor's full audit list (40 rules). **Zero mention** of AI agents,
`CLAUDE.md`, `AGENTS.md`, MCP servers, or agent instruction files. Same for
poutine's rule set and octoscan's. The agent-config ingress class is unclaimed in
CI-scanner OSS.

The adjacent tools that *do* look at agent config — `mcp-scan`, AgentShield, the
"CLAUDE.md Security Auditor" — scan agent config **in isolation, on a developer
laptop**. None of them knows what a workflow is, which trigger reaches the file,
or whether the job holding that file also holds a secret. **The join is the
product.** That is exactly the moat KICKOFF.md flags as un-cuttable, and the
research confirms it is still open.

### Two structural gaps we exploit

1. **Everyone is per-finding; nobody is per-context.** zizmor tells you
   "template injection on line 14" and separately "excessive permissions on line
   3." It never says *these are the same job, and that's the exploit.* Our unit
   of output is the execution context, not the line.
2. **The graph tools need infrastructure.** Raven proves the graph idea works but
   requires downloading an org's workflows and standing up Neo4j. We do the same
   join in-process, offline, on one repo, in one command. That is a completely
   different adoption curve.

---

## 3. What we harvest (concrete, with licenses cleared)

These are real starting points, not inspiration.

### a. `actionlint`'s untrusted-input tree → `data/untrusted_contexts.yml`
MIT, attribution required. I pulled the live `BuiltinUntrustedInputs` from
`expr_insecure.go`. It is a **superset of the brief's §3 list** — it adds paths
we would have missed:

```
github.event.issue.title|body
github.event.pull_request.title|body
github.event.pull_request.head.ref|label
github.event.pull_request.head.repo.default_branch
github.event.comment.body
github.event.review.body
github.event.review_comment.body
github.event.discussion.title|body
github.event.pages.*.page_name
github.event.commits.*.message
github.event.commits.*.author.email|name
github.event.head_commit.message
github.event.head_commit.author.email|name
github.head_ref
```

Note the object-filter form (`github.event.*.body`, `commits.*.message`) — our
matcher needs to handle `*` segments or we miss real injections. That is a
design requirement the brief did not call out.

Upstream for the same data is [GitHub Security Lab's untrusted-input
research](https://securitylab.github.com/resources/github-actions-untrusted-input/)
and the CodeQL `ExpressionInjection.ql` query. actionlint tracks it most actively.

### b. OASIS SARIF 2.1.0 schema → `schema/sarif-2.1.0.json` ✅ vendored
110 KB, fetched from `oasis-tcs/sarif-spec`. **Gotcha found:** it is
`draft-04`, not a modern draft. `jsonschema` handles it, but the validator must
be selected from the `$schema` key rather than assuming Draft7/2020-12. Cheap to
get wrong in Phase A, and Phase A is the phase everything else hangs off.

### c. zizmor's fixture corpus → seeds for `tests/fixtures/`
MIT. Its integration tests contain minimal, known-bad workflows for
`pull_request_target`, template injection, and excessive permissions. The
adversary agent can adapt them for the U+P and U+E near-miss buckets rather than
inventing from scratch. **Exception:** the three named 2026 exploit fixtures must
be authored from the threat model, not borrowed — nothing upstream has them.

### d. Poutine's Rego idea → *rejected for v1, noted for v2*
Externalizing rules as Rego is genuinely better for a rule set that grows
weekly. But it adds OPA as a dependency and contradicts the brief's dep
allowlist. Our `data/*.yml` tables get most of the tunability at none of the
cost. Revisit when the rule count passes ~15.

---

## 4. Toolchain checks — already run

- Python **3.11.15** present.
- `ruamel.yaml 0.19.1`, `jsonschema 4.26.0`, `pytest` all install clean in a venv.
- The dependency allowlist in the brief (§2.3) holds. **No graph library needed.**
  At the time of this prewalk the model was one flat list of contexts with no
  edges; it has since grown them — `needs:` propagation and the artifact taint
  channel (`DECISIONS.md` §3, and detection case D3). The conclusion survived the
  change: the edges are a few dozen lines of in-process adjacency, and pulling in
  a graph library (or a Neo4j server, as Raven does) would cost the offline
  guarantee for nothing.

---

## 5. What the prewalk changes about the plan

Four deltas against the brief, all small:

1. **Package/CLI naming.** Package `tridelphi/`, entry point `tridelphi`,
   subcommand `core`, rule IDs `tridelphi/u-p-e-intersection` and
   `tridelphi/two-of-three`. Applied throughout the brief and subagent files.
2. **The U matcher needs glob segments** (`github.event.*.body`) — see 3a.
   Feeds `capability-detective`'s table format.
3. **Pin the SARIF validator to draft-04** — see 3b.
4. **Lead with Rule of Two in the README.** Free credibility; costs one
   paragraph.

Everything else in the brief survives contact with the research. Scope,
phase order, and the frozen interfaces stand.

---

## 6. Risk this prewalk did *not* retire

The brief's own pre-mortem flags the wrapper problem. Research sharpens it:
zizmor is MIT, actively developed, has 40 rules and real adoption. **If zizmor
adds one `agent-ingress` audit, our per-rule advantage evaporates overnight.**

What does not evaporate is the *context-level join* and the SARIF shape that
carries it. So the defensibility ordering is:

1. The capability-graph output format (the thing others would have to adopt).
2. The agent-config ingress detector (the finding nobody else has today).
3. Per-rule detection quality (commodity — assume it gets copied).

Build in that order, which is what Phases A→E already do.

---

## Sources

- [zizmor](https://github.com/zizmorcore/zizmor) · [audit list](https://docs.zizmor.sh/audits/) · MIT
- [poutine](https://github.com/boostsecurityio/poutine) · [announcement](https://labs.boostsecurity.io/articles/unveiling-poutine-an-open-source-build-pipelines-security-scanner/)
- [Raven](https://github.com/CycodeLabs/raven) · [Cycode announcement](https://cycode.com/blog/introducing-raven/)
- [octoscan](https://github.com/synacktiv/octoscan) · [gato-x](https://github.com/AdnaneKhan/gato-x)
- [actionlint `expr_insecure.go`](https://github.com/rhysd/actionlint/blob/main/expr_insecure.go) · [checks docs](https://github.com/rhysd/actionlint/blob/main/docs/checks.md)
- [GitHub Security Lab — untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/)
- [Meta — Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/) · [Simon Willison's writeup](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- [CSA — Claude Code GitHub Action prompt injection](https://labs.cloudsecurityalliance.org/research/csa-research-note-claude-code-github-action-prompt-injection/)
- [OASIS SARIF 2.1.0 schema](https://github.com/oasis-tcs/sarif-spec)
