# A removed guardrail, not a held capability

The agent reads only base-branch content and holds no secret, so the U/P/E join
produces nothing. But `allowed_non_write_users: "*"` means **any** account —
including one created a minute ago — can invoke it.

That is not a capability the job holds; it is a boundary the job removed. It is
not exploitable alone, which is why it is a warning and not a critical, but it
enlarges the blast radius of anything else that lands in this job.

Maps to ADR's *Exploitation of Excessive Tool Permissions*, and to the wildcard
allowlist Trail of Bits called out in zizmor issue #1605.

Expected: WARNING under `tridelphi/agent-overbroad-tools`, strip target `P`.
