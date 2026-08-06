# Two-capability fixtures

Holding exactly two capabilities is **compliant** with the Agents Rule of Two.
These fixtures therefore assert *proximity*, not presence: each is one small,
hard-to-review edit away from critical, and the tool must name which capability
to strip.

| Fixture | Shape | Expected strip |
|---|---|---|
| `up-no-egress` | untrusted checkout + secret, no shell and only read-only actions | `U` — drop the `ref:` |
| `ue-no-privilege` | untrusted checkout + shell, secret defined in a sibling job | `U` — drop the `ref:` |

secrets and a read-only token, so privilege looked absent, while a non-ephemeral
runner means compromise persists across jobs and reaches other jobs' caches and
credentials.
