# False-positive budget

A typical unhardened application repo: 5 workflows, 8 jobs, mostly with no
`permissions:` block. Nothing here is exploitable.

The old spec produced CRITICAL on the CI jobs, the docs job, and the CodeQL job
— including GitHub's own recommended CodeQL workflow — because it assumed
write-all permissions and treated a fork-reachable trigger as untrusted input.

Budget asserted by `test_false_positive_budget`: **zero criticals**, and at most
15% of jobs carrying any finding. Self-authored malicious fixtures cannot catch
over-firing; only a corpus of ordinary code can, and this is the smallest
version of that corpus. `scripts/corpus.py` runs the same budget over real
cloned repositories.
