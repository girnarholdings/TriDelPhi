from __future__ import annotations

import runpy
from datetime import date


def test_agent_signal_evidence_is_current(repo_root):
    namespace = runpy.run_path(str(repo_root / "scripts" / "check-agent-signals.py"))
    assert namespace["review_errors"](today=date(2026, 9, 1), max_age_days=120) == []
