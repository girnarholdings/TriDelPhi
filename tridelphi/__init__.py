"""TriDelPhi — a static Agents Rule of Two checker for GitHub Actions."""

from .model import (
    AnalysisResult,
    CapabilityHit,
    Diagnostic,
    ExecutionContext,
    Finding,
    Position,
    RULES,
    Remediation,
    RepoInventory,
    RuleSpec,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "analyze",
    "analyze_to_sarif",
    "AnalysisResult",
    "CapabilityHit",
    "Diagnostic",
    "ExecutionContext",
    "Finding",
    "Position",
    "Remediation",
    "RepoInventory",
    "RuleSpec",
    "RULES",
]


def __getattr__(name: str):
    # Deferred so `import tridelphi` stays cheap and free of parser imports.
    if name in ("analyze", "analyze_to_sarif"):
        from . import api

        return getattr(api, name)
    raise AttributeError(name)
