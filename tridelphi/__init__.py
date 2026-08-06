"""TriDelPhi — a static Agents Rule of Two checker for GitHub Actions."""

from .model import (
    RULES,
    AnalysisResult,
    CapabilityHit,
    Diagnostic,
    ExecutionContext,
    Finding,
    Position,
    Remediation,
    RepoInventory,
    RuleSpec,
)

__version__ = "0.1.0"

__all__ = [
    "RULES",
    "AnalysisResult",
    "CapabilityHit",
    "Diagnostic",
    "ExecutionContext",
    "Finding",
    "Position",
    "Remediation",
    "RepoInventory",
    "RuleSpec",
    "__version__",
    "analyze",
    "analyze_to_sarif",
]


def __getattr__(name: str):
    # Deferred so `import tridelphi` stays cheap and free of parser imports.
    if name in ("analyze", "analyze_to_sarif"):
        from . import api

        return getattr(api, name)
    raise AttributeError(name)
