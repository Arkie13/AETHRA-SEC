"""Deterministic analytics: traffic statistics, detection rules, risk scoring.

Everything in this package is pure computation over observed data - no I/O, no
randomness, no machine learning (§87). The same inputs always produce the same
outputs, which is what makes the resulting severities auditable.
"""

from __future__ import annotations

from aethra_sec.analytics.risk_engine import (
    RiskEngine,
    ThreatEvidence,
    explain_severity,
)

__all__ = ["RiskEngine", "ThreatEvidence", "explain_severity"]
