"""Traffic-analysis anomaly models (§24).

These records describe *observations*, not confirmed attacks. The wording used
throughout ("Potential ...", "... behaviour detected", "Traffic anomaly") is
deliberate: a deterministic threshold rule provides evidence, not proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.models.enums import (
    EvaluationLabel,
    EvidenceSource,
    Severity,
    ThreatCategory,
)


@dataclass
class TrafficAnomaly:
    """A deterministic traffic rule that fired on real observations.

    Attributes:
        rule_id: stable identifier of the rule that fired.
        observation: exactly what was measured, in plain language.
        why_it_matters: educational explanation (§53).
        what_to_check: the analyst's next step.
        evidence: measured values (counts, rates, window length, thresholds).
        observed_value / threshold_value: the numbers behind the decision, so
            the operator can audit the judgement instead of trusting it.
    """

    id: int | None = None
    rule_id: str = ""
    category: ThreatCategory = ThreatCategory.UNCLASSIFIED
    title: str = ""
    observation: str = ""
    why_it_matters: str = ""
    what_to_check: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    protocol: str = ""
    interface: str = ""
    observed_value: float = 0.0
    threshold_value: float = 0.0
    window_seconds: int = 0
    event_count: int = 1
    #: T2 - the instant the rule crossed its threshold, taken from the
    #: clock at that moment. Distinct from ``created_at``, which is when
    #: the row reached the database: without both, a slow detection and a
    #: slow write are indistinguishable.
    detected_at: datetime | None = None
    #: When an analyst marked this reviewed. A read receipt, deliberately
    #: separate from ``evaluation``: being looked at is not a verdict, and
    #: the evaluation labels feed the detection-accuracy statistics.
    reviewed_at: datetime | None = None
    reviewed_by: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    host_id: int | None = None
    incident_id: int | None = None
    evaluation: EvaluationLabel = EvaluationLabel.UNCLASSIFIED
    source: EvidenceSource = EvidenceSource.PYSHARK
    created_at: datetime | None = None

    @property
    def dedup_key(self) -> str:
        """Key used to suppress repeat records inside the suppression window."""
        return f"{self.rule_id}|{self.src_ip}|{self.dst_ip}|{self.dst_port or ''}"

    @property
    def summary(self) -> str:
        """One-line description for tables and the threat timeline."""
        if self.src_ip and self.dst_ip:
            return f"{self.title}: {self.src_ip} -> {self.dst_ip}"
        if self.src_ip:
            return f"{self.title}: {self.src_ip}"
        return self.title

    def evidence_lines(self) -> tuple[str, ...]:
        """Evidence rendered as readable ``key: value`` lines."""
        return tuple(f"{key}: {value}" for key, value in sorted(self.evidence.items()))


@dataclass
class DetectionRuleDefinition:
    """Static description of a deterministic detection rule.

    Used by the Help screen and by reports to explain *how* a detection was
    made, which is a stated requirement of the educational design (§53, §86).
    """

    rule_id: str
    title: str
    category: ThreatCategory
    description: str
    threshold_setting: str
    window_setting: str
    base_severity: Severity
    why_it_matters: str
    what_to_check: str
    source: EvidenceSource = EvidenceSource.PYSHARK


@dataclass
class ThreatSummary:
    """Counts used by the dashboard security overview, all query-derived."""

    active_incidents: int = 0
    #: No ``critical_alerts``: CRITICAL is outside the detection severity
    #: model, so a field for it could only ever hold zero.
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    info_alerts: int = 0
    open_findings: int = 0
    anomalies_today: int = 0
    unresolved_incidents: int = 0

    @property
    def total_alerts(self) -> int:
        """Total alerts across all severities in the queried window."""
        return (
            self.high_alerts
            + self.medium_alerts
            + self.low_alerts
            + self.info_alerts
        )

    @property
    def has_data(self) -> bool:
        """False when nothing has been recorded yet."""
        return bool(
            self.total_alerts
            or self.active_incidents
            or self.open_findings
            or self.anomalies_today
        )
