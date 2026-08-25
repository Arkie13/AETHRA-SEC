"""Correlated incident models (§27, §44)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.models.enums import (
    EvaluationLabel,
    EvidenceSource,
    IncidentStatus,
    Severity,
    ThreatCategory,
)


@dataclass
class IncidentEvent:
    """One piece of evidence attached to an incident.

    ``source`` records which subsystem produced it, so the investigation view
    can state exactly what confirmed what (§78, §96).
    """

    id: int | None = None
    incident_id: int | None = None
    source: EvidenceSource = EvidenceSource.CORRELATION
    event_type: str = ""
    reference_table: str = ""
    reference_id: int | None = None
    occurred_at: datetime | None = None
    summary: str = ""
    detail: str = ""
    created_at: datetime | None = None


@dataclass
class IncidentNote:
    """An analyst's investigation note."""

    id: int | None = None
    incident_id: int | None = None
    user_id: int | None = None
    username: str = ""
    note: str = ""
    created_at: datetime | None = None


@dataclass
class RiskAssessment:
    """A transparent, explainable severity calculation (§28).

    Attributes:
        score: total points accumulated by the scoring rules.
        severity: the level the score maps to.
        factors: ``(factor name, points, explanation)`` for every contribution,
            so the operator can audit exactly why a severity was assigned.
    """

    score: int = 0
    severity: Severity = Severity.INFO
    confidence: int = 0
    factors: tuple[tuple[str, int, str], ...] = ()

    def explanation_lines(self) -> tuple[str, ...]:
        """Readable ``+N  factor - explanation`` lines."""
        return tuple(
            f"+{points:<3} {name} - {reason}" for name, points, reason in self.factors
        )


@dataclass
class Incident:
    """A correlated threat incident built only from real evidence.

    Attributes:
        evidence_sources: which subsystems contributed. An incident supported
            by a single source says so explicitly instead of implying
            multi-source confirmation (§78).
        confidence: 0-100, derived from evidence count and source diversity.
    """

    id: int | None = None
    reference: str = ""
    title: str = ""
    description: str = ""
    category: ThreatCategory = ThreatCategory.UNCLASSIFIED
    severity: Severity = Severity.MEDIUM
    confidence: int = 0
    status: IncidentStatus = IncidentStatus.NEW
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    protocol: str = ""
    affected_host_id: int | None = None
    affected_host_ip: str = ""
    affected_service: str = ""
    correlation_key: str = ""
    evidence_sources: tuple[EvidenceSource, ...] = ()
    event_count: int = 0
    snort_alert_count: int = 0
    anomaly_count: int = 0
    finding_count: int = 0
    risk_score: int = 0
    risk_rationale: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    resolved_at: datetime | None = None
    assigned_user_id: int | None = None
    assigned_username: str = ""
    mitigation_id: int | None = None
    evaluation: EvaluationLabel = EvaluationLabel.UNCLASSIFIED
    evaluated_by: int | None = None
    evaluated_at: datetime | None = None
    #: When this incident was first opened in the investigation view, and by
    #: whom. ``None`` means nobody has read it yet, which is what the sidebar
    #: counter counts.
    viewed_at: datetime | None = None
    viewed_by: int | None = None
    detection_latency_seconds: float | None = None
    events: list[IncidentEvent] = field(default_factory=list)
    notes: list[IncidentNote] = field(default_factory=list)

    @property
    def source_label(self) -> str:
        """Exactly which subsystems support this incident."""
        if not self.evidence_sources:
            return "No evidence recorded"
        if len(self.evidence_sources) == 1:
            return f"{self.evidence_sources[0].label} only"
        return " + ".join(source.label for source in self.evidence_sources)

    @property
    def is_multi_source(self) -> bool:
        """True when more than one subsystem contributed evidence."""
        return len(set(self.evidence_sources)) > 1

    @property
    def duration_seconds(self) -> float | None:
        """Span between first and last evidence, when both are known."""
        if not self.first_seen or not self.last_seen:
            return None
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    @property
    def endpoint_text(self) -> str:
        """``src -> dst:port`` description of the incident's traffic."""
        if not self.src_ip and not self.dst_ip:
            return "-"
        destination = self.dst_ip or "?"
        if self.dst_port:
            destination = f"{destination}:{self.dst_port}"
        return f"{self.src_ip or '?'} -> {destination}"
