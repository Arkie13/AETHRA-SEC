"""Snort IDS alert models (§21-§23).

Nothing in this module creates an alert. Instances exist only when a real Snort
sensor emitted one over the configured transport.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from aethra_sec.models.enums import (
    AlertStatus,
    EvaluationLabel,
    EvidenceSource,
    Severity,
)


@dataclass
class SnortAlert:
    """One alert received from Snort.

    Attributes:
        alert_time: the timestamp Snort assigned to the event. When the
            transport does not carry one (rare), ``received_at`` is used and
            ``time_source`` records that fact, so detection-time measurements
            stay honest (§80, §81).
        generator_id: Snort GID.
        signature_id: Snort SID.
        revision: signature revision.
        priority: Snort priority (1 = most severe).
        raw_alert: the exact bytes/text received, retained as evidence.
    """

    id: int | None = None
    alert_time: datetime | None = None
    received_at: datetime | None = None
    time_source: str = "snort"
    generator_id: int | None = None
    signature_id: int | None = None
    revision: int | None = None
    message: str = ""
    classification: str = ""
    priority: int | None = None
    severity: Severity = Severity.MEDIUM
    protocol: str = ""
    src_ip: str = ""
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    interface: str = ""
    sensor: str = ""
    transport: str = ""
    raw_alert: str = ""
    src_host_id: int | None = None
    dst_host_id: int | None = None
    incident_id: int | None = None
    status: AlertStatus = AlertStatus.NEW
    evaluation: EvaluationLabel = EvaluationLabel.UNCLASSIFIED
    evaluated_by: int | None = None
    evaluated_at: datetime | None = None
    duplicate_count: int = 1
    dedup_key: str = ""
    source: EvidenceSource = EvidenceSource.SNORT
    created_at: datetime | None = None

    @property
    def signature_text(self) -> str:
        """``[1:2001219:19]`` style signature identity."""
        gid = self.generator_id if self.generator_id is not None else "?"
        sid = self.signature_id if self.signature_id is not None else "?"
        rev = self.revision if self.revision is not None else "?"
        return f"[{gid}:{sid}:{rev}]"

    @property
    def effective_time(self) -> datetime | None:
        """Best available event timestamp for ordering and correlation."""
        return self.alert_time or self.received_at

    @property
    def detection_latency_seconds(self) -> float | None:
        """Seconds between Snort's event time and our ingest time.

        ``None`` when Snort supplied no timestamp - the value is measured, not
        estimated (§81).
        """
        if self.alert_time is None or self.received_at is None:
            return None
        return max(0.0, (self.received_at - self.alert_time).total_seconds())

    @property
    def summary(self) -> str:
        """One-line description used in tables and notifications."""
        endpoints = ""
        if self.src_ip and self.dst_ip:
            src = f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip
            dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip
            endpoints = f" {src} -> {dst}"
        return f"{self.message or 'Snort alert'}{endpoints}"


@dataclass
class AlertClassificationStat:
    """Aggregated alert reliability counters (§84)."""

    received: int = 0
    stored: int = 0
    duplicates: int = 0
    parse_failures: int = 0
    correlated: int = 0
    unresolved: int = 0

    @property
    def processed(self) -> int:
        """Alerts that were parsed and stored successfully."""
        return self.stored

    @property
    def failure_rate(self) -> float:
        """Percentage of received alerts that could not be parsed."""
        return (self.parse_failures / self.received * 100.0) if self.received else 0.0


@dataclass
class SnortStatus:
    """Observed state of the Snort ingest path.

    Every field reflects a real observation; the UI shows "Snort unavailable"
    whenever ``is_connected`` is false rather than implying a running sensor.
    """

    transport: str = "disabled"
    endpoint: str = ""
    is_connected: bool = False
    started_at: datetime | None = None
    last_alert_at: datetime | None = None
    alerts_received: int = 0
    parse_failures: int = 0
    last_error: str = ""
    detail: str = ""

    @property
    def status_text(self) -> str:
        """Status label for the dashboard indicator."""
        if self.transport == "disabled":
            return "DISABLED"
        if self.is_connected:
            return "RUNNING"
        return "OFFLINE"
