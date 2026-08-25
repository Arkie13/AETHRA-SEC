"""Event vocabulary for the internal real-time event bus (§75).

Events decouple producers (capture worker, Snort reader, Nmap worker, database
monitor) from consumers (dashboard, screens, notification service). Every
payload is a plain dataclass so consumers never touch producer internals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from aethra_sec.models.enums import (
    EvidenceSource,
    NotificationLevel,
    ServiceState,
    Severity,
)
from aethra_sec.utils.timeutil import utcnow


class EventType:
    """Event name constants.

    Using a class of constants rather than an enum keeps subscriber code short
    (``bus.subscribe(EventType.SNORT_ALERT_RECEIVED, ...)``) while still giving
    one authoritative definition of the vocabulary.
    """

    # Capture pipeline
    CAPTURE_STARTED = "capture.started"
    CAPTURE_STOPPED = "capture.stopped"
    CAPTURE_ERROR = "capture.error"
    PACKET_BATCH_PROCESSED = "capture.packet_batch"
    TRAFFIC_STATS_UPDATED = "traffic.stats_updated"
    TRAFFIC_ANOMALY_DETECTED = "traffic.anomaly_detected"

    # Snort
    SNORT_ALERT_RECEIVED = "snort.alert_received"
    SNORT_STATUS_CHANGED = "snort.status_changed"

    # Nmap
    NMAP_SCAN_STARTED = "nmap.scan_started"
    NMAP_SCAN_PROGRESS = "nmap.scan_progress"
    NMAP_SCAN_COMPLETED = "nmap.scan_completed"
    NMAP_SCAN_FAILED = "nmap.scan_failed"

    # Correlation / mitigation
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    MITIGATION_GENERATED = "mitigation.generated"

    # Platform
    DATABASE_STATUS_CHANGED = "database.status_changed"
    SERVICE_STATUS_CHANGED = "service.status_changed"
    NOTIFICATION_RAISED = "notification.raised"
    REPORT_GENERATED = "report.generated"
    SYSTEM_ERROR = "system.error"
    HOST_OBSERVED = "host.observed"

    ALL: tuple[str, ...] = (
        CAPTURE_STARTED, CAPTURE_STOPPED, CAPTURE_ERROR,
        PACKET_BATCH_PROCESSED, TRAFFIC_STATS_UPDATED, TRAFFIC_ANOMALY_DETECTED,
        SNORT_ALERT_RECEIVED, SNORT_STATUS_CHANGED,
        NMAP_SCAN_STARTED, NMAP_SCAN_PROGRESS, NMAP_SCAN_COMPLETED,
        NMAP_SCAN_FAILED,
        INCIDENT_CREATED, INCIDENT_UPDATED, MITIGATION_GENERATED,
        DATABASE_STATUS_CHANGED, SERVICE_STATUS_CHANGED, NOTIFICATION_RAISED,
        REPORT_GENERATED, SYSTEM_ERROR, HOST_OBSERVED,
    )


@dataclass(frozen=True)
class Event:
    """Envelope delivered to subscribers."""

    type: str
    payload: Any = None
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True)
class ServiceStatusPayload:
    """A subsystem's observed state changed."""

    service: str
    state: ServiceState
    detail: str = ""
    observed_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True)
class CaptureStatusPayload:
    """Capture lifecycle transition, carrying the real interface name."""

    interface: str
    detail: str = ""
    packets_captured: int = 0
    started_at: datetime | None = None


@dataclass(frozen=True)
class PacketBatchPayload:
    """A processed batch of real packets handed to the UI for display.

    ``packets`` holds :class:`aethra_sec.models.traffic.CapturedPacket` values;
    the type is not imported here to keep this module dependency-light.
    """

    packets: tuple[Any, ...]
    total_captured: int
    dropped: int


@dataclass(frozen=True)
class TrafficStatsPayload:
    """Recomputed live traffic statistics.

    ``snapshot`` is a
    :class:`aethra_sec.analytics.traffic_analyzer.TrafficSnapshot`.
    """

    snapshot: Any


@dataclass(frozen=True)
class AnomalyPayload:
    """A deterministic traffic rule fired on real observations."""

    anomaly: Any  # aethra_sec.models.threat.TrafficAnomaly
    source: EvidenceSource = EvidenceSource.PYSHARK


@dataclass(frozen=True)
class SnortAlertPayload:
    """A real Snort alert was received and stored."""

    alert: Any  # aethra_sec.models.alert.SnortAlert


@dataclass(frozen=True)
class ScanProgressPayload:
    """Progress of a running Nmap assessment."""

    scan_id: int
    target: str
    status: str
    detail: str = ""
    hosts_found: int = 0
    elapsed_seconds: float = 0.0


@dataclass(frozen=True)
class ScanCompletedPayload:
    """A finished Nmap assessment, with counts taken from the real result."""

    scan_id: int
    target: str
    hosts_up: int
    open_ports: int
    findings: int
    duration_seconds: float


@dataclass(frozen=True)
class ScanFailedPayload:
    """A failed Nmap assessment and the actual error text."""

    scan_id: int | None
    target: str
    error: str


@dataclass(frozen=True)
class IncidentPayload:
    """An incident was created or updated by the correlation engine."""

    incident: Any  # aethra_sec.models.incident.Incident
    is_new: bool = False


@dataclass(frozen=True)
class MitigationPayload:
    """A mitigation recommendation was attached to an incident."""

    incident_id: int
    recommendation_id: int
    title: str
    severity: Severity


@dataclass(frozen=True)
class NotificationPayload:
    """An in-application notification for a genuine event."""

    title: str
    message: str
    level: NotificationLevel = NotificationLevel.INFO
    category: str = "system"
    reference_type: str = ""
    reference_id: int | None = None


@dataclass(frozen=True)
class ErrorPayload:
    """A subsystem failure worth surfacing to the operator."""

    component: str
    message: str
    detail: str = ""
