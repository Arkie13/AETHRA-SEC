"""System, diagnostics, notification and reporting models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from aethra_sec.models.enums import (
    CheckResult,
    ExportFormat,
    NotificationLevel,
    ReportType,
    ServiceState,
)


@dataclass
class SystemSetting:
    """One administrator-tunable setting persisted in ``system_settings``."""

    key: str
    value: str
    value_type: str = "str"
    category: str = "general"
    description: str = ""
    updated_by: int | None = None
    updated_at: datetime | None = None

    def typed_value(self) -> Any:
        """Convert the stored string to its declared type.

        Malformed stored values fall back to the raw string rather than
        raising, so one bad row cannot prevent the application from starting.
        """
        raw = self.value
        try:
            if self.value_type == "int":
                return int(raw)
            if self.value_type == "float":
                return float(raw)
            if self.value_type == "bool":
                return str(raw).strip().lower() in {"1", "true", "yes", "on"}
        except (TypeError, ValueError):
            return raw
        return raw


@dataclass
class ServiceStatus:
    """Observed state of one subsystem (§10).

    A status is only ever written from a real probe. ``ServiceState.UNKNOWN``
    is used before the first probe rather than assuming health.
    """

    name: str
    state: ServiceState = ServiceState.UNKNOWN
    detail: str = ""
    last_checked: datetime | None = None
    last_success: datetime | None = None
    last_error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_healthy(self) -> bool:
        """True only for states that represent a working subsystem."""
        return self.state.is_healthy

    @property
    def display_state(self) -> str:
        """Status text for the dashboard indicator."""
        return str(self.state)


@dataclass
class DiagnosticCheck:
    """One row on the System Diagnostics page (§71)."""

    name: str
    category: str
    result: CheckResult
    summary: str
    detail: str = ""
    remedy: str = ""
    checked_at: datetime | None = None

    @property
    def passed(self) -> bool:
        """True when the check passed outright."""
        return self.result is CheckResult.PASS


@dataclass
class DiagnosticsReport:
    """The full diagnostics run."""

    generated_at: datetime
    checks: tuple[DiagnosticCheck, ...] = ()

    @property
    def passed(self) -> int:
        """Number of checks that passed."""
        return sum(1 for c in self.checks if c.result is CheckResult.PASS)

    @property
    def warnings(self) -> int:
        """Number of checks that produced a warning."""
        return sum(1 for c in self.checks if c.result is CheckResult.WARNING)

    @property
    def failures(self) -> int:
        """Number of checks that failed."""
        return sum(1 for c in self.checks if c.result is CheckResult.FAIL)

    @property
    def is_ready(self) -> bool:
        """True when no check failed outright."""
        return self.failures == 0


@dataclass
class Notification:
    """An in-application notification raised by a genuine event (§52)."""

    id: int | None = None
    user_id: int | None = None
    level: NotificationLevel = NotificationLevel.INFO
    title: str = ""
    message: str = ""
    category: str = "system"
    reference_type: str = ""
    reference_id: int | None = None
    is_read: bool = False
    created_at: datetime | None = None
    read_at: datetime | None = None

    @property
    def display_message(self) -> str:
        """The message with any correlation key removed.

        A service that deduplicates its alerts stores the key it correlates on
        after an invisible marker. It is an implementation detail of the
        deduplication and has no business on an operator's screen.
        """
        return str(self.message or "").split("⁣", 1)[0].rstrip()


@dataclass
class AppError:
    """A recorded subsystem failure (§57, §58)."""

    id: int | None = None
    component: str = ""
    message: str = ""
    detail: str = ""
    severity: str = "ERROR"
    occurred_at: datetime | None = None
    acknowledged: bool = False


@dataclass
class ReportRecord:
    """Metadata for a generated report (§95 - report auditability)."""

    id: int | None = None
    report_type: ReportType = ReportType.SECURITY_ASSESSMENT
    title: str = ""
    export_format: ExportFormat = ExportFormat.PDF
    file_path: str = ""
    period_start: datetime | None = None
    period_end: datetime | None = None
    scope: str = ""
    record_counts: dict[str, int] = field(default_factory=dict)
    generated_by: int | None = None
    generated_by_username: str = ""
    generated_at: datetime | None = None
    file_size_bytes: int = 0

    @property
    def has_records(self) -> bool:
        """False when the report covered no records at all."""
        return any(count > 0 for count in self.record_counts.values())


@dataclass
class DashboardSnapshot:
    """Everything the dashboard shows, assembled from real stored records.

    The figures fall into two kinds, and the field names say which is which
    (§114).

    ``*_in_period`` counts what happened inside the reporting window and so
    genuinely starts again at zero when a new day begins. ``open_*`` and the
    ``*_total`` figures are **current state**: an alert left unreviewed overnight
    is still open in the morning, and zeroing it at midnight would report a
    backlog as cleared. The daily rollover moves the window; it never resets a
    state figure and never touches a stored record.

    ``has_any_data`` drives the first-run empty state: on a clean installation
    every counter is genuinely zero and the UI says so (§72).
    """

    generated_at: datetime

    # -- the reporting window these period figures were counted over --------
    #: ``str(PeriodMode)`` - which kind of span was asked for.
    period_mode: str = "TODAY"
    #: Inclusive lower bound in UTC; ``None`` only for the all-data period.
    period_start: datetime | None = None
    #: Exclusive upper bound in UTC.
    period_end: datetime | None = None
    period_label: str = ""
    period_detail: str = ""

    # -- counted inside [period_start, period_end) --------------------------
    packets_in_period: int = 0
    #: Detections from *both* engines. The severity fields below are the same
    #: query grouped, so the parts always sum to this total.
    detections_in_period: int = 0
    snort_alerts_in_period: int = 0
    anomalies_in_period: int = 0
    findings_in_period: int = 0
    scans_in_period: int = 0
    #: Hosts seen at all during the period, and hosts seen for the first time.
    #: Both are period activity and both start again at zero each day, which
    #: ``active_hosts`` below deliberately does not.
    hosts_seen_in_period: int = 0
    hosts_discovered_in_period: int = 0
    #: No ``critical_alerts``: CRITICAL is not part of the IDS
    #: severity model, so the field would always be zero and inviting a caller
    #: to render it would recreate the card this removed.
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    info_alerts: int = 0

    # -- current state, deliberately not bounded by the period --------------
    total_packets_stored: int = 0
    active_hosts: int = 0
    observed_hosts: int = 0
    open_ports: int = 0
    ids_alerts_total: int = 0
    open_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    scans_total: int = 0
    #: :class:`~aethra_sec.models.host.AssessmentSummary`, the same object the
    #: Vulnerability Assessment tiles are built from. ``None`` when it could
    #: not be read.
    assessment: Any = None

    #: The same counters over the comparable preceding period.
    #: ``None`` means the database holds nothing covering that period, so no
    #: trend can honestly be shown (§1).
    packets_previous_period: int | None = None
    alerts_previous_period: int | None = None
    last_scan_at: datetime | None = None
    last_alert_at: datetime | None = None
    last_packet_at: datetime | None = None
    mean_detection_latency_seconds: float | None = None
    traffic_series: tuple[tuple[datetime, float], ...] = ()
    alert_series: tuple[tuple[datetime, int], ...] = ()
    #: Bucket width of ``alert_series``, chosen from the span of the
    #: period. Carried so the chart can say what it is actually showing
    #: rather than a fixed caption that stops being true.
    alert_bucket_minutes: int = 15
    severity_distribution: tuple[tuple[str, int], ...] = ()
    protocol_distribution: tuple[tuple[str, int], ...] = ()
    recent_alerts: tuple[Any, ...] = ()
    recent_findings: tuple[Any, ...] = ()
    recent_activity: tuple[Any, ...] = ()
    threat_timeline: tuple[dict[str, Any], ...] = ()

    @property
    def has_any_data(self) -> bool:
        """True once any real security or traffic record exists."""
        return bool(
            self.total_packets_stored
            or self.ids_alerts_total
            or self.observed_hosts
            or self.open_findings
            or self.scans_total
        )
