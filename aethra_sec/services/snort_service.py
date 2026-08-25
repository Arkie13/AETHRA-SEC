"""Snort alert ingestion service (§21-§23, §84).

Receives real alerts from the configured transport, normalises them into
:class:`SnortAlert`, deduplicates repeats inside the suppression window,
persists them and publishes events.

The service never generates an alert. When no transport is configured, or the
configured one cannot start, :meth:`status` reports "Snort unavailable" and the
dashboard indicator shows OFFLINE - it does not show a green light (§120).
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from typing import Any

from aethra_sec.analytics.risk_engine import RiskEngine
from aethra_sec.config.settings import SnortSettings, ToolSettings
from aethra_sec.core.errors import SnortIngestError
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import (
    ErrorPayload,
    EventType,
    ServiceStatusPayload,
    SnortAlertPayload,
)
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.integrations.snort import (
    AlertTransport,
    DecodedAlertPkt,
    ParsedAlert,
    build_transport,
)
from aethra_sec.models.alert import AlertStatus, SnortAlert, SnortStatus
from aethra_sec.models.enums import (
    EvaluationLabel,
    EvidenceSource,
    ServiceState,
)
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import find_executable
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("services.snort")

SNORT_UNAVAILABLE_TEXT = "Snort unavailable"


class SnortService:
    """Ingests, normalises and stores real Snort alerts."""

    def __init__(
        self,
        alerts: AlertRepository,
        hosts: HostRepository,
        settings: SettingsService,
        event_bus: EventBus,
        audit: AuditService,
        access: AccessControl,
        snort_settings: SnortSettings,
        tools: ToolSettings,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        """Wire the service to its collaborators."""
        self._alerts = alerts
        self._hosts = hosts
        self._settings = settings
        self._bus = event_bus
        self._audit = audit
        self._access = access
        self._config = snort_settings
        self._tools = tools
        self._risk = risk_engine or RiskEngine()

        self._transport: AlertTransport | None = None
        self._lock = threading.RLock()
        self._stored = 0
        self._duplicates = 0
        self._store_failures = 0
        self._last_error = ""
        self._started_at: datetime | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> bool:
        """Start the configured transport.

        Returns:
            True when ingest is running. False when ingest is disabled or the
            transport could not start; the reason is reported by
            :meth:`status`, never hidden.
        """
        with self._lock:
            if self._transport and self._transport.is_running:
                return True
            if not self._config.enabled:
                LOGGER.info("Snort ingest is disabled by configuration.")
                self._publish_status(
                    ServiceState.DISABLED,
                    "Snort alert ingest is disabled (AETHRA_SNORT_TRANSPORT=disabled).",
                )
                return False

            try:
                transport = build_transport(
                    self._config.transport,
                    socket_path=self._config.socket_path,
                    tcp_host=self._config.tcp_host,
                    tcp_port=self._config.tcp_port,
                    syslog_host=self._config.syslog_host,
                    syslog_port=self._config.syslog_port,
                    alert_file=self._config.alert_file,
                    on_alert=self._on_alert,
                    on_failure=self._on_transport_failure,
                )
            except SnortIngestError as exc:
                self._last_error = exc.user_message
                self._record_offline(exc.user_message)
                return False

            if transport is None:
                self._publish_status(ServiceState.DISABLED, "Snort ingest disabled.")
                return False

            try:
                transport.start()
            except SnortIngestError as exc:
                self._last_error = exc.user_message
                self._record_offline(exc.user_message)
                return False
            except Exception as exc:  # noqa: BLE001
                message = f"{SNORT_UNAVAILABLE_TEXT}: {exc}"
                self._last_error = message
                self._record_offline(message)
                return False

            self._transport = transport
            self._started_at = utcnow()
            self._last_error = ""

        self._audit.record(
            AuditAction.SNORT_CONNECTED,
            category=AuditCategory.DETECTION,
            target_type="transport",
            target_id=self._config.transport,
            detail=f"Snort alert ingest started: {self._config.describe()}",
        )
        self._publish_status(
            ServiceState.RUNNING,
            f"Snort alert ingest active ({self._config.describe()}).",
        )
        LOGGER.info("Snort ingest started: %s", self._config.describe())
        return True

    def stop(self, reason: str = "application shutdown") -> None:
        """Stop the transport and record the disconnection."""
        with self._lock:
            transport = self._transport
            self._transport = None
        if transport is None:
            return
        transport.stop()
        self._audit.record(
            AuditAction.SNORT_DISCONNECTED,
            category=AuditCategory.DETECTION,
            target_type="transport",
            target_id=self._config.transport,
            detail=f"Snort alert ingest stopped ({reason}).",
        )
        self._publish_status(ServiceState.OFFLINE, f"Snort ingest stopped ({reason}).")

    def restart(self, session: Session | None = None) -> bool:
        """Stop and start the transport (used by the Settings screen)."""
        if session is not None:
            self._access.require(session, Permission.SETTINGS_MANAGE, target="snort")
        self.stop(reason="restart requested")
        return self.start()

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def status(self) -> SnortStatus:
        """Report the true state of the Snort ingest path (§10, §21)."""
        with self._lock:
            transport = self._transport
        if transport is None:
            detail = (
                "Snort alert ingest is disabled. Set AETHRA_SNORT_TRANSPORT in "
                ".env to unixsock, file, syslog or tcp - see "
                "docs/SNORT_INTEGRATION.md."
                if not self._config.enabled
                else self._last_error or f"{SNORT_UNAVAILABLE_TEXT}."
            )
            return SnortStatus(
                transport=self._config.transport,
                endpoint=self._config.describe(),
                is_connected=False,
                last_error=self._last_error,
                detail=detail,
            )

        state = transport.status
        return SnortStatus(
            transport=self._config.transport,
            endpoint=state.endpoint,
            is_connected=bool(state.connected and transport.is_running),
            started_at=state.started_at,
            last_alert_at=state.last_alert_at,
            alerts_received=state.alerts_received,
            parse_failures=state.parse_failures,
            last_error=state.last_error or self._last_error,
            detail=state.detail,
        )

    def executable_status(self) -> tuple[bool, str]:
        """Locate the Snort executable, for the diagnostics screen.

        AETHRA-SEC never launches Snort - the sensor is operated separately -
        but knowing whether the binary is present helps an operator configure
        the integration.
        """
        from pathlib import Path

        executable = find_executable(
            self._tools.snort_path,
            "snort",
            "snort.exe",
            extra_dirs=(Path(r"C:\Snort\bin"), Path("/usr/sbin"), Path("/usr/local/bin")),
        )
        if executable:
            return True, str(executable)
        return False, (
            "The Snort executable was not found. AETHRA-SEC does not start "
            "Snort itself; run the sensor separately and point "
            "AETHRA_SNORT_TRANSPORT at its alert output."
        )

    def reliability(self) -> dict[str, int]:
        """Alert reliability counters, mixing live and stored figures (§84)."""
        state = self.status()
        counters = self._alerts.reliability_counters()
        return {
            "received": state.alerts_received,
            "stored": counters.get("stored", 0),
            "duplicates": counters.get("duplicates", 0),
            "parse_failures": state.parse_failures,
            "store_failures": self._store_failures,
            "correlated": counters.get("correlated", 0),
            "unresolved": counters.get("unresolved", 0),
        }

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def _on_alert(
        self, alert: ParsedAlert | DecodedAlertPkt, transport_name: str
    ) -> None:
        """Normalise, deduplicate, store and publish one real alert."""
        try:
            record = self._normalise(alert, transport_name)
            if record is None:
                return

            suppression = max(
                1, self._settings.get_int("detection.suppression_window_seconds", 120)
            )
            existing = self._alerts.find_duplicate(
                record.dedup_key, utcnow() - timedelta(seconds=suppression)
            )
            if existing:
                alert_id, _count = existing
                self._alerts.increment_duplicate(
                    alert_id, record.received_at or utcnow()
                )
                self._duplicates += 1
                return

            record.src_host_id = self._resolve_host(record.src_ip)
            record.dst_host_id = self._resolve_host(record.dst_ip)
            record.id = self._alerts.insert_alert(record)
            self._stored += 1

            self._bus.publish(EventType.SNORT_ALERT_RECEIVED, SnortAlertPayload(record))
            LOGGER.info(
                "Snort alert stored: %s %s (severity %s)",
                record.signature_text,
                record.message[:80],
                record.severity,
            )
        except Exception:  # noqa: BLE001 - ingest must survive one bad alert
            self._store_failures += 1
            LOGGER.exception("Could not store a Snort alert.")

    def _normalise(
        self, alert: ParsedAlert | DecodedAlertPkt, transport_name: str
    ) -> SnortAlert | None:
        """Convert transport output into a :class:`SnortAlert`."""
        received = utcnow()

        if isinstance(alert, DecodedAlertPkt):
            classification = (
                f"Snort classification id {alert.classification_id}"
                if alert.classification_id
                else ""
            )
            record = SnortAlert(
                alert_time=alert.timestamp,
                received_at=received,
                time_source="snort" if alert.timestamp else "aethra_receipt",
                generator_id=alert.generator_id,
                signature_id=alert.signature_id,
                revision=alert.revision,
                message=alert.message,
                classification=classification,
                priority=alert.priority,
                protocol=alert.protocol,
                src_ip=alert.src_ip,
                src_port=alert.src_port,
                dst_ip=alert.dst_ip,
                dst_port=alert.dst_port,
                transport=transport_name,
                raw_alert=self._describe_alertpkt(alert),
            )
        else:
            record = SnortAlert(
                alert_time=alert.timestamp,
                received_at=received,
                time_source="snort" if alert.timestamp else "aethra_receipt",
                generator_id=alert.generator_id,
                signature_id=alert.signature_id,
                revision=alert.revision,
                message=alert.message,
                classification=alert.classification,
                priority=alert.priority,
                protocol=alert.protocol,
                src_ip=alert.src_ip,
                src_port=alert.src_port,
                dst_ip=alert.dst_ip,
                dst_port=alert.dst_port,
                interface=alert.interface,
                sensor=alert.sensor,
                transport=transport_name,
                raw_alert=alert.raw,
            )

        if not record.message and record.signature_id is None:
            return None

        record.severity = self._risk.severity_for_snort_priority(record.priority)
        record.status = AlertStatus.NEW
        record.evaluation = EvaluationLabel.UNCLASSIFIED
        record.source = EvidenceSource.SNORT
        record.created_at = received
        record.dedup_key = (
            f"{record.generator_id or ''}:{record.signature_id or ''}:"
            f"{record.src_ip}:{record.dst_ip}:{record.dst_port or ''}"
        )
        return record

    @staticmethod
    def _describe_alertpkt(alert: DecodedAlertPkt) -> str:
        """Render a binary alert's decoded fields as retained evidence."""
        parts = [
            f"transport=alert_unixsock",
            f"layout={alert.layout}",
            f"datagram_bytes={alert.raw_size}",
            f"event_id={alert.event_id}",
            f"event_reference={alert.event_reference}",
            f"packet_len={alert.packet_length}",
            f"capture_len={alert.capture_length}",
        ]
        if alert.ttl is not None:
            parts.append(f"ttl={alert.ttl}")
        if alert.warnings:
            parts.append("warnings=" + "; ".join(alert.warnings))
        return " | ".join(parts)

    def _resolve_host(self, ip_address: str) -> int | None:
        """Attach an alert endpoint to the host inventory when known."""
        if not ip_address:
            return None
        try:
            host_id = self._hosts.find_id_by_ip(ip_address)
            if host_id:
                return host_id
            return self._hosts.upsert_observed(
                ip_address, observed_at=utcnow(), source=EvidenceSource.SNORT
            ) or None
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not resolve host %s.", ip_address, exc_info=True)
            return None

    def _on_transport_failure(self, message: str) -> None:
        """Record and publish a transport failure (§57)."""
        self._last_error = message
        self._record_offline(message)

    def _record_offline(self, message: str) -> None:
        """Audit and publish that Snort ingest is offline."""
        self._audit.record(
            AuditAction.INTEGRATION_FAILURE,
            category=AuditCategory.DETECTION,
            target_type="snort",
            target_id=self._config.transport,
            result="FAILURE",
            detail=message,
        )
        self._publish_status(ServiceState.OFFLINE, message)
        self._bus.publish(EventType.SYSTEM_ERROR, ErrorPayload("snort", message))

    def _publish_status(self, state: ServiceState, detail: str) -> None:
        """Publish a subsystem status change."""
        self._bus.publish(
            EventType.SNORT_STATUS_CHANGED,
            ServiceStatusPayload(service="snort", state=state, detail=detail),
        )

    # ------------------------------------------------------------------
    # Reads and analyst actions (permission-checked)
    # ------------------------------------------------------------------
    def search(self, session: Session, **filters: Any) -> list[SnortAlert]:
        """Search stored alerts."""
        self._access.require(session, Permission.ALERT_VIEW)
        return self._alerts.search_alerts(**filters)

    def get(self, session: Session, alert_id: int) -> SnortAlert | None:
        """Fetch one alert."""
        self._access.require(session, Permission.ALERT_VIEW, target=str(alert_id))
        return self._alerts.get_alert(alert_id)

    def recent(self, session: Session, limit: int = 10) -> list[SnortAlert]:
        """Newest alerts for the dashboard."""
        self._access.require(session, Permission.ALERT_VIEW)
        return self._alerts.recent_alerts(limit)

    def unresolved_alert_count(self, session: Session) -> int:
        """Stored alerts nobody has reviewed yet (the sidebar counter)."""
        self._access.require(session, Permission.ALERT_VIEW)
        return int(self._alerts.reliability_counters().get("unresolved", 0))

    def set_status(
        self, session: Session, alert_id: int, status: AlertStatus
    ) -> None:
        """Change an alert's workflow status (§43)."""
        live = self._access.require(
            session, Permission.ALERT_MANAGE, target=str(alert_id)
        )
        self._alerts.set_alert_status(alert_id, status)
        self._audit.record(
            AuditAction.ALERT_UPDATED,
            session=live,
            category=AuditCategory.DETECTION,
            target_type="alert",
            target_id=alert_id,
            detail=f"Alert status changed to {status}.",
        )

    def mark_all_reviewed(self, session: Session) -> int:
        """Move every NEW alert to REVIEWED (the sidebar's "mark all read")."""
        live = self._access.require(session, Permission.ALERT_MANAGE)
        count = self._alerts.mark_all_new_reviewed()
        if count:
            self._audit.record(
                AuditAction.ALERT_UPDATED,
                session=live,
                category=AuditCategory.DETECTION,
                target_type="alert",
                detail=f"{count} alert(s) marked reviewed in bulk.",
            )
        return count

    def classify(
        self, session: Session, alert_id: int, evaluation: EvaluationLabel
    ) -> None:
        """Record an evaluator's true/false-positive judgement (§82)."""
        live = self._access.require(
            session, Permission.EVALUATION_CLASSIFY, target=str(alert_id)
        )
        self._alerts.set_alert_evaluation(alert_id, evaluation, live.user_id)
        self._audit.record(
            AuditAction.EVALUATION_RECORDED,
            session=live,
            category=AuditCategory.DETECTION,
            target_type="alert",
            target_id=alert_id,
            detail=f"Alert classified as {evaluation}.",
        )

    def evaluation_summary(self, session: Session) -> dict[str, int]:
        """Counts per evaluation label, for detection-accuracy analysis."""
        self._access.require(session, Permission.ALERT_VIEW)
        return self._alerts.evaluation_counts()
