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
from aethra_sec.core.errors import SnortIngestError, ValidationFailedError
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
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import (
    find_executable,
    host_address_rejection,
    is_on_link,
    local_ipv4_networks,
)
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
        self._network_lock = threading.Lock()
        self._networks: tuple[Any, ...] = ()
        self._networks_read_at: datetime | None = None

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
                "the configuration file to unixsock, file, syslog or tcp - see "
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

            # Idempotency first: the same Snort line re-read later is the
            # same event, however long ago it was first seen. Without this a
            # re-processed alert file created a second alert *and* a second
            # incident for an event that happened once.
            identical = self._alerts.find_identical(record.raw_alert)
            if identical:
                alert_id, _count = identical
                self._alerts.increment_duplicate(
                    alert_id, record.received_at or utcnow()
                )
                self._duplicates += 1
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
        """Attach an alert endpoint to the host inventory when known.

        An alert endpoint is *not* by itself evidence that a host belongs to
        the monitored network. Most Snort alerts name a remote internet
        address at one end, and enrolling those created inventory rows for
        machines that are not on the laboratory LAN at all - Google and
        Facebook front-ends appeared in Host Inventory as if they were
        discovered devices.

        So an existing row is always linked, but a *new* row is created only
        for an address on a network this sensor is actually attached to. A
        remote endpoint stays recorded on the alert itself, where the source
        and destination addresses are the evidence; it simply does not become
        an inventory entry.
        """
        if not ip_address:
            return None
        try:
            host_id = self._hosts.find_id_by_ip(ip_address)
            if host_id:
                return host_id
            if not is_on_link(ip_address, self._local_networks()):
                return None
            if host_address_rejection(ip_address, self._local_networks()):
                return None
            return self._hosts.upsert_observed(
                ip_address, observed_at=utcnow(), source=EvidenceSource.SNORT,
                interface="snort", detail="named in an alert",
            ) or None
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not resolve host %s.", ip_address, exc_info=True)
            return None

    def _local_networks(self) -> tuple[Any, ...]:
        """The sensor's own subnets, re-read at most once a minute.

        Reading the interface table costs a system call, and alert ingest is
        the hot path, so the answer is cached. The refresh matters because a
        laptop changes network without restarting the console.
        """
        now = utcnow()
        with self._network_lock:
            if (
                self._networks_read_at is None
                or (now - self._networks_read_at).total_seconds() > 60
            ):
                try:
                    self._networks = local_ipv4_networks()
                except Exception:  # noqa: BLE001 - no interface table available
                    LOGGER.debug("Could not read local subnets.", exc_info=True)
                    self._networks = ()
                self._networks_read_at = now
            return self._networks

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

    def search_anomalies(self, session: Session, **filters: Any) -> list[TrafficAnomaly]:
        """Detections raised by AETHRA-SEC's own rules.

        These are not Snort alerts and must never be presented as though they
        were: Snort's alerts come from Snort's rules and its alert file, while
        these come from the capture pipeline and the threshold rules configured
        on the Detection screen. The Alerts screen shows both because an
        operator looking for "what did the system detect" reasonably expects
        one place to look, but each row carries its own origin.

        Gated on ``alert.view``, the same permission that reads the alert list.
        """
        self._access.require(session, Permission.ALERT_VIEW)
        return self._alerts.search_anomalies(**filters)

    def detection_totals(
        self,
        session: Session,
        *,
        alert_filters: dict[str, Any] | None = None,
        anomaly_filters: dict[str, Any] | None = None,
    ) -> dict[str, int]:
        """Severity totals across both sources for one set of filters.

        Counted in the database over the same predicate that selects the rows,
        so a summary can never describe a different set from the table beneath
        it, and the figure reconciles with the Dashboard for the same window.

        ``anomaly_filters`` of ``None`` means "Snort's queue only", which is
        what a status filter asks for - anomalies have no such workflow state.
        """
        self._access.require(session, Permission.ALERT_VIEW)
        totals = self._alerts.detection_totals(
            alert_filters=alert_filters if alert_filters is not None else {},
            anomaly_filters=anomaly_filters,
        )
        totals["unreviewed"] = self._alerts.count_unreviewed_matching(
            alert_filters=alert_filters if alert_filters is not None else {},
            anomaly_filters=anomaly_filters,
        )
        return totals

    def unreviewed_anomaly_count(self, session: Session) -> int:
        """Anomalies an analyst has not evaluated yet."""
        self._access.require(session, Permission.ALERT_VIEW)
        return self._alerts.count_unreviewed_anomalies()

    def unresolved_alert_count(self, session: Session) -> int:
        """Stored alerts nobody has reviewed yet (the sidebar counter)."""
        self._access.require(session, Permission.ALERT_VIEW)
        return int(self._alerts.reliability_counters().get("unresolved", 0))

    def mark_all_reviewed(self, session: Session) -> int:
        """Move every alert still in NEW to REVIEWED, clearing the badge.

        This is deliberately not called "mark as read". The alert badge counts
        alerts in the NEW state, and leaving that state is an analyst's
        judgement recorded against the alert - so it needs ``alert.manage``
        rather than the ``alert.view`` that reading the list needs, and it is
        audited like any other status change.

        Alerts already acknowledged, escalated or suppressed are left as they
        are: those are decisions, and a bulk action must not overwrite them.
        Neither is any ``evaluation`` label written - those are an analyst's
        verdict and the input to the detection-accuracy statistics, so this
        records only that the backlog was read.

        Returns:
            How many detections were marked, across both sources.
        """
        live = self._access.require(session, Permission.ALERT_MANAGE)
        moved = self._alerts.mark_all_reviewed(live.user_id)
        # The screen shows both detection sources, so the action that clears
        # its counter has to cover both. Clearing only Snort's queue left the
        # button doing nothing visible whenever the backlog was AETHRA-SEC's
        # own detections - which, with Snort quiet, is all of it.
        marked = self._alerts.mark_all_anomalies_reviewed(live.user_id)
        if moved or marked:
            self._audit.record(
                AuditAction.ALERT_UPDATED,
                session=live,
                category=AuditCategory.MONITORING,
                target_type="detection",
                target_id=str(moved + marked),
                detail=(
                    f"{moved} Snort alert(s) moved from NEW to REVIEWED and "
                    f"{marked} AETHRA-SEC detection(s) marked reviewed in one "
                    "action. Alerts in another state were not changed, and no "
                    "evaluation label was assigned."
                ),
            )
        return moved + marked

    def mark_anomaly_reviewed(self, session: Session, anomaly_id: int) -> bool:
        """Record that an analyst has read one AETHRA-SEC detection.

        The single-row counterpart of the bulk action. AETHRA-SEC's own
        detections have no Snort workflow status, only a read receipt, so this
        is what "mark reviewed" means for them - and it is gated and audited
        like the alert status change it sits beside, because it is the same
        claim: an analyst looked at this.

        No ``evaluation`` label is written. That is a verdict and the input to
        the detection-accuracy statistics, and it stays the analyst's own.

        Returns:
            True when this call marked it, False when it was already reviewed.
        """
        live = self._access.require(
            session, Permission.ALERT_MANAGE, target=str(anomaly_id)
        )
        marked = self._alerts.mark_anomaly_reviewed(anomaly_id, live.user_id)
        if marked:
            self._audit.record(
                AuditAction.ALERT_UPDATED,
                session=live,
                category=AuditCategory.DETECTION,
                target_type="anomaly",
                target_id=anomaly_id,
                detail=(
                    "AETHRA-SEC detection marked reviewed. No evaluation "
                    "label was assigned."
                ),
            )
        return marked

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

    def classify_anomaly(
        self, session: Session, anomaly_id: int, evaluation: EvaluationLabel
    ) -> None:
        """Record an evaluator's judgement on an AETHRA-SEC detection (§82).

        The same permission and the same audit action as classifying a Snort
        alert, because it is the same analyst decision about the same kind of
        question. Only the store differs.
        """
        live = self._access.require(
            session, Permission.EVALUATION_CLASSIFY, target=str(anomaly_id)
        )
        if not self._alerts.set_anomaly_evaluation(
            anomaly_id, evaluation, live.user_id
        ):
            raise ValidationFailedError(
                f"anomaly {anomaly_id} does not exist",
                user_message="That detection no longer exists.",
            )
        self._audit.record(
            AuditAction.EVALUATION_RECORDED,
            session=live,
            category=AuditCategory.DETECTION,
            target_type="anomaly",
            target_id=anomaly_id,
            detail=f"AETHRA-SEC detection classified as {evaluation}.",
        )

    def review_anomaly(self, session: Session, anomaly_id: int) -> bool:
        """Stamp one AETHRA-SEC detection as read.

        Needs ``alert.manage`` like the bulk action, and is audited, so a
        single read receipt is as traceable as clearing the whole queue.
        """
        live = self._access.require(
            session, Permission.ALERT_MANAGE, target=str(anomaly_id)
        )
        marked = self._alerts.mark_anomaly_reviewed(anomaly_id, live.user_id)
        if marked:
            self._audit.record(
                AuditAction.ALERT_UPDATED,
                session=live,
                category=AuditCategory.DETECTION,
                target_type="anomaly",
                target_id=anomaly_id,
                detail="AETHRA-SEC detection marked reviewed.",
            )
        return marked

    def evaluation_summary(self, session: Session) -> dict[str, int]:
        """Counts per evaluation label, for detection-accuracy analysis."""
        self._access.require(session, Permission.ALERT_VIEW)
        return self._alerts.evaluation_counts()
