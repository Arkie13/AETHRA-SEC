"""In-application notifications for genuine events (§52).

The service subscribes to the event bus and persists a notification for each
real occurrence: a new critical alert, a new high-risk finding, a new incident,
a completed or failed scan, a lost subsystem. Nothing is raised speculatively -
if no event happened, the notification list stays empty.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from typing import Any

from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import Event, EventType, NotificationPayload
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.settings import (
    _REFERENCE_MARKER,
    ErrorRepository,
    NotificationRepository,
)
from aethra_sec.models.enums import NotificationLevel, Severity
from aethra_sec.models.system import Notification
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("services.notifications")


#: ``reference_type`` for alerts a security service raises directly.
SECURITY_ALERT_REFERENCE = "security_alert"

#: ``reference_type`` for a detection raised by AETHRA-SEC's own rules, kept
#: distinct from "alert" (which is Snort's) so the two engines stay countable
#: apart in the notification history.
ANOMALY_REFERENCE = "anomaly"


#: How a detection severity becomes a notification level.
#:
#: These are two different vocabularies and the mapping between them used to
#: be lossy: everything below HIGH became INFO, so a MEDIUM detection could
#: never satisfy a ``sound_min_level`` of WARNING and a real attack at 500-999
#: pps popped up silently. The audio service ranks levels
#: INFO < SUCCESS < WARNING < ERROR < CRITICAL, so mapping each severity to a
#: distinct level is what makes the setting configurable: WARNING sounds for
#: MEDIUM and above, ERROR for HIGH and above.
SEVERITY_LEVELS: dict[str, NotificationLevel] = {
    "CRITICAL": NotificationLevel.CRITICAL,
    "HIGH": NotificationLevel.ERROR,
    "MEDIUM": NotificationLevel.WARNING,
    "LOW": NotificationLevel.INFO,
    "INFO": NotificationLevel.INFO,
}


def level_for_severity(severity: Any) -> NotificationLevel:
    """The notification level that matches this detection severity.

    An unrecognised severity returns WARNING rather than INFO: failing
    towards audible is the safer direction for a security detection, and it
    is logged by the caller that produced the odd value.
    """
    return SEVERITY_LEVELS.get(str(severity).upper(), NotificationLevel.WARNING)


class NotificationService:
    """Turns real system events into stored, reviewable notifications."""

    def __init__(
        self,
        notifications: NotificationRepository,
        errors: ErrorRepository,
        settings: SettingsService,
        event_bus: EventBus,
    ) -> None:
        """Subscribe to the events worth telling the operator about."""
        self._repository = notifications
        self._errors = errors
        self._settings = settings
        self._bus = event_bus
        self._lock = threading.Lock()
        self._raised = 0
        #: Snort alerts that raised no popup because of the evidence-only policy.
        self.snort_evidence_only = 0
        self._subscription = event_bus.subscribe(
            (
                EventType.NOTIFICATION_RAISED,
                EventType.REPORT_GENERATED,
                EventType.SNORT_ALERT_RECEIVED,
                # Detections from AETHRA-SEC's own rules. Absent here, the
                # handler below was unreachable for them: the service was
                # never delivered the event, so a port scan, host sweep or
                # flood produced an alerts-table row and no notification.
                EventType.TRAFFIC_ANOMALY_DETECTED,
                EventType.NMAP_SCAN_COMPLETED,
                EventType.NMAP_SCAN_FAILED,
                EventType.CAPTURE_STOPPED,
                EventType.CAPTURE_ERROR,
                EventType.SNORT_STATUS_CHANGED,
                EventType.DATABASE_STATUS_CHANGED,
                EventType.SYSTEM_ERROR,
            ),
            self._handle,
            queued=False,
            name="notification-service",
        )

    @property
    def raised_count(self) -> int:
        """Number of notifications this service has created."""
        return self._raised

    def close(self) -> None:
        """Unsubscribe during shutdown."""
        self._bus.unsubscribe(self._subscription)

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------
    def _handle(self, event: Event) -> None:
        """Route one event to its notification, if it warrants one."""
        if not self._settings.get_bool("notifications.enabled", True):
            return
        try:
            handler = {
                EventType.NOTIFICATION_RAISED: self._from_payload,
                EventType.REPORT_GENERATED: self._from_payload,
                EventType.SNORT_ALERT_RECEIVED: self._from_alert,
                EventType.TRAFFIC_ANOMALY_DETECTED: self._from_anomaly,
                EventType.NMAP_SCAN_COMPLETED: self._from_scan_completed,
                EventType.NMAP_SCAN_FAILED: self._from_scan_failed,
                EventType.CAPTURE_STOPPED: self._from_capture_stopped,
                EventType.CAPTURE_ERROR: self._from_error,
                EventType.SNORT_STATUS_CHANGED: self._from_service_status,
                EventType.DATABASE_STATUS_CHANGED: self._from_service_status,
                EventType.SYSTEM_ERROR: self._from_error,
            }.get(event.type)
            if handler is not None:
                handler(event.payload)
        except Exception:  # noqa: BLE001 - notifications must never break work
            LOGGER.exception("Could not process event %s", event.type)

    def _from_payload(self, payload: Any) -> None:
        """Store an explicitly raised notification."""
        if payload is None:
            return
        self._store(
            Notification(
                level=getattr(payload, "level", NotificationLevel.INFO),
                title=str(getattr(payload, "title", "")),
                message=str(getattr(payload, "message", "")),
                category=str(getattr(payload, "category", "system")),
                reference_type=str(getattr(payload, "reference_type", "")),
                reference_id=getattr(payload, "reference_id", None),
            )
        )

    def _from_alert(self, payload: Any) -> None:
        """Notify on a new Snort alert at or above the configured severity.

        Only when ``notifications.snort_popups`` is on (off by default). The
        primary alerts are AETHRA-SEC's own detections; a Snort alert is
        supporting evidence and does not raise a popup or sound of its own.
        It is still stored, correlated into its attack, and counted on Attack
        Statistics. Measured before this: 504 Snort notifications - each a
        popup - in 27 minutes of one test session, against 6 for AETHRA-SEC.
        """
        alert = getattr(payload, "alert", None)
        if alert is None:
            return
        if not self._settings.get_bool("notifications.snort_popups", False):
            with self._lock:
                self.snort_evidence_only += 1
            LOGGER.debug(
                "[NOTIFY] Snort alert %s recorded as supporting evidence; Snort "
                "alerts raise no popup (notifications.snort_popups is off).",
                alert.id,
            )
            return
        minimum = Severity.parse(
            self._settings.get_str("notifications.min_severity", "MEDIUM"),
            Severity.MEDIUM,
        )
        if not alert.severity.at_least(minimum):
            LOGGER.debug(
                "[NOTIFY] Snort alert %s is %s, below the minimum %s; no "
                "notification raised.", alert.id, alert.severity, minimum,
            )
            return
        # Keyed on the alert AND its severity, the same rule detections use:
        # a Snort alert first graded at the start of a flood and upgraded as
        # the measured rate rose announces again at the higher severity, but
        # never twice at the same one.
        reference = f"{alert.id}:{alert.severity}"
        since = utcnow() - timedelta(seconds=self.ANOMALY_DEDUP_SECONDS)
        if alert.id is not None and self._reference_exists("alert", reference, since):
            LOGGER.debug(
                "[NOTIFY] Snort alert %s already announced at %s.",
                alert.id, alert.severity,
            )
            return
        level = level_for_severity(alert.severity)
        LOGGER.info(
            "[NOTIFY] Snort alert %s (%s) is eligible at minimum %s; raising "
            "a %s notification.", alert.id, alert.severity, minimum, level,
        )
        self._store(
            Notification(
                level=level,
                title=f"{alert.severity} IDS alert",
                message=f"{alert.summary}{_REFERENCE_MARKER}{reference}"[:512],
                category="alert",
                reference_type="alert",
                reference_id=alert.id,
                severity=str(alert.severity),
            )
        )

    #: How long one detection's notification stands for its own severity.
    #: Matched to the detection suppression window, which is already the
    #: period inside which a repeat observation folds into the existing
    #: episode rather than becoming a new detection - so inside it there is
    #: nothing new to announce.
    ANOMALY_DEDUP_SECONDS = 120

    def _from_anomaly(self, payload: Any) -> None:
        """Notify on a detection raised by AETHRA-SEC's own rules.

        These never reached this service at all: the handler map routed
        ``SNORT_ALERT_RECEIVED`` and not ``TRAFFIC_ANOMALY_DETECTED``, so a
        port scan, a host sweep or a flood produced an alerts-table row and
        nothing else. On an installation where most detections come from
        AETHRA-SEC's own rules - which is the normal case when Snort is not
        the primary sensor - that is every notification the operator never
        got.

        Eligibility is the same test the Snort path applies, by severity
        RANK rather than by string, so MEDIUM and HIGH are compared on the
        order the model defines and not alphabetically.

        The correlation key carries the severity as well as the detection id.
        That is what lets an escalation through: a flood already announced at
        MEDIUM announces again when it reaches HIGH, because the key changed,
        while a repeat at the same severity inside the window does not. The
        capture service only republishes this event on a genuine escalation,
        so this is a second guard rather than the only one.
        """
        anomaly = getattr(payload, "anomaly", None)
        if anomaly is None:
            return
        anomaly_id = getattr(anomaly, "id", None)
        if anomaly_id is None:
            # Not persisted, so there is nothing for the operator to open.
            LOGGER.debug("Detection without an id raised no notification.")
            return

        severity = getattr(anomaly, "severity", None)
        if not isinstance(severity, Severity):
            LOGGER.warning(
                "Detection %s carried no usable severity (%r); no "
                "notification was raised.", anomaly_id, severity,
            )
            return

        minimum = Severity.parse(
            self._settings.get_str("notifications.min_severity", "MEDIUM"),
            Severity.MEDIUM,
        )
        if not severity.at_least(minimum):
            LOGGER.debug(
                "Detection %s is %s, below the configured minimum of %s; "
                "no notification raised.", anomaly_id, severity, minimum,
            )
            return

        reference = f"{anomaly_id}:{severity}"
        since = utcnow() - timedelta(seconds=self.ANOMALY_DEDUP_SECONDS)
        if self._reference_exists(ANOMALY_REFERENCE, reference, since):
            LOGGER.debug(
                "Detection %s already announced at %s inside the window.",
                anomaly_id, severity,
            )
            return

        # The same mapping the Snort path uses, so one severity means one
        # level across both engines.
        level = level_for_severity(severity)
        rule = str(getattr(anomaly, "rule_id", "") or "detection")
        title = str(getattr(anomaly, "title", "") or rule)
        source = str(getattr(anomaly, "src_ip", "") or "")
        destination = str(getattr(anomaly, "dst_ip", "") or "")
        where = source or "source not recorded"
        if destination:
            where = f"{where} -> {destination}"
        message = f"{rule} · {where} · {title}"

        LOGGER.info(
            "[NOTIFY] Detection %s (%s, %s) is eligible at minimum %s; "
            "raising a %s notification.",
            anomaly_id, rule, severity, minimum, level,
        )
        self._store(
            Notification(
                level=level,
                title=f"{severity} detection",
                message=f"{message}{_REFERENCE_MARKER}{reference}"[:512],
                category="alert",
                reference_type=ANOMALY_REFERENCE,
                reference_id=anomaly_id,
                severity=str(severity),
            )
        )

    def _reference_exists(
        self, reference_type: str, reference: str, since: datetime
    ) -> bool:
        """True when a notification with this key already stands.

        A database failure reports True, so a broken lookup cannot turn into
        a flood of duplicate notifications during an attack.
        """
        try:
            return self._repository.exists_since(
                reference_type, reference, since
            )
        except Exception:  # noqa: BLE001
            LOGGER.debug(
                "Could not check for an existing notification.", exc_info=True
            )
            return True

    def _from_scan_completed(self, payload: Any) -> None:
        """Notify that an assessment finished, with its real counts."""
        if payload is None:
            return
        self._store(
            Notification(
                level=NotificationLevel.SUCCESS,
                title="Vulnerability assessment completed",
                message=(
                    f"{payload.target}: {payload.hosts_up} host(s) up, "
                    f"{payload.open_ports} open port(s), {payload.findings} "
                    f"finding(s) in {payload.duration_seconds:.1f}s."
                ),
                category="assessment",
                reference_type="scan",
                reference_id=payload.scan_id,
            )
        )

    def _from_scan_failed(self, payload: Any) -> None:
        """Notify that an assessment failed, with the real error."""
        if payload is None:
            return
        self._store(
            Notification(
                level=NotificationLevel.ERROR,
                title="Vulnerability assessment failed",
                message=f"{payload.target}: {payload.error}"[:512],
                category="assessment",
                reference_type="scan",
                reference_id=payload.scan_id,
            )
        )

    def _from_capture_stopped(self, payload: Any) -> None:
        """Notify when capture stops unexpectedly (§52, §57)."""
        if payload is None:
            return
        detail = str(getattr(payload, "detail", ""))
        if detail in ("operator request", "application shutdown"):
            return
        self._store(
            Notification(
                level=NotificationLevel.WARNING,
                title="PACKET CAPTURE STOPPED",
                message=(
                    f"Capture on '{payload.interface}' stopped: {detail}. "
                    f"{payload.packets_captured} packet(s) were captured."
                )[:512],
                category="monitoring",
            )
        )

    def _from_service_status(self, payload: Any) -> None:
        """Notify when a subsystem changes state."""
        if payload is None:
            return
        state = getattr(payload, "state", None)
        service = str(getattr(payload, "service", "service"))
        detail = str(getattr(payload, "detail", ""))
        if state is None or getattr(state, "is_healthy", False):
            return
        if str(state) == "DISABLED":
            return
        self._store(
            Notification(
                level=NotificationLevel.WARNING,
                title=f"{service.upper()} {state}",
                message=detail[:512],
                category="system",
            )
        )

    def _from_error(self, payload: Any) -> None:
        """Record a subsystem failure and notify."""
        if payload is None:
            return
        component = str(getattr(payload, "component", "system"))
        message = str(getattr(payload, "message", ""))
        detail = str(getattr(payload, "detail", ""))
        try:
            self._errors.record(component, message, detail)
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not persist the error record.", exc_info=True)
        self._store(
            Notification(
                level=NotificationLevel.ERROR,
                title=f"{component} error",
                message=message[:512],
                category="system",
            )
        )

    # ------------------------------------------------------------------
    # Security alerts raised directly by a service
    # ------------------------------------------------------------------
    def raise_security_alert(
        self,
        *,
        title: str,
        message: str,
        reference: str,
        user_id: int | None = None,
    ) -> None:
        """Store an authentication-security alert for administrators.

        This is the existing notification pipeline, not a second one: the row
        lands in ``notifications`` with the usual level, category and read
        state, so it reaches the header badge, the notification list and the
        "mark all read" action that already exist.

        ``reference`` is the correlation key. It is appended to the stored
        message behind an invisible marker and stripped before display, so a
        repeated condition can be recognised without a schema change and
        without the operator seeing an identifier.

        The level is :attr:`NotificationLevel.WARNING`, the same level a HIGH
        detection uses. It is deliberately not CRITICAL: that level re-sounds
        an unacknowledged alert, and a run of failed passwords - which is often
        somebody's caps lock - should not be able to start an alarm that
        repeats until an administrator silences it.
        """
        self._store(
            Notification(
                user_id=user_id,
                level=NotificationLevel.WARNING,
                title=title[:190],
                message=f"{message}{_REFERENCE_MARKER}{reference}"[:512],
                category="security",
                reference_type=SECURITY_ALERT_REFERENCE,
                reference_id=user_id,
                created_at=utcnow(),
            )
        )

    def security_alert_exists(self, reference: str, since: datetime) -> bool:
        """True when an alert with this correlation key already stands."""
        try:
            return self._repository.exists_since(
                SECURITY_ALERT_REFERENCE, reference, since
            )
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not check for an existing alert.", exc_info=True)
            # Reported as present, so a database problem cannot turn into a
            # flood of duplicate alerts.
            return True

    def _store(self, notification: Notification) -> None:
        """Persist a notification, then announce that it exists.

        The announcement is the point. Storing a row is what makes the badge
        count rise, but nothing was ever published afterwards, so the interface
        never learned that a notification had appeared and the alert sound -
        which is driven by that event - never played. 101 real alert
        notifications were sitting in this installation's database, including
        SYN floods from the operator's own testing, every one of them silent.

        It is published *after* a successful insert and carries the real row
        id, so three things follow for free: a notification that failed to
        persist cannot sound, the sound and the badge are driven by the same
        record rather than by two guesses at it, and the audio service has an
        immutable identifier to fold repeats against.
        """
        try:
            notification_id = self._repository.create(notification)
            with self._lock:
                self._raised += 1
            keep = self._settings.get_int("notifications.max_retained", 500)
            if self._raised % 50 == 0:
                self._repository.prune_excess(keep)
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not store a notification.", exc_info=True)
            return

        LOGGER.info(
            "[NOTIFY] Stored: id=%s level=%s category=%s ref=%s:%s",
            notification_id,
            notification.level,
            notification.category,
            notification.reference_type or "-",
            notification.reference_id if notification.reference_id else "-",
        )
        try:
            self._bus.publish(
                EventType.NOTIFICATION_STORED,
                NotificationPayload(
                    title=notification.title,
                    message=notification.message,
                    level=notification.level,
                    category=notification.category,
                    reference_type=notification.reference_type,
                    reference_id=notification.reference_id,
                    notification_id=notification_id,
                    severity=notification.severity,
                ),
            )
        except Exception:  # noqa: BLE001 - a failed announcement must not
            # undo a stored notification, nor break the producer's work.
            LOGGER.exception("Could not announce notification %s", notification_id)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def recent(
        self, session: Session | None, *, unread_only: bool = False, limit: int = 50
    ) -> list[Notification]:
        """Notifications visible to a session."""
        user_id = session.user_id if session else None
        return self._repository.list_recent(user_id, unread_only=unread_only, limit=limit)

    def unread_count(self, session: Session | None) -> int:
        """Unread notification count for the header badge."""
        try:
            return self._repository.unread_count(session.user_id if session else None)
        except Exception:  # noqa: BLE001
            return 0

    def mark_read(self, notification_id: int, session: Session | None) -> None:
        """Record that this reader has read one notification.

        The session is required rather than optional-by-omission: a read is a
        statement about a person, and a broadcast notification is visible to
        everyone. Marking it read without saying *who* read it is what let one
        analyst clear the queue for the whole team.
        """
        self._repository.mark_read(
            notification_id, session.user_id if session else None
        )

    def mark_all_read(self, session: Session | None) -> int:
        """Mark everything this reader can see as read by them."""
        return self._repository.mark_all_read(session.user_id if session else None)
