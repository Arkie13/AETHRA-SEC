"""In-application notifications for genuine events (§52).

The service subscribes to the event bus and persists a notification for each
real occurrence: a new critical alert, a new high-risk finding, a new incident,
a completed or failed scan, a lost subsystem. Nothing is raised speculatively -
if no event happened, the notification list stays empty.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Any

from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import Event, EventType
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
        self._subscription = event_bus.subscribe(
            (
                EventType.NOTIFICATION_RAISED,
                EventType.REPORT_GENERATED,
                EventType.SNORT_ALERT_RECEIVED,
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
        """Notify on a new Snort alert at or above the configured severity."""
        alert = getattr(payload, "alert", None)
        if alert is None:
            return
        minimum = Severity.parse(
            self._settings.get_str("notifications.min_severity", "MEDIUM"),
            Severity.MEDIUM,
        )
        if not alert.severity.at_least(minimum):
            return
        # No CRITICAL branch: a detection cannot reach that severity, so
        # the mapping starts at HIGH. HIGH keeps the level it always had.
        level = (
            NotificationLevel.WARNING
            if alert.severity is Severity.HIGH
            else NotificationLevel.INFO
        )
        self._store(
            Notification(
                level=level,
                title=f"{alert.severity} IDS alert",
                message=alert.summary[:512],
                category="alert",
                reference_type="alert",
                reference_id=alert.id,
            )
        )

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
        """Persist a notification and trim the retained list."""
        try:
            self._repository.create(notification)
            with self._lock:
                self._raised += 1
            keep = self._settings.get_int("notifications.max_retained", 500)
            if self._raised % 50 == 0:
                self._repository.prune_excess(keep)
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not store a notification.", exc_info=True)

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
