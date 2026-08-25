"""Role-based access control enforcement (§8, §55).

The service layer calls :meth:`AccessControl.require` before every action that
reads restricted data or changes state. Hiding a button in the UI is a
convenience for the operator; this module is the actual control.
"""

from __future__ import annotations

from typing import Iterable

from aethra_sec.core.errors import PermissionDeniedError, SessionExpiredError
from aethra_sec.core.permissions import Permission, PermissionSet
from aethra_sec.core.session import Session, SessionManager
from aethra_sec.security.audit import AuditService
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("security.rbac")


class AccessControl:
    """Checks session permissions and audits every refusal."""

    def __init__(
        self, session_manager: SessionManager, audit: AuditService | None = None
    ) -> None:
        """Bind the checker to the session registry and the audit trail."""
        self._sessions = session_manager
        self._audit = audit

    def resolve(self, session: Session | str | None) -> Session:
        """Accept a session object or token and return a live session.

        Raises:
            SessionExpiredError: when the session is unknown or has expired.
        """
        if session is None:
            raise SessionExpiredError()
        if isinstance(session, str):
            return self._sessions.require(session)
        live = self._sessions.get(session.token)
        if live is None:
            raise SessionExpiredError()
        live.touch(self._sessions.timeout_minutes)
        return live

    def require(
        self,
        session: Session | str | None,
        permission: str,
        *,
        target: str = "",
    ) -> Session:
        """Assert that a session holds ``permission``.

        Args:
            session: session object or token.
            permission: required permission code.
            target: optional description of the resource, for the audit record.

        Returns:
            The live session, so callers can use it immediately.

        Raises:
            SessionExpiredError: when the session is not live.
            PermissionDeniedError: when the permission is not granted; the
                refusal is written to the audit trail first.
        """
        live = self.resolve(session)
        if not live.has(permission):
            if self._audit:
                self._audit.record_denied(live, permission, target)
            LOGGER.warning(
                "Permission denied: user=%s role=%s permission=%s target=%s",
                live.username,
                live.role,
                permission,
                target or "-",
            )
            raise PermissionDeniedError(permission)
        return live

    def require_any(
        self, session: Session | str | None, permissions: Iterable[str], *, target: str = ""
    ) -> Session:
        """Assert that a session holds at least one of ``permissions``."""
        codes = tuple(permissions)
        live = self.resolve(session)
        if not live.permissions.has_any(*codes):
            if self._audit:
                self._audit.record_denied(live, "|".join(codes), target)
            raise PermissionDeniedError("|".join(codes))
        return live

    def require_admin(self, session: Session | str | None, *, target: str = "") -> Session:
        """Assert that a session holds the ADMIN role."""
        live = self.resolve(session)
        if not live.is_admin:
            if self._audit:
                self._audit.record_denied(live, "role:ADMIN", target)
            raise PermissionDeniedError(
                "role:ADMIN",
                user_message="This action requires an administrator account.",
            )
        return live

    def has(self, session: Session | str | None, permission: str) -> bool:
        """Non-raising check used by the UI to hide or disable controls."""
        try:
            live = self.resolve(session)
        except SessionExpiredError:
            return False
        return live.has(permission)

    def visible_navigation(self, session: Session | None) -> tuple[str, ...]:
        """Navigation entries a session may open (§61).

        The UI uses this to build the sidebar; the service layer still enforces
        each individual action independently.
        """
        if session is None:
            return ()
        permissions: PermissionSet = session.permissions
        entries: list[str] = []

        def add(label: str, *required: str) -> None:
            if permissions.has_any(*required):
                entries.append(label)

        add("Dashboard", Permission.DASHBOARD_VIEW)
        add("Network Monitoring", Permission.MONITOR_VIEW)
        add("Vulnerability Assessment", Permission.SCAN_VIEW, Permission.SCAN_RUN)
        add("Hosts", Permission.HOST_VIEW)
        add("Alerts", Permission.ALERT_VIEW)
        add("Incidents", Permission.INCIDENT_VIEW)
        add("Mitigation", Permission.MITIGATION_VIEW)
        add("Reports", Permission.REPORT_GENERATE)
        add("Logs & Audit", Permission.LOG_VIEW)
        add("Users", Permission.USER_MANAGE)
        add("System Health", Permission.HEALTH_VIEW)
        add("Settings", Permission.SETTINGS_MANAGE)
        entries.append("Help")
        entries.append("About")
        return tuple(entries)
