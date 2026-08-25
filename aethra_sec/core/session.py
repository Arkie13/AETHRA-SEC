"""Authenticated session state and the in-process session registry.

Sessions are also persisted to the ``sessions`` table by
:class:`aethra_sec.security.authentication.AuthenticationService`, which lets an
administrator see and forcibly terminate sessions. This module owns the
in-memory view used for permission checks on every service call.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from aethra_sec.core.errors import SessionExpiredError
from aethra_sec.core.permissions import PermissionSet
from aethra_sec.utils.timeutil import utcnow

_TOKEN_BYTES = 32


@dataclass
class Session:
    """A signed-in operator.

    Attributes:
        token: opaque, cryptographically random identifier. Never derived from
            user data and never logged in full.
        user_id: primary key of the authenticated user.
        username: login name, used in audit records.
        role: role name (``ADMIN`` / ``USER``).
        permissions: permission codes resolved from the database at login.
        created_at: when authentication succeeded.
        expires_at: absolute expiry; refreshed by :meth:`touch`.
        last_activity: timestamp of the most recent authorised action.
        host_context: hostname of the workstation, recorded for audit.
        db_session_id: primary key of the persisted ``sessions`` row.
    """

    token: str
    user_id: int
    username: str
    role: str
    permissions: PermissionSet
    created_at: datetime = field(default_factory=utcnow)
    expires_at: datetime | None = None
    last_activity: datetime = field(default_factory=utcnow)
    host_context: str = ""
    db_session_id: int | None = None

    @property
    def is_admin(self) -> bool:
        """True when the session holds the ADMIN role."""
        return self.role.upper() == "ADMIN"

    @property
    def is_expired(self) -> bool:
        """True when the session has passed its absolute expiry."""
        return self.expires_at is not None and utcnow() >= self.expires_at

    @property
    def token_prefix(self) -> str:
        """Short, non-reversible identifier safe for log lines."""
        return self.token[:8]

    def touch(self, timeout_minutes: int) -> None:
        """Record activity and slide the idle expiry forward."""
        self.last_activity = utcnow()
        self.expires_at = self.last_activity + timedelta(minutes=timeout_minutes)

    def has(self, permission: str) -> bool:
        """True when this session holds ``permission``."""
        return self.permissions.has(permission)


class SessionManager:
    """Thread-safe registry of active sessions."""

    def __init__(self, timeout_minutes: int = 60) -> None:
        """Create an empty registry.

        Args:
            timeout_minutes: idle timeout applied to newly created sessions.
        """
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}
        self._timeout_minutes = max(1, timeout_minutes)

    @property
    def timeout_minutes(self) -> int:
        """Configured idle timeout in minutes."""
        return self._timeout_minutes

    def set_timeout(self, minutes: int) -> None:
        """Update the idle timeout applied to new and refreshed sessions."""
        with self._lock:
            self._timeout_minutes = max(1, int(minutes))

    def create(
        self,
        *,
        user_id: int,
        username: str,
        role: str,
        permissions: PermissionSet,
        host_context: str = "",
        db_session_id: int | None = None,
    ) -> Session:
        """Issue a new session with a fresh random token."""
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        session = Session(
            token=token,
            user_id=user_id,
            username=username,
            role=role,
            permissions=permissions,
            host_context=host_context,
            db_session_id=db_session_id,
        )
        session.touch(self._timeout_minutes)
        with self._lock:
            self._sessions[token] = session
        return session

    def get(self, token: str) -> Session | None:
        """Return a live session, or ``None`` when unknown or expired."""
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session.is_expired:
                self._sessions.pop(token, None)
                return None
            return session

    def require(self, token: str) -> Session:
        """Return a live session or raise.

        Raises:
            SessionExpiredError: when the token is unknown, expired, or was
                invalidated by an administrator.
        """
        session = self.get(token)
        if session is None:
            raise SessionExpiredError()
        session.touch(self._timeout_minutes)
        return session

    def invalidate(self, token: str) -> Session | None:
        """Remove one session (logout). Returns the removed session, if any."""
        with self._lock:
            return self._sessions.pop(token, None)

    def invalidate_user(self, user_id: int) -> list[Session]:
        """Remove every session of one user (administrative force-logout)."""
        with self._lock:
            targets = [s for s in self._sessions.values() if s.user_id == user_id]
            for session in targets:
                self._sessions.pop(session.token, None)
            return targets

    def purge_expired(self) -> int:
        """Drop expired sessions; returns how many were removed."""
        with self._lock:
            expired = [t for t, s in self._sessions.items() if s.is_expired]
            for token in expired:
                self._sessions.pop(token, None)
            return len(expired)

    def active_sessions(self) -> list[Session]:
        """Snapshot of live sessions (administrative view)."""
        with self._lock:
            return [s for s in self._sessions.values() if not s.is_expired]

    def count(self) -> int:
        """Number of live sessions."""
        return len(self.active_sessions())
