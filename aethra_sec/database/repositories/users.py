"""User, role, session and login-attempt persistence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from aethra_sec.core.permissions import PermissionSet
from aethra_sec.database.repositories.base import (
    Repository,
    as_bool,
    as_dt,
    as_int,
    as_text,
)
from aethra_sec.models.user import LoginAttempt, Role, User, UserSessionRecord
from aethra_sec.utils.timeutil import to_db, utcnow

_USER_COLUMNS = (
    "u.id, u.username, u.password_hash, u.password_algorithm, u.full_name, "
    "u.email, u.role_id, u.is_active, u.is_locked, u.failed_login_count, "
    "u.locked_until, u.last_login_at, u.last_login_host, u.password_changed_at, "
    "u.must_change_password, u.created_at, u.updated_at, u.created_by, "
    "r.name AS role_name"
)


class UserRepository(Repository):
    """CRUD and lookup operations for accounts, roles and sessions."""

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------
    @staticmethod
    def _map_user(row: dict[str, Any]) -> User:
        """Map a joined user row to :class:`User` (without the hash)."""
        return User(
            id=as_int(row.get("id")),
            username=as_text(row.get("username")),
            full_name=as_text(row.get("full_name")),
            email=as_text(row.get("email")),
            role_id=as_int(row.get("role_id")),
            role_name=as_text(row.get("role_name")),
            is_active=as_bool(row.get("is_active")),
            is_locked=as_bool(row.get("is_locked")),
            failed_login_count=as_int(row.get("failed_login_count")) or 0,
            locked_until=as_dt(row.get("locked_until")),
            last_login_at=as_dt(row.get("last_login_at")),
            last_login_host=as_text(row.get("last_login_host")),
            password_algorithm=as_text(row.get("password_algorithm")),
            password_changed_at=as_dt(row.get("password_changed_at")),
            must_change_password=as_bool(row.get("must_change_password")),
            created_at=as_dt(row.get("created_at")),
            updated_at=as_dt(row.get("updated_at")),
            created_by=as_int(row.get("created_by")),
        )

    # ------------------------------------------------------------------
    # Roles and permissions
    # ------------------------------------------------------------------
    def get_role_by_name(self, name: str) -> Role | None:
        """Look up a role by its name."""
        row = self.db.query_one(
            "SELECT id, name, description, created_at FROM roles WHERE name = %s",
            (name.upper(),),
        )
        if not row:
            return None
        return Role(
            id=as_int(row["id"]),
            name=as_text(row["name"]),
            description=as_text(row["description"]),
            permissions=self.permissions_for_role(int(row["id"])),
            created_at=as_dt(row.get("created_at")),
        )

    def list_roles(self) -> list[Role]:
        """All roles with their granted permissions."""
        rows = self.db.query(
            "SELECT id, name, description, created_at FROM roles ORDER BY name"
        )
        return [
            Role(
                id=as_int(r["id"]),
                name=as_text(r["name"]),
                description=as_text(r["description"]),
                permissions=self.permissions_for_role(int(r["id"])),
                created_at=as_dt(r.get("created_at")),
            )
            for r in rows
        ]

    def permissions_for_role(self, role_id: int) -> tuple[str, ...]:
        """Permission codes granted to a role."""
        rows = self.db.query(
            "SELECT p.code FROM role_permissions rp "
            "JOIN permissions p ON p.id = rp.permission_id "
            "WHERE rp.role_id = %s ORDER BY p.code",
            (role_id,),
        )
        return tuple(as_text(r["code"]) for r in rows)

    def permissions_for_user(self, user_id: int) -> PermissionSet:
        """Resolve a user's effective permissions from their role."""
        rows = self.db.query(
            "SELECT p.code FROM users u "
            "JOIN role_permissions rp ON rp.role_id = u.role_id "
            "JOIN permissions p ON p.id = rp.permission_id "
            "WHERE u.id = %s",
            (user_id,),
        )
        return PermissionSet.of(as_text(r["code"]) for r in rows)

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------
    def get_by_username(self, username: str) -> User | None:
        """Fetch an account by login name."""
        row = self.db.query_one(
            f"SELECT {_USER_COLUMNS} FROM users u "
            "LEFT JOIN roles r ON r.id = u.role_id WHERE u.username = %s",
            (username,),
        )
        return self._map_user(row) if row else None

    def get_by_id(self, user_id: int) -> User | None:
        """Fetch an account by primary key."""
        row = self.db.query_one(
            f"SELECT {_USER_COLUMNS} FROM users u "
            "LEFT JOIN roles r ON r.id = u.role_id WHERE u.id = %s",
            (user_id,),
        )
        return self._map_user(row) if row else None

    def get_password_hash(self, user_id: int) -> tuple[str, str]:
        """Return ``(hash, algorithm)`` for verification.

        Kept separate from :meth:`get_by_id` so the hash is only loaded by the
        authentication service and never travels inside a ``User`` handed to
        the UI.
        """
        row = self.db.query_one(
            "SELECT password_hash, password_algorithm FROM users WHERE id = %s",
            (user_id,),
        )
        if not row:
            return "", ""
        return as_text(row["password_hash"]), as_text(row["password_algorithm"])

    def list_users(self, include_inactive: bool = True) -> list[User]:
        """All accounts, newest first."""
        sql = (
            f"SELECT {_USER_COLUMNS} FROM users u "
            "LEFT JOIN roles r ON r.id = u.role_id "
        )
        params: tuple[Any, ...] = ()
        if not include_inactive:
            sql += "WHERE u.is_active = 1 "
            params = ()
        sql += "ORDER BY u.username"
        return self._map_all(self.db.query(sql, params), self._map_user)

    def count_users(self, *, active_only: bool = False) -> int:
        """Number of accounts."""
        if active_only:
            return self.count("SELECT COUNT(*) FROM users WHERE is_active = 1")
        return self.count("SELECT COUNT(*) FROM users")

    def count_admins(self, *, active_only: bool = True) -> int:
        """Number of accounts holding the ADMIN role.

        Used to prevent removing or deactivating the last administrator.
        """
        sql = (
            "SELECT COUNT(*) FROM users u JOIN roles r ON r.id = u.role_id "
            "WHERE r.name = 'ADMIN'"
        )
        if active_only:
            sql += " AND u.is_active = 1"
        return self.count(sql)

    def create_user(
        self,
        *,
        username: str,
        password_hash: str,
        password_algorithm: str,
        role_id: int,
        full_name: str = "",
        email: str = "",
        created_by: int | None = None,
        must_change_password: bool = False,
    ) -> int:
        """Insert a new account and return its id."""
        now = to_db(utcnow())
        return self.db.insert(
            "INSERT INTO users (username, password_hash, password_algorithm, "
            "full_name, email, role_id, is_active, is_locked, "
            "failed_login_count, password_changed_at, must_change_password, "
            "created_at, updated_at, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, 1, 0, 0, %s, %s, %s, %s, %s)",
            (
                username,
                password_hash,
                password_algorithm,
                full_name,
                email,
                role_id,
                now,
                1 if must_change_password else 0,
                now,
                now,
                created_by,
            ),
        )

    def update_profile(
        self,
        user_id: int,
        *,
        full_name: str,
        email: str,
        role_id: int,
        is_active: bool,
    ) -> None:
        """Update editable account fields."""
        self.db.execute(
            "UPDATE users SET full_name = %s, email = %s, role_id = %s, "
            "is_active = %s, updated_at = %s WHERE id = %s",
            (full_name, email, role_id, 1 if is_active else 0, to_db(utcnow()), user_id),
        )

    def set_password(
        self,
        user_id: int,
        password_hash: str,
        algorithm: str,
        *,
        must_change: bool = False,
    ) -> None:
        """Replace the stored password hash and clear any lockout."""
        now = to_db(utcnow())
        self.db.execute(
            "UPDATE users SET password_hash = %s, password_algorithm = %s, "
            "password_changed_at = %s, must_change_password = %s, "
            "failed_login_count = 0, is_locked = 0, locked_until = NULL, "
            "updated_at = %s WHERE id = %s",
            (password_hash, algorithm, now, 1 if must_change else 0, now, user_id),
        )

    def set_active(self, user_id: int, active: bool) -> None:
        """Activate or deactivate an account."""
        self.db.execute(
            "UPDATE users SET is_active = %s, updated_at = %s WHERE id = %s",
            (1 if active else 0, to_db(utcnow()), user_id),
        )

    def set_locked(
        self, user_id: int, locked: bool, locked_until: datetime | None = None
    ) -> None:
        """Lock or unlock an account."""
        self.db.execute(
            "UPDATE users SET is_locked = %s, locked_until = %s, "
            "failed_login_count = CASE WHEN %s THEN failed_login_count ELSE 0 END, "
            "updated_at = %s WHERE id = %s",
            (
                1 if locked else 0,
                to_db(locked_until),
                1 if locked else 0,
                to_db(utcnow()),
                user_id,
            ),
        )

    def register_failed_login(self, user_id: int) -> int:
        """Increment and return the consecutive failed-login counter."""
        self.db.execute(
            "UPDATE users SET failed_login_count = failed_login_count + 1, "
            "updated_at = %s WHERE id = %s",
            (to_db(utcnow()), user_id),
        )
        return int(
            self.db.query_value(
                "SELECT failed_login_count FROM users WHERE id = %s",
                (user_id,),
                default=0,
            )
            or 0
        )

    def register_successful_login(self, user_id: int, host_context: str) -> None:
        """Reset the failure counter and record the login time and host."""
        now = to_db(utcnow())
        self.db.execute(
            "UPDATE users SET failed_login_count = 0, is_locked = 0, "
            "locked_until = NULL, last_login_at = %s, last_login_host = %s, "
            "updated_at = %s WHERE id = %s",
            (now, host_context, now, user_id),
        )

    # ------------------------------------------------------------------
    # Login attempts
    # ------------------------------------------------------------------
    def record_login_attempt(
        self,
        *,
        username: str,
        user_id: int | None,
        successful: bool,
        reason: str = "",
        host_context: str = "",
    ) -> int:
        """Append a login attempt record."""
        return self.db.insert(
            "INSERT INTO login_attempts "
            "(username, user_id, successful, reason, host_context, attempted_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (
                username[:64],
                user_id,
                1 if successful else 0,
                reason[:128],
                host_context[:128],
                to_db(utcnow()),
            ),
        )

    def list_login_attempts(
        self, *, username: str = "", user_id: int | None = None, limit: int = 100
    ) -> list[LoginAttempt]:
        """Recent login attempts, optionally scoped to one account."""
        clauses: list[str] = []
        params: list[Any] = []
        if username:
            clauses.append("username = %s")
            params.append(username)
        if user_id is not None:
            clauses.append("user_id = %s")
            params.append(user_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(int(limit), 5000)))
        rows = self.db.query(
            "SELECT id, username, user_id, successful, reason, host_context, "
            f"attempted_at FROM login_attempts {where} "
            "ORDER BY attempted_at DESC LIMIT %s",
            params,
        )
        return [
            LoginAttempt(
                id=as_int(r["id"]),
                username=as_text(r["username"]),
                user_id=as_int(r["user_id"]),
                successful=as_bool(r["successful"]),
                reason=as_text(r["reason"]),
                host_context=as_text(r["host_context"]),
                attempted_at=as_dt(r["attempted_at"]),
            )
            for r in rows
        ]

    def recent_failure_count(self, username: str, since: datetime) -> int:
        """Failed attempts for a username since a point in time."""
        return self.count(
            "SELECT COUNT(*) FROM login_attempts "
            "WHERE username = %s AND successful = 0 AND attempted_at >= %s",
            (username, to_db(since)),
        )

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------
    def create_session(
        self,
        *,
        user_id: int,
        token_fingerprint: str,
        host_context: str,
        expires_at: datetime | None,
    ) -> int:
        """Persist a new session row."""
        now = to_db(utcnow())
        return self.db.insert(
            "INSERT INTO sessions (user_id, token_fingerprint, host_context, "
            "created_at, last_activity_at, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, token_fingerprint, host_context[:128], now, now, to_db(expires_at)),
        )

    def touch_session(self, session_id: int, expires_at: datetime | None) -> None:
        """Record activity on a session."""
        self.db.execute(
            "UPDATE sessions SET last_activity_at = %s, expires_at = %s "
            "WHERE id = %s AND ended_at IS NULL",
            (to_db(utcnow()), to_db(expires_at), session_id),
        )

    def end_session(self, session_id: int, reason: str) -> None:
        """Mark a session as ended."""
        self.db.execute(
            "UPDATE sessions SET ended_at = %s, end_reason = %s "
            "WHERE id = %s AND ended_at IS NULL",
            (to_db(utcnow()), reason[:64], session_id),
        )

    def end_sessions_for_user(self, user_id: int, reason: str) -> int:
        """End every open session of a user (administrative force-logout)."""
        return self.db.execute(
            "UPDATE sessions SET ended_at = %s, end_reason = %s "
            "WHERE user_id = %s AND ended_at IS NULL",
            (to_db(utcnow()), reason[:64], user_id),
        )

    def list_sessions(
        self, *, active_only: bool = True, limit: int = 200
    ) -> list[UserSessionRecord]:
        """Session rows for the administrative session view."""
        where = "WHERE s.ended_at IS NULL" if active_only else ""
        rows = self.db.query(
            "SELECT s.id, s.user_id, u.username, s.token_fingerprint, "
            "s.host_context, s.created_at, s.last_activity_at, s.expires_at, "
            "s.ended_at, s.end_reason FROM sessions s "
            f"LEFT JOIN users u ON u.id = s.user_id {where} "
            "ORDER BY s.last_activity_at DESC LIMIT %s",
            (max(1, min(int(limit), 5000)),),
        )
        return [
            UserSessionRecord(
                id=as_int(r["id"]),
                user_id=as_int(r["user_id"]) or 0,
                username=as_text(r["username"]),
                token_fingerprint=as_text(r["token_fingerprint"]),
                host_context=as_text(r["host_context"]),
                created_at=as_dt(r["created_at"]),
                last_activity_at=as_dt(r["last_activity_at"]),
                expires_at=as_dt(r["expires_at"]),
                ended_at=as_dt(r["ended_at"]),
                end_reason=as_text(r["end_reason"]),
            )
            for r in rows
        ]

    def expire_stale_sessions(self) -> int:
        """Close sessions whose expiry has passed."""
        now = to_db(utcnow())
        return self.db.execute(
            "UPDATE sessions SET ended_at = %s, end_reason = 'expired' "
            "WHERE ended_at IS NULL AND expires_at IS NOT NULL AND expires_at < %s",
            (now, now),
        )
