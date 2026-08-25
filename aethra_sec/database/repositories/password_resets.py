"""Password recovery queue persistence (§6, §70).

One table, one lifecycle. The row records who asked, when, from where, who
decided, and when the approval was consumed - everything an auditor needs to
reconstruct how a credential came to be changed.

The authorisation code itself is never stored: only its SHA-256 digest is,
in ``code_hash``, and the comparison is done in constant time by the service.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from aethra_sec.database.repositories.base import (
    Repository,
    as_dt,
    as_int,
    as_text,
)
from aethra_sec.models.user import PasswordResetRequest, ResetStatus
from aethra_sec.utils.timeutil import to_db, utcnow

_REQUEST_COLUMNS = (
    "r.id, r.user_id, r.username, r.status, r.reason, r.contact, "
    "r.host_context, r.requested_at, r.expires_at, r.reviewed_by, "
    "r.reviewed_at, r.review_note, r.code_expires_at, r.code_attempts, "
    "r.completed_at, a.username AS reviewer_username"
)

_FROM_REQUESTS = (
    "FROM password_reset_requests r LEFT JOIN users a ON a.id = r.reviewed_by "
)


class PasswordResetRepository(Repository):
    """Reads and writes password-reset requests."""

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------
    @staticmethod
    def _map(row: dict[str, Any]) -> PasswordResetRequest:
        """Map a joined request row to :class:`PasswordResetRequest`."""
        return PasswordResetRequest(
            id=as_int(row.get("id")),
            user_id=as_int(row.get("user_id")) or 0,
            username=as_text(row.get("username")),
            status=as_text(row.get("status")) or ResetStatus.PENDING,
            reason=as_text(row.get("reason")),
            contact=as_text(row.get("contact")),
            host_context=as_text(row.get("host_context")),
            requested_at=as_dt(row.get("requested_at")),
            expires_at=as_dt(row.get("expires_at")),
            reviewed_by=as_int(row.get("reviewed_by")),
            reviewer_username=as_text(row.get("reviewer_username")),
            reviewed_at=as_dt(row.get("reviewed_at")),
            review_note=as_text(row.get("review_note")),
            code_expires_at=as_dt(row.get("code_expires_at")),
            code_attempts=as_int(row.get("code_attempts")) or 0,
            completed_at=as_dt(row.get("completed_at")),
        )

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def create(
        self,
        *,
        user_id: int,
        username: str,
        reason: str,
        contact: str,
        host_context: str,
        expires_at: datetime,
    ) -> int:
        """Insert a pending request and return its id."""
        return self.db.insert(
            "INSERT INTO password_reset_requests "
            "(user_id, username, status, reason, contact, host_context, "
            "requested_at, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                user_id,
                username[:32],
                ResetStatus.PENDING,
                reason[:255],
                contact[:190],
                host_context[:128],
                to_db(utcnow()),
                to_db(expires_at),
            ),
        )

    def approve(
        self,
        request_id: int,
        *,
        reviewer_id: int,
        note: str,
        code_hash: str,
        code_expires_at: datetime,
    ) -> int:
        """Approve a request and attach the hashed one-time code.

        The ``status = 'PENDING'`` guard makes the transition atomic: two
        administrators clicking Approve at the same moment produce one approval
        and one "no longer pending" result, never two live codes.

        Returns:
            The number of rows changed - ``0`` when the request had already
            moved on.
        """
        return self.db.execute(
            "UPDATE password_reset_requests SET status = %s, reviewed_by = %s, "
            "reviewed_at = %s, review_note = %s, code_hash = %s, "
            "code_expires_at = %s, code_attempts = 0 "
            "WHERE id = %s AND status = %s",
            (
                ResetStatus.APPROVED,
                reviewer_id,
                to_db(utcnow()),
                note[:255],
                code_hash,
                to_db(code_expires_at),
                request_id,
                ResetStatus.PENDING,
            ),
        )

    def reject(
        self, request_id: int, *, reviewer_id: int | None, note: str
    ) -> int:
        """Reject a request that is still open, discarding any code.

        ``reviewer_id`` is ``None`` when the system itself revokes an approval
        (too many wrong codes) rather than an administrator deciding.
        """
        return self.db.execute(
            "UPDATE password_reset_requests SET status = %s, reviewed_by = %s, "
            "reviewed_at = %s, review_note = %s, code_hash = NULL, "
            "code_expires_at = NULL WHERE id = %s AND status IN (%s, %s)",
            (
                ResetStatus.REJECTED,
                reviewer_id,
                to_db(utcnow()),
                note[:255],
                request_id,
                ResetStatus.PENDING,
                ResetStatus.APPROVED,
            ),
        )

    def complete(self, request_id: int) -> int:
        """Consume an approved request exactly once.

        The ``status = 'APPROVED'`` guard is what makes the code single-use:
        the second attempt updates no rows, so the caller knows not to change
        the password.
        """
        return self.db.execute(
            "UPDATE password_reset_requests SET status = %s, completed_at = %s, "
            "code_hash = NULL, code_expires_at = NULL "
            "WHERE id = %s AND status = %s",
            (ResetStatus.COMPLETED, to_db(utcnow()), request_id, ResetStatus.APPROVED),
        )

    def register_code_attempt(self, request_id: int) -> int:
        """Count a wrong code and return the new total."""
        self.db.execute(
            "UPDATE password_reset_requests SET code_attempts = code_attempts + 1 "
            "WHERE id = %s",
            (request_id,),
        )
        return int(
            self.db.query_value(
                "SELECT code_attempts FROM password_reset_requests WHERE id = %s",
                (request_id,),
                default=0,
            )
            or 0
        )

    def expire_stale(self, now: datetime | None = None) -> int:
        """Expire requests whose review window or code deadline has passed."""
        moment = to_db(now or utcnow())
        return self.db.execute(
            "UPDATE password_reset_requests SET status = %s, code_hash = NULL "
            "WHERE (status = %s AND expires_at < %s) "
            "OR (status = %s AND code_expires_at IS NOT NULL AND code_expires_at < %s)",
            (
                ResetStatus.EXPIRED,
                ResetStatus.PENDING,
                moment,
                ResetStatus.APPROVED,
                moment,
            ),
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def get(self, request_id: int) -> PasswordResetRequest | None:
        """One request by id."""
        row = self.db.query_one(
            f"SELECT {_REQUEST_COLUMNS} {_FROM_REQUESTS} WHERE r.id = %s",
            (request_id,),
        )
        return self._map(row) if row else None

    def code_hash_for(self, request_id: int) -> str:
        """The stored digest of an approved request's code.

        Kept out of :meth:`get` so the digest never travels inside a model
        handed to the interface, exactly as the password hash never does.
        """
        return as_text(
            self.db.query_value(
                "SELECT code_hash FROM password_reset_requests WHERE id = %s",
                (request_id,),
                default="",
            )
        )

    def open_for_user(self, user_id: int) -> PasswordResetRequest | None:
        """The user's live request, pending or approved, if there is one."""
        row = self.db.query_one(
            f"SELECT {_REQUEST_COLUMNS} {_FROM_REQUESTS} "
            "WHERE r.user_id = %s AND r.status IN (%s, %s) "
            "ORDER BY r.requested_at DESC LIMIT 1",
            (user_id, ResetStatus.PENDING, ResetStatus.APPROVED),
        )
        return self._map(row) if row else None

    def approved_for_username(self, username: str) -> PasswordResetRequest | None:
        """The newest approved request for a username, if any."""
        row = self.db.query_one(
            f"SELECT {_REQUEST_COLUMNS} {_FROM_REQUESTS} "
            "WHERE r.username = %s AND r.status = %s "
            "ORDER BY r.reviewed_at DESC LIMIT 1",
            (username, ResetStatus.APPROVED),
        )
        return self._map(row) if row else None

    def list_requests(
        self, *, statuses: tuple[str, ...] = (), limit: int = 200
    ) -> list[PasswordResetRequest]:
        """Requests for the administrative queue, newest first.

        ``statuses`` is validated against :class:`ResetStatus` before use, so
        only known literals ever reach the statement.
        """
        clean = tuple(s for s in statuses if s in ResetStatus.ALL)
        params: list[Any] = []
        where = ""
        if clean:
            placeholders = ", ".join(["%s"] * len(clean))
            where = f"WHERE r.status IN ({placeholders}) "
            params.extend(clean)
        params.append(max(1, min(int(limit), 5000)))
        rows = self.db.query(
            f"SELECT {_REQUEST_COLUMNS} {_FROM_REQUESTS} {where}"
            "ORDER BY r.requested_at DESC LIMIT %s",
            params,
        )
        return self._map_all(rows, self._map)

    def count_by_status(self, status: str) -> int:
        """How many requests are in one state."""
        if status not in ResetStatus.ALL:
            return 0
        return self.count(
            "SELECT COUNT(*) FROM password_reset_requests WHERE status = %s",
            (status,),
        )

    def recent_request_count(self, user_id: int, since: datetime) -> int:
        """Requests raised for one account since a point in time.

        Used to rate-limit the sign-in screen so the queue cannot be flooded.
        """
        return self.count(
            "SELECT COUNT(*) FROM password_reset_requests "
            "WHERE user_id = %s AND requested_at >= %s",
            (user_id, to_db(since)),
        )
