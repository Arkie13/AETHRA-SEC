"""Audit trail service (§32, §33).

Every security-relevant action funnels through :meth:`AuditService.record`,
which appends a hash-chained row. The chain head is cached in memory and
guarded by a lock so concurrent writers cannot interleave and produce a broken
chain.

Audit failures never break the audited operation: if the database is offline the
event goes to the diagnostic log with a clear marker and the application keeps
running, because a monitoring tool that stops monitoring when its log server
hiccups is worse than one that records the gap.
"""

from __future__ import annotations

import socket
import threading
from datetime import datetime
from typing import Any

from aethra_sec.core.session import Session
from aethra_sec.database.repositories.audit import AuditRepository
from aethra_sec.models.user import AuditRecord
from aethra_sec.security.integrity import (
    GENESIS_HASH,
    IntegrityReport,
    compute_hash,
    verify_chain,
)
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("security.audit")


class AuditAction:
    """Audited action names (§32)."""

    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGIN_LOCKED = "LOGIN_LOCKED"
    #: Raised once a run of failed sign-ins reaches the alerting threshold.
    #: Distinct from LOGIN_FAILED, which records every individual attempt: this
    #: one marks the moment the pattern became worth an administrator's time.
    MULTIPLE_LOGIN_FAILURES = "MULTIPLE_LOGIN_FAILURES_DETECTED"
    LOGOUT = "LOGOUT"

    # Notification email. Sign-in never involves email, so these say only
    # whether a notification about something that already happened reached the
    # administrator - a delivery failure is an operational fact to record, not
    # an access decision. The recorded detail names the reason and never the
    # credential used to send.
    #
    # Historical "2FA_*" rows written by earlier versions are left exactly as
    # they are: the column is free text, the audit chain covers them, and
    # rewriting settled history to match a removed feature would be the one
    # thing an audit trail must never do.
    NOTIFICATION_EMAIL_SENT = "NOTIFICATION_EMAIL_SENT"
    NOTIFICATION_EMAIL_FAILED = "NOTIFICATION_EMAIL_FAILED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_TERMINATED = "SESSION_TERMINATED"

    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"
    USER_DEACTIVATED = "USER_DEACTIVATED"
    USER_ACTIVATED = "USER_ACTIVATED"
    USER_UNLOCKED = "USER_UNLOCKED"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED"
    PASSWORD_RESET = "PASSWORD_RESET"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    PERMISSION_DENIED = "PERMISSION_DENIED"

    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"
    PASSWORD_RESET_APPROVED = "PASSWORD_RESET_APPROVED"
    PASSWORD_RESET_REJECTED = "PASSWORD_RESET_REJECTED"
    PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED"
    PASSWORD_RESET_EXPIRED = "PASSWORD_RESET_EXPIRED"

    SETTING_CHANGED = "SETTING_CHANGED"
    TRUSTED_HOST_ADDED = "TRUSTED_HOST_ADDED"
    TRUSTED_HOST_REMOVED = "TRUSTED_HOST_REMOVED"

    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    SCAN_STOPPED = "SCAN_STOPPED"
    SCAN_REFUSED = "SCAN_REFUSED"
    SCAN_TIMED_OUT = "SCAN_TIMED_OUT"
    FINDING_RECORDED = "FINDING_RECORDED"
    HOST_DISCOVERED = "HOST_DISCOVERED"
    ASSESSMENT_QUEUED = "ASSESSMENT_QUEUED"
    ASSESSMENT_SCOPE_UNAVAILABLE = "ASSESSMENT_SCOPE_UNAVAILABLE"
    ASSESSMENT_SCOPE_CHANGED = "ASSESSMENT_SCOPE_CHANGED"
    # EVALUATION_RUN_STARTED / EVALUATION_RUN_COMPLETED were removed with the
    # Evaluation Runs feature. Nothing writes them any more. The audit rows
    # that already carry them are untouched and still readable: the audit
    # repository reads `action` as stored text rather than parsing it back
    # through this enum, and the Logs & Audit filter is built from the
    # distinct values in the table - so the history stays visible and
    # filterable without a constant that no code can now produce.
    #
    # EVALUATION_RECORDED stays: it is an analyst classifying a real alert,
    # which is a different thing entirely and is still offered on Alerts.

    CAPTURE_STARTED = "CAPTURE_STARTED"
    CAPTURE_STOPPED = "CAPTURE_STOPPED"
    CAPTURE_ERROR = "CAPTURE_ERROR"

    SNORT_CONNECTED = "SNORT_CONNECTED"
    SNORT_DISCONNECTED = "SNORT_DISCONNECTED"
    SNORT_ALERT_STORED = "SNORT_ALERT_STORED"

    THREAT_CORRELATED = "THREAT_CORRELATED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_UPDATED = "INCIDENT_UPDATED"
    INCIDENT_NOTE_ADDED = "INCIDENT_NOTE_ADDED"
    ALERT_UPDATED = "ALERT_UPDATED"
    EVALUATION_RECORDED = "EVALUATION_RECORDED"
    MITIGATION_GENERATED = "MITIGATION_GENERATED"
    MITIGATION_CREATED = "MITIGATION_CREATED"
    MITIGATION_UPDATED = "MITIGATION_UPDATED"
    MITIGATION_DEACTIVATED = "MITIGATION_DEACTIVATED"
    FINDING_RESOLVED = "FINDING_RESOLVED"

    REPORT_GENERATED = "REPORT_GENERATED"
    DATA_EXPORTED = "DATA_EXPORTED"
    LOG_INTEGRITY_VERIFIED = "LOG_INTEGRITY_VERIFIED"
    LOG_CHAIN_REHASHED = "LOG_CHAIN_REHASHED"
    DATA_PRUNED = "DATA_PRUNED"
    DATABASE_BACKUP = "DATABASE_BACKUP"

    APPLICATION_STARTED = "APPLICATION_STARTED"
    APPLICATION_STOPPED = "APPLICATION_STOPPED"
    INTEGRATION_FAILURE = "INTEGRATION_FAILURE"
    SYSTEM_ERROR = "SYSTEM_ERROR"


class AuditCategory:
    """Audit categories used for filtering."""

    AUTHENTICATION = "authentication"
    ADMINISTRATION = "administration"
    ASSESSMENT = "assessment"
    MONITORING = "monitoring"
    DETECTION = "detection"
    MITIGATION = "mitigation"
    REPORTING = "reporting"
    SYSTEM = "system"


class AuditService:
    """Appends and verifies hash-chained audit records."""

    def __init__(
        self,
        repository: AuditRepository,
        *,
        enable_hash_chain: bool = True,
        host_context: str = "",
    ) -> None:
        """Create the service and load the current chain head.

        Args:
            repository: audit persistence.
            enable_hash_chain: when false, records are still appended but
                without integrity hashes (reported truthfully by verification).
            host_context: hostname recorded with each entry; detected when
                omitted.
        """
        self._repository = repository
        self._enabled = enable_hash_chain
        self._lock = threading.Lock()
        self._host_context = host_context or self._detect_host()
        self._failures = 0
        self._written = 0

    @staticmethod
    def _detect_host() -> str:
        """Best-effort local hostname for the audit ``host_context`` column."""
        try:
            return socket.gethostname()[:128]
        except Exception:  # noqa: BLE001
            return ""

    @property
    def host_context(self) -> str:
        """Hostname recorded with audit entries."""
        return self._host_context

    @property
    def write_failures(self) -> int:
        """Number of audit writes that could not be persisted."""
        return self._failures

    @property
    def records_written(self) -> int:
        """Number of audit records this service has appended."""
        return self._written

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------
    def record(
        self,
        action: str,
        *,
        session: Session | None = None,
        user_id: int | None = None,
        username: str = "",
        category: str = AuditCategory.SYSTEM,
        target_type: str = "",
        target_id: str | int = "",
        result: str = "SUCCESS",
        detail: str = "",
        source: str = "SYSTEM",
    ) -> int | None:
        """Append an audit record.

        Args:
            action: one of :class:`AuditAction`.
            session: the acting session, when there is one.
            user_id / username: used when no session exists (for example a
                failed login, where the account may not even be known).
            category: audit category for filtering.
            target_type / target_id: the resource acted upon.
            result: ``SUCCESS``, ``FAILURE``, ``DENIED`` or ``WARNING``.
            detail: human-readable explanation. Must never contain a secret.
            source: which subsystem produced the entry.

        Returns:
            The new record id, or ``None`` when the write failed (in which case
            the event is written to the diagnostic log instead).
        """
        effective_user_id = session.user_id if session else user_id
        effective_username = session.username if session else username

        record = AuditRecord(
            id=None,
            occurred_at=utcnow(),
            user_id=effective_user_id,
            username=(effective_username or "")[:64],
            action=action[:64],
            category=category[:32],
            target_type=str(target_type)[:48],
            target_id=str(target_id)[:64],
            result=result[:16],
            detail=detail,
            host_context=(session.host_context if session else "") or self._host_context,
            source=source[:24],
        )

        with self._lock:
            try:
                if self._enabled:
                    # The predecessor is read and locked inside the append's own
                    # transaction. It used to come from a head cached in this
                    # object, which was correct only while one process wrote:
                    # a second window, or a background job in another process,
                    # linked its records to the head it had seen at start-up,
                    # and the log verified as broken although nothing had been
                    # touched. That was PT-04's chain noise.
                    record_id, _ = self._repository.append_chained(
                        record, compute_hash, GENESIS_HASH
                    )
                else:
                    record_id = self._repository.append(record)
                self._written += 1
                return record_id
            except Exception as exc:  # noqa: BLE001 - auditing must not break work
                self._failures += 1
                LOGGER.error(
                    "AUDIT WRITE FAILED (%s) action=%s user=%s target=%s:%s "
                    "result=%s detail=%s",
                    exc,
                    action,
                    effective_username or effective_user_id,
                    target_type,
                    target_id,
                    result,
                    detail,
                )
                return None

    def record_denied(
        self, session: Session | None, permission: str, target: str = ""
    ) -> None:
        """Record a refused authorisation attempt (§55 elevation of privilege)."""
        self.record(
            AuditAction.PERMISSION_DENIED,
            session=session,
            category=AuditCategory.ADMINISTRATION,
            target_type="permission",
            target_id=permission,
            result="DENIED",
            detail=f"Permission '{permission}' required{f' for {target}' if target else ''}.",
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def verify(self, batch_size: int = 1000, max_records: int = 200_000) -> IntegrityReport:
        """Verify the audit chain from the beginning (§56).

        Reads in bounded batches so a large log does not exhaust memory.
        """
        issues: list[Any] = []
        checked = 0
        unhashed = 0
        legacy = 0
        first_id: int | None = None
        last_id: int | None = None
        expected_previous = GENESIS_HASH
        cursor = 0

        while checked < max_records:
            batch = self._repository.iterate_for_verification(cursor, batch_size)
            if not batch:
                break
            report = verify_chain(batch, expected_previous)
            issues.extend(report.issues)
            checked += report.checked
            unhashed += report.unhashed
            legacy += report.legacy
            if first_id is None:
                first_id = report.first_record_id
            last_id = report.last_record_id
            last_hashed = next(
                (r.record_hash for r in reversed(batch) if r.record_hash), ""
            )
            expected_previous = last_hashed or GENESIS_HASH
            cursor = int(batch[-1].id or cursor)
            if len(batch) < batch_size:
                break

        return IntegrityReport(
            checked=checked,
            issues=tuple(issues),
            first_record_id=first_id,
            last_record_id=last_id,
            unhashed=unhashed,
            legacy=legacy,
        )

    def rebase_chain_head(self) -> None:
        """No-op kept for callers that ran after an administrative prune.

        There is no head to reload any more: every append reads and locks the
        real last row inside its own transaction, so a prune is picked up by
        the next write without being told. Pruning still leaves the surviving
        prefix no longer linked to the genesis hash, and verification still
        reports that truncation - which is the point, and must not be repaired
        away.
        """
        return


    def rehash_chain(self) -> tuple[int, int]:
        """Re-hash records carried over from the earlier canonical format.

        The mechanical half of audit maintenance. Authorization and the audit
        of the maintenance itself belong to
        :meth:`~aethra_sec.services.log_service.LogService.rehash_chain`, which
        is the only caller: this class is the primitive every service records
        through, so it cannot hold the access control that records denials.

        Only ``previous_hash`` and ``record_hash`` are written. No timestamp,
        actor, action, target or detail is rewritten, so the evidence itself is
        untouched - what changes is the representation its hash is taken over.

        Returns:
            ``(examined, rehashed)``.
        """
        return self._repository.rehash_chain(compute_hash, GENESIS_HASH)

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def search(self, **kwargs: Any) -> list[AuditRecord]:
        """Proxy to :meth:`AuditRepository.search`."""
        return self._repository.search(**kwargs)

    def recent(self, limit: int = 10) -> list[AuditRecord]:
        """Most recent audit records."""
        return self._repository.recent_activity(limit)

    def total(self) -> int:
        """Total audit records stored."""
        return self._repository.total_count()

    def prune_before(self, cutoff: datetime) -> int:
        """Delete audit records older than ``cutoff`` and rebase the chain."""
        removed = self._repository.prune_before(cutoff)
        self.rebase_chain_head()
        return removed
