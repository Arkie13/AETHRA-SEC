"""Log and audit access (§69, §56).

Read, search, export and integrity-verify the audit trail. There is no method
here that modifies an audit record - the table is append-only from the
application's perspective, and the only removal path is the administrator
pruning in :class:`aethra_sec.services.retention_service.RetentionService`.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from aethra_sec.core.errors import IntegrityError
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.audit import AuditRepository
from aethra_sec.database.repositories.settings import ErrorRepository
from aethra_sec.models.system import AppError
from aethra_sec.models.user import AuditRecord
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.integrity import IntegrityReport
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import format_local
from aethra_sec.utils.validation import resolve_within, safe_filename

LOGGER = get_logger("services.logs")

AUDIT_EXPORT_COLUMNS = (
    "ID", "Time", "User", "Action", "Category", "Target type", "Target",
    "Result", "Detail", "Host", "Source", "Record hash",
)


class LogService:
    """Search, export and verify the audit trail."""

    def __init__(
        self,
        repository: AuditRepository,
        errors: ErrorRepository,
        audit: AuditService,
        access: AccessControl,
        log_dir: Path,
    ) -> None:
        """Wire the service to its collaborators."""
        self._repository = repository
        self._errors = errors
        self._audit = audit
        self._access = access
        self._log_dir = Path(log_dir)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def search(self, session: Session, **filters: Any) -> list[AuditRecord]:
        """Search audit records."""
        self._access.require(session, Permission.LOG_VIEW)
        return self._repository.search(**filters)

    def count(self, session: Session, **filters: Any) -> int:
        """Count audit records matching the same filters as :meth:`search`."""
        self._access.require(session, Permission.LOG_VIEW)
        return self._repository.count_matching(**filters)

    def total(self, session: Session) -> int:
        """Total audit records stored."""
        self._access.require(session, Permission.LOG_VIEW)
        return self._repository.total_count()

    def filter_options(self, session: Session) -> dict[str, list[str]]:
        """Distinct values for the log filter drop-downs."""
        self._access.require(session, Permission.LOG_VIEW)
        return {
            "actions": self._repository.distinct_actions(),
            "categories": self._repository.distinct_categories(),
        }

    def errors(self, session: Session, limit: int = 100) -> list[AppError]:
        """Recorded subsystem failures."""
        self._access.require(session, Permission.LOG_VIEW)
        return self._errors.list_recent(limit)

    def acknowledge_error(self, session: Session, error_id: int) -> None:
        """Acknowledge a recorded error."""
        live = self._access.require(session, Permission.LOG_VIEW, target=str(error_id))
        self._errors.acknowledge(error_id)
        self._audit.record(
            AuditAction.SYSTEM_ERROR,
            session=live,
            category=AuditCategory.SYSTEM,
            target_type="app_error",
            target_id=error_id,
            detail="Error acknowledged by the operator.",
        )

    def application_log_path(self) -> Path | None:
        """Path of the rotating diagnostic log, when it exists."""
        candidate = self._log_dir / "aethra_sec.log"
        return candidate if candidate.exists() else None

    def tail_application_log(self, session: Session, lines: int = 500) -> list[str]:
        """Read the last lines of the diagnostic log."""
        self._access.require(session, Permission.LOG_VIEW)
        path = self.application_log_path()
        if path is None:
            return []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                return handle.readlines()[-max(1, min(lines, 5000)) :]
        except OSError as exc:
            LOGGER.warning("Could not read the application log: %s", exc)
            return [f"Could not read {path}: {exc}"]

    # ------------------------------------------------------------------
    # Integrity (§56)
    # ------------------------------------------------------------------
    def verify_integrity(self, session: Session) -> IntegrityReport:
        """Verify the audit hash chain and audit the verification itself."""
        live = self._access.require(session, Permission.LOG_VERIFY, target="audit_logs")
        report = self._audit.verify()
        self._audit.record(
            AuditAction.LOG_INTEGRITY_VERIFIED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="audit_logs",
            target_id=str(report.checked),
            result="SUCCESS" if report.is_valid else "WARNING",
            detail=report.summary,
        )
        if not report.is_valid:
            LOGGER.error(
                "LOG INTEGRITY WARNING: %d issue(s) detected.", len(report.issues)
            )
        return report


    def rehash_chain(self, session: Session) -> tuple[int, int]:
        """Re-hash records written under the earlier canonical format.

        This is the only operation in AETHRA-SEC that rewrites an integrity
        hash, so it is deliberately narrow:

        * it requires ``data.maintain``, not the ``log.verify`` an operator
          uses to read the report, so a normal user cannot touch historical
          records;
        * it refuses if verification finds a CONTENT problem, so a real
          modification cannot be laundered into a fresh, valid-looking chain;
        * it writes an audit record before and after. The maintenance is itself
          part of the log it maintains, including when it refuses.

        Returns:
            ``(examined, rehashed)``.

        Raises:
            PermissionDeniedError: without ``data.maintain``.
            IntegrityError: when the log shows a content modification.
        """
        live = self._access.require(
            session, Permission.DATA_MAINTAIN, target="audit_logs"
        )

        before = self._audit.verify()
        tampered = [issue for issue in before.issues if issue.kind == "CONTENT"]
        if tampered:
            first = tampered[0].record_id
            self._audit.record(
                AuditAction.LOG_CHAIN_REHASHED,
                session=live,
                category=AuditCategory.ADMINISTRATION,
                target_type="audit_logs",
                result="DENIED",
                detail=(
                    f"Refused: {len(tampered)} record(s) do not match their "
                    f"stored hash, the first at id {first}. A modified log is "
                    "investigated, not re-hashed."
                ),
            )
            LOGGER.error(
                "Audit re-hash refused: %d modified record(s), first at id %s.",
                len(tampered),
                first,
            )
            raise IntegrityError(
                f"{len(tampered)} audit record(s) fail their content hash.",
                user_message=(
                    f"The audit log cannot be re-hashed: {len(tampered)} "
                    f"record(s) have been modified since they were written, the "
                    f"first at id {first}. Investigate before running "
                    "maintenance."
                ),
            )

        self._audit.record(
            AuditAction.LOG_CHAIN_REHASHED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="audit_logs",
            target_id=str(before.checked),
            result="WARNING",
            detail=(
                f"Starting re-hash: {before.legacy} record(s) of "
                f"{before.checked} verified are on the earlier hash format. "
                "Record contents are not modified."
            ),
        )

        examined, rehashed = self._audit.rehash_chain()

        after = self._audit.verify()
        self._audit.record(
            AuditAction.LOG_CHAIN_REHASHED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="audit_logs",
            target_id=str(rehashed),
            result="SUCCESS" if after.is_valid else "WARNING",
            detail=(
                f"Re-hashed {rehashed} of {examined} record(s). "
                f"{after.summary}"
            ),
        )
        return examined, rehashed

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export(
        self,
        session: Session,
        output_dir: Path,
        *,
        filename: str = "",
        **filters: Any,
    ) -> Path:
        """Export matching audit records to CSV (§50).

        The export includes each record's integrity hash so an exported copy
        can be checked against the live chain.
        """
        live = self._access.require(session, Permission.LOG_EXPORT, target="audit_logs")
        records = self._repository.search(**{**filters, "limit": filters.get("limit", 20_000)})

        from aethra_sec.reports.writers import write_rows_csv

        name = safe_filename(
            filename or f"aethra_audit_{live.username}_{len(records)}"
        )
        target = resolve_within(Path(output_dir), f"{name}.csv")
        rows = [
            (
                r.id, format_local(r.occurred_at), r.username, r.action, r.category,
                r.target_type, r.target_id, r.result, r.detail, r.host_context,
                r.source, r.record_hash,
            )
            for r in records
        ]
        write_rows_csv(AUDIT_EXPORT_COLUMNS, rows, target)
        self._audit.record(
            AuditAction.DATA_EXPORTED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="audit_logs",
            target_id=target.name,
            detail=f"Exported {len(records)} audit record(s) to {target}.",
        )
        return target
