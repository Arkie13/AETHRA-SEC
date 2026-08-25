"""Report generation service (§48-§50, §95, §115).

Generation runs on a worker thread so a large report cannot freeze the
interface, and every generated report is recorded with who produced it, over
what period, and how many records it covered.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Sequence

from aethra_sec.core.errors import ReportError
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import EventType, NotificationPayload
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.settings import ReportRepository
from aethra_sec.models.enums import ExportFormat, NotificationLevel, ReportType
from aethra_sec.models.system import ReportRecord
from aethra_sec.reports.builder import ReportBuilder, ReportDocument
from aethra_sec.reports.writers import write_csv, write_excel, write_pdf, write_rows_csv
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow
from aethra_sec.utils.validation import resolve_within, safe_filename

LOGGER = get_logger("services.reports")


class ReportService:
    """Builds, exports and records reports."""

    def __init__(
        self,
        builder: ReportBuilder,
        repository: ReportRepository,
        event_bus: EventBus,
        audit: AuditService,
        access: AccessControl,
        output_dir: Path,
    ) -> None:
        """Wire the service and ensure the output directory exists."""
        self._builder = builder
        self._repository = repository
        self._bus = event_bus
        self._audit = audit
        self._access = access
        self._output_dir = Path(output_dir)
        self._lock = threading.Lock()
        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            LOGGER.warning("Report directory %s could not be created.", self._output_dir)

    @property
    def output_dir(self) -> Path:
        """Directory reports are written to."""
        return self._output_dir

    def set_output_dir(self, path: Path) -> None:
        """Change the report output directory."""
        self._output_dir = Path(path)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------
    def preview(
        self,
        session: Session,
        report_type: ReportType,
        *,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
        scope: str = "All monitored assets",
    ) -> ReportDocument:
        """Build a report without writing a file (used by the preview pane)."""
        live = self._access.require(
            session, Permission.REPORT_GENERATE, target=str(report_type)
        )
        return self._builder.build(
            report_type,
            period_start=period_start,
            period_end=period_end,
            generated_by=live.username,
            scope=scope,
        )

    def generate(
        self,
        session: Session,
        report_type: ReportType,
        export_format: ExportFormat,
        *,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
        scope: str = "All monitored assets",
        filename: str = "",
    ) -> ReportRecord:
        """Build and write a report, then record its metadata.

        Raises:
            PermissionDeniedError: without ``report.generate``/``report.export``.
            ReportError: when the file cannot be written.
        """
        live = self._access.require(
            session, Permission.REPORT_GENERATE, target=str(report_type)
        )
        self._access.require(session, Permission.REPORT_EXPORT, target=str(export_format))

        end = period_end or utcnow()
        start = period_start or (end - timedelta(days=7))
        document = self._builder.build(
            report_type,
            period_start=start,
            period_end=end,
            generated_by=live.username,
            scope=scope,
        )

        stamp = utcnow().strftime("%Y%m%d_%H%M%S")
        base = filename or f"aethra_{str(report_type).lower()}_{stamp}"
        target = resolve_within(
            self._output_dir, f"{safe_filename(base)}{export_format.extension}"
        )

        writer: Callable[[ReportDocument, Path], Path] = {
            ExportFormat.CSV: write_csv,
            ExportFormat.XLSX: write_excel,
            ExportFormat.PDF: write_pdf,
        }[export_format]
        writer(document, target)

        size = target.stat().st_size if target.exists() else 0
        record = ReportRecord(
            report_type=report_type,
            title=document.title,
            export_format=export_format,
            file_path=str(target),
            period_start=start,
            period_end=end,
            scope=scope,
            record_counts=document.record_counts,
            generated_by=live.user_id,
            generated_by_username=live.username,
            generated_at=document.generated_at,
            file_size_bytes=size,
        )
        try:
            record.id = self._repository.record(record)
        except Exception:  # noqa: BLE001 - the file exists even if metadata fails
            LOGGER.exception("Could not record report metadata.")

        self._audit.record(
            AuditAction.REPORT_GENERATED,
            session=live,
            category=AuditCategory.REPORTING,
            target_type="report",
            target_id=record.id or target.name,
            detail=(
                f"{document.title} ({export_format}) covering "
                f"{document.total_records} record(s) from {start} to {end}; "
                f"written to {target}."
            ),
        )
        self._bus.publish(
            EventType.REPORT_GENERATED,
            NotificationPayload(
                title="Report generated",
                message=(
                    f"{document.title} ({export_format}) - "
                    f"{document.total_records} record(s) -> {target.name}"
                ),
                level=NotificationLevel.SUCCESS,
                category="reporting",
                reference_type="report",
                reference_id=record.id,
            ),
        )
        LOGGER.info(
            "Report generated: %s (%s) with %d record(s) -> %s",
            document.title, export_format, document.total_records, target,
        )
        return record

    def generate_async(
        self,
        session: Session,
        report_type: ReportType,
        export_format: ExportFormat,
        on_complete: Callable[[ReportRecord | None, str], None],
        **kwargs: Any,
    ) -> None:
        """Generate a report on a worker thread (§37).

        Args:
            on_complete: called with ``(record, error_message)``. Exactly one
                of the two is meaningful.
        """

        def worker() -> None:
            try:
                record = self.generate(session, report_type, export_format, **kwargs)
                on_complete(record, "")
            except ReportError as exc:
                on_complete(None, exc.user_message)
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Report generation failed.")
                on_complete(None, str(exc))

        threading.Thread(target=worker, name="report-worker", daemon=True).start()

    # ------------------------------------------------------------------
    # Ad-hoc exports
    # ------------------------------------------------------------------
    def export_records(
        self,
        session: Session,
        columns: Sequence[str],
        rows: Sequence[Sequence[Any]],
        *,
        filename: str,
        description: str = "record export",
    ) -> Path:
        """Export an arbitrary record set to CSV (§50).

        When ``rows`` is empty the file contains "No records available for
        export." rather than being silently skipped.
        """
        live = self._access.require(session, Permission.REPORT_EXPORT, target=filename)
        target = resolve_within(self._output_dir, f"{safe_filename(filename)}.csv")
        write_rows_csv(columns, rows, target)
        self._audit.record(
            AuditAction.DATA_EXPORTED,
            session=live,
            category=AuditCategory.REPORTING,
            target_type="export",
            target_id=target.name,
            detail=f"Exported {len(rows)} record(s) ({description}) to {target}.",
        )
        return target

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------
    def history(self, session: Session, limit: int = 100) -> list[ReportRecord]:
        """Previously generated reports."""
        self._access.require(session, Permission.REPORT_GENERATE)
        return self._repository.list_recent(limit)

    def count(self) -> int:
        """Total reports generated (used by the health screen)."""
        try:
            return self._repository.count_all()
        except Exception:  # noqa: BLE001
            return 0
