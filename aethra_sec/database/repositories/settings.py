"""System settings, integration status, notifications, errors and reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from aethra_sec.database.repositories.base import (
    Repository,
    as_bool,
    as_dt,
    as_int,
    as_text,
    decode_json,
    encode_json,
    limit_clause,
)
from aethra_sec.models.enums import (
    ExportFormat,
    NotificationLevel,
    ReportType,
    ServiceState,
)
from aethra_sec.models.system import (
    AppError,
    Notification,
    ReportRecord,
    ServiceStatus,
    SystemSetting,
)
from aethra_sec.utils.timeutil import to_db, utcnow


class SettingsRepository(Repository):
    """Reads and writes the administrator-tunable settings table."""

    @staticmethod
    def _map(row: dict[str, Any]) -> SystemSetting:
        """Map a row to :class:`SystemSetting`."""
        return SystemSetting(
            key=as_text(row.get("setting_key")),
            value=as_text(row.get("setting_value")),
            value_type=as_text(row.get("value_type")) or "str",
            category=as_text(row.get("category")),
            description=as_text(row.get("description")),
            updated_by=as_int(row.get("updated_by")),
            updated_at=as_dt(row.get("updated_at")),
        )

    def load_all(self) -> dict[str, SystemSetting]:
        """Load every setting keyed by setting key."""
        rows = self.db.query(
            "SELECT setting_key, setting_value, value_type, category, "
            "description, updated_by, updated_at FROM system_settings"
        )
        return {as_text(r["setting_key"]): self._map(r) for r in rows}

    def list_by_category(self, category: str = "") -> list[SystemSetting]:
        """Settings in one category, or all when ``category`` is empty."""
        if category:
            rows = self.db.query(
                "SELECT setting_key, setting_value, value_type, category, "
                "description, updated_by, updated_at FROM system_settings "
                "WHERE category = %s ORDER BY setting_key",
                (category,),
            )
        else:
            rows = self.db.query(
                "SELECT setting_key, setting_value, value_type, category, "
                "description, updated_by, updated_at FROM system_settings "
                "ORDER BY category, setting_key"
            )
        return self._map_all(rows, self._map)

    def get(self, key: str) -> SystemSetting | None:
        """Fetch one setting."""
        row = self.db.query_one(
            "SELECT setting_key, setting_value, value_type, category, "
            "description, updated_by, updated_at FROM system_settings "
            "WHERE setting_key = %s",
            (key,),
        )
        return self._map(row) if row else None

    def set_value(self, key: str, value: str, user_id: int | None) -> None:
        """Update a setting's value, recording who changed it."""
        self.db.execute(
            "UPDATE system_settings SET setting_value = %s, updated_by = %s, "
            "updated_at = %s WHERE setting_key = %s",
            (str(value)[:512], user_id, to_db(utcnow()), key),
        )

    def categories(self) -> list[str]:
        """Distinct setting categories."""
        rows = self.db.query(
            "SELECT DISTINCT category FROM system_settings ORDER BY category"
        )
        return [as_text(r["category"]) for r in rows]


class IntegrationStatusRepository(Repository):
    """Persists the last observed state of each subsystem (§10, §39)."""

    def upsert(self, status: ServiceStatus) -> None:
        """Record a real probe result."""
        self.db.execute(
            "INSERT INTO integration_status (name, state, detail, last_checked, "
            "last_success, last_error, metadata) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE state = VALUES(state), "
            "detail = VALUES(detail), last_checked = VALUES(last_checked), "
            "last_success = COALESCE(VALUES(last_success), last_success), "
            "last_error = VALUES(last_error), metadata = VALUES(metadata)",
            (
                status.name[:48], str(status.state), status.detail[:512],
                to_db(status.last_checked or utcnow()), to_db(status.last_success),
                status.last_error[:512], encode_json(status.metadata),
            ),
        )

    def load_all(self) -> dict[str, ServiceStatus]:
        """Load every recorded subsystem status."""
        rows = self.db.query(
            "SELECT name, state, detail, last_checked, last_success, "
            "last_error, metadata FROM integration_status ORDER BY name"
        )
        return {
            as_text(r["name"]): ServiceStatus(
                name=as_text(r["name"]),
                state=ServiceState.parse(r["state"], ServiceState.UNKNOWN),
                detail=as_text(r["detail"]),
                last_checked=as_dt(r["last_checked"]),
                last_success=as_dt(r["last_success"]),
                last_error=as_text(r["last_error"]),
                metadata=decode_json(r["metadata"], {}),
            )
            for r in rows
        }


class NotificationRepository(Repository):
    """In-application notifications for genuine events (§52)."""

    @staticmethod
    def _map(row: dict[str, Any]) -> Notification:
        """Map a row to :class:`Notification`."""
        return Notification(
            id=as_int(row.get("id")),
            user_id=as_int(row.get("user_id")),
            level=NotificationLevel.parse(row.get("level"), NotificationLevel.INFO),
            title=as_text(row.get("title")),
            message=as_text(row.get("message")),
            category=as_text(row.get("category")),
            reference_type=as_text(row.get("reference_type")),
            reference_id=as_int(row.get("reference_id")),
            is_read=as_bool(row.get("is_read")),
            created_at=as_dt(row.get("created_at")),
            read_at=as_dt(row.get("read_at")),
        )

    def create(self, notification: Notification) -> int:
        """Insert a notification."""
        return self.db.insert(
            "INSERT INTO notifications (user_id, level, title, message, "
            "category, reference_type, reference_id, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                notification.user_id, str(notification.level),
                notification.title[:190], notification.message[:512],
                notification.category[:32], notification.reference_type[:48],
                notification.reference_id, to_db(notification.created_at or utcnow()),
            ),
        )

    def list_recent(
        self, user_id: int | None = None, *, unread_only: bool = False, limit: int = 50
    ) -> list[Notification]:
        """Notifications visible to a user (broadcast rows have no user id)."""
        clauses = ["(user_id IS NULL OR user_id = %s)"]
        params: list[Any] = [user_id]
        if unread_only:
            clauses.append("is_read = 0")
        limit_sql, limit_params = limit_clause(limit)
        rows = self.db.query(
            "SELECT id, user_id, level, title, message, category, "
            "reference_type, reference_id, is_read, created_at, read_at "
            f"FROM notifications WHERE {' AND '.join(clauses)} "
            f"ORDER BY created_at DESC {limit_sql}",
            (*params, *limit_params),
        )
        return self._map_all(rows, self._map)

    def mark_read(self, notification_id: int) -> None:
        """Mark one notification as read."""
        self.db.execute(
            "UPDATE notifications SET is_read = 1, read_at = %s WHERE id = %s",
            (to_db(utcnow()), notification_id),
        )

    def mark_all_read(self, user_id: int | None) -> int:
        """Mark every notification visible to a user as read."""
        return self.db.execute(
            "UPDATE notifications SET is_read = 1, read_at = %s "
            "WHERE is_read = 0 AND (user_id IS NULL OR user_id = %s)",
            (to_db(utcnow()), user_id),
        )

    def unread_count(self, user_id: int | None) -> int:
        """Number of unread notifications for a user."""
        return self.count(
            "SELECT COUNT(*) FROM notifications WHERE is_read = 0 "
            "AND (user_id IS NULL OR user_id = %s)",
            (user_id,),
        )

    def prune_excess(self, keep: int = 500) -> int:
        """Trim the notification list to the most recent ``keep`` rows."""
        threshold = self.db.query_value(
            "SELECT id FROM notifications ORDER BY id DESC LIMIT 1 OFFSET %s",
            (max(1, int(keep)),),
        )
        if threshold is None:
            return 0
        return self.db.execute(
            "DELETE FROM notifications WHERE id <= %s", (int(threshold),)
        )


class ErrorRepository(Repository):
    """Recorded subsystem failures (§57, §58)."""

    def record(
        self, component: str, message: str, detail: str = "", severity: str = "ERROR"
    ) -> int:
        """Append an error record."""
        return self.db.insert(
            "INSERT INTO app_errors (component, message, detail, severity, "
            "occurred_at) VALUES (%s, %s, %s, %s, %s)",
            (component[:64], message[:512], detail, severity[:16], to_db(utcnow())),
        )

    def list_recent(self, limit: int = 100, unacknowledged_only: bool = False) -> list[AppError]:
        """Recent errors for the System Health screen."""
        where = "WHERE acknowledged = 0" if unacknowledged_only else ""
        limit_sql, limit_params = limit_clause(limit)
        rows = self.db.query(
            "SELECT id, component, message, detail, severity, occurred_at, "
            f"acknowledged FROM app_errors {where} ORDER BY occurred_at DESC {limit_sql}",
            limit_params,
        )
        return [
            AppError(
                id=as_int(r["id"]),
                component=as_text(r["component"]),
                message=as_text(r["message"]),
                detail=as_text(r["detail"]),
                severity=as_text(r["severity"]),
                occurred_at=as_dt(r["occurred_at"]),
                acknowledged=as_bool(r["acknowledged"]),
            )
            for r in rows
        ]

    def acknowledge(self, error_id: int) -> None:
        """Mark an error as acknowledged."""
        self.db.execute(
            "UPDATE app_errors SET acknowledged = 1 WHERE id = %s", (error_id,)
        )

    def count_unacknowledged(self) -> int:
        """Number of unacknowledged errors."""
        return self.count("SELECT COUNT(*) FROM app_errors WHERE acknowledged = 0")


class ReportRepository(Repository):
    """Report metadata, so every generated report is auditable (§95)."""

    def record(self, report: ReportRecord) -> int:
        """Insert report metadata after a successful generation."""
        return self.db.insert(
            "INSERT INTO reports (report_type, title, export_format, "
            "file_path, period_start, period_end, scope, record_counts, "
            "generated_by, generated_at, file_size_bytes) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                str(report.report_type), report.title[:190],
                str(report.export_format), report.file_path[:512],
                to_db(report.period_start), to_db(report.period_end),
                report.scope[:255], encode_json(report.record_counts),
                report.generated_by, to_db(report.generated_at or utcnow()),
                report.file_size_bytes,
            ),
        )

    def list_recent(self, limit: int = 100) -> list[ReportRecord]:
        """Recently generated reports."""
        limit_sql, limit_params = limit_clause(limit)
        rows = self.db.query(
            "SELECT r.id, r.report_type, r.title, r.export_format, r.file_path, "
            "r.period_start, r.period_end, r.scope, r.record_counts, "
            "r.generated_by, r.generated_at, r.file_size_bytes, "
            "u.username AS generated_by_username FROM reports r "
            f"LEFT JOIN users u ON u.id = r.generated_by "
            f"ORDER BY r.generated_at DESC {limit_sql}",
            limit_params,
        )
        return [
            ReportRecord(
                id=as_int(r["id"]),
                report_type=ReportType.parse(
                    r["report_type"], ReportType.SECURITY_ASSESSMENT
                ),
                title=as_text(r["title"]),
                export_format=ExportFormat.parse(r["export_format"], ExportFormat.PDF),
                file_path=as_text(r["file_path"]),
                period_start=as_dt(r["period_start"]),
                period_end=as_dt(r["period_end"]),
                scope=as_text(r["scope"]),
                record_counts=decode_json(r["record_counts"], {}),
                generated_by=as_int(r["generated_by"]),
                generated_by_username=as_text(r["generated_by_username"]),
                generated_at=as_dt(r["generated_at"]),
                file_size_bytes=as_int(r["file_size_bytes"]) or 0,
            )
            for r in rows
        ]

    def count_all(self) -> int:
        """Total reports generated."""
        return self.count("SELECT COUNT(*) FROM reports")

    def prune_before(self, cutoff: datetime) -> int:
        """Delete report metadata older than ``cutoff`` (files are untouched)."""
        return self.db.execute(
            "DELETE FROM reports WHERE generated_at < %s", (to_db(cutoff),)
        )
