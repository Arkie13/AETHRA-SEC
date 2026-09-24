"""Data retention and maintenance (§79, §110, §111).

Live capture writes continuously, so unbounded growth is a real operational
risk. This service prunes each data class on its own configured schedule.

Two safeguards apply throughout:

* evidence linked to an incident is never pruned automatically;
* audit records are pruned only when an administrator asks, and the pruning is
  itself audited (§33, §110).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from aethra_sec.core.errors import ValidationFailedError
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.connection import DatabaseManager
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.database.repositories.settings import ReportRepository
from aethra_sec.database.repositories.traffic import TrafficRepository
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("services.retention")


@dataclass
class PruneResult:
    """Rows removed by one retention run."""

    traffic_records: int = 0
    traffic_aggregates: int = 0
    snort_alerts: int = 0
    traffic_anomalies: int = 0
    scans: int = 0
    reports: int = 0
    ran_at: datetime = field(default_factory=utcnow)

    @property
    def total(self) -> int:
        """Total rows removed."""
        return (
            self.traffic_records + self.traffic_aggregates + self.snort_alerts
            + self.traffic_anomalies + self.scans + self.reports
        )

    def summary(self) -> str:
        """One-line description for the audit record."""
        if not self.total:
            return "Retention run removed no records."
        return (
            f"Retention removed {self.total:,} row(s): "
            f"{self.traffic_records:,} packet metadata, "
            f"{self.traffic_aggregates:,} aggregates, "
            f"{self.snort_alerts:,} alerts, "
            f"{self.traffic_anomalies:,} anomalies, "
            f"{self.scans:,} scans, {self.reports:,} report records."
        )


class RetentionService:
    """Prunes aged data and provides administrative maintenance operations."""

    def __init__(
        self,
        db: DatabaseManager,
        traffic: TrafficRepository,
        alerts: AlertRepository,
        scans: ScanRepository,
        reports: ReportRepository,
        settings: SettingsService,
        audit: AuditService,
        access: AccessControl,
    ) -> None:
        """Wire the service to its collaborators."""
        self._db = db
        self._traffic = traffic
        self._alerts = alerts
        self._scans = scans
        self._reports = reports
        self._settings = settings
        self._audit = audit
        self._access = access
        self._lock = threading.Lock()
        self.last_result: PruneResult | None = None

    def run(self) -> PruneResult:
        """Prune every data class according to its configured retention.

        Runs on the background scheduler and never raises: a failed prune must
        not stop monitoring.
        """
        result = PruneResult()
        now = utcnow()
        with self._lock:
            for label, hours, action in self._plan(now):
                if hours is None:
                    continue
                try:
                    removed = action()
                    setattr(result, label, removed)
                except Exception:  # noqa: BLE001
                    LOGGER.exception("Retention step '%s' failed.", label)
            self.last_result = result

        if result.total:
            LOGGER.info(result.summary())
            self._audit.record(
                AuditAction.DATA_PRUNED,
                category=AuditCategory.SYSTEM,
                target_type="retention",
                target_id="scheduled",
                detail=result.summary(),
            )
        return result

    def _plan(self, now: datetime) -> list[tuple[str, float | None, Any]]:
        """Build the list of prune steps from the configured retention."""
        def cutoff(hours: float) -> datetime:
            return now - timedelta(hours=hours)

        record_hours = self._settings.get_int("retention.traffic_records_hours", 24)
        aggregate_days = self._settings.get_int("retention.traffic_aggregates_days", 30)
        alert_days = self._settings.get_int("retention.snort_alerts_days", 90)
        scan_days = self._settings.get_int("retention.scan_history_days", 365)

        return [
            (
                "traffic_records",
                record_hours or None,
                lambda: self._prune_traffic_records(cutoff(record_hours)),
            ),
            (
                "traffic_aggregates",
                (aggregate_days * 24) or None,
                lambda: self._traffic.prune_aggregates_before(cutoff(aggregate_days * 24)),
            ),
            (
                "snort_alerts",
                (alert_days * 24) or None,
                lambda: self._alerts.prune_alerts_before(cutoff(alert_days * 24)),
            ),
            (
                "traffic_anomalies",
                (alert_days * 24) or None,
                lambda: self._alerts.prune_anomalies_before(cutoff(alert_days * 24)),
            ),
            (
                "scans",
                (scan_days * 24) or None,
                lambda: self._scans.prune_before(cutoff(scan_days * 24)),
            ),
            (
                "reports",
                (scan_days * 24) or None,
                lambda: self._reports.prune_before(cutoff(scan_days * 24)),
            ),
        ]

    def _prune_traffic_records(self, cutoff: datetime) -> int:
        """Delete aged packet metadata in bounded batches.

        Batching keeps a single delete from locking the table for long enough
        to stall the capture worker's inserts.
        """
        total = 0
        for _ in range(50):
            removed = self._traffic.prune_records_before(cutoff, batch=20_000)
            total += removed
            if removed < 20_000:
                break
        return total

    # ------------------------------------------------------------------
    # Administrative operations
    # ------------------------------------------------------------------
    def run_now(self, session: Session) -> PruneResult:
        """Trigger a retention run on demand (administrator only)."""
        live = self._access.require(session, Permission.DATA_MAINTAIN, target="retention")
        result = self.run()
        self._audit.record(
            AuditAction.DATA_PRUNED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="retention",
            target_id="manual",
            detail=result.summary(),
        )
        return result

    def prune_audit_logs(self, session: Session, days: int) -> int:
        """Prune audit records older than ``days`` (administrator only).

        Pruning necessarily truncates the hash chain's prefix; verification
        reports that as truncation rather than tampering, and this operation is
        itself audited so the removal is never invisible.
        """
        live = self._access.require(session, Permission.DATA_MAINTAIN, target="audit")
        if days < 30:
            raise ValidationFailedError(
                "Audit retention below 30 days was refused.",
                user_message=(
                    "Audit records must be retained for at least 30 days. "
                    "Choose 30 or more."
                ),
            )
        removed = self._audit.prune_before(utcnow() - timedelta(days=days))
        self._audit.record(
            AuditAction.DATA_PRUNED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="audit_logs",
            target_id=str(days),
            detail=(
                f"Pruned {removed:,} audit record(s) older than {days} days. "
                "The integrity chain prefix is now truncated; verification will "
                "report this."
            ),
        )
        return removed

    def table_sizes(self, session: Session) -> dict[str, int]:
        """Row estimates per table, for the maintenance screen."""
        self._access.require(session, Permission.DATA_MAINTAIN)
        return self._db.table_row_counts()

    def database_size_bytes(self, session: Session) -> int:
        """Approximate on-disk size of the schema."""
        self._access.require(session, Permission.DATA_MAINTAIN)
        return self._db.database_size_bytes()

    # Backups live in their own service (``services.backup_service``): they
    # gained a schedule, a file listing and an export destination, which is
    # more than a pruning service should be carrying.
