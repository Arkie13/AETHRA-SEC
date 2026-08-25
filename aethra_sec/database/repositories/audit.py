"""Audit trail persistence with chained integrity hashes (§33, §56).

The audit table is append-only from the application's point of view: this
repository exposes ``append`` and read/verify operations, and a single
administrator-only prune that is itself audited. There is no update method.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from aethra_sec.database.repositories.base import (
    QueryFilter,
    Repository,
    as_dt,
    as_int,
    as_text,
    limit_clause,
    order_clause,
)
from aethra_sec.models.user import AuditRecord
from aethra_sec.utils.timeutil import to_db, utcnow

_FILTERABLE = {
    "occurred_at",
    "user_id",
    "username",
    "action",
    "category",
    "target_type",
    "target_id",
    "result",
    "source",
    "detail",
}
_SORTABLE = {"occurred_at", "id", "username", "action", "category", "result"}

_SELECT = (
    "SELECT id, occurred_at, user_id, username, action, category, target_type, "
    "target_id, result, detail, host_context, source, previous_hash, record_hash "
    "FROM audit_logs"
)


class AuditRepository(Repository):
    """Reads and appends audit records."""

    @staticmethod
    def _map(row: dict[str, Any]) -> AuditRecord:
        """Map a row to :class:`AuditRecord`."""
        return AuditRecord(
            id=as_int(row.get("id")),
            occurred_at=as_dt(row.get("occurred_at")),
            user_id=as_int(row.get("user_id")),
            username=as_text(row.get("username")),
            action=as_text(row.get("action")),
            category=as_text(row.get("category")),
            target_type=as_text(row.get("target_type")),
            target_id=as_text(row.get("target_id")),
            result=as_text(row.get("result")),
            detail=as_text(row.get("detail")),
            host_context=as_text(row.get("host_context")),
            source=as_text(row.get("source")),
            previous_hash=as_text(row.get("previous_hash")),
            record_hash=as_text(row.get("record_hash")),
        )

    def append(self, record: AuditRecord) -> int:
        """Insert an audit record and return its id."""
        return self.db.insert(
            "INSERT INTO audit_logs (occurred_at, user_id, username, action, "
            "category, target_type, target_id, result, detail, host_context, "
            "source, previous_hash, record_hash) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                to_db(record.occurred_at or utcnow()),
                record.user_id,
                record.username[:64],
                record.action[:64],
                record.category[:32],
                record.target_type[:48],
                record.target_id[:64],
                record.result[:16],
                record.detail,
                record.host_context[:128],
                record.source[:24],
                record.previous_hash,
                record.record_hash,
            ),
        )

    def last_record(self) -> AuditRecord | None:
        """Most recently inserted audit record (the hash-chain head)."""
        row = self.db.query_one(f"{_SELECT} ORDER BY id DESC LIMIT 1")
        return self._map(row) if row else None

    def get(self, record_id: int) -> AuditRecord | None:
        """Fetch one audit record."""
        row = self.db.query_one(f"{_SELECT} WHERE id = %s", (record_id,))
        return self._map(row) if row else None

    def search(
        self,
        *,
        text: str = "",
        username: str = "",
        action: str = "",
        category: str = "",
        result: str = "",
        start: datetime | None = None,
        end: datetime | None = None,
        sort_by: str = "occurred_at",
        sort_dir: str = "DESC",
        limit: int = 500,
        offset: int = 0,
    ) -> list[AuditRecord]:
        """Search audit records with validated filters and sorting."""
        query = QueryFilter(_FILTERABLE)
        query.equals("username", username)
        query.equals("action", action)
        query.equals("category", category)
        query.equals("result", result)
        query.gte("occurred_at", to_db(start))
        query.lte("occurred_at", to_db(end))
        query.any_of(("action", "detail", "target_id", "username"), text)

        order = order_clause(sort_by, sort_dir, _SORTABLE, "occurred_at")
        limit_sql, limit_params = limit_clause(limit, offset)
        rows = self.db.query(
            f"{_SELECT} {query.where_clause()} {order} {limit_sql}",
            (*query.bound_params(), *limit_params),
        )
        return self._map_all(rows, self._map)

    def count_matching(
        self,
        *,
        text: str = "",
        username: str = "",
        action: str = "",
        category: str = "",
        result: str = "",
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> int:
        """Number of audit records matching the same filters as :meth:`search`."""
        query = QueryFilter(_FILTERABLE)
        query.equals("username", username)
        query.equals("action", action)
        query.equals("category", category)
        query.equals("result", result)
        query.gte("occurred_at", to_db(start))
        query.lte("occurred_at", to_db(end))
        query.any_of(("action", "detail", "target_id", "username"), text)
        return self.count(
            f"SELECT COUNT(*) FROM audit_logs {query.where_clause()}",
            query.bound_params(),
        )

    def iterate_for_verification(
        self, start_id: int = 0, batch_size: int = 1000
    ) -> list[AuditRecord]:
        """Fetch a contiguous batch of records in id order for chain checking."""
        rows = self.db.query(
            f"{_SELECT} WHERE id > %s ORDER BY id ASC LIMIT %s",
            (start_id, max(1, min(int(batch_size), 5000))),
        )
        return self._map_all(rows, self._map)

    def total_count(self) -> int:
        """Total number of audit records."""
        return self.count("SELECT COUNT(*) FROM audit_logs")

    def distinct_actions(self) -> list[str]:
        """Distinct action names, for the log filter drop-down."""
        rows = self.db.query(
            "SELECT DISTINCT action FROM audit_logs ORDER BY action LIMIT 200"
        )
        return [as_text(r["action"]) for r in rows]

    def distinct_categories(self) -> list[str]:
        """Distinct categories, for the log filter drop-down."""
        rows = self.db.query(
            "SELECT DISTINCT category FROM audit_logs ORDER BY category LIMIT 200"
        )
        return [as_text(r["category"]) for r in rows]

    def recent_activity(self, limit: int = 10) -> list[AuditRecord]:
        """Latest audit records for the dashboard 'Recent activity' widget."""
        rows = self.db.query(
            f"{_SELECT} ORDER BY occurred_at DESC LIMIT %s",
            (max(1, min(int(limit), 200)),),
        )
        return self._map_all(rows, self._map)

    def prune_before(self, cutoff: datetime) -> int:
        """Delete audit records older than ``cutoff``.

        Administrator-triggered only; the caller writes an audit record about
        the pruning itself. Note that pruning necessarily breaks the hash chain
        for the removed prefix - :meth:`verify` reports this as a truncation
        rather than as tampering.
        """
        return self.db.execute(
            "DELETE FROM audit_logs WHERE occurred_at < %s", (to_db(cutoff),)
        )
