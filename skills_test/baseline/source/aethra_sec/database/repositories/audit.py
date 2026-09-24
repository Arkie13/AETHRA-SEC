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

    def append_chained(
        self, record: AuditRecord, compute: Any, genesis: str
    ) -> tuple[int, str]:
        """Append ``record``, linking it to whatever is genuinely last.

        The head is read inside this transaction and locked, so two appenders -
        two windows, a background job, a second process - cannot both link to
        the same predecessor. That is what produced the chain mismatches PT-04
        found: each service instance cached the head it saw at start-up and
        kept linking to it, so a log that had never been touched verified as
        broken. The cache is gone; the database is the head.

        Args:
            record: the record to append. Its ``previous_hash`` and
                ``record_hash`` are filled in here.
            compute: ``compute(record, previous_hash) -> str``, the chained
                hash function.
            genesis: the hash an empty chain starts from. Both are passed in so
                persistence does not import the security package, which imports
                this one.

        Returns:
            ``(record_id, record_hash)``.
        """
        with self.db.transaction() as cursor:
            # FOR UPDATE holds the last row until this transaction commits, so
            # a concurrent append waits here rather than racing for the head.
            cursor.execute(
                "SELECT id, record_hash FROM audit_logs ORDER BY id DESC LIMIT 1 "
                "FOR UPDATE"
            )
            head = cursor.fetchone()
            record.previous_hash = (head or {}).get("record_hash") or genesis

            cursor.execute(
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
                    "",
                ),
            )
            record_id = int(cursor.lastrowid)
            record.id = record_id

            # The id is part of the hashed material, so it can only be computed
            # once the row exists. Both statements commit together: a record
            # with a provisional empty hash is never visible to a reader.
            record.record_hash = compute(record, record.previous_hash)
            cursor.execute(
                "UPDATE audit_logs SET record_hash = %s WHERE id = %s",
                (record.record_hash, record_id),
            )
        return record_id, record.record_hash

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

    def rehash_chain(
        self, compute: Any, genesis: str, batch_size: int = 500
    ) -> tuple[int, int]:
        """Recompute the chain over every record, in id order.

        Only the two hash columns are written. The record's own fields are read
        and hashed but never updated, so this cannot alter evidence even by
        accident - there is no UPDATE here that names an evidence column.

        Each batch commits as one transaction, so an interrupted run leaves a
        prefix that is consistent rather than a chain half in each format.

        Returns:
            ``(examined, rewritten)``.
        """
        previous_hash = genesis
        examined = 0
        rewritten = 0
        cursor_id = 0

        while True:
            batch = self.iterate_for_verification(cursor_id, batch_size)
            if not batch:
                break
            with self.db.transaction() as cursor:
                for record in batch:
                    examined += 1
                    fresh = compute(record, previous_hash)
                    if (
                        fresh != record.record_hash
                        or record.previous_hash != previous_hash
                    ):
                        cursor.execute(
                            "UPDATE audit_logs SET previous_hash = %s, "
                            "record_hash = %s WHERE id = %s",
                            (previous_hash, fresh, record.id),
                        )
                        rewritten += 1
                    previous_hash = fresh
            cursor_id = int(batch[-1].id or cursor_id)
            if len(batch) < batch_size:
                break

        return examined, rewritten

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
