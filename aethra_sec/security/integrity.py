"""Audit-log integrity through SHA-256 hash chaining (§56).

Each audit record stores:

* ``previous_hash`` - the ``record_hash`` of the record before it;
* ``record_hash``   - ``SHA-256(previous_hash || canonical(record fields))``.

Altering, deleting or re-ordering a record therefore breaks the chain at that
point and at every record after it. Verification reports the first break and
never repairs it silently: a tampered log must stay visibly tampered.

This detects modification through the database (the STRIDE *Tampering*
control). It is not a defence against an attacker who owns the application and
can recompute the whole chain - that is what least-privilege database accounts
and operating-system controls are for.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Sequence

from aethra_sec.models.user import AuditRecord

GENESIS_HASH = "0" * 64
_FIELD_SEPARATOR = "\x1f"
_RECORD_SEPARATOR = "\x1e"


def canonical_payload(record: AuditRecord) -> str:
    """Render the fields covered by the integrity hash.

    Field order is fixed and every value is normalised to text, so the same
    record always produces the same payload regardless of driver types.
    ``id`` is included so a record cannot be swapped with another.
    """
    timestamp = (
        record.occurred_at.astimezone().isoformat() if record.occurred_at else ""
    )
    fields: Sequence[str] = (
        str(record.id or ""),
        timestamp,
        str(record.user_id or ""),
        record.username or "",
        record.action or "",
        record.category or "",
        record.target_type or "",
        record.target_id or "",
        record.result or "",
        record.detail or "",
        record.host_context or "",
        record.source or "",
    )
    return _FIELD_SEPARATOR.join(fields)


def compute_hash(record: AuditRecord, previous_hash: str) -> str:
    """Compute the chained hash for ``record`` following ``previous_hash``."""
    material = f"{previous_hash or GENESIS_HASH}{_RECORD_SEPARATOR}" + canonical_payload(
        record
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IntegrityIssue:
    """One detected integrity problem."""

    record_id: int
    kind: str
    detail: str


@dataclass(frozen=True)
class IntegrityReport:
    """Outcome of an integrity verification run."""

    checked: int
    issues: tuple[IntegrityIssue, ...]
    first_record_id: int | None = None
    last_record_id: int | None = None
    unhashed: int = 0

    @property
    def is_valid(self) -> bool:
        """True when no issue was detected."""
        return not self.issues

    @property
    def summary(self) -> str:
        """One-line result for the Logs screen."""
        if self.checked == 0:
            return "No audit records to verify."
        if self.is_valid:
            extra = (
                f" ({self.unhashed} record(s) predate hashing)"
                if self.unhashed
                else ""
            )
            return f"LOG INTEGRITY OK - {self.checked:,} record(s) verified{extra}."
        return (
            f"LOG INTEGRITY WARNING - {len(self.issues)} problem(s) found across "
            f"{self.checked:,} record(s)."
        )


def verify_chain(
    records: Iterable[AuditRecord], starting_hash: str = GENESIS_HASH
) -> IntegrityReport:
    """Verify a contiguous run of audit records in id order.

    Args:
        records: records ordered by ascending id.
        starting_hash: expected ``previous_hash`` of the first record. Use
            :data:`GENESIS_HASH` when verifying from the beginning of the log.

    Returns:
        A report naming every break. Records written before hashing was
        enabled (empty ``record_hash``) are counted separately and do not
        themselves count as tampering, but they do reset the chain.
    """
    issues: list[IntegrityIssue] = []
    expected_previous = starting_hash
    checked = 0
    unhashed = 0
    first_id: int | None = None
    last_id: int | None = None
    previous_id: int | None = None

    for record in records:
        checked += 1
        record_id = int(record.id or 0)
        if first_id is None:
            first_id = record_id
        last_id = record_id

        if previous_id is not None and record_id <= previous_id:
            issues.append(
                IntegrityIssue(
                    record_id,
                    "ORDER",
                    f"Record id {record_id} does not follow {previous_id}; "
                    "records must be verified in ascending id order.",
                )
            )
        previous_id = record_id

        if not record.record_hash:
            unhashed += 1
            expected_previous = GENESIS_HASH
            continue

        if record.previous_hash != expected_previous:
            issues.append(
                IntegrityIssue(
                    record_id,
                    "CHAIN",
                    "Chain link mismatch: this record does not follow the "
                    "previous record. A record may have been inserted, "
                    "removed or re-ordered.",
                )
            )

        recomputed = compute_hash(record, record.previous_hash or GENESIS_HASH)
        if recomputed != record.record_hash:
            issues.append(
                IntegrityIssue(
                    record_id,
                    "CONTENT",
                    "Stored hash does not match the record contents. The "
                    "record appears to have been modified after it was written.",
                )
            )

        expected_previous = record.record_hash

    return IntegrityReport(
        checked=checked,
        issues=tuple(issues),
        first_record_id=first_id,
        last_record_id=last_id,
        unhashed=unhashed,
    )
