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
from datetime import UTC, datetime
from typing import Iterable, Sequence

from aethra_sec.models.user import AuditRecord

GENESIS_HASH = "0" * 64
_FIELD_SEPARATOR = "\x1f"
_RECORD_SEPARATOR = "\x1e"


def canonical_timestamp(moment: datetime | None) -> str:
    """Render an audit timestamp for hashing, identically on every host.

    The hash is evidence, so its input cannot depend on where or when the
    verification runs. This previously used ``astimezone()`` with no argument,
    which converts to whatever the *host's* local zone happens to be and writes
    that offset into the string: the same stored record hashed to one value in
    Asia/Manila and a different one in UTC, so moving the database, or a host
    crossing a daylight-saving boundary, would have turned every record into a
    content mismatch at once.

    Everything is normalised to UTC with a fixed six-digit fractional part -
    the precision of the ``DATETIME(6)`` column, so no rounding happens between
    the value hashed and the value stored. A naive datetime is read as UTC,
    which is how values come back from MySQL.
    """
    if moment is None:
        return ""
    absolute = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    return absolute.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def canonical_payload(record: AuditRecord) -> str:
    """Render the fields covered by the integrity hash.

    Field order is fixed and every value is normalised to text, so the same
    record always produces the same payload regardless of driver types, host
    timezone or display formatting. ``id`` is included so a record cannot be
    swapped with another.
    """
    return _FIELD_SEPARATOR.join(_payload_fields(record))


def _payload_fields(record: AuditRecord) -> Sequence[str]:
    """The hashed fields, in their fixed order."""
    return (
        str(record.id or ""),
        canonical_timestamp(record.occurred_at),
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


def compute_hash(record: AuditRecord, previous_hash: str) -> str:
    """Compute the chained hash for ``record`` following ``previous_hash``."""
    return _digest(previous_hash, canonical_payload(record))


def _digest(previous_hash: str, payload: str) -> str:
    """SHA-256 over the predecessor's hash and this record's canonical fields."""
    material = f"{previous_hash or GENESIS_HASH}{_RECORD_SEPARATOR}{payload}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _legacy_hash(record: AuditRecord, previous_hash: str) -> str:
    """The hash a record written before the timestamp fix would carry.

    The old canonical form rendered the timestamp with ``astimezone()``, which
    writes the *verifying host's* offset into the hashed material. Records
    written under it are intact; they are simply hashed against a
    representation that was never stable. Recognising that form is what lets
    verification distinguish "written under the old rules" from "modified after
    it was written", instead of condemning a whole archive on the day the
    format changed.

    Only meaningful on the host that wrote the records - which is precisely why
    the format was replaced.
    """
    legacy_timestamp = (
        record.occurred_at.astimezone().isoformat() if record.occurred_at else ""
    )
    payload = _FIELD_SEPARATOR.join(
        (legacy_timestamp if index == 1 else field)
        for index, field in enumerate(_payload_fields(record))
    )
    return _digest(previous_hash, payload)


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
    #: Records that are intact but hashed under the pre-fix representation.
    #: Counted apart from tampering because they are not the same thing.
    legacy: int = 0

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
    legacy = 0
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
                    f"Chain link broken at record {record_id} "
                    f"({record.action or 'unknown action'} by "
                    f"{record.username or 'system'} at "
                    f"{canonical_timestamp(record.occurred_at) or 'unknown time'}): "
                    "it names a predecessor that is not the record before it, "
                    "so a record may have been inserted, removed or re-ordered "
                    "here. Every record after this one is chained to this "
                    "record's hash and is reported separately only if its own "
                    "link or contents also fail.",
                )
            )

        previous = record.previous_hash or GENESIS_HASH
        recomputed = compute_hash(record, previous)
        if recomputed != record.record_hash:
            if _legacy_hash(record, previous) == record.record_hash:
                # Intact, but hashed under the pre-fix representation. Naming
                # this separately is the difference between an honest migration
                # note and a false accusation of tampering.
                legacy += 1
                issues.append(
                    IntegrityIssue(
                        record_id,
                        "LEGACY",
                        f"Record {record_id} verifies only against the earlier "
                        "hash format, whose timestamp rendering depended on the "
                        "host timezone. The record's contents are unchanged. "
                        "An administrator can re-hash the log to the stable "
                        "format; nothing is altered until they do.",
                    )
                )
            else:
                issues.append(
                    IntegrityIssue(
                        record_id,
                        "CONTENT",
                        f"Contents of record {record_id} "
                        f"({record.action or 'unknown action'} by "
                        f"{record.username or 'system'}) do not match its stored "
                        "hash: the record was modified after it was written. "
                        "Its hash is what the next record links to, so the "
                        "chain from here on cannot be trusted either.",
                    )
                )

        expected_previous = record.record_hash

    return IntegrityReport(
        checked=checked,
        issues=tuple(issues),
        first_record_id=first_id,
        last_record_id=last_id,
        unhashed=unhashed,
        legacy=legacy,
    )
