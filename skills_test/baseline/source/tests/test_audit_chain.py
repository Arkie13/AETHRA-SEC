"""Audit-chain determinism and maintenance (§57).

PT-04 reported chain noise: 52 link mismatches in a log nobody had touched.
Two defects produced it, and both are pinned here.

The first was a cached head. Each ``AuditService`` read the last record's hash
once at start-up and kept linking new records to it, so a second window or a
background job in another process wrote a record whose predecessor was already
stale.

The second was in the hashed material itself: the timestamp was rendered with
``astimezone()``, which writes the *verifying host's* UTC offset into the
string. The same record hashed to different values in different timezones, so
moving the database - or a host crossing a daylight-saving boundary - would
have condemned every record at once.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from aethra_sec.models.user import AuditRecord
from aethra_sec.security.integrity import (
    GENESIS_HASH,
    canonical_payload,
    canonical_timestamp,
    compute_hash,
    verify_chain,
)

ROOT = Path(__file__).resolve().parent.parent
AUDIT = ROOT / "aethra_sec" / "security" / "audit.py"
LOGS = ROOT / "aethra_sec" / "services" / "log_service.py"
REPO = ROOT / "aethra_sec" / "database" / "repositories" / "audit.py"


def _code_only(path: Path) -> str:
    """Source with docstrings removed, so prose about a bug is not the bug."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def _record(record_id: int, **overrides: object) -> AuditRecord:
    """A record with every hashed field populated."""
    fields: dict[str, object] = {
        "id": record_id,
        "occurred_at": datetime(2026, 9, 3, 18, 42, 33, 793408, tzinfo=UTC),
        "user_id": 7,
        "username": "operator",
        "action": "LOGIN_SUCCESS",
        "category": "AUTHENTICATION",
        "target_type": "session",
        "target_id": "42",
        "result": "SUCCESS",
        "detail": "signed in",
        "host_context": "workstation",
        "source": "UI",
    }
    fields.update(overrides)
    return AuditRecord(**fields)  # type: ignore[arg-type]


class TestTheHashedMaterialIsStable:
    """The same record must hash the same way everywhere."""

    def test_the_timezone_the_value_arrives_in_does_not_matter(self) -> None:
        moment = datetime(2026, 9, 3, 18, 42, 33, 793408, tzinfo=UTC)
        rendered = {
            canonical_timestamp(moment),
            canonical_timestamp(moment.astimezone(timezone(timedelta(hours=8)))),
            canonical_timestamp(moment.astimezone(timezone(-timedelta(hours=5)))),
            # Naive values come back this way from MySQL and mean UTC.
            canonical_timestamp(moment.replace(tzinfo=None)),
        }
        assert len(rendered) == 1, f"the same instant rendered {len(rendered)} ways"

    def test_the_rendering_carries_no_local_offset(self) -> None:
        """A local offset in the material is what made the hash host-dependent."""
        rendered = canonical_timestamp(datetime(2026, 1, 1, tzinfo=UTC))
        assert rendered.endswith("Z")
        assert "+" not in rendered

    def test_the_full_precision_of_the_column_survives(self) -> None:
        """DATETIME(6) stores microseconds; rounding them would break re-reads."""
        moment = datetime(2026, 9, 3, 18, 42, 33, 793408, tzinfo=UTC)
        assert "793408" in canonical_timestamp(moment)

    def test_the_payload_is_ordered_and_reproducible(self) -> None:
        assert canonical_payload(_record(1)) == canonical_payload(_record(1))

    def test_every_evidence_field_is_covered(self) -> None:
        """A field outside the hash could be altered without detection."""
        base = compute_hash(_record(1), GENESIS_HASH)
        for field, altered in (
            ("username", "someone else"),
            ("action", "LOGIN_FAILED"),
            ("category", "SYSTEM"),
            ("target_type", "user"),
            ("target_id", "99"),
            ("result", "FAILURE"),
            ("detail", "something else"),
            ("host_context", "another host"),
            ("source", "API"),
            ("user_id", 8),
            ("id", 2),
            ("occurred_at", datetime(2020, 1, 1, tzinfo=UTC)),
        ):
            changed = compute_hash(_record(1, **{field: altered}), GENESIS_HASH)
            assert changed != base, f"{field} is not covered by the hash"

    def test_the_predecessor_is_part_of_the_hash(self) -> None:
        record = _record(1)
        assert compute_hash(record, GENESIS_HASH) != compute_hash(record, "a" * 64)


class TestVerificationNamesWhatFailed:
    """A report has to be actionable, not just negative."""

    def _chain(self, count: int = 3) -> list[AuditRecord]:
        records: list[AuditRecord] = []
        previous = GENESIS_HASH
        for index in range(1, count + 1):
            record = _record(index, detail=f"event {index}")
            record.previous_hash = previous
            record.record_hash = compute_hash(record, previous)
            records.append(record)
            previous = record.record_hash
        return records

    def test_an_untouched_chain_verifies(self) -> None:
        assert verify_chain(self._chain()).is_valid

    def test_a_modified_record_is_named_with_its_actor_and_action(self) -> None:
        records = self._chain()
        records[1].detail = "quietly rewritten"
        content = [i for i in verify_chain(records).issues if i.kind == "CONTENT"]
        assert content, "a modified record was not detected"
        assert content[0].record_id == 2
        assert "operator" in content[0].detail
        assert "LOGIN_SUCCESS" in content[0].detail

    def test_the_report_says_that_later_records_depend_on_the_break(self) -> None:
        records = self._chain()
        records[1].detail = "quietly rewritten"
        content = [i for i in verify_chain(records).issues if i.kind == "CONTENT"][0]
        assert "chain from here on" in content.detail.lower()

    def test_a_removed_record_breaks_the_link_and_says_so(self) -> None:
        records = self._chain(4)
        del records[1]
        chain = [i for i in verify_chain(records).issues if i.kind == "CHAIN"]
        assert chain, "a removed record did not break the chain"
        assert "inserted, removed or re-ordered" in chain[0].detail

    def test_verification_reports_rather_than_repairs(self) -> None:
        """A tampered log must stay visibly tampered."""
        records = self._chain()
        records[1].detail = "quietly rewritten"
        stored = records[1].record_hash
        verify_chain(records)
        assert records[1].record_hash == stored, "verification rewrote the hash"
        assert records[1].detail == "quietly rewritten", "verification rewrote the record"


class TestTheHeadComesFromTheDatabase:
    """The cached-head defect, read out of the source."""

    def test_the_service_keeps_no_cached_head(self) -> None:
        assert "_head_hash" not in _code_only(AUDIT), (
            "the audit service caches a chain head again; two writers will "
            "link to the same predecessor"
        )

    def test_appends_go_through_the_locking_transaction(self) -> None:
        assert "append_chained" in _code_only(AUDIT)

    def test_the_head_is_read_under_a_row_lock(self) -> None:
        assert "FOR UPDATE" in _code_only(REPO), (
            "concurrent appends can race for the head without a row lock"
        )


class TestMaintenanceIsGovernedAndRecorded:
    """The one operation that rewrites a hash."""

    def test_it_requires_the_maintenance_permission_not_the_read_one(self) -> None:
        code = _code_only(LOGS)
        rehash = code[code.index("def rehash_chain") :]
        assert "Permission.DATA_MAINTAIN" in rehash[: rehash.index("def export")], (
            "re-hashing historical audit records is not gated on data.maintain"
        )

    def test_it_refuses_when_the_log_shows_a_modification(self) -> None:
        """Otherwise maintenance would launder tampering into a valid chain."""
        code = _code_only(LOGS)
        assert "CONTENT" in code
        assert "IntegrityError" in code

    def test_it_records_its_own_maintenance(self) -> None:
        assert _code_only(LOGS).count("AuditAction.LOG_CHAIN_REHASHED") >= 3, (
            "the refusal, the start and the outcome must each be audited"
        )

    def test_the_rewrite_touches_only_the_hash_columns(self) -> None:
        """No UPDATE in the re-hash may name an evidence column."""
        code = _code_only(REPO)
        rehash = code[code.index("def rehash_chain") : code.index("def last_record")]
        assert "previous_hash = %s" in rehash and "record_hash = %s" in rehash
        for evidence in ("detail", "username", "action", "occurred_at", "result"):
            assert f"{evidence} = %s" not in rehash, (
                f"the re-hash writes {evidence}, which is evidence"
            )
