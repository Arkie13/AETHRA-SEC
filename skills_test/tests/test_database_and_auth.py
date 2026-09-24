"""Database persistence and authentication.

These run against the isolated test schema from the application suite's
``clean_db`` fixture. No production security history is read or written.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills_test.tools.coverage import covers  # noqa: E402

HOSTS = "aethra_sec/database/repositories/hosts.py"
AUTH = "aethra_sec/security/authentication.py"
RBAC = "aethra_sec/security/rbac.py"
PASSWORD = "aethra_sec/security/password.py"
MIGRATIONS = "aethra_sec/database/migrations.py"


# ---------------------------------------------------------------------------
# Host persistence
# ---------------------------------------------------------------------------
@covers(HOSTS, "HostRepository.upsert_observed",
        feature="Hosts", action="Host upsert")
def test_a_host_is_created_once_and_then_updated(clean_db) -> None:
    from aethra_sec.database.repositories import HostRepository
    from aethra_sec.models.enums import EvidenceSource
    from aethra_sec.utils.timeutil import utcnow

    hosts = HostRepository(clean_db)
    first = hosts.upsert_observed(
        "192.168.1.60", observed_at=utcnow(), mac_address="aa:bb:cc:00:00:01",
        source=EvidenceSource.PYSHARK, interface="test", detail="fixture",
    )
    second = hosts.upsert_observed(
        "192.168.1.60", observed_at=utcnow(),
        source=EvidenceSource.PYSHARK, interface="test", detail="fixture",
    )
    assert first and first == second, "a second observation created a duplicate host"
    assert hosts.count_all() == 1
    stored = clean_db.query_one(
        "SELECT mac_address, discovery_source FROM hosts WHERE id = %s", (first,)
    )
    assert stored["mac_address"] == "aa:bb:cc:00:00:01", (
        "an observation without a MAC erased the one already recorded"
    )
    assert stored["discovery_source"] == "PYSHARK"


@covers(HOSTS, "HostRepository.mark_stale_offline",
        feature="Hosts", action="Offline sweep")
def test_a_stale_host_goes_offline_but_is_not_deleted(clean_db) -> None:
    from datetime import timedelta

    from aethra_sec.database.repositories import HostRepository
    from aethra_sec.models.enums import EvidenceSource
    from aethra_sec.utils.timeutil import utcnow

    hosts = HostRepository(clean_db)
    host_id = hosts.upsert_observed(
        "192.168.1.61", observed_at=utcnow() - timedelta(hours=3),
        source=EvidenceSource.PYSHARK,
    )
    clean_db.execute(
        "UPDATE hosts SET last_seen = %s WHERE id = %s",
        (utcnow() - timedelta(hours=3), host_id),
    )
    hosts.mark_stale_offline(utcnow() - timedelta(minutes=15))

    stored = clean_db.query_one(
        "SELECT status, first_seen FROM hosts WHERE id = %s", (host_id,)
    )
    assert stored is not None, "the stale host was deleted instead of marked offline"
    assert stored["status"] == "DOWN"


@covers(HOSTS, "HostRepository.upsert_observed",
        feature="Hosts", action="Return from offline")
def test_a_host_seen_again_returns_to_up(clean_db) -> None:
    from aethra_sec.database.repositories import HostRepository
    from aethra_sec.models.enums import EvidenceSource
    from aethra_sec.utils.timeutil import utcnow

    hosts = HostRepository(clean_db)
    host_id = hosts.upsert_observed(
        "192.168.1.62", observed_at=utcnow(), source=EvidenceSource.PYSHARK
    )
    clean_db.execute(
        "UPDATE hosts SET status = 'DOWN', assessment_detail = %s WHERE id = %s",
        ("offline: not observed recently", host_id),
    )
    hosts.upsert_observed(
        "192.168.1.62", observed_at=utcnow(), source=EvidenceSource.PYSHARK
    )
    stored = clean_db.query_one(
        "SELECT status, assessment_detail FROM hosts WHERE id = %s", (host_id,)
    )
    assert stored["status"] == "UP"
    assert "offline" not in (stored["assessment_detail"] or ""), (
        "the row now reads UP beside a note saying it is offline"
    )


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
@covers(MIGRATIONS, "verify_schema", feature="Database", action="Schema integrity")
def test_the_schema_is_complete(clean_db) -> None:
    from aethra_sec.database.migrations import (
        LATEST_VERSION, current_version, verify_schema,
    )

    ok, detail = verify_schema(clean_db)
    assert ok, f"the schema is incomplete: {detail}"
    assert current_version(clean_db) == LATEST_VERSION


@covers(MIGRATIONS, "", feature="Database", action="No seeded security data")
def test_a_fresh_database_contains_no_security_records(clean_db) -> None:
    """Visual completeness must never come from fabricated rows."""
    for table in ("hosts", "scans", "scan_findings", "snort_alerts",
                  "traffic_anomalies", "incidents", "traffic_records"):
        count = clean_db.query_value(f"SELECT COUNT(*) FROM `{table}`", default=0)
        assert int(count) == 0, f"{table} was seeded with data"


# ---------------------------------------------------------------------------
# Authentication and access control
# ---------------------------------------------------------------------------
@covers(PASSWORD, "PasswordHashService.verify",
        feature="Authentication", action="Password verification")
def test_a_wrong_password_is_rejected() -> None:
    from aethra_sec.security.password import PasswordHashService

    service = PasswordHashService()
    stored = service.hash("correct-horse-battery-staple").hash
    assert service.verify("correct-horse-battery-staple", stored) is True
    assert service.verify("wrong-password", stored) is False, (
        "an incorrect password was accepted"
    )


@covers(PASSWORD, "PasswordHashService.hash",
        feature="Authentication", action="Password storage")
def test_a_password_is_never_stored_in_clear() -> None:
    from aethra_sec.security.password import PasswordHashService

    secret = "correct-horse-battery-staple"
    stored = PasswordHashService().hash(secret).hash
    assert secret not in stored, "the password appears verbatim in the stored hash"
    assert stored.startswith("$argon2") or "$" in stored


@covers(RBAC, "AccessControl.require", feature="Authentication", action="RBAC")
def test_a_permission_the_role_lacks_is_refused(clean_db) -> None:
    from aethra_sec.core.errors import PermissionDeniedError
    from aethra_sec.core.session import PermissionSet, SessionManager
    from aethra_sec.security.rbac import AccessControl

    sessions = SessionManager()
    control = AccessControl(sessions)
    session = sessions.create(
        user_id=1, username="analyst", role="USER",
        permissions=PermissionSet({"alert.view"}), host_context="skills-test",
    )
    control.require(session, "alert.view")  # allowed
    try:
        control.require(session, "user.manage")
    except PermissionDeniedError:
        return
    raise AssertionError("a permission the role does not hold was granted")
