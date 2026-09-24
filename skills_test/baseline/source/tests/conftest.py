"""Shared pytest fixtures.

Synthetic fixtures live **only** in this test suite (§99). Nothing here is
importable by the running application, and the application itself never
constructs a packet, alert, finding or incident that a real tool did not
produce.

Database-backed tests are skipped unless a MySQL-compatible server is reachable
with the configured credentials, so the pure-logic suite runs anywhere.
"""

from __future__ import annotations

import os
import socket
import struct
from datetime import timedelta
from typing import Iterator

import pytest

from aethra_sec.config.settings import (
    AppSettings,
    AuthorizationSettings,
    DatabaseSettings,
    load_settings,
)
from aethra_sec.database.connection import DatabaseManager, server_reachable
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.utils.timeutil import utcnow

#: Test schema name, kept separate from any real installation.
TEST_DATABASE = os.environ.get("AETHRA_TEST_DB_NAME", "aethra_sec_test")


# ---------------------------------------------------------------------------
# Tk
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def tk_root() -> Iterator[object]:
    """One Tk interpreter, shared by every widget test in the session.

    Creating and destroying an interpreter per test is unreliable on Windows:
    measured here, roughly one run in three had a later ``tk.Tk()`` raise
    TclError, and because each of those tests guards the call with a skip, the
    run stayed green while silently losing the coverage. Reusing one root
    removes the flake - tests build their widgets as children of it and
    destroy those, not the interpreter.
    """
    import tkinter as tk

    try:
        root = tk.Tk()
    except tk.TclError:  # pragma: no cover - genuinely headless
        pytest.skip("no display available")
    root.withdraw()
    try:
        yield root
    finally:
        root.destroy()


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def app_settings() -> AppSettings:
    """Deployment settings as configured for this machine."""
    return load_settings()


@pytest.fixture(scope="session")
def test_database_settings(app_settings: AppSettings) -> DatabaseSettings:
    """Database settings pointing at the isolated test schema."""
    base = app_settings.database
    return DatabaseSettings(
        host=base.host,
        port=base.port,
        database=TEST_DATABASE,
        user=base.user,
        password=base.password,
        pool_size=3,
        connect_timeout=base.connect_timeout,
    )


@pytest.fixture(scope="session")
def database_available(test_database_settings: DatabaseSettings) -> bool:
    """True when a MySQL-compatible server can be reached."""
    reachable, _detail = server_reachable(test_database_settings)
    return reachable


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def db(
    test_database_settings: DatabaseSettings, database_available: bool
) -> Iterator[DatabaseManager]:
    """A migrated, seeded, empty test database.

    Skips the whole database suite when no server is reachable.
    """
    if not database_available:
        pytest.skip("No MySQL-compatible server is reachable for database tests.")

    from aethra_sec.database.migrations import ensure_database_exists, run_migrations
    from aethra_sec.database.seed import seed_all

    ensure_database_exists(test_database_settings)
    manager = DatabaseManager(test_database_settings)
    _drop_all(manager)
    run_migrations(manager)
    seed_all(manager)
    try:
        yield manager
    finally:
        manager.close()


def _drop_all(manager: DatabaseManager) -> None:
    """Drop every table so each session starts from a known state."""
    from aethra_sec.database.schema import CREATE_TABLE_STATEMENTS

    manager.execute("SET FOREIGN_KEY_CHECKS = 0")
    for name, _ddl in reversed(CREATE_TABLE_STATEMENTS):
        manager.execute(f"DROP TABLE IF EXISTS `{name}`")
    manager.execute("SET FOREIGN_KEY_CHECKS = 1")


#: Tables truncated between tests, in an order that respects foreign keys even
#: if the constraint check were left on. ``users`` is included: seeding creates
#: roles, permissions, settings and the mitigation knowledge base but never a
#: user account, so every account in the test schema was created by a test.
PER_TEST_TABLES = (
    "incident_events", "incident_notes", "incidents", "snort_alerts",
    "traffic_anomalies", "scan_findings", "ports", "scan_hosts", "scans",
    "traffic_records", "traffic_aggregates", "host_observations",
    "trusted_hosts", "hosts", "notification_reads", "notifications",
    "app_errors", "reports",
    "audit_logs", "login_attempts", "sessions",
    "password_reset_requests", "users",
)


@pytest.fixture
def clean_db(db: DatabaseManager) -> Iterator[DatabaseManager]:
    """Truncate per-test tables between tests, keeping seeded configuration.

    The whole cleanup runs on **one** checked-out connection. This matters:
    ``FOREIGN_KEY_CHECKS`` is a MySQL *session* variable, so issuing it through
    the pooled ``execute`` helper set it on whichever connection happened to be
    free, while the ``TRUNCATE`` statements that depend on it ran on others
    with the constraint still enforced. ``TRUNCATE users`` then failed, the
    teardown raised, and the accounts survived into the next test - which is
    why ``test_password_recovery`` intermittently failed with a duplicate
    ``admin`` depending on the order the suite happened to run in.

    Cleared **before** the test as well as after. Cleaning up only on the way
    out guarantees nothing about what a test *starts* with: a test using the
    plain ``db`` fixture leaves its rows behind, so whether a ``clean_db``
    test saw an empty database depended on the order pytest happened to
    collect the files in. One report test asserting "the one stored alert"
    passed alone and failed after a module that inserts alerts, which is the
    worst kind of failure - real, but visible only in some orderings.
    """
    _truncate_per_test_tables(db)
    yield db
    _truncate_per_test_tables(db)


def _truncate_per_test_tables(db: DatabaseManager) -> None:
    """Empty the per-test tables, keeping seeded configuration."""
    with db.connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            for table in PER_TEST_TABLES:
                cursor.execute(f"TRUNCATE TABLE `{table}`")
            # Configuration tables survive truncation, so clear the author
            # columns that still point at the accounts just removed.
            cursor.execute("UPDATE system_settings SET updated_by = NULL")
            cursor.execute(
                "UPDATE mitigation_recommendations "
                "SET created_by = NULL, updated_by = NULL"
            )
            cursor.execute("UPDATE vuln_knowledge SET created_by = NULL")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            conn.commit()
        finally:
            cursor.close()


# ---------------------------------------------------------------------------
# Synthetic packet fixtures (test-only)
# ---------------------------------------------------------------------------
def make_packet(
    *,
    src_ip: str = "192.168.1.50",
    dst_ip: str = "192.168.1.25",
    src_port: int | None = 40000,
    dst_port: int | None = 22,
    protocol: str = "TCP",
    length: int = 74,
    tcp_flags: int | None = 0x02,
    app_protocol: str = "",
    offset_seconds: float = 0.0,
    interface: str = "test0",
    ttl: int | None = 64,
) -> CapturedPacket:
    """Build a synthetic :class:`CapturedPacket` for rule and analyzer tests."""
    return CapturedPacket(
        captured_at=utcnow() + timedelta(seconds=offset_seconds),
        interface=interface,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        transport=protocol if protocol in ("TCP", "UDP") else "",
        highest_layer=app_protocol or protocol,
        app_protocol=app_protocol,
        length=length,
        ttl=ttl,
        tcp_flags=tcp_flags,
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        ip_version=4,
        layers=("ETH", "IP", protocol),
    )


def make_frame(src: str, dst: str, src_port: int, dst_port: int) -> bytes:
    """Build a raw Ethernet/IPv4/TCP frame for Alertpkt decoder tests."""
    ethernet = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00"
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, 1, 0, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    tcp_header = struct.pack(
        "!HHIIBBHHH", src_port, dst_port, 0, 0, 0x50, 0x02, 8192, 0, 0
    )
    return ethernet + ip_header + tcp_header


@pytest.fixture
def packet_factory():
    """Expose :func:`make_packet` as a fixture."""
    return make_packet


@pytest.fixture
def frame_factory():
    """Expose :func:`make_frame` as a fixture."""
    return make_frame


@pytest.fixture
def lab_authorization() -> AuthorizationSettings:
    """Authorisation boundary used by target-validation tests."""
    return AuthorizationSettings(
        networks=("192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"),
        allow_public=False,
    )
