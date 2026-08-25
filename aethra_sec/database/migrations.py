"""Schema creation and migration.

The runner is deliberately simple and forward-only: each migration has an
integer version and is applied exactly once, recorded in ``schema_migrations``.
Adding a future migration means appending a :class:`Migration` to
:data:`MIGRATIONS` - existing installations then upgrade on next start.

Nothing here seeds security data. Only structure is created; static
configuration is handled by :mod:`aethra_sec.database.seed` (§102).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from aethra_sec.config.settings import DatabaseSettings
from aethra_sec.core.errors import SchemaError
from aethra_sec.database.connection import (
    MYSQL_AVAILABLE,
    MYSQL_IMPORT_ERROR,
    DatabaseManager,
)
from aethra_sec.database.schema import CREATE_TABLE_STATEMENTS, REQUIRED_TABLES
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import to_db, utcnow

LOGGER = get_logger("database.migrations")

_IDENTIFIER_SAFE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)


@dataclass(frozen=True)
class Migration:
    """One forward-only schema migration."""

    version: int
    name: str
    apply: Callable[[DatabaseManager], None]


def _apply_initial_schema(db: DatabaseManager) -> None:
    """Create every table in dependency order."""
    for table_name, ddl in CREATE_TABLE_STATEMENTS:
        LOGGER.debug("Creating table if missing: %s", table_name)
        db.execute(ddl)


def _apply_password_recovery(db: DatabaseManager) -> None:
    """Add the administrator-reviewed password recovery queue.

    Existing installations gain the table without touching any account data;
    a fresh installation already created it in migration 1 and the DDL is
    idempotent, so this runs safely in both directions.
    """
    from aethra_sec.database.schema import PASSWORD_RESET_REQUESTS

    db.execute(PASSWORD_RESET_REQUESTS)


def _column_exists(db: DatabaseManager, table: str, column: str) -> bool:
    """True when a column is already present in the connected schema."""
    return bool(
        db.query_value(
            "SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = %s "
            "AND column_name = %s",
            (table, column),
            default=0,
        )
    )


def _apply_incident_read_state(db: DatabaseManager) -> None:
    """Record when an incident was first opened, for the unread counter.

    The sidebar counter previously showed every open incident, so triaging one
    never changed it. Storing when an incident was first read lets the counter
    mean what a badge should mean: how many incidents nobody has looked at yet.

    Existing rows keep ``viewed_at IS NULL`` and so count as unread, which is
    the truthful starting state - the application has no record of anyone
    having opened them.
    """
    if not _column_exists(db, "incidents", "viewed_at"):
        db.execute(
            "ALTER TABLE incidents "
            "ADD COLUMN viewed_at DATETIME(6) NULL AFTER evaluated_at, "
            "ADD COLUMN viewed_by INT UNSIGNED NULL AFTER viewed_at, "
            "ADD KEY ix_incidents_viewed (viewed_at, status), "
            "ADD CONSTRAINT fk_incidents_viewer "
            "FOREIGN KEY (viewed_by) REFERENCES users (id) ON DELETE SET NULL"
        )


def _apply_hostname_lookup_state(db: DatabaseManager) -> None:
    """Record when reverse DNS was last attempted for a host.

    Capture sees an address and a MAC on the wire; it cannot see a hostname.
    Without a record of the attempt, an empty ``hostname`` means two different
    things - "nobody has looked yet" and "looked, and this address has no DNS
    record" - and the inventory cannot tell an operator which. It also means a
    background resolver would query the same nameless addresses forever.

    Existing rows keep ``hostname_checked_at IS NULL``, which is the truthful
    starting state: no lookup has been recorded for any of them.
    """
    if not _column_exists(db, "hosts", "hostname_checked_at"):
        db.execute(
            "ALTER TABLE hosts "
            "ADD COLUMN hostname_checked_at DATETIME(6) NULL AFTER hostname, "
            "ADD KEY ix_hosts_hostname_checked (hostname_checked_at)"
        )


def _apply_windows_firewall_events(db: DatabaseManager) -> None:
    """Add the Windows Firewall connection-log events table.

    A fresh installation already created it in migration 1 and the DDL is
    idempotent (``CREATE TABLE IF NOT EXISTS``), so this runs safely on both
    an existing installation and a brand new one, exactly like migration 2.

    The DDL is inlined rather than imported from ``database.schema``: the
    Windows Firewall evidence source was later abandoned (migration 6 drops
    the table), so ``schema.py`` no longer defines this table. A historical
    migration must stay runnable exactly as it always was, independent of
    what the current schema module contains.
    """
    from aethra_sec.database.schema import TABLE_OPTIONS

    db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS windows_firewall_events (
            id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            event_time          DATETIME(6)  NULL,
            received_at         DATETIME(6)  NOT NULL,
            action              VARCHAR(16)  NOT NULL DEFAULT '',
            protocol            VARCHAR(16)  NOT NULL DEFAULT '',
            src_ip              VARCHAR(45)  NOT NULL DEFAULT '',
            src_port            SMALLINT UNSIGNED NULL,
            dst_ip              VARCHAR(45)  NOT NULL DEFAULT '',
            dst_port            SMALLINT UNSIGNED NULL,
            size                INT UNSIGNED NULL,
            tcp_flags           VARCHAR(16)  NOT NULL DEFAULT '',
            tcp_syn             VARCHAR(16)  NOT NULL DEFAULT '',
            tcp_ack             VARCHAR(16)  NOT NULL DEFAULT '',
            tcp_win             VARCHAR(16)  NOT NULL DEFAULT '',
            icmp_type           SMALLINT     NULL,
            icmp_code           SMALLINT     NULL,
            info                VARCHAR(64)  NOT NULL DEFAULT '',
            direction           VARCHAR(16)  NOT NULL DEFAULT '',
            severity            VARCHAR(16)  NOT NULL DEFAULT 'LOW',
            raw_line            TEXT         NULL,
            src_host_id         BIGINT UNSIGNED NULL,
            dst_host_id         BIGINT UNSIGNED NULL,
            incident_id         BIGINT UNSIGNED NULL,
            status              VARCHAR(16)  NOT NULL DEFAULT 'NEW',
            evaluation          VARCHAR(20)  NOT NULL DEFAULT 'UNCLASSIFIED',
            evaluated_by        INT UNSIGNED NULL,
            evaluated_at        DATETIME(6)  NULL,
            duplicate_count     INT UNSIGNED NOT NULL DEFAULT 1,
            dedup_key           VARCHAR(190) NOT NULL DEFAULT '',
            source              VARCHAR(24)  NOT NULL DEFAULT 'WINDOWS_FIREWALL',
            created_at          DATETIME(6)  NOT NULL,
            PRIMARY KEY (id),
            KEY ix_firewall_events_time (event_time),
            KEY ix_firewall_events_received (received_at),
            KEY ix_firewall_events_action (action),
            KEY ix_firewall_events_severity (severity),
            KEY ix_firewall_events_status (status),
            KEY ix_firewall_events_src (src_ip),
            KEY ix_firewall_events_dst (dst_ip),
            KEY ix_firewall_events_incident (incident_id),
            KEY ix_firewall_events_dedup (dedup_key, received_at),
            KEY ix_firewall_events_evaluation (evaluation),
            CONSTRAINT fk_firewall_events_src_host
                FOREIGN KEY (src_host_id) REFERENCES hosts (id) ON DELETE SET NULL,
            CONSTRAINT fk_firewall_events_dst_host
                FOREIGN KEY (dst_host_id) REFERENCES hosts (id) ON DELETE SET NULL,
            CONSTRAINT fk_firewall_events_incident
                FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE SET NULL,
            CONSTRAINT fk_firewall_events_evaluator
                FOREIGN KEY (evaluated_by) REFERENCES users (id) ON DELETE SET NULL
        ) {TABLE_OPTIONS}
        """
    )


def _apply_drop_windows_firewall_events(db: DatabaseManager) -> None:
    """Drop the Windows Firewall connection-log events table.

    The Windows Firewall log ingest evidence source was abandoned; this
    removes the table migration 5 created. ``DROP TABLE IF EXISTS`` is
    idempotent, so this runs safely whether or not the table exists.
    """
    db.execute("DROP TABLE IF EXISTS windows_firewall_events")


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "initial_schema", _apply_initial_schema),
    Migration(2, "password_recovery_requests", _apply_password_recovery),
    Migration(3, "incident_read_state", _apply_incident_read_state),
    Migration(4, "hostname_lookup_state", _apply_hostname_lookup_state),
    Migration(5, "windows_firewall_events", _apply_windows_firewall_events),
    Migration(6, "drop_windows_firewall_events", _apply_drop_windows_firewall_events),
)

LATEST_VERSION: int = max(m.version for m in MIGRATIONS)


def _validate_identifier(name: str) -> str:
    """Guard the one place a name must be interpolated (``CREATE DATABASE``).

    MySQL does not accept a bound parameter for a schema name, so the value is
    validated character-by-character instead of being quoted.

    Raises:
        SchemaError: when the name contains anything but ``[A-Za-z0-9_]``.
    """
    candidate = (name or "").strip()
    if not candidate or len(candidate) > 64:
        raise SchemaError(f"Invalid database name: '{name}'")
    if not set(candidate) <= _IDENTIFIER_SAFE:
        raise SchemaError(
            f"Invalid database name '{name}': only letters, digits and "
            "underscores are permitted."
        )
    return candidate


def ensure_database_exists(settings: DatabaseSettings) -> bool:
    """Create the configured schema if the account is permitted to.

    Returns:
        True when the schema exists after the call.

    Raises:
        SchemaError: when the driver is missing or the schema cannot be created
            (for example because the least-privilege account lacks CREATE).
    """
    if not MYSQL_AVAILABLE:
        raise SchemaError(
            f"mysql-connector-python is not installed ({MYSQL_IMPORT_ERROR}).",
            user_message=(
                "The MySQL driver is not installed. Run "
                "'pip install -r requirements.txt'."
            ),
        )

    import mysql.connector
    from mysql.connector import Error as MySQLError

    database = _validate_identifier(settings.database)
    try:
        connection = mysql.connector.connect(
            host=settings.host,
            port=settings.port,
            user=settings.user,
            password=settings.password,
            connection_timeout=settings.connect_timeout,
        )
    except MySQLError as exc:
        raise SchemaError(
            f"Could not connect to MySQL at {settings.host}:{settings.port}: {exc}",
            user_message=(
                "DATABASE OFFLINE - could not connect to the MySQL server. "
                "Check the service and the credentials in .env."
            ),
        ) from exc

    try:
        cursor = connection.cursor()
        try:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{database}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            connection.commit()
            return True
        except MySQLError as exc:
            raise SchemaError(
                f"Could not create database '{database}': {exc}",
                user_message=(
                    f"The database '{database}' does not exist and could not "
                    "be created with the configured account. Create it "
                    "manually or grant CREATE to the account."
                ),
            ) from exc
        finally:
            cursor.close()
    finally:
        connection.close()


def applied_versions(db: DatabaseManager) -> set[int]:
    """Versions already recorded in ``schema_migrations`` (empty when absent)."""
    try:
        rows = db.query("SELECT version FROM schema_migrations")
    except Exception:  # noqa: BLE001 - table may not exist yet
        return set()
    return {int(row["version"]) for row in rows}


def current_version(db: DatabaseManager) -> int:
    """Highest applied migration version, or ``0`` on a fresh database."""
    versions = applied_versions(db)
    return max(versions) if versions else 0


def run_migrations(db: DatabaseManager) -> list[int]:
    """Apply every migration that has not been applied yet.

    Returns:
        The versions applied during this call (empty when already current).

    Raises:
        SchemaError: when a migration fails; the failure text names the
            migration so an administrator can act on it.
    """
    from aethra_sec.database.schema import SCHEMA_MIGRATIONS

    db.execute(SCHEMA_MIGRATIONS)
    already = applied_versions(db)
    applied: list[int] = []

    for migration in sorted(MIGRATIONS, key=lambda m: m.version):
        if migration.version in already:
            continue
        LOGGER.info("Applying migration %s: %s", migration.version, migration.name)
        try:
            migration.apply(db)
        except Exception as exc:  # noqa: BLE001
            raise SchemaError(
                f"Migration {migration.version} ({migration.name}) failed: {exc}",
                user_message=(
                    f"Database migration {migration.version} failed. The "
                    "schema may be incomplete - see the System Health screen."
                ),
            ) from exc
        db.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) "
            "VALUES (%s, %s, %s)",
            (migration.version, migration.name, to_db(utcnow())),
        )
        applied.append(migration.version)

    if applied:
        LOGGER.info("Applied migrations: %s", applied)
    return applied


def missing_tables(db: DatabaseManager) -> tuple[str, ...]:
    """Required tables that are absent from the schema."""
    present = db.table_names()
    present_lower = {name.lower() for name in present}
    return tuple(t for t in REQUIRED_TABLES if t.lower() not in present_lower)


def verify_schema(db: DatabaseManager) -> tuple[bool, str]:
    """Check that the schema is complete and current.

    Returns:
        ``(ok, detail)``. ``detail`` names the problem when ``ok`` is false, so
        the diagnostics screen can show something actionable.
    """
    missing = missing_tables(db)
    if missing:
        return False, f"Missing tables: {', '.join(missing)}"
    version = current_version(db)
    if version < LATEST_VERSION:
        return (
            False,
            f"Schema version {version} is older than the required "
            f"version {LATEST_VERSION}. Run the migrations.",
        )
    return True, f"Schema version {version} (current)"


def initialise_database(settings: DatabaseSettings) -> DatabaseManager:
    """Create the schema, run migrations, and return a ready manager.

    Used by ``scripts/init_db.py`` and the application's first-run path.
    """
    ensure_database_exists(settings)
    db = DatabaseManager(settings)
    run_migrations(db)
    return db
