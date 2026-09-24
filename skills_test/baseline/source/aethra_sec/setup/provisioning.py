"""Database preparation and administrator creation.

This is the one implementation of "make this installation ready to use". The
graphical wizard, the console setup and ``setup.bat`` all call these functions;
none of them has a copy of the logic. That matters because the two paths must
not be able to drift into producing different installations - an administrator
created by the console must be exactly the account the wizard would have
created, hashed the same way, with the same role.

What provisioning does, in order:

1. create the database when it does not exist and the account may create it;
2. apply every migration that has not been applied yet;
3. seed the static configuration - roles, permissions, tunable settings and the
   mitigation knowledge base;
4. create the first administrator, if there is not one already.

What it does **not** do is insert a single security record. No hosts, no
packets, no alerts, no incidents, no vulnerabilities. A freshly installed
AETHRA-SEC shows zeros because it has genuinely observed nothing, and an
upgrade over an existing installation keeps every row that is already there:
migrations run, seeding is idempotent, and an existing administrator is
reported rather than replaced.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aethra_sec.config.settings import DatabaseSettings
from aethra_sec.core.errors import AethraError
from aethra_sec.database.connection import DatabaseManager
from aethra_sec.database.migrations import (
    current_version,
    ensure_database_exists,
    run_migrations,
    verify_schema,
)
from aethra_sec.database.repositories.users import UserRepository
from aethra_sec.database.seed import seed_all
from aethra_sec.security.password import PasswordHashService
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.validation import (
    ValidationError,
    validate_email,
    validate_password,
    validate_username,
)

LOGGER = get_logger("setup.provisioning")


@dataclass
class ProvisionResult:
    """What preparing the database actually did.

    Attributes:
        ok: whether the database is usable now.
        created_database: whether the schema had to be created.
        migrations_applied: migration versions applied during this call. Empty
            on a fresh install that got everything from the initial schema, and
            empty again on a re-run, which is how "already current" looks.
        schema_version: the version the database is at afterwards.
        seeded: counts of static configuration rows written.
        detail: one line describing the outcome.
        remedy: what to do when ``ok`` is false.
        preserved_rows: existing security records found before any change was
            made. Reported so an upgrade can state what it is protecting rather
            than merely promising not to delete it.
    """

    ok: bool = False
    created_database: bool = False
    migrations_applied: tuple[int, ...] = ()
    schema_version: int = 0
    seeded: dict[str, int] = field(default_factory=dict)
    detail: str = ""
    remedy: str = ""
    preserved_rows: dict[str, int] = field(default_factory=dict)


@dataclass
class AdminResult:
    """The outcome of creating (or finding) the first administrator."""

    ok: bool = False
    created: bool = False
    username: str = ""
    user_id: int | None = None
    detail: str = ""
    existing_admins: tuple[str, ...] = ()


#: Tables whose contents are security history. Counted before an upgrade so the
#: setup report can state what already exists and is being kept.
HISTORY_TABLES = (
    "hosts",
    "snort_alerts",
    "traffic_anomalies",
    "incidents",
    "scan_results",
    "audit_log",
)


def count_existing_history(db: DatabaseManager) -> dict[str, int]:
    """Count the security records already stored.

    Used to show an operator, before anything is changed, exactly what an
    upgrade is preserving. A table that does not exist yet contributes nothing
    rather than raising - a fresh install has none of them.
    """
    counts: dict[str, int] = {}
    for table in HISTORY_TABLES:
        try:
            row = db.query_one(f"SELECT COUNT(*) AS total FROM `{table}`")
        except Exception:  # noqa: BLE001 - a missing table is not an error here
            continue
        if row:
            counts[table] = int(row.get("total", 0) or 0)
    return counts


def prepare_database(settings: DatabaseSettings) -> ProvisionResult:
    """Create, migrate and seed the database. Safe to run again.

    Never inserts security data. Seeding writes roles, permissions, tunable
    settings and mitigation guidance only, and it updates built-in descriptions
    without overwriting an administrator's own edits.
    """
    result = ProvisionResult()

    try:
        result.created_database = ensure_database_exists(settings)
    except AethraError as exc:
        result.detail = f"The database could not be created: {exc.user_message}"
        result.remedy = (
            "Grant the account CREATE permission, or create the schema as an "
            "administrator and run setup again. The SQL is in "
            "sql/aethra_sec_schema.sql."
        )
        return result
    except Exception as exc:  # noqa: BLE001
        result.detail = f"The database could not be created: {exc}"
        result.remedy = "Check that MySQL or MariaDB is running and reachable."
        return result

    manager: DatabaseManager | None = None
    try:
        manager = DatabaseManager(settings)

        # Counted before migrations touch anything, so the number describes
        # what was already there rather than what is there afterwards.
        result.preserved_rows = count_existing_history(manager)

        result.migrations_applied = tuple(run_migrations(manager))
        result.schema_version = current_version(manager)

        ok, detail = verify_schema(manager)
        if not ok:
            result.detail = f"The schema is not usable: {detail}"
            result.remedy = (
                "Apply sql/aethra_sec_schema.sql with an account that may "
                "create tables, then run setup again."
            )
            return result

        result.seeded = seed_all(manager)
    except AethraError as exc:
        result.detail = f"Database preparation failed: {exc.user_message}"
        result.remedy = "Check the database credentials and permissions."
        return result
    except Exception as exc:  # noqa: BLE001
        result.detail = f"Database preparation failed: {exc}"
        result.remedy = "See the setup log for the full error."
        return result
    finally:
        if manager is not None:
            try:
                manager.close()
            except Exception:  # noqa: BLE001
                pass

    result.ok = True
    applied = (
        f"{len(result.migrations_applied)} migration(s) applied"
        if result.migrations_applied
        else "already current"
    )
    result.detail = (
        f"Schema version {result.schema_version} ({applied}); "
        f"{sum(result.seeded.values())} configuration row(s) seeded."
    )
    LOGGER.info("Database prepared: %s", result.detail)
    return result


def list_administrators(db: DatabaseManager) -> tuple[str, ...]:
    """Active administrator usernames, for the "already set up" case."""
    try:
        rows = db.query(
            "SELECT u.username FROM users u JOIN roles r ON r.id = u.role_id "
            "WHERE r.name = 'ADMIN' AND u.is_active = 1 ORDER BY u.id"
        )
    except Exception:  # noqa: BLE001
        return ()
    return tuple(str(row["username"]) for row in rows)


def validate_admin_input(
    username: str, password: str, confirmation: str, email: str
) -> str:
    """Check the administrator details and return the first problem found.

    Returns an empty string when everything is acceptable. The password itself
    never appears in the returned message.
    """
    try:
        validate_username(username)
    except ValidationError as exc:
        return str(exc)
    try:
        validate_password(password)
    except ValidationError as exc:
        return str(exc)
    if password != confirmation:
        return "The two passwords do not match."
    try:
        validate_email(email, allow_empty=False)
    except ValidationError as exc:
        return str(exc)
    return ""


def create_administrator(
    settings: DatabaseSettings,
    username: str,
    password: str,
    email: str,
    *,
    allow_additional: bool = False,
) -> AdminResult:
    """Create the first administrator account.

    The password is hashed with Argon2id and the plaintext is discarded in this
    function; it is never written to the database, the configuration file, the
    audit trail or the log.

    Running this again is safe. When an active administrator already exists the
    existing accounts are reported and nothing is changed, unless
    ``allow_additional`` is set - which is how an operator deliberately adds a
    second administrator rather than how an accidental re-run overwrites one.
    """
    result = AdminResult()
    manager: DatabaseManager | None = None
    try:
        manager = DatabaseManager(settings)

        existing = list_administrators(manager)
        result.existing_admins = existing
        if existing and not allow_additional:
            result.ok = True
            result.detail = (
                f"An administrator already exists ({', '.join(existing)}). "
                "Nothing was changed - the existing password and address are kept."
            )
            return result

        role = UserRepository(manager).get_role_by_name("ADMIN")
        if role is None or role.id is None:
            result.detail = (
                "The ADMIN role is missing, so the database has not been seeded."
            )
            return result

        users = UserRepository(manager)
        if users.get_by_username(username) is not None:
            result.detail = f"An account named '{username}' already exists."
            return result

        hashed = PasswordHashService().hash(password)
        del password  # the plaintext does not leave this scope

        result.user_id = users.create_user(
            username=username,
            password_hash=hashed.hash,
            password_algorithm=hashed.algorithm,
            role_id=role.id,
            full_name="",
            email=email,
            must_change_password=False,
        )
    except AethraError as exc:
        result.detail = f"The administrator could not be created: {exc.user_message}"
        return result
    except Exception as exc:  # noqa: BLE001
        result.detail = f"The administrator could not be created: {exc}"
        return result
    finally:
        if manager is not None:
            try:
                manager.close()
            except Exception:  # noqa: BLE001
                pass

    result.ok = True
    result.created = True
    result.username = username
    result.detail = (
        f"Administrator '{username}' created with role ADMIN. "
        f"The password is stored as an Argon2id hash."
    )
    LOGGER.info("Administrator '%s' created (id %s).", username, result.user_id)
    return result


def existing_administrators(settings: DatabaseSettings) -> tuple[str, ...]:
    """Active administrator usernames, opening a connection to find them.

    An unreachable database is answered with an empty tuple rather than an
    exception: setup runs precisely when the database may not be there yet, and
    "no administrators found" is the correct thing to proceed on.
    """
    manager: DatabaseManager | None = None
    try:
        manager = DatabaseManager(settings)
        return list_administrators(manager)
    except Exception:  # noqa: BLE001 - not yet reachable is the normal case
        return ()
    finally:
        if manager is not None:
            try:
                manager.close()
            except Exception:  # noqa: BLE001
                pass


def administrator_exists(settings: DatabaseSettings) -> bool:
    """True when the database already holds an active administrator."""
    manager: DatabaseManager | None = None
    try:
        manager = DatabaseManager(settings)
        return bool(list_administrators(manager))
    except Exception:  # noqa: BLE001
        return False
    finally:
        if manager is not None:
            try:
                manager.close()
            except Exception:  # noqa: BLE001
                pass
