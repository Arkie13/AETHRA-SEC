"""Create the AETHRA-SEC schema and seed its configuration tables.

    python scripts/init_db.py            create/migrate, then seed
    python scripts/init_db.py --verify   report the schema state and exit

The script reads its connection details from the environment (``.env``), so it
never contains a password. It is safe to run repeatedly: migrations are applied
once and recorded, and seeding uses insert-or-update on the built-in rows.

Seeding creates roles, permissions, default thresholds and the mitigation
knowledge base. It creates no users, no hosts, no scans, no alerts and no
incidents - the security tables stay empty until real tools produce real
records (§1).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aethra_sec.config.settings import load_settings  # noqa: E402
from aethra_sec.core.errors import AethraError  # noqa: E402
from aethra_sec.database.connection import DatabaseManager  # noqa: E402
from aethra_sec.database.migrations import (  # noqa: E402
    LATEST_VERSION,
    current_version,
    ensure_database_exists,
    missing_tables,
    run_migrations,
    verify_schema,
)
from aethra_sec.database.seed import seed_all  # noqa: E402
from aethra_sec.version import APP_NAME, APP_VERSION  # noqa: E402

EVIDENCE_TABLES = (
    "hosts", "scans", "scan_findings", "snort_alerts",
    "traffic_anomalies", "incidents", "traffic_aggregates",
)


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="init_db",
        description="Create and seed the AETHRA-SEC database schema.",
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="report the schema state without changing anything",
    )
    parser.add_argument(
        "--no-seed", action="store_true",
        help="apply migrations but do not seed the configuration tables",
    )
    return parser.parse_args(argv)


def _report_state(db: DatabaseManager) -> int:
    """Print the current schema state. Returns a process exit code."""
    ok, detail = verify_schema(db)
    print(f"Schema version : {current_version(db)} (latest {LATEST_VERSION})")
    print(f"Schema check   : {'OK' if ok else 'INCOMPLETE'} - {detail}")
    absent = missing_tables(db)
    if absent:
        print(f"Missing tables : {', '.join(absent)}")

    print("Stored records :")
    for table in EVIDENCE_TABLES:
        try:
            rows = db.query(f"SELECT COUNT(*) AS total FROM `{table}`")
            print(f"  {table:<20} {rows[0]['total']}")
        except AethraError:
            print(f"  {table:<20} (table not present)")
    return 0 if ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    """Create, migrate and seed the database."""
    settings = load_settings()
    database = settings.database
    print(f"{APP_NAME} {APP_VERSION} - database initialisation")
    print(
        f"Target: {database.user}@{database.host}:{database.port}"
        f"/{database.database}"
    )

    try:
        arguments = _parse_arguments(argv)
        if not arguments.verify:
            created = ensure_database_exists(database)
            print(f"Schema '{database.database}' present: {created}")

        db = DatabaseManager(database)
        try:
            if arguments.verify:
                return _report_state(db)

            applied = run_migrations(db)
            if applied:
                print(f"Applied migration(s): {', '.join(str(v) for v in applied)}")
            else:
                print("Schema already at the latest version; nothing to apply.")

            if not arguments.no_seed:
                counts = seed_all(db)
                print(
                    "Seeded configuration: "
                    f"{counts['roles']} roles, {counts['permissions']} permissions, "
                    f"{counts['settings']} settings, "
                    f"{counts['mitigation_recommendations']} mitigation entries."
                )
                print(
                    "No users, hosts, scans, alerts or incidents were created - "
                    "those tables fill only from real tool output."
                )

            return _report_state(db)
        finally:
            db.close()
    except AethraError as exc:
        print(f"\nFailed: {exc.user_message}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
