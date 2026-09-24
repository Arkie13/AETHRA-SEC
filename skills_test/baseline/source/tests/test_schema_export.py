"""The exported SQL file must stay in step with the schema the code creates.

``sql/aethra_sec_schema.sql`` is generated from ``database/schema.py`` and
``database/seed.py``. If someone changes a table and forgets to re-export, the
file would quietly describe a schema the application no longer builds - so this
compares the committed file against a freshly generated one and fails loudly.

Regenerate with::

    python scripts/export_schema.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from aethra_sec.config.defaults import ALL_SETTING_SPECS
from aethra_sec.core.permissions import PERMISSION_SPECS, ROLE_DEFINITIONS
from aethra_sec.database.schema import CREATE_TABLE_STATEMENTS
from aethra_sec.database.seed import _MITIGATIONS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SQL_FILE = PROJECT_ROOT / "sql" / "aethra_sec_schema.sql"


@pytest.fixture(scope="module")
def exported_sql() -> str:
    """The committed SQL file."""
    if not SQL_FILE.exists():
        pytest.fail(
            f"{SQL_FILE} is missing. Run 'python scripts/export_schema.py'."
        )
    return SQL_FILE.read_text(encoding="utf-8")


class TestExportIsCurrent:
    """The committed file matches what the exporter produces today."""

    def test_no_drift(self, exported_sql: str) -> None:
        """Regenerating the file produces exactly the committed text."""
        result = subprocess.run(
            [sys.executable, "scripts/export_schema.py", "--stdout"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, check=True,
        )
        # ``--stdout`` adds one newline from print(); compare the content.
        assert result.stdout.strip() == exported_sql.strip(), (
            "sql/aethra_sec_schema.sql is stale. "
            "Run 'python scripts/export_schema.py' and commit the result."
        )


class TestExportContents:
    """The file creates the database and everything a new install needs."""

    def test_creates_the_database_and_selects_it(self, exported_sql: str) -> None:
        """The file is self-contained: it makes the schema before using it."""
        assert "CREATE DATABASE IF NOT EXISTS `aethra_sec`" in exported_sql
        assert "USE `aethra_sec`;" in exported_sql
        assert exported_sql.index("CREATE DATABASE") < exported_sql.index("USE `aethra_sec`")

    def test_every_table_is_present_in_dependency_order(self, exported_sql: str) -> None:
        """Every table is created, in the order the code creates them."""
        positions = []
        for name, _ddl in CREATE_TABLE_STATEMENTS:
            marker = f"CREATE TABLE IF NOT EXISTS {name} "
            assert marker in exported_sql, f"table '{name}' missing from the export"
            positions.append(exported_sql.index(marker))
        assert positions == sorted(positions), "tables are not in dependency order"

    def test_tables_referenced_by_alerts_come_first(self, exported_sql: str) -> None:
        """incidents and mitigation precede the tables holding keys into them."""
        for earlier, later in (
            ("incidents", "snort_alerts"),
            ("incidents", "traffic_anomalies"),
            ("mitigation_recommendations", "threat_mitigation_mapping"),
            ("users", "sessions"),
            ("scans", "scan_findings"),
        ):
            assert exported_sql.index(
                f"CREATE TABLE IF NOT EXISTS {earlier} "
            ) < exported_sql.index(f"CREATE TABLE IF NOT EXISTS {later} ")

    def test_reference_rows_are_complete(self, exported_sql: str) -> None:
        """Roles, permissions, settings and mitigation guidance are all seeded."""
        for spec in PERMISSION_SPECS:
            assert f"'{spec.code}'" in exported_sql
        for role_name in ROLE_DEFINITIONS:
            assert f"'{role_name}'" in exported_sql
        for spec in ALL_SETTING_SPECS:
            assert f"'{spec.key}'" in exported_sql
        for entry in _MITIGATIONS:
            assert f"'{entry['code']}'" in exported_sql

    def test_schema_version_is_recorded(self, exported_sql: str) -> None:
        """The file records the migration it represents."""
        assert "INSERT INTO schema_migrations" in exported_sql
        assert "'initial_schema'" in exported_sql


class TestExportCarriesNoData:
    """The file ships configuration only - never a record or a credential."""

    @pytest.mark.parametrize(
        "table",
        [
            "users", "hosts", "scans", "scan_hosts", "ports", "scan_findings",
            "snort_alerts", "traffic_anomalies", "incidents", "incident_events",
            "incident_notes", "traffic_records", "traffic_aggregates",
            "host_observations", "trusted_hosts", "audit_logs", "sessions",
            "login_attempts", "reports", "notifications", "app_errors",
            "vuln_knowledge",
        ],
    )
    def test_no_inserts_into_evidence_tables(
        self, exported_sql: str, table: str
    ) -> None:
        """No security record, and no account, is written by the file."""
        assert f"INSERT INTO {table}" not in exported_sql

    def test_no_credentials(self, exported_sql: str) -> None:
        """No password, hash or key is present; the sample GRANT is commented."""
        lowered = exported_sql.lower()
        assert "$argon2" not in lowered
        assert "pbkdf2_sha256$" not in lowered
        for line in exported_sql.splitlines():
            stripped = line.strip()
            if "identified by" in stripped.lower():
                assert stripped.startswith("--"), (
                    "the sample account statement must stay commented out"
                )

    def test_states_what_it_does_not_contain(self, exported_sql: str) -> None:
        """The header is explicit that no security data ships with the schema."""
        assert "NO user accounts and NO security records" in exported_sql
