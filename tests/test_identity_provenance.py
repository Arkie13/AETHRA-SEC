"""How a hostname and an OS were established is evidence, so it is stored.

The identity probe already worked this out - which lookup produced the name,
what named the operating system, and what was tried and came back empty - and
then dropped all of it: ``scan_hosts`` had no column for any of the three.
The scan-host detail has rows for "Hostname source" and "OS source" and a
block for the notes, so against a stored scan they could only ever render a
dash and the notes never appeared.

That is the question that actually matters when a column reads Unknown. An
operator could not find out whether anything had been asked, what had been
asked, or why it came back empty - which makes an honest "Unknown" look like
a broken one.

These tests hold the provenance through the write and back out again, and
hold the line that matters more: an absent answer is never filled in.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from aethra_sec.models.enums import HostStatus
from aethra_sec.models.scan import ScanHostResult

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
SCANS = PACKAGE / "database" / "repositories" / "scans.py"
SCHEMA = PACKAGE / "database" / "schema.py"
MIGRATIONS = PACKAGE / "database" / "migrations.py"
VULN_SCREEN = PACKAGE / "ui" / "screens" / "vulnerabilities.py"


def _method(path: Path, name: str) -> str:
    node = next(
        n for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    return ast.unparse(node)


def _code(path: Path, name: str) -> str:
    """One function's statements, with its docstring removed.

    Keyword checks below look for SQL. A docstring that *describes* the bug -
    "used once and dropped", "reverse DNS" - would otherwise match them, which
    has caught me twice.
    """
    node = next(
        n for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    body = list(node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return "\n".join(ast.unparse(stmt) for stmt in body)


# ---------------------------------------------------------------------------
# The columns exist and are written
# ---------------------------------------------------------------------------
class TestTheProvenanceIsPersisted:
    def test_the_schema_declares_the_columns(self) -> None:
        source = SCHEMA.read_text(encoding="utf-8")
        table = source[source.index("CREATE TABLE IF NOT EXISTS scan_hosts"):]
        table = table[: table.index("PRIMARY KEY")]
        for column in ("hostname_source", "os_source", "identity_notes"):
            assert column in table, f"scan_hosts has no {column} column"

    def test_the_insert_writes_them(self) -> None:
        body = _method(SCANS, "add_scan_host")
        for column in ("hostname_source", "os_source", "identity_notes"):
            assert column in body, f"{column} is computed and then discarded"

    def test_a_rescan_updates_them(self) -> None:
        """The unique key makes this an upsert; stale provenance would linger."""
        body = _method(SCANS, "add_scan_host")
        for column in ("hostname_source", "os_source", "identity_notes"):
            assert f"{column} = VALUES({column})" in body

    def test_the_mapper_reads_them_back(self) -> None:
        body = _method(SCANS, "_map_scan_host")
        for column in ("hostname_source", "os_source", "identity_notes"):
            assert column in body

    def test_the_migration_is_registered(self) -> None:
        from aethra_sec.database.migrations import LATEST_VERSION, MIGRATIONS

        assert "identity_provenance" in {m.name for m in MIGRATIONS}
        assert LATEST_VERSION >= 20

    def test_the_migration_adds_rather_than_rebuilds(self) -> None:
        body = _code(MIGRATIONS, "_apply_identity_provenance")
        assert "ADD COLUMN" in body
        assert "_column_exists" in body, "re-running it would fail"
        for destructive in ("DROP", "DELETE FROM", "TRUNCATE"):
            assert destructive not in body.upper()

    def test_the_migration_invents_no_provenance_for_old_rows(self) -> None:
        """Which lookup found a name months ago cannot be reconstructed."""
        body = _code(MIGRATIONS, "_apply_identity_provenance")
        assert "UPDATE scan_hosts SET hostname_source" not in body
        assert "reverse DNS" not in body


class TestTheDetailCanNowExplainItself:
    def test_the_panel_still_shows_the_sources(self) -> None:
        source = (PACKAGE / "ui" / "detail_panels.py").read_text(encoding="utf-8")
        assert "host.hostname_source" in source
        assert "host.os_source" in source
        assert "host.identity_notes" in source

    def test_the_model_carries_them(self) -> None:
        for field in ("hostname_source", "os_source", "identity_notes"):
            assert field in ScanHostResult.__dataclass_fields__


# ---------------------------------------------------------------------------
# The OS limitation is stated, not left to be guessed at
# ---------------------------------------------------------------------------
class TestTheMissingOsIsExplained:
    """Nmap cannot fingerprint without raw sockets, so most hosts read Unknown."""

    def test_the_identity_probe_only_adds_o_when_privileged(self) -> None:
        from aethra_sec.integrations.nmap.identity import identity_arguments

        assert "-O" not in identity_arguments(privileged=False)
        assert "-O" in identity_arguments(privileged=True)

    def test_the_unprivileged_probe_still_asks_the_other_questions(self) -> None:
        """Losing -O must not mean losing NetBIOS and SMB too."""
        from aethra_sec.integrations.nmap.identity import identity_arguments

        args = identity_arguments(privileged=False)
        assert "nbstat" in args
        assert "smb-os-discovery" in args
        assert "-sV" in args

    def test_the_screen_reports_the_limitation(self) -> None:
        source = VULN_SCREEN.read_text(encoding="utf-8")
        assert "OS fingerprinting is unavailable" in source, (
            "a whole column reads Unknown with nothing saying why"
        )
        assert "Administrator" in source, "the remedy is not named"

    def test_it_is_shown_only_when_it_applies(self) -> None:
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        body = inspect.getsource(VulnerabilitiesScreen._apply_automation)
        assert "if not view.privileged" in body

    def test_the_flag_is_measured_not_assumed(self) -> None:
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        body = inspect.getsource(VulnerabilitiesScreen._refresh_automation)
        assert "has_raw_socket_privilege()" in body

    def test_the_notice_does_not_overstate_the_effect(self) -> None:
        """Hostnames come from DNS and mDNS, which privilege does not touch."""
        source = VULN_SCREEN.read_text(encoding="utf-8")
        notice = source[source.index("OS fingerprinting is unavailable"):]
        notice = notice[: notice.index('")') if '")' in notice else 400]
        assert "Hostnames are unaffected" in notice


# ---------------------------------------------------------------------------
# Nothing is invented when a lookup comes back empty
# ---------------------------------------------------------------------------
class TestAnAbsentAnswerStaysAbsent:
    def test_an_unknown_hostname_is_not_replaced_by_the_address(self) -> None:
        host = ScanHostResult(
            id=None, scan_id=1, host_id=1, ip_address="10.0.0.9",
            status=HostStatus.UP,
        )
        assert host.ip_address not in host.hostname_text
        assert host.hostname == ""

    def test_an_unknown_hostname_says_a_probe_ran(self) -> None:
        """"Not detected", not "Unknown": a probe ran and returned nothing."""
        host = ScanHostResult(
            id=None, scan_id=1, host_id=1, ip_address="10.0.0.9",
            status=HostStatus.UP,
        )
        assert host.hostname_text
        assert "10.0.0.9" not in host.hostname_text

    def test_no_os_is_guessed_from_the_vendor(self) -> None:
        """An Apple OUI is not evidence of iOS; §10 of the brief, still true."""
        source = (
            PACKAGE / "integrations" / "nmap" / "identity.py"
        ).read_text(encoding="utf-8")
        for guess in ('"iPhone"', '"Android"', '"iOS"', '"iPadOS"'):
            assert f"os_name = {guess}" not in source
            assert f"os_name={guess}" not in source


# ---------------------------------------------------------------------------
# Against a real database
# ---------------------------------------------------------------------------
class TestAgainstARealDatabase:
    @pytest.fixture()
    def repo(self, db):  # noqa: ANN001, ANN201
        from aethra_sec.database.repositories.scans import ScanRepository

        return ScanRepository(db)

    def _scan(self, repo) -> int:  # noqa: ANN001
        from aethra_sec.models.enums import ScanTrigger
        from aethra_sec.models.scan import Scan

        return int(repo.create_scan(Scan(
            id=None, target="10.88.0.1", target_kind="host", profile="standard",
            profile_label="Standard", port_spec="", timing="T3",
            arguments="-sT -sV", trigger_source=ScanTrigger.MANUAL,
        )))

    def test_the_provenance_survives_a_round_trip(self, repo) -> None:  # noqa: ANN001
        scan_id = self._scan(repo)
        repo.add_scan_host(scan_id, ScanHostResult(
            id=None, scan_id=scan_id, host_id=None, ip_address="10.88.0.1",
            hostname="lab-pc", status=HostStatus.UP, os_name="Microsoft Windows",
            hostname_source="NetBIOS (nbstat)",
            os_source="SMB (smb-os-discovery)",
            identity_notes=("mDNS returned no answer",),
        ))
        stored = repo.get_scan_with_results(scan_id).hosts[0]
        assert stored.hostname_source == "NetBIOS (nbstat)"
        assert stored.os_source == "SMB (smb-os-discovery)"
        assert stored.identity_notes == ("mDNS returned no answer",)

    def test_several_notes_round_trip(self, repo) -> None:  # noqa: ANN001
        scan_id = self._scan(repo)
        notes = (
            "reverse DNS returned no PTR record",
            "mDNS returned no answer",
            "NetBIOS name query returned nothing",
        )
        repo.add_scan_host(scan_id, ScanHostResult(
            id=None, scan_id=scan_id, host_id=None, ip_address="10.88.0.2",
            status=HostStatus.UP, identity_notes=notes,
        ))
        assert repo.get_scan_with_results(scan_id).hosts[0].identity_notes == notes

    def test_no_provenance_stays_empty(self, repo) -> None:  # noqa: ANN001
        """An unprobed host records nothing rather than a placeholder."""
        scan_id = self._scan(repo)
        repo.add_scan_host(scan_id, ScanHostResult(
            id=None, scan_id=scan_id, host_id=None, ip_address="10.88.0.3",
            status=HostStatus.UP,
        ))
        stored = repo.get_scan_with_results(scan_id).hosts[0]
        assert stored.hostname_source == ""
        assert stored.os_source == ""
        assert stored.identity_notes == ()

    def test_a_rescan_replaces_stale_provenance(self, repo) -> None:  # noqa: ANN001
        scan_id = self._scan(repo)
        host = ScanHostResult(
            id=None, scan_id=scan_id, host_id=None, ip_address="10.88.0.4",
            hostname="old", status=HostStatus.UP, hostname_source="mDNS",
        )
        repo.add_scan_host(scan_id, host)
        host.hostname = "new"
        host.hostname_source = "reverse DNS (local resolver)"
        repo.add_scan_host(scan_id, host)

        stored = repo.get_scan_with_results(scan_id).hosts[0]
        assert stored.hostname == "new"
        assert stored.hostname_source == "reverse DNS (local resolver)"
