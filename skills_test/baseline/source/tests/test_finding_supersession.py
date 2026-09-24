"""A finding belongs to the assessment that observed it.

Nothing closed the previous assessment's findings, so every completed scan
added a fresh set and a host accumulated the union of everything it had ever
exposed. The exposure panel listed the same four ports five times - once per
scan - under "20 open services", next to a status line reporting that the
latest scan had found four. One host held eleven open findings while its most
recent answered assessment found none at all, which is worse than a
duplicate: it presents withdrawn exposure as current.

These tests hold the rule that fixes it, and the guard that keeps the rule
safe:

* a later assessment that completed **and that the host answered** supersedes
  the earlier one's findings, because it is the current picture of the host;
* a scan the host did not answer supersedes nothing, because it observed
  nothing - one unanswered probe must never close a real finding;
* nothing is deleted. A superseded finding keeps its scan, its evidence, its
  rating and its score, and stays readable through the scan it belongs to.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from aethra_sec.models.enums import HostStatus, RiskLevel, Severity
from aethra_sec.models.scan import ScanFinding

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
NMAP = PACKAGE / "services" / "nmap_service.py"
SCANS = PACKAGE / "database" / "repositories" / "scans.py"
MIGRATIONS = PACKAGE / "database" / "migrations.py"


def _method(path: Path, name: str) -> str:
    """One function's source, for looking inside it."""
    node = next(
        n for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    return ast.unparse(node)


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------
class TestTheRepositorySupersedes:
    def test_the_method_exists(self) -> None:
        from aethra_sec.database.repositories.scans import ScanRepository

        assert callable(getattr(ScanRepository, "supersede_host_findings", None))

    def test_it_closes_only_older_assessments(self) -> None:
        body = _method(SCANS, "supersede_host_findings")
        assert "scan_id < %s" in body, (
            "the update is not bounded to earlier scans, so it could close "
            "the findings of the assessment being written"
        )

    def test_it_leaves_an_already_resolved_finding_alone(self) -> None:
        """An analyst's own resolution must not be restamped."""
        body = _method(SCANS, "supersede_host_findings")
        assert "resolved_at IS NULL" in body

    def test_it_resolves_rather_than_deletes(self) -> None:
        body = _method(SCANS, "supersede_host_findings").upper()
        assert "UPDATE SCAN_FINDINGS SET RESOLVED_AT" in body
        # Statement forms, not the word: the docstring legitimately says
        # "nothing is deleted", which an upper-cased search for "DELETE" hits.
        assert "DELETE FROM" not in body

    def test_it_is_scoped_to_one_host(self) -> None:
        body = _method(SCANS, "supersede_host_findings")
        assert "host_id = %s" in body

    def test_it_is_parameterised(self) -> None:
        body = _method(SCANS, "supersede_host_findings")
        assert "f'" not in body and 'f"' not in body, (
            "the statement interpolates values instead of binding them"
        )

    def test_a_missing_id_is_a_no_op(self) -> None:
        body = _method(SCANS, "supersede_host_findings")
        assert "return 0" in body


class TestTheWritePathSupersedesOnlyOnAnAnswer:
    """The guard that makes the rule safe."""

    def _persist(self) -> str:
        source = NMAP.read_text(encoding="utf-8")
        node = next(
            n for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.FunctionDef)
            and "supersede_host_findings" in ast.unparse(n)
        )
        return ast.unparse(node)

    def test_the_persist_path_supersedes(self) -> None:
        assert "supersede_host_findings" in self._persist()

    def test_it_is_guarded_on_the_host_answering(self) -> None:
        body = self._persist()
        call = body.index("supersede_host_findings")
        guard = body.rfind("if host_id and answered", 0, call)
        assert guard != -1, (
            "the supersession is not guarded on the host having answered, so "
            "a scan that got no reply would close known exposure"
        )

    def test_it_runs_even_when_the_new_scan_found_nothing(self) -> None:
        """The case that most needs it: exposure that has been withdrawn."""
        body = self._persist()
        call = body.index("supersede_host_findings")
        # The "if findings:" block that inserts must come *after* the
        # supersession, so an empty result still closes the old set.
        insert = body.index("add_findings")
        assert call < insert, (
            "supersession happens inside or after the insert branch, so a "
            "host that answered and now exposes nothing keeps its old "
            "findings open"
        )

    def test_answered_means_the_host_was_up(self) -> None:
        body = self._persist()
        assert "answered = host.status is HostStatus.UP" in body


# ---------------------------------------------------------------------------
# The display
# ---------------------------------------------------------------------------
class TestTheDetailViewShowsTheCurrentAssessment:
    def test_it_narrows_to_the_scan_it_was_given(self) -> None:
        from aethra_sec.services.nmap_service import NmapService

        body = inspect.getsource(NmapService.host_evidence)
        assert "f.scan_id == int(scan_id)" in body, (
            "the detail view shows every open finding for the host, so a port "
            "appears once per scan ever run against it"
        )

    def test_it_still_excludes_resolved_findings(self) -> None:
        from aethra_sec.services.nmap_service import NmapService

        body = inspect.getsource(NmapService.host_evidence)
        assert "resolved_at is None" in body

    def test_it_changes_no_stored_row(self) -> None:
        from aethra_sec.services.nmap_service import NmapService

        body = inspect.getsource(NmapService.host_evidence)
        for write in ("UPDATE ", "INSERT ", "resolve_finding(", "supersede_"):
            assert write not in body, (
                f"host_evidence performs a write ({write}); opening a detail "
                "view must not change the record"
            )


# ---------------------------------------------------------------------------
# The migration
# ---------------------------------------------------------------------------
class TestTheMigration:
    def test_it_is_registered(self) -> None:
        from aethra_sec.database.migrations import LATEST_VERSION, MIGRATIONS

        names = {m.name for m in MIGRATIONS}
        assert "supersede_stale_findings" in names
        assert LATEST_VERSION >= 19

    def test_it_uses_the_same_answered_guard(self) -> None:
        body = _method(MIGRATIONS, "_apply_supersede_stale_findings")
        assert "s.status = 'COMPLETED'" in body
        assert "hosts_up, 0) >= 1" in body, (
            "the migration would close findings against a scan the host never "
            "answered"
        )

    def test_it_only_closes_older_findings(self) -> None:
        body = _method(MIGRATIONS, "_apply_supersede_stale_findings")
        assert "f.scan_id < (" in body

    def test_it_deletes_nothing(self) -> None:
        body = _method(MIGRATIONS, "_apply_supersede_stale_findings").upper()
        # Statement forms only; the docstring says "nothing is deleted".
        for statement in ("DELETE FROM", "DROP TABLE", "TRUNCATE TABLE"):
            assert statement not in body

    def test_it_spares_an_already_resolved_finding(self) -> None:
        body = _method(MIGRATIONS, "_apply_supersede_stale_findings")
        assert "f.resolved_at IS NULL" in body


# ---------------------------------------------------------------------------
# Against a real database
# ---------------------------------------------------------------------------
class TestAgainstARealDatabase:
    """Real MySQL: the accumulation, and that superseding ends it."""

    @pytest.fixture()
    def repo(self, db):  # noqa: ANN001, ANN201
        from aethra_sec.database.repositories.scans import ScanRepository

        return ScanRepository(db)

    # The db fixture is session-scoped, so every test here would otherwise
    # share one host and inherit the previous test's findings. Each gets its
    # own address instead, which keeps the counts meaningful.
    _next_octet = [10]

    @pytest.fixture()
    def address(self) -> str:
        self._next_octet[0] += 1
        return f"10.77.0.{self._next_octet[0]}"

    @pytest.fixture()
    def host_id(self, db, address) -> int:  # noqa: ANN001
        from aethra_sec.database.repositories.hosts import HostRepository
        from aethra_sec.models.enums import EvidenceSource
        from aethra_sec.utils.timeutil import utcnow

        return int(
            HostRepository(db).upsert_observed(
                address, observed_at=utcnow(),
                source=EvidenceSource.NMAP, interface="test",
                detail="supersession fixture",
            )
        )

    def _scan(self, repo, db, address="10.77.0.5", *, hosts_up: int = 1) -> int:  # noqa: ANN001
        from aethra_sec.models.enums import ScanTrigger
        from aethra_sec.models.scan import Scan
        from aethra_sec.utils.timeutil import to_db, utcnow

        scan_id = int(repo.create_scan(Scan(
            id=None, target=address, target_kind="host",
            profile="standard", profile_label="Standard", port_spec="",
            timing="T3", arguments="-sT -sV",
            trigger_source=ScanTrigger.MANUAL,
        )))
        db.execute(
            "UPDATE scans SET status = 'COMPLETED', hosts_up = %s, "
            "finished_at = %s WHERE id = %s",
            (hosts_up, to_db(utcnow()), scan_id),
        )
        return scan_id

    def _finding(self, repo, host_id: int, scan_id: int, port: int,
                 address: str = "10.77.0.5") -> None:  # noqa: ANN001
        repo.add_findings([
            ScanFinding(
                id=None, scan_id=scan_id, scan_host_id=None, host_id=host_id,
                ip_address=address, port=port, protocol="tcp",
                service="msrpc", title=f"msrpc exposed on {port}/tcp",
                risk_level=RiskLevel.LOW, verification_required=True,
            )
        ])

    def _open(self, repo, host_id: int) -> list[ScanFinding]:  # noqa: ANN001
        return [
            f for f in repo.findings_for_host(host_id) if f.resolved_at is None
        ]

    def test_two_scans_accumulate_without_supersession(self, repo, db, host_id, address) -> None:  # noqa: ANN001
        """The bug, reproduced: the same port twice."""
        first = self._scan(repo, db, address)
        self._finding(repo, host_id, first, 135, address)
        second = self._scan(repo, db, address)
        self._finding(repo, host_id, second, 135, address)
        assert len(self._open(repo, host_id)) == 2
        ports = [f.port for f in self._open(repo, host_id)]
        assert ports == [135, 135], "the same port is open twice over"

    def test_superseding_leaves_only_the_current_assessment(self, repo, db, host_id, address) -> None:  # noqa: ANN001
        first = self._scan(repo, db, address)
        self._finding(repo, host_id, first, 135, address)
        second = self._scan(repo, db, address)

        closed = repo.supersede_host_findings(host_id, second)
        self._finding(repo, host_id, second, 135, address)

        assert closed == 1
        remaining = self._open(repo, host_id)
        assert len(remaining) == 1
        assert remaining[0].scan_id == second

    def test_the_superseded_row_keeps_all_its_evidence(self, repo, db, host_id, address) -> None:  # noqa: ANN001
        """Resolved, not deleted - the history stays readable."""
        first = self._scan(repo, db, address)
        self._finding(repo, host_id, first, 445, address)
        second = self._scan(repo, db, address)
        repo.supersede_host_findings(host_id, second)

        everything = repo.findings_for_host(host_id)
        assert len(everything) == 1, "the finding was deleted"
        kept = everything[0]
        assert kept.resolved_at is not None
        assert kept.scan_id == first, "it no longer belongs to its own scan"
        assert kept.port == 445
        assert kept.title == "msrpc exposed on 445/tcp"
        assert kept.risk_level is RiskLevel.LOW

    def test_a_host_that_now_exposes_nothing_is_cleared(self, repo, db, host_id, address) -> None:  # noqa: ANN001
        """The worst case: eleven open findings, latest scan found none."""
        first = self._scan(repo, db, address)
        for port in (135, 139, 445):
            self._finding(repo, host_id, first, port, address)
        assert len(self._open(repo, host_id)) == 3

        # A later scan the host answered, which found nothing open.
        second = self._scan(repo, db, address, hosts_up=1)
        repo.supersede_host_findings(host_id, second)

        assert self._open(repo, host_id) == [], (
            "exposure that has been withdrawn is still reported as current"
        )
        assert len(repo.findings_for_host(host_id)) == 3, "history was lost"

    def test_an_older_scan_cannot_close_a_newer_finding(self, repo, db, host_id, address) -> None:  # noqa: ANN001
        first = self._scan(repo, db, address)
        second = self._scan(repo, db, address)
        self._finding(repo, host_id, second, 3389, address)

        closed = repo.supersede_host_findings(host_id, first)

        assert closed == 0
        assert len(self._open(repo, host_id)) == 1

    def test_another_hosts_findings_are_untouched(self, repo, db, host_id, address) -> None:  # noqa: ANN001
        from aethra_sec.database.repositories.hosts import HostRepository
        from aethra_sec.models.enums import EvidenceSource
        from aethra_sec.utils.timeutil import utcnow

        other = int(HostRepository(db).upsert_observed(
            "10.77.0.6", observed_at=utcnow(), source=EvidenceSource.NMAP,
            interface="test", detail="supersession fixture",
        ))
        first = self._scan(repo, db, address)
        self._finding(repo, host_id, first, 135, address)
        self._finding(repo, other, first, 135)
        second = self._scan(repo, db, address)

        repo.supersede_host_findings(host_id, second)

        assert len(self._open(repo, other)) == 1, (
            "superseding one host closed another host's findings"
        )

    def test_an_analyst_resolution_is_not_restamped(self, repo, db, host_id, address) -> None:  # noqa: ANN001
        first = self._scan(repo, db, address)
        self._finding(repo, host_id, first, 135, address)
        finding = repo.findings_for_host(host_id)[0]
        repo.resolve_finding(finding.id)
        stamped = repo.findings_for_host(host_id)[0].resolved_at

        second = self._scan(repo, db, address)
        closed = repo.supersede_host_findings(host_id, second)

        assert closed == 0
        assert repo.findings_for_host(host_id)[0].resolved_at == stamped

    def test_the_host_finding_count_follows(self, repo, db, host_id, address) -> None:  # noqa: ANN001
        """§4-style consistency: the table's count is the same set."""
        from aethra_sec.database.repositories.hosts import HostRepository

        hosts = HostRepository(db)
        first = self._scan(repo, db, address)
        for port in (135, 139):
            self._finding(repo, host_id, first, port, address)
        second = self._scan(repo, db, address)
        self._finding(repo, host_id, second, 135, address)
        repo.supersede_host_findings(host_id, second)

        # assessment_overview, not get(): the counters live in that query's
        # sub-selects, and it is the one the Vulnerability Assessment table
        # is built from. get() is a plain row fetch and leaves them at zero.
        host = next(
            h for h in hosts.assessment_overview(text=address, limit=50)
            if h.id == host_id
        )
        assert host.finding_count == len(self._open(repo, host_id)) == 1, (
            "the Findings column and the open findings disagree"
        )
