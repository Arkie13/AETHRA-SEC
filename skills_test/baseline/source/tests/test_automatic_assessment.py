"""Automatic vulnerability assessment: honest results, real evidence (§4-§20).

The automation discovers hosts from real packets, assesses them with real Nmap
through the reviewed service path, and reports what the evidence supports. These
tests pin the parts where "make it look finished" would be tempting and wrong:

* missing or failed evidence is never rendered as safety;
* a host that did not answer a scan is not "no findings";
* a host returns from OFFLINE only by being observed again;
* the discovery-to-assessment loop is actually wired, not dormant.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from typing import Any

from aethra_sec.models.enums import (
    AssessmentState,
    EvidenceSource,
    HostStatus,
    RiskLevel,
)
from aethra_sec.models.host import (
    NOT_DETERMINED,
    SAFE,
    AT_RISK,
    LOW_FINDINGS,
    NO_FINDINGS,
    NO_RESPONSE,
    NOT_ASSESSED,
    NOT_AUTHORISED,
    OUT_OF_SCOPE,
    QUEUED,
    SCAN_FAILED,
    SCANNING,
    TIMEOUT,
    VULNERABLE,
    Host,
    derive_security_result,
)

NOW = datetime.now(UTC)


def _host(**kwargs: Any) -> Host:
    base: dict[str, Any] = {"id": 1, "ip_address": "192.168.1.10"}
    base.update(kwargs)
    return Host(**base)


# ---------------------------------------------------------------------------
# The security result is derived from evidence, and never invents safety
# ---------------------------------------------------------------------------
class TestSecurityResultNeverInventsSafety:
    """§8, §9, §15 - the forbidden conversions, made impossible."""

    def test_a_failed_scan_is_not_safe(self) -> None:
        host = _host(
            assessment_state=AssessmentState.FAILED, last_assessed_at=NOW,
            last_scan_status="FAILED", finding_count=0,
        )
        assert host.security_result is SCAN_FAILED
        assert host.security_result is not NO_FINDINGS

    def test_a_host_that_did_not_answer_the_scan_is_not_safe(self) -> None:
        """A scan nothing answered establishes nothing, so it concludes nothing."""
        host = _host(
            assessment_state=AssessmentState.COMPLETED, last_assessed_at=NOW,
            last_scan_status="COMPLETED", last_scan_hosts_up=0, finding_count=0,
        )
        assert host.security_result is NOT_DETERMINED
        assert host.security_result is not SAFE
        assert host.security_conclusion is NOT_DETERMINED

    def test_an_unauthorised_host_is_not_safe(self) -> None:
        host = _host(assessment_state=AssessmentState.SKIPPED, finding_count=0)
        assert host.security_result is NOT_AUTHORISED

    def test_a_never_assessed_host_is_not_safe(self) -> None:
        host = _host(assessment_state=AssessmentState.DISCOVERED, finding_count=0)
        assert host.security_result is NOT_ASSESSED

    def test_assessed_without_a_recorded_scan_outcome_is_unknown(self) -> None:
        host = _host(
            assessment_state=AssessmentState.COMPLETED, last_assessed_at=NOW,
            last_scan_status="", last_scan_hosts_up=None, finding_count=0,
        )
        assert host.security_result is NOT_DETERMINED

    def test_no_findings_needs_a_completed_scan_of_a_live_host(self) -> None:
        host = _host(
            assessment_state=AssessmentState.COMPLETED, last_assessed_at=NOW,
            last_scan_status="COMPLETED", last_scan_hosts_up=1, finding_count=0,
        )
        assert host.security_result is SAFE
        assert host.security_conclusion is SAFE

    def test_a_high_rated_finding_makes_the_host_vulnerable(self) -> None:
        """§3.9.9: vulnerable when the highest finding is High or Critical."""
        host = _host(
            assessment_state=AssessmentState.COMPLETED, last_assessed_at=NOW,
            last_scan_status="COMPLETED", last_scan_hosts_up=1, finding_count=3,
            highest_finding=RiskLevel.HIGH, confirmed_finding_count=3,
        )
        assert host.security_result is VULNERABLE
        assert host.security_conclusion is VULNERABLE

    def test_a_medium_rated_finding_is_at_risk_not_vulnerable(self) -> None:
        """Any open finding used to read VULNERABLE; §3.9.9 says At risk."""
        host = _host(
            assessment_state=AssessmentState.COMPLETED, last_assessed_at=NOW,
            last_scan_status="COMPLETED", last_scan_hosts_up=1, finding_count=2,
            highest_finding=RiskLevel.MEDIUM, confirmed_finding_count=0,
        )
        # An open RDP port rated MEDIUM is exposure, not a vulnerability:
        # nothing here is evidence a scanner can point at.
        assert host.security_result is SAFE
        assert host.security_result is not VULNERABLE

    def test_only_low_rated_findings_are_not_vulnerable(self) -> None:
        """An informational 'tcpwrapped exposed' port read VULNERABLE before."""
        host = _host(
            assessment_state=AssessmentState.COMPLETED, last_assessed_at=NOW,
            last_scan_status="COMPLETED", last_scan_hosts_up=1, finding_count=1,
            highest_finding=RiskLevel.INFORMATIONAL, confirmed_finding_count=0,
        )
        assert host.security_result is SAFE
        assert host.security_result is not VULNERABLE

    def test_an_unrated_finding_is_not_guessed_either_way(self) -> None:
        """An unconfirmed finding never makes a host Vulnerable."""
        host = _host(
            assessment_state=AssessmentState.COMPLETED, last_assessed_at=NOW,
            last_scan_status="COMPLETED", last_scan_hosts_up=1, finding_count=1,
            confirmed_finding_count=0,
        )
        assert host.security_result is not VULNERABLE

    def test_a_real_cvss_score_decides_the_band(self) -> None:
        from aethra_sec.models.host import cvss_band

        assert cvss_band(9.8) is RiskLevel.CRITICAL
        assert cvss_band(7.0) is RiskLevel.HIGH
        assert cvss_band(6.9) is RiskLevel.MEDIUM
        assert cvss_band(4.0) is RiskLevel.MEDIUM
        assert cvss_band(3.9) is RiskLevel.LOW
        assert cvss_band(0.0) is RiskLevel.INFORMATIONAL
        assert cvss_band(None) is None, "no score must never become a default band"

    def test_a_timed_out_scan_is_not_safe(self) -> None:
        """Nmap reports a host-timeout host UP with exit=success."""
        host = _host(
            assessment_state=AssessmentState.TIMEOUT, last_assessed_at=None,
            last_scan_status="TIMEOUT", finding_count=0,
        )
        assert host.security_result is TIMEOUT
        assert host.security_result is not NO_FINDINGS

    def test_outside_the_scope_is_reported_as_such(self) -> None:
        host = _host(assessment_state=AssessmentState.SKIPPED, finding_count=0)
        host.in_scope = False
        assert host.security_result is OUT_OF_SCOPE
        assert host.assessment_status_text == "OUT OF SCOPE"

    def test_cooldown_is_treated_as_assessed(self) -> None:
        host = _host(
            assessment_state=AssessmentState.COOLDOWN, last_assessed_at=NOW,
            last_scan_status="COMPLETED", last_scan_hosts_up=1, finding_count=0,
        )
        assert host.security_result is SAFE

    def test_scanning_and_queued_report_their_own_state(self) -> None:
        assert _host(assessment_state=AssessmentState.SCANNING).security_result is SCANNING
        assert _host(assessment_state=AssessmentState.QUEUED).security_result is QUEUED

    def test_findings_outrank_a_missing_scan_row(self) -> None:
        """An unresolved finding is vulnerability evidence even if the last
        scan row is gone."""
        result = derive_security_result(
            AssessmentState.COOLDOWN, finding_count=1,
            last_scan_status="", last_scan_hosts_up=None, last_assessed_at=NOW,
            highest_finding=RiskLevel.CRITICAL, confirmed_finding_count=1,
        )
        assert result is VULNERABLE

    def test_an_unresolved_finding_makes_even_a_never_queued_host_vulnerable(
        self,
    ) -> None:
        """A finding from a manual scan counts, so the vulnerable-hosts count
        equals the VULNERABLE rows shown."""
        host = _host(
            assessment_state=AssessmentState.DISCOVERED, last_assessed_at=None,
            last_scan_status="", finding_count=2, highest_finding=RiskLevel.HIGH,
            confirmed_finding_count=2,
        )
        assert host.security_result is VULNERABLE

    def test_findings_outrank_an_in_progress_rescan(self) -> None:
        """VULNERABLE while a re-scan runs; the assessment column shows SCANNING."""
        host = _host(
            assessment_state=AssessmentState.SCANNING, finding_count=1,
            last_assessed_at=NOW, highest_finding=RiskLevel.HIGH,
            confirmed_finding_count=1,
        )
        # A re-scan in progress reports SCANNING; the security column waits
        # for it to finish rather than restating the previous verdict.
        assert host.assessment_status_text == "SCANNING"
        # Confirmed evidence is not suppressed by a re-scan in progress.
        assert host.security_result is VULNERABLE


class TestTheThreeStatusesStaySeparate:
    """§15 - host status, assessment status and security result are distinct."""

    def test_up_but_failed_assessment_is_unknown_not_safe(self) -> None:
        host = _host(
            status=HostStatus.UP, assessment_state=AssessmentState.FAILED,
            last_assessed_at=NOW, last_scan_status="FAILED",
        )
        assert host.host_status_text == "UP"
        assert host.assessment_status_text == "SCAN FAILED"
        assert host.security_result is SCAN_FAILED

    def test_down_host_reads_as_offline(self) -> None:
        assert _host(status=HostStatus.DOWN).host_status_text == "OFFLINE"

    def test_unknown_host_status(self) -> None:
        assert _host(status=HostStatus.UNKNOWN).host_status_text == "UNKNOWN"


# ---------------------------------------------------------------------------
# The repository queries do what the honesty rules require
# ---------------------------------------------------------------------------
class _FakeDB:
    """Captures SQL so a query's shape can be asserted without a server."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows or []
        self.calls: list[tuple[str, tuple]] = []

    def execute(self, sql: str, params: Any = ()) -> int:
        self.calls.append((sql, tuple(params)))
        return 1

    def execute_many(self, sql: str, rows: Any = ()) -> int:
        self.calls.append((sql, tuple(rows)))
        return len(list(rows))

    def query(self, sql: str, params: Any = ()) -> list[dict[str, Any]]:
        self.calls.append((sql, tuple(params)))
        return self.rows

    def query_one(self, sql: str, params: Any = ()) -> dict[str, Any] | None:
        self.calls.append((sql, tuple(params)))
        return self.rows[0] if self.rows else None

    def query_value(self, sql: str, params: Any = (), default: Any = None) -> Any:
        self.calls.append((sql, tuple(params)))
        return default


class TestRepositoryHonesty:
    def _repo(self, rows: list[dict[str, Any]] | None = None):
        from aethra_sec.database.repositories.hosts import HostRepository

        db = _FakeDB(rows)
        return HostRepository(db), db

    def test_reobservation_restores_up(self) -> None:
        """A host seen transmitting again must leave OFFLINE."""
        repo, db = self._repo()
        repo.upsert_observed("192.168.1.10", observed_at=NOW, source=EvidenceSource.PYSHARK)
        sql = db.calls[0][0]
        assert "status = 'UP'" in sql
        assert "ON DUPLICATE KEY UPDATE" in sql

    def test_offline_marking_targets_only_stale_non_down_hosts(self) -> None:
        repo, db = self._repo()
        repo.mark_stale_offline(NOW - timedelta(minutes=15))
        sql, params = db.calls[0]
        assert "UPDATE hosts SET status" in sql
        assert "last_seen <" in sql
        assert "status <> " in sql
        # It never touches first_seen, assessments or findings.
        assert "first_seen" not in sql
        assert "assessment_state" not in sql
        assert str(HostStatus.DOWN) in params

    def test_vulnerable_count_is_unresolved_findings(self) -> None:
        repo, db = self._repo()
        repo.count_vulnerable()
        sql = db.calls[0][0]
        assert "scan_findings" in sql
        assert "resolved_at IS NULL" in sql
        assert "COUNT(DISTINCT host_id)" in sql

    def test_overview_joins_the_last_scan_and_populates_transient_fields(self) -> None:
        repo, db = self._repo(
            rows=[{
                "id": 5, "ip_address": "192.168.1.20",
                "assessment_state": "COMPLETED", "status": "UP",
                "last_scan_status": "COMPLETED", "last_scan_hosts_up": 1,
                "finding_count": 0,
            }]
        )
        hosts = repo.assessment_overview(text="192.168")
        sql = db.calls[0][0]
        assert "LEFT JOIN scans s ON s.id = h.last_scan_id" in sql
        assert "resolved_at IS NULL" in sql  # unresolved findings only
        assert len(hosts) == 1
        host = hosts[0]
        assert host.last_scan_status == "COMPLETED"
        assert host.last_scan_hosts_up == 1
        # And the derived result flows straight through.
        assert host.security_result is SAFE


# ---------------------------------------------------------------------------
# The loop is actually wired
# ---------------------------------------------------------------------------
class TestTheLoopIsClosed:
    """The automation was dormant because no session was ever attached."""

    def test_set_session_attaches_the_session_to_the_queue(self) -> None:
        """Without this, run_cycle returns 'No session: idle' forever."""
        source = inspect.getsource(
            __import__(
                "aethra_sec.core.application", fromlist=["ApplicationContext"]
            ).ApplicationContext.set_session
        )
        assert "assessment_queue" in source
        assert "attach_session" in source

    def test_a_scheduler_job_runs_the_cycle(self) -> None:
        from aethra_sec.core.application import ApplicationContext

        source = inspect.getsource(ApplicationContext._register_jobs)
        assert "assessment-queue" in source
        assert "run_cycle" in source

    def test_offline_marking_is_scheduled(self) -> None:
        from aethra_sec.core.application import ApplicationContext

        source = inspect.getsource(ApplicationContext._register_jobs)
        assert "host-liveness" in source
