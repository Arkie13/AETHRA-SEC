"""A finished scan and an examined host are different facts.

The automatic assessment reported

    Host: OFFLINE   Assessment: COMPLETED   Open ports: 0   Findings: 0

for hosts Nmap had never got an answer from. Each of those columns was
individually defensible and together they read as a host that had been
examined and found clean. It had not been examined at all.

The lifecycle now has a terminal state for it, and these tests hold the
distinction at every layer it has to survive: the enum, the queue that settles
a finished scan, the host model that labels it, the security result derived
from it, and the counts on both screens.

They also hold the two rules the whole feature rests on:

* an unexamined host is never Safe, and
* an open port is exposure, never a vulnerability, whatever its rating.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aethra_sec.models.enums import AssessmentState, HostStatus, RiskLevel
from aethra_sec.models.host import (
    NOT_DETERMINED,
    OFFLINE,
    SAFE,
    VULNERABLE,
    AssessmentSummary,
    Host,
    derive_security_result,
    is_confirmed_vulnerability,
    summarize_assessment,
)

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
QUEUE = PACKAGE / "services" / "assessment_queue.py"
VULN_SCREEN = PACKAGE / "ui" / "screens" / "vulnerabilities.py"
DASHBOARD = PACKAGE / "ui" / "screens" / "dashboard.py"


def _host(**kwargs) -> Host:  # noqa: ANN003
    """A host with only the fields a test names."""
    base = {
        "id": 1,
        "ip_address": "192.168.100.50",
        "status": HostStatus.DOWN,
        "assessment_state": AssessmentState.COMPLETED,
        "last_scan_status": "COMPLETED",
        "last_scan_hosts_up": 1,
        "last_assessed_at": datetime.now(tz=timezone.utc),
    }
    base.update(kwargs)
    return Host(**base)


# ---------------------------------------------------------------------------
# The state exists
# ---------------------------------------------------------------------------
class TestTheTerminalStateExists:
    """§7 lists five terminal results; one of them had nowhere to be stored."""

    def test_no_response_is_a_real_state(self) -> None:
        assert AssessmentState.NO_RESPONSE == "NO_RESPONSE"

    def test_every_terminal_outcome_can_be_expressed(self) -> None:
        for name in ("COMPLETED", "NO_RESPONSE", "TIMEOUT", "FAILED", "SKIPPED"):
            assert hasattr(AssessmentState, name), (
                f"{name} is a terminal outcome the pipeline can reach with no "
                "state to record it in"
            )

    def test_it_fits_the_stored_column(self) -> None:
        """``hosts.assessment_state`` is VARCHAR(16)."""
        assert len(str(AssessmentState.NO_RESPONSE)) <= 16

    def test_it_is_not_pending(self) -> None:
        """A terminal state must not read as work still in progress."""
        assert not AssessmentState.NO_RESPONSE.is_pending


# ---------------------------------------------------------------------------
# The queue settles a finished scan on the evidence
# ---------------------------------------------------------------------------
class TestTheQueueReadsWhetherTheHostAnswered:
    def _reap_source(self) -> str:
        tree = ast.parse(QUEUE.read_text(encoding="utf-8"))
        node = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "_reap_finished"
        )
        return ast.unparse(node)

    def test_it_selects_the_answer_count(self) -> None:
        assert "hosts_up" in self._reap_source(), (
            "the queue settles a finished scan from its status alone, so a "
            "clean scan of a silent host is recorded as COMPLETED"
        )

    def test_a_silent_host_settles_as_no_response(self) -> None:
        source = self._reap_source()
        assert "AssessmentState.NO_RESPONSE" in source

    def test_an_answering_host_still_settles_as_completed(self) -> None:
        source = self._reap_source()
        assert "AssessmentState.COMPLETED" in source

    def test_a_silent_host_does_not_burn_the_retry_cap(self) -> None:
        """It is not a failing scan, and the host may come back."""
        source = self._reap_source()
        no_response = source[source.index("NO_RESPONSE"):]
        # The NO_RESPONSE branch must not advance the attempt counter.
        branch = no_response[: no_response.index("elif") if "elif" in no_response
                             else len(no_response)]
        assert "attempt=True" not in branch

    def test_a_silent_host_is_still_paced(self) -> None:
        """Without a stamp it would be re-queued every cycle forever."""
        source = self._reap_source()
        assert source.count("assessed=True") >= 2, (
            "the NO_RESPONSE branch does not stamp the host as assessed, so "
            "the reassessment cooldown never applies and a quiet subnet is "
            "rescanned continuously"
        )


# ---------------------------------------------------------------------------
# The host labels it honestly
# ---------------------------------------------------------------------------
class TestTheAssessmentColumn:
    def test_an_answering_host_reads_completed(self) -> None:
        assert _host().assessment_status_text == "COMPLETED"

    def test_a_silent_host_reads_no_response(self) -> None:
        assert _host(last_scan_hosts_up=0).assessment_status_text == "NO RESPONSE"

    def test_the_new_state_reads_no_response(self) -> None:
        host = _host(assessment_state=AssessmentState.NO_RESPONSE)
        assert host.assessment_status_text == "NO RESPONSE"

    def test_a_cooldown_after_a_silent_scan_does_not_read_completed(self) -> None:
        """COOLDOWN inherited COMPLETED's label without checking the evidence."""
        host = _host(
            assessment_state=AssessmentState.COOLDOWN, last_scan_hosts_up=0
        )
        assert host.assessment_status_text == "NO RESPONSE"

    def test_a_cooldown_after_a_real_scan_still_reads_completed(self) -> None:
        host = _host(assessment_state=AssessmentState.COOLDOWN)
        assert host.assessment_status_text == "COMPLETED"

    def test_a_host_with_no_scan_is_not_relabelled(self) -> None:
        """Nothing to check against, so the stored state stands."""
        host = _host(last_scan_status="", last_scan_hosts_up=None)
        assert host.assessment_status_text == "COMPLETED"

    def test_host_answered_requires_both_facts(self) -> None:
        assert _host().host_answered
        assert not _host(last_scan_hosts_up=0).host_answered
        assert not _host(last_scan_status="TIMEOUT").host_answered
        assert not _host(last_scan_status="FAILED", last_scan_hosts_up=1).host_answered


class TestTheHostStateAndAssessmentStayApart:
    """§30: UP/OFFLINE, the lifecycle, and the security result are three axes."""

    def test_an_offline_host_keeps_its_completed_assessment(self) -> None:
        """§53: the host went away after a real assessment; both are true."""
        host = _host(status=HostStatus.DOWN)
        assert host.assessment_status_text == "COMPLETED"
        assert host.security_conclusion is SAFE
        assert host.last_assessed_at is not None, (
            "the timestamp is what tells the operator the result is historical"
        )

    def test_an_offline_host_that_never_answered_is_not_safe(self) -> None:
        host = _host(status=HostStatus.DOWN, last_scan_hosts_up=0)
        assert host.assessment_status_text == "NO RESPONSE"
        assert host.security_conclusion is NOT_DETERMINED


# ---------------------------------------------------------------------------
# The security result
# ---------------------------------------------------------------------------
class TestTheSecurityResultIsEvidenceBased:
    """§24: exactly three answers, two of which need a completed assessment."""

    def _derive(self, **kwargs):  # noqa: ANN003, ANN202
        base = {
            "finding_count": 0,
            "last_scan_status": "COMPLETED",
            "last_scan_hosts_up": 1,
            "last_assessed_at": datetime.now(tz=timezone.utc),
            "confirmed_finding_count": 0,
        }
        state = kwargs.pop("state", AssessmentState.COMPLETED)
        base.update(kwargs)
        return derive_security_result(state, **base)

    def test_completed_and_answered_with_nothing_confirmed_is_safe(self) -> None:
        assert self._derive() is SAFE

    def test_confirmed_evidence_is_vulnerable(self) -> None:
        assert self._derive(confirmed_finding_count=1) is VULNERABLE

    def test_the_new_state_is_never_safe(self) -> None:
        result = self._derive(state=AssessmentState.NO_RESPONSE)
        assert result is not SAFE
        assert result is OFFLINE

    def test_the_new_state_survives_the_scan_row_going_away(self) -> None:
        """Retention prunes scans; the verdict must not become Safe."""
        result = self._derive(
            state=AssessmentState.NO_RESPONSE,
            last_scan_status="", last_scan_hosts_up=None,
        )
        assert result is not SAFE

    @pytest.mark.parametrize(
        "state",
        [
            AssessmentState.QUEUED,
            AssessmentState.SCANNING,
            AssessmentState.NO_RESPONSE,
            AssessmentState.TIMEOUT,
            AssessmentState.FAILED,
            AssessmentState.DISCOVERED,
        ],
    )
    def test_no_incomplete_state_reaches_a_conclusion(
        self, state: AssessmentState
    ) -> None:
        """§29: the security column stays empty for all of these."""
        host = _host(assessment_state=state, last_scan_hosts_up=0)
        assert host.security_conclusion is NOT_DETERMINED
        assert host.security_conclusion.label == "-"

    def test_zero_open_ports_is_a_valid_safe(self) -> None:
        """§15: a phone that answered and exposes nothing is Safe."""
        host = _host(open_port_count=0, finding_count=0)
        assert host.security_conclusion is SAFE

    def test_only_safe_is_coloured(self) -> None:
        """§25: Safe is green; every other result stays neutral."""
        assert SAFE.tone == "ok"
        for result in (VULNERABLE, NOT_DETERMINED):
            assert result.tone != "ok", (
                f"{result.label!r} carries a colour that only Safe may have"
            )


class TestExposureIsNotVulnerability:
    """§19, §26, §56, §58 - the rule the whole confirmed-only policy rests on."""

    @pytest.mark.parametrize("risk", [RiskLevel.MEDIUM, RiskLevel.LOW,
                                      RiskLevel.INFORMATIONAL])
    def test_an_unconfirmed_finding_is_never_a_vulnerability(
        self, risk: RiskLevel
    ) -> None:
        assert not is_confirmed_vulnerability(
            verification_required=True, cvss_base_score=None,
            risk_level=risk, reference_id="",
        )

    def test_a_medium_exposure_alone_does_not_make_a_host_vulnerable(self) -> None:
        """§58: MEDIUM+ must not be a shortcut to Vulnerable."""
        host = _host(finding_count=3, confirmed_finding_count=0)
        assert host.security_conclusion is SAFE

    def test_a_cve_reference_is_confirmation(self) -> None:
        assert is_confirmed_vulnerability(
            verification_required=True, cvss_base_score=None,
            risk_level=RiskLevel.LOW, reference_id="CVE-2021-44228",
        )

    def test_a_cvss_score_is_confirmation(self) -> None:
        assert is_confirmed_vulnerability(
            verification_required=True, cvss_base_score=5.3,
            risk_level=RiskLevel.MEDIUM, reference_id="",
        )

    def test_a_high_rating_is_confirmation(self) -> None:
        assert is_confirmed_vulnerability(
            verification_required=True, cvss_base_score=None,
            risk_level=RiskLevel.HIGH, reference_id="",
        )

    def test_one_confirmed_finding_outranks_the_lifecycle(self) -> None:
        """A known vulnerability is not hidden by a re-scan in progress."""
        host = _host(
            assessment_state=AssessmentState.SCANNING, confirmed_finding_count=1
        )
        assert host.security_conclusion is VULNERABLE
        assert host.assessment_status_text == "SCANNING"


# ---------------------------------------------------------------------------
# Identity columns answer about identity
# ---------------------------------------------------------------------------
class TestTheIdentityColumns:
    """§8, §37: unknown identity reads Unknown, and never implies a skip."""

    def test_an_unresolved_hostname_reads_unknown(self) -> None:
        assert _host(hostname="").hostname_text == "Unknown"

    def test_the_column_never_says_the_lookup_was_not_made(self) -> None:
        for host in (
            _host(hostname=""),
            _host(hostname="", hostname_checked_at=datetime.now(tz=timezone.utc)),
        ):
            assert "checked" not in host.hostname_text.lower(), (
                "the identity column reports the lookup's progress, which "
                "beside a completed assessment reads as a skipped host"
            )

    def test_the_lookup_state_is_still_available(self) -> None:
        assert "Not looked up yet" == _host(hostname="").hostname_lookup_text

    def test_a_real_name_is_never_replaced(self) -> None:
        assert _host(hostname="iPad-5.local").hostname_text == "iPad-5.local"

    def test_no_name_is_invented(self) -> None:
        """§11: never "iPhone-001" or the address dressed up as a name."""
        host = _host(hostname="")
        assert host.ip_address not in host.hostname_text
        assert host.hostname_text == "Unknown"


class TestASkippedHostSaysWhy:
    """§37: a blank reason leaves the operator unable to tell why."""

    def test_a_recorded_reason_is_used(self) -> None:
        host = _host(
            assessment_state=AssessmentState.SKIPPED,
            assessment_detail="the monitoring host itself",
        )
        assert host.assessment_reason_text == "the monitoring host itself"

    def test_a_blank_reason_is_reported_as_missing(self) -> None:
        host = _host(assessment_state=AssessmentState.SKIPPED, assessment_detail="")
        assert "no reason was recorded" in host.assessment_reason_text

    def test_other_states_do_not_gain_filler(self) -> None:
        host = _host(assessment_state=AssessmentState.COMPLETED, assessment_detail="")
        assert host.assessment_reason_text == ""


# ---------------------------------------------------------------------------
# The counts
# ---------------------------------------------------------------------------
class TestTheCountsMatchTheRows:
    """§38: the tiles and the table derive from one rule."""

    def test_an_unexamined_host_is_not_counted_safe(self) -> None:
        hosts = [
            _host(id=1, ip_address="10.0.0.1"),
            _host(id=2, ip_address="10.0.0.2", last_scan_hosts_up=0,
                  assessment_state=AssessmentState.NO_RESPONSE),
        ]
        summary = summarize_assessment(hosts, None)
        assert summary.safe == 1
        assert summary.offline == 1, "the no-response host is counted apart"

    def test_a_confirmed_host_counts_vulnerable(self) -> None:
        summary = summarize_assessment(
            [_host(confirmed_finding_count=1)], None
        )
        assert summary.vulnerable == 1
        assert summary.safe == 0

    def test_the_summary_has_the_three_conclusions(self) -> None:
        for field in ("vulnerable", "safe", "not_determined"):
            assert field in AssessmentSummary.__dataclass_fields__

    def test_an_empty_inventory_counts_zero(self) -> None:
        """No hosts means 0, never a placeholder."""
        summary = summarize_assessment([], None)
        assert (summary.safe, summary.vulnerable, summary.discovered) == (0, 0, 0)


class TestTheScreensUseTheNewVocabulary:
    """§23, §62: the forbidden labels are not shown as a security result."""

    @pytest.mark.parametrize(
        "banned",
        ["AT RISK", "LOW-RATED", "NO FINDINGS", "Offline (no scan response)"],
    )
    def test_the_assessment_counts_do_not_use_them(self, banned: str) -> None:
        source = VULN_SCREEN.read_text(encoding="utf-8")
        assert banned not in source, (
            f"{banned!r} is still shown on the Vulnerability Assessment "
            "screen as a security result"
        )

    def test_the_counts_name_the_three_conclusions(self) -> None:
        source = VULN_SCREEN.read_text(encoding="utf-8")
        for expected in ("VULNERABLE", "SAFE", "NO CONCLUSION"):
            assert expected in source

    def test_the_counts_keep_the_lifecycle_separate(self) -> None:
        source = VULN_SCREEN.read_text(encoding="utf-8")
        for expected in ("NO RESPONSE", "TIMEOUT", "SCAN FAILED", "SKIPPED"):
            assert expected in source

    def test_the_dashboard_tiles_were_renamed_too(self) -> None:
        source = DASHBOARD.read_text(encoding="utf-8")
        assert '"va_safe"' in source and '"va_no_conclusion"' in source
        assert '"va_no_findings"' not in source
        assert "at risk ·" not in source, (
            "the dashboard still grades exposures as a security result"
        )

    def test_the_table_shows_the_conclusion_not_the_lifecycle(self) -> None:
        source = VULN_SCREEN.read_text(encoding="utf-8")
        assert '"security": host.security_conclusion.label' in source


class TestTheUnscopedViewDoesNotInvent:
    """§2, §63: without a scope the monitored network cannot be listed."""

    def test_the_monitored_filter_reports_the_missing_scope(self) -> None:
        source = inspect.getsource(
            __import__(
                "aethra_sec.ui.screens.vulnerabilities", fromlist=["x"]
            ).VulnerabilitiesScreen._render_inventory
        )
        assert "scope_available" in source, (
            "the monitored-network view falls through to the whole inventory "
            "when no scope is resolved, listing Internet addresses observed "
            "as traffic destinations as though they were local hosts"
        )
        assert "Assessment scope is not configured" in source

    def test_the_wording_matches_the_halt_message(self) -> None:
        source = VULN_SCREEN.read_text(encoding="utf-8")
        assert "hosts are discovered from real observed traffic" in source


# ---------------------------------------------------------------------------
# Mitigation reaches the vulnerability detail
# ---------------------------------------------------------------------------
class TestTheVulnerabilityDetailCarriesMitigation:
    """§27, §55: the evidence and what to do about it, in one place."""

    def test_a_confirmed_finding_gets_a_mitigation_section(self) -> None:
        source = VULN_SCREEN.read_text(encoding="utf-8")
        assert "_mitigation_drawer_section(" in source

    def test_the_lookup_runs_off_the_ui_thread(self) -> None:
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        body = inspect.getsource(VulnerabilitiesScreen._load_host_evidence)
        assert "match_for_finding" in body, (
            "the drawer resolves mitigation while rendering, on the Tk thread"
        )

    def test_only_confirmed_findings_are_looked_up(self) -> None:
        """An open port is not something to remediate."""
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        body = inspect.getsource(VulnerabilitiesScreen._load_host_evidence)
        assert "_is_confirmed(finding)" in body

    def test_the_three_outcomes_are_kept_apart(self) -> None:
        from aethra_sec.models.mitigation import MitigationMatch
        from aethra_sec.models.enums import ThreatCategory
        from aethra_sec.ui.screens.vulnerabilities import (
            _mitigation_drawer_section,
        )

        failed = _mitigation_drawer_section(
            MitigationMatch(lookup_failed=True, failure_detail="gone"), 1, 1
        )
        empty = _mitigation_drawer_section(
            MitigationMatch(category=ThreatCategory.SERVICE_EXPOSURE), 1, 1
        )
        absent = _mitigation_drawer_section(None, 1, 1)
        assert len({failed.subtitle, empty.subtitle, absent.subtitle}) == 3
        assert "lookup failed" in failed.subtitle
        assert "no mapping" in empty.subtitle

    def test_a_failure_does_not_read_as_nothing_configured(self) -> None:
        from aethra_sec.models.mitigation import LOOKUP_FAILED_TEXT, MitigationMatch
        from aethra_sec.services.mitigation_service import NO_RECOMMENDATION_TEXT
        from aethra_sec.ui.screens.vulnerabilities import (
            _mitigation_drawer_section,
        )

        section = _mitigation_drawer_section(
            MitigationMatch(lookup_failed=True), 1, 1
        )
        assert LOOKUP_FAILED_TEXT in section.text
        assert NO_RECOMMENDATION_TEXT not in section.text

    def test_no_guidance_is_composed_locally(self) -> None:
        """Every line is a stored field or a statement about the lookup."""
        from aethra_sec.ui.screens.vulnerabilities import (
            _mitigation_drawer_section,
        )

        source = inspect.getsource(_mitigation_drawer_section)
        for invented in ("Block the", "immediately", "Disable the service"):
            assert invented not in source


class TestMitigationResolvesFromTheRealFinding:
    """The mapping is the existing one, driven by the scanner's own reading."""

    def test_the_category_is_service_exposure(self) -> None:
        from aethra_sec.services.mitigation_service import MitigationService

        body = inspect.getsource(MitigationService.match_for_finding)
        assert "SERVICE_EXPOSURE" in body

    def test_the_service_comes_from_the_finding_not_the_port(self) -> None:
        from aethra_sec.services.mitigation_service import MitigationService

        body = inspect.getsource(MitigationService.match_for_finding)
        assert "finding, 'service'" in body or 'finding, "service"' in body
        assert "observed_service" not in body, (
            "the service is guessed from the port instead of using the "
            "scanner's own service detection"
        )


# ---------------------------------------------------------------------------
# Automation must not time out while the application is open
# ---------------------------------------------------------------------------
class TestAutomationOutlivesAQuietHour:
    """§41: no artificial timeout on the assessment workers.

    The queue authenticated with the operator's console session, which idles
    out after ``security.session_timeout_minutes`` (60). The reassessment
    cooldown is six hours, so by the time a host was due again the session had
    always expired: the scan was refused with "Your session has expired" and
    the host was recorded as SKIPPED. Automation stopped about an hour after
    the operator stopped clicking, and blamed the hosts for it.
    """

    def test_the_cycle_refreshes_its_own_session(self) -> None:
        from aethra_sec.services.assessment_queue import AssessmentQueueService

        body = inspect.getsource(AssessmentQueueService.run_cycle)
        assert "_touch_session" in body, (
            "the cycle does not refresh its session, so it expires between "
            "due hosts and every later scan is refused"
        )

    def test_the_refresh_needs_a_live_session(self) -> None:
        """A revoked session must not be revived by the background worker."""
        from aethra_sec.services.assessment_queue import AssessmentQueueService

        body = inspect.getsource(AssessmentQueueService._touch_session)
        assert "sessions.get(" in body, (
            "the refresh touches the session object directly, which would let "
            "automation outlive the sign-in that authorised it"
        )

    def test_automation_gets_its_own_session_not_the_operators(self) -> None:
        from aethra_sec.core.application import ApplicationContext

        body = inspect.getsource(ApplicationContext.set_session)
        assert "automatic-assessment" in body, (
            "the queue is attached to the operator's console session, so "
            "refreshing it would hold an unattended interface signed in"
        )
        assert "sessions.create(" in body

    def test_the_previous_automation_session_is_revoked(self) -> None:
        """One operator's automation must not outlive their sign-in."""
        from aethra_sec.core.application import ApplicationContext

        body = inspect.getsource(ApplicationContext.set_session)
        assert "invalidate(" in body

    def test_signing_out_stops_automation(self) -> None:
        from aethra_sec.core.application import ApplicationContext

        body = inspect.getsource(ApplicationContext.set_session)
        assert "attach_session(None)" in body

    def test_a_session_failure_does_not_blame_the_host(self) -> None:
        """It says nothing about the device, so it must not mark it SKIPPED."""
        from aethra_sec.services.assessment_queue import AssessmentQueueService

        body = inspect.getsource(AssessmentQueueService._start)
        expired = body.index("SessionExpiredError")
        refused = body.index("AethraError")
        assert expired < refused, (
            "SessionExpiredError is caught by the generic refusal handler, "
            "which records the host as SKIPPED for a fault on our side"
        )
        branch = body[expired:refused]
        assert "AssessmentState.DISCOVERED" in branch
        assert "AssessmentState.SKIPPED" not in branch

    def test_a_real_refusal_is_still_recorded(self) -> None:
        """An out-of-scope or unresolvable target still settles as SKIPPED."""
        from aethra_sec.services.assessment_queue import AssessmentQueueService

        body = inspect.getsource(AssessmentQueueService._start)
        assert "AssessmentState.SKIPPED" in body[body.index("AethraError"):]


# ---------------------------------------------------------------------------
# Nothing fabricated
# ---------------------------------------------------------------------------
class TestNoFabricatedProductionData:
    """§3, §4 - audited as a test so it cannot quietly regress."""

    def test_production_never_imports_random(self) -> None:
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    if any(a.name == "random" for a in node.names):
                        offenders.append(path.name)
                elif isinstance(node, ast.ImportFrom) and node.module == "random":
                    offenders.append(path.name)
        assert not offenders, f"production imports random: {offenders}"

    def test_hosts_are_only_written_from_a_real_source(self) -> None:
        """Three callers, each holding real evidence."""
        callers = set()
        for path in PACKAGE.rglob("*.py"):
            if "__pycache__" in path.parts or "repositories" in path.parts:
                continue
            code = path.read_text(encoding="utf-8")
            if "upsert_observed(" in code or "bulk_upsert_observed(" in code:
                callers.add(path.name)
        assert callers <= {
            "nmap_service.py", "packet_capture.py", "snort_service.py"
        }, f"a host is written from an unexpected place: {callers}"

    def test_a_finding_is_only_built_by_the_parser_or_the_row_mapper(self) -> None:
        """Two legitimate places: Nmap's XML, and reading a stored row back.

        Anywhere else would be a finding this system invented rather than
        observed - which is the one thing the assessment must never produce.
        """
        allowed = {"database/repositories/scans.py"}
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            if "__pycache__" in path.parts or "nmap" in path.parts:
                continue
            relative = path.relative_to(PACKAGE).as_posix()
            if "ScanFinding(" not in path.read_text(encoding="utf-8"):
                continue
            if relative in allowed:
                continue
            offenders.append(relative)
        assert not offenders, f"findings built outside the Nmap parser: {offenders}"

    def test_the_row_mapper_only_maps(self) -> None:
        """The one allowance above must stay a mapper, not a source."""
        from aethra_sec.database.repositories.scans import ScanRepository

        body = inspect.getsource(ScanRepository._map_finding)
        assert 'row.get(' in body, "the mapper no longer reads from the row"
        for invented in ("CVE-", "cvss_base_score=7", "random", "default="):
            assert invented not in body, (
                f"the row mapper supplies {invented!r} rather than reading it"
            )
