"""The full alert view carries the mitigation mapped to that alert.

An analyst reading one alert should not have to go and look up what to do
about it. These tests hold the chain from a stored detection to the guidance
shown beside it, and - more importantly - hold it *honest*:

* the guidance is whatever the mitigation knowledge base says, never text
  composed here from the alert's name;
* it changes with the detection, so two different alerts cannot show the same
  advice through a stale panel or a category everything falls into;
* the three outcomes stay apart. Guidance that exists is shown with the
  mapping that produced it. A category nobody has written guidance for says
  so. A knowledge base that could not be *read* says that instead, because
  reporting a fault as "nothing is configured" tells the operator something
  untrue about their own system;
* opening an alert stays a read: no status, no evaluation, no new record.

Nothing here asserts on production rows. The database tests run against the
seeded test schema, and the rest need no database at all.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.enums import Severity, ThreatCategory
from aethra_sec.models.mitigation import (
    LOOKUP_FAILED_TEXT,
    MATCH_CATEGORY,
    MATCH_MAPPING,
    MATCH_SERVICE,
    MATCH_SEVERITY,
    MitigationMatch,
    MitigationRecommendation,
)
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.services.correlation_service import categorise_alert
from aethra_sec.services.mitigation_service import (
    NO_RECOMMENDATION_TEXT,
    MitigationService,
)
from aethra_sec.ui.screens.alerts import (
    _detail_status,
    _mitigation_section,
    _rule_text,
    _value,
)

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "aethra_sec" / "ui" / "screens" / "alerts.py"


# ---------------------------------------------------------------------------
# Test doubles: a knowledge base, not a detection
# ---------------------------------------------------------------------------
def _entry(
    code: str,
    category: ThreatCategory,
    *,
    severity: Severity = Severity.MEDIUM,
    service: str = "",
    active: bool = True,
) -> MitigationRecommendation:
    """One knowledge-base entry, as an administrator would have stored it."""
    return MitigationRecommendation(
        id=abs(hash(code)) % 10_000,
        code=code,
        threat_name=f"{code} threat",
        category=category,
        severity=severity,
        applies_to_service=service,
        explanation=f"{code} explanation",
        why_it_matters=f"{code} why",
        immediate_action=f"{code} immediate",
        long_term_action=f"{code} long term",
        verification_steps=f"{code} verification",
        is_active=active,
    )


class _Repo:
    """A stand-in for the real repository, holding entries by category."""

    def __init__(self, entries: dict[ThreatCategory, list[MitigationRecommendation]]):
        self._entries = entries
        self.calls = 0

    def candidates_for_category(self, category):  # noqa: ANN001, ANN201
        self.calls += 1
        return list(self._entries.get(category, []))


class _BrokenRepo:
    """A repository that cannot be read - the lookup-failure case."""

    def __init__(self, message: str = "Lost connection to MySQL server"):
        self.message = message

    def candidates_for_category(self, category):  # noqa: ANN001, ANN201
        raise RuntimeError(self.message)


def _service(repo: object) -> MitigationService:
    """The real service over a stand-in repository."""
    return MitigationService(repo, audit=None, access=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The alert reaches the category its own text names
# ---------------------------------------------------------------------------
class TestTheAlertReachesItsOwnCategory:
    """A sensor that names the flood it saw is taken at its word.

    Every category asserted here has an entry in the shipped mitigation
    catalogue, so these are mappings that exist rather than ones invented to
    make the view look richer.
    """

    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("TCP SYN flood - possible DoS", ThreatCategory.TCP_SYN_FLOOD),
            ("UDP flood - possible DoS", ThreatCategory.UDP_FLOOD),
            ("ICMP flood - possible ping flood/DoS", ThreatCategory.ICMP_FLOOD),
            ("HTTP request flood against web server", ThreatCategory.HTTP_FLOOD),
        ],
    )
    def test_a_named_flood_keeps_its_own_category(
        self, message: str, expected: ThreatCategory
    ) -> None:
        alert = SnortAlert(message=message, severity=Severity.HIGH)
        assert categorise_alert(alert) is expected

    def test_a_syn_flood_at_a_web_server_is_still_a_syn_flood(self) -> None:
        """HTTP_FLOOD means request volume, which is a different observation."""
        alert = SnortAlert(
            message="HTTP port SYN flood - possible web server DoS",
            classification="Attempted Denial of Service",
            severity=Severity.HIGH,
        )
        assert categorise_alert(alert) is ThreatCategory.TCP_SYN_FLOOD

    def test_an_unnamed_denial_of_service_stays_general(self) -> None:
        """Text that says only "denial of service" gets the general entry."""
        alert = SnortAlert(
            message="Generic denial of service attempt", severity=Severity.HIGH
        )
        assert categorise_alert(alert) is ThreatCategory.DENIAL_OF_SERVICE

    def test_unfamiliar_text_is_still_not_given_a_category(self) -> None:
        """The refinement must not become a licence to guess."""
        for message in (
            "ET TROJAN Command and Control activity",
            "ET SCAN Potential SSH brute force login attempt",
            "Something entirely unfamiliar",
        ):
            alert = SnortAlert(message=message, severity=Severity.MEDIUM)
            assert categorise_alert(alert) is ThreatCategory.UNCLASSIFIED

    def test_every_flood_category_is_a_real_enum_member(self) -> None:
        from aethra_sec.services.correlation_service import _CATEGORY_KEYWORDS

        for category, keywords in _CATEGORY_KEYWORDS:
            assert isinstance(category, ThreatCategory)
            assert keywords


# ---------------------------------------------------------------------------
# Selection: the most specific real mapping wins
# ---------------------------------------------------------------------------
class TestSelectionPrefersTheMostSpecificMapping:
    def test_a_service_specific_entry_outranks_a_generic_one(self) -> None:
        repo = _Repo({
            ThreatCategory.SERVICE_EXPOSURE: [
                _entry("MIT-SSH", ThreatCategory.SERVICE_EXPOSURE, service="ssh"),
                _entry("MIT-GENERIC", ThreatCategory.SERVICE_EXPOSURE),
            ]
        })
        alert = SnortAlert(
            message="service exposure", severity=Severity.MEDIUM,
            protocol="TCP", dst_port=22,
        )
        # The category comes from the text, so drive the selection directly.
        match = _service(repo)._match(
            ThreatCategory.SERVICE_EXPOSURE,
            category_source="test", severity=alert.severity, service="ssh",
        )
        assert match.recommendation is not None
        assert match.recommendation.code == "MIT-SSH"
        assert match.matched_on == MATCH_SERVICE

    def test_a_severity_match_is_reported_as_one(self) -> None:
        repo = _Repo({
            ThreatCategory.PORT_SCAN: [
                _entry("MIT-SCAN", ThreatCategory.PORT_SCAN, severity=Severity.HIGH)
            ]
        })
        match = _service(repo)._match(
            ThreatCategory.PORT_SCAN, category_source="test",
            severity=Severity.HIGH, service="",
        )
        assert match.matched_on == MATCH_SEVERITY

    def test_a_category_only_match_is_reported_as_one(self) -> None:
        repo = _Repo({
            ThreatCategory.PORT_SCAN: [
                _entry("MIT-SCAN", ThreatCategory.PORT_SCAN, severity=Severity.HIGH)
            ]
        })
        match = _service(repo)._match(
            ThreatCategory.PORT_SCAN, category_source="test",
            severity=Severity.LOW, service="",
        )
        assert match.matched_on == MATCH_CATEGORY

    def test_the_mapping_is_used_when_only_a_service_entry_exists(self) -> None:
        """The real HTTP_FLOOD case.

        Its only mapped entry applies to "http", while most real detections of
        it are observed on an ephemeral port. Reporting "no guidance
        configured" for a category the administrator *did* configure would be
        wrong, so the mapping's own first choice is used - and the match says
        it was reached that way.
        """
        repo = _Repo({
            ThreatCategory.HTTP_FLOOD: [
                _entry("MIT-HTTP", ThreatCategory.HTTP_FLOOD, service="http")
            ]
        })
        match = _service(repo)._match(
            ThreatCategory.HTTP_FLOOD, category_source="test",
            severity=Severity.MEDIUM, service="",
        )
        assert match.recommendation is not None
        assert match.recommendation.code == "MIT-HTTP"
        assert match.matched_on == MATCH_MAPPING

    def test_the_mapping_fallback_never_overrides_a_real_match(self) -> None:
        repo = _Repo({
            ThreatCategory.SERVICE_EXPOSURE: [
                _entry("MIT-FIRST", ThreatCategory.SERVICE_EXPOSURE, service="ssh"),
                _entry("MIT-SECOND", ThreatCategory.SERVICE_EXPOSURE),
            ]
        })
        match = _service(repo)._match(
            ThreatCategory.SERVICE_EXPOSURE, category_source="test",
            severity=Severity.MEDIUM, service="mysql",
        )
        # The ssh entry does not apply; the generic one scores and wins. The
        # fallback would have returned MIT-FIRST, which would be wrong.
        assert match.recommendation is not None
        assert match.recommendation.code == "MIT-SECOND"
        assert match.matched_on != MATCH_MAPPING

    def test_an_inactive_entry_is_never_selected(self) -> None:
        repo = _Repo({
            ThreatCategory.PORT_SCAN: [
                _entry("MIT-OLD", ThreatCategory.PORT_SCAN, active=False)
            ]
        })
        match = _service(repo)._match(
            ThreatCategory.PORT_SCAN, category_source="test",
            severity=Severity.MEDIUM, service="",
        )
        assert match.recommendation is None
        assert not match.lookup_failed


class TestTheServiceIsObservedNeverInferred:
    """A service name is evidence, so it comes from the observed port only."""

    def test_a_well_known_port_names_its_service(self) -> None:
        assert MitigationService.observed_service(22, "TCP") == "ssh"
        assert MitigationService.observed_service(80, "TCP") == "http"

    def test_an_ephemeral_port_names_nothing(self) -> None:
        assert MitigationService.observed_service(51753, "UDP") == ""

    def test_a_missing_port_names_nothing(self) -> None:
        assert MitigationService.observed_service(None) == ""
        assert MitigationService.observed_service(0) == ""
        assert MitigationService.observed_service("not a port") == ""

    def test_the_category_never_supplies_the_service(self) -> None:
        """An HTTP_FLOOD detection on no port is not "http"."""
        anomaly = TrafficAnomaly(
            id=1, rule_id="RULE-HTTP-RATE", category=ThreatCategory.HTTP_FLOOD,
            severity=Severity.MEDIUM, dst_port=None,
        )
        repo = _Repo({
            ThreatCategory.HTTP_FLOOD: [
                _entry("MIT-HTTP", ThreatCategory.HTTP_FLOOD, service="http")
            ]
        })
        match = _service(repo).match_for_anomaly(anomaly)
        assert match.observed_service == "", (
            "the service was taken from the threat category, which makes the "
            "mapping look confirmed by traffic that never named it"
        )


# ---------------------------------------------------------------------------
# The three outcomes stay apart
# ---------------------------------------------------------------------------
class TestTheThreeOutcomesStayApart:
    def test_a_resolved_lookup_reports_the_entry(self) -> None:
        repo = _Repo({
            ThreatCategory.PORT_SCAN: [_entry("MIT-SCAN", ThreatCategory.PORT_SCAN)]
        })
        match = _service(repo)._match(
            ThreatCategory.PORT_SCAN, category_source="test",
            severity=Severity.MEDIUM, service="",
        )
        assert match.resolved
        assert not match.lookup_failed
        assert match.status_text == "ACTIVE"

    def test_an_empty_knowledge_base_is_not_a_failure(self) -> None:
        match = _service(_Repo({}))._match(
            ThreatCategory.PORT_SCAN, category_source="test",
            severity=Severity.MEDIUM, service="",
        )
        assert not match.resolved
        assert not match.lookup_failed
        assert match.status_text == "No mapping configured"

    def test_an_unreadable_knowledge_base_is_a_failure(self) -> None:
        match = _service(_BrokenRepo())._match(
            ThreatCategory.PORT_SCAN, category_source="test",
            severity=Severity.MEDIUM, service="",
        )
        assert not match.resolved
        assert match.lookup_failed
        assert match.status_text == "Lookup failed"
        assert "Lost connection" in match.failure_detail

    def test_a_failure_never_reads_as_nothing_configured(self) -> None:
        """The distinction this whole class exists for."""
        failed = _mitigation_section(
            _service(_BrokenRepo())._match(
                ThreatCategory.PORT_SCAN, category_source="test",
                severity=Severity.MEDIUM, service="",
            )
        )
        assert LOOKUP_FAILED_TEXT in failed.body
        assert NO_RECOMMENDATION_TEXT not in failed.body, (
            "a database failure is being reported as an absent configuration"
        )

    def test_the_forgiving_path_still_survives_a_failure(self) -> None:
        """Correlation and reports must not stop for an unreadable knowledge base."""
        assert (
            _service(_BrokenRepo()).recommendation_for(ThreatCategory.PORT_SCAN)
            is None
        )


# ---------------------------------------------------------------------------
# Rendering: nothing is composed here
# ---------------------------------------------------------------------------
class TestNothingIsFabricated:
    def test_every_guidance_line_comes_from_the_stored_entry(self) -> None:
        entry = _entry("MIT-SCAN", ThreatCategory.PORT_SCAN)
        section = _mitigation_section(
            MitigationMatch(
                recommendation=entry, category=ThreatCategory.PORT_SCAN,
                category_source="test", matched_on=MATCH_CATEGORY,
            )
        )
        for stored in (
            entry.explanation, entry.why_it_matters, entry.immediate_action,
            entry.long_term_action, entry.verification_steps, entry.threat_name,
        ):
            assert stored in section.body

    def test_an_empty_field_is_omitted_rather_than_filled_in(self) -> None:
        entry = _entry("MIT-THIN", ThreatCategory.PORT_SCAN)
        entry.long_term_action = ""
        entry.verification_steps = ""
        section = _mitigation_section(
            MitigationMatch(
                recommendation=entry, category=ThreatCategory.PORT_SCAN,
                matched_on=MATCH_CATEGORY,
            )
        )
        assert "Recommended long-term action" not in section.body
        assert "Verification\n" not in section.body

    def test_no_mapping_says_so_and_recommends_nothing(self) -> None:
        section = _mitigation_section(
            MitigationMatch(
                category=ThreatCategory.PORT_SCAN, category_source="test"
            )
        )
        assert "No mapped mitigation recommendation available" in section.body
        for invented in ("Block", "block the", "immediately", "firewall rule to"):
            assert invented not in section.body, (
                f"{invented!r} appears in the no-mapping state, which means "
                "advice was composed where the knowledge base had none"
            )

    def test_the_mapping_is_shown_so_it_can_be_checked(self) -> None:
        entry = _entry("MIT-SCAN", ThreatCategory.PORT_SCAN)
        section = _mitigation_section(
            MitigationMatch(
                recommendation=entry, category=ThreatCategory.PORT_SCAN,
                category_source="Snort signature text", matched_on=MATCH_CATEGORY,
            )
        )
        joined = " ".join(value for _key, value in section.rows)
        assert "MIT-SCAN" in joined
        assert "PORT_SCAN" in joined
        assert "threat_mitigation_mapping" in joined

    def test_the_advisory_note_is_carried(self) -> None:
        """AETHRA-SEC recommends; it never acts (§90)."""
        section = _mitigation_section(
            MitigationMatch(
                recommendation=_entry("MIT-SCAN", ThreatCategory.PORT_SCAN),
                category=ThreatCategory.PORT_SCAN, matched_on=MATCH_CATEGORY,
            )
        )
        assert "recommends only" in section.body

    def test_a_missing_field_is_named_not_invented(self) -> None:
        assert _value("") == "Not available"
        assert _value(None) == "Not available"
        assert _value(0) == "0"
        assert _value("  ") == "Not available"

    def test_a_missing_rule_number_says_it_was_not_supplied(self) -> None:
        text = _rule_text(SnortAlert(generator_id=1, signature_id=None, revision=3))
        assert "SID not supplied" in text
        assert "GID 1" in text and "Rev 3" in text


class TestTheGuidanceFollowsTheDetection:
    def test_two_different_alerts_resolve_to_two_different_entries(self) -> None:
        repo = _Repo({
            ThreatCategory.TCP_SYN_FLOOD: [
                _entry("MIT-SYN", ThreatCategory.TCP_SYN_FLOOD)
            ],
            ThreatCategory.PORT_SCAN: [
                _entry("MIT-SCAN", ThreatCategory.PORT_SCAN)
            ],
        })
        service = _service(repo)
        syn = service.match_for_alert(
            SnortAlert(message="TCP SYN flood - possible DoS", severity=Severity.HIGH)
        )
        scan = service.match_for_alert(
            SnortAlert(message="ET SCAN Nmap portscan detected", severity=Severity.HIGH)
        )
        assert syn.recommendation is not None and scan.recommendation is not None
        assert syn.recommendation.code == "MIT-SYN"
        assert scan.recommendation.code == "MIT-SCAN"

    def test_the_rendered_sections_differ_too(self) -> None:
        """Guards against a panel that keeps the previous alert's advice."""
        repo = _Repo({
            ThreatCategory.TCP_SYN_FLOOD: [
                _entry("MIT-SYN", ThreatCategory.TCP_SYN_FLOOD)
            ],
            ThreatCategory.ICMP_FLOOD: [
                _entry("MIT-ICMP", ThreatCategory.ICMP_FLOOD)
            ],
        })
        service = _service(repo)
        first = _mitigation_section(
            service.match_for_alert(
                SnortAlert(message="TCP SYN flood", severity=Severity.HIGH)
            )
        )
        second = _mitigation_section(
            service.match_for_alert(
                SnortAlert(message="ICMP flood detected", severity=Severity.HIGH)
            )
        )
        assert first.body != second.body
        assert "MIT-SYN" not in second.body

    def test_an_anomaly_uses_its_own_recorded_category(self) -> None:
        """No keyword guessing: the rule already recorded the category."""
        repo = _Repo({
            ThreatCategory.HOST_SWEEP: [
                _entry("MIT-SWEEP", ThreatCategory.HOST_SWEEP)
            ]
        })
        anomaly = TrafficAnomaly(
            id=7, rule_id="RULE-HOST-SWEEP", category=ThreatCategory.HOST_SWEEP,
            severity=Severity.MEDIUM,
        )
        match = _service(repo).match_for_anomaly(anomaly)
        assert match.recommendation is not None
        assert match.recommendation.code == "MIT-SWEEP"
        assert "RULE-HOST-SWEEP" in match.category_source

    def test_the_status_line_states_the_real_outcome(self) -> None:
        repo = _Repo({
            ThreatCategory.PORT_SCAN: [_entry("MIT-SCAN", ThreatCategory.PORT_SCAN)]
        })
        resolved = _service(repo)._match(
            ThreatCategory.PORT_SCAN, category_source="t",
            severity=Severity.MEDIUM, service="",
        )
        assert "MIT-SCAN" in _detail_status(resolved)
        assert "could not be read" in _detail_status(
            MitigationMatch(lookup_failed=True)
        )
        assert "No mitigation entry is mapped" in _detail_status(
            MitigationMatch(category=ThreatCategory.PORT_SCAN)
        )
        assert "not available" in _detail_status(None)


# ---------------------------------------------------------------------------
# One detail view, reached three ways, that writes nothing
# ---------------------------------------------------------------------------
class TestOneSharedDetailView:
    def _source(self) -> str:
        return ALERTS.read_text(encoding="utf-8")

    def test_all_three_entry_points_call_the_same_method(self) -> None:
        source = self._source()
        assert 'act("Details", self._show_detail)' in source
        assert "on_activate=lambda _row: self._show_detail()" in source, (
            "double-click no longer opens the full alert view"
        )
        assert 'RowAction("View full alert", lambda _row: self._show_detail())' in (
            source
        ), "the right-click entry no longer opens the full alert view"

    def test_there_is_only_one_alert_detail_renderer(self) -> None:
        """A second implementation is how the two drift apart."""
        tree = ast.parse(self._source())
        renderers = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name.startswith("_render_")
            and node.name.endswith("_detail")
        ]
        assert sorted(renderers) == ["_render_alert_detail", "_render_anomaly_detail"]

    def test_both_renderers_use_the_same_mitigation_block(self) -> None:
        source = self._source()
        for name in ("_render_alert_detail", "_render_anomaly_detail"):
            body = _method_source(source, name)
            # The block is shared; it now also takes the detection whose
            # addresses fill the procedure placeholders.
            assert "_mitigation_section(match" in body, (
                f"{name} builds its own mitigation block"
            )

    def test_the_lookup_runs_off_the_tk_thread(self) -> None:
        body = _method_source(self._source(), "_open_detail")
        assert "run_async" in body, (
            "the mitigation lookup queries the database on the Tk thread, "
            "which freezes the window while the dialog opens"
        )

    def test_the_lookup_happens_once_per_opening(self) -> None:
        """Not once per field, and never on a timer while the dialog is open."""
        body = _method_source(self._source(), "_open_detail")
        assert body.count("run_async") == 1
        for renderer in ("_render_alert_detail", "_render_anomaly_detail"):
            rendered = _method_source(self._source(), renderer)
            assert "match_for_" not in rendered, (
                f"{renderer} performs its own lookup while rendering"
            )

    def test_opening_an_alert_changes_nothing(self) -> None:
        """Viewing is not triaging (§21 of the request)."""
        source = self._source()
        for name in ("_show_detail", "_open_detail", "_render_alert_detail"):
            body = _method_source(source, name)
            for write in ("set_status", "classify(", "set_alert_status",
                          "mark_anomaly_reviewed", "set_alert_evaluation"):
                assert write not in body, (
                    f"{name} writes to the detection ({write}); opening an "
                    "alert must not record a review"
                )

    def test_the_workflow_actions_are_still_wired(self) -> None:
        source = self._source()
        # Acknowledge, Escalate and Benign/expected were removed as unused
        # actions in a later change; the stored states they wrote are kept.
        for label in (
            "Mark reviewed", "True positive", "False positive", "Export",
        ):
            assert f'"{label}"' in source, f"the {label} action is gone"

    def test_the_view_in_mitigation_link_is_permission_gated(self) -> None:
        body = _method_source(self._source(), "_mitigation_actions")
        assert "MITIGATION_VIEW" in body, (
            "the link into the mitigation screen is offered without checking "
            "the operator may read the knowledge base"
        )
        assert "match.resolved" in body, (
            "the link is offered even when nothing resolved, so it would open "
            "the screen on no record"
        )

    def test_the_link_opens_an_existing_record_and_creates_nothing(self) -> None:
        body = _method_source(self._source(), "_mitigation_actions")
        # ast.unparse normalises quotes, so match on the call shape.
        assert "navigate('mitigation', focus_code=code)" in body
        for write in ("create(", "insert", "update("):
            assert write not in body

    def test_the_raw_evidence_is_kept(self) -> None:
        body = _method_source(self._source(), "_render_alert_detail")
        assert "alert.raw_alert" in body, (
            "the raw sensor text is no longer shown, so the original evidence "
            "is not reachable from the detail view"
        )
        assert "collapsed=True" in body


def _method_source(source: str, name: str) -> str:
    """The source of one method, so a test can look inside it."""
    tree = ast.parse(source)
    node = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == name),
        None,
    )
    assert node is not None, f"{name} not found"
    return ast.unparse(node)


# ---------------------------------------------------------------------------
# The mitigation screen accepts the link
# ---------------------------------------------------------------------------
class TestTheMitigationScreenAcceptsTheLink:
    def test_it_exposes_the_setter_navigate_will_call(self) -> None:
        from aethra_sec.ui.screens.mitigation import MitigationScreen

        assert callable(getattr(MitigationScreen, "set_focus_code", None)), (
            "navigate(..., focus_code=...) has no setter to call, so the "
            "link would open the screen on its first row instead"
        )

    def test_the_focus_clears_the_filters_that_could_hide_the_entry(self) -> None:
        from aethra_sec.ui.screens.mitigation import MitigationScreen

        body = inspect.getsource(MitigationScreen.set_focus_code)
        assert "_category_var" in body and "_active_only" in body

    def test_a_missing_code_falls_back_rather_than_showing_nothing(self) -> None:
        from aethra_sec.ui.screens.mitigation import MitigationScreen

        body = inspect.getsource(MitigationScreen._apply)
        assert "_select_focused()" in body
        assert "select_first()" in body, (
            "an entry that has since been removed would leave the table with "
            "nothing selected"
        )

    def test_the_eager_selection_survives_the_reload_that_follows(self) -> None:
        """The second visit to the screen used to land on the first row.

        navigate() calls the setter before on_show(), and on_show() always
        refreshes. When the screen was already loaded, set_focus_code selected
        the right entry at once and cleared the pending code - then the reload
        arrived, found nothing pending and selected the first row, so every
        link after the first opened MIT-DOS instead of the alert's own entry.
        """
        from aethra_sec.ui.screens.mitigation import MitigationScreen

        eager = inspect.getsource(MitigationScreen.set_focus_code)
        assert "consume=False" in eager, (
            "the eager selection consumes the pending code, so the refresh "
            "that follows navigation overwrites it"
        )
        applied = inspect.getsource(MitigationScreen._apply)
        assert "_select_focused()" in applied, (
            "the reload no longer re-applies the pending focus"
        )

    def test_the_table_can_select_a_row_by_predicate(self) -> None:
        from aethra_sec.ui.widgets import DataTable

        assert callable(getattr(DataTable, "select_where", None))


# ---------------------------------------------------------------------------
# Against the real seeded knowledge base
# ---------------------------------------------------------------------------
class TestAgainstTheSeededKnowledgeBase:
    """The shipped catalogue, through the real repository and mapping table."""

    @pytest.fixture()
    def service(self, db) -> MitigationService:  # noqa: ANN001
        from aethra_sec.database.repositories.audit import AuditRepository
        from aethra_sec.database.repositories.mitigation import MitigationRepository
        from aethra_sec.core.session import SessionManager
        from aethra_sec.security.audit import AuditService
        from aethra_sec.security.rbac import AccessControl

        audit = AuditService(AuditRepository(db))
        return MitigationService(
            MitigationRepository(db), audit, AccessControl(SessionManager(60), audit)
        )

    @pytest.mark.parametrize(
        ("message", "classification", "expected_code"),
        [
            ("TCP SYN flood - possible DoS", "Attempted Denial of Service",
             "MIT-TCP-SYN-FLOOD"),
            ("UDP flood - possible DoS", "Attempted Denial of Service",
             "MIT-UDP-FLOOD"),
            ("ICMP flood - possible ping flood/DoS", "Attempted Denial of Service",
             "MIT-ICMP-FLOOD"),
            ("ET SCAN Nmap portscan detected", "", "MIT-PORT-SCAN"),
            ("ICMP ping sweep detected", "", "MIT-HOST-SWEEP"),
            ("SQL Injection attempt detected", "", "MIT-SUSPICIOUS-PAYLOAD"),
            ("ICMP echo request", "Misc activity", "MIT-UNCLASSIFIED"),
        ],
    )
    def test_each_signature_resolves_to_its_own_entry(
        self, service: MitigationService, message: str,
        classification: str, expected_code: str,
    ) -> None:
        alert = SnortAlert(
            message=message, classification=classification, severity=Severity.HIGH
        )
        match = service.match_for_alert(alert)
        assert match.resolved, f"{message!r} resolved to nothing"
        assert match.recommendation is not None
        assert match.recommendation.code == expected_code

    def test_the_flood_signatures_no_longer_share_one_entry(
        self, service: MitigationService
    ) -> None:
        """The change this feature exists for, stated as a fact about the data."""
        codes = set()
        for message in (
            "TCP SYN flood - possible DoS",
            "UDP flood - possible DoS",
            "ICMP flood - possible ping flood/DoS",
        ):
            match = service.match_for_alert(
                SnortAlert(message=message, severity=Severity.HIGH)
            )
            assert match.recommendation is not None
            codes.add(match.recommendation.code)
        assert len(codes) == 3, (
            f"three different floods share {codes}; each has its own entry in "
            "the shipped catalogue"
        )

    @pytest.mark.parametrize(
        ("rule", "category", "expected_code"),
        [
            ("RULE-HOST-SWEEP", ThreatCategory.HOST_SWEEP, "MIT-HOST-SWEEP"),
            ("RULE-PORT-SCAN", ThreatCategory.PORT_SCAN, "MIT-PORT-SCAN"),
            ("RULE-UDP-RATE", ThreatCategory.UDP_FLOOD, "MIT-UDP-FLOOD"),
            ("RULE-ICMP-RATE", ThreatCategory.ICMP_FLOOD, "MIT-ICMP-FLOOD"),
            ("RULE-TCP-SYN-RATE", ThreatCategory.TCP_SYN_FLOOD,
             "MIT-TCP-SYN-FLOOD"),
        ],
    )
    def test_each_detection_rule_resolves_to_its_own_entry(
        self, service: MitigationService, rule: str,
        category: ThreatCategory, expected_code: str,
    ) -> None:
        anomaly = TrafficAnomaly(
            id=1, rule_id=rule, category=category, severity=Severity.MEDIUM
        )
        match = service.match_for_anomaly(anomaly)
        assert match.resolved, f"{rule} resolved to nothing"
        assert match.recommendation is not None
        assert match.recommendation.code == expected_code

    def test_an_http_flood_on_an_ephemeral_port_still_resolves(
        self, service: MitigationService
    ) -> None:
        """Its only mapped entry is service-specific; the mapping still applies."""
        anomaly = TrafficAnomaly(
            id=1, rule_id="RULE-HTTP-RATE", category=ThreatCategory.HTTP_FLOOD,
            severity=Severity.MEDIUM, protocol="TCP", dst_port=51753,
        )
        match = service.match_for_anomaly(anomaly)
        assert match.resolved
        assert match.recommendation is not None
        assert match.recommendation.code == "MIT-HTTP-FLOOD"
        assert match.matched_on == MATCH_MAPPING
        assert match.observed_service == ""
        joined = " ".join(match.mapping_lines())
        assert "was not verified" in joined, (
            "the service condition is presented as though the traffic "
            "confirmed it"
        )

    def test_the_guidance_is_the_stored_text(
        self, service: MitigationService, db
    ) -> None:  # noqa: ANN001
        """Byte for byte what the knowledge base holds - nothing rewritten."""
        match = service.match_for_alert(
            SnortAlert(message="TCP SYN flood", severity=Severity.HIGH)
        )
        assert match.recommendation is not None
        stored = db.query_one(
            "SELECT explanation, immediate_action FROM mitigation_recommendations "
            "WHERE code = %s",
            (match.recommendation.code,),
        )
        assert match.recommendation.explanation == stored["explanation"]
        section = _mitigation_section(match)
        assert stored["explanation"] in section.body
        assert stored["immediate_action"] in section.body

    def test_every_seeded_category_resolves(
        self, service: MitigationService, db
    ) -> None:  # noqa: ANN001
        """No mapped category is left with nothing to show."""
        categories = [
            row["category"]
            for row in db.query(
                "SELECT DISTINCT category FROM threat_mitigation_mapping "
                "WHERE is_active = 1"
            )
        ]
        assert categories, "the mapping table is empty"
        unresolved = []
        for name in categories:
            category = ThreatCategory.parse(name, ThreatCategory.UNCLASSIFIED)
            match = service._match(
                category, category_source="test",
                severity=Severity.MEDIUM, service="",
            )
            if not match.resolved:
                unresolved.append(name)
        assert not unresolved, f"mapped but unresolvable: {unresolved}"

    def test_the_lookup_is_cached_rather_than_repeated(
        self, service: MitigationService
    ) -> None:
        """§22: the panel must not re-query while it is open."""
        alert = SnortAlert(message="TCP SYN flood", severity=Severity.HIGH)
        first = service.match_for_alert(alert)
        service._repository = _BrokenRepo()  # type: ignore[assignment]
        second = service.match_for_alert(alert)
        assert second.resolved, "the second lookup went back to the database"
        assert first.recommendation is not None
        assert second.recommendation is not None
        assert second.recommendation.code == first.recommendation.code


# ---------------------------------------------------------------------------
# The dialog itself
# ---------------------------------------------------------------------------
class TestTheDialogRendersTheSections:
    """Built for real, against a live Tk interpreter."""

    @pytest.fixture()
    def dialog_for(self, tk_root):  # noqa: ANN001, ANN201
        from aethra_sec.ui.theme import apply_theme
        from aethra_sec.ui.widgets import DetailDialog

        fonts = apply_theme(tk_root)
        built: list[object] = []

        def build(**kwargs):  # noqa: ANN003, ANN202
            dialog = DetailDialog(tk_root, "Alert", rows=[], fonts=fonts, **kwargs)
            # Never shown modally: show() would block the test run.
            dialog.withdraw()
            built.append(dialog)
            return dialog

        yield build
        for dialog in built:
            try:
                dialog.destroy()
            except Exception:  # noqa: BLE001 - already torn down
                pass

    def _text(self, dialog) -> str:  # noqa: ANN001
        return dialog._text.get("1.0", "end")

    def test_the_mitigation_block_is_rendered(self, dialog_for) -> None:  # noqa: ANN001
        section = _mitigation_section(
            MitigationMatch(
                recommendation=_entry("MIT-SCAN", ThreatCategory.PORT_SCAN),
                category=ThreatCategory.PORT_SCAN, matched_on=MATCH_CATEGORY,
            )
        )
        text = self._text(dialog_for(sections=[section]))
        assert "MITIGATION RECOMMENDATION" in text
        assert "MIT-SCAN" in text
        assert "MIT-SCAN immediate" in text

    def test_a_plain_tuple_section_still_works(self, dialog_for) -> None:  # noqa: ANN001
        """Every other screen passes tuples; they must keep rendering."""
        text = self._text(dialog_for(sections=[("HEADING", "body text")]))
        assert "HEADING" in text and "body text" in text

    def test_a_collapsed_section_keeps_its_evidence_in_the_widget(
        self, dialog_for
    ) -> None:  # noqa: ANN001
        from aethra_sec.ui.widgets import DetailSection

        raw = "[**] [1:1000007:1] TCP SYN flood [**]"
        dialog = dialog_for(
            sections=[DetailSection("RAW ALERT", body=raw, collapsed=True)]
        )
        assert dialog.is_collapsed(0)
        assert raw in self._text(dialog), (
            "the raw evidence was withheld rather than hidden, so a copy of "
            "the dialog would not carry it"
        )

    def test_the_toggle_reveals_and_hides(self, dialog_for) -> None:  # noqa: ANN001
        from aethra_sec.ui.widgets import DetailSection

        dialog = dialog_for(
            sections=[DetailSection("RAW ALERT", body="raw text", collapsed=True)]
        )
        assert dialog.is_collapsed(0)
        dialog.toggle_section(0)
        assert not dialog.is_collapsed(0)
        assert dialog._text.tag_cget("collapsed0", "elide") in ("0", "false", "")
        dialog.toggle_section(0)
        assert dialog.is_collapsed(0)

    def test_an_action_button_is_added(self, dialog_for) -> None:  # noqa: ANN001
        clicked: list[str] = []
        dialog = dialog_for(
            sections=[("H", "b")],
            actions=[("View in Mitigation", lambda: clicked.append("yes"))],
        )
        labels = [
            child.cget("text")
            for child in dialog.buttons.winfo_children()
            if "text" in child.keys()
        ]
        assert "View in Mitigation" in labels
        assert "Close" in labels

    def test_the_sections_appear_in_order(self, dialog_for) -> None:  # noqa: ANN001
        from aethra_sec.ui.widgets import DetailSection

        text = self._text(dialog_for(sections=[
            DetailSection("ALERT INFORMATION", rows=[("Alert ID", "254")]),
            DetailSection("NETWORK DETAILS", rows=[("Protocol", "TCP")]),
            DetailSection("MITIGATION RECOMMENDATION", body="guidance"),
        ]))
        assert (
            text.index("ALERT INFORMATION")
            < text.index("NETWORK DETAILS")
            < text.index("MITIGATION RECOMMENDATION")
        )
        assert "Alert ID: 254" in text
