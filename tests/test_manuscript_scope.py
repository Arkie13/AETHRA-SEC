"""The implemented scope must equal the study's scope (§115).

The manuscript defines five simulated attack scenarios - port scanning, TCP SYN
flooding, UDP flooding, ICMP flooding and HTTP flooding - each executed
repeatedly in a controlled and isolated laboratory LAN. The application had
grown categories beyond that, and two of them, brute force and malware, were
not scenarios at all: they were keyword buckets that read the *text* of an
incoming Snort signature and attributed it to a category AETHRA-SEC has no
detection rule for.

Three rules are pinned here, and they pull in different directions on purpose.

**Nothing may claim to be a tested scenario that is not one.** The five are
defined once, in :mod:`aethra_sec.models.scope`, and no other module may
redefine them.

**Nothing out of scope may reach an operator as a finding.** A retired category
must not be selectable in a filter, seeded into the mitigation catalogue,
produced by a detection rule, or attached to an incident as guidance.

**No real observation may be deleted to achieve either of the above.** A host
sweep the sensors genuinely saw is evidence. It is kept, and labelled as an
event outside the tested scenarios rather than counted as one of them.
Falsifying the record to match a chapter heading is not scoping.

Severity is deliberately untouched. The manuscript defines no severity model,
so inventing thresholds - or collapsing the existing ones - would replace an
undocumented model with a freshly invented one. What is asserted instead is
that the system never presents severity as something the study defined.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.analytics.anomaly_rules import RULE_DEFINITIONS
from aethra_sec.database import seed
from aethra_sec.models.enums import Severity, ThreatCategory
from aethra_sec.models.scope import (
    PRIMARY_SCENARIOS,
    SCENARIO_NAMES,
    CategoryScope,
    is_primary,
    scenario_name,
    scope_of,
)
from aethra_sec.models.severity_source import (
    SEVERITY_DISCLOSURE,
    SeveritySource,
)
from aethra_sec.services.correlation_service import (
    _CATEGORY_KEYWORDS,
    categorise_alert,
)

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"

#: The categories retired because the manuscript does not test them.
RETIRED = ("BRUTE_FORCE", "MALWARE_INDICATOR")
RETIRED_MITIGATIONS = ("MIT-BRUTE-FORCE", "MIT-MALWARE-INDICATOR")


def _python_sources() -> list[Path]:
    """Every application module, tests excluded."""
    return [p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts]


def _statements(path: Path) -> str:
    """Source with docstrings removed, so prose is not mistaken for code."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


# ---------------------------------------------------------------------------
# The five scenarios
# ---------------------------------------------------------------------------
class TestOnlyManuscriptSupportedDetectionCategories:
    """test_only_manuscript_supported_detection_categories()."""

    def test_the_five_tested_scenarios(self) -> None:
        """Exactly the five the study defines, and nothing else."""
        assert PRIMARY_SCENARIOS == (
            ThreatCategory.PORT_SCAN,
            ThreatCategory.TCP_SYN_FLOOD,
            ThreatCategory.UDP_FLOOD,
            ThreatCategory.ICMP_FLOOD,
            ThreatCategory.HTTP_FLOOD,
        )

    def test_each_scenario_is_named_in_the_studys_own_words(self) -> None:
        """A report should read in the study's terms, not an identifier."""
        assert set(SCENARIO_NAMES) == set(PRIMARY_SCENARIOS)
        assert scenario_name(ThreatCategory.PORT_SCAN) == "Port Scanning"
        assert scenario_name(ThreatCategory.TCP_SYN_FLOOD) == "TCP SYN Flooding"

    def test_the_scope_is_defined_in_exactly_one_place(self) -> None:
        """A second list would drift from the first."""
        defining = [
            path for path in _python_sources()
            if "PRIMARY_SCENARIOS: tuple" in path.read_text(encoding="utf-8")
        ]
        assert [p.name for p in defining] == ["scope.py"]

    def test_an_event_outside_the_five_is_not_promoted_to_one(self) -> None:
        """Host sweep is real and is kept - as another detected event."""
        assert not is_primary(ThreatCategory.HOST_SWEEP)
        assert scope_of(ThreatCategory.HOST_SWEEP) is CategoryScope.OTHER_DETECTED
        assert ThreatCategory.HOST_SWEEP in list(ThreatCategory)

    def test_every_scenario_has_a_detection_rule(self) -> None:
        """A scenario the engine cannot detect would be untestable."""
        detected = {rule.category for rule in RULE_DEFINITIONS}
        missing = [c for c in PRIMARY_SCENARIOS if c not in detected]
        assert not missing, f"no detection rule for {missing}"

    def test_every_detection_rule_maps_to_a_real_category(self) -> None:
        for rule in RULE_DEFINITIONS:
            assert isinstance(rule.category, ThreatCategory)
            assert scope_of(rule.category) is not CategoryScope.UNCLASSIFIED


class TestNoBruteForceMitigation:
    """test_no_brute_force_mitigation()."""

    def test_the_category_is_gone_from_the_model(self) -> None:
        assert not hasattr(ThreatCategory, "BRUTE_FORCE")
        assert "BRUTE_FORCE" not in {c.value for c in ThreatCategory}

    def test_the_seed_catalogue_does_not_carry_it(self) -> None:
        codes = {entry["code"] for entry in seed._MITIGATIONS}
        assert "MIT-BRUTE-FORCE" not in codes

    def test_no_snort_signature_can_be_classified_as_brute_force(self) -> None:
        """The keyword bucket that produced it is gone."""
        categories = {str(category) for category, _kw in _CATEGORY_KEYWORDS}
        assert "BRUTE_FORCE" not in categories

    def test_a_credential_signature_is_not_given_a_category(self) -> None:
        from aethra_sec.models.alert import SnortAlert

        alert = SnortAlert(
            message="ET SCAN Potential SSH brute force login attempt",
            severity=Severity.MEDIUM,
        )
        assert categorise_alert(alert) is ThreatCategory.UNCLASSIFIED


class TestNoMalwareIndicatorMitigation:
    """test_no_malware_indicator_mitigation()."""

    def test_the_category_is_gone_from_the_model(self) -> None:
        assert not hasattr(ThreatCategory, "MALWARE_INDICATOR")
        assert "MALWARE_INDICATOR" not in {c.value for c in ThreatCategory}

    def test_the_seed_catalogue_does_not_carry_it(self) -> None:
        codes = {entry["code"] for entry in seed._MITIGATIONS}
        assert "MIT-MALWARE-INDICATOR" not in codes

    def test_no_snort_signature_can_be_classified_as_malware(self) -> None:
        categories = {str(category) for category, _kw in _CATEGORY_KEYWORDS}
        assert "MALWARE_INDICATOR" not in categories

    def test_a_trojan_signature_is_not_given_a_category(self) -> None:
        from aethra_sec.models.alert import SnortAlert

        for message in (
            "ET TROJAN Command and Control activity",
            "ET MALWARE Ransomware beacon observed",
            "Botnet CnC channel detected",
        ):
            alert = SnortAlert(message=message, severity=Severity.MEDIUM)
            assert categorise_alert(alert) is ThreatCategory.UNCLASSIFIED


class TestTheRetiredCategoriesAreGoneEverywhere:
    """Not hidden - absent from the application source."""

    @pytest.mark.parametrize("name", RETIRED)
    def test_no_module_references_the_category(self, name: str) -> None:
        """The migration names them, because it is what retires them."""
        offenders = [
            path.relative_to(ROOT).as_posix()
            for path in _python_sources()
            if name in _statements(path)
            and path.name != "migrations.py"
        ]
        assert not offenders, f"{name} still referenced by {offenders}"

    @pytest.mark.parametrize("code", RETIRED_MITIGATIONS)
    def test_no_module_seeds_the_mitigation(self, code: str) -> None:
        offenders = [
            path.relative_to(ROOT).as_posix()
            for path in _python_sources()
            if code in _statements(path) and path.name != "migrations.py"
        ]
        assert not offenders, f"{code} still referenced by {offenders}"

    def test_the_schema_export_does_not_seed_them(self) -> None:
        """The export is what a fresh installation is built from."""
        exported = (ROOT / "sql" / "aethra_sec_schema.sql").read_text(
            encoding="utf-8"
        )
        for code in RETIRED_MITIGATIONS:
            assert code not in exported
        for name in RETIRED:
            assert name not in exported


class TestNoUnsupportedFiltersOrDropdowns:
    """test_no_unsupported_ids_filters()."""

    @pytest.mark.parametrize(
        "screen", ["mitigation.py", "alerts.py"]
    )
    def test_category_controls_are_generated_from_the_model(
        self, screen: str
    ) -> None:
        """So retiring a category removes it from the control automatically.

        A hand-written list is how a filter keeps offering something the
        backend no longer produces.
        """
        code = _statements(PACKAGE / "ui" / "screens" / screen)
        for name in RETIRED:
            assert name not in code
        for code_name in RETIRED_MITIGATIONS:
            assert code_name not in code

    def test_the_category_filters_read_the_enum(self) -> None:
        for screen in ("mitigation.py",):
            code = _statements(PACKAGE / "ui" / "screens" / screen)
            assert "for c in ThreatCategory" in code, (
                f"{screen} hard-codes its category list"
            )


class TestMitigationScopeConsistency:
    """test_mitigation_scope_consistency()."""

    def test_every_seeded_mitigation_has_a_live_category(self) -> None:
        """Guidance for a category nothing can produce is unreachable."""
        for entry in seed._MITIGATIONS:
            assert isinstance(entry["category"], ThreatCategory), (
                f"{entry['code']} names a category the model no longer has"
            )

    def test_every_tested_scenario_has_guidance(self) -> None:
        """A detection with no recommendation leaves an operator stuck."""
        covered = {entry["category"] for entry in seed._MITIGATIONS}
        missing = [c for c in PRIMARY_SCENARIOS if c not in covered]
        assert not missing, f"no mitigation guidance for {missing}"

    def test_mitigation_stays_advisory(self) -> None:
        """The study describes recommendation only, never auto-containment."""
        code = _statements(PACKAGE / "services" / "mitigation_service.py")
        for forbidden in (
            "subprocess", "iptables", "netsh", "firewall-cmd", "os.system",
        ):
            assert forbidden not in code, (
                f"the mitigation service references {forbidden}; guidance must "
                "never reconfigure anything"
            )


class TestDetectionToIncidentScopeConsistency:
    """test_detection_to_incident_scope_consistency()."""

    def test_an_incident_category_is_always_a_live_category(self) -> None:
        code = _statements(PACKAGE / "services" / "correlation_service.py")
        for name in RETIRED:
            assert name not in code

    def test_every_keyword_group_names_a_live_category(self) -> None:
        for category, keywords in _CATEGORY_KEYWORDS:
            assert isinstance(category, ThreatCategory)
            assert keywords, f"{category} has no keywords and can never match"

    def test_a_vendor_rule_prefix_is_not_treated_as_evidence(self) -> None:
        """"ET SCAN" names a rule family, not the traffic it matched."""
        for _category, keywords in _CATEGORY_KEYWORDS:
            assert "scan" not in keywords, (
                "a bare 'scan' keyword matches every Emerging Threats rule "
                "named 'ET SCAN ...', whatever the traffic actually was"
            )


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
class TestOnlyManuscriptSupportedSeverities:
    """test_only_manuscript_supported_severities().

    Revision 9 of the manuscript defines severity for floods only (§3.9.8 rate
    bands). The assertion is that exactly that source - and nothing else - is
    presented as coming from the study.
    """

    def test_only_the_flood_band_is_presented_as_study_defined(self) -> None:
        defined = [s for s in SeveritySource if s.is_manuscript_defined]
        assert defined == [SeveritySource.MANUSCRIPT_FLOOD_BAND]

    def test_the_flood_bands_diverge_from_section_3_9_8_deliberately(self) -> None:
        """The operative bands are NOT §3.9.8 as written, and that is intended.

        §3.9.8 of manuscript revision 9 reads "Low 100-500, Medium 501-1,000,
        High above 1,000". The application now classifies a measured 500 pps
        as MEDIUM, a measured 1,000 pps as HIGH, and has no lower floor on
        Low. This test pins the three points of divergence so they stay
        deliberate: if §3.9.8 is later rewritten to match the application,
        this test is the place that records it was the manuscript that moved.
        """
        from aethra_sec.analytics.anomaly_rules import flood_severity

        # Divergence 1: the Medium floor is inclusive, so 500 is MEDIUM.
        assert flood_severity(499)[0] is Severity.LOW
        assert flood_severity(500)[0] is Severity.MEDIUM

        # Divergence 2: the High floor is inclusive, so 1,000 is HIGH.
        assert flood_severity(999)[0] is Severity.MEDIUM
        assert flood_severity(1000)[0] is Severity.HIGH

        # Divergence 3: Low is open at the bottom, so a detection under the
        # old 100 pps floor is simply Low and no longer says it fell beneath
        # a band. The HTTP flood threshold of 10 req/s reaches this.
        severity, band = flood_severity(40)
        assert severity is Severity.LOW
        assert "below" not in band.lower()

        # Unchanged from §3.9.8.
        assert flood_severity(750)[0] is Severity.MEDIUM
        assert flood_severity(1001)[0] is Severity.HIGH

    def test_the_default_thresholds_are_the_manuscripts(self) -> None:
        from aethra_sec.analytics.anomaly_rules import (
            MANUSCRIPT_THRESHOLDS,
            DetectionThresholds,
        )
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY

        defaults = DetectionThresholds()
        assert defaults.syn_per_second == 200
        assert defaults.udp_per_second == 300
        assert defaults.icmp_per_second == 120
        assert defaults.http_per_second * 60 == 600
        for key, value in MANUSCRIPT_THRESHOLDS.items():
            assert SETTING_SPEC_BY_KEY[key].default == value

    def test_every_source_states_its_provenance(self) -> None:
        for source in SeveritySource:
            assert source.provenance.strip()
            assert source.label.strip()

    def test_snort_severity_stays_traceable_to_snort(self) -> None:
        """Its priority is mapped, not reweighted."""
        from aethra_sec.analytics.risk_engine import RiskEngine

        source = inspect.getsource(RiskEngine.severity_for_snort_priority)
        assert "priority" in source
        assert "None" in source, (
            "a missing priority must be recorded as absent, not guessed"
        )

    def test_the_bands_were_not_silently_re_banded(self) -> None:
        """Collapsing them would reclassify stored events by arithmetic."""
        assert [str(s) for s in Severity] == [
            "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL",
        ]

    def test_reports_disclose_where_severity_came_from(self) -> None:
        code = _statements(PACKAGE / "reports" / "builder.py")
        assert "SEVERITY_DISCLOSURE" in code
        assert "not defined by the study" in SEVERITY_DISCLOSURE


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
class TestRealObservationsSurviveTheScopeCorrection:
    """No observation is deleted to make the interface match the study."""

    def test_the_migration_refuses_to_delete_referenced_guidance(self) -> None:
        code = _statements(PACKAGE / "database" / "migrations.py")
        action = code[code.index("def _apply_scope_alignment"):]
        action = action[: action.index("\nMIGRATIONS")]
        assert "mitigation_id" in action, (
            "the migration deletes guidance without checking whether an "
            "incident depends on it"
        )
        assert "created_by" in action and "updated_by" in action, (
            "the migration cannot tell seed data from an administrator's work"
        )
        assert "traffic_anomalies" in action, (
            "the migration does not check whether observations carry the "
            "category before retiring its guidance"
        )

    def test_the_migration_deletes_nothing_else(self) -> None:
        code = _statements(PACKAGE / "database" / "migrations.py")
        action = code[code.index("def _apply_scope_alignment"):]
        action = action[: action.index("\nMIGRATIONS")]
        assert action.count("DELETE FROM") == 1
        assert "mitigation_recommendations" in action
        for table in (
            "snort_alerts", "traffic_records", "incidents ", "audit_logs",
            "scan_findings", "hosts",
        ):
            assert f"DELETE FROM {table}" not in action

    def test_out_of_scope_evidence_is_still_stored_in_full(self) -> None:
        """An alert naming a retired threat keeps its message and addresses."""
        from aethra_sec.models.alert import SnortAlert

        alert = SnortAlert(
            message="ET TROJAN Command and Control activity",
            severity=Severity.HIGH, src_ip="192.168.1.50",
            dst_ip="192.168.1.25", dst_port=443,
        )
        # Categorisation declines to guess; the record itself is untouched.
        assert categorise_alert(alert) is ThreatCategory.UNCLASSIFIED
        assert alert.message == "ET TROJAN Command and Control activity"
        assert alert.src_ip == "192.168.1.50"


class TestNoFabricatedData:
    """The scope correction must not become a licence to invent."""

    def test_nothing_seeds_a_detection_record(self) -> None:
        code = _statements(PACKAGE / "database" / "seed.py")
        for table in ("snort_alerts", "traffic_anomalies", "incidents"):
            assert f"INSERT INTO {table}" not in code

    def test_the_scope_module_reads_no_database(self) -> None:
        """A scope decision is a fact about the study, not about the data."""
        code = _statements(PACKAGE / "models" / "scope.py")
        for forbidden in ("SELECT", "db.", "Repository"):
            assert forbidden not in code

    def test_an_unknown_category_is_not_guessed_into_the_five(self) -> None:
        assert scope_of("SOMETHING_RETIRED") is CategoryScope.UNCLASSIFIED
        assert scope_of(None) is CategoryScope.UNCLASSIFIED
        assert not is_primary("SOMETHING_RETIRED")


# ---------------------------------------------------------------------------
# Counts
# ---------------------------------------------------------------------------
class TestNoUnsupportedDashboardCounts:
    """test_no_unsupported_dashboard_counts()."""

    def test_the_dashboard_counts_only_live_categories(self) -> None:
        code = _statements(PACKAGE / "services" / "dashboard_service.py")
        for name in RETIRED:
            assert name not in code

    def test_the_dashboard_and_the_ids_screen_share_one_query(self) -> None:
        """Different queries are how the two came to disagree."""
        dashboard = _statements(PACKAGE / "services" / "dashboard_service.py")
        assert "count_detections_by_severity" in dashboard
        repo = _statements(
            PACKAGE / "database" / "repositories" / "alerts.py"
        )
        assert "def detection_totals" in repo
        for method in ("_alert_filter", "_anomaly_filter"):
            assert repo.count(f"def {method}") == 1, (
                f"{method} is defined more than once, so the rows and the "
                "counts can be selected by different predicates"
            )

    def test_the_summary_is_counted_where_the_records_are(self) -> None:
        """Not from the page of rows that reached the screen."""
        screen = _statements(PACKAGE / "ui" / "screens" / "alerts.py")
        assert "detection_totals(" in screen
        assert "def _detection_counts" not in screen


class TestNoUnsupportedReportCategories:
    """test_no_unsupported_report_categories()."""

    def test_reports_never_name_a_retired_category(self) -> None:
        code = _statements(PACKAGE / "reports" / "builder.py")
        for name in RETIRED:
            assert name not in code

    def test_reports_separate_tested_scenarios_from_other_events(self) -> None:
        code = _statements(PACKAGE / "reports" / "builder.py")
        assert "PRIMARY_SCENARIOS" in code
        assert "scenario_name" in code

    def test_the_scope_section_states_both_totals(self) -> None:
        from aethra_sec.reports.builder import ReportBuilder

        source = inspect.getsource(ReportBuilder._scope_section)
        assert "tested" in source and "other" in source


# ---------------------------------------------------------------------------
# Application security controls are not detection categories
# ---------------------------------------------------------------------------
class TestAuthenticationControlsSurvive:
    """Removing a *detection* category must not weaken the application.

    Brute force is not one of the study's network attack scenarios. That says
    nothing about whether the console itself should resist credential guessing,
    and the two were explicitly not to be confused.
    """

    def test_account_lockout_still_exists(self) -> None:
        from aethra_sec.security.authentication import AuthenticationPolicy

        policy = AuthenticationPolicy()
        assert policy.max_failed_logins >= 1
        assert policy.lockout_minutes >= 1

    def test_the_lockout_is_still_enforced_on_sign_in(self) -> None:
        from aethra_sec.security.authentication import AuthenticationService

        assert hasattr(AuthenticationService, "_is_locked")
        source = inspect.getsource(AuthenticationService.login)
        assert "_is_locked" in source, (
            "sign-in no longer consults the lockout state"
        )

    def test_a_failed_sign_in_is_still_counted(self) -> None:
        from aethra_sec.security.authentication import AuthenticationService

        source = inspect.getsource(AuthenticationService.login)
        assert "_record_failure" in source

    def test_password_hashing_is_still_in_place(self) -> None:
        from aethra_sec.security.password import PasswordHashService

        hashed = PasswordHashService(prefer_argon2=False).hash("CorrectHorse!42")
        assert hashed.hash and hashed.hash != "CorrectHorse!42"

    def test_the_sign_in_throttle_is_still_an_application_control(self) -> None:
        """Bounding password guessing survives; it is not a detection category.

        This replaced a pair of second-factor tests. The second factor is gone,
        so the control that bounds guessing is the progressive lockout, and it
        is the one that must not quietly disappear with it.
        """
        from aethra_sec.security import lockout

        assert lockout.FAILURES_BEFORE_LOCK == 3
        assert lockout.BACKOFF_SECONDS[0] == 30
        assert hasattr(lockout, "evaluate")

    def test_email_is_a_notification_channel_and_not_a_sign_in_step(self) -> None:
        """The removal is structural, not merely disabled by configuration."""
        import inspect as _inspect

        from aethra_sec.security.authentication import AuthenticationService

        source = _inspect.getsource(AuthenticationService)
        for absent in ("smtp", "otp", "verification code"):
            assert absent not in source.lower(), absent

    def test_nmap_still_refuses_intrusive_script_categories(self) -> None:
        """A safety control, unrelated to the detection taxonomy."""
        from aethra_sec.integrations.nmap import profiles

        source = inspect.getsource(profiles)
        for blocked in ("brute", "exploit", "dos", "intrusive", "malware"):
            assert blocked in source, (
                f"'{blocked}' is no longer refused as an Nmap script category"
            )
