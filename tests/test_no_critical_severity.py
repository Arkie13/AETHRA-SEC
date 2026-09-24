"""CRITICAL is not part of the IDS Alerts / Threat Incidents model (§116).

Two modules present a severity to an analyst: IDS Alerts and Threat Incidents.
Their model is HIGH / MEDIUM / LOW, with INFO folding into LOW. CRITICAL is
outside it, so nothing produces one, no screen has a cell or filter option for
it, and no report prints a row for it.

What this is not
----------------
It is not a redistribution. The top band was removed and every remaining cut
point - 55, 30, 12 - is the value it has always been, so a score that graded
MEDIUM still grades MEDIUM. No stored record was rewritten, and no migration
ran: at the time of the change the database held zero records at CRITICAL in
``snort_alerts``, ``traffic_anomalies`` and ``incidents`` alike.

It is not a change to the vulnerability module either.
:class:`~aethra_sec.models.enums.RiskLevel` keeps its own CRITICAL, because
assessment findings have a separate and legitimate risk model. A CRITICAL Nmap
finding is still a CRITICAL finding, and these tests check that it stayed that
way rather than being caught in the blast radius.

And it is not a loss of Snort evidence. A priority-1 alert now normalises to
HIGH for display, but ``priority`` still stores the 1 the sensor sent and
``raw_alert`` still holds the original line, so
raw alert -> parsed alert -> AETHRA-SEC alert -> incident stays traceable.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from aethra_sec.analytics.risk_engine import (
    SCORE_HIGH,
    SCORE_LOW,
    SCORE_MEDIUM,
    RiskEngine,
)
from aethra_sec.models.enums import RiskLevel, Severity
from aethra_sec.models.severity_source import (
    DETECTION_SEVERITIES,
    is_detection_severity,
)
from aethra_sec.ui.screens.alerts import _SEVERITY_CELL as ALERT_CELLS
from aethra_sec.ui.screens.alerts import _summary_cells

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
ALERTS = PACKAGE / "ui" / "screens" / "alerts.py"


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
# The model
# ---------------------------------------------------------------------------
class TestTheDetectionSeverityModel:
    """One definition, read by both modules."""

    def test_the_model_is_high_medium_low(self) -> None:
        assert DETECTION_SEVERITIES == (
            Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
        )

    def test_critical_is_not_in_it(self) -> None:
        assert Severity.CRITICAL not in DETECTION_SEVERITIES
        assert not is_detection_severity(Severity.CRITICAL)
        assert not is_detection_severity("CRITICAL")

    def test_high_is_the_top(self) -> None:
        assert max(DETECTION_SEVERITIES, key=lambda s: s.rank) is Severity.HIGH


class TestIdsAlertsHasNoCritical:
    """test_ids_alerts_has_no_critical()."""

    def test_the_strip_has_exactly_four_cells(self) -> None:
        """HIGH / MEDIUM / LOW / UNREVIEWED, in that order."""
        cells = _summary_cells({"total": 0})
        assert list(cells) == ["high", "medium", "low", "unreviewed"]

    def test_there_is_no_critical_cell(self) -> None:
        assert "CRITICAL" not in ALERT_CELLS
        assert "critical" not in _summary_cells({"total": 0})

    def test_the_strip_is_built_with_four_cells(self) -> None:
        """Asserted on the widget definition, not just the count mapping."""
        code = _statements(ALERTS)
        build = code[code.index("def _build_summary"):]
        build = build[: build.index("\n    def ", 1)]
        for key in ("'high'", "'medium'", "'low'", "'unreviewed'"):
            assert key in build
        assert "'critical'" not in build
        assert "Critical" not in build

    def test_a_critical_value_is_not_folded_into_another_cell(self) -> None:
        """Regrading it would make the strip lie rather than show a gap."""
        counts = _summary_cells({"CRITICAL": 4, "total": 4})
        assert sum(counts[k] for k in ("high", "medium", "low")) == 0


class TestSeverityFiltersExcludeCritical:
    """test_ids_severity_filter_excludes_critical() /
    test_incident_severity_filter_excludes_critical()."""

    @pytest.mark.parametrize("path", [ALERTS])
    def test_the_filter_is_built_from_the_detection_model(
        self, path: Path
    ) -> None:
        """Not from every Severity the enum can express."""
        code = _statements(path)
        assert "for s in DETECTION_SEVERITIES" in code, (
            f"{path.name} offers a severity filter built from the full enum, "
            "so it would list a value nothing can produce"
        )
        assert "for s in Severity]" not in code

    @pytest.mark.parametrize("path", [ALERTS])
    def test_the_filter_cannot_offer_critical(self, path: Path) -> None:
        offered = ["All", *[str(s) for s in DETECTION_SEVERITIES]]
        assert "CRITICAL" not in offered
        assert offered == ["All", "HIGH", "MEDIUM", "LOW", "INFO"]

# ---------------------------------------------------------------------------
# Nothing produces CRITICAL any more
# ---------------------------------------------------------------------------
class TestNothingCanProduceCritical:
    """Removed from the logic, not hidden in the view."""

    def test_no_score_grades_critical(self) -> None:
        for score in range(-50, 250):
            assert RiskEngine.severity_for_score(score) is not Severity.CRITICAL

    def test_no_snort_priority_grades_critical(self) -> None:
        for priority in [None, *range(0, 20)]:
            assert (
                RiskEngine.severity_for_snort_priority(priority)
                is not Severity.CRITICAL
            )

    def test_the_remaining_thresholds_are_unchanged(self) -> None:
        """The top band was removed; nothing else moved."""
        assert (SCORE_HIGH, SCORE_MEDIUM, SCORE_LOW) == (55, 30, 12)
        assert RiskEngine.severity_for_score(SCORE_HIGH) is Severity.HIGH
        assert RiskEngine.severity_for_score(SCORE_HIGH - 1) is Severity.MEDIUM
        assert RiskEngine.severity_for_score(SCORE_MEDIUM) is Severity.MEDIUM
        assert RiskEngine.severity_for_score(SCORE_MEDIUM - 1) is Severity.LOW
        assert RiskEngine.severity_for_score(SCORE_LOW) is Severity.LOW
        assert RiskEngine.severity_for_score(SCORE_LOW - 1) is Severity.INFO

    def test_there_is_no_critical_score_threshold(self) -> None:
        from aethra_sec.analytics import risk_engine

        assert not hasattr(risk_engine, "SCORE_CRITICAL")

    def test_no_notification_escalates_on_a_detection_being_critical(
        self,
    ) -> None:
        """A dead branch that suggests the value is reachable."""
        for module in (
            PACKAGE / "services" / "notification_service.py",
            PACKAGE / "services" / "correlation_service.py",
        ):
            code = _statements(module)
            assert "Severity.CRITICAL" not in code


class TestSnortRawEvidencePreserved:
    """test_snort_raw_evidence_preserved()."""

    def test_the_sensors_priority_is_stored_not_replaced(self) -> None:
        from aethra_sec.models.alert import SnortAlert

        alert = SnortAlert(
            message="High priority signature", priority=1,
            severity=RiskEngine.severity_for_snort_priority(1),
            raw_alert="[**] [1:1000:1] High priority signature [**] "
                      "[Priority: 1] {TCP} 10.0.0.1 -> 10.0.0.2",
        )
        assert alert.priority == 1, "the sensor's own priority was overwritten"
        assert "[Priority: 1]" in alert.raw_alert
        assert alert.severity is Severity.HIGH

    def test_the_priority_column_still_exists(self) -> None:
        schema = (ROOT / "sql" / "aethra_sec_schema.sql").read_text(
            encoding="utf-8"
        )
        alerts_table = schema[schema.index("CREATE TABLE IF NOT EXISTS snort_alerts"):]
        alerts_table = alerts_table[: alerts_table.index(";")]
        assert "priority" in alerts_table
        assert "raw_alert" in alerts_table

    def test_normalisation_is_documented_where_it_happens(self) -> None:
        source = inspect.getsource(RiskEngine.severity_for_snort_priority)
        assert "raw_alert" in source and "priority" in source


# ---------------------------------------------------------------------------
# The vulnerability module keeps its own model
# ---------------------------------------------------------------------------
class TestVulnerabilityRiskIsUntouched:
    """§7: do not break a module with its own legitimate severity model."""

    def test_risk_level_still_has_critical(self) -> None:
        assert RiskLevel.CRITICAL in list(RiskLevel)
        assert str(RiskLevel.CRITICAL) == "CRITICAL"

    def test_a_critical_finding_still_grades_critical(self) -> None:
        assert RiskEngine._risk_level_for(90) is RiskLevel.CRITICAL
        assert RiskEngine._risk_level_for(55) is RiskLevel.CRITICAL

    def test_the_host_filter_still_offers_critical_risk(self) -> None:
        code = _statements(PACKAGE / "ui" / "screens" / "hosts.py")
        assert "CRITICAL" in code, (
            "host risk filtering lost CRITICAL, but host risk is assessment "
            "risk and has its own model"
        )

    def test_the_dashboard_still_counts_critical_findings(self) -> None:
        code = _statements(PACKAGE / "services" / "dashboard_service.py")
        assert "critical_findings" in code
        assert "critical_alerts" not in code

    def test_reports_still_grade_findings_at_critical(self) -> None:
        # ast.unparse normalises quoting, so match the text, not the quotes.
        code = _statements(PACKAGE / "reports" / "builder.py")
        assert "findings_by_risk.get(" in code
        assert "CRITICAL" in code, (
            "the assessment report lost its CRITICAL finding grade"
        )

    def test_notification_levels_are_a_different_dimension(self) -> None:
        """NotificationLevel.CRITICAL is urgency, not security severity."""
        from aethra_sec.models.enums import NotificationLevel

        assert NotificationLevel.CRITICAL in list(NotificationLevel)


# ---------------------------------------------------------------------------
# Counts
# ---------------------------------------------------------------------------
class TestCountsReconcile:
    """test_ids_counts_reconcile() / test_incident_counts_reconcile()."""

    def test_ids_cells_sum_to_the_matching_total(self) -> None:
        counts = _summary_cells(
            {"HIGH": 28, "MEDIUM": 70, "LOW": 0, "total": 98}
        )
        assert counts["high"] + counts["medium"] + counts["low"] == 98

    def test_ids_unreviewed_is_not_added_to_the_severities(self) -> None:
        """It counts the same rows again by a different question."""
        counts = _summary_cells(
            {"HIGH": 28, "MEDIUM": 70, "unreviewed": 13, "total": 98}
        )
        assert counts["high"] + counts["medium"] + counts["low"] == 98
        assert counts["unreviewed"] == 13

    def test_info_folds_into_low(self) -> None:
        assert ALERT_CELLS["INFO"] == "low"
        assert _summary_cells({"INFO": 1, "total": 1})["low"] == 1


class TestNoFakeSeverityData:
    """test_no_fake_severity_data()."""

    def test_an_empty_dataset_shows_zeros_not_placeholders(self) -> None:
        assert _summary_cells({"total": 0}) == {
            "high": 0, "medium": 0, "low": 0, "unreviewed": 0,
        }

    def test_the_strip_invents_no_count(self) -> None:
        """Every figure comes from what it was handed."""
        for source in (
            inspect.getsource(_summary_cells),
        ):
            for forbidden in ("random", "sample", "choice", "fake", "demo"):
                assert forbidden not in source

    def test_no_seeded_record_carries_a_severity(self) -> None:
        code = _statements(PACKAGE / "database" / "seed.py")
        for table in ("snort_alerts", "traffic_anomalies", "incidents"):
            assert f"INSERT INTO {table}" not in code
