"""Severity counters must describe the records they sit above (§67).

The IDS Alerts strip read CRITICAL 0 / HIGH 17 / MEDIUM 1 while the table under
it listed 30 detections. Both numbers were honestly computed - from different
datasets. The table had been widened to show detections from both engines; the
strip still counted Snort alerts alone, so it reported 18 of 36 and was short by
exactly the detections AETHRA-SEC had raised itself.

It regressed a second way, for the same underlying reason. The summary was
tallied from the rows the screen had loaded, and those rows are capped so a
large result set does not freeze the table. The cap therefore became part of
the count: 1,000 rows returned out of 1,412 matching, and a summary short by
exactly the 412 that did not fit - while the Dashboard, counting in the
database, reported all of them.

The rule these tests hold is that the summary and the rows are selected by the
*same predicate*, and that the summary is counted where the records are rather
than from whatever subset reached the screen.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from aethra_sec.models.enums import AlertStatus, EvaluationLabel, Severity
from aethra_sec.ui.screens.alerts import (
    _SEVERITY_CELL,
    _is_unreviewed,
    _summary_cells,
)

ROOT = Path(__file__).resolve().parent.parent
SCREEN = ROOT / "aethra_sec" / "ui" / "screens" / "alerts.py"
DASHBOARD = ROOT / "aethra_sec" / "services" / "dashboard_service.py"
ALERT_REPO = ROOT / "aethra_sec" / "database" / "repositories" / "alerts.py"


def _code_only(path: Path) -> str:
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


def _method(path: Path, name: str) -> str:
    code = _code_only(path)
    start = code.index(f"def {name}")
    rest = code[start + 4 :]
    end = rest.index("\n    def ") if "\n    def " in rest else len(rest)
    return code[start : start + 4 + end]


class _Alert:
    """A Snort alert: severity plus a workflow status."""

    def __init__(self, severity, status=AlertStatus.REVIEWED) -> None:
        self.severity = severity
        self.status = status


class _Anomaly:
    """An AETHRA-SEC detection: severity plus an analyst evaluation."""

    def __init__(self, severity, evaluation=EvaluationLabel.TRUE_POSITIVE) -> None:
        self.severity = severity
        self.evaluation = evaluation


class TestTheCountsReconcileWithTheRows:
    """CRITICAL + HIGH + MEDIUM + LOW must equal the matching total."""

    def test_both_sources_are_counted(self) -> None:
        """The database query spans both tables; the strip renders the sum."""
        counts = _summary_cells({"HIGH": 18, "MEDIUM": 18, "total": 36})
        assert counts["high"] == 18
        assert counts["medium"] == 18
        assert counts["high"] + counts["medium"] + counts["low"] == 36

    def test_the_total_always_equals_the_sum_of_the_cells(self) -> None:
        for supplied in (
            {"total": 0},
            {"HIGH": 1, "total": 1},
            {"LOW": 5, "total": 5},
            {"HIGH": 1, "MEDIUM": 1, "LOW": 1, "total": 3},
        ):
            counts = _summary_cells(supplied)
            total = sum(counts[k] for k in ("high", "medium", "low"))
            assert total == supplied["total"]

    def test_an_empty_set_reports_zero_not_a_stale_value(self) -> None:
        counts = _summary_cells({"total": 0})
        assert all(counts[k] == 0 for k in counts)

    def test_the_unreviewed_cell_comes_from_the_same_query(self) -> None:
        """Not from the loaded rows, which are capped."""
        counts = _summary_cells({"HIGH": 900, "unreviewed": 412, "total": 900})
        assert counts["unreviewed"] == 412


class TestSeverityMapping:
    """One canonical mapping, and nothing silently miscounted."""

    @pytest.mark.parametrize(
        "severity, cell",
        [
            (Severity.HIGH, "high"),
            (Severity.MEDIUM, "medium"),
            (Severity.LOW, "low"),
            (Severity.INFO, "low"),
        ],
    )
    def test_every_real_severity_lands_in_its_cell(self, severity, cell) -> None:
        counts = _summary_cells({str(severity): 1, "total": 1})
        assert counts[cell] == 1

    def test_info_folds_into_low_as_the_tooltip_promises(self) -> None:
        assert _SEVERITY_CELL["INFO"] == "low"

    def test_an_unknown_severity_is_not_silently_counted_as_low(self) -> None:
        """It used to be: any unrecognised value fell through to LOW."""
        counts = _summary_cells({"NOT_A_SEVERITY": 1, "total": 1})
        assert counts["low"] == 0, "an unrecognised severity inflated the LOW cell"
        assert sum(counts[k] for k in ("high", "medium", "low")) == 0

    def test_every_detection_severity_has_a_cell(self) -> None:
        """A new severity must not become an invisible discrepancy."""
        from aethra_sec.models.severity_source import DETECTION_SEVERITIES

        for severity in DETECTION_SEVERITIES:
            assert str(severity).upper() in _SEVERITY_CELL, (
                f"{severity} has no summary cell, so it would go uncounted"
            )

    def test_critical_has_no_cell(self) -> None:
        """It is outside the detection severity model, so it has no card."""
        assert "CRITICAL" not in _SEVERITY_CELL
        counts = _summary_cells({"CRITICAL": 3, "total": 3})
        assert "critical" not in counts
        assert sum(counts[k] for k in ("high", "medium", "low")) == 0, (
            "a CRITICAL value was folded into another cell instead of being "
            "reported as a discrepancy"
        )


class TestUnreviewedSpansBothConventions:
    """The two sources record 'not yet triaged' differently."""

    def test_a_new_snort_alert_is_unreviewed(self) -> None:
        assert _is_unreviewed(_Alert(Severity.HIGH, AlertStatus.NEW))

    def test_a_reviewed_snort_alert_is_not(self) -> None:
        assert not _is_unreviewed(_Alert(Severity.HIGH, AlertStatus.REVIEWED))

    def test_an_unclassified_anomaly_is_unreviewed(self) -> None:
        assert _is_unreviewed(_Anomaly(Severity.HIGH, EvaluationLabel.UNCLASSIFIED))

    def test_a_classified_anomaly_is_not(self) -> None:
        assert not _is_unreviewed(_Anomaly(Severity.HIGH, EvaluationLabel.TRUE_POSITIVE))

    def test_the_counter_covers_both_sources(self) -> None:
        """The SQL counts NEW alerts and unreceipted anomalies together."""
        from aethra_sec.database.repositories.alerts import AlertRepository

        source = inspect.getsource(AlertRepository.count_unreviewed_matching)
        assert "snort_alerts" in source and "traffic_anomalies" in source
        assert "AlertStatus.NEW" in source
        assert "reviewed_at" in source


class TestOneAuthoritativeSet:
    """Structural: the summary and the rows cannot come from different data."""

    def test_the_summary_comes_from_the_database_not_the_loaded_rows(
        self,
    ) -> None:
        """The second regression: the row cap became part of the count."""
        apply = _method(SCREEN, "_apply")
        assert "_summary_cells(totals)" in apply, (
            "the summary is tallied from the rows the screen happened to load"
        )
        # The old row tally is gone from the module, not merely unused.
        screen = SCREEN.read_text(encoding="utf-8")
        assert "def _detection_counts" not in screen, (
            "the row-derived tally still exists and can be wired back in"
        )

    def test_the_totals_are_fetched_with_the_same_filters_as_the_rows(
        self,
    ) -> None:
        refresh = _method(SCREEN, "refresh")
        assert "detection_totals(" in refresh
        assert "alert_filters=counted" in refresh, (
            "the totals are counted over a different predicate from the rows"
        )

    def test_the_row_limit_is_excluded_from_the_count(self) -> None:
        """Counting with the limit applied is how the bug worked."""
        refresh = _method(SCREEN, "refresh")
        assert "k != 'limit'" in refresh or 'k != "limit"' in refresh

    def test_a_truncated_table_says_so(self) -> None:
        """A summary above a shorter table must not look like a new bug."""
        apply = _method(SCREEN, "_apply")
        assert "truncated" in apply
        assert "showing newest" in apply

    def test_the_rows_come_from_the_same_two_lists(self) -> None:
        apply = _method(SCREEN, "_apply")
        assert "_alert_rows(alerts)" in apply and "_anomaly_rows(anomalies)" in apply


class TestTheDashboardCountsTheSameThing:
    """Two screens describing detections must not count different records."""

    def test_the_dashboard_uses_the_both_source_query(self) -> None:
        code = _code_only(DASHBOARD)
        assert "count_detections_by_severity" in code, (
            "the dashboard counts Snort alerts only, so it reports a subset of "
            "what the IDS Alerts screen lists for the same window"
        )

    def test_the_both_source_query_reads_both_tables(self) -> None:
        query = _method(ALERT_REPO, "count_detections_by_severity")
        assert "snort_alerts" in query and "traffic_anomalies" in query

    def test_each_source_is_filtered_on_its_own_arrival_column(self) -> None:
        """Snort alerts arrive; AETHRA-SEC detections are created here."""
        query = _method(ALERT_REPO, "count_detections_by_severity")
        assert "received_at" in query and "created_at" in query

    def test_the_snort_only_query_still_exists_and_says_so(self) -> None:
        """Kept for callers that genuinely mean Snort's own queue."""
        code = _code_only(ALERT_REPO)
        assert "def count_by_severity" in code
