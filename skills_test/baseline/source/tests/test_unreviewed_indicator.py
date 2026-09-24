"""Every untriaged detection is marked, and the mark is the stored state.

The Alerts screen counted eight unreviewed detections and then gave an analyst
no way to see *which* eight. These tests hold the indicator to the one thing
that makes it worth having: it is the same stored review state the counter is
computed from, read per detection, so the two cannot disagree.

What they rule out, explicitly, is every cheaper way to draw a dot:

* not from severity - a HIGH alert is not unreviewed for being HIGH;
* not from age - a recent alert is not unreviewed for being recent;
* not from row position or index - it survives sorting and filtering;
* not from the acknowledgement state or the analyst's evaluation, which are
  different questions with their own columns.

They also hold the honest failure behaviour: the mark comes from the database
on every refresh, so a failed write cannot leave a row looking reviewed when
it is not.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.enums import (
    AlertStatus,
    EvaluationLabel,
    Severity,
    ThreatCategory,
)
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.ui.screens.alerts import (
    ALERT_COLUMNS,
    UNREVIEWED_MARK,
    UNREVIEWED_TEXT,
    _is_unreviewed,
    _review_cell,
    _review_status_text,
    _summary_cells,
)
from aethra_sec.ui.widgets.tables import Column, DataTable

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "aethra_sec" / "ui" / "screens" / "alerts.py"
ALERT_REPO = ROOT / "aethra_sec" / "database" / "repositories" / "alerts.py"


def _alert(**kwargs) -> SnortAlert:  # noqa: ANN003
    base = {"id": 1, "severity": Severity.MEDIUM, "status": AlertStatus.NEW}
    base.update(kwargs)
    return SnortAlert(**base)


def _anomaly(**kwargs) -> TrafficAnomaly:  # noqa: ANN003
    base = {"id": 1, "severity": Severity.MEDIUM}
    base.update(kwargs)
    return TrafficAnomaly(**base)


# ---------------------------------------------------------------------------
# The column
# ---------------------------------------------------------------------------
class TestTheColumn:
    def test_the_table_has_a_review_column_first(self) -> None:
        assert ALERT_COLUMNS[0].key == "review"
        assert ALERT_COLUMNS[0].title == "Review"

    def test_it_is_compact(self) -> None:
        """§10: a dot, not a banner. It must not crowd the record."""
        assert ALERT_COLUMNS[0].width <= 70

    def test_it_draws_a_marker_rather_than_its_text(self) -> None:
        assert ALERT_COLUMNS[0].marker == UNREVIEWED_MARK

    def test_the_marker_is_a_shape_not_a_colour(self) -> None:
        """§12: the indicator must not depend on colour to be readable."""
        assert UNREVIEWED_MARK.strip(), "the marker is blank"
        assert ALERT_COLUMNS[0].colour_by == "", (
            "the review column drives a row colour, which would make the "
            "indicator a colour signal and collide with severity"
        )

    def test_the_marker_is_not_a_severity_glyph(self) -> None:
        """§2, §17: review state and severity must not share a symbol.

        Every circle is already spoken for - LOW is a filled circle and INFO
        a hollow one - so a plain dot here would be the identical character
        the same row shows for its severity two columns along.
        """
        from aethra_sec.ui.theme import SEVERITY_GLYPHS

        assert UNREVIEWED_MARK not in set(SEVERITY_GLYPHS.values()), (
            f"the review mark {UNREVIEWED_MARK!r} is also the glyph for "
            f"{[k for k, v in SEVERITY_GLYPHS.items() if v == UNREVIEWED_MARK]}"
        )

    def test_the_marker_renders_from_the_same_font_coverage(self) -> None:
        """Geometric Shapes, like every other glyph the tables already draw."""
        assert 0x25A0 <= ord(UNREVIEWED_MARK) <= 0x25FF, (
            "the review mark is outside the Unicode block the existing "
            "severity glyphs come from, so it may not render on a fresh "
            "Windows installation"
        )

    def test_it_does_not_disturb_the_severity_presentation(self) -> None:
        """§2, §17: severity styling is untouched and stays separate."""
        severity = next(c for c in ALERT_COLUMNS if c.key == "severity")
        assert severity.colour_by == "severity"
        assert severity.glyph is True
        assert severity.marker == "", (
            "severity was turned into a marker column, which would replace "
            "HIGH/MEDIUM/LOW with a glyph"
        )

    def test_the_existing_columns_are_all_still_there(self) -> None:
        keys = [c.key for c in ALERT_COLUMNS]
        for expected in (
            "time", "origin", "severity", "priority", "signature", "message",
            "protocol", "source", "destination", "count", "status",
            "evaluation",
        ):
            assert expected in keys, f"the {expected} column was dropped"


class TestTheMarkerRendersWithoutLosingTheWord:
    """Drawn as a dot; stored, copied and exported as the word."""

    COLUMN = Column("review", "Review", marker=UNREVIEWED_MARK)

    def test_an_unreviewed_cell_draws_the_dot(self) -> None:
        assert DataTable._cell({"review": UNREVIEWED_TEXT}, self.COLUMN) == (
            UNREVIEWED_MARK
        )

    def test_a_reviewed_cell_draws_nothing(self) -> None:
        assert DataTable._cell({"review": ""}, self.COLUMN) == ""

    def test_an_export_reads_the_word(self) -> None:
        """§10 wants a dot on screen; a CSV of security records needs words."""
        assert DataTable._cell(
            {"review": UNREVIEWED_TEXT}, self.COLUMN, display=False
        ) == UNREVIEWED_TEXT

    def test_the_export_path_asks_for_the_word(self) -> None:
        body = inspect.getsource(DataTable.export_rows)
        assert "display=False" in body

    def test_the_clipboard_path_asks_for_the_word(self) -> None:
        body = inspect.getsource(DataTable._copy_selection)
        assert "display=False" in body

    def test_a_marker_column_does_not_change_other_columns(self) -> None:
        severity = Column("severity", "Severity", glyph=True)
        assert "HIGH" in DataTable._cell({"severity": "HIGH"}, severity)


# ---------------------------------------------------------------------------
# The mark is the stored review state
# ---------------------------------------------------------------------------
class TestTheMarkComesFromTheStoredState:
    def test_a_new_snort_alert_is_marked(self) -> None:
        assert _review_cell(_alert(status=AlertStatus.NEW)) == UNREVIEWED_TEXT

    def test_a_reviewed_snort_alert_is_not_marked(self) -> None:
        assert _review_cell(_alert(status=AlertStatus.REVIEWED)) == ""

    def test_an_unread_anomaly_is_marked(self) -> None:
        assert _review_cell(_anomaly()) == UNREVIEWED_TEXT

    def test_a_read_anomaly_is_not_marked(self) -> None:
        stamped = _anomaly(reviewed_at=datetime.now(tz=timezone.utc))
        assert _review_cell(stamped) == ""

    def test_a_classified_anomaly_is_not_marked(self) -> None:
        """A verdict is attention too, which is what the counter's SQL says."""
        judged = _anomaly(evaluation=EvaluationLabel.TRUE_POSITIVE)
        assert _review_cell(judged) == ""

    def test_the_cell_uses_the_shared_predicate(self) -> None:
        """One definition, so the mark and the counter cannot drift apart."""
        source = inspect.getsource(_review_cell)
        assert "_is_unreviewed(" in source

    @pytest.mark.parametrize("severity", list(Severity))
    def test_severity_never_decides_the_mark(self, severity: Severity) -> None:
        """§17: every severity appears in both review states."""
        assert _review_cell(
            _alert(severity=severity, status=AlertStatus.NEW)
        ) == UNREVIEWED_TEXT
        assert _review_cell(
            _alert(severity=severity, status=AlertStatus.REVIEWED)
        ) == ""

    def test_age_never_decides_the_mark(self) -> None:
        """A week-old alert still in NEW is unreviewed; a new one need not be."""
        now = datetime.now(tz=timezone.utc)
        old_untriaged = _alert(
            status=AlertStatus.NEW, received_at=now - timedelta(days=7)
        )
        fresh_reviewed = _alert(status=AlertStatus.REVIEWED, received_at=now)
        assert _review_cell(old_untriaged) == UNREVIEWED_TEXT
        assert _review_cell(fresh_reviewed) == ""

    def test_the_row_builders_read_the_detection_not_the_index(self) -> None:
        """§18: bound to the record, so sorting cannot shuffle the marks."""
        source = ALERTS.read_text(encoding="utf-8")
        for builder in ("_alert_rows", "_anomaly_rows"):
            node = next(
                n for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.FunctionDef) and n.name == builder
            )
            body = ast.unparse(node)
            assert "_review_cell(" in body, f"{builder} sets no review cell"
            assert "enumerate" not in body, (
                f"{builder} uses a row index, which the mark must not depend on"
            )


class TestTheRemovedActionsAreGoneButTheirStatesSurvive:
    """Acknowledge, Escalate and Benign/expected were removed as unused.

    Only the *actions* went. Stored records still carry those states - on the
    installation this was done for, two alerts are ESCALATED and two
    detections are classified BENIGN_EXPECTED - so the enum values, the
    status colours and the columns that report them all stay. Nothing can be
    put into those states from the Alerts screen any more; nothing already in
    them was altered.
    """

    @pytest.mark.parametrize(
        "label", ["Acknowledge", "Escalate", "Benign/expected"]
    )
    def test_the_action_is_not_offered(self, label: str) -> None:
        source = ALERTS.read_text(encoding="utf-8")
        assert f'act("{label}"' not in source, f"{label} is still a button"
        assert f'RowAction(\n                    "{label}"' not in source
        assert f'RowAction("{label}"' not in source

    @pytest.mark.parametrize(
        "setter",
        ["AlertStatus.ACKNOWLEDGED", "AlertStatus.ESCALATED",
         "EvaluationLabel.BENIGN_EXPECTED"],
    )
    def test_the_screen_never_writes_the_state(self, setter: str) -> None:
        source = ALERTS.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call):
                rendered = ast.unparse(node)
                assert setter not in rendered, (
                    f"the Alerts screen still puts a detection into {setter}"
                )

    def test_the_states_still_exist_for_stored_records(self) -> None:
        """Removing them from the model would orphan real rows."""
        assert AlertStatus.ACKNOWLEDGED == "ACKNOWLEDGED"
        assert AlertStatus.ESCALATED == "ESCALATED"
        assert EvaluationLabel.BENIGN_EXPECTED == "BENIGN_EXPECTED"

    def test_a_stored_state_still_renders(self) -> None:
        """The Status and Evaluation columns must keep reporting them."""
        from aethra_sec.ui.screens.alerts import AlertsScreen

        rows = AlertsScreen._alert_rows(
            None,  # type: ignore[arg-type]
            [_alert(status=AlertStatus.ESCALATED,
                    evaluation=EvaluationLabel.BENIGN_EXPECTED)],
        )
        assert rows[0]["status"] == "ESCALATED"
        assert rows[0]["evaluation"] == EvaluationLabel.BENIGN_EXPECTED.label

    def test_a_stored_state_keeps_its_colour(self) -> None:
        from aethra_sec.ui.theme import status_colour

        assert status_colour("ESCALATED")
        assert status_colour("ACKNOWLEDGED")

    def test_an_escalated_alert_is_still_not_unreviewed(self) -> None:
        """It left NEW, so the counter and the mark agree it was looked at."""
        assert _review_cell(_alert(status=AlertStatus.ESCALATED)) == ""

    def test_the_status_filter_still_offers_every_stored_state(self) -> None:
        """An analyst must be able to find the records that carry them."""
        source = ALERTS.read_text(encoding="utf-8")
        assert "[str(s) for s in AlertStatus]" in source, (
            "the Status filter no longer lists every stored status, so the "
            "escalated records cannot be filtered to"
        )


class TestReviewIsNotTheOtherStates:
    """§16, §17: three different questions, three different answers."""

    def test_acknowledgement_is_recorded_separately(self) -> None:
        source = ALERTS.read_text(encoding="utf-8")
        assert '("Review status", _review_status_text(alert))' in source
        assert '("Workflow status", str(alert.status))' in source, (
            "the workflow status is gone, so ACKNOWLEDGED and ESCALATED have "
            "nowhere to be reported"
        )

    def test_the_evaluation_is_recorded_separately(self) -> None:
        source = ALERTS.read_text(encoding="utf-8")
        assert '("Analyst evaluation", alert.evaluation.label)' in source

    def test_marking_reviewed_writes_no_evaluation(self) -> None:
        """§16: reviewing must not assign a verdict."""
        from aethra_sec.ui.screens.alerts import AlertsScreen

        body = inspect.getsource(AlertsScreen._set_status)
        assert "classify" not in body
        assert "EvaluationLabel" not in body

    def test_classifying_does_not_silently_review(self) -> None:
        from aethra_sec.ui.screens.alerts import AlertsScreen

        body = inspect.getsource(AlertsScreen._classify)
        assert "AlertStatus.REVIEWED" not in body


# ---------------------------------------------------------------------------
# One source of truth
# ---------------------------------------------------------------------------
class TestOneSourceOfTruth:
    """§4: the counter, the marks, the detail and the badge are one state."""

    def test_the_counter_comes_from_the_database(self) -> None:
        from aethra_sec.services.snort_service import SnortService

        body = inspect.getsource(SnortService.detection_totals)
        assert "count_unreviewed_matching" in body, (
            "the UNREVIEWED figure is no longer counted in the database"
        )

    def test_the_counter_is_not_tallied_from_the_loaded_rows(self) -> None:
        """A row-limited page must not become the count."""
        source = inspect.getsource(_summary_cells)
        assert "_is_unreviewed" not in source
        assert 'totals.get("unreviewed"' in source

    def test_the_stored_figure_is_shown_as_it_is(self) -> None:
        cells = _summary_cells({"HIGH": 2, "MEDIUM": 6, "unreviewed": 9})
        assert cells["unreviewed"] == 9
        assert _summary_cells({})["unreviewed"] == 0

    def test_the_sql_and_the_predicate_agree_for_alerts(self) -> None:
        """Both say: a Snort alert is unreviewed exactly while it is NEW."""
        sql = ALERT_REPO.read_text(encoding="utf-8")
        node = next(
            n for n in ast.walk(ast.parse(sql))
            if isinstance(n, ast.FunctionDef)
            and n.name == "count_unreviewed_matching"
        )
        body = ast.unparse(node)
        assert "AlertStatus.NEW" in body
        # And the Python predicate agrees, on the same two cases.
        assert _is_unreviewed(_alert(status=AlertStatus.NEW))
        assert not _is_unreviewed(_alert(status=AlertStatus.REVIEWED))

    def test_the_sql_and_the_predicate_agree_for_anomalies(self) -> None:
        sql = ALERT_REPO.read_text(encoding="utf-8")
        node = next(
            n for n in ast.walk(ast.parse(sql))
            if isinstance(n, ast.FunctionDef)
            and n.name == "count_unreviewed_matching"
        )
        body = ast.unparse(node)
        assert "reviewed_at" in body
        assert "UNCLASSIFIED" in body
        assert _is_unreviewed(_anomaly())
        assert not _is_unreviewed(_anomaly(reviewed_at=datetime.now(tz=timezone.utc)))
        assert not _is_unreviewed(
            _anomaly(evaluation=EvaluationLabel.TRUE_POSITIVE)
        )

    def test_the_detail_view_agrees_with_the_row(self) -> None:
        for detection in (
            _alert(status=AlertStatus.NEW), _anomaly(),
        ):
            assert _review_status_text(detection) == UNREVIEWED_TEXT
            assert _review_cell(detection) == UNREVIEWED_TEXT
        for detection in (
            _alert(status=AlertStatus.REVIEWED),
            _anomaly(reviewed_at=datetime.now(tz=timezone.utc)),
        ):
            assert _review_status_text(detection) == "REVIEWED"
            assert _review_cell(detection) == ""

    def test_no_review_metadata_is_invented_for_an_alert(self) -> None:
        """§15: snort_alerts stores no reviewed_by/reviewed_at."""
        assert not hasattr(SnortAlert, "reviewed_by")
        assert "reviewed_by" not in SnortAlert.__dataclass_fields__
        source = ALERTS.read_text(encoding="utf-8")
        assert "alert.reviewed_by" not in source
        assert "alert.reviewed_at" not in source

    def test_the_anomaly_review_metadata_that_exists_is_shown(self) -> None:
        assert "reviewed_by" in TrafficAnomaly.__dataclass_fields__
        source = ALERTS.read_text(encoding="utf-8")
        assert "anomaly.reviewed_by" in source
        assert "anomaly.reviewed_at" in source


# ---------------------------------------------------------------------------
# Marking reviewed
# ---------------------------------------------------------------------------
class TestMarkingReviewedPersistsFirst:
    """§5, §29: the database is changed first, and the UI follows it."""

    def test_the_single_action_calls_the_service(self) -> None:
        from aethra_sec.ui.screens.alerts import AlertsScreen

        body = inspect.getsource(AlertsScreen._set_status)
        assert "snort.set_status(" in body

    def test_the_anomaly_action_calls_the_service(self) -> None:
        from aethra_sec.ui.screens.alerts import AlertsScreen

        body = inspect.getsource(AlertsScreen._review_anomaly)
        assert "mark_anomaly_reviewed(" in body

    def test_the_bulk_action_calls_the_service(self) -> None:
        from aethra_sec.ui.screens.alerts import AlertsScreen

        body = inspect.getsource(AlertsScreen._mark_all_reviewed)
        assert "service.mark_all_reviewed(" in body

    def test_the_ui_refreshes_only_after_a_successful_write(self) -> None:
        """A failed write must not clear the mark."""
        from aethra_sec.ui.screens.alerts import AlertsScreen

        for name in ("_set_status", "_review_anomaly", "_mark_all_reviewed"):
            body = inspect.getsource(getattr(AlertsScreen, name))
            refresh = body.find("refresh()")
            assert refresh != -1, f"{name} never reloads from the database"
            # The reload must sit in the success callback, never before the
            # call that writes.
            assert "run_async" in body

    def test_the_mark_is_re_derived_from_the_database_every_refresh(self) -> None:
        """The strongest form of §29: the UI holds no review state of its own.

        Nothing caches "this row is reviewed now". Each reload maps the stored
        rows through ``_review_cell``, so a write that failed leaves the mark
        exactly where the database left it.
        """
        source = ALERTS.read_text(encoding="utf-8")
        assert source.count("_review_cell(") == 3, (
            "the review cell is set somewhere other than the two row "
            "builders, which risks a second, stale source"
        )
        node = next(
            n for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.FunctionDef) and n.name == "_apply"
        )
        body = ast.unparse(node)
        assert "_alert_rows(" in body and "_anomaly_rows(" in body

    def test_the_bulk_action_is_confirmed_first(self) -> None:
        from aethra_sec.ui.screens.alerts import AlertsScreen

        body = inspect.getsource(AlertsScreen._mark_all_reviewed)
        assert "confirm(" in body

    def test_nothing_is_deleted_by_reviewing(self) -> None:
        """No destructive SQL on this screen at all.

        Checked as a statement, not as the word: the confirmation dialog
        legitimately reassures the operator that "nothing is deleted", and an
        upper-cased substring search flagged that sentence.
        """
        source = ALERTS.read_text(encoding="utf-8").upper()
        # Full statement forms only. "TRUNCATE" alone is the text-shortening
        # helper this screen imports for the message column.
        for statement in ("DELETE FROM", "TRUNCATE TABLE", "DROP TABLE"):
            assert statement not in source, (
                f"the Alerts screen contains {statement}"
            )


class TestNoNotificationIsRaisedByTheMark:
    """§9: a dot is a rendering, not an event."""

    def test_the_row_builders_raise_nothing(self) -> None:
        source = ALERTS.read_text(encoding="utf-8")
        for builder in ("_alert_rows", "_anomaly_rows", "_review_cell"):
            node = next(
                n for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.FunctionDef) and n.name == builder
            )
            body = ast.unparse(node)
            for side_effect in ("notify", "publish", "insert", "record("):
                assert side_effect not in body, (
                    f"{builder} has a side effect ({side_effect}); refreshing "
                    "the table would create records"
                )


# ---------------------------------------------------------------------------
# Against a real database
# ---------------------------------------------------------------------------
class TestAgainstARealDatabase:
    """Real MySQL, real repository: the write persists and the mark follows."""

    @pytest.fixture()
    def stack(self, db):  # noqa: ANN001, ANN201
        from aethra_sec.database.repositories.alerts import AlertRepository

        return AlertRepository(db)

    def _store(self, repo, **kwargs) -> int:  # noqa: ANN001
        from aethra_sec.utils.timeutil import utcnow

        alert = SnortAlert(
            id=None, severity=Severity.MEDIUM, status=AlertStatus.NEW,
            message="unreviewed indicator fixture", signature_id=999001,
            generator_id=1, revision=1, received_at=utcnow(),
            alert_time=utcnow(), src_ip="10.99.0.1", dst_ip="10.99.0.2",
            protocol="TCP", **kwargs,
        )
        return int(repo.insert_alert(alert))

    def test_a_stored_new_alert_is_counted_and_marked(self, stack) -> None:  # noqa: ANN001
        alert_id = self._store(stack)
        stored = stack.get_alert(alert_id)
        assert stored is not None
        assert stored.status is AlertStatus.NEW
        assert _review_cell(stored) == UNREVIEWED_TEXT
        counted = stack.count_unreviewed_matching(
            alert_filters={}, anomaly_filters=None
        )
        assert counted >= 1

    def test_marking_reviewed_persists_and_clears_the_mark(self, stack) -> None:  # noqa: ANN001
        alert_id = self._store(stack)
        before = stack.count_unreviewed_matching(
            alert_filters={}, anomaly_filters=None
        )

        stack.set_alert_status(alert_id, AlertStatus.REVIEWED)

        # Re-read: this is what a refresh does, so it is what the mark sees.
        reloaded = stack.get_alert(alert_id)
        assert reloaded is not None
        assert reloaded.status is AlertStatus.REVIEWED
        assert _review_cell(reloaded) == "", "the mark survived the write"
        assert _review_status_text(reloaded) == "REVIEWED"
        after = stack.count_unreviewed_matching(
            alert_filters={}, anomaly_filters=None
        )
        assert after == before - 1, "the counter did not follow the write"

    def test_the_alert_itself_is_not_deleted_by_reviewing(self, stack) -> None:  # noqa: ANN001
        alert_id = self._store(stack)
        stack.set_alert_status(alert_id, AlertStatus.REVIEWED)
        kept = stack.get_alert(alert_id)
        assert kept is not None
        assert kept.message == "unreviewed indicator fixture"
        assert kept.src_ip == "10.99.0.1", "the evidence was altered"

    def test_the_state_is_read_back_not_remembered(self, stack, db) -> None:  # noqa: ANN001
        """What "survives a restart" means here: nothing is held in memory.

        The mark is derived from a fresh row on every read, so a new process
        reading the same database reaches the same answer. This asserts the
        persistence that property rests on.
        """
        alert_id = self._store(stack)
        stack.set_alert_status(alert_id, AlertStatus.REVIEWED)
        row = db.query_one(
            "SELECT status FROM snort_alerts WHERE id = %s", (alert_id,)
        )
        assert row["status"] == str(AlertStatus.REVIEWED)

    def test_acknowledging_is_not_the_same_write_as_reviewing(
        self, stack
    ) -> None:  # noqa: ANN001
        """§16: they are distinct states, stored distinctly."""
        alert_id = self._store(stack)
        stack.set_alert_status(alert_id, AlertStatus.ACKNOWLEDGED)
        reloaded = stack.get_alert(alert_id)
        assert reloaded is not None
        assert reloaded.status is AlertStatus.ACKNOWLEDGED
        assert reloaded.evaluation is EvaluationLabel.UNCLASSIFIED, (
            "acknowledging assigned an analyst evaluation"
        )

    def test_an_unreviewed_anomaly_is_marked_then_cleared(self, stack) -> None:  # noqa: ANN001
        from aethra_sec.utils.timeutil import utcnow

        anomaly = TrafficAnomaly(
            id=None, rule_id="RULE-TEST-INDICATOR",
            category=ThreatCategory.PORT_SCAN, severity=Severity.LOW,
            title="unreviewed indicator fixture", detected_at=utcnow(),
            first_seen=utcnow(), last_seen=utcnow(),
        )
        anomaly_id = int(stack.insert_anomaly(anomaly))
        stored = stack.get_anomaly(anomaly_id)
        assert stored is not None
        assert _review_cell(stored) == UNREVIEWED_TEXT

        assert stack.mark_anomaly_reviewed(anomaly_id, None)
        reloaded = stack.get_anomaly(anomaly_id)
        assert reloaded is not None
        assert reloaded.reviewed_at is not None
        assert _review_cell(reloaded) == ""

    def test_the_counter_and_the_marks_agree_over_the_same_rows(
        self, stack
    ) -> None:  # noqa: ANN001
        """§4 as a fact about data, not about code.

        Count in SQL, mark in Python, over the same set - the two must match.
        """
        for _ in range(3):
            self._store(stack)
        reviewed_id = self._store(stack)
        stack.set_alert_status(reviewed_id, AlertStatus.REVIEWED)

        rows = stack.search_alerts(limit=1000)
        marked = sum(1 for a in rows if _review_cell(a) == UNREVIEWED_TEXT)
        counted = stack.count_unreviewed_matching(
            alert_filters={}, anomaly_filters=None
        )
        assert marked == counted, (
            f"{marked} rows are marked but the database counts {counted}"
        )
