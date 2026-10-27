"""Clearing the sidebar badges in one action (§64).

The Incidents and Alerts badges both showed 99+ with no way to clear them
except opening records one at a time. They count different things, and the two
bulk actions are deliberately not the same operation:

* the incident badge counts open incidents nobody has *read*, so clearing it is
  a read receipt and needs only ``incident.view``;
* the alert badge counts alerts in the ``NEW`` state, and leaving that state is
  an analyst's judgement recorded against the alert - so it needs
  ``alert.manage``, is audited, and is labelled "Mark all reviewed" rather than
  "mark as read".

What both must guarantee is that they change the counted rows and nothing else.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCIDENT_REPO = ROOT / "aethra_sec" / "database" / "repositories" / "incidents.py"
ALERT_REPO = ROOT / "aethra_sec" / "database" / "repositories" / "alerts.py"
CORRELATION = ROOT / "aethra_sec" / "services" / "correlation_service.py"
SNORT = ROOT / "aethra_sec" / "services" / "snort_service.py"
ALERT_SCREEN = ROOT / "aethra_sec" / "ui" / "screens" / "alerts.py"


def _code_only(path: Path) -> str:
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


def _method(path: Path, name: str) -> str:
    """One method's source, without its docstring."""
    code = _code_only(path)
    # The trailing parenthesis matters: without it a lookup for _apply
    # matches a longer name such as _apply_guide_context.
    start = code.index(f"def {name}(")
    rest = code[start + 4 :]
    end = rest.index("\n    def ") if "\n    def " in rest else len(rest)
    return code[start : start + 4 + end]


class TestTheActionsClearExactlyWhatTheBadgesCount:
    """A badge that survives the button meant to clear it is a bug."""

    def test_incidents_mark_the_rows_the_badge_counts(self) -> None:
        """Both use ``viewed_at IS NULL`` and the same open-status set."""
        counter = _method(INCIDENT_REPO, "count_unread")
        action = _method(INCIDENT_REPO, "mark_all_viewed")
        assert "viewed_at IS NULL" in counter
        assert "viewed_at IS NULL" in action, (
            "the bulk action does not select on the unread marker the badge counts"
        )
        assert "_OPEN_STATUSES" in counter and "_OPEN_STATUSES" in action, (
            "the badge and the action disagree about which statuses are open"
        )

    def test_alerts_move_the_rows_the_badge_counts(self) -> None:
        """The badge counts ``status = 'NEW'``; the action moves exactly those."""
        action = _method(ALERT_REPO, "mark_all_reviewed")
        assert "AlertStatus.NEW" in action, "the action does not target NEW alerts"
        assert "AlertStatus.REVIEWED" in action


class TestNeitherActionOverwritesADecision:
    """Bulk convenience must not silently undo analyst work."""

    def test_marking_incidents_read_does_not_touch_status(self) -> None:
        """Reading a backlog is not triaging it."""
        action = _method(INCIDENT_REPO, "mark_all_viewed")
        assert "status =" not in action, (
            "marking incidents read also changes their status"
        )
        assert "resolved_at" not in action

    def test_marking_alerts_reviewed_leaves_other_states_alone(self) -> None:
        """Acknowledged, escalated and suppressed are decisions already made."""
        action = _method(ALERT_REPO, "mark_all_reviewed")
        assert "WHERE status = %s" in action, (
            "the update is not restricted to alerts still in NEW"
        )
        for decided in ("ACKNOWLEDGED", "ESCALATED", "SUPPRESSED"):
            assert decided not in action

    def test_an_already_read_incident_keeps_its_original_reader(self) -> None:
        """Being marked again must not rewrite who saw it first."""
        action = _method(INCIDENT_REPO, "mark_all_viewed")
        assert "viewed_at IS NULL" in action


class TestAuthorizationMatchesWhatTheActionMeans:
    """Reading needs less than deciding."""

    def test_incidents_need_only_the_view_permission(self) -> None:
        action = _method(CORRELATION, "mark_all_viewed")
        assert "Permission.INCIDENT_VIEW" in action

    def test_alerts_need_the_manage_permission(self) -> None:
        """Moving an alert out of NEW is a judgement, not a read."""
        action = _method(SNORT, "mark_all_reviewed")
        assert "Permission.ALERT_MANAGE" in action, (
            "a bulk status change is gated on the view permission"
        )

    def test_both_are_audited(self) -> None:
        assert "AuditAction.INCIDENT_UPDATED" in _method(CORRELATION, "mark_all_viewed")
        assert "AuditAction.ALERT_UPDATED" in _method(SNORT, "mark_all_reviewed")

    def test_the_alert_control_is_hidden_without_the_permission(self) -> None:
        """An operator should not be offered a button that will refuse them."""
        code = _code_only(ALERT_SCREEN)
        assert "self.can(Permission.ALERT_MANAGE)" in code


class TestTheControlsExist:
    """The affordance the sidebar badges were missing."""

    def test_alerts_names_the_action_for_what_it_does(self) -> None:
        """Calling a status change "mark as read" would misdescribe it."""
        code = _code_only(ALERT_SCREEN)
        assert "Mark all reviewed" in code
        assert "_mark_all_reviewed" in code

    def test_the_alert_action_asks_first(self) -> None:
        """It writes a decision onto every counted alert."""
        assert "confirm(" in _method(ALERT_SCREEN, "_mark_all_reviewed")

    def test_it_refreshes_the_badge_it_cleared(self) -> None:
        for path, name in (
            (ALERT_SCREEN, "_mark_all_reviewed"),
        ):
            assert "_refresh_nav_badges" in _method(path, name), (
                f"{name} does not repaint the sidebar counter"
            )


class TestMarkAllReviewedCoversWhatTheScreenShows:
    """§67 - the action must clear the counter the operator is looking at.

    The Alerts screen shows both detection sources, but the bulk action only
    moved Snort alerts out of NEW. With Snort quiet the whole backlog was
    AETHRA-SEC's own detections, so the button ran, reported success, and the
    UNREVIEWED cell did not move.
    """

    def test_it_marks_anomalies_as_well_as_alerts(self) -> None:
        action = _method(SNORT, "mark_all_reviewed")
        assert "mark_all_reviewed" in action
        assert "mark_all_anomalies_reviewed" in action, (
            "the action clears Snort's queue only, so a backlog of "
            "AETHRA-SEC detections cannot be cleared at all"
        )

    def test_it_reports_the_total_across_both_sources(self) -> None:
        action = _method(SNORT, "mark_all_reviewed")
        assert "moved + marked" in action


class TestNoBulkActionEverWritesAVerdict:
    """EvaluationLabel is an analyst's judgement, not a read receipt.

    The enum is documented as applied by an authorised evaluator and never
    assigned automatically, and those labels are the input to the
    detection-accuracy statistics. Stamping them in bulk to clear a counter
    would corrupt the measurement they exist to support.
    """

    def test_the_anomaly_action_writes_only_the_read_receipt(self) -> None:
        action = _method(ALERT_REPO, "mark_all_anomalies_reviewed")
        assert "reviewed_at" in action
        assert "evaluation" not in action, (
            "a bulk action assigns an evaluation label, fabricating a verdict"
        )
        for verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_EXPECTED"):
            assert verdict not in action

    def test_an_already_reviewed_anomaly_keeps_its_first_reviewer(self) -> None:
        action = _method(ALERT_REPO, "mark_all_anomalies_reviewed")
        assert "reviewed_at IS NULL" in action

    def test_the_counter_treats_either_kind_of_attention_as_reviewed(self) -> None:
        """Read or judged both count; only the receipt is ever written in bulk.

        Counting the verdict alone left the counter unclearable without
        fabricating one. Counting the receipt alone would have called a
        detection an analyst had already classified "unreviewed".
        """
        counter = _method(ALERT_REPO, "count_unreviewed_anomalies")
        assert "reviewed_at IS NULL" in counter
        assert "UNCLASSIFIED" in counter

    def test_the_screen_predicate_agrees_with_the_counter(self) -> None:
        import ast as _ast

        screen = (
            Path(__file__).resolve().parent.parent
            / "aethra_sec" / "ui" / "screens" / "alerts.py"
        )
        tree = _ast.parse(screen.read_text(encoding="utf-8"))
        fn = next(
            n for n in _ast.walk(tree)
            if isinstance(n, _ast.FunctionDef) and n.name == "_is_unreviewed"
        )
        if (
            fn.body
            and isinstance(fn.body[0], _ast.Expr)
            and isinstance(fn.body[0].value, _ast.Constant)
        ):
            fn.body = fn.body[1:]
        body = _ast.unparse(fn)
        assert "reviewed_at" in body, (
            "the strip counts a different thing from the action that clears it"
        )
        assert "UNCLASSIFIED" in body, (
            "a detection an analyst has already classified would be counted "
            "as unreviewed"
        )
