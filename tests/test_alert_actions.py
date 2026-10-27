"""Every IDS Alerts action must work on the row that is selected (§122).

The buttons were all wired and all worked - for a Snort alert. The screen shows
both detection sources, and on an installation where Snort is quiet almost
every row an operator clicks is one of AETHRA-SEC's own detections. For those,
Details and the three evaluation buttons answered "Select an
alert first" with a row plainly selected, which is indistinguishable from a
dead button.

The worst of it was not cosmetic. ``traffic_anomalies.evaluation`` has always
existed and nothing ever wrote it, so an analyst's verdict could be recorded
for a Snort alert and not for a detection this system raised itself - and those
verdicts are exactly what the detection-accuracy statistics are computed from.
On a quiet-Snort installation the measurement was unanswerable for the large
majority of detections.

What is pinned here:

**A verdict is stored beside the detection, never over it.** The rule that
fired, the value it measured, the threshold it crossed and the raw Snort text
are untouched by any analyst action, so a detection classified FALSE_POSITIVE
stays traceable to the evidence that produced it.

**Authorisation is enforced in the service, not by hiding a button.** Disabling
a control is a courtesy to the operator; the refusal has to happen server-side
or it is not a control at all.

**A button that cannot act is disabled rather than silently inert.** The two
Snort-only workflow states are disabled for an anomaly, because it has no
column to hold them.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.models.enums import AlertStatus, EvaluationLabel
from aethra_sec.services.snort_service import SnortService
from aethra_sec.ui.screens import alerts as screen

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
SCREEN = PACKAGE / "ui" / "screens" / "alerts.py"


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


def _method(name: str) -> str:
    """One screen method's statements."""
    code = _statements(SCREEN)
    # The trailing parenthesis matters: without it a lookup for _apply
    # matches a longer name such as _apply_guide_context.
    start = code.index(f"def {name}(")
    rest = code[start + 4 :]
    end = rest.index("\n    def ") if "\n    def " in rest else len(rest)
    return code[start : start + 4 + end]


# ---------------------------------------------------------------------------
# Both sources reach every applicable action
# ---------------------------------------------------------------------------
class TestEveryActionHandlesBothSources:
    """The defect: eight of nine buttons were Snort-only."""

    @pytest.mark.parametrize(
        "handler", ["_show_detail", "_classify", "_set_status"]
    )
    def test_the_handler_checks_for_an_anomaly(self, handler: str) -> None:
        body = _method(handler)
        assert "_selected_anomaly()" in body, (
            f"{handler} never looks at an AETHRA-SEC detection, so it does "
            "nothing for the majority of rows on this screen"
        )

    def test_details_opens_for_an_anomaly(self) -> None:
        """Both kinds of row route through the one detail path."""
        body = _method("_show_detail")
        assert "_open_detail" in body
        assert "snort=False" in body, (
            "an AETHRA-SEC detection no longer reaches its own renderer"
        )

    def test_classify_routes_an_anomaly(self) -> None:
        assert "_classify_anomaly" in _method("_classify")

    def test_no_handler_tells_the_operator_to_select_what_is_selected(
        self,
    ) -> None:
        """"Select an alert first" with a row selected reads as broken."""
        for handler in ("_show_detail", "_classify"):
            body = _method(handler)
            refusal = body.find("Select a")
            anomaly = body.find("_selected_anomaly")
            assert anomaly >= 0 and (refusal < 0 or anomaly < refusal), (
                f"{handler} refuses before it has looked for an anomaly"
            )


class TestTheEvaluationReachesTheDatabase:
    """The column existed; nothing wrote it."""

    def test_the_repository_can_write_an_anomaly_evaluation(self) -> None:
        assert hasattr(AlertRepository, "set_anomaly_evaluation")
        source = inspect.getsource(AlertRepository.set_anomaly_evaluation)
        assert "UPDATE traffic_anomalies SET evaluation" in source

    def test_the_service_exposes_it(self) -> None:
        assert hasattr(SnortService, "classify_anomaly")

    def test_classifying_also_stamps_the_receipt(self) -> None:
        """Forming a judgement means having read it."""
        source = inspect.getsource(AlertRepository.set_anomaly_evaluation)
        assert "reviewed_at = %s" in source
        assert "reviewed_at IS NULL" in source, (
            "re-classifying rewrites who read it first"
        )

    def test_it_reports_whether_a_row_was_updated(self) -> None:
        source = inspect.getsource(AlertRepository.set_anomaly_evaluation)
        assert "return bool(changed)" in source

    def test_a_missing_detection_is_an_error_not_a_silent_success(self) -> None:
        source = inspect.getsource(SnortService.classify_anomaly)
        assert "raise" in source


class TestRawEvidenceIsNeverRewritten:
    """§21 - the verdict sits beside the detection."""

    def test_the_evaluation_update_touches_nothing_else(self) -> None:
        source = inspect.getsource(AlertRepository.set_anomaly_evaluation)
        update = source[source.index("UPDATE traffic_anomalies SET evaluation"):]
        update = update[: update.index(")")]
        for evidence in (
            "rule_id", "observed_value", "threshold_value", "evidence",
            "src_ip", "dst_ip", "detected_at", "first_seen", "severity",
        ):
            assert evidence not in update, (
                f"classifying rewrites {evidence}, which is detection evidence"
            )

    def test_no_analyst_action_deletes_a_detection(self) -> None:
        for name in ("set_anomaly_evaluation", "mark_anomaly_reviewed"):
            source = inspect.getsource(getattr(AlertRepository, name))
            assert "DELETE" not in source.upper()

    def test_the_detail_view_does_not_write(self) -> None:
        """Opening a record must not change it.

        Asserted on calls rather than bare words: the view legitimately
        *reads* ``reviewed_at`` to display it, and matching the substring
        "review" would have flagged that as a write.
        """
        body = _method("_render_anomaly_detail")
        for call in (
            "snort.classify", "snort.set_status", "snort.review_anomaly",
            ".execute(", "run_async(",
        ):
            assert call not in body, f"the detail view calls {call}"


class TestAuthorizationIsEnforcedInTheService:
    """§16 - hiding a button is not a security control."""

    @pytest.mark.parametrize(
        ("method", "permission"),
        [
            ("classify_anomaly", "EVALUATION_CLASSIFY"),
            ("review_anomaly", "ALERT_MANAGE"),
            ("classify", "EVALUATION_CLASSIFY"),
            ("set_status", "ALERT_MANAGE"),
        ],
    )
    def test_the_service_requires_a_permission(
        self, method: str, permission: str
    ) -> None:
        source = inspect.getsource(getattr(SnortService, method))
        assert "self._access.require" in source
        assert permission in source

    def test_the_permission_check_precedes_the_write(self) -> None:
        for method in ("classify_anomaly", "review_anomaly"):
            source = inspect.getsource(getattr(SnortService, method))
            assert source.index("_access.require") < source.index("self._alerts")


class TestEveryStateChangeIsAudited:
    """§17."""

    @pytest.mark.parametrize("method", ["classify_anomaly", "review_anomaly"])
    def test_it_records_an_audit_event(self, method: str) -> None:
        source = inspect.getsource(getattr(SnortService, method))
        assert "self._audit.record" in source
        assert 'target_type="anomaly"' in source
        assert "target_id=anomaly_id" in source

    def test_the_audit_names_no_secret(self) -> None:
        for method in ("classify_anomaly", "review_anomaly"):
            source = inspect.getsource(getattr(SnortService, method))
            for secret in ("password", "token", "hash"):
                assert secret not in source.lower()


# ---------------------------------------------------------------------------
# The interface
# ---------------------------------------------------------------------------
class TestButtonState:
    """§13 - a live-looking control that does nothing is a broken one."""

    def test_row_actions_are_tracked(self) -> None:
        code = _statements(SCREEN)
        assert "_row_actions" in code
        assert "def _paint_actions" in code

    def test_nothing_selected_disables_them(self) -> None:
        body = _method("_paint_actions")
        assert "disabled" in body
        assert "usable = False" in body

    def test_an_anomaly_is_only_offered_what_it_can_accept(self) -> None:
        """A detection must never be offered a Snort-only workflow action.

        That set is empty now: Acknowledge and Escalate were removed as
        unused, and every remaining action - Details, Mark reviewed and the
        two evaluations - works for both detection sources. The check stays
        because the distinction is real and the gate must remain wired, so
        re-adding a Snort-only action cannot silently offer it on a row that
        has no such column.
        """
        body = _method("_paint_actions")
        assert "_snort_only" in body, (
            "the gate that withholds Snort-only actions from an AETHRA-SEC "
            "detection is gone"
        )
        from aethra_sec.models.enums import AlertStatus
        from aethra_sec.ui.screens.alerts import AlertsScreen

        code = _statements(SCREEN)
        for removed in ("AlertStatus.ACKNOWLEDGED", "AlertStatus.ESCALATED"):
            assert removed not in code, (
                f"{removed} is set from the Alerts screen again; if that is "
                "intended it must also be added back to _snort_only"
            )
        # The states themselves survive: stored alerts still carry them.
        assert AlertStatus.ACKNOWLEDGED and AlertStatus.ESCALATED

    def test_export_is_not_a_row_action(self) -> None:
        """It exports the filtered set, so it needs no selection."""
        code = _statements(SCREEN)
        assert "toolbar.add_button('Export', self._export)" in code

    def test_the_buttons_start_disabled(self) -> None:
        body = _method("build")
        assert "_paint_actions()" in body

    def test_selection_repaints_them(self) -> None:
        assert "_paint_actions()" in _method("_preview")

    def test_a_reload_repaints_them(self) -> None:
        """set_rows clears the selection, so the buttons must follow."""
        assert "_paint_actions()" in _method("_apply")


class TestBusyState:
    """§23 - a second click must not start a second write."""

    def test_an_action_blocks_the_buttons(self) -> None:
        code = _statements(SCREEN)
        assert "def _begin_action" in code
        assert "_action_busy = True" in _method("_begin_action")

    def test_busy_disables_every_row_action(self) -> None:
        assert "if self._action_busy:" in _method("_paint_actions")

    def test_success_is_reported_only_on_the_success_path(self) -> None:
        """§14 / §27 - never "Success" for an operation that failed."""
        body = _method("_after_action")
        assert "self.status(message)" in body
        assert "self.refresh()" in body, "the table is not re-read after a write"

    def test_a_failure_reports_a_failure(self) -> None:
        body = _method("_action_failed")
        assert "show_error_message" in body
        assert "_action_busy = False" in body

    def test_the_counters_are_re_read_not_adjusted(self) -> None:
        """§18 - the database is the source of truth."""
        body = _method("_after_action")
        for forged in ("+= 1", "-= 1", "count +", "count -"):
            assert forged not in body


class TestDetailShowsOnlyRealFields:
    """§1 / §20 - absent values say so rather than being filled in."""

    def test_an_absent_value_is_named_not_invented(self) -> None:
        body = _method("_render_anomaly_detail")
        assert "Not recorded" in body

    def test_missing_evidence_says_so(self) -> None:
        assert "recorded no evidence fields" in _method("_render_anomaly_detail")

    def test_it_does_not_point_at_the_removed_incident_screen(self) -> None:
        """An incident id with nowhere to open it is a dead end."""
        body = _method("_render_anomaly_detail")
        assert "incident_id" not in body

    def test_it_reports_review_and_evaluation_state(self) -> None:
        body = _method("_render_anomaly_detail")
        assert "reviewed_at" in body and "evaluation" in body


class TestExportRespectsTheFilters:
    """§9 - what is exported is what is on screen."""

    def test_it_exports_the_visible_rows(self) -> None:
        body = _method("_export")
        assert "visible_only=True" in body, (
            "export writes rows the operator's filters excluded"
        )

    def test_it_goes_through_the_report_service(self) -> None:
        body = _method("_export")
        assert "reports.export_records" in body

    def test_the_writer_escapes_formula_leads(self) -> None:
        """CSV injection, already guarded - asserted so it stays that way."""
        from aethra_sec.reports import writers

        assert writers._FORMULA_LEAD
        for lead in ("=", "+", "-", "@"):
            assert lead in writers._FORMULA_LEAD


class TestAdvertisedInteractionsExist:
    """§11 / §12 - the table says these work, so they must."""

    def test_double_click_opens_details(self) -> None:
        code = _statements(SCREEN)
        assert "on_activate=lambda _row: self._show_detail()" in code

    def test_right_click_actions_are_registered(self) -> None:
        code = _statements(SCREEN)
        assert "RowAction(" in code

    def test_row_actions_reuse_the_toolbar_handlers(self) -> None:
        """§12 - no duplicate action logic."""
        code = _statements(SCREEN)
        for handler in ("_show_detail", "_set_status", "_classify"):
            assert f"self.{handler}" in code
