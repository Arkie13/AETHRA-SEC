"""The Alerts screen must show every detection, whichever engine made it (§65).

An operator simulated a flood, AETHRA-SEC detected it, and the Alerts screen
stayed empty. Both facts were true: the screen read ``snort_alerts`` only, and
Snort was not running, so a detection the system had certainly made was
reachable nowhere except by opening the incident it produced.

The screen now shows both sources. What must never happen is the other failure
mode - presenting one engine's finding as though it came from the other. A
detection from the threshold rules is not a Snort alert, and the row says so.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCREEN = ROOT / "aethra_sec" / "ui" / "screens" / "alerts.py"
SERVICE = ROOT / "aethra_sec" / "services" / "snort_service.py"


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
    code = _code_only(path)
    # The trailing parenthesis matters: without it a lookup for _apply
    # matches a longer name such as _apply_guide_context.
    start = code.index(f"def {name}(")
    rest = code[start + 4 :]
    end = rest.index("\n    def ") if "\n    def " in rest else len(rest)
    return code[start : start + 4 + end]


class TestBothSourcesReachTheScreen:
    """A detection that exists must be findable."""

    def test_the_screen_loads_anomalies_as_well_as_alerts(self) -> None:
        code = _code_only(SCREEN)
        assert "search_anomalies" in code, (
            "the Alerts screen reads Snort alerts only, so a detection from "
            "AETHRA-SEC's own rules would be invisible"
        )

    def test_the_service_exposes_anomalies_behind_the_view_permission(self) -> None:
        action = _method(SERVICE, "search_anomalies")
        assert "Permission.ALERT_VIEW" in action

    def test_rows_from_both_sources_share_one_ordering(self) -> None:
        """Newest first, whichever engine raised it."""
        apply = _method(SCREEN, "_apply")
        assert "_sort" in apply and "reverse=True" in apply


class TestProvenanceIsNeverBlurred:
    """The worse failure would be showing an anomaly as a Snort alert."""

    def test_there_is_an_origin_column(self) -> None:
        code = _code_only(SCREEN)
        # ast.unparse normalises quoting, so match the text, not the quotes.
        assert "Detected by" in code, "no column names the detecting engine"

    def test_each_row_carries_its_origin(self) -> None:
        assert "ORIGIN_AETHRA" in _method(SCREEN, "_anomaly_rows")
        assert "ORIGIN_SNORT" in _method(SCREEN, "_alert_rows")

    def test_an_anomaly_is_labelled_as_aethra_not_snort(self) -> None:
        rows = _method(SCREEN, "_anomaly_rows")
        assert "'AETHRA-SEC'" in rows or '"AETHRA-SEC"' in rows

    def test_an_anomaly_does_not_borrow_a_snort_workflow_status(self) -> None:
        """Anomalies have no NEW/REVIEWED status; inventing one would mislead."""
        rows = _method(SCREEN, "_anomaly_rows")
        for borrowed in ("AlertStatus", "'NEW'", '"NEW"', "REVIEWED"):
            assert borrowed not in rows, (
                f"an anomaly row carries {borrowed}, a Snort-only workflow value"
            )


class TestActionsCannotHitTheWrongRecord:
    """Snort's workflow actions apply to Snort's alerts only."""

    def test_the_alert_selector_rejects_an_anomaly_row(self) -> None:
        selector = _method(SCREEN, "_selected_alert")
        assert "ORIGIN_SNORT" in selector, (
            "a status change could be applied to a row that has no such status"
        )

    def test_there_is_a_separate_selector_for_anomalies(self) -> None:
        code = _code_only(SCREEN)
        assert "_selected_anomaly" in code


class TestTheWorkerNeverTouchesTk:
    """A Tk variable read off the Tk thread is a threading fault."""

    def test_the_status_filter_is_read_before_the_worker_starts(self) -> None:
        """This regressed once: the load silently returned nothing."""
        refresh = _method(SCREEN, "refresh")
        worker_at = refresh.index("def work")
        assert "self._status_var.get()" in refresh[:worker_at], (
            "the status filter is read on the Tk thread"
        )
        assert "_status_var" not in refresh[worker_at:], (
            "the worker reads a Tk variable, which is not thread-safe and "
            "makes the load return nothing"
        )


class TestTheScreenUpdatesDuringAnAttack:
    """§66 - a detection nobody sees arrive is a detection that did not happen.

    The screen refreshed only on ``SNORT_ALERT_RECEIVED``. A detection from
    AETHRA-SEC's own rules was stored, counted and correlated into an incident,
    but never repainted the table - so an operator watching during an attack
    saw an unchanged screen and reasonably concluded nothing had been detected.
    """

    def test_an_anomaly_event_refreshes_the_screen(self) -> None:
        handler = _method(SCREEN, "handle_event")
        assert "TRAFFIC_ANOMALY_DETECTED" in handler, (
            "the Alerts screen ignores detections from AETHRA-SEC's own rules, "
            "so the table goes stale during an attack"
        )

    def test_snort_alerts_still_refresh_it(self) -> None:
        handler = _method(SCREEN, "handle_event")
        assert "SNORT_ALERT_RECEIVED" in handler

    def test_both_trigger_the_same_reload(self) -> None:
        """One refresh path, so the two sources cannot drift apart."""
        handler = _method(SCREEN, "handle_event")
        assert handler.count("self.refresh()") == 1, (
            "the two detection sources take different refresh paths"
        )

    def test_the_event_reaches_screens_at_all(self) -> None:
        """A handler for an event the shell never forwards would be dead code."""
        app = (
            Path(__file__).resolve().parent.parent
            / "aethra_sec" / "ui" / "app.py"
        ).read_text(encoding="utf-8")
        forwarded = app[app.index("_UI_EVENTS") : app.index("_UI_EVENTS") + 900]
        assert "TRAFFIC_ANOMALY_DETECTED" in forwarded
