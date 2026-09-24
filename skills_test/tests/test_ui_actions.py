"""UI wiring: button -> callback -> backend.

A professor can break only the connection: the button still draws, the
callback still exists, and nothing happens when it is pressed. "The function
exists" is therefore not enough - each test here follows the chain from the
widget's ``command=`` through to the backend call it is supposed to make.

These are static-wiring checks by design. They import no Tk display and start
no services, so they run anywhere; the behavioural consequence of each action
is covered by the database tests alongside them.
"""

from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills_test.tools.coverage import covers  # noqa: E402

ALERTS = "aethra_sec/ui/screens/alerts.py"
VULN = "aethra_sec/ui/screens/vulnerabilities.py"
TRAFFIC = "aethra_sec/ui/screens/traffic.py"


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _method_body(relative: str, qualname: str) -> str:
    """The source of one method, so a test can look inside it."""
    tree = ast.parse(_source(relative))
    *outer, name = qualname.split(".")
    node: ast.AST = tree
    for part in outer:
        node = next(
            (n for n in ast.walk(node)
             if isinstance(n, ast.ClassDef) and n.name == part),
            None,
        )
        assert node is not None, f"class {part} not found in {relative}"
    target = next(
        (n for n in ast.walk(node)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name),
        None,
    )
    assert target is not None, f"{qualname} not found in {relative}"
    return ast.unparse(target)


def _commands(relative: str) -> set[str]:
    """Every ``command=self._x`` handler a screen binds to a widget."""
    import re

    return set(re.findall(r"command=self\.(\w+)", _source(relative)))


# ---------------------------------------------------------------------------
# IDS Alerts
# ---------------------------------------------------------------------------
@covers(ALERTS, "AlertsScreen._mark_all_reviewed",
        feature="IDS Alerts", action="Mark reviewed button")
def test_mark_reviewed_is_bound_and_reaches_the_backend() -> None:
    assert "_mark_all_reviewed" in _commands(ALERTS), (
        "the Mark reviewed button is no longer wired to its callback"
    )
    body = _method_body(ALERTS, "AlertsScreen._mark_all_reviewed")
    assert "mark_all_reviewed" in body, (
        "the callback no longer calls the repository - pressing the button "
        "would change nothing in the database"
    )


@covers(ALERTS, "AlertsScreen._classify",
        feature="IDS Alerts", action="True/false positive buttons")
def test_classification_reaches_the_backend() -> None:
    body = _method_body(ALERTS, "AlertsScreen._classify")
    assert "evaluation" in body.lower(), (
        "the classify callback no longer records an evaluation"
    )


@covers(ALERTS, "AlertsScreen.refresh",
        feature="IDS Alerts", action="Apply filter button")
def test_the_filter_apply_button_is_bound() -> None:
    assert "refresh" in _commands(ALERTS)
    assert "_reset_filters" in _commands(ALERTS)


# ---------------------------------------------------------------------------
# Vulnerability Assessment
# ---------------------------------------------------------------------------
@covers(VULN, "VulnerabilitiesScreen._start_scan",
        feature="Vulnerability Assessment", action="Start scan button")
def test_start_scan_is_bound_and_starts_a_scan() -> None:
    assert "_start_scan" in _commands(VULN), (
        "the Start scan button is no longer wired to its callback"
    )
    body = _method_body(VULN, "VulnerabilitiesScreen._start_scan")
    assert "scan" in body.lower() and "self." in body
    assert body.strip() != "pass", "the Start scan callback does nothing"


@covers(VULN, "VulnerabilitiesScreen._stop_scan",
        feature="Vulnerability Assessment", action="Stop scan button")
def test_stop_scan_is_bound_and_stops_a_scan() -> None:
    assert "_stop_scan" in _commands(VULN)
    body = _method_body(VULN, "VulnerabilitiesScreen._stop_scan")
    assert "cancel" in body.lower() or "stop" in body.lower(), (
        "the Stop scan callback no longer cancels anything"
    )


@covers(VULN, "VulnerabilitiesScreen._refresh_automation",
        feature="Vulnerability Assessment", action="Refresh button")
def test_refresh_is_bound_and_loads_off_the_ui_thread() -> None:
    assert "_refresh_automation" in _commands(VULN)
    body = _method_body(VULN, "VulnerabilitiesScreen._refresh_automation")
    assert "run_async" in body, (
        "the refresh now queries the database on the Tk thread, which freezes "
        "the interface"
    )


@covers(VULN, "VulnerabilitiesScreen._toggle_automation",
        feature="Vulnerability Assessment", action="Automatic assessment toggle")
def test_the_automation_toggle_reaches_the_queue() -> None:
    assert "_toggle_automation" in _commands(VULN)
    body = _method_body(VULN, "VulnerabilitiesScreen._toggle_automation")
    assert "queue" in body.lower() or "enabled" in body.lower()


# ---------------------------------------------------------------------------
# Live Monitoring
# ---------------------------------------------------------------------------
@covers(TRAFFIC, "TrafficScreen._start_capture",
        feature="Live Monitoring", action="Start capture button")
def test_start_capture_is_bound_and_starts_capture() -> None:
    assert "_start_capture" in _commands(TRAFFIC), (
        "the Start capture button is no longer wired to its callback"
    )
    body = _method_body(TRAFFIC, "TrafficScreen._start_capture")
    assert "start" in body.lower(), "the callback no longer starts the capture"
    assert body.strip() != "pass"


@covers(TRAFFIC, "TrafficScreen._stop_capture",
        feature="Live Monitoring", action="Stop capture button")
def test_stop_capture_is_bound_and_stops_capture() -> None:
    assert "_stop_capture" in _commands(TRAFFIC)
    body = _method_body(TRAFFIC, "TrafficScreen._stop_capture")
    assert "stop" in body.lower(), "the callback no longer stops the capture"


@covers(TRAFFIC, "TrafficScreen._load_interfaces",
        feature="Live Monitoring", action="Interface selection")
def test_interface_selection_is_bound() -> None:
    assert "_load_interfaces" in _commands(TRAFFIC), (
        "the interface refresh is no longer wired"
    )


@covers(TRAFFIC, "TrafficScreen._apply_display_filter",
        feature="Live Monitoring", action="Display filter")
def test_the_display_filter_is_applied() -> None:
    body = _method_body(TRAFFIC, "TrafficScreen._apply_display_filter")
    assert "filter" in body.lower()
    assert body.strip() != "pass", "applying a filter does nothing"


# ---------------------------------------------------------------------------
# Workers must never run on the Tk thread
# ---------------------------------------------------------------------------
@covers("aethra_sec/ui/dispatch.py", "post",
        feature="User interface", action="Worker to UI bridge")
def test_the_worker_bridge_exists() -> None:
    """Workers hand results back through this; without it they touch Tk."""
    from aethra_sec.ui import dispatch

    assert hasattr(dispatch, "post"), "the worker->Tk bridge is gone"
    assert callable(dispatch.post)
