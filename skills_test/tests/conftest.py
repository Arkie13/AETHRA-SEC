"""Record which behavioural tests failed, and what code they were about.

pytest reports failures to a human; the runner needs them as data, joined to
the ``@covers`` target so the diagnosis can show the right baseline function.
This hook writes that join to ``skills_test/reports/failures.json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills_test.tools.coverage import ATTRIBUTE  # noqa: E402

#: Reuse the application suite's fixtures - the isolated test schema, the
#: packet factories - rather than building a second, divergent set.
pytest_plugins = ["tests.conftest"]

REPORTS = ROOT / "skills_test" / "reports"
FAILURES = REPORTS / "failures.json"

_results: list[dict] = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return
    target = getattr(item.function, ATTRIBUTE, None)
    _results.append({
        "nodeid": item.nodeid,
        "name": item.name,
        "outcome": report.outcome,
        "message": _short(report),
        "docstring": (item.function.__doc__ or "").strip(),
        "target": target.as_dict() if target is not None else None,
    })


def _short(report) -> str:
    """The assertion line, without the whole traceback."""
    if report.outcome != "failed":
        return ""
    text = str(getattr(report, "longrepr", "") or "")
    lines = [l for l in text.splitlines() if l.startswith("E ")]
    return "\n".join(line[2:].strip() for line in lines[:8]) or text[-400:]


def pytest_sessionfinish(session, exitstatus):
    REPORTS.mkdir(parents=True, exist_ok=True)
    FAILURES.write_text(
        json.dumps({
            "exitstatus": int(exitstatus),
            "total": len(_results),
            "failed": sum(1 for r in _results if r["outcome"] == "failed"),
            "passed": sum(1 for r in _results if r["outcome"] == "passed"),
            "results": _results,
        }, indent=2),
        encoding="utf-8",
    )
