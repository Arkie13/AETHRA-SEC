"""Every period figure moves with the period, and only those (§117).

Two defects sat behind the same misconception - that a figure's time window is
a display detail rather than part of what the figure means.

**The Dashboard reset only its packet count.** Not because midnight was
mishandled, but because most period figures never reached the screen.
``findings_in_period`` and ``scans_in_period`` were queried on every load and
then dropped; hosts had no period query at all; and the tile beneath "Open
ports" printed the *lifetime* assessment count while sitting in a band captioned
"today". Worse, the protocol donut and the top-talkers bar were repainted on
every live traffic event from the analyzer's rolling **300-second** window - so a
chart captioned "packets · today" showed the last five minutes, and its centre
figure disagreed with the packets tile beside it by orders of magnitude.

**Threat Incidents could not be filtered by date at all**, and its date columns
sorted the *formatted string*: "31 Aug 23:40" sorted after "07 Sep 00:25",
because "3" > "0".

What is pinned here is that a period query is bounded, a state query is not,
that the two are visibly separated, and that no widget quietly keeps a window
of its own.
"""

from __future__ import annotations

import ast
import inspect
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.models.periods import (
    NAMED_RANGES,
    DashboardPeriod,
    local_midnight,
    local_today,
    period_for_range,
)
from aethra_sec.models.system import DashboardSnapshot
from aethra_sec.services.dashboard_service import DashboardService

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
DASHBOARD = PACKAGE / "ui" / "screens" / "dashboard.py"
SERVICE = PACKAGE / "services" / "dashboard_service.py"


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


class _RecordingRepo:
    """Records the bounds each query was given; answers "nothing stored"."""

    def __init__(self, answers: dict[str, Any] | None = None) -> None:
        self.calls: dict[str, tuple[Any, ...]] = {}
        self._answers = answers or {}

    def __getattr__(self, name: str) -> Any:
        def call(*args: Any, **kwargs: Any) -> Any:
            # Keyword values count as much as positional ones: a query given
            # start=/end= by name is bounded exactly as one given them in order.
            self.calls[name] = args + tuple(kwargs.values())
            return self._answers.get(name)

        return call


class _AllowAll:
    def require(self, *_a: Any, **_k: Any) -> None:
        """Permit."""


def _service(**answers: Any):
    repos = {
        name: _RecordingRepo(answers.get(name))
        for name in ("traffic", "alerts", "scans", "hosts", "audit")
    }
    service = DashboardService(
        repos["traffic"], repos["alerts"], repos["scans"],
        repos["hosts"], repos["audit"], _AllowAll(),
    )
    return service, repos


# ---------------------------------------------------------------------------
# Every period metric
# ---------------------------------------------------------------------------
#: Every figure the Dashboard reports over the period, and the query behind it.
PERIOD_QUERIES = (
    ("traffic", "packets_in_period"),
    ("alerts", "count_alerts_in_period"),
    ("alerts", "count_anomalies_in_period"),
    ("alerts", "count_detections_by_severity"),
    ("alerts", "detections_per_interval"),
    ("alerts", "mean_detection_latency"),
    ("traffic", "aggregates_between"),
    ("traffic", "protocol_distribution"),
    # The threat timeline plots alerts; it must move with the period too.
    ("alerts", "search_alerts"),
    ("scans", "count_findings_in_period"),
    ("scans", "count_scans_in_period"),
    ("hosts", "count_seen_in_period"),
    ("hosts", "count_first_seen_in_period"),
)

#: Figures that describe the present and must survive midnight untouched.
STATE_QUERIES = (
    ("scans", "count_open_findings"),
    ("scans", "count_open_ports"),
    ("scans", "count_scans"),
    ("scans", "count_findings_by_risk"),
    ("hosts", "count_all"),
    ("traffic", "total_packets_observed"),
    ("alerts", "count_alerts"),
)


class TestEveryPeriodMetricIsBounded:
    """Not just packets."""

    @pytest.mark.parametrize(("repo", "method"), PERIOD_QUERIES)
    def test_the_query_receives_the_period(self, repo: str, method: str) -> None:
        period = DashboardPeriod.for_day(date(2026, 9, 6))
        service, repos = _service()
        service.snapshot(object(), period=period)

        assert method in repos[repo].calls, (
            f"{repo}.{method} is never called, so the figure it feeds cannot "
            "move when the period does"
        )
        args = repos[repo].calls[method]
        assert period.start in args and period.end in args, (
            f"{repo}.{method} was not given the reporting period"
        )

    @pytest.mark.parametrize(("repo", "method"), STATE_QUERIES)
    def test_state_queries_get_no_period(self, repo: str, method: str) -> None:
        service, repos = _service()
        service.snapshot(object(), period=DashboardPeriod.for_day(date(2026, 9, 6)))
        assert repos[repo].calls.get(method) == (), (
            f"{repo}.{method} is current state but was bounded, so it would "
            "reset at midnight"
        )

    def test_a_new_day_zeroes_every_period_figure(self) -> None:
        """The empty-new-day state, asserted field by field."""
        service, _repos = _service()
        snapshot = service.snapshot(object(), period=DashboardPeriod.today())
        for field in (
            "packets_in_period", "detections_in_period", "snort_alerts_in_period",
            "anomalies_in_period",
            "findings_in_period", "scans_in_period", "hosts_seen_in_period",
            "hosts_discovered_in_period", "high_alerts", "medium_alerts",
            "low_alerts", "info_alerts",
        ):
            assert getattr(snapshot, field) == 0, f"{field} did not reset"
        assert snapshot.traffic_series == ()
        assert snapshot.alert_series == ()
        assert snapshot.protocol_distribution == ()
        assert snapshot.severity_distribution == ()

    def test_a_new_day_leaves_state_figures_standing(self) -> None:
        service, _repos = _service(
            scans={"count_open_findings": 38, "count_open_ports": 25},
            hosts={"count_all": 1912, "count_active_since": 737},
        )
        snapshot = service.snapshot(object(), period=DashboardPeriod.today())
        assert snapshot.open_findings == 38
        assert snapshot.open_ports == 25
        assert snapshot.observed_hosts == 1912
        assert snapshot.active_hosts == 737


class TestNoWidgetKeepsItsOwnWindow:
    """The defect that made a donut captioned "today" show five minutes."""

    def test_live_traffic_events_do_not_repaint_the_period_charts(self) -> None:
        code = _statements(DASHBOARD)
        handler = code[code.index("def handle_event"):]
        handler = handler[: handler.index("\n    def ", 1)]
        for chart in ("_protocol_chart", "_talkers_chart"):
            assert f"{chart}.set_items" not in handler, (
                f"{chart} is repainted from the live analyzer, whose counters "
                "cover a rolling window and not the reporting period"
            )

    def test_the_period_charts_are_painted_from_the_snapshot(self) -> None:
        code = _statements(DASHBOARD)
        update = code[code.index("def _update_charts"):]
        update = update[: update.index("\n    def ", 1)]
        assert "snapshot.protocol_distribution" in update
        assert "snapshot.traffic_series" in update

    def test_the_analyzer_window_is_not_the_reporting_period(self) -> None:
        """Why the two could never have agreed."""
        from aethra_sec.analytics.traffic_analyzer import DEFAULT_WINDOW_SECONDS

        assert DEFAULT_WINDOW_SECONDS == 300
        whole_day = DashboardPeriod.for_day(local_today()).duration_seconds
        assert whole_day == 86_400
        assert DEFAULT_WINDOW_SECONDS < whole_day / 100, (
            "the live analyzer window is a rounding error beside a calendar "
            "day, which is why a chart fed from it could never be 'today'"
        )

    def test_the_service_holds_no_trailing_window_but_host_recency(self) -> None:
        """One deliberate exception, named and documented."""
        code = _statements(SERVICE)
        assert code.count("timedelta(hours=") == 1
        assert "ACTIVE_HOST_RECENCY_HOURS" in code


class TestThePeriodAndStateStripsAreSeparate:
    """A figure's kind must be visible before its value is read."""

    def test_there_are_two_strips_with_their_own_headings(self) -> None:
        code = _statements(DASHBOARD)
        build = code[code.index("def _build_stat_row"):]
        build = build[: build.index("\n    def ", 1)]
        assert "'PERIOD ACTIVITY'" in build
        assert "'CURRENT SECURITY STATE'" in build
        assert build.index("'PERIOD ACTIVITY'") < build.index(
            "'CURRENT SECURITY STATE'"
        )

    def test_the_period_strip_carries_the_period_figures(self) -> None:
        from aethra_sec.ui.screens.dashboard import PERIOD_KPIS

        assert set(PERIOD_KPIS) == {
            "packets", "alerts", "findings_new", "hosts_seen",
        }

    def test_the_state_tiles_are_not_captioned_with_the_period(self) -> None:
        from aethra_sec.ui.screens.dashboard import PERIOD_KPIS

        for key in ("hosts", "ports", "findings"):
            assert key not in PERIOD_KPIS

    def test_findings_and_assessments_reach_the_screen(self) -> None:
        """Both were queried and then thrown away."""
        code = _statements(DASHBOARD)
        stats = code[code.index("def _update_stats"):]
        stats = stats[: stats.index("\n    def ", 1)]
        assert "snapshot.findings_in_period" in stats
        assert "snapshot.scans_in_period" in stats
        assert "snapshot.hosts_seen_in_period" in stats

    def test_the_snapshot_declares_every_period_field(self) -> None:
        fields = set(DashboardSnapshot.__dataclass_fields__)
        for field in (
            "packets_in_period", "detections_in_period", "anomalies_in_period",
            "findings_in_period",
            "scans_in_period", "hosts_seen_in_period",
            "hosts_discovered_in_period",
        ):
            assert field in fields


# ---------------------------------------------------------------------------
# Incident date filtering
# ---------------------------------------------------------------------------
class TestDateRanges:
    """Every option resolves to real datetimes on a half-open window."""

    def test_the_offered_ranges(self) -> None:
        """One list, offered by the record screen and resolved in one place."""
        assert NAMED_RANGES == (
            "Today", "Yesterday", "Last hour", "Last 24 hours",
            "Last 7 days", "Last 30 days", "This month", "Previous month",
            "This year", "All data", "Custom...",
        )

    def test_the_alerts_screen_offers_the_shared_ranges(self) -> None:
        """Not a private list: one had once drifted to "All time"."""
        alerts = _statements(PACKAGE / "ui" / "screens" / "alerts.py")
        assert "list(NAMED_RANGES)" in alerts, (
            "the alerts screen hard-codes its own range list"
        )
        assert "period_for_range" in alerts
        for stale in ("'All time'", '"All time"'):
            assert stale not in alerts, (
                "the Alerts screen still uses its own name for all data"
            )

    def test_the_time_filter_is_called_period(self) -> None:
        alerts = _statements(PACKAGE / "ui" / "screens" / "alerts.py")
        assert "'Period'" in alerts

    def test_a_trailing_range_ends_now(self) -> None:
        """"Last hour" is a window, not a calendar day."""
        now = datetime(2026, 9, 7, 18, 30).astimezone()
        period = period_for_range("Last hour", now)
        assert period is not None and period.start is not None
        assert period.end == now
        assert (period.end - period.start) == timedelta(hours=1)

    def test_the_legacy_all_time_name_still_resolves(self) -> None:
        """A saved preference must not silently become "no filter"."""
        assert period_for_range("All time") is not None
        assert period_for_range("All time").start is None

    @pytest.mark.parametrize(
        "name",
        [n for n in NAMED_RANGES if n != "Custom..."],
    )
    def test_every_range_resolves_to_datetimes(self, name: str) -> None:
        period = period_for_range(name)
        assert period is not None
        assert isinstance(period.end, datetime)
        assert period.start is None or isinstance(period.start, datetime)

    def test_custom_is_answered_by_the_screen(self) -> None:
        assert period_for_range("Custom...") is None

    def test_today_starts_at_local_midnight(self) -> None:
        now = datetime(2026, 9, 7, 0, 25).astimezone()
        period = period_for_range("Today", now)
        assert period is not None
        assert period.start == local_midnight(date(2026, 9, 7))

    def test_yesterday_is_a_whole_closed_day(self) -> None:
        now = datetime(2026, 9, 7, 0, 25).astimezone()
        period = period_for_range("Yesterday", now)
        assert period is not None
        assert period.start == local_midnight(date(2026, 9, 6))
        assert period.end == local_midnight(date(2026, 9, 7))

    def test_yesterday_and_today_neither_overlap_nor_gap(self) -> None:
        now = datetime(2026, 9, 7, 12, 0).astimezone()
        yesterday = period_for_range("Yesterday", now)
        today = period_for_range("Today", now)
        assert yesterday is not None and today is not None
        assert yesterday.end == today.start
        boundary = local_midnight(date(2026, 9, 7))
        assert not yesterday.contains(boundary)
        assert today.contains(boundary)

    def test_last_seven_days_counts_calendar_days(self) -> None:
        """Not a 168-hour window, which drifts through the day."""
        now = datetime(2026, 9, 7, 18, 0).astimezone()
        period = period_for_range("Last 7 days", now)
        assert period is not None
        assert period.start == local_midnight(date(2026, 9, 1))

    def test_previous_month_handles_a_year_boundary(self) -> None:
        now = datetime(2026, 1, 15, 9, 0).astimezone()
        period = period_for_range("Previous month", now)
        assert period is not None
        assert period.start == local_midnight(date(2025, 12, 1))
        assert period.end == local_midnight(date(2026, 1, 1))

    def test_all_data_has_no_lower_bound(self) -> None:
        period = period_for_range("All data")
        assert period is not None and period.start is None


class TestOneParserForEveryCustomRange:
    """Three copies of a date parser would eventually disagree."""

    def test_the_parser_is_defined_once(self) -> None:
        defining = [
            path
            for path in PACKAGE.rglob("*.py")
            if "__pycache__" not in path.parts
            and "def parse_moment(" in path.read_text(encoding="utf-8")
        ]
        assert [p.name for p in defining] == ["periods.py"]

    def test_no_screen_keeps_a_private_copy(self) -> None:
        for name in ("alerts.py", "dashboard.py"):
            code = (PACKAGE / "ui" / "screens" / name).read_text(encoding="utf-8")
            assert "def _parse_moment" not in code, name

    def test_the_custom_option_is_named_once(self) -> None:
        from aethra_sec.models.periods import CUSTOM_RANGE

        assert CUSTOM_RANGE == "Custom..."
        assert CUSTOM_RANGE in NAMED_RANGES


class TestIncidentQueryUsesRealTimestamps:
    """Not string comparison, and not a 23:59:59 cut."""

    def test_the_repository_bounds_are_half_open(self) -> None:
        from aethra_sec.database.repositories.incidents import IncidentRepository

        source = inspect.getsource(IncidentRepository.search)
        assert 'query.gte("created_at"' in source
        assert 'query.lt("created_at"' in source
        assert 'query.lte("created_at"' not in source, (
            "an inclusive upper bound counts a midnight record in both days"
        )

    def test_no_query_is_built_by_concatenating_a_date(self) -> None:
        code = _statements(PACKAGE / "database" / "repositories" / "incidents.py")
        assert "created_at >= '" not in code
        assert "23:59:59" not in code

class TestSortingByStoredInstant:
    """By the stored instant, never by the rendered text."""

    def test_the_table_honours_the_shadow_sort_value(self) -> None:
        from aethra_sec.ui.widgets.tables import DataTable

        source = inspect.getsource(DataTable._sort_value)
        assert "_sort" in source

    def test_sorting_the_formatted_text_would_be_wrong(self) -> None:
        """The concrete failure: August after September."""
        formatted = ["31 Aug 23:40", "07 Sep 00:25", "06 Sep 23:59"]
        assert sorted(formatted) != ["31 Aug 23:40", "06 Sep 23:59", "07 Sep 00:25"]

class TestIncidentDetailKeepsEveryTimestamp:
    """First seen, last seen, created and updated are all stored."""

    def test_the_model_carries_all_four(self) -> None:
        from aethra_sec.models.incident import Incident

        fields = set(Incident.__dataclass_fields__)
        for name in ("first_seen", "last_seen", "created_at", "updated_at"):
            assert name in fields

    def test_the_query_selects_all_four(self) -> None:
        from aethra_sec.database.repositories import incidents as module

        select = module._SELECT
        for name in ("i.first_seen", "i.last_seen", "i.created_at", "i.updated_at"):
            assert name in select


class TestNothingIsFabricated:
    """A period with no activity shows zero, not a filler value."""

    def test_the_service_never_writes(self) -> None:
        code = _statements(SERVICE).upper()
        for statement in ("INSERT INTO", "UPDATE ", "DELETE FROM", "TRUNCATE TABLE"):
            assert statement not in code

    def test_no_dashboard_figure_is_randomised(self) -> None:
        for path in (DASHBOARD, SERVICE):
            code = _statements(path)
            for forbidden in ("random", "randint", "sample(", "choice("):
                assert forbidden not in code

    def test_the_rollover_deletes_nothing(self) -> None:
        code = _statements(DASHBOARD)
        rollover = code[code.index("def _apply_rollover"):]
        rollover = rollover[: rollover.index("\n    def ", 1)]
        for forbidden in ("DELETE", "TRUNCATE", "shutdown", "restart"):
            assert forbidden not in rollover
