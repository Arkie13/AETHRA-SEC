"""The Dashboard's automatic daily reporting reset (§114).

The Dashboard reported over a trailing "last 24 hours", which answers a
different question from the one its tiles claimed to answer. At 00:05 it still
counted almost all of yesterday, and there was no moment at which a new day
began.

It now reports over a calendar period, defaulting to today, and that period
moves to the new day on its own at 00:00:00 local.

What "reset" means here, and what it must never mean
----------------------------------------------------
The rollover changes *query boundaries* and nothing else. No packet, alert,
host, finding or audit record is deleted, rewritten or renumbered by
it, and no service is restarted. Yesterday stays exactly as queryable the
morning after as it was the evening before - these tests assert that directly,
by counting rows before and after.

The other half of the requirement is that a *state* figure must not reset. A
backlog of open findings does not clear because the clock passed midnight, and
showing zero would be a false all-clear. Period figures and state figures are
therefore separate fields, asked with and without bounds respectively.
"""

from __future__ import annotations

import ast
import inspect
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.database.repositories.base import period_bounds
from aethra_sec.models.periods import (
    DashboardPeriod,
    PeriodMode,
    local_midnight,
    local_today,
    next_local_midnight,
)
from aethra_sec.models.system import DashboardSnapshot
from aethra_sec.services.dashboard_service import DashboardService
from aethra_sec.utils.timeutil import UTC, to_local, to_utc, utcnow

ROOT = Path(__file__).resolve().parent.parent
PERIODS = ROOT / "aethra_sec" / "models" / "periods.py"
SERVICE = ROOT / "aethra_sec" / "services" / "dashboard_service.py"
SCREEN = ROOT / "aethra_sec" / "ui" / "screens" / "dashboard.py"


def _at(day: date, hour: int = 0, minute: int = 0, second: int = 0,
        micro: int = 0) -> datetime:
    """A local wall-clock instant on ``day``, as UTC.

    Built the same way the production boundary is - naive local time resolved
    by the OS timezone database - so these tests read in the operator's clock
    and run correctly in any timezone.
    """
    return datetime(
        day.year, day.month, day.day, hour, minute, second, micro
    ).astimezone().astimezone(UTC)


# ---------------------------------------------------------------------------
# The period itself
# ---------------------------------------------------------------------------
class TestTheDashboardOpensOnToday:
    """The default is the calendar day, not a trailing window."""

    def test_the_default_period_is_today(self) -> None:
        assert DashboardPeriod.default().mode is PeriodMode.TODAY

    def test_today_starts_at_local_midnight(self) -> None:
        """00:00:00 local, whatever that is in UTC."""
        period = DashboardPeriod.today(_at(date(2026, 9, 6), 18, 24))
        local_start = to_local(period.start)
        assert local_start is not None
        assert (local_start.hour, local_start.minute, local_start.second) == (0, 0, 0)
        assert local_start.date() == date(2026, 9, 6)

    def test_today_ends_now_not_at_the_end_of_the_day(self) -> None:
        """A period cannot report over hours that have not happened yet."""
        now = _at(date(2026, 9, 6), 18, 24)
        assert DashboardPeriod.today(now).end == now

    def test_the_header_names_the_actual_date_and_span(self) -> None:
        """"Today" alone does not say which today."""
        detail = DashboardPeriod.today(_at(date(2026, 9, 6), 18, 24)).detail
        assert "06 Sep 2026" in detail
        assert "00:00" in detail and "18:24" in detail


class TestTheBoundaryIsHalfOpen:
    """``[start, end)`` - a record at midnight belongs to one day only."""

    def test_one_days_end_is_the_next_days_start(self) -> None:
        assert (
            DashboardPeriod.for_day(date(2026, 9, 6)).end
            == DashboardPeriod.for_day(date(2026, 9, 7)).start
        )

    def test_a_record_at_exactly_midnight_belongs_to_the_new_day(self) -> None:
        """Inclusive on the left, exclusive on the right."""
        midnight = local_midnight(date(2026, 9, 7))
        assert not DashboardPeriod.for_day(date(2026, 9, 6)).contains(midnight)
        assert DashboardPeriod.for_day(date(2026, 9, 7)).contains(midnight)

    def test_the_last_microsecond_of_the_day_is_still_that_day(self) -> None:
        last = local_midnight(date(2026, 9, 7)) - timedelta(microseconds=1)
        assert DashboardPeriod.for_day(date(2026, 9, 6)).contains(last)
        assert not DashboardPeriod.for_day(date(2026, 9, 7)).contains(last)

    def test_the_sql_helper_writes_an_exclusive_upper_bound(self) -> None:
        """The rule has to hold in the query, not only in the value object."""
        clause, params = period_bounds(
            "received_at", local_midnight(date(2026, 9, 6)),
            local_midnight(date(2026, 9, 7)),
        )
        assert "received_at >= %s" in clause
        assert "received_at < %s" in clause
        assert "<=" not in clause, (
            "an inclusive upper bound counts a midnight record in both days"
        )
        assert len(params) == 2

    def test_an_absent_lower_bound_means_everything_up_to_the_end(self) -> None:
        """What the ALL DATA period asks for."""
        clause, params = period_bounds("created_at", None, utcnow())
        assert "created_at >= %s" not in clause
        assert "created_at < %s" in clause
        assert len(params) == 1

    def test_bounding_nothing_produces_no_clause(self) -> None:
        clause, params = period_bounds("created_at", None, None)
        assert clause == "" and params == []


class TestTheRolloverHappensAtMidnight:
    """Driven by a controllable clock, so the boundary is testable now."""

    def test_one_second_before_midnight_nothing_moves(self) -> None:
        period = DashboardPeriod.today(_at(date(2026, 9, 6), 12, 0))
        assert not period.needs_rollover(_at(date(2026, 9, 6), 23, 59, 59))

    def test_at_midnight_the_period_moves_to_the_new_day(self) -> None:
        """23:59:59 on the 6th, then 00:00:00 on the 7th."""
        period = DashboardPeriod.today(_at(date(2026, 9, 6), 23, 59, 59))
        assert period.anchor == date(2026, 9, 6)

        midnight = _at(date(2026, 9, 7))
        assert period.needs_rollover(midnight)

        rolled = period.rolled_over(midnight)
        assert rolled.anchor == date(2026, 9, 7)
        assert rolled.start == local_midnight(date(2026, 9, 7))
        assert rolled.end == midnight

    def test_the_new_day_starts_from_its_own_boundary(self) -> None:
        """Nothing from the 6th can fall inside the 7th's window."""
        rolled = DashboardPeriod.today(_at(date(2026, 9, 6), 23, 59)).rolled_over(
            _at(date(2026, 9, 7), 0, 0, 30)
        )
        assert not rolled.contains(_at(date(2026, 9, 6), 23, 59, 59))
        assert rolled.contains(_at(date(2026, 9, 7), 0, 0, 10))

    def test_rolling_over_again_within_the_day_is_a_no_op(self) -> None:
        rolled = DashboardPeriod.today(_at(date(2026, 9, 7), 0, 0, 1))
        assert not rolled.needs_rollover(_at(date(2026, 9, 7), 9, 30))
        assert rolled.rolled_over(_at(date(2026, 9, 7), 9, 30)) is rolled


class TestTheClockIsTheAuthority:
    """Not "a timer fired", and not "24 hours have passed"."""

    def test_waking_after_a_long_sleep_lands_on_the_real_date(self) -> None:
        """Windows slept through three midnights; the date decides, not the
        number of timers that did or did not fire."""
        period = DashboardPeriod.today(_at(date(2026, 9, 6), 22, 0))
        resumed = _at(date(2026, 9, 9), 7, 30)
        assert period.needs_rollover(resumed)
        assert period.rolled_over(resumed).anchor == date(2026, 9, 9)

    def test_a_clock_put_back_returns_to_the_earlier_day(self) -> None:
        """A correction is still the truth about what day it is."""
        period = DashboardPeriod.today(_at(date(2026, 9, 7), 0, 5))
        corrected = _at(date(2026, 9, 6), 23, 50)
        assert period.needs_rollover(corrected)
        assert period.rolled_over(corrected).anchor == date(2026, 9, 6)

    def test_the_next_boundary_is_derived_from_the_calendar(self) -> None:
        """Not "now plus 24 hours", so a 23- or 25-hour DST day still lands on
        00:00:00 local."""
        boundary = next_local_midnight(_at(date(2026, 9, 6), 18, 24))
        assert boundary == local_midnight(date(2026, 9, 7))
        local = to_local(boundary)
        assert local is not None
        assert (local.hour, local.minute, local.second) == (0, 0, 0)

    def test_midnight_is_built_from_local_wall_clock_time(self) -> None:
        """Which is what keeps it correct across a DST transition.

        Carrying today's UTC offset backwards onto an arbitrary date - what
        ``now.replace(hour=0, ...)`` does - is wrong by an hour either side of
        a transition. Read from the statements only, so the explanation in the
        docstring cannot be what satisfies the assertion.
        """
        code = _statements(PERIODS)
        body = code[code.index("def local_midnight"):]
        body = body[: body.index(chr(10) + "def ", 1)]
        assert ".astimezone()" in body
        assert "replace(hour=0" not in body

    def test_every_midnight_of_the_year_reads_as_midnight_locally(self) -> None:
        """The property that a fixed-offset shortcut would break.

        Runs in whatever timezone this machine is in; in one with a DST
        transition, a boundary built from today's offset lands at 23:00 or
        01:00 on the days around it.
        """
        day = date(2026, 1, 1)
        while day.year == 2026:
            local = to_local(local_midnight(day))
            assert local is not None
            assert (local.hour, local.minute, local.second) == (0, 0, 0), (
                f"{day} did not begin at 00:00:00 local"
            )
            assert local.date() == day
            day += timedelta(days=1)


class TestAHistoricalViewIsNotDraggedForward:
    """An investigation in progress must stay where the operator put it."""

    @pytest.mark.parametrize(
        "period",
        [
            DashboardPeriod.for_day(date(2026, 9, 5)),
            DashboardPeriod.for_month(2026, 8),
            DashboardPeriod.for_year(2025),
        ],
    )
    def test_a_chosen_period_never_rolls_over(self, period: DashboardPeriod) -> None:
        assert not period.rolls_over
        assert not period.needs_rollover(_at(date(2026, 9, 7)))
        assert period.rolled_over(_at(date(2026, 9, 7))) is period

    def test_only_today_rolls_over(self) -> None:
        assert DashboardPeriod.today().rolls_over
        assert not DashboardPeriod.all_data().rolls_over


class TestHistoryStaysAvailable:
    """Yesterday is still yesterday after midnight."""

    def test_yesterdays_window_is_unchanged_by_today(self) -> None:
        """The bounds are pure functions of the date, not of "now"."""
        before = DashboardPeriod.for_day(date(2026, 9, 6))
        after = DashboardPeriod.for_day(date(2026, 9, 6))
        assert (before.start, before.end) == (after.start, after.end)

    def test_the_month_still_contains_the_day_that_just_ended(self) -> None:
        month = DashboardPeriod.for_month(2026, 9)
        assert month.contains(_at(date(2026, 9, 6), 12, 0))
        assert month.contains(_at(date(2026, 9, 30), 23, 59))
        assert not month.contains(_at(date(2026, 10, 1)))

    def test_the_year_covers_every_month_in_it(self) -> None:
        year = DashboardPeriod.for_year(2026)
        assert year.start == local_midnight(date(2026, 1, 1))
        assert year.end == local_midnight(date(2027, 1, 1))

    def test_all_data_has_no_lower_bound(self) -> None:
        assert DashboardPeriod.all_data().start is None


# ---------------------------------------------------------------------------
# Which figures the reset applies to
# ---------------------------------------------------------------------------
class _RecordingRepo:
    """Records the bounds each query was given, and answers "nothing stored".

    ``None`` is what a repository genuinely returns for an absent timestamp,
    and the service turns it into ``0`` where a count is expected - so this
    reproduces an empty installation rather than a half-populated one.
    """

    def __init__(self, answers: dict[str, Any] | None = None) -> None:
        self.calls: dict[str, tuple[Any, ...]] = {}
        self._answers = answers or {}

    def __getattr__(self, name: str) -> Any:
        def call(*args: Any, **kwargs: Any) -> Any:
            self.calls[name] = args
            return self._answers.get(name)

        return call


class _AllowAll:
    """Access control stub: the permission check is tested elsewhere."""

    def require(self, *_args: Any, **_kwargs: Any) -> None:
        """Permit."""


def _service(**answers: Any) -> tuple[DashboardService, dict[str, _RecordingRepo]]:
    """A service wired to recording repositories."""
    repos = {
        name: _RecordingRepo(answers.get(name))
        for name in ("traffic", "alerts", "scans", "hosts", "audit")
    }
    service = DashboardService(
        repos["traffic"], repos["alerts"], repos["scans"],
        repos["hosts"], repos["audit"], _AllowAll(),
    )
    return service, repos


class TestPeriodFiguresAreBoundedAndStateFiguresAreNot:
    """The distinction that stops midnight reading as "the backlog cleared"."""

    def test_every_period_query_receives_the_same_bounds(self) -> None:
        period = DashboardPeriod.for_day(date(2026, 9, 6))
        service, repos = _service()
        service.snapshot(object(), period=period)

        expected = (period.start, period.end)
        for repo, method in (
            ("traffic", "packets_in_period"),
            ("alerts", "count_alerts_in_period"),
            ("alerts", "count_anomalies_in_period"),
            ("alerts", "count_detections_by_severity"),
            ("scans", "count_findings_in_period"),
            ("scans", "count_scans_in_period"),
        ):
            assert repos[repo].calls[method][:2] == expected, (
                f"{repo}.{method} was not given the reporting period, so it "
                "can report on a different span from the rest of the page"
            )

    def test_current_state_queries_are_given_no_period(self) -> None:
        """Open work does not stop being open because a day ended."""
        service, repos = _service()
        service.snapshot(object(), period=DashboardPeriod.for_day(date(2026, 9, 6)))

        for repo, method in (
            ("scans", "count_open_findings"),
            ("scans", "count_open_ports"),
            ("scans", "count_findings_by_risk"),
            ("hosts", "count_all"),
            ("traffic", "total_packets_observed"),
        ):
            assert repos[repo].calls[method] == (), (
                f"{repo}.{method} is a current-state figure but was bounded "
                "by the reporting period, so it would reset at midnight"
            )

    def test_active_hosts_keeps_its_own_recency_window(self) -> None:
        """"What is live on the network now" is not a daily total."""
        service, repos = _service()
        service.snapshot(object(), period=DashboardPeriod.for_day(date(2020, 1, 1)))
        (since,) = repos["hosts"].calls["count_active_since"]
        assert since > _at(date(2020, 1, 2)), (
            "active hosts was bounded to a historical period, which would "
            "claim the network had emptied"
        )

    def test_the_snapshot_records_the_window_it_used(self) -> None:
        period = DashboardPeriod.for_day(date(2026, 9, 6))
        service, _repos = _service()
        snapshot = service.snapshot(object(), period=period)
        assert snapshot.period_mode == "DAY"
        assert snapshot.period_start == period.start
        assert snapshot.period_end == period.end

    def test_a_period_that_tracks_now_is_brought_up_to_date(self) -> None:
        """A period built at start-up must not still end at start-up time."""
        stale = DashboardPeriod.today(utcnow() - timedelta(hours=3))
        service, _repos = _service()
        snapshot = service.snapshot(object(), period=stale)
        assert snapshot.period_end is not None
        assert snapshot.period_end > stale.end


class TestSeverityCountsCannotDisagree:
    """The reconciliation the previous count bug broke."""

    def test_the_headline_total_is_the_sum_of_the_severity_split(self) -> None:
        """Derived, not queried a second time - so they cannot drift."""
        service, _repos = _service(
            alerts={
                "count_detections_by_severity": {
                    "HIGH": 19, "MEDIUM": 21, "LOW": 3, "INFO": 2,
                }
            }
        )
        snapshot = service.snapshot(object(), period=DashboardPeriod.today())
        assert snapshot.detections_in_period == 45
        assert (
            snapshot.high_alerts + snapshot.medium_alerts
            + snapshot.low_alerts + snapshot.info_alerts
        ) == snapshot.detections_in_period

    def test_the_split_counts_both_detection_sources(self) -> None:
        """Snort's share alone disagreed with the IDS Alerts screen."""
        from aethra_sec.database.repositories.alerts import AlertRepository

        source = inspect.getsource(AlertRepository.count_detections_by_severity)
        assert "snort_alerts" in source and "traffic_anomalies" in source

    def test_the_alert_chart_counts_the_same_two_sources(self) -> None:
        from aethra_sec.database.repositories.alerts import AlertRepository

        source = inspect.getsource(AlertRepository.detections_per_interval)
        assert "snort_alerts" in source and "traffic_anomalies" in source

    def test_the_ids_alerts_screen_offers_the_same_today(self) -> None:
        """Otherwise "reconciles with IDS Alerts filtered to today" is not
        something anyone can actually check."""
        source = (ROOT / "aethra_sec" / "ui" / "screens" / "alerts.py").read_text(
            encoding="utf-8"
        )
        assert "NAMED_RANGES" in source, (
            "the Alerts screen offers its own list of ranges, so a range can "
            "mean one thing there and another on the Dashboard"
        )
        assert "period_for_range" in source, (
            "the Alerts screen computes its own idea of today, which can "
            "differ from the Dashboard's"
        )
        assert 'filters["end"] = period.end' in source, (
            "the screen bounds only the start, so its window runs past the "
            "Dashboard's and the two can disagree"
        )
        # "Today" is resolved by the shared table to the Dashboard's own
        # local-midnight boundary, so the two are the identical span.
        from aethra_sec.models.periods import period_for_range

        assert period_for_range("Today").start == DashboardPeriod.today().start


class TestAnEmptyNewDayLooksEmpty:
    """Zero is the correct answer, and yesterday is not carried forward."""

    def test_every_period_figure_is_zero_when_nothing_happened(self) -> None:
        service, _repos = _service()
        snapshot = service.snapshot(object(), period=DashboardPeriod.today())
        assert snapshot.packets_in_period == 0
        assert snapshot.detections_in_period == 0
        assert snapshot.anomalies_in_period == 0
        assert snapshot.findings_in_period == 0

    def test_the_charts_are_empty_rather_than_carried_over(self) -> None:
        service, _repos = _service()
        snapshot = service.snapshot(object(), period=DashboardPeriod.today())
        assert snapshot.traffic_series == ()
        assert snapshot.alert_series == ()
        assert snapshot.protocol_distribution == ()

    def test_an_empty_day_does_not_hide_a_real_backlog(self) -> None:
        """The point of keeping state figures unbounded."""
        service, _repos = _service(scans={"count_open_findings": 517})
        snapshot = service.snapshot(object(), period=DashboardPeriod.today())
        assert snapshot.findings_in_period == 0
        assert snapshot.open_findings == 517

    def test_no_trend_is_shown_without_a_comparable_stored_period(self) -> None:
        """A 100% fall from a period that was never recorded is not a fact."""
        service, _repos = _service()
        snapshot = service.snapshot(object(), period=DashboardPeriod.today())
        assert snapshot.packets_previous_period is None
        assert snapshot.alerts_previous_period is None



class TestTheLoadDoesNoDiscardedWork:
    """A query whose result nothing shows is not worth a second of the load.

    ``network_overview`` fetched top destinations, top ports and a second
    protocol distribution that the Dashboard never displayed. Measured against
    679k stored packets on this installation, the top-ports query alone took
    18 seconds - the optimiser prefers the ``dst_port`` index over the time
    range - and the whole load fell from 18.7s to 4.6s once the three unused
    queries were removed.
    """

    def test_the_overview_fetches_only_what_the_panel_shows(self) -> None:
        service, repos = _service()
        service.network_overview(object(), DashboardPeriod.today())
        assert "top_sources" in repos["traffic"].calls
        for discarded in ("top_destinations", "top_ports"):
            assert discarded not in repos["traffic"].calls, (
                f"{discarded} is queried on every dashboard load and its "
                "result is never displayed"
            )

    def test_the_panel_still_gets_its_talkers_for_the_period(self) -> None:
        period = DashboardPeriod.for_day(date(2026, 9, 6))
        service, repos = _service()
        service.network_overview(object(), period)
        start, _limit, end = repos["traffic"].calls["top_sources"]
        assert (start, end) == (period.start, period.end)

    def test_the_screen_reads_only_the_keys_the_service_returns(self) -> None:
        """A key that quietly disappeared would leave the panel empty."""
        # ast.unparse normalises quoting, so match the text, not the quotes.
        code = _statements(SCREEN)
        assert "overview.get(" in code and "top_sources" in code
        for gone in ("top_destinations", "top_ports"):
            assert gone not in code, (
                f"the screen still reads {gone}, which the service no longer "
                "returns, so the panel would be silently empty"
            )

# ---------------------------------------------------------------------------
# What the reset must never do
# ---------------------------------------------------------------------------
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


class TestTheResetTouchesNoData:
    """It is a change of query boundaries, and only that."""

    @pytest.mark.parametrize("path", [PERIODS, SERVICE, SCREEN])
    def test_no_destructive_statement_anywhere_on_this_path(
        self, path: Path
    ) -> None:
        code = _statements(path).upper()
        for statement in (
            "DELETE FROM", "TRUNCATE TABLE", "DROP TABLE", "ALTER TABLE",
        ):
            assert statement not in code, (
                f"{path.name} contains {statement}; the daily reset must be "
                "implemented entirely through query boundaries"
            )

    def test_the_service_never_writes(self) -> None:
        """A read-only page cannot corrupt the evidence it reports on."""
        code = _statements(SERVICE).upper()
        for statement in ("INSERT INTO", "UPDATE ", "REPLACE INTO"):
            assert statement not in code

    def test_the_rollover_restarts_no_service(self) -> None:
        """Not the application, the capture, TShark or Snort."""
        code = _statements(SCREEN)
        rollover = code[code.index("def _apply_rollover"):]
        rollover = rollover[: rollover.index("\n    def ", 1)]
        for forbidden in (
            "shutdown", "restart", "capture.stop", "capture.start",
            "snort.stop", "snort.start", "destroy(",
        ):
            assert forbidden not in rollover, (
                f"the midnight rollover calls {forbidden!r}; it is a refresh, "
                "not a restart"
            )

    def test_the_rollover_only_changes_the_period_and_repaints(self) -> None:
        code = _statements(SCREEN)
        rollover = code[code.index("def _apply_rollover"):]
        rollover = rollover[: rollover.index("\n    def ", 1)]
        assert "DashboardPeriod.today()" in rollover
        assert "_paint_period" in rollover


class TestTheScreenRollsOverOnItsOwn:
    """Automatic at 00:00:00 - not a button, and not only while visible."""

    def test_a_timer_is_armed_for_the_next_local_midnight(self) -> None:
        code = _statements(SCREEN)
        scheduler = code[code.index("def _schedule_rollover"):]
        scheduler = scheduler[: scheduler.index("\n    def ", 1)]
        assert "next_local_midnight()" in scheduler, (
            "the delay is not computed from the midnight boundary"
        )
        assert "self.after(" in scheduler

    def test_the_pending_timer_is_cancelled_before_re_arming(self) -> None:
        """Otherwise every period change leaks another timer."""
        scheduler = _statements(SCREEN)
        assert "after_cancel" in scheduler

    def test_the_timer_re_arms_itself_after_every_firing(self) -> None:
        code = _statements(SCREEN)
        handler = code[code.index("def _on_rollover_timer"):]
        handler = handler[: handler.index("\n    def ", 1)]
        assert "_schedule_rollover" in handler
        assert "finally" in handler, (
            "a failed check would stop the loop and the page would never roll "
            "over again"
        )

    def test_the_firing_re_checks_the_real_date(self) -> None:
        """A timer firing is not evidence that the date changed."""
        source = inspect.getsource(DashboardPeriod.needs_rollover)
        assert "local_today" in source

    def test_navigating_back_to_the_page_rolls_it_over(self) -> None:
        """Screens are built once and kept, so a stale page would persist."""
        code = _statements(SCREEN)
        on_show = code[code.index("def on_show"):]
        on_show = on_show[: on_show.index("\n    def ", 1)]
        assert "_apply_rollover" in on_show

    def test_leaving_the_page_does_not_cancel_the_timer(self) -> None:
        """The requirement is 00:00, not "00:00 if someone is looking"."""
        code = _statements(SCREEN)
        on_hide = code[code.index("def on_hide"):]
        on_hide = on_hide[: on_hide.index("\n    def ", 1)]
        assert "after_cancel" not in on_hide
        assert "_rollover_job" not in on_hide

    def test_the_timer_is_bounded_so_a_resumed_machine_re_arms(self) -> None:
        """A timer measured against a time that has already passed is useless
        after a resume from sleep."""
        from aethra_sec.ui.screens import dashboard as screen

        assert 0 < screen.MAX_ROLLOVER_SLEEP_MS <= 3_600_000
        assert screen.ROLLOVER_GUARD_MS > 0

    def test_the_periods_offered_are_the_ones_required(self) -> None:
        from aethra_sec.ui.screens import dashboard as screen

        modes = [mode for _label, mode, _choice in screen.PERIOD_BUTTONS]
        assert modes == [
            PeriodMode.TODAY, PeriodMode.DAY, PeriodMode.MONTH,
            PeriodMode.YEAR, PeriodMode.ALL, PeriodMode.CUSTOM,
        ]

    def test_a_custom_range_keeps_the_exclusive_upper_bound(self) -> None:
        """So two adjacent ranges neither overlap nor leave a gap."""
        from aethra_sec.models.periods import parse_moment

        start = parse_moment("2026-09-05 08:30")
        middle = parse_moment("2026-09-06 12:00")
        end = parse_moment("2026-09-07 09:00")
        assert start and middle and end
        first = DashboardPeriod.custom(start, middle)
        second = DashboardPeriod.custom(middle, end)
        assert not first.contains(middle)
        assert second.contains(middle)

    def test_a_custom_range_is_read_as_local_wall_clock_time(self) -> None:
        """The clock the operator is reading, like every other boundary."""
        from aethra_sec.models.periods import parse_moment

        moment = parse_moment("2026-09-05 08:30")
        local = to_local(moment)
        assert local is not None
        assert (local.year, local.month, local.day) == (2026, 9, 5)
        assert (local.hour, local.minute) == (8, 30)

    def test_an_unparseable_range_is_refused_not_guessed(self) -> None:
        from aethra_sec.models.periods import parse_moment

        for bad in ("", "nope", "2026-13-45 99:99", None):
            assert parse_moment(bad) is None

    def test_a_custom_range_does_not_roll_over(self) -> None:
        """It is a historical view like DAY, MONTH and YEAR."""
        period = DashboardPeriod.custom(
            _at(date(2026, 9, 5), 8), _at(date(2026, 9, 6), 12)
        )
        assert not period.rolls_over
        assert not period.needs_rollover(_at(date(2026, 9, 8)))

    def test_the_page_opens_on_today(self) -> None:
        code = _statements(SCREEN)
        assert "DashboardPeriod.default()" in code

    def test_live_updates_do_not_repaint_a_historical_page(self) -> None:
        """Today's live traffic on yesterday's chart would be a fabrication."""
        code = _statements(SCREEN)
        handler = code[code.index("def handle_event"):]
        handler = handler[: handler.index("\n    def ", 1)]
        assert "tracks_now" in handler
        assert "self._period.contains(" in handler, (
            "the trailing live window straddles midnight, so its earlier "
            "points would be drawn under the new day's heading"
        )


# ---------------------------------------------------------------------------
# The boundary, against real SQL
# ---------------------------------------------------------------------------
class TestTheBoundaryInTheDatabase:
    """The half-open rule proved on stored rows, not only in Python.

    Rows are written into the isolated test schema, never a live installation,
    and the test asserts that the row count is the same afterwards - the reset
    reads, and nothing else.
    """

    @staticmethod
    def _insert(db: Any, when: datetime, message: str) -> None:
        """Store one alert at an exact instant."""
        db.execute(
            "INSERT INTO snort_alerts (received_at, message, severity, "
            "created_at) VALUES (%s, %s, 'HIGH', %s)",
            (to_utc(when).replace(tzinfo=None), message,
             to_utc(when).replace(tzinfo=None)),
        )

    def test_a_midnight_record_is_counted_once_and_on_the_new_day(
        self, clean_db: Any
    ) -> None:
        from aethra_sec.database.repositories.alerts import AlertRepository

        alerts = AlertRepository(clean_db)
        sixth, seventh = date(2026, 9, 6), date(2026, 9, 7)
        boundary = local_midnight(seventh)

        self._insert(clean_db, boundary - timedelta(microseconds=1), "last of the 6th")
        self._insert(clean_db, boundary, "first of the 7th")
        self._insert(clean_db, boundary + timedelta(seconds=30), "later on the 7th")

        day_six = DashboardPeriod.for_day(sixth)
        day_seven = DashboardPeriod.for_day(seventh)

        counted_six = alerts.count_alerts_in_period(day_six.start, day_six.end)
        counted_seven = alerts.count_alerts_in_period(day_seven.start, day_seven.end)

        assert counted_six == 1, "the midnight record leaked into the old day"
        assert counted_seven == 2
        assert counted_six + counted_seven == 3, "a record was counted twice"

    def test_yesterday_is_still_queryable_after_midnight(
        self, clean_db: Any
    ) -> None:
        """The whole point: the window moved, the records did not."""
        from aethra_sec.database.repositories.alerts import AlertRepository

        alerts = AlertRepository(clean_db)
        sixth = date(2026, 9, 6)
        for hour in (9, 13, 21):
            self._insert(clean_db, _at(sixth, hour), f"the 6th at {hour}")

        day_six = DashboardPeriod.for_day(sixth)
        before = alerts.count_alerts_in_period(day_six.start, day_six.end)
        stored_before = alerts.count_alerts()

        # The rollover is only this: a different pair of bounds.
        day_seven = DashboardPeriod.for_day(date(2026, 9, 7))
        assert alerts.count_alerts_in_period(day_seven.start, day_seven.end) == 0

        assert alerts.count_alerts_in_period(day_six.start, day_six.end) == before == 3
        assert alerts.count_alerts() == stored_before, (
            "rows were lost across the rollover"
        )

    def test_a_month_and_a_year_still_include_the_day(self, clean_db: Any) -> None:
        from aethra_sec.database.repositories.alerts import AlertRepository

        alerts = AlertRepository(clean_db)
        self._insert(clean_db, _at(date(2026, 9, 6), 12), "September")

        month = DashboardPeriod.for_month(2026, 9)
        year = DashboardPeriod.for_year(2026)
        every = DashboardPeriod.all_data(_at(date(2026, 12, 31)))

        assert alerts.count_alerts_in_period(month.start, month.end) == 1
        assert alerts.count_alerts_in_period(year.start, year.end) == 1
        assert alerts.count_alerts_in_period(every.start, every.end) == 1

    def test_the_severity_split_respects_the_same_boundary(
        self, clean_db: Any
    ) -> None:
        """So the donut cannot include a record the headline count excludes."""
        from aethra_sec.database.repositories.alerts import AlertRepository

        alerts = AlertRepository(clean_db)
        boundary = local_midnight(date(2026, 9, 7))
        self._insert(clean_db, boundary - timedelta(seconds=1), "the 6th")
        self._insert(clean_db, boundary, "the 7th")

        day_seven = DashboardPeriod.for_day(date(2026, 9, 7))
        split = alerts.count_detections_by_severity(day_seven.start, day_seven.end)
        assert sum(split.values()) == 1
        assert split.get("HIGH") == 1


# ---------------------------------------------------------------------------
# Regression: the trailing window this replaced
# ---------------------------------------------------------------------------
class TestTheTrailingWindowIsGone:
    """A rolling 24 hours answered a different question from the one asked."""

    def test_the_service_takes_a_period_not_a_number_of_hours(self) -> None:
        signature = inspect.signature(DashboardService.snapshot)
        assert "period" in signature.parameters
        assert "window_hours" not in signature.parameters, (
            "a widget can still ask for its own trailing window"
        )

    def test_the_network_overview_takes_the_same_period(self) -> None:
        signature = inspect.signature(DashboardService.network_overview)
        assert "period" in signature.parameters
        assert "window_hours" not in signature.parameters

    def test_the_screen_hands_one_period_to_both_queries(self) -> None:
        """Two windows would let the halves of the page disagree."""
        code = _statements(SCREEN)
        refresh = code[code.index("def refresh"):]
        refresh = refresh[: refresh.index("\n    def ", 1)]
        assert refresh.count("period=period") == 2

    def test_the_snapshot_names_period_figures_as_such(self) -> None:
        """``packets_today`` was a claim the trailing window did not support."""
        fields = set(DashboardSnapshot.__dataclass_fields__)
        assert "packets_in_period" in fields
        assert "packets_today" not in fields
        assert "ids_alerts_today" not in fields


# ---------------------------------------------------------------------------
# The screen, driven for real
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def dashboard_screen():
    """A built Dashboard screen on a real Tk root, or a skip where none exists.

    The context is a stub with no services attached, so ``refresh`` returns
    immediately and nothing is queried. What is exercised here is the rollover
    itself: the period the page holds, and the timer that moves it.
    """
    import tkinter as tk
    from types import SimpleNamespace

    from aethra_sec.ui.screens.dashboard import DashboardScreen
    from aethra_sec.ui.theme import apply_theme

    try:
        root = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - headless CI
        pytest.skip(f"no display: {exc}")
    root.geometry("1500x950+30+30")
    fonts = apply_theme(root)

    posted: list[str] = []
    app = SimpleNamespace(
        context=SimpleNamespace(
            dashboard=None, health=None, capture=None, snort=None,
            access=None, current_session=None,
        ),
        fonts=fonts,
        set_status=posted.append,
        navigate=lambda *_a, **_k: None,
    )
    screen = DashboardScreen(root, app)
    screen.build()
    screen.pack(fill="both", expand=True)
    root.update()
    screen.posted = posted  # type: ignore[attr-defined]
    yield screen
    root.destroy()


class TestTheScreenRollsTheDayOverForReal:
    """Not asserted from the source - the widget is built and driven."""

    def test_it_opens_on_today(self, dashboard_screen: Any) -> None:
        assert dashboard_screen._period.mode is PeriodMode.TODAY
        assert dashboard_screen._period.anchor == local_today()

    def test_the_header_names_todays_date(self, dashboard_screen: Any) -> None:
        shown = dashboard_screen._period_detail.cget("text")
        assert local_today().strftime("%d %b %Y") in shown
        assert dashboard_screen._period_name.cget("text") == "TODAY"

    def test_the_all_data_heading_is_named_as_the_control_is(self) -> None:
        """``str(PeriodMode.ALL)`` is "ALL", which no button says."""
        assert DashboardPeriod.all_data().heading == "ALL DATA"
        assert DashboardPeriod.today().heading == "TODAY"

    def test_a_timer_is_armed_for_the_boundary(self, dashboard_screen: Any) -> None:
        dashboard_screen._schedule_rollover()
        assert dashboard_screen._rollover_job is not None

    def test_re_arming_replaces_the_timer_rather_than_adding_one(
        self, dashboard_screen: Any
    ) -> None:
        """A leaked timer per period change would fire repeatedly."""
        dashboard_screen._schedule_rollover()
        first = dashboard_screen._rollover_job
        dashboard_screen._schedule_rollover()
        second = dashboard_screen._rollover_job
        assert first != second
        assert first not in dashboard_screen.tk.call("after", "info")

    def test_a_page_left_on_yesterday_moves_to_today(
        self, dashboard_screen: Any
    ) -> None:
        """What the machine does after sleeping through midnight."""
        yesterday = local_today() - timedelta(days=1)
        dashboard_screen._period = DashboardPeriod.today(
            local_midnight(yesterday) + timedelta(hours=22)
        )
        assert dashboard_screen._period.anchor == yesterday

        moved = dashboard_screen._apply_rollover()

        assert moved is True
        assert dashboard_screen._period.anchor == local_today()
        assert local_today().strftime("%d %b %Y") in (
            dashboard_screen._period_detail.cget("text")
        )
        assert any("New day" in message for message in dashboard_screen.posted)

    def test_rolling_over_twice_in_one_day_does_nothing(
        self, dashboard_screen: Any
    ) -> None:
        dashboard_screen._period = DashboardPeriod.today()
        assert dashboard_screen._apply_rollover() is False

    def test_a_historical_view_is_left_alone(self, dashboard_screen: Any) -> None:
        """An investigation must not be moved under the operator."""
        chosen = DashboardPeriod.for_day(date(2026, 9, 5))
        dashboard_screen._period = chosen
        assert dashboard_screen._apply_rollover() is False
        assert dashboard_screen._period is chosen
        dashboard_screen._period = DashboardPeriod.today()

    def test_the_period_buttons_are_all_present(
        self, dashboard_screen: Any
    ) -> None:
        assert set(dashboard_screen._period_buttons) == {
            PeriodMode.TODAY, PeriodMode.DAY, PeriodMode.MONTH,
            PeriodMode.YEAR, PeriodMode.ALL, PeriodMode.CUSTOM,
        }

    def test_choosing_all_data_removes_the_lower_bound(
        self, dashboard_screen: Any
    ) -> None:
        dashboard_screen._select_mode(PeriodMode.ALL)
        assert dashboard_screen._period.start is None
        assert dashboard_screen._period_name.cget("text") == "ALL DATA"
        dashboard_screen._select_mode(PeriodMode.TODAY)
        assert dashboard_screen._period.mode is PeriodMode.TODAY


    def test_the_captions_state_the_period_and_the_bucket(
        self, dashboard_screen: Any
    ) -> None:
        """"(24h)" beside a figure counted over a calendar day is wrong, and
        it would become wrong on its own at midnight."""
        snapshot = DashboardSnapshot(
            generated_at=utcnow(), period_label="06 Sep 2026",
            alert_bucket_minutes=180,
        )
        dashboard_screen._restate_chart_captions(snapshot)

        assert "06 sep 2026" in (
            dashboard_screen._traffic_card.subtitle_label.cget("text")
        )
        ids = dashboard_screen._ids_card.subtitle_label.cget("text")
        assert "per 3 hours" in ids and "06 sep 2026" in ids

    def test_the_bucket_is_named_in_the_unit_it_is_read_in(self) -> None:
        from aethra_sec.ui.screens.dashboard import _bucket_text

        assert _bucket_text(15) == "per 15 minutes"
        assert _bucket_text(180) == "per 3 hours"
        assert _bucket_text(1440) == "per day"
        assert _bucket_text(10080) == "per week"

    def test_a_whole_snapshot_renders_without_touching_a_service(
        self, dashboard_screen: Any
    ) -> None:
        """Every widget path is walked, including the empty states.

        A period with genuinely nothing in it is the state the Dashboard is in
        for the first seconds of every new day, so it has to render.
        """
        empty = DashboardSnapshot(
            generated_at=utcnow(),
            period_mode="TODAY",
            period_start=local_midnight(local_today()),
            period_end=utcnow(),
            period_label="Today",
            period_detail="empty day",
            open_findings=38,
        )
        dashboard_screen._apply((empty, {"top_sources": []}))
        dashboard_screen.update_idletasks()

        # The period figures read zero; the state figures do not.
        assert dashboard_screen._stat_cards["packets"]._value.cget("text") == "0"
        assert dashboard_screen._stat_cards["alerts"]._value.cget("text") == "0"
        assert dashboard_screen._stat_cards["findings"]._value.cget("text") == "38"

    def test_the_period_tiles_are_captioned_with_the_period(
        self, dashboard_screen: Any
    ) -> None:
        """And the state tiles are not, so the two cannot be confused."""
        from aethra_sec.ui.screens.dashboard import PERIOD_KPIS

        snapshot = DashboardSnapshot(generated_at=utcnow(), period_label="Today")
        dashboard_screen._apply((snapshot, {"top_sources": []}))

        for key in PERIOD_KPIS:
            assert "TODAY" in dashboard_screen._stat_cards[key]._label.cget("text")
        for key in ("findings", "hosts", "ports"):
            assert "TODAY" not in dashboard_screen._stat_cards[key]._label.cget("text")
