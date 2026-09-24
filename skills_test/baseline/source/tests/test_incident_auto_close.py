"""Open incidents must mean "needs attention now" (§120).

Nothing in AETHRA-SEC had ever closed an incident. The correlation engine
opened one for every real detection, and only an analyst clicking Resolve could
close it - which, on a live installation, had happened zero times in three
weeks. The figure therefore was not a backlog at all; it was a running total of
everything ever detected, and 485 of the 578 it counted had had no new evidence
for over a day.

The fix is to close what has gone quiet, not to hide it. An incident is closed
once its *last evidence* is older than the configured window - measured from
evidence, not from when the incident was created, so an attack running for
three days keeps its incident open the whole time because every matching packet
refreshes ``last_seen``.

Three things this must never become:

**A deletion.** The row keeps its evidence, its timeline and its notes, and
stays searchable under any historical period. Only the claim that it is
*outstanding* is retracted, and each retraction is audited with its reason.

**A silent edit of someone's work.** An incident a person has moved to
INVESTIGATING or ACKNOWLEDGED is theirs. Closing it out from under them would
be worse than a high count, so only untouched NEW incidents are closed.

**A way to make a real backlog look clear.** Zeroing the counter on a timer
would report 485 unexamined detections as nothing to do. What falls to zero
here is the count of incidents with recent evidence, which is a fact about the
network rather than about the clock.
"""

from __future__ import annotations

import ast
import inspect
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY
from aethra_sec.database.repositories.incidents import IncidentRepository
from aethra_sec.models.enums import IncidentStatus, Severity, ThreatCategory
from aethra_sec.models.incident import Incident
from aethra_sec.services.correlation_service import CorrelationService
from aethra_sec.utils.timeutil import utcnow

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
SETTING = "incidents.auto_close_hours"


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


def _incident(
    repo: IncidentRepository,
    reference: str,
    *,
    last_seen_hours_ago: float,
    status: IncidentStatus = IncidentStatus.NEW,
) -> int:
    """Store one incident whose evidence stopped ``hours`` ago."""
    when = utcnow() - timedelta(hours=last_seen_hours_ago)
    incident_id = repo.create(
        Incident(
            reference=reference, title=f"Incident {reference}",
            description="d", category=ThreatCategory.PORT_SCAN,
            severity=Severity.MEDIUM, confidence=50, status=status,
            correlation_key=reference, first_seen=when, last_seen=when,
            created_at=when, updated_at=when,
        )
    )
    # ``create`` stamps its own timestamps, so the evidence times are set to
    # what the test needs afterwards.
    # ``create`` stamps created_at with the present, and ``search`` filters
    # on created_at - so an incident whose evidence is old must have an old
    # created_at too, or a historical period could never contain it.
    repo.db.execute(
        "UPDATE incidents SET first_seen = %s, last_seen = %s, "
        "created_at = %s, status = %s WHERE id = %s",
        (when.replace(tzinfo=None), when.replace(tzinfo=None),
         when.replace(tzinfo=None), str(status), incident_id),
    )
    return incident_id


class _Settings:
    def __init__(self, **values: Any) -> None:
        self.values = {SETTING: 24, "correlation.enabled": True, **values}

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self.values.get(key, default))

    def get_bool(self, key: str, default: bool = False) -> bool:
        return bool(self.values.get(key, default))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


# ---------------------------------------------------------------------------
# The policy
# ---------------------------------------------------------------------------
class TestTheSettingExists:
    """It is configurable, bounded, and can be switched off."""

    def test_the_setting_is_declared(self) -> None:
        spec = SETTING_SPEC_BY_KEY.get(SETTING)
        assert spec is not None, "the window would not survive a restart"
        assert spec.value_type == "int"

    def test_it_defaults_to_a_day(self) -> None:
        assert SETTING_SPEC_BY_KEY[SETTING].default == 24

    def test_zero_disables_it(self) -> None:
        """Some deployments want every incident to await a person."""
        assert SETTING_SPEC_BY_KEY[SETTING].minimum == 0
        source = inspect.getsource(CorrelationService.close_stale_incidents)
        assert "if hours <= 0:" in source
        assert "return 0" in source

    def test_it_is_bounded(self) -> None:
        assert SETTING_SPEC_BY_KEY[SETTING].maximum <= 8760


class TestClosingIsNotDeleting:
    """The evidence outlives the claim that it is outstanding."""

    def test_the_repository_never_deletes(self) -> None:
        """Read from the statements: the docstring explains the deletion it
        is not doing, and would otherwise match."""
        code = _statements(
            PACKAGE / "database" / "repositories" / "incidents.py"
        )
        action = code[code.index("def close_stale"):]
        action = action[: action.index(chr(10) + "    def ", 1)]
        assert "DELETE" not in action.upper()
        assert "UPDATE incidents SET status" in action

    def test_the_service_never_deletes(self) -> None:
        code = _statements(PACKAGE / "services" / "correlation_service.py")
        action = code[code.index("def close_stale_incidents"):]
        action = action[: action.index(chr(10) + "    def ", 1)]
        assert "DELETE" not in action.upper()

    def test_each_closure_is_audited(self) -> None:
        source = inspect.getsource(CorrelationService.close_stale_incidents)
        assert "self._audit.record" in source
        assert "INCIDENT_UPDATED" in source
        assert "for incident_id in closed" in source, (
            "closures are audited in bulk, so the trail cannot say which "
            "incidents were closed"
        )

    def test_the_audit_states_the_reason(self) -> None:
        source = inspect.getsource(CorrelationService.close_stale_incidents)
        assert "no new evidence" in source
        assert "retained" in source


class TestOnlyUntouchedIncidentsClose:
    """Work a person has picked up is theirs."""

    def test_only_new_is_selected(self) -> None:
        code = _statements(
            PACKAGE / "database" / "repositories" / "incidents.py"
        )
        action = code[code.index("def close_stale"):]
        action = action[: action.index(chr(10) + "    def ", 1)]
        assert "IncidentStatus.NEW" in action
        for owned in ("INVESTIGATING", "ACKNOWLEDGED"):
            assert owned not in action

    def test_the_update_re_checks_the_status(self) -> None:
        """Between the SELECT and the UPDATE somebody may have claimed it."""
        source = inspect.getsource(IncidentRepository.close_stale)
        update = source[source.index("UPDATE incidents"):]
        assert "AND status = %s" in update


class TestTheCutoffIsEvidenceNotAge:
    """An attack running for a week keeps its incident open."""

    def test_the_query_bounds_last_seen(self) -> None:
        source = inspect.getsource(IncidentRepository.close_stale)
        assert "last_seen < %s" in source
        assert "created_at" not in source, (
            "closing on creation time would retire an incident that is still "
            "receiving evidence"
        )

    def test_the_service_measures_from_now(self) -> None:
        source = inspect.getsource(CorrelationService.close_stale_incidents)
        assert "utcnow() - timedelta(hours=hours)" in source


class TestItRunsOnItsOwn:
    """No operator action, and no separate scheduler."""

    def test_correlation_calls_it(self) -> None:
        source = inspect.getsource(CorrelationService.correlate_recent)
        assert "close_stale_incidents()" in source

    def test_it_runs_before_correlating(self) -> None:
        """So the count is right even on a tick that finds no new evidence."""
        source = inspect.getsource(CorrelationService.correlate_recent)
        assert source.index("close_stale_incidents") < source.index(
            "uncorrelated_alerts"
        )

    def test_a_failure_does_not_stop_correlation(self) -> None:
        source = inspect.getsource(CorrelationService.close_stale_incidents)
        assert "except Exception" in source
        assert "return 0" in source


class TestTheDashboardFigureIsUnchangedInMeaning:
    """Open incidents is still current state, not a period figure.

    The Dashboard no longer shows it - the Threat Incidents screen was
    removed - but the repository query keeps its meaning for the backend.
    """

    def test_count_open_is_still_unbounded(self) -> None:
        source = inspect.getsource(IncidentRepository.count_open)
        assert "last_seen" not in source
        assert "_OPEN_STATUSES" in source

    def test_closed_is_not_an_open_status(self) -> None:
        from aethra_sec.database.repositories import incidents as module

        assert "CLOSED" not in module._OPEN_STATUSES
        assert not IncidentStatus.CLOSED.is_open


# ---------------------------------------------------------------------------
# Against the database
# ---------------------------------------------------------------------------
class TestAgainstStoredIncidents:
    """The behaviour, on real rows."""

    def test_a_quiet_incident_closes(self, clean_db: Any) -> None:
        repo = IncidentRepository(clean_db)
        _incident(repo, "INC-OLD", last_seen_hours_ago=48)
        closed = repo.close_stale(utcnow() - timedelta(hours=24))
        assert len(closed) == 1
        assert repo.count_open() == 0

    def test_an_active_incident_stays_open(self, clean_db: Any) -> None:
        """Created a week ago, but evidence arrived a minute ago."""
        repo = IncidentRepository(clean_db)
        incident_id = _incident(repo, "INC-LIVE", last_seen_hours_ago=0.01)
        clean_db.execute(
            "UPDATE incidents SET created_at = %s WHERE id = %s",
            ((utcnow() - timedelta(days=7)).replace(tzinfo=None), incident_id),
        )
        assert repo.close_stale(utcnow() - timedelta(hours=24)) == []
        assert repo.count_open() == 1

    @pytest.mark.parametrize(
        "status", [IncidentStatus.INVESTIGATING, IncidentStatus.ACKNOWLEDGED]
    )
    def test_an_owned_incident_is_left_alone(
        self, clean_db: Any, status: IncidentStatus
    ) -> None:
        repo = IncidentRepository(clean_db)
        _incident(repo, "INC-OWNED", last_seen_hours_ago=200, status=status)
        assert repo.close_stale(utcnow() - timedelta(hours=24)) == []
        assert repo.count_open() == 1

    def test_nothing_is_deleted(self, clean_db: Any) -> None:
        repo = IncidentRepository(clean_db)
        for index in range(5):
            _incident(repo, f"INC-{index}", last_seen_hours_ago=100)
        repo.close_stale(utcnow() - timedelta(hours=24))
        assert clean_db.query_value("SELECT COUNT(*) FROM incidents") == 5
        assert repo.count_open() == 0
        assert len(repo.search(limit=100)) == 5, (
            "closed incidents are no longer searchable"
        )

    def test_a_closed_incident_keeps_its_evidence_times(
        self, clean_db: Any
    ) -> None:
        repo = IncidentRepository(clean_db)
        _incident(repo, "INC-OLD", last_seen_hours_ago=48)
        before = clean_db.query_one(
            "SELECT first_seen, last_seen FROM incidents WHERE reference = 'INC-OLD'"
        )
        repo.close_stale(utcnow() - timedelta(hours=24))
        after = clean_db.query_one(
            "SELECT first_seen, last_seen, status, resolved_at FROM incidents "
            "WHERE reference = 'INC-OLD'"
        )
        assert after["first_seen"] == before["first_seen"]
        assert after["last_seen"] == before["last_seen"]
        assert after["status"] == "CLOSED"
        assert after["resolved_at"] is not None, "the closure has no timestamp"

    def test_running_twice_closes_nothing_the_second_time(
        self, clean_db: Any
    ) -> None:
        repo = IncidentRepository(clean_db)
        _incident(repo, "INC-OLD", last_seen_hours_ago=48)
        cutoff = utcnow() - timedelta(hours=24)
        assert len(repo.close_stale(cutoff)) == 1
        assert repo.close_stale(cutoff) == []

    @staticmethod
    def _hours_into_yesterday() -> float:
        """Hours ago that lands in the middle of yesterday, locally.

        Computed rather than guessed: "30 hours ago" is two days back when the
        console is used after midnight, which is exactly when an operator is
        looking at this screen.
        """
        from aethra_sec.models.periods import DashboardPeriod, local_today

        yesterday = DashboardPeriod.for_day(local_today() - timedelta(days=1))
        midday = yesterday.start + timedelta(hours=12)
        return (utcnow() - midday).total_seconds() / 3600.0

    def test_a_historical_period_still_finds_it(self, clean_db: Any) -> None:
        """Closing must not remove an incident from yesterday's report."""
        from aethra_sec.models.periods import DashboardPeriod, local_today

        repo = IncidentRepository(clean_db)
        _incident(repo, "INC-OLD",
                  last_seen_hours_ago=self._hours_into_yesterday())
        yesterday = DashboardPeriod.for_day(local_today() - timedelta(days=1))
        # Cut off at this morning's midnight, so everything in yesterday is
        # stale regardless of what time of day the suite happens to run.
        repo.close_stale(yesterday.end)
        found = repo.search(start=yesterday.start, end=yesterday.end, limit=100)
        assert len(found) == 1, "a closed incident vanished from a past period"
        assert found[0].reference == "INC-OLD"
        assert found[0].status is IncidentStatus.CLOSED

    def test_the_created_count_for_that_day_is_unchanged(
        self, clean_db: Any
    ) -> None:
        """Closing an incident must not alter what a past day reports."""
        from aethra_sec.models.periods import DashboardPeriod, local_today

        repo = IncidentRepository(clean_db)
        _incident(repo, "INC-OLD",
                  last_seen_hours_ago=self._hours_into_yesterday())
        yesterday = DashboardPeriod.for_day(local_today() - timedelta(days=1))
        before = repo.count_created_in_period(yesterday.start, yesterday.end)
        assert before == 1, "the fixture did not land in yesterday"
        repo.close_stale(yesterday.end)
        assert repo.count_created_in_period(yesterday.start, yesterday.end) == before
