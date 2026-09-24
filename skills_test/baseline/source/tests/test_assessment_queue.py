"""Automatic assessment must never become a network scanner (§124).

The service closes a loop that was open: PyShark already observed every host an
operator was typing into the target field, so assessment can select its own
targets. What makes that safe rather than reckless is that it *selects* and
hands each target to the existing ``NmapService``, which validates it, enforces
the authorised networks, checks ``scan.run`` and audits the decision. There is
one path to the Nmap subprocess, and it is the reviewed one.

Four independent limits are pinned here, because any one of them failing turns
a monitoring tool into something that scans a network continuously:

**Authorisation.** A host outside the configured networks is marked SKIPPED and
never offered to Nmap.

**Cooldown.** A host assessed inside the reassessment interval is not due, so a
chatty host cannot trigger a scan per packet.

**Concurrency.** A burst of newly discovered hosts becomes a queue rather than a
process per host.

**Attempt cap.** A host whose assessment keeps failing stops being retried.

Also pinned: the service never invents a host. Discovery is what the capture
pipeline does from real packets; this reads that inventory and nothing else.
"""

from __future__ import annotations

import ast
import inspect
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.models.enums import AssessmentState, EvidenceSource, ScanTrigger
from aethra_sec.models.host import Host
from aethra_sec.services.assessment_queue import (
    SETTING_ENABLED,
    SETTING_EXCLUDED,
    SETTING_INTERVAL_HOURS,
    SETTING_MAX_ATTEMPTS,
    SETTING_MAX_CONCURRENT,
    SETTING_NEW_HOSTS,
    AssessmentQueueService,
)
from aethra_sec.utils.timeutil import utcnow

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
MODULE = PACKAGE / "services" / "assessment_queue.py"
AUTHORIZED = ("192.168.0.0/16", "10.0.0.0/8")


class _Settings:
    def __init__(self, **values: Any) -> None:
        self.values: dict[str, Any] = {
            SETTING_ENABLED: True,
            SETTING_NEW_HOSTS: True,
            SETTING_INTERVAL_HOURS: 6,
            SETTING_MAX_CONCURRENT: 2,
            SETTING_MAX_ATTEMPTS: 3,
            SETTING_EXCLUDED: "",
            **values,
        }

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        return bool(self.values.get(key, default))

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self.values.get(key, default))


class _Hosts:
    """The inventory, and a record of every state change written to it."""

    def __init__(self, hosts: list[Host] | None = None) -> None:
        self.hosts = hosts or []
        self.states: list[tuple[int, AssessmentState]] = []
        self.db = None

    def assessment_candidates(self, limit: int = 200) -> list[Host]:
        return [
            host for host in self.hosts
            if host.assessment_state
            not in (AssessmentState.SCANNING, AssessmentState.SKIPPED)
        ][:limit]

    def set_assessment_state(self, host_id: int, state: AssessmentState, **_: Any):
        self.states.append((host_id, state))
        for host in self.hosts:
            if host.id == host_id:
                host.assessment_state = state

    def assessment_state_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for host in self.hosts:
            key = str(host.assessment_state)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def last_assessment_time(self):
        return None

    def last_discovery_time(self):
        return None


class _Nmap:
    """Records what it was asked to scan; starts nothing."""

    def __init__(self) -> None:
        self.started: list[tuple[str, ScanTrigger]] = []
        self._next = 100

    def start_scan(self, _session: Any, target: str, **kwargs: Any) -> int:
        self.started.append((target, kwargs.get("trigger")))
        self._next += 1
        return self._next

    def running_scans(self):
        return ()


def _host(
    host_id: int,
    address: str,
    *,
    state: AssessmentState = AssessmentState.DISCOVERED,
    assessed_hours_ago: float | None = None,
    attempts: int = 0,
    source: EvidenceSource = EvidenceSource.PYSHARK,
) -> Host:
    # These stand for hosts capture actually observed. The model's own default
    # is LEGACY - a row whose origin was never established - and such a host is
    # deliberately never queued, so a fixture has to say how it was discovered.
    return Host(
        id=host_id, ip_address=address, assessment_state=state,
        assessment_attempts=attempts,
        discovery_source=source,
        last_assessed_at=(
            None if assessed_hours_ago is None
            else utcnow() - timedelta(hours=assessed_hours_ago)
        ),
    )


def _queue(hosts: list[Host], **settings: Any):
    inventory = _Hosts(hosts)
    nmap = _Nmap()
    service = AssessmentQueueService(
        inventory, nmap, _Settings(**settings), authorized_networks=AUTHORIZED
    )
    service.attach_session(object())
    # No real machine's addresses in these tests, so nothing is "our own".
    service._is_own_address = lambda _address: False
    return service, inventory, nmap


def _statements(path: Path) -> str:
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


# ---------------------------------------------------------------------------
# Authorisation
# ---------------------------------------------------------------------------
class TestOnlyAuthorizedNetworks:
    """§7 - it must never become an unrestricted scanner."""

    @pytest.mark.parametrize(
        ("address", "authorized"),
        [
            ("192.168.0.1", True),
            ("192.168.44.9", True),
            ("10.1.2.3", True),
            ("8.8.8.8", False),
            ("142.251.150.4", False),
            ("172.16.0.1", False),
            ("", False),
            ("not-an-address", False),
        ],
    )
    def test_membership(self, address: str, authorized: bool) -> None:
        service, _inv, _nmap = _queue([])
        assert service.is_authorized(address) is authorized

    def test_an_unauthorized_host_is_skipped_not_queued(self) -> None:
        service, _inv, nmap = _queue([_host(1, "8.8.8.8")])
        due, state, reason = service.eligibility(service._hosts.hosts[0])
        assert not due
        assert state is AssessmentState.SKIPPED
        assert "authorised" in reason
        assert service.run_cycle() == 0
        assert nmap.started == []

    def test_the_refusal_is_recorded_so_it_is_decided_once(self) -> None:
        service, inventory, _nmap = _queue([_host(1, "8.8.8.8")])
        service.run_cycle()
        assert (1, AssessmentState.SKIPPED) in inventory.states

    def test_an_excluded_address_is_skipped(self) -> None:
        service, _inv, nmap = _queue(
            [_host(1, "192.168.0.50")], **{SETTING_EXCLUDED: "192.168.0.50"}
        )
        assert service.run_cycle() == 0
        assert nmap.started == []

    def test_the_monitoring_host_is_never_scanned(self) -> None:
        service, _inv, nmap = _queue([_host(1, "192.168.0.104")])
        service._is_own_address = lambda address: address == "192.168.0.104"
        assert service.run_cycle() == 0
        assert nmap.started == []


class TestCooldown:
    """§6 - a chatty host must not be scanned repeatedly."""

    def test_a_recently_assessed_host_is_not_due(self) -> None:
        service, _inv, _nmap = _queue(
            [_host(1, "192.168.0.5", assessed_hours_ago=1)]
        )
        due, state, reason = service.eligibility(service._hosts.hosts[0])
        assert not due
        assert state is AssessmentState.COOLDOWN
        assert reason == "assessed recently"

    def test_it_becomes_due_once_the_interval_passes(self) -> None:
        service, _inv, nmap = _queue(
            [_host(1, "192.168.0.5", assessed_hours_ago=7)]
        )
        assert service.run_cycle() == 1
        assert nmap.started[0][0] == "192.168.0.5"

    def test_the_interval_is_configurable(self) -> None:
        service, _inv, _nmap = _queue(
            [_host(1, "192.168.0.5", assessed_hours_ago=7)],
            **{SETTING_INTERVAL_HOURS: 24},
        )
        due, state, _reason = service.eligibility(service._hosts.hosts[0])
        assert not due and state is AssessmentState.COOLDOWN

    def test_a_never_assessed_host_is_due_immediately(self) -> None:
        service, _inv, nmap = _queue([_host(1, "192.168.0.5")])
        assert service.run_cycle() == 1
        assert nmap.started[0][1] is ScanTrigger.AUTOMATIC_DISCOVERY

    def test_new_host_assessment_can_be_switched_off(self) -> None:
        service, _inv, nmap = _queue(
            [_host(1, "192.168.0.5")], **{SETTING_NEW_HOSTS: False}
        )
        assert service.run_cycle() == 0
        assert nmap.started == []


class TestConcurrency:
    """§25 - a burst of hosts is a queue, not a process per host."""

    def test_the_limit_is_respected(self) -> None:
        hosts = [_host(n, f"192.168.0.{n}") for n in range(1, 10)]
        service, _inv, nmap = _queue(hosts, **{SETTING_MAX_CONCURRENT: 2})
        assert service.run_cycle() == 2
        assert len(nmap.started) == 2

    def test_a_second_cycle_does_not_exceed_it(self) -> None:
        hosts = [_host(n, f"192.168.0.{n}") for n in range(1, 10)]
        service, _inv, nmap = _queue(hosts, **{SETTING_MAX_CONCURRENT: 2})
        service.run_cycle()
        assert service.run_cycle() == 0, "the in-flight scans were not counted"
        assert len(nmap.started) == 2

    def test_the_limit_is_bounded(self) -> None:
        service, _inv, _nmap = _queue([], **{SETTING_MAX_CONCURRENT: 9999})
        assert service._max_concurrent() <= 8


class TestRetryCap:
    """A permanently unreachable host must stop being scanned."""

    def test_a_repeatedly_failing_host_stops_being_retried(self) -> None:
        """It stays FAILED - visibly - rather than being relabelled "Skipped".

        Relabelling a host whose assessment kept failing as SKIPPED hid the
        failure behind the word used for "deliberately not assessed". The cap
        now stops the retries while the state keeps saying what happened.
        """
        service, _inv, nmap = _queue(
            [_host(1, "192.168.0.5", state=AssessmentState.FAILED, attempts=3)]
        )
        due, state, reason = service.eligibility(service._hosts.hosts[0])
        assert not due
        assert state is AssessmentState.FAILED
        assert "retry limit" in reason
        assert service.run_cycle() == 0
        assert nmap.started == []

    def test_it_is_retried_below_the_cap(self) -> None:
        service, _inv, nmap = _queue(
            [_host(1, "192.168.0.5", state=AssessmentState.FAILED, attempts=1)]
        )
        assert service.run_cycle() == 1


class TestPauseAndResume:
    """§9 - automatic assessment can be stopped."""

    def test_disabled_starts_nothing(self) -> None:
        service, _inv, nmap = _queue(
            [_host(1, "192.168.0.5")], **{SETTING_ENABLED: False}
        )
        assert service.run_cycle() == 0
        assert nmap.started == []

    def test_no_session_starts_nothing(self) -> None:
        """An automatic scan still runs as somebody, and is audited as such."""
        service, _inv, nmap = _queue([_host(1, "192.168.0.5")])
        service.attach_session(None)
        assert service.run_cycle() == 0
        assert nmap.started == []

    def test_pausing_goes_through_the_audited_settings_path(self) -> None:
        source = inspect.getsource(AssessmentQueueService.set_enabled)
        assert "self._settings.set(session" in source, (
            "the pause flag is set without a permission check or an audit "
            "record"
        )

    def test_it_is_on_by_default_but_bounded_by_authorised_networks(self) -> None:
        """Fully automated by default, yet it scans nothing until the operator
        configures the authorised networks: a host outside them is SKIPPED.

        The default is on so discovery-to-assessment is closed out of the box;
        the authorised-network boundary, not an off switch, is what keeps it
        from being a network scanner. It remains switchable from the
        Vulnerability Assessment screen.
        """
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY

        assert SETTING_SPEC_BY_KEY[SETTING_ENABLED].default is True

        # With the default on but no authorised networks, an observed host is
        # skipped rather than scanned.
        service = AssessmentQueueService(
            _Hosts([_host(1, "192.168.0.5")]), _Nmap(),
            _Settings(), authorized_networks=(),
        )
        service.attach_session(object())
        service._is_own_address = lambda _address: False
        assert service.run_cycle() == 0


class TestItDelegatesRatherThanScanning:
    """§26 / §32 - one reviewed path to the Nmap subprocess."""

    def test_it_never_builds_a_command(self) -> None:
        code = _statements(MODULE)
        for forbidden in ("subprocess", "Popen", "os.system", "nmap.exe", "-sV"):
            assert forbidden not in code, f"the queue reaches Nmap directly ({forbidden})"

    def test_it_calls_the_existing_service(self) -> None:
        source = inspect.getsource(AssessmentQueueService._start)
        assert "self._nmap.start_scan(" in source

    def test_the_profile_comes_from_the_catalogue(self) -> None:
        """Automatic scans cannot use arbitrary Nmap arguments."""
        source = inspect.getsource(AssessmentQueueService._start)
        assert "profile_key=" in source
        assert "arguments" not in source

    def test_it_records_why_the_scan_ran(self) -> None:
        service, _inv, nmap = _queue(
            [_host(1, "192.168.0.5"), _host(2, "192.168.0.6", assessed_hours_ago=9)],
            **{SETTING_MAX_CONCURRENT: 2},
        )
        service.run_cycle()
        triggers = dict(nmap.started)
        assert triggers["192.168.0.5"] is ScanTrigger.AUTOMATIC_DISCOVERY
        assert triggers["192.168.0.6"] is ScanTrigger.SCHEDULED_REASSESSMENT


class TestItInventsNothing:
    """§23 - discovery is the capture pipeline's job, from real packets."""

    def test_it_never_generates_an_address(self) -> None:
        code = _statements(MODULE)
        for forbidden in ("random", "range(", "sample(", "choice("):
            assert forbidden not in code

    def test_it_only_reads_the_inventory(self) -> None:
        code = _statements(MODULE)
        for forbidden in ("INSERT INTO hosts", "upsert", "bulk_upsert"):
            assert forbidden not in code, (
                "the queue creates hosts; discovery belongs to capture"
            )

    def test_an_empty_inventory_starts_nothing(self) -> None:
        service, _inv, nmap = _queue([])
        assert service.run_cycle() == 0
        assert nmap.started == []

    def test_statistics_are_counted_from_the_inventory(self) -> None:
        hosts = [
            _host(1, "192.168.0.5", state=AssessmentState.COMPLETED),
            _host(2, "8.8.8.8", state=AssessmentState.SKIPPED),
        ]
        service, _inv, _nmap = _queue(hosts)
        stats = service.statistics()
        assert stats.completed == 1
        assert stats.skipped == 1
        assert stats.total == 2


class TestStateSurvivesARestart:
    """§24 - the database is the source of truth."""

    def test_the_state_lives_on_the_host_row(self) -> None:
        from aethra_sec.database.repositories.hosts import HostRepository

        assert hasattr(HostRepository, "set_assessment_state")
        source = inspect.getsource(HostRepository.set_assessment_state)
        assert "UPDATE hosts SET" in source

    def test_a_stuck_scan_is_released_at_startup(self) -> None:
        """Otherwise a crash mid-scan retires the host permanently."""
        from aethra_sec.database.repositories.hosts import HostRepository

        source = inspect.getsource(HostRepository.reset_stuck_assessments)
        assert "SCANNING" in source
        assert "DISCOVERED" in source

    def test_completion_is_settled_from_the_scan_row(self) -> None:
        """Not from another service's in-memory list, which this cannot see."""
        # Statements only: the docstring explains the in-memory approach it
        # replaced, and naming it there is not using it.
        code = _statements(MODULE)
        action = code[code.index("def _reap_finished"):]
        action = action[: action.index(chr(10) + "    def ", 1)]
        assert "FROM hosts h JOIN scans s" in action
        assert "running_scans" not in action, (
            "settling depends on a live structure owned elsewhere; a scan that "
            "left it unobserved would strand the host in SCANNING forever"
        )

    def test_only_terminal_scan_states_settle_a_host(self) -> None:
        code = _statements(MODULE)
        action = code[code.index("def _reap_finished"):]
        action = action[: action.index(chr(10) + "    def ", 1)]
        assert "'COMPLETED', 'FAILED', 'CANCELLED'" in action


class TestNothingBreaksTheScheduler:
    """A failure here must not stop capture or correlation."""

    def test_the_cycle_swallows_its_own_failures(self) -> None:
        source = inspect.getsource(AssessmentQueueService.run_cycle)
        assert "except Exception" in source
        assert "return 0" in source

    def test_a_refused_scan_is_recorded_not_retried_blindly(self) -> None:
        source = inspect.getsource(AssessmentQueueService._start)
        assert "except AethraError" in source
        assert "AssessmentState.SKIPPED" in source

    def test_statistics_survive_a_database_failure(self) -> None:
        source = inspect.getsource(AssessmentQueueService.statistics)
        assert "except Exception" in source
