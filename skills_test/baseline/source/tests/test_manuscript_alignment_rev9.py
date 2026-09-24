"""Manuscript rev9 alignment: the rules that keep automation honest and bounded.

Each test pins a defect found in the audit or a manuscript definition that was
missing:

* automatic assessment was scoped to every private address, including a
  ZeroTier overlay whose peers are other people's machines;
* every scan's ``started_at`` was overwritten with its finish time;
* a scan Nmap abandoned on ``--host-timeout`` (reported UP, exit success) was
  stored as a completed scan - and so as "no findings";
* any open finding, even an informational one, made a host VULNERABLE, where
  §3.9.9 classifies by CVSS band;
* the assessment tiles counted a 1,000-row display cap;
* nothing recorded attack initiation, so §3.9.2 detection time could not be
  computed.
"""

from __future__ import annotations

import inspect
import tempfile
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.analytics.assessment_scope import (
    UNAVAILABLE_MESSAGE,
    AssessmentScope,
    resolve_scope,
)
from aethra_sec.models.enums import (
    AssessmentState,
    EvidenceSource,
    HostStatus,
    RiskLevel,
    ScanTrigger,
)
from aethra_sec.models.host import Host, summarize_assessment
from aethra_sec.utils.timeutil import utcnow


@dataclass
class _Iface:
    name: str
    addresses: tuple[str, ...] = ()
    netmasks: tuple[tuple[str, str], ...] = ()
    mac: str = ""


def _table() -> dict[str, _Iface]:
    """The development machine's real adapter layout, as observed."""
    return {
        "Wi-Fi": _Iface("Wi-Fi", ("192.168.1.26",), (("192.168.1.26", "255.255.255.0"),)),
        "VMware Network Adapter VMnet1": _Iface(
            "VMware Network Adapter VMnet1", ("192.168.1.1",),
            (("192.168.1.1", "255.255.255.0"),),
        ),
        "ZeroTier One [83048a0632cd2227]": _Iface(
            "ZeroTier One [83048a0632cd2227]", ("172.22.126.241",),
            (("172.22.126.241", "255.255.0.0"),),
        ),
        "Loopback Pseudo-Interface 1": _Iface(
            "Loopback Pseudo-Interface 1", ("127.0.0.1",), (("127.0.0.1", "255.0.0.0"),),
        ),
    }


RFC1918 = ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8")
WIFI_DEVICE = r"\Device\NPF_{2B4A77CE-A29A-41CE-844D-D378853A0D82}"


def _scope(interface: str, configured=RFC1918, **kw) -> AssessmentScope:
    return resolve_scope(
        interface, configured, interfaces=_table,
        adapter_names=lambda: {"{2B4A77CE-A29A-41CE-844D-D378853A0D82}": "Wi-Fi"},
        **kw,
    )


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------
class TestAssessmentScopeIsTheMonitoredNetwork:
    def test_the_monitored_wifi_subnet_only(self) -> None:
        scope = _scope(WIFI_DEVICE)
        assert scope.available
        assert [str(n) for n in scope.networks] == ["192.168.1.0/24"]
        assert scope.contains("192.168.1.40")

    def test_other_private_networks_are_not_in_scope(self) -> None:
        """RFC 1918 configured is not RFC 1918 authorised for automation."""
        scope = _scope(WIFI_DEVICE)
        for address in ("192.168.100.31", "10.0.0.5", "172.22.217.9", "192.168.204.10"):
            assert not scope.contains(address), address

    def test_a_zerotier_overlay_is_refused(self) -> None:
        """Its /16 'on-link' peers are remote machines."""
        scope = _scope("ZeroTier One [83048a0632cd2227]")
        assert not scope.available
        assert "larger than" in scope.reason

    def test_no_configured_range_means_unavailable_not_guessed(self) -> None:
        scope = _scope(WIFI_DEVICE, configured=())
        assert not scope.available
        assert scope.describe().startswith(UNAVAILABLE_MESSAGE)

    def test_no_monitored_interface_means_unavailable(self) -> None:
        scope = _scope("")
        assert not scope.available
        assert "No interface is being monitored" in scope.reason

    def test_an_unmatched_interface_means_unavailable(self) -> None:
        assert not _scope(r"\Device\NPF_{00000000-0000-0000-0000-000000000000}").available

    def test_a_network_outside_every_configured_range_is_unavailable(self) -> None:
        scope = _scope(WIFI_DEVICE, configured=("10.0.0.0/8",))
        assert not scope.available
        assert "not inside any configured" in scope.reason

    def test_a_narrower_configured_range_narrows_the_scope(self) -> None:
        scope = _scope(WIFI_DEVICE, configured=("192.168.1.0/28",))
        assert [str(n) for n in scope.networks] == ["192.168.1.0/28"]
        assert not scope.contains("192.168.1.40")

    def test_network_and_broadcast_addresses_are_not_hosts(self) -> None:
        scope = _scope(WIFI_DEVICE)
        assert not scope.is_assessable_address("192.168.1.0")
        assert not scope.is_assessable_address("192.168.1.255")
        assert scope.is_assessable_address("192.168.1.7")

    def test_ipv6_is_never_inside_an_automatic_scope(self) -> None:
        assert not _scope(WIFI_DEVICE).contains("fe80::1")

    def test_the_sql_ranges_match_the_networks(self) -> None:
        scope = _scope(WIFI_DEVICE)
        assert scope.address_ranges == ((3232235776, 3232236031),)


# ---------------------------------------------------------------------------
# The queue in scope mode
# ---------------------------------------------------------------------------
class _Settings:
    def __init__(self, **values: Any) -> None:
        self.values = {
            "assessment.auto_enabled": True, "assessment.auto_new_hosts": True,
            "assessment.reassess_hours": 6, "assessment.max_concurrent": 2,
            "assessment.max_attempts": 3, "assessment.excluded_addresses": "",
            "assessment.retry_base_minutes": 5, **values,
        }

    def get(self, key, default=None):
        return self.values.get(key, default)

    def get_bool(self, key, default=False):
        return bool(self.values.get(key, default))

    def get_int(self, key, default=0):
        return int(self.values.get(key, default))


@dataclass
class _Hosts:
    hosts: list[Host] = field(default_factory=list)
    ranges_seen: list[Any] = field(default_factory=list)
    states: list[tuple[int, AssessmentState, dict]] = field(default_factory=list)
    db: Any = None

    def assessment_candidates(self, limit=200, *, ranges=None):
        self.ranges_seen.append(ranges)
        import ipaddress

        return [
            h for h in self.hosts
            if h.assessment_state is not AssessmentState.SCANNING
            and (ranges is None or any(
                lo <= int(ipaddress.ip_address(h.ip_address)) <= hi for lo, hi in ranges
            ))
        ]

    def set_assessment_state(self, host_id, state, **kw):
        self.states.append((host_id, state, kw))
        for host in self.hosts:
            if host.id == host_id:
                host.assessment_state = state

    def assessment_state_counts(self):
        return {}

    def last_assessment_time(self):
        return None

    def last_discovery_time(self):
        return None


class _Nmap:
    def __init__(self) -> None:
        self.started: list[str] = []

    def start_scan(self, _s, target, **_kw):
        self.started.append(target)
        return 1000 + len(self.started)


def _queue(hosts, scope, **settings):
    from aethra_sec.services.assessment_queue import AssessmentQueueService

    inventory, nmap = _Hosts(hosts), _Nmap()
    service = AssessmentQueueService(
        inventory, nmap, _Settings(**settings), scope_provider=lambda: scope
    )
    service.attach_session(object())
    service._is_own_address = lambda _a: False  # noqa: SLF001
    return service, inventory, nmap


def _h(i, ip, **kw) -> Host:
    # A source is stated because the model's default is LEGACY - a row whose
    # origin was never established - and such a host is deliberately never
    # queued. These stand for hosts capture genuinely observed.
    kw.setdefault("discovery_source", EvidenceSource.PYSHARK)
    return Host(id=i, ip_address=ip, status=kw.pop("status", HostStatus.UP), **kw)


class TestTheQueueHonoursTheScope:
    def test_an_unavailable_scope_starts_nothing_and_says_why(self) -> None:
        scope = _scope("")
        service, _inv, nmap = _queue([_h(1, "192.168.1.5")], scope)
        assert service.run_cycle() == 0
        assert nmap.started == []
        assert service.statistics().detail.startswith(UNAVAILABLE_MESSAGE)

    def test_only_in_scope_hosts_are_selected(self) -> None:
        scope = _scope(WIFI_DEVICE)
        hosts = [_h(1, "192.168.1.5"), _h(2, "192.168.100.31"), _h(3, "172.22.1.9")]
        service, inventory, nmap = _queue(hosts, scope)
        assert service.run_cycle() == 1
        assert nmap.started == ["192.168.1.5"]
        assert inventory.ranges_seen[-1] == scope.address_ranges

    def test_an_offline_host_is_not_reassessed(self) -> None:
        """Re-scanning an address nobody is using only confirms it is gone."""
        scope = _scope(WIFI_DEVICE)
        host = _h(
            1, "192.168.1.5", status=HostStatus.DOWN,
            assessment_state=AssessmentState.COOLDOWN,
            assessment_attempts=1, last_assessed_at=utcnow() - timedelta(days=1),
            last_scan_id=7,
        )
        service, _inv, nmap = _queue([host], scope)
        due, _state, reason = service.eligibility(host)
        assert not due and "offline" in reason
        assert service.run_cycle() == 0 and nmap.started == []

    def test_an_offline_host_that_was_never_assessed_still_gets_one_attempt(
        self,
    ) -> None:
        """ARP proved the device exists; it must not stop at DISCOVERED.

        A device can go quiet between being discovered and the queue reaching
        it - phones do this constantly. Skipping it there left it unassessed
        for ever: on the development installation 42 of 83 hosts on the
        monitored subnet had never been assessed once, every one for this
        reason.
        """
        scope = _scope(WIFI_DEVICE)
        host = _h(1, "192.168.1.5", status=HostStatus.DOWN)
        service, _inv, nmap = _queue([host], scope)
        due, _state, _reason = service.eligibility(host)
        assert due, "a never-assessed host was skipped for being offline"
        assert service.run_cycle() == 1 and nmap.started == ["192.168.1.5"]

    def test_a_failure_backs_off_instead_of_retrying_every_cycle(self) -> None:
        scope = _scope(WIFI_DEVICE)
        host = _h(1, "192.168.1.5", assessment_state=AssessmentState.FAILED,
                  assessment_attempts=1, last_attempt_at=utcnow() - timedelta(minutes=1))
        service, _inv, nmap = _queue([host], scope)
        due, state, reason = service.eligibility(host)
        assert not due and state is AssessmentState.FAILED
        assert "back-off" in reason
        host.last_attempt_at = utcnow() - timedelta(minutes=6)
        assert service.eligibility(host)[0] is True

    def test_back_off_doubles(self) -> None:
        service, _inv, _nmap = _queue([], _scope(WIFI_DEVICE))
        assert service._retry_delay(1) == timedelta(minutes=5)  # noqa: SLF001
        assert service._retry_delay(2) == timedelta(minutes=10)  # noqa: SLF001
        assert service._retry_delay(3) == timedelta(minutes=20)  # noqa: SLF001
        assert service._retry_delay(99) == timedelta(hours=6)  # noqa: SLF001

    def test_a_timed_out_host_is_retried_with_back_off_too(self) -> None:
        host = _h(1, "192.168.1.5", assessment_state=AssessmentState.TIMEOUT,
                  assessment_attempts=1, last_attempt_at=utcnow())
        service, _inv, _nmap = _queue([host], _scope(WIFI_DEVICE))
        assert service.eligibility(host)[0] is False

    def test_new_hosts_go_before_reassessments(self) -> None:
        scope = _scope(WIFI_DEVICE)
        old = _h(1, "192.168.1.5", last_assessed_at=utcnow() - timedelta(hours=9),
                 last_seen=utcnow())
        new = _h(2, "192.168.1.6", last_seen=utcnow() - timedelta(minutes=5))
        service, _inv, nmap = _queue([old, new], scope, **{"assessment.max_concurrent": 1})
        service.run_cycle()
        assert nmap.started == ["192.168.1.6"]

    def test_timeout_is_a_terminal_scan_status_the_reaper_settles(self) -> None:
        from aethra_sec.services.assessment_queue import AssessmentQueueService

        source = inspect.getsource(AssessmentQueueService._reap_finished)
        assert "'TIMEOUT'" in source
        assert "AssessmentState.TIMEOUT" in source

    def test_one_host_many_packets_one_job(self) -> None:
        """Deduplication: a host already QUEUED/SCANNING is never started again."""
        scope = _scope(WIFI_DEVICE)
        host = _h(1, "192.168.1.5")
        service, _inv, nmap = _queue([host], scope)
        service.run_cycle()
        for _ in range(50):
            service.run_cycle()
        assert nmap.started == ["192.168.1.5"]


# ---------------------------------------------------------------------------
# Nmap execution
# ---------------------------------------------------------------------------
REAL_TIMEOUT_XML = (
    '<nmaprun><host starttime="1789480530" endtime="1789480532" timedout="true">'
    '<status state="up" reason="user-set" reason_ttl="0"/>'
    '<address addr="127.0.0.1" addrtype="ipv4"/></host>'
    '<runstats><finished time="1789480532" elapsed="1.85" exit="success"/>'
    '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
)


class TestNmapNeverReportsAnUnfinishedScanAsFinished:
    def test_host_timeout_is_read_from_nmaps_own_xml(self) -> None:
        from aethra_sec.integrations.nmap.runner import timed_out_hosts

        assert timed_out_hosts(REAL_TIMEOUT_XML) == ("127.0.0.1",)
        assert timed_out_hosts(REAL_TIMEOUT_XML.replace(' timedout="true"', "")) == ()

    def test_an_abandoned_host_raises_a_timeout_not_a_completion(self) -> None:
        from aethra_sec.services.nmap_service import NmapService

        source = inspect.getsource(NmapService._execute)
        assert "timed_out_hosts" in source
        assert "raise ScanTimeoutError" in source
        assert "except ScanTimeoutError" in source

    def test_started_at_is_written_once(self) -> None:
        """The second mark_running call overwrote the start with the finish."""
        from aethra_sec.services.nmap_service import NmapService

        source = inspect.getsource(NmapService._execute)
        assert source.count("mark_running(") == 1
        assert "record_command(" in source

    def test_record_command_cannot_touch_started_at(self) -> None:
        from aethra_sec.database.repositories.scans import ScanRepository

        source = inspect.getsource(ScanRepository.record_command)
        assert "started_at" not in source.split('"""')[-1]

    def test_the_runner_owns_the_process_so_cancel_and_timeout_kill_it(self) -> None:
        from aethra_sec.integrations.nmap.runner import NmapRunner

        run = inspect.getsource(NmapRunner.run)
        assert "subprocess.Popen" in run
        assert "adopt(process.pid)" in run
        assert "ScanTimeoutError" in run
        assert "self._terminate()" in inspect.getsource(NmapRunner.cancel)

    def test_a_timeout_scan_status_is_terminal(self) -> None:
        from aethra_sec.models.enums import ScanStatus

        assert ScanStatus.TIMEOUT.is_terminal


# ---------------------------------------------------------------------------
# Summary counts equal the rows
# ---------------------------------------------------------------------------
class TestTheTilesCountEveryHost:
    def test_the_summary_is_uncapped_and_agrees_with_per_host_results(self) -> None:
        now = utcnow()
        hosts = [
            _h(i, f"192.168.1.{i}", assessment_state=AssessmentState.COMPLETED,
               last_assessed_at=now, last_scan_status="COMPLETED",
               last_scan_hosts_up=1)
            for i in range(1, 1201)
        ]
        # One host with confirmed vulnerability evidence, one with exposure
        # only. Exposure is not a vulnerability, so only the first is counted.
        hosts[0].finding_count, hosts[0].highest_finding = 2, RiskLevel.HIGH
        hosts[0].confirmed_finding_count = 2
        hosts[1].finding_count, hosts[1].highest_finding = 1, RiskLevel.MEDIUM
        hosts[2].assessment_state, hosts[2].last_scan_status = AssessmentState.TIMEOUT, "TIMEOUT"
        summary = summarize_assessment(hosts, None)
        assert summary.discovered == 1200, "the count was capped"
        assert summary.vulnerable == 1
        assert summary.timeout == 1
        # The exposure-only host is Safe alongside the 1,197 with nothing.
        assert summary.safe == 1198
        assert summary.vulnerable + summary.safe + summary.timeout == 1200, (
            "every host must land in exactly one bucket"
        )

    def test_outside_scope_hosts_are_counted_apart(self) -> None:
        hosts = [_h(1, "192.168.1.5"), _h(2, "8.8.8.8"), _h(3, "192.168.100.2")]
        summary = summarize_assessment(hosts, _scope(WIFI_DEVICE))
        assert summary.discovered == 1
        assert summary.outside_scope == 2

    def test_the_screen_and_dashboard_use_the_summary(self) -> None:
        from aethra_sec.services.dashboard_service import DashboardService
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        screen = inspect.getsource(VulnerabilitiesScreen._refresh_automation)
        assert "assessment_summary(" in screen
        assert "for host in hosts" not in screen, "tiles counted from capped rows"
        assert "summarize_assessment" in inspect.getsource(
            DashboardService._assessment_summary
        )


# ---------------------------------------------------------------------------
# Traffic classes, single instance
# ---------------------------------------------------------------------------
class TestManuscriptTrafficClasses:
    def test_load_classes_follow_section_4_5_4(self) -> None:
        from aethra_sec.analytics.traffic_classes import traffic_load_class

        assert traffic_load_class(None) == ""
        assert traffic_load_class(99).startswith("Small")
        assert traffic_load_class(100).startswith("Medium")
        assert traffic_load_class(1000).startswith("Medium")
        assert traffic_load_class(1001).startswith("Large")

    def test_capture_reliability_follows_section_3_9_10(self) -> None:
        from aethra_sec.analytics.traffic_classes import CaptureReliability

        assert CaptureReliability(0, 0).loss_percent is None
        assert CaptureReliability(990, 9).reliable is True
        assert CaptureReliability(99, 1).reliable is False  # exactly 1% is not < 1%


class TestOneConsole:
    def test_main_refuses_a_second_console_before_services_start(self) -> None:
        from aethra_sec import main as entry

        source = inspect.getsource(entry.main)
        assert source.index("single_instance.acquire") < source.index("context.start(")

    def test_acquiring_twice_in_one_process_is_idempotent(self) -> None:
        """Re-acquiring in the same process returns True without re-locking.

        The lock name is machine-global on purpose, so this test must not use
        the real one: on a developer machine with the console open, the real
        name is legitimately already held and the first acquire correctly
        returns False. Isolating the name tests the idempotency rule itself.
        """
        import os
        import uuid

        from aethra_sec.core import single_instance

        name = f"Local\\AETHRA-SEC.test.{uuid.uuid4().hex}"
        held, original = single_instance._held, single_instance.MUTEX_NAME
        single_instance._held, single_instance.MUTEX_NAME = None, name
        try:
            with tempfile.TemporaryDirectory() as directory:
                # POSIX locks a file rather than a named object.
                lock_dir = None if os.name == "nt" else Path(directory)
                assert single_instance.acquire(lock_dir) is True
                assert single_instance.is_held() is True
                # The second call short-circuits on the handle it already has.
                assert single_instance.acquire(lock_dir) is True
        finally:
            single_instance._held, single_instance.MUTEX_NAME = held, original
