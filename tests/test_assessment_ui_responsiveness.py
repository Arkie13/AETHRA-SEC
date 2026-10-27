"""The Vulnerability Assessment screen must not stall the interface.

The screen froze for several seconds, recovered, and froze again, repeatedly,
while Automatic assessment was open. The cause was not the screen's own work
and not the database: it was ``psutil.net_if_addrs()``, which on Windows is
``GetAdaptersAddresses`` behind a C extension that **does not release the
GIL**. While it runs, no thread in the process can execute Python bytecode -
the Tk thread included - so the window stops answering the OS and Windows
paints it "Not Responding".

It was being called once per candidate host. ``_is_own_address`` enumerated
every adapter, ``eligibility`` called it per host, and ``statistics`` called
``eligibility`` for up to 500 candidates. Measured against the real 2,156-row
inventory with capture running:

    psutil.net_if_addrs      737 calls in 60 s   32.95 s of wall time
    queue.statistics           3 calls           8,920 ms each
    queue._is_own_address    370 calls              88 ms each
    tk main-loop stalls       35 over 250 ms    17.7 s frozen out of 60 s

What proved it was the GIL rather than slow Tk work was running two probes at
once: an ``after(25)`` callback on the Tk thread, and a plain thread that only
sleeps. They starved together, which a busy Tk thread cannot explain.

After caching the enumeration: 3 calls, 0.14 s, no stall over 250 ms, 0.0 s
frozen. The cost is an OS call, so the fix is to stop repeating it - not to
refresh less often, which would have hidden the stall rather than removed it.

These tests hold the shape of that fix. They deliberately assert on *call
counts into the operating system*, because that is the quantity that froze the
interface; timing assertions would be flaky on a loaded machine.
"""

from __future__ import annotations

import ast
import inspect
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.models.enums import AssessmentState, EvidenceSource
from aethra_sec.models.host import Host
from aethra_sec.services.assessment_queue import AssessmentQueueService
from aethra_sec.utils import net as net_utils

ROOT = Path(__file__).resolve().parent.parent
SCREEN = ROOT / "aethra_sec" / "ui" / "screens" / "vulnerabilities.py"

AUTHORIZED = ("192.168.0.0/16", "10.0.0.0/8")


# ---------------------------------------------------------------------------
# Fakes: no real machine, no real database, no real Nmap.
# ---------------------------------------------------------------------------
class _Settings:
    def __init__(self, **values: Any) -> None:
        self.values = values

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        return bool(self.values.get(key, default))

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self.values.get(key, default))


class _Hosts:
    def __init__(self, hosts: list[Host]) -> None:
        self.hosts = hosts
        self.db = None

    def assessment_candidates(self, limit: int = 200, **_: Any) -> list[Host]:
        return self.hosts[:limit]

    def set_assessment_state(self, *_a: Any, **_k: Any) -> None:
        return None

    def assessment_state_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for host in self.hosts:
            counts[str(host.assessment_state)] = (
                counts.get(str(host.assessment_state), 0) + 1
            )
        return counts

    def last_assessment_time(self) -> None:
        return None

    def last_discovery_time(self) -> None:
        return None


class _Nmap:
    def start_scan(self, *_a: Any, **_k: Any) -> int:
        raise AssertionError("no scan may start from a counter refresh")

    def running_scans(self) -> tuple:
        return ()


def _host(host_id: int, address: str) -> Host:
    return Host(
        id=host_id,
        ip_address=address,
        assessment_state=AssessmentState.DISCOVERED,
        discovery_source=EvidenceSource.PYSHARK,
    )


@pytest.fixture
def counted_adapters(monkeypatch: pytest.MonkeyPatch):
    """Count every trip into the operating system's adapter table."""
    psutil = pytest.importorskip("psutil")
    net_utils.invalidate_adapter_cache()
    calls = {"addrs": 0, "stats": 0}
    sample = {
        "Wi-Fi": [
            type("A", (), {
                "family": __import__("socket").AF_INET,
                "address": "192.168.100.31",
                "netmask": "255.255.255.0",
            })()
        ]
    }

    def fake_addrs():  # noqa: ANN202
        calls["addrs"] += 1
        return sample

    def fake_stats():  # noqa: ANN202
        calls["stats"] += 1
        return {"Wi-Fi": type("S", (), {"isup": True, "speed": 100})()}

    monkeypatch.setattr(psutil, "net_if_addrs", fake_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", fake_stats)
    yield calls
    net_utils.invalidate_adapter_cache()


# ---------------------------------------------------------------------------
# The enumeration is made once, not per caller
# ---------------------------------------------------------------------------
class TestTheAdapterTableIsReadOnce:
    def test_repeated_reads_hit_the_operating_system_once(self, counted_adapters) -> None:  # noqa: ANN001
        for _ in range(50):
            net_utils.adapter_tables()
        assert counted_adapters["addrs"] == 1, (
            "each enumeration is ~41 ms during which no Python can run; "
            "50 of them is two seconds of frozen interface"
        )
        assert counted_adapters["stats"] == 1

    def test_the_helpers_share_the_one_reading(self, counted_adapters) -> None:  # noqa: ANN001
        net_utils.local_ipv4_networks()
        net_utils.local_ipv4_addresses()
        net_utils.list_interfaces()
        net_utils.local_ipv4_networks()
        assert counted_adapters["addrs"] == 1

    def test_the_cache_expires_so_a_moved_machine_is_noticed(
        self, counted_adapters
    ) -> None:  # noqa: ANN001
        net_utils.adapter_tables()
        assert counted_adapters["addrs"] == 1
        # Asking for a reading no older than zero seconds must go to the OS:
        # the addresses have to stay live, or the assessment scope would keep
        # describing a network the machine has left.
        net_utils.adapter_tables(max_age=0.0)
        assert counted_adapters["addrs"] == 2

    def test_invalidating_forces_a_fresh_reading(self, counted_adapters) -> None:  # noqa: ANN001
        net_utils.adapter_tables()
        net_utils.invalidate_adapter_cache()
        net_utils.adapter_tables()
        assert counted_adapters["addrs"] == 2

    def test_the_ttl_is_short_enough_to_stay_truthful(self) -> None:
        assert 0 < net_utils.ADAPTER_CACHE_SECONDS <= 30, (
            "the adapters must still be read live; this is a burst guard, "
            "not a permanent snapshot"
        )

    def test_concurrent_readers_do_not_each_pay_for_it(self, counted_adapters) -> None:  # noqa: ANN001
        """Two workers arriving together must make one call, not two.

        The refresh worker, the capture pipeline and the scope resolver can all
        ask at once, and without single-flight the first cold read costs each
        of them 41 ms of GIL.
        """
        net_utils.invalidate_adapter_cache()
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            net_utils.adapter_tables()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert counted_adapters["addrs"] == 1


# ---------------------------------------------------------------------------
# Eligibility does not enumerate per host
# ---------------------------------------------------------------------------
class TestEligibilityDoesNotEnumeratePerHost:
    def _service(self, hosts: list[Host]) -> AssessmentQueueService:
        service = AssessmentQueueService(
            _Hosts(hosts), _Nmap(), _Settings(), authorized_networks=AUTHORIZED
        )
        service.attach_session(object())
        return service

    def test_two_hundred_hosts_cost_one_enumeration(self, counted_adapters) -> None:  # noqa: ANN001
        hosts = [_host(i, f"192.168.100.{i % 254 + 1}") for i in range(1, 201)]
        service = self._service(hosts)
        for host in hosts:
            service.eligibility(host)
        assert counted_adapters["addrs"] <= 1, (
            f"{counted_adapters['addrs']} enumerations for 200 hosts: this is "
            "the per-host adapter read that froze the screen"
        )

    def test_the_monitoring_host_is_still_recognised(self, counted_adapters) -> None:  # noqa: ANN001
        """The fix must not cost correctness: our own address stays excluded."""
        service = self._service([])
        assert service._is_own_address("192.168.100.31") is True  # noqa: SLF001
        assert service._is_own_address("192.168.100.99") is False  # noqa: SLF001

    def test_our_own_address_is_never_queued(self, counted_adapters) -> None:  # noqa: ANN001
        service = self._service([])
        due, state, reason = service.eligibility(_host(1, "192.168.100.31"))
        assert due is False
        assert state is AssessmentState.SKIPPED
        assert "monitoring host" in reason

    def test_counting_does_not_start_a_scan(self, counted_adapters) -> None:  # noqa: ANN001
        """_Nmap.start_scan raises, so a counter refresh that scans fails here."""
        hosts = [_host(i, f"192.168.100.{i}") for i in range(1, 30)]
        service = self._service(hosts)
        service.statistics()


# ---------------------------------------------------------------------------
# A host already queued or scanning is never queued again
# ---------------------------------------------------------------------------
class TestNoDuplicateQueueing:
    def _service(self, hosts: list[Host]) -> AssessmentQueueService:
        service = AssessmentQueueService(
            _Hosts(hosts), _Nmap(), _Settings(), authorized_networks=AUTHORIZED
        )
        service.attach_session(object())
        service._is_own_address = lambda _a: False  # noqa: SLF001
        return service

    @pytest.mark.parametrize(
        "state", [AssessmentState.QUEUED, AssessmentState.SCANNING]
    )
    def test_an_in_flight_host_is_not_due(self, state) -> None:  # noqa: ANN001
        host = _host(1, "192.168.100.40")
        host.assessment_state = state
        service = self._service([host])
        due, reported, reason = service.eligibility(host)
        assert due is False
        assert reported is state
        assert "already queued or scanning" in reason


# ---------------------------------------------------------------------------
# The Nmap probe is not re-run on every refresh
# ---------------------------------------------------------------------------
class TestTheNmapProbeIsCached:
    def test_repeated_probes_spawn_one_subprocess(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from aethra_sec.integrations.nmap import runner as runner_mod

        runner_mod.invalidate_nmap_probe()
        calls = {"n": 0}
        sentinel = object()

        def fake_uncached(path=None):  # noqa: ANN001, ANN202
            calls["n"] += 1
            return sentinel

        monkeypatch.setattr(runner_mod, "_probe_nmap_uncached", fake_uncached)
        for _ in range(20):
            assert runner_mod.probe_nmap() is sentinel
        assert calls["n"] == 1, (
            "probe_nmap runs 'nmap --version' as a real subprocess; the screen "
            "asked for it every few seconds"
        )
        runner_mod.probe_nmap(refresh=True)
        assert calls["n"] == 2, "an explicit refresh must still re-probe"
        runner_mod.invalidate_nmap_probe()

    def test_the_probe_still_expires(self) -> None:
        from aethra_sec.integrations.nmap import runner as runner_mod

        assert 0 < runner_mod.NMAP_PROBE_CACHE_SECONDS <= 300, (
            "installing or removing Nmap must be noticed while the "
            "application runs"
        )


# ---------------------------------------------------------------------------
# The screen's own refresh discipline
# ---------------------------------------------------------------------------
class TestTheRefreshCannotOverlapOrRunOffScreen:
    def test_a_refresh_in_flight_blocks_another(self) -> None:
        """A second refresh must not start while the first worker is out.

        Without this, a refresh slower than the tick interval stacks workers,
        each holding a connection and each ending in a Tk update.
        """
        body = inspect.getsource(
            __import__(
                "aethra_sec.ui.screens.vulnerabilities", fromlist=["x"]
            ).VulnerabilitiesScreen._refresh_automation
        )
        assert "_automation_loading" in body
        guard = body.index("self._automation_loading")
        work = body.index("def work(")
        assert guard < work, "the single-flight guard must precede the work"

    def test_the_tick_does_nothing_off_the_automation_tab(self) -> None:
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        body = inspect.getsource(VulnerabilitiesScreen.on_tick)
        assert "_automation_tab" in body
        assert "return" in body, (
            "rendering work must stop when the tab is not visible; the "
            "backend assessment keeps running regardless"
        )

    def test_the_screen_never_touches_psutil_directly(self) -> None:
        """Adapter reads belong behind the cache, not in a UI callback."""
        source = SCREEN.read_text(encoding="utf-8")
        assert "psutil" not in source, (
            "a UI module reading adapters directly would reintroduce the stall"
        )

    def test_no_sql_or_subprocess_on_the_tk_thread(self) -> None:
        """Every expensive call in this screen goes through run_async.

        Checked structurally: an apply/render method runs on the Tk thread, so
        it must not execute a query or spawn a process.
        """
        tree = ast.parse(SCREEN.read_text(encoding="utf-8"))
        banned = {"query", "query_one", "query_value", "run", "Popen",
                  "communicate", "check_output"}
        offenders: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not (node.name.startswith("_apply") or node.name.startswith("_render")):
                continue
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
                    if inner.func.attr in banned:
                        offenders.append(f"{node.name} -> .{inner.func.attr}()")
        assert not offenders, f"blocking work on the Tk thread: {offenders}"


# ---------------------------------------------------------------------------
# Stopping a scan
# ---------------------------------------------------------------------------
class TestStoppingAScan:
    def test_the_gui_does_not_wait_for_the_process(self) -> None:
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        body = inspect.getsource(VulnerabilitiesScreen._stop_scan)
        assert "run_async" in body, "Stop must not block the Tk thread"
        assert ".join(" not in body and ".wait(" not in body

    def test_cancel_kills_the_owned_process_by_handle(self) -> None:
        from aethra_sec.integrations.nmap.runner import NmapRunner

        cancel = inspect.getsource(NmapRunner.cancel)
        terminate = inspect.getsource(NmapRunner._terminate)
        assert "_terminate" in cancel, "cancel must stop the real process now"
        assert "self._process" in terminate, (
            "the process is signalled by its own handle"
        )
        # Never by name: that would kill an Nmap another tool started.
        for text in (cancel, terminate):
            assert "taskkill" not in text and "nmap.exe" not in text

    def test_a_cancelled_scan_is_not_recorded_as_safe(self) -> None:
        from aethra_sec.models.host import derive_security_result

        result = derive_security_result(
            assessment_state=AssessmentState.DISCOVERED,
            last_scan_status="CANCELLED",
            last_scan_hosts_up=1,
            last_assessed_at=None,
            confirmed_finding_count=0,
            finding_count=0,
            highest_finding=None,
        )
        assert result.code != "SAFE"


# ---------------------------------------------------------------------------
# A counter that cannot be computed says so
# ---------------------------------------------------------------------------
class TestAFailedCountIsNotReportedAsZero:
    """``statistics()`` used to swallow the failure and leave ``due_now`` at 0.

    Zero due and "could not work out what is due" look identical on screen but
    mean opposite things, and an operator has to be able to tell them apart.
    """

    def _service(self, inventory: Any) -> AssessmentQueueService:
        service = AssessmentQueueService(
            inventory, _Nmap(), _Settings(), authorized_networks=AUTHORIZED
        )
        service.attach_session(object())
        service._is_own_address = lambda _a: False  # noqa: SLF001
        return service

    def test_a_working_count_is_marked_available(self) -> None:
        hosts = [_host(1, "192.168.100.40")]
        stats = self._service(_Hosts(hosts)).statistics()
        assert stats.due_now_available is True

    def test_a_broken_candidate_query_is_admitted(self) -> None:
        class _Broken(_Hosts):
            def assessment_candidates(self, limit: int = 200, **_: Any):  # noqa: ANN201
                raise RuntimeError("the inventory could not be read")

        stats = self._service(_Broken([_host(1, "192.168.100.40")])).statistics()
        assert stats.due_now == 0
        assert stats.due_now_available is False, (
            "a zero that means 'unknown' must be distinguishable from a zero "
            "that means 'nothing is due'"
        )
        assert "could not be determined" in stats.detail
        # The state counts came from a different query and are still good.
        assert stats.discovered == 1

    def test_the_failure_does_not_propagate(self) -> None:
        """A broken counter must not take the refresh - or the screen - down."""
        class _Broken(_Hosts):
            def last_assessment_time(self):  # noqa: ANN201
                raise RuntimeError("clock table unavailable")

        stats = self._service(_Broken([_host(1, "192.168.100.40")])).statistics()
        assert stats.due_now_available is False
