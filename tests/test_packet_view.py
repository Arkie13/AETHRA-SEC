"""The packet view: filtering captured packets without ever touching capture.

The view is driven through :meth:`PacketView.step` with an injected clock, so
every assertion is about one deterministic pass rather than thread timing.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
import threading
from datetime import UTC, datetime
from typing import Any

from aethra_sec.analytics.display_filter import compile_filter
from aethra_sec.analytics.traffic_direction import LocalAddresses
from aethra_sec.config.settings import CaptureSettings, ToolSettings
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import EventType
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.services.packet_capture import PacketCaptureService
from aethra_sec.services.packet_view import PacketView

MONITOR = "192.0.2.10"
REMOTE = "198.51.100.20"
LOCAL = LocalAddresses(interface="test0", addresses=frozenset({MONITOR}))


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_view(**options: Any) -> tuple[PacketView, list[tuple[str, Any]], Clock]:
    events: list[tuple[str, Any]] = []
    clock = Clock()
    view = PacketView(
        lambda kind, payload: events.append((kind, payload)),
        resolver=options.pop("resolver", lambda _interface: LOCAL),
        clock=clock,
        **options,
    )
    return view, events, clock


def packet(number: int, *, incoming: bool = True, layers: tuple[str, ...] = ("ETH", "IP", "TCP")) -> CapturedPacket:
    return CapturedPacket(
        captured_at=datetime.now(UTC),
        interface="test0",
        number=number,
        src_ip=REMOTE if incoming else MONITOR,
        dst_ip=MONITOR if incoming else REMOTE,
        transport="TCP" if "TCP" in layers else "UDP",
        layers=layers,
        ip_version=4,
    )


def run(view: PacketView, clock: Clock, passes: int = 1) -> None:
    for _ in range(passes):
        clock.now += 1.0
        view.step()


def published(events: list[tuple[str, Any]], kind: str) -> list[Any]:
    return [payload for event, payload in events if event == kind]


class TestIngestAndClassify:
    def test_packets_are_classified_counted_and_published(self) -> None:
        view, events, clock = make_view()
        view.begin_session("test0")
        batch = [packet(1), packet(2, incoming=False), packet(3)]
        view.ingest(batch)
        run(view, clock, 2)
        assert [p.direction for p in batch] == ["INCOMING", "OUTGOING", "INCOMING"]
        stats = view.statistics()
        assert stats.session_packets == 3
        assert stats.direction("INCOMING") == 2 and stats.direction("OUTGOING") == 1
        listed = [p for payload in published(events, EventType.DISPLAY_VIEW_BATCH) for p in payload.packets]
        assert listed == batch

    def test_unknown_addresses_are_reported_not_guessed(self) -> None:
        view, _events, clock = make_view(resolver=lambda _i: LocalAddresses(interface="test0", detail="not matched"))
        view.begin_session("test0")
        view.ingest([packet(1)])
        run(view, clock)
        stats = view.statistics()
        assert not stats.local_resolved
        assert stats.direction("UNKNOWN") == 1
        assert "not matched" in stats.local_description

    def test_a_resolver_failure_does_not_stop_the_view(self) -> None:
        def broken(_interface: str) -> LocalAddresses:
            raise RuntimeError("adapter query failed")

        view, _events, clock = make_view(resolver=broken)
        view.begin_session("test0")
        view.ingest([packet(1)])
        run(view, clock)
        assert view.statistics().direction("UNKNOWN") == 1


class TestApplyingAFilter:
    def test_the_retained_packets_are_refiltered_under_a_new_generation(self) -> None:
        view, events, clock = make_view()
        view.begin_session("test0")
        view.ingest([packet(1), packet(2, layers=("ETH", "IP", "UDP")), packet(3)])
        run(view, clock, 2)
        events.clear()

        generation = view.apply_filter(compile_filter("udp"))
        run(view, clock)
        resets = published(events, EventType.DISPLAY_VIEW_RESET)
        assert len(resets) == 1
        assert resets[0].generation == generation
        assert [p.number for p in resets[0].packets] == [2]
        stats = view.statistics()
        assert stats.matched == 1 and stats.evaluated == 3
        assert stats.session_packets == 3, "the captured count must not reset"

    def test_new_packets_are_judged_by_the_active_filter(self) -> None:
        view, events, clock = make_view()
        view.begin_session("test0")
        run(view, clock)
        generation = view.apply_filter(compile_filter("direction == outgoing"))
        run(view, clock)
        events.clear()
        view.ingest([packet(10), packet(11, incoming=False)])
        run(view, clock, 2)
        batches = published(events, EventType.DISPLAY_VIEW_BATCH)
        assert [p.number for payload in batches for p in payload.packets] == [11]
        assert all(payload.generation == generation for payload in batches)

    def test_the_filter_survives_a_capture_restart(self) -> None:
        view, events, clock = make_view()
        view.apply_filter(compile_filter("tcp"))
        view.begin_session("test0")
        view.ingest([packet(1)])
        run(view, clock)
        restarted = view.begin_session("test0")
        run(view, clock)
        assert view.active_filter.expression == "tcp"
        reset = published(events, EventType.DISPLAY_VIEW_RESET)[-1]
        assert reset.generation == restarted and reset.packets == ()
        assert view.statistics().session_packets == 0

    def test_protocol_counts_cover_only_matching_packets(self) -> None:
        view, _events, clock = make_view()
        view.begin_session("test0")
        view.apply_filter(compile_filter("udp"))
        view.ingest([packet(1), packet(2, layers=("ETH", "IP", "UDP", "DNS"))])
        run(view, clock)
        stats = view.statistics()
        assert stats.matched_protocols["UDP"] == 1
        assert stats.matched_protocols["DNS"] == 1
        assert stats.matched_protocols["TCP"] == 0


class TestBounds:
    def test_the_retained_window_is_bounded_and_says_so(self) -> None:
        view, _events, clock = make_view(retained=5)
        view.begin_session("test0")
        view.ingest([packet(n) for n in range(12)])
        run(view, clock)
        view.apply_filter(compile_filter("tcp"))
        run(view, clock)
        stats = view.statistics()
        assert stats.retained == 5 and stats.session_packets == 12
        assert stats.evaluated == 5 and stats.window_limited

    def test_the_hand_off_is_bounded_and_counts_what_it_drops(self) -> None:
        view, _events, clock = make_view(ingest_capacity=3)
        view.begin_session("test0")
        view.ingest([packet(n) for n in range(5)])
        run(view, clock)
        stats = view.statistics()
        assert stats.session_packets == 3 and stats.ingest_dropped == 2

    def test_what_the_table_cannot_hold_is_counted(self) -> None:
        view, events, clock = make_view(table_packets=3)
        view.begin_session("test0")
        run(view, clock)
        view.ingest([packet(n) for n in range(10)])
        run(view, clock, 2)
        listed = [p.number for payload in published(events, EventType.DISPLAY_VIEW_BATCH) for p in payload.packets]
        assert listed == [7, 8, 9]
        assert view.statistics().not_listed == 7


class TestNothingIsFabricated:
    def test_only_ingested_packets_are_ever_published(self) -> None:
        view, events, clock = make_view()
        view.begin_session("test0")
        ingested = [packet(n, incoming=bool(n % 2)) for n in range(40)]
        view.ingest(ingested)
        run(view, clock, 2)
        view.apply_filter(compile_filter("direction == incoming"))
        run(view, clock, 2)
        identities = {id(p) for p in ingested}
        for _kind, payload in events:
            assert all(id(p) in identities for p in payload.packets)

    def test_an_idle_view_publishes_no_packets(self) -> None:
        view, events, clock = make_view()
        view.begin_session("test0")
        run(view, clock, 3)
        assert all(payload.packets == () for _kind, payload in events)


class TestTheThread:
    def test_starting_twice_runs_one_thread(self) -> None:
        view, _events, _clock = make_view()
        view.start()
        view.start()
        try:
            assert sum(1 for t in threading.enumerate() if t.name == "packet-view") == 1
        finally:
            view.stop()
        assert not view.is_running


# ---------------------------------------------------------------------------
# Through the capture service
# ---------------------------------------------------------------------------
class _Settings:
    def get(self, _key: str, default: Any = None) -> Any:
        return default

    def get_int(self, _key: str, default: int = 0) -> int:
        return default

    def get_bool(self, _key: str, default: bool = False) -> bool:
        return default

    def add_listener(self, _listener: Any) -> None:
        pass


class _Access:
    def __init__(self) -> None:
        self.checked: list[str] = []

    def require(self, session: Any, permission: str, **_kw: Any) -> Any:
        self.checked.append(permission)
        return session


def make_service() -> tuple[PacketCaptureService, _Access]:
    access = _Access()
    service = PacketCaptureService(
        traffic=None, hosts=None, alerts=None,  # type: ignore[arg-type]
        settings=_Settings(),  # type: ignore[arg-type]
        event_bus=EventBus(),
        audit=None,  # type: ignore[arg-type]
        access=access,  # type: ignore[arg-type]
        tools=ToolSettings(),
        capture_settings=CaptureSettings(),
    )
    return service, access


class TestThroughTheCaptureService:
    def test_a_valid_filter_is_applied(self) -> None:
        service, access = make_service()
        applied, error, generation = service.set_display_filter(object(), "tcp")
        assert applied and error == "" and generation == service.view.generation
        assert service.view.active_filter.expression == "tcp"
        assert access.checked == ["monitor.view"]

    def test_an_invalid_filter_leaves_the_previous_one_in_force(self) -> None:
        service, _access = make_service()
        service.set_display_filter(object(), "tcp")
        before = service.view.generation
        applied, error, generation = service.set_display_filter(object(), "ip.src ===")
        assert not applied
        assert error == "'===' is not an operator. Use '=='."
        assert generation == before
        assert service.view.active_filter.expression == "tcp"

    def test_changing_the_filter_touches_nothing_in_capture(self) -> None:
        service, _access = make_service()
        reader, worker, state = service._reader, service._worker, service.state  # noqa: SLF001
        for expression in ("http", "tls", "direction == incoming", "", "udp || icmp"):
            service.set_display_filter(object(), expression)
        assert service._reader is reader and service._worker is worker  # noqa: SLF001
        assert service.state is state
        # Inspect the code, not the docstring - which names the reader precisely
        # to say that it is left alone.
        tree = ast.parse(textwrap.dedent(inspect.getsource(PacketCaptureService.set_display_filter)))
        function = tree.body[0]
        assert isinstance(function, ast.FunctionDef)
        statements = function.body[1:] if ast.get_docstring(function) else function.body
        code = "\n".join(ast.unparse(statement) for statement in statements)
        for forbidden in ("stop(", "start(", "_bpf", "_reader", "_queue", "_worker"):
            assert forbidden not in code
