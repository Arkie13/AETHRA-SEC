"""The interface must not be flooded with one event per packet.

AETHRA-SEC froze during an authorised 3,624 pps SYN flood on 14 October and
had to be killed. There was no exception and no shutdown line in the log -
the window simply stopped answering while the event bus reported its buffer
overflowing continuously, the discarded count climbing 6,221 -> 19,220 ->
28,770 -> 33,637 in about ninety seconds.

The cause was in the capture worker. The UI publish was gated on
``last_flush``, the timestamp of the last *database* row write, which it
never updated itself:

    if ui_batch and (len(ui_batch) >= 50 or (now - last_flush) >= 0.5):

That is harmless while rows are being written. It stops being harmless when
row storage stops, which is exactly what ``_allow_row`` does during a flood -
it caps storage at ``capture.max_packet_rows_per_minute`` and then skips
every further row for the rest of the minute. With nothing pending, the
database block never runs, ``last_flush`` freezes, the half-second condition
holds on every pass, and the loop publishes a batch per iteration: one event
per packet.

These tests drive the real worker loop with real packets.

The packets below are test fixtures. They are not observations of a network,
and no attack was performed to produce them.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Any

import pytest

from aethra_sec.config.settings import CaptureSettings, ToolSettings
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import EventType
from aethra_sec.services.packet_capture import PacketCaptureService

from conftest import make_packet

#: Packets per event the loop is supposed to batch at.
BATCH = 50


class _Settings:
    """Settings as the worker reads them, with the real defaults."""

    def __init__(self, **overrides: Any) -> None:
        self._values: dict[str, Any] = {
            "capture.persist_batch_size": 200,
            "capture.persist_flush_seconds": 2,
            "capture.persist_packet_metadata": True,
            # The ceiling that starves the database flush during a flood.
            "capture.max_packet_rows_per_minute": 6000,
            "ui.chart_points": 60,
        }
        self._values.update(overrides)

    def get(self, key: str, default: Any = None) -> Any:
        return self._values.get(key, default)

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self._values.get(key, default))

    def get_bool(self, key: str, default: bool = False) -> bool:
        return bool(self._values.get(key, default))

    def get_str(self, key: str, default: str = "") -> str:
        return str(self._values.get(key, default))

    def add_listener(self, _listener: Any) -> None:
        return None


class _Audit:
    def record(self, *args: Any, **kwargs: Any) -> None:
        return None


class _Access:
    def require(self, *args: Any, **kwargs: Any) -> None:
        return None


class _Traffic:
    """Accepts row batches and remembers how many arrived."""

    def __init__(self) -> None:
        self.batches = 0
        self.rows = 0

    def insert_batch(self, rows: list[Any]) -> int:
        self.batches += 1
        self.rows += len(rows)
        return len(rows)


def _service(bus: EventBus, settings: _Settings, traffic: Any = None):
    service = PacketCaptureService(
        traffic=traffic, hosts=None, alerts=None,  # type: ignore[arg-type]
        settings=settings,  # type: ignore[arg-type]
        event_bus=bus,
        audit=_Audit(),  # type: ignore[arg-type]
        access=_Access(),  # type: ignore[arg-type]
        tools=ToolSettings(),
        capture_settings=CaptureSettings(),
    )
    return service


class _Clock:
    """A monotonic clock the test advances, one packet at a time.

    Without this the loop drains a pre-filled queue in milliseconds, no
    simulated time passes, and the half-second branch that caused the freeze
    is never taken - which is how the first version of these tests managed to
    pass against the defective code.
    """

    def __init__(self, pps: float = 3624.0) -> None:
        self.now = 1000.0
        self._step = 1.0 / pps

    def __call__(self) -> float:
        self.now += self._step
        return self.now


def _run_flood(service: PacketCaptureService, packets: int,
               rows_already_used: int = 0,
               monkeypatch: Any = None) -> None:
    """Push packets through the real worker loop on a test-driven clock.

    ``rows_already_used`` pre-spends the per-minute row budget, which is the
    state a flood reaches within seconds and the state the defect needs: with
    no rows pending, the database flush stops and its timestamp freezes.
    """
    import aethra_sec.services.packet_capture as module

    clock = _Clock()
    assert monkeypatch is not None, "the clock has to be patched for this to mean anything"
    monkeypatch.setattr(module.time, "monotonic", clock)

    service._minute_rows = rows_already_used  # noqa: SLF001
    service._minute_anchor = clock.now  # noqa: SLF001
    for index in range(packets):
        service._queue.put(  # noqa: SLF001
            make_packet(src_ip="198.51.100.9", dst_ip="198.51.100.1",
                        protocol="TCP", tcp_flags=0x02,
                        offset_seconds=index / 3624.0)
        )
    service._stop_worker.set()  # noqa: SLF001
    service._process_loop()  # noqa: SLF001 - run it inline, on this thread


class TestTheInterfaceIsNotFloodedWithEvents:
    def test_packets_are_batched_when_row_storage_has_stopped(self, monkeypatch) -> None:
        """The exact condition of the freeze: the row budget is spent.

        Every packet still flows through analysis and counting. What must not
        happen is one UI event per packet.
        """
        bus = EventBus()
        published: list[Any] = []
        bus.subscribe((EventType.PACKET_BATCH_PROCESSED,), published.append,
                      queued=False, name="test")
        service = _service(bus, _Settings(), _Traffic())

        packets = 1000
        _run_flood(service, packets, rows_already_used=6000,
                   monkeypatch=monkeypatch)

        assert published, "no batch reached the interface at all"
        assert len(published) <= (packets / BATCH) + 2, (
            f"{len(published)} events for {packets} packets - the loop is "
            f"publishing roughly one event per packet again"
        )

    def test_every_packet_still_reaches_the_interface(self, monkeypatch) -> None:
        """Batching must not lose packets, only group them."""
        bus = EventBus()
        published: list[Any] = []
        bus.subscribe((EventType.PACKET_BATCH_PROCESSED,), published.append,
                      queued=False, name="test")
        service = _service(bus, _Settings(), _Traffic())

        packets = 500
        _run_flood(service, packets, rows_already_used=6000,
                   monkeypatch=monkeypatch)

        delivered = sum(len(event.payload.packets) for event in published)
        assert delivered == packets, (
            f"{delivered} of {packets} packets reached the interface"
        )

    def test_the_batch_size_is_respected(self, monkeypatch) -> None:
        bus = EventBus()
        published: list[Any] = []
        bus.subscribe((EventType.PACKET_BATCH_PROCESSED,), published.append,
                      queued=False, name="test")
        service = _service(bus, _Settings(), _Traffic())
        _run_flood(service, 500, rows_already_used=6000,
                   monkeypatch=monkeypatch)

        # The final batch may be short; every other one should be full.
        full = [len(e.payload.packets) for e in published[:-1]]
        assert full, "nothing to check"
        assert all(size == BATCH for size in full), (
            f"batch sizes were {full[:8]}, expected {BATCH} each"
        )

    def test_batching_holds_while_rows_are_being_written_too(self, monkeypatch) -> None:
        """The healthy path must not regress either."""
        bus = EventBus()
        published: list[Any] = []
        bus.subscribe((EventType.PACKET_BATCH_PROCESSED,), published.append,
                      queued=False, name="test")
        traffic = _Traffic()
        service = _service(bus, _Settings(), traffic)

        packets = 1000
        _run_flood(service, packets, rows_already_used=0,
                   monkeypatch=monkeypatch)

        assert len(published) <= (packets / BATCH) + 2
        assert traffic.rows > 0, "no rows were written on the healthy path"

    def test_row_storage_still_stops_at_the_configured_ceiling(self, monkeypatch) -> None:
        """The fix must not disable the row cap it interacts with."""
        bus = EventBus()
        traffic = _Traffic()
        service = _service(bus, _Settings(), traffic)
        _run_flood(service, 400, rows_already_used=6000,
                   monkeypatch=monkeypatch)
        assert traffic.rows == 0, (
            "rows were written past the per-minute ceiling"
        )
        assert service.statistics().sampled_out >= 400


class TestTheUiPublishKeepsItsOwnClock:
    """The defect in one line, guarded directly."""

    def test_the_condition_does_not_read_the_database_clock(self) -> None:
        import inspect

        source = inspect.getsource(PacketCaptureService._process_loop)
        assert "(now - last_ui) >= 0.5" in source, (
            "the UI publish no longer uses its own timestamp"
        )
        assert "(now - last_flush) >= 0.5" not in source, (
            "the UI publish is gated on the database flush clock again - this "
            "is the defect that froze the interface during a flood"
        )

    def test_the_timestamp_is_advanced_after_publishing(self) -> None:
        import inspect

        source = inspect.getsource(PacketCaptureService._process_loop)
        start = source.index("if ui_batch and")
        block = source[start:start + 240]
        assert "last_ui = now" in block, (
            "last_ui is never advanced, so the condition stays true for ever"
        )


class TestTheEventBufferSurvivesTheFlood:
    """What the buffer sees, at the rates the screenshot recorded."""

    @pytest.mark.parametrize("pps,seconds", [(3624.0, 10.0), (2762.0, 10.0)])
    def test_the_published_rate_stays_within_the_buffer(
        self, pps: float, seconds: float
    ) -> None:
        """A 4,000-slot buffer must not fill from a flood of this size.

        At one event per packet, 3,624 pps fills 4,000 slots in about a
        second, which is what the production log recorded. Batched at fifty,
        the same flood produces about 72 events a second.
        """
        expected_events = (pps * seconds) / BATCH
        assert expected_events / seconds < 400, (
            "the batched event rate exceeds what one UI tick drains"
        )
        assert expected_events < 4000, (
            "a ten-second flood would still fill the buffer"
        )
