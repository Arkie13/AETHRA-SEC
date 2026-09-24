"""Staying up, and detecting, while under a traffic flood.

An attack is input to a monitoring system, not a reason for one to stop. Under
a sustained multi-source flood the console used to stop servicing its own event
loop: counters flatlined, the window stopped repainting, and the capture reader
was starved along with everything else.

The cause was not the packet rate. It was that appending to a live table cost
the Tk thread a full teardown and rebuild of every row it already held, so the
price of showing one new packet rose with the number of packets already shown -
~37 ms into a 2,000-row grid. Past roughly 25 writes a second the interface
could never catch up, and the backlog only grew.

What is pinned here:

* appending costs the rows appended, not the rows held;
* the cap evicts from the widget as well as from the model, so a bounded table
  stays bounded in both;
* live packets are coalesced onto a fixed cadence, so display cost is bounded
  by the clock rather than by the attacker;
* the display buffer is bounded and says when it dropped something;
* the display filter is applied before packets reach the screen, so traffic
  nobody asked to see costs the interface nothing;
* nothing above is allowed to hide traffic: what is not displayed is still
  analysed, counted and stored, and the screen says so.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from aethra_sec.ui.screens import traffic as traffic_module
from aethra_sec.ui.screens.traffic import (
    DIRECTION_BUTTONS,
    FLUSH_INTERVAL_MS,
    MAX_BUFFERED_PACKETS,
    PROTOCOL_BUTTONS,
    TrafficScreen,
)
from aethra_sec.ui.widgets.tables import Column, DataTable

COLUMNS = (
    Column("time", "Time"),
    Column("source", "Source"),
    Column("protocol", "Protocol"),
)


class _Tree:
    """A stand-in Treeview that records what the table asks of it."""

    def __init__(self) -> None:
        self.items: list[str] = []
        self.inserts = 0
        self.deletes = 0

    def insert(self, _parent: str, _where: str, iid: str = "", **_kw: Any) -> str:
        self.items.append(iid)
        self.inserts += 1
        return iid

    def delete(self, *iids: str) -> None:
        for iid in iids:
            if iid in self.items:
                self.items.remove(iid)
            self.deletes += 1

    def exists(self, iid: str) -> bool:
        return iid in self.items

    def get_children(self, _item: str = "") -> tuple[str, ...]:
        return tuple(self.items)

    def selection(self) -> tuple[str, ...]:
        return ()

    def selection_add(self, *_a: Any) -> None:
        pass

    def tag_configure(self, *_a: Any, **_k: Any) -> None:
        pass


class _Table(DataTable):
    """A DataTable with the widget layer replaced, so no display is needed."""

    def __init__(self, max_rows: int | None = None) -> None:
        # Bypass the ttk construction entirely; only the row logic is tested.
        self._columns = list(COLUMNS)
        self._visible_keys = [c.key for c in self._columns]
        self._max_rows = max_rows
        self._on_select = None
        self._on_activate = None
        self._rows = {}
        self._order = []
        self._sort_key = None
        self._sort_reverse = False
        self._filter_text = ""
        self._quick_text = ""
        self._filter_predicate = None
        self._next_id = 0
        self._trimmed = 0
        self._rendered = 0
        self._actions = []
        self._empty_text = ""
        self._hovered = ""
        self._marked = set()
        self._counter = None
        self._hint = None
        self._footer = None
        self._toolbar = None
        self._filter_var = None
        self.tree = _Tree()

    def _update_counter(self, _visible: int) -> None:
        """The footer is not built in this harness."""


def _row(index: int, protocol: str = "ICMP") -> dict[str, Any]:
    """One packet row."""
    return {
        "_key": f"p{index}", "time": "10:21:41.123",
        "source": "127.0.0.2", "protocol": protocol,
    }


# ---------------------------------------------------------------------------
# The cost of appending
# ---------------------------------------------------------------------------
class TestAppendCost:
    """The defect that stopped the event loop, stated as a bound."""

    def test_appending_touches_only_the_new_rows(self) -> None:
        """The regression: this used to be 2,000 deletes and 2,001 inserts."""
        table = _Table(max_rows=2000)
        table.add_rows([_row(i) for i in range(2000)])
        before_inserts, before_deletes = table.tree.inserts, table.tree.deletes

        table.add_rows([_row(9000)])

        assert table.tree.inserts - before_inserts == 1
        # One eviction, because the table was already at its cap.
        assert table.tree.deletes - before_deletes == 1

    def test_the_cost_does_not_grow_with_the_rows_already_held(self) -> None:
        """A big table and a small one charge the same for one new packet."""
        costs = []
        for cap in (100, 1000, 5000):
            table = _Table(max_rows=cap)
            table.add_rows([_row(i) for i in range(cap)])
            mark = table.tree.inserts
            table.add_rows([_row(90000)])
            costs.append(table.tree.inserts - mark)
        assert costs == [1, 1, 1]

    def test_a_batch_costs_its_own_size(self) -> None:
        """Fifty new packets is fifty inserts, not fifty full redraws."""
        table = _Table(max_rows=2000)
        table.add_rows([_row(i) for i in range(500)])
        mark = table.tree.inserts
        table.add_rows([_row(1000 + i) for i in range(50)])
        assert table.tree.inserts - mark == 50

    def test_a_single_row_append_is_incremental_too(self) -> None:
        """``add_row`` shares the path with ``add_rows``."""
        table = _Table(max_rows=100)
        table.add_rows([_row(i) for i in range(100)])
        mark = table.tree.inserts
        table.add_row(_row(500))
        assert table.tree.inserts - mark == 1


class TestBoundedTable:
    """A live table must stay bounded in the widget, not only in the model."""

    def test_the_cap_holds_in_the_widget(self) -> None:
        """Otherwise memory grows without bound during a capture."""
        table = _Table(max_rows=200)
        for batch in range(10):
            table.add_rows([_row(batch * 100 + i) for i in range(100)])
        assert len(table.tree.items) == 200
        assert len(table._order) == 200  # noqa: SLF001

    def test_evicted_rows_leave_the_widget(self) -> None:
        """The model and the widget must not disagree about what is shown."""
        table = _Table(max_rows=50)
        table.add_rows([_row(i) for i in range(200)])
        assert set(table.tree.items) == set(table._order)  # noqa: SLF001

    def test_the_trim_is_counted_so_it_can_be_reported(self) -> None:
        """The operator is told the view is windowed, not silently truncated."""
        table = _Table(max_rows=50)
        table.add_rows([_row(i) for i in range(200)])
        assert table.trimmed_count == 150

    def test_the_visible_count_tracks_an_incremental_append(self) -> None:
        """The footer read "Showing 0 of 31" while 31 rows were on screen:
        the append loop counted into a local and never stored the result."""
        table = _Table(max_rows=100)
        table.add_rows([_row(i) for i in range(30)])
        assert table.visible_count == 30
        table.add_rows([_row(100 + i) for i in range(5)])
        assert table.visible_count == 35

    def test_the_visible_count_survives_eviction(self) -> None:
        """At the cap, adding and evicting must leave the count at the cap."""
        table = _Table(max_rows=20)
        table.add_rows([_row(i) for i in range(60)])
        assert table.visible_count == 20

    def test_the_visible_count_is_not_read_back_from_the_widget(self) -> None:
        """get_children() builds a tuple of every row - O(n) all over again."""
        source = inspect.getsource(DataTable.visible_count.fget)  # type: ignore[union-attr]
        assert "get_children" not in source

    def test_a_sorted_table_still_renders_in_full(self) -> None:
        """Position depends on content, so there is no correct end to append to."""
        table = _Table(max_rows=100)
        table.add_rows([_row(i) for i in range(10)])
        table._sort_key = "source"  # noqa: SLF001
        mark = table.tree.inserts
        table.add_rows([_row(999)])
        assert table.tree.inserts - mark > 1


# ---------------------------------------------------------------------------
# Coalescing and filtering on the live screen
# ---------------------------------------------------------------------------
class _Packet:
    """A captured packet, as the screen and the packet view read one."""

    def __init__(self, layers: tuple[str, ...] = ("ETH", "IP", "ICMP")) -> None:
        self.layers = layers
        self.protocol = layers[-1]
        self.direction = ""
        self.src_ip = ""
        self.dst_ip = ""
        self.src_mac = ""
        self.dst_mac = ""


class _Screen:
    """TrafficScreen's buffering logic, without a display."""

    def __init__(self) -> None:
        self._buffer: list[Any] = []
        self._flush_job: str | None = None
        self._seen_since_flush = 0
        self._buffer_dropped = 0
        self.scheduled = 0

    _buffer_packets = TrafficScreen._buffer_packets

    def _flush_buffer(self) -> None:
        """The real flush needs a table; scheduling it is what is under test."""

    @property
    def is_alive(self) -> bool:
        return True

    def after(self, _ms: int, _cb: Any) -> str:
        self.scheduled += 1
        return "job1"


class TestCoalescing:
    """Display cost is bounded by the clock, not by the packet rate."""

    def test_packets_are_buffered_rather_than_drawn_on_arrival(self) -> None:
        """Each table write has a fixed cost; fewer writes is the whole point."""
        screen = _Screen()
        screen._buffer_packets([_Packet() for _ in range(200)])
        assert len(screen._buffer) == 200
        assert screen.scheduled == 1

    def test_many_batches_schedule_one_flush(self) -> None:
        """Twenty arrivals in a tick must not become twenty redraws."""
        screen = _Screen()
        for _ in range(20):
            screen._buffer_packets([_Packet()])
        assert screen.scheduled == 1

    def test_the_flush_cadence_is_bounded(self) -> None:
        """A quarter second is fast enough to read and cheap enough to survive."""
        assert 100 <= FLUSH_INTERVAL_MS <= 500

    def test_the_display_buffer_is_bounded(self) -> None:
        """A flood must not grow the buffer without limit."""
        screen = _Screen()
        screen._buffer_packets([_Packet() for _ in range(MAX_BUFFERED_PACKETS * 3)])
        assert len(screen._buffer) == MAX_BUFFERED_PACKETS

    def test_an_overflowing_buffer_keeps_the_newest_and_counts_the_rest(self) -> None:
        """Silently losing packets from a live view would be the wrong answer."""
        screen = _Screen()
        screen._buffer_packets([_Packet() for _ in range(MAX_BUFFERED_PACKETS + 500)])
        assert screen._buffer_dropped == 500

    def test_everything_arriving_is_counted(self) -> None:
        """What reached the screen is counted whether or not it was drawn."""
        screen = _Screen()
        screen._buffer_packets([_Packet() for _ in range(100)])
        assert screen._seen_since_flush == 100


def _view(expression: str) -> tuple[Any, list[Any]]:
    """A packet view with ``expression`` applied, driven by hand."""
    from aethra_sec.analytics.display_filter import compile_filter
    from aethra_sec.analytics.traffic_direction import LocalAddresses
    from aethra_sec.services.packet_view import PacketView

    published: list[Any] = []
    ticks = [0.0]

    def clock() -> float:
        ticks[0] += 1.0
        return ticks[0]

    view = PacketView(
        lambda _kind, payload: published.append(payload),
        resolver=lambda _interface: LocalAddresses(),
        clock=clock,
    )
    view.begin_session("test0")
    view.apply_filter(compile_filter(expression))
    return view, published


def _listed(published: list[Any]) -> list[Any]:
    return [packet for payload in published for packet in payload.packets]


class TestDisplayViews:
    """Choose what to watch, and do not pay for the rest."""

    def test_the_required_views_are_offered(self) -> None:
        """All, Incoming, Outgoing, Transit; HTTP, HTTPS, Web, TCP, UDP, ICMP, DNS, ARP."""
        assert {key for key, _label in DIRECTION_BUTTONS} == {"", "INCOMING", "OUTGOING", "TRANSIT"}
        assert {key for key, _label in PROTOCOL_BUTTONS} == {
            "HTTP", "HTTPS", "WEB", "SITES", "TCP", "UDP", "ICMP", "DNS", "ARP",
        }

    def test_all_traffic_admits_everything(self) -> None:
        """The default view hides nothing."""
        view, published = _view("")
        view.ingest([_Packet(("ETH", "IP", "ICMP")), _Packet(("ETH", "IP", "TCP"))])
        view.step()
        view.step()
        assert len(_listed(published)) == 2

    @pytest.mark.parametrize("protocol", ["icmp", "tcp", "udp", "arp"])
    def test_a_protocol_view_admits_only_that_protocol(self, protocol: str) -> None:
        """Watching ICMP means a TCP flood costs the view nothing."""
        view, published = _view(protocol)
        view.ingest([_Packet(("ETH", "IP", protocol.upper())), _Packet(("ETH", "IP", "OTHER"))])
        view.step()
        view.step()
        listed = _listed(published)
        assert len(listed) == 1 and listed[0].layers[-1] == protocol.upper()

    def test_an_application_view_matches_the_decoded_layer_not_the_port(self) -> None:
        """HTTP is what TShark decoded, not where the packet was going."""
        view, published = _view("http")
        decoded = _Packet(("ETH", "IP", "TCP", "HTTP"))
        port_only = _Packet(("ETH", "IP", "TCP"))
        port_only.dst_port = 80
        view.ingest([decoded, port_only])
        view.step()
        view.step()
        assert _listed(published) == [decoded]

    def test_filtering_happens_before_the_screen(self) -> None:
        """Traffic nobody asked for never reaches the table at all."""
        view, published = _view("icmp")
        view.ingest([_Packet(("ETH", "IP", "TCP")) for _ in range(500)])
        view.step()
        view.step()
        assert _listed(published) == []
        assert view.statistics().evaluated == 500
        assert view.statistics().matched == 0


class TestHonesty:
    """None of the above is allowed to quietly reduce what is monitored."""

    def test_changing_the_display_filter_is_not_a_capture_change(self) -> None:
        """A display filter must never stop, start or re-filter the capture."""
        source = inspect.getsource(TrafficScreen._apply_display_filter)
        for forbidden in (
            "capture.stop", "capture.start", "_bpf_var", "_perform_stop",
            "_begin_capture", "rules",
        ):
            assert forbidden not in source

    def test_the_screen_states_what_it_is_not_showing(self) -> None:
        """A quiet table during a flood would be a lie."""
        source = inspect.getsource(TrafficScreen._update_surge_note)
        assert "still analysed, counted and stored" in source
        assert "not matching this view" in source

    def test_the_drop_count_is_surfaced_not_swallowed(self) -> None:
        """If the display buffer overflows, the operator is told."""
        source = inspect.getsource(TrafficScreen._update_surge_note)
        assert "_buffer_dropped" in source

    def test_the_https_limitation_is_stated_for_encrypted_views(self) -> None:
        source = inspect.getsource(TrafficScreen._update_surge_note)
        assert "HTTPS_NOTICE" in source

    def test_the_table_is_not_narrowed_by_matching_rendered_text(self) -> None:
        source = inspect.getsource(TrafficScreen._build_packet_table)
        assert "show_toolbar=False" in source

    def test_hiding_the_screen_stops_drawing_not_capturing(self) -> None:
        """Leaving the page must not reduce detection."""
        source = inspect.getsource(TrafficScreen.on_hide)
        assert "_cancel_flush" in source
        for forbidden in ("capture.stop", "self.context.capture.stop"):
            assert forbidden not in source

    def test_the_module_documents_why_the_cadence_exists(self) -> None:
        """So the next person does not 'optimise' it away."""
        assert "FLUSH_INTERVAL_MS" in inspect.getsource(traffic_module)
