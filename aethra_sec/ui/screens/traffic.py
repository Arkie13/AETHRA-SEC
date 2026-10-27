"""Network monitoring screen (§11-§14, §64).

Live packet table, capture controls, traffic analytics and a packet detail
panel. The table is bounded (§105): once the configured row cap is reached the
oldest rows leave the *view* while the database keeps the full history, and the
row counter says so explicitly.

Two filters, never confused
---------------------------
The CAPTURE FILTER (BPF) in the capture strip is applied by dumpcap before a
frame is captured; changing it restarts capture. The DISPLAY FILTER above the
table - the preset buttons, the IP and port searches and the typed expression -
is applied by the capture service's packet view to packets already captured. It
never restarts capture and never changes what is analysed or stored.

The table is fed only by the packet view (DISPLAY_VIEW_RESET / _BATCH), so every
row on it matched the filter this screen shows. A batch filtered under an older
filter carries an older generation and is never appended.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from aethra_sec.analytics.display_filter import (
    HTTPS_NOTICE,
    NOT_VISIBLE_NOTICE,
    ComposedFilter,
    FilterRequest,
    FilterSyntaxError,
    compose_filter,
)
from aethra_sec.analytics.traffic_direction import DIRECTION_ORDER, Direction
from aethra_sec.core.errors import AethraError
from aethra_sec.core.events import Event, EventType
from aethra_sec.integrations.pyshark_capture import CaptureInterface
from aethra_sec.models.traffic import CapturedPacket, tls_version_name
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import METRICS, PALETTE, configure_text_widget
from aethra_sec.ui.widgets import (
    BarChart,
    Card,
    Column,
    DataTable,
    DonutChart,
    InterfacePicker,
    PacketInspector,
    StatusChip,
    RowAction,
    TimeSeriesChart,
    Toolbar,
    bytes_formatter,
    confirm,
    show_message,
)
from aethra_sec.ui.widgets.tooltip import Tooltip
from aethra_sec.utils.formatting import (
    NO_DATA_TEXT,
    WAITING_FOR_CAPTURE_TEXT,
    format_bandwidth,
    format_bytes,
    format_count,
    format_rate,
    truncate,
)
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import format_local_ms

LOGGER = get_logger("ui.traffic")

PACKET_COLUMNS = (
    Column("time", "Time", width=100),
    Column("source", "Source", width=140),
    Column("destination", "Destination", width=140),
    Column("protocol", "Protocol", width=76),
    Column("sport", "Src port", width=66, anchor="e"),
    Column("dport", "Dst port", width=66, anchor="e"),
    Column("length", "Length", width=60, anchor="e"),
    Column("direction", "Direction", width=80),
    Column("info", "Info", width=360, stretch=True),
)


#: Live table writes are coalesced onto this cadence. Each write costs the Tk
#: thread a fixed amount whatever its size, so bounding writes per second is
#: what keeps the interface responsive when the packet rate is not bounded.
FLUSH_INTERVAL_MS = 250

#: Most packets held for display between flushes. The database keeps every
#: record; this only bounds what the screen is asked to draw.
MAX_BUFFERED_PACKETS = 5000

#: Most packet rows inserted into the table in one flush. The table keeps only
#: ``ui.packet_table_max_rows`` (2,000) newest rows, so inserting more than a
#: bounded number per flush only costs Tk-thread time that a trim then throws
#: away. A live UI-stall report (logs/ui_stall_20261015_232606_1.txt) caught
#: the Tk thread 5.5 s deep in ttk Treeview inserts during a flood: a single
#: flush was inserting thousands of rows. Capping it bounds each flush's cost
#: by the clock. The newest rows win; the database keeps every packet.
MAX_ROWS_PER_FLUSH = 600

#: Direction views on the filter bar, left to right. The empty key is "all
#: directions" - the absence of a direction filter, not a filter of its own.
DIRECTION_BUTTONS: tuple[tuple[str, str], ...] = (
    ("", "All Traffic"),
    ("INCOMING", "Incoming"),
    ("OUTGOING", "Outgoing"),
    ("TRANSIT", "Transit"),
)

#: Protocol views on the filter bar. Choosing the active one again clears it.
PROTOCOL_BUTTONS: tuple[tuple[str, str], ...] = (
    ("HTTP", "HTTP"),
    ("HTTPS", "HTTPS/TLS"),
    # "Web" was removed: it was exactly HTTP or HTTPS/TLS, both of which are
    # still on the bar beside it, so it offered nothing the two of them did
    # not already offer one click apart.
    ("SITES", "Sites"),
    ("TCP", "TCP"),
    ("UDP", "UDP"),
    ("ICMP", "ICMP"),
    ("DNS", "DNS"),
    ("ARP", "ARP"),
)

#: How an IP or port search is scoped, as its combobox shows it.
SCOPE_LABELS: dict[str, str] = {
    "either": "Either",
    "source": "Source",
    "destination": "Destination",
}

#: The packet view publishes a re-filtered table within a quarter second, but
#: screens receive events only on the application tick, which defaults to two
#: seconds. After a filter change the screen pumps events itself for a short
#: while, so a click is answered promptly.
FILTER_PUMP_INTERVAL_MS = 150
FILTER_PUMP_ATTEMPTS = 20

#: Packets that must have been taken in before an empty view that depends on
#: seeing other devices is attributed to the capture position, rather than to a
#: network that has simply been quiet so far.
VISIBILITY_SAMPLE = 200

#: Width of the analytics column beside the packet table. Narrow on
#: purpose: traffic rate and protocol mix are glanced at, not read, and
#: every pixel here is a pixel the packet stream does not get.
ANALYTICS_COLUMN_WIDTH = 300

# Capture states shown to the operator. The first four are the service's own
# truth; PAUSED and STOPPING describe what this screen is doing and are only
# ever shown alongside a real backend state.
# The capture service's own state names. This screen does not invent a second
# vocabulary: it shows what the pipeline reports, so the chip and the service
# can never disagree about whether a capture is running.
STATE_IDLE = "IDLE"
STATE_STARTING = "STARTING"
STATE_CAPTURING = "CAPTURING"
STATE_STOPPING = "STOPPING"
STATE_STOPPED = "STOPPED"
STATE_FAILED = "FAILED"

#: The one state that belongs to the display rather than the pipeline: capture
#: continues while the table is held still.
STATE_PAUSED = "PAUSED"

#: Table footer messages. Each states why the table is empty rather than
#: implying that nothing happened.
EMPTY_READY = "No capture running. Choose an interface and press Start capture."
EMPTY_WAITING = "No packets captured yet."
EMPTY_STOPPED = "Capture stopped."
EMPTY_ERROR = "Capture could not start - see the message above."


class TrafficScreen(Screen):
    """Live packet capture and traffic analytics."""

    title = "Live Monitoring"
    subtitle = "Live packet capture and traffic analysis (PyShark / TShark)"
    required_permission = "monitor.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._interfaces: list[CaptureInterface] = []
        self._paused = False
        #: True between asking the service to stop and the reader ending.
        self._stopping = False
        #: True while a start is in flight. Guards the window between asking
        #: for a capture and TShark actually running, where a second request
        #: would spawn a duplicate process.
        self._starting = False
        #: Set when the operator presses Stop. Automatic start-up respects it,
        #: so returning to this screen does not undo their decision.
        self._stopped_by_operator = False
        #: Interface of the capture whose packets are on screen.
        self._last_interface = ""
        self._packet_index: dict[str, CapturedPacket] = {}
        self._sequence = 0
        #: Packets waiting for the next coalesced flush to the table.
        self._buffer: list[CapturedPacket] = []
        self._flush_job: str | None = None
        self._seen_since_flush = 0
        self._buffer_dropped = 0
        #: The display filter the table shows, and the request it came from.
        self._active_filter: ComposedFilter = compose_filter(FilterRequest())
        self._direction_key = ""
        self._protocol_key = ""
        #: Generation of the packet-view table this screen is showing. A batch
        #: from any other generation was filtered under a different filter.
        self._expected_generation = 0
        self._view_generation_seen = 0
        self._view_statistics: Any = None
        self._filter_error = ""
        self._pump_job: str | None = None
        self._pump_remaining = 0
        #: Set when matching packets arrived while the display was paused.
        self._missed_while_paused = False
        self._last_state = STATE_IDLE

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the monitoring screen.

        The packet stream is the work, so it gets the page: the capture strip
        takes the height it needs and nothing more, and the table fills
        everything left over. The analytics sit in a narrow column beside it
        rather than above or across, where they would cost the table rows.
        """
        self._build_controls()

        body = ttk.Frame(self, style="TFrame")
        body.pack(fill="both", expand=True, pady=(METRICS.space_md, 0))

        # The analytics column is packed first so it reserves its width; the
        # packet table then fills whatever remains. Packing it last would let
        # the table's wide columns squeeze it to nothing.
        right = ttk.Frame(body, style="TFrame", width=ANALYTICS_COLUMN_WIDTH)
        right.pack(side="right", fill="y", padx=(METRICS.space_md, 0))
        right.pack_propagate(False)
        self._build_analytics(right)

        left = ttk.Frame(body, style="TFrame")
        left.pack(side="left", fill="both", expand=True)
        self._build_packet_table(left)

    def _build_controls(self) -> None:
        """Capture controls as one compact strip.

        Choosing an interface is a one-off decision and watching packets is the
        work, so this takes the height it needs and no more. The interface list
        that used to sit here was eighteen rows tall on this machine, which
        pushed the packet table off the page.
        """
        card = Card(self, "Capture", fonts=self.fonts, padding=METRICS.space_md)
        card.pack(fill="x")

        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")

        ttk.Label(row, text="INTERFACE", style="CardDim.TLabel").pack(side="left")
        self._picker = InterfacePicker(
            row, on_select=self._on_interface_chosen, surface=card.fill
        )
        self._picker.pack(side="left", padx=(METRICS.space_sm, METRICS.space_lg))

        ttk.Button(
            row, text="Refresh", style="Ghost.TButton",
            command=self._load_interfaces,
        ).pack(side="left", padx=(0, METRICS.space_lg))

        ttk.Label(row, text="CAPTURE FILTER (BPF)", style="CardDim.TLabel").pack(
            side="left"
        )
        self._bpf_var = tk.StringVar(value=self.context.settings.capture.bpf_filter)
        bpf_entry = ttk.Entry(row, textvariable=self._bpf_var, width=30)
        bpf_entry.pack(side="left", padx=(METRICS.space_sm, METRICS.space_lg))
        Tooltip(
            bpf_entry,
            "CAPTURE FILTER (BPF): applied by dumpcap before a packet is "
            "captured, so excluded traffic is never recorded, analysed or "
            "stored - for example: tcp port 80, udp, host <address>. Changing "
            "it restarts capture. The DISPLAY FILTER above the packet table is "
            "different: it only chooses which captured packets are shown.",
        )

        self._start_button = ttk.Button(
            row, text="Start capture", style="Accent.TButton",
            command=self._start_capture,
        )
        self._start_button.pack(side="left")
        self._stop_button = ttk.Button(
            row, text="Stop capture", style="Danger.TButton",
            command=self._stop_capture,
        )
        self._stop_button.pack(side="left", padx=(METRICS.space_sm, 0))
        self._stop_button.state(["disabled"])

        if not self.can("monitor.control"):
            self._start_button.state(["disabled"])
            self._stop_button.state(["disabled"])

        # --- status: the real capture state ----------------------------
        status_row = ttk.Frame(card, style="Card.TFrame")
        status_row.pack(fill="x", pady=(METRICS.space_sm, 0))
        self._status_chip = StatusChip(
            status_row, "CAPTURE", state=STATE_IDLE,
            fonts=self.fonts, surface=card.fill,
        )
        self._status_chip.pack(side="left")
        self._status_detail = ttk.Label(
            status_row, text="", style="CardMuted.TLabel"
        )
        self._status_detail.pack(side="left", padx=(METRICS.space_sm, 0))
        self._counters_label = ttk.Label(
            status_row, text="", style="CardDim.TLabel"
        )
        self._counters_label.pack(side="left", padx=(METRICS.space_md, 0))

        self._permission_note = ttk.Label(
            card, text="", style="CardDim.TLabel", justify="left"
        )
        self._retry_button = ttk.Button(
            card, text="Retry capture", style="Accent.TButton",
            command=self._retry_capture,
        )
        # A fixed wraplength clips whenever the window is narrower than the
        # guess, so follow the card's real width.
        card.bind(
            "<Configure>",
            lambda event: self._permission_note.configure(
                wraplength=max(360, event.width - 2 * METRICS.space_lg)
            ),
            add="+",
        )

    def _build_packet_table(self, parent: tk.Misc) -> None:
        """Live packet table with display controls and a detail pane."""
        # The detail pane is created and packed to the bottom first so it
        # reserves its height: packed after an expanding table it was squeezed
        # to nothing and a selected packet had nowhere to show its decode.
        # Shown only once a packet is selected. While the operator is watching
        # the stream - the normal state - those rows belong to the table, and
        # an empty pane saying "select a packet" is not worth 160px of it.
        self._detail_card = Card(
            parent, "Packet detail", fonts=self.fonts, padding=12
        )
        detail_card = self._detail_card
        # Compact: the packet stream is the workspace, and a decode this size
        # still shows the frame, its addresses and its transport.
        self._detail_text = tk.Text(detail_card, height=8, wrap="word")
        configure_text_widget(self._detail_text, self.fonts, mono=True)
        self._detail_text.insert("1.0", "Select a packet to see its decoded fields.")
        self._detail_text.configure(state="disabled")
        self._detail_text.pack(fill="x")

        card = Card(parent, "Live packets", fonts=self.fonts, padding=12)
        card.pack(side="top", fill="both", expand=True)

        self._build_filter_bar(card)

        self._table = DataTable(
            card, PACKET_COLUMNS, height=18, mono=True,
            # No quick-filter box: it matches rendered text, and this table is
            # narrowed by the display filter, which evaluates packet fields.
            show_toolbar=False,
            max_rows=self._max_rows(), on_select=self._show_packet_detail,
            # Opening a packet reads the frame back from the capture file and
            # shows TShark's own decode, rather than the summary this row holds.
            on_activate=self._inspect_packet,
            actions=[
                RowAction("Inspect packet", self._inspect_packet),
                RowAction("Follow TCP stream", lambda row: self._inspect_packet(row, follow="tcp")),
                RowAction("Follow UDP stream", lambda row: self._inspect_packet(row, follow="udp")),
                RowAction("Mark / unmark packet", self._toggle_mark),
                RowAction("Copy packet summary", self._copy_packet_summary),
                RowAction("Filter by source", lambda row: self._filter_by(row, "src_ip")),
                RowAction("Filter by destination", lambda row: self._filter_by(row, "dst_ip")),
                RowAction("Filter by protocol", lambda row: self._filter_by(row, "protocol")),
                RowAction("Filter by source port", lambda row: self._filter_by(row, "src_port")),
                RowAction("Filter by destination port", lambda row: self._filter_by(row, "dst_port")),
            ],
        )
        self._table.pack(fill="both", expand=True)



    def _build_filter_bar(self, card: Any) -> None:
        """Presets, searches and the display filter, in as little height as fits.

        Two wrapping rows of controls and two lines of text. The packet table
        below keeps the rest of the card: it is the workspace, and these only
        decide which captured packets it shows. None of them touches capture.
        """
        presets = Toolbar(card)
        presets.pack(fill="x", pady=(0, 4))
        self._direction_buttons: dict[str, ttk.Button] = {}
        for key, label in DIRECTION_BUTTONS:
            self._direction_buttons[key] = presets.add_button(
                label, lambda chosen=key: self._select_direction(chosen),
                style="Tool.TButton",
            )
        presets.add_label("·")
        self._protocol_buttons: dict[str, ttk.Button] = {}
        for key, label in PROTOCOL_BUTTONS:
            self._protocol_buttons[key] = presets.add_button(
                label, lambda chosen=key: self._select_protocol(chosen),
                style="Tool.TButton",
            )
        presets.add_label("·")
        clear_button = presets.add_button(
            "Clear Filter", self._clear_filters, style="Tool.TButton"
        )
        # The theme gives every button a wide minimum width, which put the
        # presets on two rows. Sized to their labels they fit on one, and the
        # table keeps the height.
        for button in (
            *self._direction_buttons.values(), *self._protocol_buttons.values(), clear_button
        ):
            button.configure(width=len(str(button.cget("text"))) + 1)
        Tooltip(
            self._direction_buttons["TRANSIT"],
            "Traffic between two other devices that reached this adapter. On a "
            "switched or wireless network that needs a mirror (SPAN) port, a "
            "network TAP, or AETHRA-SEC in the traffic path.",
        )
        Tooltip(self._protocol_buttons["HTTPS"], HTTPS_NOTICE)
        Tooltip(
            self._protocol_buttons["SITES"],
            "Names this computer connected to or looked up: HTTPS server names "
            "(SNI), HTTP Host headers and DNS queries. Names, not pages - an HTTPS "
            "page's path and content are encrypted. Background services appear "
            "too, and secure DNS or an encrypted Client Hello can hide a name.",
        )
        Tooltip(
            clear_button,
            "Return to all traffic. Capture is not stopped and nothing captured "
            "is discarded.",
        )

        searches = Toolbar(card)
        searches.pack(fill="x", pady=(0, 4))

        def group() -> ttk.Frame:
            # A field wraps together with its caption and its button or scope,
            # so a narrow window never strands a scope box on a line apart from
            # the field it scopes.
            frame = ttk.Frame(searches, style="Card.TFrame")
            searches.add(frame, padx=(0, 8))
            return frame

        def caption(parent: ttk.Frame, text: str) -> None:
            ttk.Label(parent, text=text, style="CardMuted.TLabel").pack(
                side="left", padx=(0, Toolbar.GAP)
            )

        filter_group = group()
        caption(filter_group, "DISPLAY FILTER")
        self._display_filter_var = tk.StringVar()
        # Long expressions scroll inside the entry; its width is what lets the
        # three search groups and the table actions share one line.
        filter_entry = ttk.Entry(filter_group, textvariable=self._display_filter_var, width=26)
        filter_entry.pack(side="left", padx=(0, 4))
        filter_entry.bind("<Return>", lambda _e: self._apply_display_filter())
        ttk.Button(
            filter_group, text="Apply", command=self._apply_display_filter,
            style="ToolAccent.TButton", width=len("Apply") + 1,
        ).pack(side="left")

        ip_group = group()
        caption(ip_group, "IP")
        self._ip_var = tk.StringVar()
        ip_entry = ttk.Entry(ip_group, textvariable=self._ip_var, width=16)
        ip_entry.pack(side="left", padx=(0, 4))
        ip_entry.bind("<Return>", lambda _e: self._apply_display_filter())
        self._ip_scope_var = tk.StringVar(value=SCOPE_LABELS["either"])
        ip_scope = ttk.Combobox(
            ip_group, textvariable=self._ip_scope_var, state="readonly", width=10,
            values=list(SCOPE_LABELS.values()),
        )
        ip_scope.pack(side="left")
        ip_scope.bind(
            "<<ComboboxSelected>>",
            lambda _e: self._apply_display_filter() if self._ip_var.get().strip() else None,
        )

        port_group = group()
        caption(port_group, "PORT")
        self._port_var = tk.StringVar()
        port_entry = ttk.Entry(port_group, textvariable=self._port_var, width=7)
        port_entry.pack(side="left", padx=(0, 4))
        port_entry.bind("<Return>", lambda _e: self._apply_display_filter())
        self._port_scope_var = tk.StringVar(value=SCOPE_LABELS["either"])
        port_scope = ttk.Combobox(
            port_group, textvariable=self._port_scope_var, state="readonly", width=10,
            values=list(SCOPE_LABELS.values()),
        )
        port_scope.pack(side="left")
        port_scope.bind(
            "<<ComboboxSelected>>",
            lambda _e: self._apply_display_filter() if self._port_var.get().strip() else None,
        )

        # Table actions share the search row's right-hand end, sized to their
        # labels so the row does not wrap on an ordinary console width.
        self._pause_button = searches.add_button(
            "Pause display", self._toggle_pause, side="right"
        )
        clear_display = searches.add_button("Clear display", self._clear_display, side="right")
        export_view = searches.add_button("Export view", self._export_view, side="right")
        for button in (self._pause_button, clear_display, export_view):
            button.configure(width=len("Resume display") if button is self._pause_button else len(str(button.cget("text"))) + 1)

        Tooltip(
            filter_entry,
            "DISPLAY FILTER: chooses which captured packets are shown. It never "
            "restarts capture or changes what is analysed and stored. "
            "Wireshark-style, for example: http, tls, dns || icmp, "
            "ip.addr == <address>, tcp.port == 443, "
            "http && direction == incoming. Press Enter or Apply.",
        )
        Tooltip(
            ip_entry,
            "An address, or a network such as <address>/24, matched against the "
            "IP source, destination or either of captured packets. Searching "
            "for an address never creates a host.",
        )
        Tooltip(
            port_entry,
            "A TCP or UDP port. A port is where traffic went, not what it "
            "contained: port 443 is not assumed to be HTTPS.",
        )

        self._filter_state_label = ttk.Label(
            card, text="", style="CardMuted.TLabel", justify="left"
        )
        self._filter_state_label.pack(fill="x", anchor="w")
        self._view_counts_label = ttk.Label(
            card, text="", style="CardDim.TLabel", justify="left"
        )
        self._view_counts_label.pack(fill="x", anchor="w", pady=(2, 4))
        # Notes shown only when they apply: the HTTPS limitation, a view that
        # depends on traffic this adapter cannot see, what the table could not
        # hold. They report what was counted; nothing here is estimated.
        self._surge_label = ttk.Label(
            card, text="", style="CardMuted.TLabel", justify="left"
        )

        def rewrap(event: tk.Event) -> None:
            width = max(360, event.width - 2 * METRICS.space_lg)
            for label in (
                self._filter_state_label, self._view_counts_label, self._surge_label
            ):
                label.configure(wraplength=width)

        card.bind("<Configure>", rewrap, add="+")
        self._refresh_filter_controls()
        self._render_filter_state()

    def _build_analytics(self, parent: tk.Misc) -> None:
        """Right-hand analytics column."""
        rate_card = Card(parent, "Traffic rate", fonts=self.fonts, padding=12)
        rate_card.pack(fill="x")
        self._rate_chart = TimeSeriesChart(
            rate_card, height=120, empty_message=WAITING_FOR_CAPTURE_TEXT,
            value_formatter=lambda v: f"{v:,.0f}",
        )
        self._rate_chart.pack(fill="x")
        self._rate_label = ttk.Label(rate_card, text="", style="CardMuted.TLabel")
        self._rate_label.pack(anchor="w", pady=(6, 0))

        protocol_card = Card(parent, "Protocols", fonts=self.fonts, padding=12)
        protocol_card.pack(fill="x", pady=(10, 0))
        self._protocol_chart = DonutChart(
            protocol_card, height=140, centre_label="packets",
            empty_message=NO_DATA_TEXT,
        )
        self._protocol_chart.pack(fill="x")

        talkers_card = Card(parent, "Top talkers", fonts=self.fonts, padding=12)
        talkers_card.pack(fill="both", expand=True, pady=(10, 0))
        self._sources_chart = BarChart(
            talkers_card, height=130, empty_message=NO_DATA_TEXT, max_bars=6
        )
        self._sources_chart.pack(fill="x")
        ttk.Label(
            talkers_card, text="Top destination ports", style="CardDim.TLabel"
        ).pack(anchor="w", pady=(8, 2))
        self._ports_chart = BarChart(
            talkers_card, height=130, empty_message=NO_DATA_TEXT, max_bars=6
        )
        self._ports_chart.pack(fill="x")

    def _max_rows(self) -> int:
        """Row cap for the live table."""
        settings = self.context.settings_service
        return settings.get_int("ui.packet_table_max_rows", 2000) if settings else 2000

    # ------------------------------------------------------------------
    # Interfaces and capture control
    # ------------------------------------------------------------------
    def on_show(self) -> None:
        """Load interfaces, reflect capture state, apply the filter, start if idle.

        Enumeration is asynchronous, so the automatic start happens once it
        returns (see :meth:`_apply_interfaces`). When the interfaces are
        already known - navigating back to this screen - there is nothing to
        wait for, so the same check runs immediately. Either way it reuses a
        running capture rather than starting a second one.

        The display filter this screen shows is re-applied too. Events reach
        only the visible screen, so the table missed whatever arrived while it
        was hidden; re-applying fills it from the packets the view retained.
        """
        self._load_interfaces()
        self._update_capture_state()
        self._sync_display_filter()
        if self._interfaces:
            self._maybe_autostart()

    def on_hide(self) -> None:
        """Stop the flush timer while the screen is not visible.

        Capture keeps running and keeps analysing - only the drawing stops,
        which is the part nobody is looking at.
        """
        self._cancel_flush()
        self._cancel_pump()

    def _cancel_flush(self) -> None:
        """Cancel a pending coalesced flush, if one is scheduled."""
        if self._flush_job is None:
            return
        try:
            self.after_cancel(self._flush_job)
        except (tk.TclError, ValueError):  # pragma: no cover - already fired
            pass
        self._flush_job = None

    def _load_interfaces(self) -> None:
        """Enumerate capture interfaces as TShark reports them (§38)."""
        capture = self.context.capture
        if capture is None:
            return
        self.status("Enumerating capture interfaces...")
        self.run_async(
            lambda: (capture.list_interfaces(), capture.availability()),
            self._apply_interfaces,
            name="interface-load",
        )

    def _apply_interfaces(self, payload: tuple[list[CaptureInterface], Any]) -> None:
        """Populate the interface picker from the real enumeration."""
        interfaces, availability = payload
        self._interfaces = interfaces

        configured = self.context.settings.capture.interface or (
            self.context.capture.interface if self.context.capture else ""
        )
        self._picker.set_interfaces(interfaces, configured)

        if not availability.available:
            self._permission_note.configure(
                text=availability.detail, foreground=PALETTE.critical
            )
            self._permission_note.pack(anchor="w", pady=(METRICS.space_md, 0))
            self._start_button.state(["disabled"])
            self.status("TShark is not available - capture cannot start.")
            self._update_capture_state()
            return

        # Capture is available, so the Npcap troubleshooting notes are not
        # needed yet. They are shown the moment a capture actually fails, which
        # is when they help - keeping them on screen permanently cost three
        # lines of the packet list for guidance nobody was reading.
        self._permission_note.pack_forget()
        self._retry_button.pack_forget()
        self.status(f"{len(interfaces)} capture interface(s) available.")
        self._update_capture_state()
        # Interfaces are only known now - enumeration runs off the Tk thread -
        # so this is the first moment an interface can be chosen and capture
        # can begin. Opening the screen is the trigger; no button is involved.
        self._maybe_autostart()

    def _on_interface_chosen(self, interface: Any) -> None:
        """Switch capture to the interface the operator picked.

        While a capture is running this is a switch, not a preference: the
        current reader is stopped and the next one starts only once that
        TShark has actually ended, so the two never overlap and no process is
        orphaned. Choosing an interface while capture is stopped only selects
        it - Stop was a decision, and picking a name is not a request to undo
        it.
        """
        capture = self.context.capture
        running = bool(capture and capture.statistics().is_running)
        where = interface.display_name + (
            f" [{interface.primary_ipv4}]" if interface.primary_ipv4 else ""
        )

        if not running:
            self.status(f"Ready to capture on {where}.")
            self._update_capture_state()
            return

        self.status(f"Switching capture to {where}...")
        target = interface.name

        def start_next() -> None:
            # The operator asked for this interface, so an explicit earlier
            # stop no longer applies.
            self._stopped_by_operator = False
            self._begin_capture(target, announce=True)

        self._perform_stop("interface change", then=start_next)

    def _selected_interface(self) -> str:
        """The interface name TShark expects for the current selection."""
        return self._picker.selected_name()

    def _start_capture(self) -> None:
        """Start capture because the operator asked for it.

        Clears the explicit-stop latch: pressing Start is the operator taking
        the decision back, so leaving and returning may auto-start again.
        """
        self._stopped_by_operator = False
        interface = self._selected_interface()
        if not interface:
            self.show_error_message(
                "Select a network interface before starting capture.",
                "No interface selected",
            )
            return
        self._begin_capture(interface, announce=True)

    def _begin_capture(self, interface: str, *, announce: bool) -> None:
        """Start a real capture on ``interface``. The only place that does.

        Automatic start-up, the Start button, a retry and an interface switch
        all arrive here, so there is exactly one capture-start implementation
        and no path can drift from the others.

        Args:
            interface: the identifier TShark expects, from real enumeration.
            announce: True to report a failure in a dialog. Automatic start-up
                passes False - an unattended start that fails should say so on
                the screen, not interrupt with a modal nobody asked for.
        """
        capture = self.context.capture
        session = self.session
        if capture is None or session is None or not interface:
            return

        # Never run two captures. The start is asynchronous, so both the
        # service's own state and an in-flight start have to be checked: the
        # window between pressing Start and TShark actually running is exactly
        # where a second call would spawn a duplicate process.
        if self._starting or capture.statistics().is_running:
            return

        chosen = self._picker.selected()
        friendly = chosen.display_name if chosen is not None else interface

        # Rows already on screen came from a different interface, so they must
        # not sit above the new ones as if they were the same capture.
        if self._last_interface and self._last_interface != interface:
            self._clear_display()
        self._last_interface = interface

        self._starting = True
        self._start_button.state(["disabled"])
        self.status(f"Starting capture on {friendly}...")
        # Read the Tk variable here; the worker must not touch Tk state.
        bpf_filter = self._bpf_var.get().strip()

        def work() -> str:
            capture.start(session, interface, bpf_filter)
            return friendly

        def done(name: str) -> None:
            self._starting = False
            self.status(f"Capturing on {name}.")
            self._update_capture_state()

        def failed(message: str) -> None:
            self._starting = False
            self._start_button.state(["!disabled"])
            self.status("Capture failed to start.")
            # TShark's own words, on the screen, with the interface named. On
            # Windows the difference between a missing Npcap driver and a
            # permissions problem is in that text.
            self._show_capture_error(friendly, message)
            self._update_capture_state()
            if announce:
                self.show_error_message(
                    f"Unable to start capture on {friendly}:\n\n{message}",
                    "Capture could not start",
                )

        self.run_async(work, done, failed, name="capture-start")

    def _show_capture_error(self, friendly: str, message: str) -> None:
        """Put the real capture failure on the screen, with a retry."""
        self._permission_note.configure(
            text=(
                "CAPTURE FAILED\n\n"
                f"Interface: {friendly}\n\n"
                f"Reason: {message}"
            ),
            foreground=PALETTE.critical,
        )
        self._permission_note.pack(anchor="w", pady=(METRICS.space_md, 0))
        self._retry_button.pack(anchor="w", pady=(METRICS.space_sm, 0))

    def _retry_capture(self) -> None:
        """Try the selected interface again after a failure."""
        self._retry_button.pack_forget()
        self._permission_note.pack_forget()
        self._start_capture()

    def _maybe_autostart(self) -> None:
        """Start capturing when the screen opens, without being asked.

        Live Monitoring exists to show live traffic, so arriving at a screen
        that shows nothing until a button is pressed is a dead end. This starts
        the same real capture the Start button starts.

        It declines in three cases, each of which would otherwise be a bug: a
        capture already running (navigating back must reuse the worker, not
        spawn a second TShark), a start already in flight, and a capture the
        operator explicitly stopped - Stop is a decision, and returning to this
        screen must not quietly undo it.
        """
        capture = self.context.capture
        if capture is None or self.session is None:
            return
        if self._stopped_by_operator or self._starting:
            return
        if capture.statistics().is_running:
            # Already capturing: adopt it rather than starting anything.
            self._update_capture_state()
            return
        if not self.can("monitor.control"):
            return
        interface = self._selected_interface()
        if not interface:
            return
        self._begin_capture(interface, announce=False)

    def _stop_capture(self) -> None:
        """Stop capture because the operator asked for it."""
        if not confirm(
            self, "Stop capture", "Stop live packet capture?",
            detail=(
                "Traffic already written to the database is retained. Analysis "
                "and detection stop until capture is restarted. Live "
                "Monitoring will not restart it automatically."
            ),
            confirm_label="Stop capture",
        ):
            return
        # Latch the decision so returning to this screen does not restart it.
        self._stopped_by_operator = True
        self._perform_stop("operator request")

    def _perform_stop(self, reason: str, then: Any = None) -> None:
        """Stop the running capture. The only place that does.

        Args:
            reason: recorded with the stop, for the audit trail.
            then: called on the Tk thread once the reader has actually ended -
                used by an interface switch, so the next capture starts only
                after the previous TShark has gone.
        """
        capture = self.context.capture
        session = self.session
        if capture is None or session is None:
            return

        self._stop_button.state(["disabled"])
        self._stopping = True
        self._update_capture_state()
        self.status("Stopping capture...")

        def stopped(_result: Any) -> None:
            self._stopping = False
            self.status("Capture stopped.")
            self._update_capture_state()
            if then is not None:
                then()

        def failed(message: str) -> None:
            # The reader may still be alive; report it and re-read the real
            # state rather than assuming the capture ended.
            self._stopping = False
            self._update_capture_state()
            self.show_error_message(message, "Capture could not be stopped")

        self.run_async(
            lambda: capture.stop(session, reason),
            stopped, failed, name="capture-stop",
        )

    def _capture_state(self, statistics: Any) -> str:
        """The state to display: the capture service's, not a second opinion.

        This screen used to work the state out for itself from whether the
        pipeline looked busy, which is how it came to show CAPTURING for a
        filter TShark had rejected. The service now runs one state machine and
        reconciles it against the real capture process; the only thing added
        here is PAUSED, which describes the table rather than the capture, and
        which is never allowed to stand in for a state that says capture is
        not running.
        """
        reported = str(getattr(statistics, "state", "") or "").upper()
        if reported == STATE_CAPTURING:
            if self._stopping:
                return STATE_STOPPING
            return STATE_PAUSED if self._paused else STATE_CAPTURING
        if reported:
            return reported

        # Statistics from a source that predates the state field. Report the
        # least optimistic reading rather than guessing at CAPTURING.
        if statistics.last_error:
            return STATE_FAILED
        if statistics.stopped_at:
            return STATE_STOPPED
        return STATE_IDLE

    def _empty_text_for(self, state: str) -> str:
        """What the packet table should say when it holds no rows.

        A display filter that matched nothing says what it was looking for -
        "No HTTP traffic captured." - rather than implying there was no
        traffic at all.
        """
        statistics = getattr(self, "_view_statistics", None)
        active = getattr(self, "_active_filter", None)
        if (
            statistics is not None
            and active is not None
            and not active.is_all
            and statistics.evaluated
            and not statistics.matched
        ):
            return active.empty_text
        if state in (STATE_CAPTURING, STATE_PAUSED, STATE_STOPPING, STATE_STARTING):
            return EMPTY_WAITING
        if state == STATE_STOPPED:
            return EMPTY_STOPPED
        if state == STATE_FAILED:
            return EMPTY_ERROR
        return EMPTY_READY

    def _update_capture_state(self) -> None:
        """Reflect the true capture state in the controls (§120).

        The chip shows the capture service's own state, which is reconciled
        against the real capture process. A TShark that failed to launch, or
        one killed by a rejected filter, therefore reads FAILED here rather
        than CAPTURING - the reader thread outliving the process was exactly
        the mismatch that used to be displayed as a live capture.
        """
        capture = self.context.capture
        if capture is None:
            return
        statistics = capture.statistics()
        state = self._capture_state(statistics)
        self._last_state = state
        # "Running" for the purposes of the controls means the pipeline is
        # doing something on the operator's behalf, which includes the moment
        # before the capture process has been seen. It never includes FAILED.
        running = state in (
            STATE_CAPTURING, STATE_PAUSED, STATE_STOPPING, STATE_STARTING
        )
        capturing = state in (STATE_CAPTURING, STATE_PAUSED, STATE_STOPPING)

        self._status_chip.update_state(state)

        # The interface actually in use while running; the pending choice
        # otherwise. Both come from real enumeration, never a stored string.
        if capturing and statistics.interface:
            shown = statistics.interface
            chosen = next(
                (i for i in self._interfaces if i.name == shown), None
            )
            detail = chosen.display_name if chosen is not None else shown
            if chosen is not None and chosen.primary_ipv4:
                detail += f" [{chosen.primary_ipv4}]"
        else:
            selected = self._picker.selected()
            if selected is None:
                detail = "No interface selected"
            else:
                detail = selected.display_name
                if selected.primary_ipv4:
                    detail += f" [{selected.primary_ipv4}]"
        if self._paused and capturing:
            detail += "  ·  display paused, capture continues"
        self._status_detail.configure(text=detail)

        self._counters_label.configure(text=self._counter_text(statistics))
        self._update_row_counter()
        self._table.set_empty_text(self._empty_text_for(state))

        # The picker stays live while capturing: choosing another interface
        # is now a switch, which stops the current reader and starts the next
        # one. It is locked only while a start or stop is mid-flight, where a
        # second request would race the one already running.
        self._picker.set_enabled(not (self._starting or self._stopping))

        if self.can("monitor.control"):
            self._start_button.state(["disabled"] if running else ["!disabled"])
            self._stop_button.state(["!disabled"] if running else ["disabled"])
        if statistics.last_error:
            from aethra_sec.integrations.pyshark_capture import (
                capture_permission_notes,
            )

            # TShark's own words first - the difference between a missing
            # driver and a permissions problem is in that text - then the
            # platform guidance that usually resolves it.
            self._permission_note.configure(
                text=statistics.last_error + "\n\n"
                + "  ".join(capture_permission_notes()),
                foreground=PALETTE.critical,
            )
            self._permission_note.pack(anchor="w", pady=(METRICS.space_md, 0))

    @staticmethod
    def _counter_text(statistics: Any) -> str:
        """Real capture counters, including what was dropped or sampled out."""
        parts = [
            f"{format_count(statistics.total_packets)} captured",
            f"{format_bytes(statistics.total_bytes)}",
            f"{format_count(statistics.persisted_rows)} stored",
        ]
        if statistics.dropped:
            parts.append(f"{format_count(statistics.dropped)} dropped (queue full)")
        if statistics.sampled_out:
            parts.append(
                f"{format_count(statistics.sampled_out)} not row-stored (rate cap)"
            )
        if statistics.decode_errors:
            parts.append(f"{format_count(statistics.decode_errors)} decode errors")
        parts.append(f"queue {statistics.queue_depth}")
        from aethra_sec.analytics.traffic_classes import CaptureReliability

        parts.append(
            CaptureReliability(
                captured=int(statistics.total_packets or 0),
                dropped=int(statistics.dropped or 0),
            ).describe()
        )
        return "  ·  ".join(parts)

    # ------------------------------------------------------------------
    # Table behaviour
    # ------------------------------------------------------------------
    def _toggle_pause(self) -> None:
        """Pause or resume the table without stopping capture (§12).

        While paused the table holds still; capture, analysis and the display
        filter's counts carry on. Resuming asks the packet view to publish the
        current matches again, so nothing that arrived meanwhile is skipped.
        """
        self._paused = not self._paused
        self._pause_button.configure(
            text="Resume display" if self._paused else "Pause display"
        )
        if not self._paused and self._missed_while_paused:
            self._missed_while_paused = False
            capture = self.context.capture
            session = self.session
            if capture is not None and session is not None:
                try:
                    self._expected_generation = capture.refresh_display_view(session)
                    self._pump_events_until_reset()
                except AethraError as exc:
                    LOGGER.debug("Could not refresh the packet view: %s", exc)
        self.status(
            "Display paused - capture continues in the background."
            if self._paused
            else "Display resumed."
        )
        self._update_capture_state()

    def _clear_display(self) -> None:
        """Clear the table. Capture, the display filter and stored records are untouched."""
        self._clear_table_rows()
        self._update_row_counter()
        self.status(
            "Display cleared. Capture continues; stored packet records are unaffected."
        )

    def _clear_table_rows(self) -> None:
        """Empty the table and its display buffer, leaving every count alone."""
        self._cancel_flush()
        self._table.clear()
        self._packet_index.clear()
        # Nothing is selected any more, so the detail pane gives its rows back.
        self._detail_card.pack_forget()
        self._buffer.clear()
        self._buffer_dropped = 0
        self._seen_since_flush = 0

    # ------------------------------------------------------------------
    # Display filter
    # ------------------------------------------------------------------
    def _select_direction(self, key: str) -> None:
        """Choose a direction view; "All Traffic" removes the direction filter."""
        self._apply_display_filter(direction=key)

    def _select_protocol(self, key: str) -> None:
        """Choose a protocol view; choosing the active one again removes it."""
        self._apply_display_filter(protocol="" if key == self._protocol_key else key)

    def _clear_filters(self) -> None:
        """Return to all traffic. Capture continues and nothing is discarded."""
        self._display_filter_var.set("")
        self._ip_var.set("")
        self._port_var.set("")
        self._ip_scope_var.set(SCOPE_LABELS["either"])
        self._port_scope_var.set(SCOPE_LABELS["either"])
        self._apply_display_filter(direction="", protocol="")

    @staticmethod
    def _scope_of(variable: tk.StringVar) -> str:
        """The scope key for a scope combobox's label."""
        label = variable.get()
        return next((key for key, text in SCOPE_LABELS.items() if text == label), "either")

    def _filter_request(
        self, *, direction: str | None = None, protocol: str | None = None
    ) -> FilterRequest:
        """Everything on the filter bar, as one request."""
        return FilterRequest(
            direction=self._direction_key if direction is None else direction,
            protocol=self._protocol_key if protocol is None else protocol,
            ip=self._ip_var.get(),
            ip_scope=self._scope_of(self._ip_scope_var),
            port=self._port_var.get(),
            port_scope=self._scope_of(self._port_scope_var),
            expression=self._display_filter_var.get(),
        )

    def _apply_display_filter(
        self, *, direction: str | None = None, protocol: str | None = None
    ) -> None:
        """Validate what the bar asks for and hand it to the packet view.

        Validation runs here because it is a parse of a few hundred characters
        at most. Re-evaluating captured packets runs on the packet-view thread.
        If any part of the request is invalid, nothing is applied: the filter in
        force stays in force, and the buttons keep showing it.
        """
        request = self._filter_request(direction=direction, protocol=protocol)
        try:
            composed = compose_filter(request)
        except FilterSyntaxError as exc:
            self._show_filter_error(exc.message)
            return

        capture = self.context.capture
        session = self.session
        if capture is None or session is None:
            return
        try:
            applied, error, generation = capture.set_display_filter(
                session, composed.expression
            )
        except AethraError as exc:
            self._show_filter_error(exc.user_message)
            return
        if not applied:
            self._show_filter_error(error)
            return

        self._filter_error = ""
        self._active_filter = composed
        self._direction_key = request.direction
        self._protocol_key = request.protocol
        self._expected_generation = generation
        self._clear_table_rows()
        self._table.set_empty_text("Applying the display filter to captured packets...")
        self._refresh_filter_controls()
        self._render_filter_state()
        self._update_surge_note()
        self._pump_events_until_reset()
        self.status(f"Display filter: {composed.label}. Capture continues.")

    def _sync_display_filter(self) -> None:
        """Make the packet view apply the filter this screen is showing."""
        capture = self.context.capture
        session = self.session
        if capture is None or session is None:
            return
        try:
            applied, _error, generation = capture.set_display_filter(
                session, self._active_filter.expression
            )
        except AethraError as exc:
            LOGGER.debug("Could not apply the display filter: %s", exc)
            return
        if applied:
            self._expected_generation = generation
            self._pump_events_until_reset()

    def _show_filter_error(self, message: str) -> None:
        """INVALID FILTER, with the reason. The active filter is not changed."""
        self._filter_error = message or "The filter could not be used."
        self._refresh_filter_controls()
        self._render_filter_state()
        self.status("Invalid filter - the previous filter remains active.")

    def _refresh_filter_controls(self) -> None:
        """Highlight the preset buttons that describe the filter in force."""
        for key, button in self._direction_buttons.items():
            button.configure(
                style="ToolAccent.TButton" if key == self._direction_key else "Tool.TButton"
            )
        for key, button in self._protocol_buttons.items():
            button.configure(
                style="ToolAccent.TButton" if key == self._protocol_key else "Tool.TButton"
            )

    def _render_filter_state(self) -> None:
        """ACTIVE FILTER, or INVALID FILTER and why, on one line."""
        active = self._active_filter
        if active.is_all:
            described = "All traffic (no display filter)"
        else:
            described = f"{active.label}   -   {active.expression}"
        if self._filter_error:
            text = (
                f"INVALID FILTER: {self._filter_error}   "
                f"Previous filter remains active: {described}"
            )
            colour = PALETTE.critical
        else:
            text = f"ACTIVE FILTER: {described}"
            colour = PALETTE.text_muted
        self._filter_state_label.configure(text=text, foreground=colour)

    def _pump_events_until_reset(self) -> None:
        """Deliver the re-filtered table promptly instead of at the next tick."""
        self._pump_remaining = FILTER_PUMP_ATTEMPTS
        if self._pump_job is None and self.is_alive:
            self._pump_job = self.after(FILTER_PUMP_INTERVAL_MS, self._pump_events)

    def _pump_events(self) -> None:
        """Dispatch queued events until the expected table has arrived."""
        self._pump_job = None
        self._pump_remaining -= 1
        try:
            # The same call the main window makes on its tick, on the same
            # (Tk) thread; it only delivers events sooner.
            self.context.event_bus.dispatch_all(limit_per_subscription=400)
        except Exception:  # noqa: BLE001
            LOGGER.exception("Event dispatch failed while applying a filter.")
        waiting = self._view_generation_seen < self._expected_generation
        if waiting and self._pump_remaining > 0 and self.is_alive:
            self._pump_job = self.after(FILTER_PUMP_INTERVAL_MS, self._pump_events)

    def _cancel_pump(self) -> None:
        """Cancel a pending event pump, if one is scheduled."""
        if self._pump_job is None:
            return
        try:
            self.after_cancel(self._pump_job)
        except (tk.TclError, ValueError):  # pragma: no cover - already fired
            pass
        self._pump_job = None

    def _apply_view_reset(self, payload: Any) -> None:
        """Replace the table with the packets the active filter matched."""
        generation = int(getattr(payload, "generation", 0) or 0)
        if generation < self._expected_generation:
            # Filtered under a filter that has since been replaced.
            return
        self._expected_generation = generation
        self._view_generation_seen = generation
        self._clear_table_rows()
        self._apply_view_statistics(getattr(payload, "statistics", None))
        self._buffer_packets(getattr(payload, "packets", ()))

    def _apply_view_batch(self, payload: Any) -> None:
        """Append newly captured packets that matched the active filter."""
        if int(getattr(payload, "generation", -1)) != self._expected_generation:
            return
        self._apply_view_statistics(getattr(payload, "statistics", None))
        packets = getattr(payload, "packets", ())
        if not packets:
            return
        if self._paused:
            self._missed_while_paused = True
            return
        self._buffer_packets(packets)

    def _apply_view_statistics(self, statistics: Any) -> None:
        """Take the packet view's latest counts."""
        if statistics is None:
            return
        self._view_statistics = statistics
        self._update_row_counter()
        self._update_surge_note()
        if self._table.row_count == 0:
            self._table.set_empty_text(self._empty_text_for(self._last_state))

    # ------------------------------------------------------------------
    # Packet inspection
    # ------------------------------------------------------------------
    def _inspect_packet(self, row: dict[str, Any], follow: str = "") -> None:
        """Open the full decode of a packet, read back from the capture file.

        The table row is a summary; the frame itself is re-read from the pcap
        the capture session wrote. That read runs on a worker, so a large
        capture never blocks the interface while TShark works.
        """
        packet = self._packet_index.get(str(row.get("_key", "")))
        if packet is None:
            show_message(
                self, "Inspect packet",
                "This packet has left the view buffer.",
                detail=(
                    "The table keeps a bounded window of recent packets. The "
                    "frame may still be in the capture file, but the row no "
                    "longer carries its position."
                ),
                fonts=self.fonts,
            )
            return

        stamp = format_local_ms(packet.captured_at)
        inspector = PacketInspector(
            self, fonts=self.fonts,
            title=(
                f"Packet #{packet.frame_index}"
                if packet.frame_index is not None else "Packet"
            ),
            subtitle=stamp,
        )
        inspector.set_stream_text("Select 'Follow stream' to read this conversation.")

        pcap_path = packet.pcap_path
        frame_index = packet.frame_index
        tshark_path = self._tshark_path()

        def work() -> Any:
            from aethra_sec.integrations.pyshark_capture.inspector import (
                load_packet_detail,
            )

            return load_packet_detail(
                pcap_path, frame_index or 0, tshark_path=tshark_path
            )

        def done(detail: Any) -> None:
            try:
                if not inspector.winfo_exists():
                    return
            except tk.TclError:  # pragma: no cover - closed while decoding
                return
            inspector.set_detail(detail)
            inspector._on_follow_stream = (  # noqa: SLF001 - same component
                lambda kind, index: self._follow_stream(inspector, pcap_path, kind, index)
            )
            if follow and detail.ok and detail.stream_kind == follow:
                self._follow_stream(
                    inspector, pcap_path, detail.stream_kind, detail.stream_index
                )
                inspector.select_stream_tab()
            elif follow:
                inspector.set_stream_text(
                    f"This frame is not part of a {follow.upper()} conversation."
                )
                inspector.select_stream_tab()

        def failed(message: str) -> None:
            try:
                if inspector.winfo_exists():
                    inspector.set_stream_text(message)
            except tk.TclError:  # pragma: no cover
                pass

        self.run_async(work, done, failed, name="packet-inspect")
        inspector.show()

    def _follow_stream(
        self, inspector: PacketInspector, pcap_path: str, kind: str, index: int | None
    ) -> None:
        """Read a conversation from the capture file on a worker thread."""
        if not kind or index is None:
            inspector.set_stream_text(
                "TShark did not assign this frame a stream index, so there is "
                "no conversation to follow."
            )
            return
        tshark_path = self._tshark_path()

        def work() -> Any:
            from aethra_sec.integrations.pyshark_capture.inspector import follow_stream

            return follow_stream(pcap_path, kind, index, tshark_path=tshark_path)

        def done(result: Any) -> None:
            packets, error = result
            try:
                if inspector.winfo_exists():
                    inspector.set_stream(packets, error)
            except tk.TclError:  # pragma: no cover - closed while reading
                pass

        self.run_async(work, done, name="packet-follow-stream")

    def _tshark_path(self) -> Any:
        """The configured tshark executable, when one was set."""
        tools = getattr(self.context, "settings", None)
        return getattr(getattr(tools, "tools", None), "tshark_path", None)

    def _toggle_mark(self, _row: dict[str, Any]) -> None:
        """Mark or unmark the packet under the pointer.

        A mark is the operator's own annotation on a real captured packet - a
        way to keep hold of it while a busy view scrolls past. It changes
        nothing about the packet or how it is decoded.
        """
        row_id = self._table.selected_row_id()
        if row_id is None:
            return
        marked = self._table.toggle_mark(row_id)
        total = self._table.marked_count
        self.status(
            f"Packet {'marked' if marked else 'unmarked'}. "
            f"{total} packet(s) marked in this view."
        )
        self._update_row_counter()

    def _copy_packet_summary(self, row: dict[str, Any]) -> None:
        """Copy the table row as tab-separated text."""
        text = "\t".join(
            f"{column.title}={row.get(column.key, '')}" for column in PACKET_COLUMNS
        )
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status("Packet summary copied.")
        except tk.TclError:  # pragma: no cover - no clipboard on this display
            pass

    def _filter_by(self, row: dict[str, Any], key: str) -> None:
        """Narrow the view to one of the selected packet's own values."""
        packet = self._packet_index.get(str(row.get("_key", "")))
        if packet is None:
            self.status("This packet has left the view buffer.")
            return
        if key in ("src_ip", "dst_ip"):
            value = getattr(packet, key, "")
            if not value or not packet.ip_version:
                self.status("This packet has no IP address to filter on.")
                return
            self._ip_var.set(value)
            self._ip_scope_var.set(SCOPE_LABELS["source" if key == "src_ip" else "destination"])
        elif key in ("src_port", "dst_port"):
            value = getattr(packet, key, None)
            if value is None:
                self.status("This packet has no port to filter on.")
                return
            self._port_var.set(str(value))
            self._port_scope_var.set(
                SCOPE_LABELS["source" if key == "src_port" else "destination"]
            )
        elif key == "protocol":
            preset = self._preset_for(packet)
            if not preset:
                self.status(
                    "There is no preset for this packet's protocol; type a display "
                    "filter instead."
                )
                return
            self._apply_display_filter(protocol=preset)
            return
        self._apply_display_filter()

    @staticmethod
    def _preset_for(packet: CapturedPacket) -> str:
        """The protocol preset that describes a packet, from its decoded layers."""
        if packet.is_http:
            return "HTTP"
        if packet.is_tls:
            return "HTTPS"
        for layers, preset in (
            (("DNS",), "DNS"), (("ARP",), "ARP"), (("ICMP", "ICMPV6"), "ICMP"),
            (("TCP",), "TCP"), (("UDP",), "UDP"),
        ):
            if packet.has_layer(*layers):
                return preset
        return ""

    def _update_row_counter(self) -> None:
        """Captured, displayed and listed counts, with direction and protocol totals.

        CAPTURED is the capture's own count and never changes when the display
        filter does. DISPLAYED is how many packets the filter matched among
        those it was evaluated against. LISTED is how many rows the table holds.
        Direction totals cover every packet the view took in this session;
        protocol totals cover the packets that matched.
        """
        label = getattr(self, "_view_counts_label", None)
        if label is None:
            return
        capture = self.context.capture
        captured = capture.statistics().total_packets if capture is not None else 0
        statistics = self._view_statistics
        parts = [f"CAPTURED {captured:,}"]
        if statistics is not None:
            parts.append(f"DISPLAYED {statistics.matched:,}")
        parts.append(f"LISTED {self._table.visible_count:,}")
        if self._table.marked_count:
            parts.append(f"MARKED {self._table.marked_count:,}")
        line = "   ".join(parts)
        if statistics is not None:
            directions = [
                f"{direction.value} {statistics.direction(direction):,}"
                for direction in DIRECTION_ORDER
                if direction is not Direction.LOCAL or statistics.direction(direction)
            ]
            line += "      " + "   ".join(directions)
            protocols = [
                f"{name} {count:,}"
                for name, count in statistics.matched_protocols.items()
                if count
            ]
            scope = "ALL CAPTURED" if self._active_filter.is_all else "FILTERED"
            line += (
                f"      {scope} BY PROTOCOL: "
                + ("   ".join(protocols) if protocols else "none")
            )
        label.configure(text=line)

    def _export_view(self) -> None:
        """Export the visible packet rows to CSV (§50)."""
        reports = self.context.reports
        session = self.session
        if reports is None or session is None:
            return
        rows = self._table.export_rows(visible_only=True)
        columns = self._table.export_columns()
        self.status("Exporting packet view...")

        def work() -> str:
            path = reports.export_records(
                session, columns, rows,
                filename=f"packets_{len(rows)}",
                description="live packet view",
            )
            return str(path)

        self.run_async(
            work,
            lambda path: show_message(
                self, "Export complete",
                f"{len(rows)} row(s) exported" if rows
                else "No records available for export.",
                detail=f"Written to:\n{path}", fonts=self.fonts,
            ),
            name="packet-export",
        )

    def _show_packet_detail(self, row: dict[str, Any]) -> None:
        """Show the decoded fields of the selected packet (§12).

        Only fields TShark decoded for this frame are shown; anything absent is
        N/A. The full decode - including cipher suites and certificates, when a
        frame carries them - is one double-click away in the packet inspector.
        """
        packet = self._packet_index.get(str(row.get("_key", "")))
        # Reveal the pane on first use; the table keeps those rows until then.
        if not self._detail_card.winfo_ismapped():
            self._detail_card.pack(
                side="bottom", fill="x", pady=(METRICS.space_md, 0)
            )
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        if packet is None:
            self._detail_text.insert("1.0", "Packet detail is no longer in the view buffer.")
        else:
            na = "N/A"
            lines = [
                f"Captured at      : {packet.captured_at.isoformat()}",
                f"Interface        : {packet.interface or na}",
                f"Frame            : {packet.number if packet.number is not None else na}"
                f"   length {packet.length} bytes",
                f"Direction        : {self._direction_text(packet)}",
                f"Ethernet         : {packet.src_mac or na} -> {packet.dst_mac or na}",
                f"Network          : {packet.src_ip or na} -> {packet.dst_ip or na}"
                + (f"  (IPv{packet.ip_version})" if packet.ip_version else ""),
                f"Protocol         : {packet.protocol or na}"
                f"   decoded layers: {', '.join(packet.layers) or na}",
            ]
            lines.extend(self._protocol_detail_lines(packet))
            lines.extend([
                "",
                "Fields not present in this frame are shown as N/A; AETHRA-SEC "
                "does not substitute values. Double-click the packet for "
                "TShark's full decode of this frame.",
            ])
            self._detail_text.insert("1.0", "\n".join(lines))
        self._detail_text.configure(state="disabled")

    @staticmethod
    def _direction_text(packet: CapturedPacket) -> str:
        """The packet's direction and the rule that decided it."""
        if not packet.direction:
            return "N/A (not classified)"
        try:
            direction = Direction(packet.direction)
        except ValueError:
            return packet.direction
        return f"{direction.label} - {direction.explanation}"

    @staticmethod
    def _protocol_detail_lines(packet: CapturedPacket) -> list[str]:
        """Per-protocol detail lines, for the layers the frame actually carries."""
        na = "N/A"

        def shown(value: Any) -> str:
            return na if value is None or value == "" else str(value)

        lines: list[str] = []
        if packet.transport == "TCP":
            lines.append(
                f"TCP              : ports {shown(packet.src_port)} -> {shown(packet.dst_port)}"
                f"   flags {packet.flags_text}   seq {shown(packet.tcp_seq)}"
                f"   ack {shown(packet.tcp_ack)}"
            )
        elif packet.transport == "UDP":
            lines.append(
                f"UDP              : ports {shown(packet.src_port)} -> {shown(packet.dst_port)}"
            )
        if packet.is_http:
            if packet.http_method:
                lines.append(
                    f"HTTP request     : method {packet.http_method}"
                    f"   host {shown(packet.http_host)}   URI {shown(packet.http_uri)}"
                    f"   version {shown(packet.http_version)}"
                )
            if packet.http_status is not None:
                lines.append(
                    f"HTTP response    : status {packet.http_status} {packet.http_phrase}".rstrip()
                    + f"   version {shown(packet.http_version)}"
                )
            if not packet.http_method and packet.http_status is None:
                lines.append(
                    "HTTP             : this frame carries neither a request line nor "
                    "a status line (method, host, URI, status: N/A)"
                )
        if packet.is_tls:
            lines.append(
                f"TLS (encrypted)  : handshake {packet.tls_handshake_name or na}"
                f"   SNI {shown(packet.tls_sni)}"
            )
            lines.append(
                "                   record-layer version "
                f"{tls_version_name(packet.tls_record_version) or na}"
                "   negotiated version "
                f"{packet.tls_negotiated_version or 'N/A (only a Server Hello states it)'}"
            )
            lines.append(
                "                   cipher suite, certificate: not extracted by live "
                "capture - the packet inspector shows them when this frame carries them"
            )
            lines.append(f"                   {HTTPS_NOTICE}")
        if packet.has_layer("DNS", "MDNS", "LLMNR"):
            response = na if packet.dns_response is None else ("yes" if packet.dns_response else "no")
            lines.append(f"DNS              : query {shown(packet.dns_query)}   response {response}")
        if packet.has_layer("ICMP", "ICMPV6"):
            lines.append(
                f"ICMP             : type {shown(packet.icmp_type)}   code {shown(packet.icmp_code)}"
            )
        if packet.has_layer("ARP"):
            opcode = {1: "request", 2: "reply"}.get(
                packet.arp_opcode, shown(packet.arp_opcode)
            )
            lines.append(
                f"ARP              : {opcode}"
                f"   sender {shown(packet.src_ip)} / {shown(packet.arp_sender_mac)}"
                f"   target {shown(packet.dst_ip)} / {shown(packet.arp_target_mac)}"
            )
        return lines

    # ------------------------------------------------------------------
    # Live events
    # ------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        """Apply live capture events.

        Rows come only from the packet view, so every row matched the display
        filter this screen shows. PACKET_BATCH_PROCESSED still arrives here for
        other consumers, but no packet is taken from it.
        """
        if event.type == EventType.DISPLAY_VIEW_RESET:
            self._apply_view_reset(event.payload)
        elif event.type == EventType.DISPLAY_VIEW_BATCH:
            self._apply_view_batch(event.payload)
        elif event.type == EventType.TRAFFIC_STATS_UPDATED:
            self._apply_snapshot(getattr(event.payload, "snapshot", None))
        elif event.type in (
            EventType.CAPTURE_STARTED, EventType.CAPTURE_STOPPED,
            EventType.CAPTURE_ERROR,
        ):
            self._update_capture_state()
            if event.type == EventType.CAPTURE_ERROR:
                message = getattr(event.payload, "message", "Capture error")
                self.show_error_message(message, "Packet capture error")

    def _buffer_packets(self, packets: Any) -> None:
        """Hold matching packets for the next coalesced table write.

        The packet view has already applied the display filter, so everything
        that arrives here belongs on the table. What is left to bound is the
        cost of drawing it: each table write costs the Tk thread a fixed amount
        whatever its size, so writes are coalesced onto
        :data:`FLUSH_INTERVAL_MS` and the cost of displaying a flood is bounded
        by the clock rather than by the attacker's packet rate.
        """
        packets = list(packets)
        self._seen_since_flush += len(packets)
        if packets:
            self._buffer.extend(packets)
            # The buffer is a display queue, not a record: the database keeps
            # everything, so the newest packets win when it overflows.
            if len(self._buffer) > MAX_BUFFERED_PACKETS:
                overflow = len(self._buffer) - MAX_BUFFERED_PACKETS
                del self._buffer[:overflow]
                self._buffer_dropped += overflow
        if self._flush_job is None and self.is_alive:
            self._flush_job = self.after(FLUSH_INTERVAL_MS, self._flush_buffer)

    def _flush_buffer(self) -> None:
        """Write one coalesced batch to the table."""
        self._flush_job = None
        buffered, self._buffer = self._buffer, []
        seen, self._seen_since_flush = self._seen_since_flush, 0
        # Bound the Tk-thread cost of one flush: insert at most
        # MAX_ROWS_PER_FLUSH newest rows. Anything older than that in a single
        # burst would be trimmed off the table immediately anyway, so it is
        # counted as display-dropped (the database still holds it) rather than
        # inserted and discarded. This is what keeps a flood from holding the
        # event loop for seconds.
        if len(buffered) > MAX_ROWS_PER_FLUSH:
            self._buffer_dropped += len(buffered) - MAX_ROWS_PER_FLUSH
            buffered = buffered[-MAX_ROWS_PER_FLUSH:]
        if buffered:
            self._append_packets(buffered)
        self._update_surge_note(seen, len(buffered))
        # Reschedule only while traffic is still arriving, so an idle screen
        # costs nothing.
        if self._buffer and self.is_alive:
            self._flush_job = self.after(FLUSH_INTERVAL_MS, self._flush_buffer)

    def _update_surge_note(self, seen: int = 0, shown: int = 0) -> None:
        """State plainly what the table is not showing, and why.

        Every figure is one the capture service or the packet view counted.
        ``seen`` and ``shown`` describe the last table write and are kept for
        callers that report them.
        """
        notes: list[str] = []
        active = self._active_filter
        statistics = self._view_statistics
        if active.encrypted:
            notes.append(HTTPS_NOTICE)
        if statistics is not None:
            if statistics.session_packets and not statistics.local_resolved:
                notes.append(f"Direction unavailable: {statistics.local_description}")
            if self._visibility_note_applies(statistics):
                searched = active.ip_value if active.request.direction != "TRANSIT" else ""
                prefix = f"No captured packet involves {searched}. " if searched else ""
                notes.append(prefix + NOT_VISIBLE_NOTICE)
            hidden: list[str] = []
            not_matching = max(0, statistics.evaluated - statistics.matched)
            if not active.is_all and not_matching:
                hidden.append(f"{not_matching:,} not matching this view")
            if statistics.not_listed:
                hidden.append(
                    f"{statistics.not_listed:,} matching packet(s) not listed "
                    f"(the table keeps the newest {self._max_rows():,})"
                )
            if statistics.window_limited and not active.is_all:
                hidden.append(
                    f"filter evaluated over {statistics.evaluated:,} retained or "
                    f"newer packets, not all {statistics.session_packets:,} "
                    "captured this session"
                )
            if statistics.ingest_dropped:
                hidden.append(
                    f"{statistics.ingest_dropped:,} not taken into the view "
                    "(hand-off full)"
                )
            if self._buffer_dropped:
                hidden.append(
                    f"{self._buffer_dropped:,} not displayed (display buffer full)"
                )
            if hidden:
                hidden.append("every packet is still analysed, counted and stored")
                notes.append("  ·  ".join(hidden))

        text = "\n".join(notes)
        if not text:
            if self._surge_label.winfo_ismapped():
                self._surge_label.pack_forget()
            return
        self._surge_label.configure(text=text)
        if not self._surge_label.winfo_ismapped():
            self._surge_label.pack(anchor="w", fill="x", pady=(0, 6), before=self._table)

    def _visibility_note_applies(self, statistics: Any) -> bool:
        """True when an empty view depends on seeing other devices' traffic.

        Two cases, both judged only after enough packets have arrived: the
        Transit view, and a search for an address that is not this interface's,
        each having found nothing.
        """
        if statistics.matched or statistics.session_packets < VISIBILITY_SAMPLE:
            return False
        active = self._active_filter
        request = active.request
        if request.direction == "TRANSIT":
            return True
        # Only a search for an address, with nothing else narrowing it, can be
        # attributed to the capture position. A search that also names a
        # protocol or a port may be empty simply because that device sent no
        # such traffic - which says nothing about where the sensor sits.
        address = active.ip_value
        narrowed = bool(request.protocol or request.port.strip() or request.expression.strip())
        return bool(
            address
            and not narrowed
            and "/" not in address
            and statistics.local_resolved
            and address not in statistics.local_addresses
            and not statistics.direction(Direction.TRANSIT)
        )

    def _append_packets(self, packets: Any) -> None:
        """Add captured packets to the table."""
        rows = []
        for packet in packets:
            self._sequence += 1
            key = f"p{self._sequence}"
            self._packet_index[key] = packet
            rows.append(
                {
                    "_key": key,
                    "time": format_local_ms(packet.captured_at),
                    "source": packet.src_ip or packet.src_mac or "-",
                    "destination": packet.dst_ip or packet.dst_mac or "-",
                    "protocol": packet.protocol,
                    "sport": packet.src_port if packet.src_port is not None else "",
                    "dport": packet.dst_port if packet.dst_port is not None else "",
                    "length": packet.length,
                    "direction": (packet.direction or "").title(),
                    "info": truncate(packet.info, 160),
                }
            )
        if rows:
            self._table.add_rows(rows)
            self._update_row_counter()
            if len(self._packet_index) > self._max_rows() * 2:
                keep = set(
                    str(r.get("_key", "")) for r in self._table.rows()
                )
                self._packet_index = {
                    k: v for k, v in self._packet_index.items() if k in keep
                }

    def _apply_snapshot(self, snapshot: Any) -> None:
        """Update the analytics column from a live snapshot."""
        if snapshot is None:
            return
        self._rate_chart.set_points(
            [(point.timestamp, point.value) for point in snapshot.pps_series]
        )
        from aethra_sec.analytics.traffic_classes import traffic_load_class

        load = traffic_load_class(snapshot.packets_per_second)
        self._rate_label.configure(
            text=(
                f"{format_rate(snapshot.packets_per_second)}  ·  "
                f"{format_bandwidth(snapshot.bytes_per_second)}  ·  "
                f"{format_count(snapshot.active_hosts)} active host(s)"
                + (f"  ·  load {load} (§4.5.4)" if load else "")
            )
        )
        self._protocol_chart.set_items(
            [(p.protocol, float(p.packets)) for p in snapshot.protocols]
        )
        self._sources_chart.set_items(
            [(t.label, float(t.packets)) for t in snapshot.top_sources]
        )
        self._ports_chart.set_items(
            [(p.label, float(p.packets)) for p in snapshot.top_dst_ports]
        )
        self._update_capture_state()

    def on_tick(self) -> None:
        """Keep the capture counters current."""
        self._update_capture_state()
