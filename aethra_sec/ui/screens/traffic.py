"""Network monitoring screen (§11-§14, §64).

Live packet table, capture controls, traffic analytics and a packet detail
panel. The table is bounded (§105): once the configured row cap is reached the
oldest rows leave the *view* while the database keeps the full history, and the
row counter says so explicitly.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from aethra_sec.core.errors import AethraError
from aethra_sec.core.events import Event, EventType
from aethra_sec.integrations.pyshark_capture import CaptureInterface
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, configure_text_widget
from aethra_sec.ui.widgets import (
    BarChart,
    Card,
    Column,
    DataTable,
    FilterBar,
    DonutChart,
    ScrollableFrame,
    TimeSeriesChart,
    Toolbar,
    bytes_formatter,
    confirm,
    show_message,
)
from aethra_sec.utils.formatting import (
    NO_DATA_TEXT,
    WAITING_FOR_CAPTURE_TEXT,
    format_bandwidth,
    format_bytes,
    format_count,
    format_rate,
    truncate,
)
from aethra_sec.utils.timeutil import format_local_ms

PACKET_COLUMNS = (
    Column("time", "Time", width=100),
    Column("source", "Source", width=140),
    Column("destination", "Destination", width=140),
    Column("protocol", "Protocol", width=70),
    Column("sport", "Src port", width=70, anchor="e"),
    Column("dport", "Dst port", width=70, anchor="e"),
    Column("length", "Length", width=64, anchor="e"),
    Column("info", "Info", width=360, stretch=True),
)


#: Live table writes are coalesced onto this cadence. Each write costs the Tk
#: thread a fixed amount whatever its size, so bounding writes per second is
#: what keeps the interface responsive when the packet rate is not bounded.
FLUSH_INTERVAL_MS = 250

#: Most packets held for display between flushes. The database keeps every
#: record; this only bounds what the screen is asked to draw.
MAX_BUFFERED_PACKETS = 5000

#: Protocol view for "show me everything".
PROTOCOL_ANY = "All"

#: Protocol views offered above the live table.
PROTOCOL_CHOICES: tuple[str, ...] = (
    PROTOCOL_ANY, "ICMP", "TCP", "UDP", "ARP", "DNS", "HTTP", "HTTPS",
)


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
        self._pending: list[CapturedPacket] = []
        self._packet_index: dict[str, CapturedPacket] = {}
        self._sequence = 0
        #: Packets waiting for the next coalesced flush to the table.
        self._buffer: list[CapturedPacket] = []
        self._flush_job: str | None = None
        self._seen_since_flush = 0
        self._buffer_dropped = 0

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the monitoring screen.

        Wrapped in a :class:`ScrollableFrame`, matching the Alerts screen:
        the analytics column stacks three chart cards with real height of
        their own, and on a window short enough that they, or the packet
        table, do not fit, the page scrolls to reach the rest rather than
        clipping it with no way back.
        """
        scroller = ScrollableFrame(self)
        scroller.pack(fill="both", expand=True)
        root = scroller.interior

        self._build_controls(root)
        body = ttk.Frame(root, style="TFrame")
        body.pack(fill="both", expand=True, pady=(16, 0))

        # The analytics column is packed first so it reserves its width; the
        # packet table then fills whatever remains. Packing it last would let
        # the table's wide columns squeeze it to nothing.
        right = ttk.Frame(body, style="TFrame", width=380)
        right.pack(side="right", fill="y", padx=(10, 0))
        right.pack_propagate(False)
        self._build_analytics(right)

        left = ttk.Frame(body, style="TFrame")
        left.pack(side="left", fill="both", expand=True)
        self._build_packet_table(left)

    def _build_controls(self, parent: tk.Misc) -> None:
        """Interface selection, capture controls and filter."""
        card = Card(parent, "Capture control", fonts=self.fonts, padding=18)
        card.pack(fill="x")

        row_one = FilterBar(card)
        row_one.pack(fill="x")

        ttk.Label(row_one, text="Interface", style="CardMuted.TLabel").pack(side="left")
        self._interface_var = tk.StringVar()
        self._interface_combo = ttk.Combobox(
            row_one, textvariable=self._interface_var, state="readonly", width=44
        )
        self._interface_combo.pack(side="left", padx=(8, 8))

        ttk.Button(
            row_one, text="Refresh", style="Ghost.TButton",
            command=self._load_interfaces,
        ).pack(side="left", padx=(0, 14))

        ttk.Label(row_one, text="Capture filter (BPF)", style="CardMuted.TLabel").pack(
            side="left"
        )
        self._bpf_var = tk.StringVar(value=self.context.settings.capture.bpf_filter)
        ttk.Entry(row_one, textvariable=self._bpf_var, width=26).pack(
            side="left", padx=(8, 14)
        )

        self._start_button = ttk.Button(
            row_one, text="Start capture", style="Accent.TButton",
            command=self._start_capture,
        )
        self._start_button.pack(side="left", padx=(0, 6))
        self._stop_button = ttk.Button(
            row_one, text="Stop capture", style="Danger.TButton",
            command=self._stop_capture,
        )
        self._stop_button.pack(side="left")
        self._stop_button.state(["disabled"])

        if not self.can("monitor.control"):
            self._start_button.state(["disabled"])
            self._stop_button.state(["disabled"])

        row_two = ttk.Frame(card, style="Card.TFrame")
        row_two.pack(fill="x", pady=(16, 0))

        self._status_label = ttk.Label(
            row_two, text="Capture NOT STARTED", style="CardMuted.TLabel"
        )
        self._status_label.pack(side="left")
        self._counters_label = ttk.Label(row_two, text="", style="CardDim.TLabel")
        self._counters_label.pack(side="left", padx=(16, 0))

        self._permission_note = ttk.Label(
            card, text="", style="CardDim.TLabel", wraplength=980, justify="left"
        )
        self._permission_note.pack(anchor="w", pady=(8, 0))

    def _build_packet_table(self, parent: tk.Misc) -> None:
        """Live packet table with display controls and a detail pane."""
        card = Card(parent, "Live packets", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True)

        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Label(toolbar, text="Protocol", style="CardMuted.TLabel").pack(
            side="left", padx=(0, 6)
        )
        # Chosen before rendering rather than after: traffic the operator did
        # not ask for is dropped on arrival, so a flood of one protocol cannot
        # cost the interface anything while they are watching another.
        self._protocol_var = tk.StringVar(value=PROTOCOL_ANY)
        protocol_combo = ttk.Combobox(
            toolbar, textvariable=self._protocol_var, state="readonly", width=9,
            values=list(PROTOCOL_CHOICES),
        )
        protocol_combo.pack(side="left", padx=(0, 10))
        protocol_combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_filter())

        ttk.Label(toolbar, text="Filter", style="CardMuted.TLabel").pack(
            side="left", padx=(0, 6)
        )
        self._filter_var = tk.StringVar()
        filter_entry = ttk.Entry(toolbar, textvariable=self._filter_var, width=26)
        filter_entry.pack(side="left", padx=(0, 10))
        filter_entry.bind("<KeyRelease>", lambda _e: self._apply_filter())

        self._pause_button = toolbar.add_button("Pause display", self._toggle_pause)
        toolbar.add_button("Clear display", self._clear_display)
        toolbar.add_button("Export view", self._export_view)
        self._rows_label = toolbar.add_label("0 packets shown", side="right")

        ttk.Label(
            card,
            text=(
                "Protocol narrows what is captured into the view; Filter "
                "matches any column - an address, a port or decoded text, for "
                "example 192.168.1.10, 443, dns."
            ),
            style="CardDim.TLabel",
        ).pack(anchor="w", pady=(0, 6))

        # Shown only while traffic is arriving faster than the table can
        # usefully display it. It reports what was actually counted, not a
        # sample: the numbers come from the capture service's own counters.
        self._surge_label = ttk.Label(card, text="", style="CardMuted.TLabel")

        self._table = DataTable(
            card, PACKET_COLUMNS, height=16, mono=True,
            max_rows=self._max_rows(), on_select=self._show_packet_detail,
        )
        self._table.pack(fill="both", expand=True)

        detail_card = Card(parent, "Packet detail", fonts=self.fonts, padding=18)
        detail_card.pack(fill="x", pady=(16, 0))
        self._detail_text = tk.Text(detail_card, height=7, wrap="word")
        configure_text_widget(self._detail_text, self.fonts, mono=True)
        self._detail_text.insert("1.0", "Select a packet to see its decoded fields.")
        self._detail_text.configure(state="disabled")
        self._detail_text.pack(fill="x")

    def _build_analytics(self, parent: tk.Misc) -> None:
        """Right-hand analytics column."""
        rate_card = Card(parent, "Traffic rate", fonts=self.fonts, padding=18)
        rate_card.pack(fill="x")
        self._rate_chart = TimeSeriesChart(
            rate_card, height=120, empty_message=WAITING_FOR_CAPTURE_TEXT,
            value_formatter=lambda v: f"{v:,.0f}",
        )
        self._rate_chart.pack(fill="x")
        self._rate_label = ttk.Label(rate_card, text="", style="CardMuted.TLabel")
        self._rate_label.pack(anchor="w", pady=(6, 0))

        protocol_card = Card(parent, "Protocols", fonts=self.fonts, padding=18)
        protocol_card.pack(fill="x", pady=(16, 0))
        self._protocol_chart = DonutChart(
            protocol_card, height=140, centre_label="packets",
            empty_message=NO_DATA_TEXT,
        )
        self._protocol_chart.pack(fill="x")

        talkers_card = Card(parent, "Top talkers", fonts=self.fonts, padding=18)
        talkers_card.pack(fill="both", expand=True, pady=(16, 0))
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
        """Load interfaces and current capture state."""
        self._load_interfaces()
        self._update_capture_state()

    def on_hide(self) -> None:
        """Stop the flush timer while the screen is not visible.

        Capture keeps running and keeps analysing - only the drawing stops,
        which is the part nobody is looking at.
        """
        self._cancel_flush()

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
        """Populate the interface picker."""
        interfaces, availability = payload
        self._interfaces = interfaces
        labels = [interface.display_label() for interface in interfaces]
        self._interface_combo.configure(values=labels)

        if not availability.available:
            self._permission_note.configure(
                text=availability.detail, foreground=PALETTE.critical
            )
            self._start_button.state(["disabled"])
            self.status("TShark is not available - capture cannot start.")
            return

        from aethra_sec.integrations.pyshark_capture import capture_permission_notes

        self._permission_note.configure(
            text="  ".join(capture_permission_notes()), foreground=PALETTE.text_dim
        )

        configured = self.context.settings.capture.interface or (
            self.context.capture.interface if self.context.capture else ""
        )
        selected = ""
        for interface, label in zip(interfaces, labels):
            if interface.name == configured:
                selected = label
                break
        if not selected and labels:
            selected = labels[0]
        if selected:
            self._interface_var.set(selected)
        self.status(f"{len(interfaces)} capture interface(s) available.")

    def _selected_interface(self) -> str:
        """The interface name TShark expects for the current selection."""
        label = self._interface_var.get()
        for interface in self._interfaces:
            if interface.display_label() == label:
                return interface.name
        return label.split(" ", 1)[0] if label else ""

    def _start_capture(self) -> None:
        """Start live capture on the selected interface."""
        capture = self.context.capture
        session = self.session
        if capture is None or session is None:
            return
        interface = self._selected_interface()
        if not interface:
            self.show_error_message(
                "Select a network interface before starting capture.",
                "No interface selected",
            )
            return

        self._start_button.state(["disabled"])
        self.status(f"Starting capture on {interface}...")
        # Read the Tk variable here; the worker must not touch Tk state.
        bpf_filter = self._bpf_var.get().strip()

        def work() -> str:
            capture.start(session, interface, bpf_filter)
            return interface

        def done(name: str) -> None:
            self.status(f"Capturing on {name}.")
            self._update_capture_state()

        def failed(message: str) -> None:
            self._start_button.state(["!disabled"])
            self.status("Capture failed to start.")
            self.show_error_message(message, "Capture could not start")

        self.run_async(work, done, failed, name="capture-start")

    def _stop_capture(self) -> None:
        """Stop live capture."""
        capture = self.context.capture
        session = self.session
        if capture is None or session is None:
            return
        if not confirm(
            self, "Stop capture", "Stop live packet capture?",
            detail=(
                "Traffic already written to the database is retained. Analysis "
                "and detection stop until capture is restarted."
            ),
            confirm_label="Stop capture",
        ):
            return
        self._stop_button.state(["disabled"])
        self.status("Stopping capture...")
        self.run_async(
            lambda: capture.stop(session, "operator request"),
            lambda _r: (self.status("Capture stopped."), self._update_capture_state()),
            name="capture-stop",
        )

    def _update_capture_state(self) -> None:
        """Reflect the true capture state in the controls (§120)."""
        capture = self.context.capture
        if capture is None:
            return
        statistics = capture.statistics()
        running = statistics.is_running
        colour = PALETTE.ok if running else (
            PALETTE.critical if statistics.last_error else PALETTE.text_muted
        )
        self._status_label.configure(
            text=(
                f"Capture {statistics.status_text}"
                + (f" on {statistics.interface}" if statistics.interface else "")
            ),
            foreground=colour,
        )
        self._counters_label.configure(text=self._counter_text(statistics))

        if self.can("monitor.control"):
            self._start_button.state(["disabled"] if running else ["!disabled"])
            self._stop_button.state(["!disabled"] if running else ["disabled"])
        if statistics.last_error:
            self._permission_note.configure(
                text=statistics.last_error, foreground=PALETTE.critical
            )

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
        return "  ·  ".join(parts)

    # ------------------------------------------------------------------
    # Table behaviour
    # ------------------------------------------------------------------
    def _toggle_pause(self) -> None:
        """Pause or resume the live display without stopping capture (§12)."""
        self._paused = not self._paused
        self._pause_button.configure(
            text="Resume display" if self._paused else "Pause display"
        )
        if not self._paused and self._pending:
            self._append_packets(self._pending)
            self._pending.clear()
        self.status(
            "Display paused - capture continues in the background."
            if self._paused
            else "Display resumed."
        )

    def _clear_display(self) -> None:
        """Clear the view (stored records are untouched)."""
        self._cancel_flush()
        self._table.clear()
        self._packet_index.clear()
        self._pending.clear()
        self._buffer.clear()
        self._buffer_dropped = 0
        self._seen_since_flush = 0
        self._update_row_counter()
        self.status("Display cleared. Stored packet records are unaffected.")

    def _apply_filter(self) -> None:
        """Apply the protocol view and the free-text display filter (§13).

        The protocol view is applied twice over, and both are needed: as a
        predicate here so rows already on screen are re-filtered the moment the
        choice changes, and on arrival in :meth:`_buffer_packets` so traffic
        the operator is not watching never costs the interface anything.
        """
        self._table.set_filter(self._filter_var.get(), self._protocol_predicate())
        self._update_row_counter()

    def _protocol_predicate(self) -> Any:
        """A row test for the selected protocol, or ``None`` for all traffic."""
        choice = self._protocol_var.get()
        if choice == PROTOCOL_ANY:
            return None

        def matches(row: dict[str, Any]) -> bool:
            packet = self._packet_index.get(str(row.get("_key", "")))
            if packet is not None:
                return self._matches_protocol(packet)
            # A row whose packet has already left the index is judged on what
            # the row itself shows rather than being silently kept.
            return str(row.get("protocol", "")).upper() == choice

        return matches

    def _update_row_counter(self) -> None:
        """Show how many rows are displayed and how many left the view."""
        text = f"{self._table.visible_count:,} of {self._table.row_count:,} shown"
        if self._table.trimmed_count:
            text += f"  ·  {self._table.trimmed_count:,} older rows left the view"
        self._rows_label.configure(text=text)

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
        """Show the decoded fields of the selected packet (§12)."""
        packet = self._packet_index.get(str(row.get("_key", "")))
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        if packet is None:
            self._detail_text.insert("1.0", "Packet detail is no longer in the view buffer.")
        else:
            lines = [
                f"Captured at      : {packet.captured_at.isoformat()}",
                f"Interface        : {packet.interface or '-'}",
                f"Frame number     : {packet.number if packet.number is not None else '-'}",
                f"Length           : {packet.length} bytes",
                f"Ethernet         : {packet.src_mac or '-'} -> {packet.dst_mac or '-'}",
                f"Network          : {packet.src_ip or '-'} -> {packet.dst_ip or '-'}"
                + (f"  (IPv{packet.ip_version})" if packet.ip_version else ""),
                f"Transport        : {packet.transport or '-'}"
                + (
                    f"  {packet.src_port} -> {packet.dst_port}"
                    if packet.src_port is not None
                    else ""
                ),
                f"Protocol         : {packet.protocol}",
                f"Application      : {packet.app_protocol or 'not decoded'}",
                f"Highest layer    : {packet.highest_layer or '-'}",
                f"TCP flags        : {packet.flags_text}",
                f"TTL              : {packet.ttl if packet.ttl is not None else '-'}",
                f"Decoded layers   : {', '.join(packet.layers) or '-'}",
                "",
                "Fields not present in the frame are shown as '-'; AETHRA-SEC "
                "does not substitute values.",
            ]
            self._detail_text.insert("1.0", "\n".join(lines))
        self._detail_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Live events
    # ------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        """Apply live capture events."""
        if event.type == EventType.PACKET_BATCH_PROCESSED:
            packets = getattr(event.payload, "packets", ())
            if self._paused:
                self._pending.extend(packets)
                del self._pending[:-5000]
            else:
                self._buffer_packets(packets)
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
        """Hold arriving packets for the next flush.

        The capture service publishes a batch per flush interval, and each
        table write costs the Tk thread a fixed amount whatever its size. Under
        a flood that arrives as many small batches a second, which is how the
        interface used to fall behind and stop servicing its own event loop.
        Coalescing turns them into one write per :data:`FLUSH_INTERVAL_MS`, so
        the cost of displaying a flood is bounded by the clock rather than by
        the attacker's packet rate.
        """
        matched = [p for p in packets if self._matches_protocol(p)]
        self._seen_since_flush += len(packets)
        if matched:
            self._buffer.extend(matched)
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
        if buffered:
            self._append_packets(buffered)
        self._update_surge_note(seen, len(buffered))
        # Reschedule only while traffic is still arriving, so an idle screen
        # costs nothing.
        if self._buffer and self.is_alive:
            self._flush_job = self.after(FLUSH_INTERVAL_MS, self._flush_buffer)

    def _matches_protocol(self, packet: Any) -> bool:
        """True when a packet belongs to the selected protocol view."""
        choice = self._protocol_var.get()
        if choice == PROTOCOL_ANY:
            return True
        protocol = str(getattr(packet, "protocol", "")).upper()
        app_protocol = str(getattr(packet, "app_protocol", "")).upper()
        if choice in {"TCP", "UDP", "ICMP", "ARP"}:
            return protocol == choice
        # DNS, HTTP and HTTPS are applications carried over a transport, so
        # they are matched on the decoded application protocol.
        return app_protocol == choice

    def _update_surge_note(self, seen: int, shown: int) -> None:
        """State plainly when the view is showing less than it counted."""
        rate = seen / (FLUSH_INTERVAL_MS / 1000.0)
        if seen <= shown and not self._buffer_dropped:
            if self._surge_label.winfo_ismapped():
                self._surge_label.pack_forget()
            return
        parts = [f"{rate:,.0f} packet/s arriving"]
        if seen > shown:
            filtered = seen - shown
            parts.append(f"{filtered:,} not matching this view")
        if self._buffer_dropped:
            parts.append(
                f"{self._buffer_dropped:,} not displayed (display buffer full)"
            )
        parts.append("every packet is still analysed, counted and stored")
        self._surge_label.configure(text="  ·  ".join(parts))
        if not self._surge_label.winfo_ismapped():
            self._surge_label.pack(anchor="w", pady=(0, 6))

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
                    "info": truncate(packet.info, 120),
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
        self._rate_label.configure(
            text=(
                f"{format_rate(snapshot.packets_per_second)}  ·  "
                f"{format_bandwidth(snapshot.bytes_per_second)}  ·  "
                f"{format_count(snapshot.active_hosts)} active host(s)"
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
