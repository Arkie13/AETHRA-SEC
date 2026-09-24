"""Wireshark-style inspection of one captured frame (§12).

The packet table shows a summary row because that is all the live pipeline can
afford to keep. This window shows the frame itself: it re-reads the frame from
the session's pcap and renders TShark's own decode - the layer tree, every
decoded field with the byte span it came from, and the captured bytes.

Every value on screen is read from the capture file. Where the frame does not
carry a value the field is simply absent, and where the whole frame cannot be
read the window says why instead of showing an empty tree that could be
mistaken for a decoded packet. Protected payloads are labelled as encrypted and
shown as the bytes they are; nothing here decrypts, and credentials that appear
in an authorised capture are masked before they reach the screen.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk
from typing import Any, Callable

from aethra_sec.integrations.pyshark_capture.inspector import (
    NOT_AVAILABLE,
    LayerNode,
    PacketDetail,
    StreamPacket,
    format_hex_dump,
    hex_line_span,
)
from aethra_sec.ui.theme import PALETTE, Fonts, configure_text_widget
from aethra_sec.ui.widgets.dialogs import ModalDialog, show_message

#: Bytes per hex-dump row. Shared with the highlighter so a field's span maps
#: onto the same rows the dump was built with.
HEX_WIDTH = 16


class PacketInspector(ModalDialog):
    """A layer tree, decoded fields, raw bytes and the followed conversation."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        fonts: Fonts | None = None,
        title: str = "Packet inspector",
        subtitle: str = "",
        on_follow_stream: Callable[[str, int], None] | None = None,
        on_export: Callable[[PacketDetail], None] | None = None,
    ) -> None:
        """Create the window in its loading state.

        The decode runs off the interface thread, so the window opens
        immediately and :meth:`set_detail` fills it in when the frame has been
        read. That is what keeps a large capture from freezing the console.
        """
        # The inspector's panes scroll themselves, so the dialog does not add
        # a viewport around them.
        super().__init__(
            parent, title, width=1060, height=720, resizable=True,
            scrollable=False,
        )
        self.fonts = fonts
        self._detail: PacketDetail | None = None
        self._on_follow_stream = on_follow_stream
        self._on_export = on_export
        self._field_rows: dict[str, Any] = {}
        #: Tree item id -> the LayerNode or PacketField it stands for.
        self._tree_nodes: dict[str, Any] = {}
        self._hex_lines: tuple[str, ...] = ()

        header = ttk.Frame(self.body, style="TFrame")
        header.pack(fill="x", pady=(0, 10))
        self._title_label = ttk.Label(header, text=title, style="CardTitle.TLabel")
        self._title_label.pack(side="left")
        self._stamp_label = ttk.Label(header, text=subtitle, style="CardDim.TLabel")
        self._stamp_label.pack(side="right")

        self._summary_label = ttk.Label(
            self.body, text="Reading the frame from the capture file...",
            style="CardMuted.TLabel", wraplength=1000, justify="left",
        )
        self._summary_label.pack(fill="x", pady=(0, 8))

        #: Shown only when the frame actually carries a masked value.
        self._sensitive_label = ttk.Label(
            self.body, text="", style="CardMuted.TLabel",
            wraplength=1000, justify="left", foreground=PALETTE.high,
        )

        self._notebook = ttk.Notebook(self.body)
        self._notebook.pack(fill="both", expand=True)

        self._build_details_tab()
        self._build_bytes_tab()
        self._build_stream_tab()
        self._build_buttons()

        self.bind("<Control-c>", lambda _event: self._copy_selected_field())
        # The tree is the natural landing place: arrow keys then walk the
        # layers and each selection updates the fields and the hex highlight.
        self.after(60, lambda: self._safely(self._tree.focus_set))

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def _build_details_tab(self) -> None:
        """Layer tree on the left, that layer's decoded fields on the right."""
        tab = ttk.Frame(self._notebook, style="TFrame", padding=8)
        self._notebook.add(tab, text="Packet details")

        split = ttk.PanedWindow(tab, orient="horizontal")
        split.pack(fill="both", expand=True)

        tree_holder = ttk.Frame(split, style="TFrame")
        split.add(tree_holder, weight=2)
        self._tree = ttk.Treeview(
            tree_holder, columns=(), show="tree", height=18, selectmode="browse"
        )
        tree_scroll = ttk.Scrollbar(
            tree_holder, orient="vertical", command=self._tree.yview
        )
        self._tree.configure(yscrollcommand=tree_scroll.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")
        tree_holder.rowconfigure(0, weight=1)
        tree_holder.columnconfigure(0, weight=1)
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self._tree.tag_configure("sensitive", foreground=PALETTE.high)

        fields_holder = ttk.Frame(split, style="TFrame")
        split.add(fields_holder, weight=3)
        self._fields = ttk.Treeview(
            fields_holder, columns=("value",), show="tree headings",
            height=18, selectmode="browse",
        )
        self._fields.heading("#0", text="Field")
        self._fields.heading("value", text="Value")
        self._fields.column("#0", width=250, stretch=False)
        self._fields.column("value", width=420, stretch=True)
        fields_scroll = ttk.Scrollbar(
            fields_holder, orient="vertical", command=self._fields.yview
        )
        self._fields.configure(yscrollcommand=fields_scroll.set)
        self._fields.grid(row=0, column=0, sticky="nsew")
        fields_scroll.grid(row=0, column=1, sticky="ns")
        fields_holder.rowconfigure(0, weight=1)
        fields_holder.columnconfigure(0, weight=1)
        self._fields.bind("<<TreeviewSelect>>", self._on_field_select)
        self._fields.tag_configure("sensitive", foreground=PALETTE.high)
        self._fields.tag_configure("encrypted", foreground=PALETTE.medium)

    def _build_bytes_tab(self) -> None:
        """The frame's captured bytes as offset / hex / ASCII."""
        tab = ttk.Frame(self._notebook, style="TFrame", padding=8)
        self._notebook.add(tab, text="Raw bytes")

        self._bytes_note = ttk.Label(
            tab, text="", style="CardDim.TLabel", wraplength=1000, justify="left"
        )
        self._bytes_note.pack(fill="x", pady=(0, 6))

        holder = ttk.Frame(tab, style="TFrame")
        holder.pack(fill="both", expand=True)
        self._hex = tk.Text(holder, wrap="none", height=20)
        if self.fonts:
            configure_text_widget(self._hex, self.fonts, mono=True)
        vertical = ttk.Scrollbar(holder, orient="vertical", command=self._hex.yview)
        horizontal = ttk.Scrollbar(holder, orient="horizontal", command=self._hex.xview)
        self._hex.configure(
            yscrollcommand=vertical.set, xscrollcommand=horizontal.set
        )
        self._hex.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        holder.rowconfigure(0, weight=1)
        holder.columnconfigure(0, weight=1)
        # The highlight marks the bytes of whatever field is selected, so the
        # decode and the bytes can be read against each other.
        self._hex.tag_configure(
            "selected", background=PALETTE.accent_dim, foreground=PALETTE.text
        )
        self._hex.configure(state="disabled")

    def _build_stream_tab(self) -> None:
        """The conversation this frame belongs to."""
        tab = ttk.Frame(self._notebook, style="TFrame", padding=8)
        self._notebook.add(tab, text="Stream")

        bar = ttk.Frame(tab, style="TFrame")
        bar.pack(fill="x", pady=(0, 6))
        self._follow_button = ttk.Button(
            bar, text="Follow stream", style="Accent.TButton",
            command=self._follow_stream,
        )
        self._follow_button.pack(side="left")
        ttk.Button(
            bar, text="Copy stream", style="Ghost.TButton",
            command=self._copy_stream,
        ).pack(side="left", padx=(6, 0))
        ttk.Button(
            bar, text="Export stream", style="Ghost.TButton",
            command=self._export_stream,
        ).pack(side="left", padx=(6, 0))
        self._stream_note = ttk.Label(
            bar, text="", style="CardDim.TLabel"
        )
        self._stream_note.pack(side="right")

        self._stream = tk.Text(tab, wrap="none", height=20)
        if self.fonts:
            configure_text_widget(self._stream, self.fonts, mono=True)
        stream_scroll = ttk.Scrollbar(tab, orient="vertical", command=self._stream.yview)
        self._stream.configure(yscrollcommand=stream_scroll.set)
        stream_scroll.pack(side="right", fill="y")
        self._stream.pack(fill="both", expand=True)
        self._stream.insert(
            "1.0",
            "Select 'Follow stream' to read this conversation back from the "
            "capture file.\n\nAn encrypted conversation is shown as the bytes "
            "it actually carried; AETHRA-SEC does not decrypt traffic.",
        )
        self._stream.configure(state="disabled")

    def _build_buttons(self) -> None:
        """Window actions."""
        ttk.Button(
            self.buttons, text="Close", style="Ghost.TButton", command=self.cancel
        ).pack(side="right")
        ttk.Button(
            self.buttons, text="Export packet", style="Ghost.TButton",
            command=self._export_packet,
        ).pack(side="right", padx=(0, 6))
        ttk.Button(
            self.buttons, text="Copy field", style="Ghost.TButton",
            command=self._copy_selected_field,
        ).pack(side="right", padx=(0, 6))
        ttk.Button(
            self.buttons, text="Copy raw bytes", style="Ghost.TButton",
            command=self._copy_raw_bytes,
        ).pack(side="right", padx=(0, 6))

    # ------------------------------------------------------------------
    # Content
    # ------------------------------------------------------------------
    def set_detail(self, detail: PacketDetail) -> None:
        """Render a decoded frame, or explain why there is none."""
        self._detail = detail
        if not detail.ok:
            self._show_failure(detail)
            return

        self._summary_label.configure(
            text=(
                detail.summary
                or f"Frame {detail.frame_index} of {detail.pcap_path}"
            )
        )
        if detail.sensitive_fields:
            self._sensitive_label.configure(
                text=(
                    "Sensitive data detected in this frame: "
                    + ", ".join(detail.sensitive_fields[:6])
                    + (" and others" if len(detail.sensitive_fields) > 6 else "")
                    + ". These values are redacted in this view; the capture "
                    "file itself is unchanged."
                )
            )
            self._sensitive_label.pack(fill="x", pady=(0, 8), before=self._notebook)

        self._populate_tree(detail)
        self._populate_bytes(detail)
        self._update_stream_controls(detail)

    def _show_failure(self, detail: PacketDetail) -> None:
        """State plainly that the frame could not be read."""
        self._summary_label.configure(
            text=detail.error or "This frame could not be decoded.",
            foreground=PALETTE.high,
        )
        for widget in (self._hex, self._stream):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", detail.error or "No decoded frame is available.")
            widget.configure(state="disabled")

    def _populate_tree(self, detail: PacketDetail) -> None:
        """Fill the tree: one expandable node per layer, its fields beneath.

        Layers sit as siblings in capture order - lowest first - and each opens
        to reveal the fields TShark decoded from it, with grouped fields (the
        bits of ``tcp.flags``, the parts of ``ip.dsfield``) nested exactly as
        the dissector grouped them.
        """
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._tree_nodes.clear()

        first = ""
        for index, layer in enumerate(detail.layers):
            label = layer.title
            if layer.encrypted:
                label += "  - encrypted payload"
            if layer.offset is not None and layer.length:
                label += f"  [{layer.offset}..{layer.offset + layer.length - 1}]"
            else:
                label += f"  ({len(layer.fields)} field(s))"
            item = self._tree.insert(
                "", "end", iid=f"L{index}", text=label, open=index == 0
            )
            self._tree_nodes[item] = layer
            first = first or item
            self._insert_fields(item, layer.fields, f"L{index}")

        if first:
            self._tree.selection_set(first)
            self._tree.focus(first)

    def _insert_fields(
        self, parent: str, fields: tuple[Any, ...], prefix: str
    ) -> None:
        """Add a layer's fields, recursing into the dissector's own groups."""
        for position, entry in enumerate(fields):
            item_id = f"{prefix}.{position}"
            text = f"{entry.label}: {entry.value}" if entry.value else entry.label
            self._tree.insert(
                parent, "end", iid=item_id, text=text,
                tags=("sensitive",) if entry.sensitive else (),
            )
            self._tree_nodes[item_id] = entry
            if entry.children:
                self._insert_fields(item_id, entry.children, item_id)

    def _populate_bytes(self, detail: PacketDetail) -> None:
        """Render the captured bytes, or say why there are none."""
        self._hex.configure(state="normal")
        self._hex.delete("1.0", "end")
        if detail.raw_bytes:
            self._hex_lines = format_hex_dump(detail.raw_bytes, width=HEX_WIDTH)
            self._hex.insert("1.0", "\n".join(self._hex_lines))
            note = (
                f"{len(detail.raw_bytes):,} byte(s) as captured. Selecting a "
                "field on the Packet details tab highlights the bytes it was "
                "decoded from."
            )
            if detail.sensitive_fields:
                # The decoded view masks credentials; these are the frame's own
                # bytes, and masking them would make every byte offset wrong.
                # Saying so is more honest than quietly altering the evidence.
                note += (
                    "  This frame carries a credential: the decoded fields "
                    "above are redacted, but these bytes are the packet "
                    "exactly as captured and still contain it. Treat this "
                    "view, and anything copied from it, as sensitive."
                )
            self._bytes_note.configure(
                text=note,
                foreground=PALETTE.high if detail.sensitive_fields else PALETTE.text_dim,
            )
        else:
            self._hex_lines = ()
            self._bytes_note.configure(
                text=(
                    "Raw bytes are not available for this frame. The capture "
                    "was read without raw mode, so only the decoded fields "
                    "could be recovered."
                )
            )
            self._hex.insert(
                "1.0",
                "Raw bytes unavailable for this packet.\n\n"
                "TShark returned no frame bytes for it, so there is\n"
                "nothing to show. No hex is ever generated here.",
            )
        self._hex.configure(state="disabled")

    def _update_stream_controls(self, detail: PacketDetail) -> None:
        """Enable following only when TShark gave this frame a stream index."""
        if detail.stream_kind and detail.stream_index is not None:
            self._stream_note.configure(
                text=f"{detail.stream_kind.upper()} stream {detail.stream_index}"
            )
            self._follow_button.state(["!disabled"])
        else:
            self._stream_note.configure(
                text="This frame is not part of a TCP or UDP conversation."
            )
            self._follow_button.state(["disabled"])

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------
    def _on_tree_select(self, _event: tk.Event | None = None) -> None:
        """Show the decoded fields of whatever the tree has selected.

        A layer shows its own fields; a grouped field shows the sub-fields the
        dissector put under it; a leaf shows itself. In every case the bytes it
        was decoded from are highlighted.
        """
        selection = self._tree.selection()
        if not selection:
            return
        node = self._tree_nodes.get(selection[0])
        if node is None:
            return

        for item in self._fields.get_children():
            self._fields.delete(item)
        self._field_rows.clear()

        if isinstance(node, LayerNode):
            if node.encrypted:
                self._fields.insert(
                    "", "end", text="payload",
                    values=(
                        "Encrypted - the handshake and record metadata are in "
                        "the clear; the application data is not readable "
                        "without keys AETHRA-SEC does not hold and does not "
                        "seek.",
                    ),
                    tags=("encrypted",),
                )
            entries = node.fields
            if not entries:
                self._fields.insert(
                    "", "end", text="(no fields)",
                    values=(f"TShark decoded no named fields for {node.name}.",),
                )
            self._show_fields(entries)
            self._highlight_span(node.offset, node.length)
            return

        # A field: show it, then whatever the dissector grouped beneath it.
        self._show_fields((node,) + node.children)
        self._highlight_span(node.offset, node.length)

    def _show_fields(self, entries: tuple[Any, ...]) -> None:
        """List fields in the right-hand pane, keeping their own nesting."""
        def add(parent: str, items: tuple[Any, ...], prefix: str) -> None:
            for position, entry in enumerate(items):
                item_id = f"{prefix}f{position}"
                node = self._fields.insert(
                    parent, "end", iid=item_id, text=entry.label,
                    values=(entry.value or "",), open=True,
                    tags=("sensitive",) if entry.sensitive else (),
                )
                self._field_rows[node] = entry
                if entry.children:
                    add(node, entry.children, f"{item_id}.")

        add("", entries, "")

    def _on_field_select(self, _event: tk.Event | None = None) -> None:
        """Highlight in the hex view the bytes the selected field came from."""
        selection = self._fields.selection()
        if not selection:
            return
        entry = self._field_rows.get(selection[0])
        if entry is None:
            return
        self._highlight_span(entry.offset, entry.length)

    def _highlight_span(self, offset: int | None, length: int | None) -> None:
        """Mark the hex rows covering a byte span, and scroll them into view."""
        self._hex.configure(state="normal")
        self._hex.tag_remove("selected", "1.0", "end")
        if offset is None or not length or not self._hex_lines:
            self._hex.configure(state="disabled")
            return
        first, last = hex_line_span(offset, length, width=HEX_WIDTH)
        if first < 0:
            self._hex.configure(state="disabled")
            return
        last = min(last, len(self._hex_lines) - 1)
        self._hex.tag_add("selected", f"{first + 1}.0", f"{last + 1}.end")
        self._hex.see(f"{first + 1}.0")
        self._hex.configure(state="disabled")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _follow_stream(self) -> None:
        """Ask the screen to read this frame's conversation."""
        detail = self._detail
        if detail is None or not detail.stream_kind or detail.stream_index is None:
            return
        self.set_stream_text("Reading the conversation from the capture file...")
        if self._on_follow_stream is not None:
            self._on_follow_stream(detail.stream_kind, detail.stream_index)

    def select_stream_tab(self) -> None:
        """Bring the Stream tab forward."""
        try:
            self._notebook.select(2)
        except tk.TclError:  # pragma: no cover - window closing
            pass

    def set_stream_text(self, text: str) -> None:
        """Replace the stream pane's contents."""
        self._stream.configure(state="normal")
        self._stream.delete("1.0", "end")
        self._stream.insert("1.0", text)
        self._stream.configure(state="disabled")

    def set_stream(self, packets: tuple[StreamPacket, ...], error: str) -> None:
        """Render a followed conversation, direction by direction."""
        if error:
            self.set_stream_text(error)
            return
        lines: list[str] = []
        encrypted_frames = sum(1 for entry in packets if entry.encrypted)
        lines.append(
            f"{len(packets)} frame(s) in this conversation, "
            f"{sum(entry.length for entry in packets):,} payload byte(s)."
        )
        if encrypted_frames:
            lines.append(
                f"{encrypted_frames} frame(s) carry an encrypted payload. Their "
                "bytes are shown as captured and are not decrypted."
            )
        lines.append("")
        for entry in packets:
            lines.append(
                f"--- frame {entry.frame_index}  {entry.source} -> "
                f"{entry.destination}  {entry.length} byte(s)"
                + ("  [encrypted]" if entry.encrypted else "")
            )
            if not entry.payload:
                lines.append("    (no payload bytes in this frame)")
                continue
            lines.extend(
                f"    {line}" for line in format_hex_dump(entry.payload, width=HEX_WIDTH)
            )
        self.set_stream_text("\n".join(lines))

    def _copy_selected_field(self) -> None:
        """Copy the selected field as ``name = value``."""
        selection = self._fields.selection()
        entry = self._field_rows.get(selection[0]) if selection else None
        if entry is None:
            show_message(self, "Copy field", "Select a field first.", kind="info")
            return
        self._to_clipboard(f"{entry.name} = {entry.value}")

    def _copy_raw_bytes(self) -> None:
        """Copy the hex dump exactly as displayed."""
        detail = self._detail
        if detail is None or not detail.raw_bytes:
            show_message(
                self, "Copy raw bytes",
                "This frame has no raw bytes to copy.", kind="info",
            )
            return
        self._to_clipboard("\n".join(self._hex_lines))

    def _copy_stream(self) -> None:
        """Copy the stream pane."""
        self._to_clipboard(self._stream.get("1.0", "end").strip())

    def _export_stream(self) -> None:
        """Write the stream pane to a file the operator chooses."""
        self._write_file(
            self._stream.get("1.0", "end").strip(), "stream", "Export stream"
        )

    def _export_packet(self) -> None:
        """Write the full decode of this frame to a file."""
        detail = self._detail
        if detail is None or not detail.ok:
            show_message(
                self, "Export packet",
                "There is no decoded frame to export.", kind="info",
            )
            return
        if self._on_export is not None:
            self._on_export(detail)
            return
        self._write_file(self.as_text(), "packet", "Export packet")

    def as_text(self) -> str:
        """The whole decode as plain text, for copy and export."""
        detail = self._detail
        if detail is None or not detail.ok:
            return detail.error if detail else "No decoded frame."
        lines = [
            f"Frame {detail.frame_index} of {detail.pcap_path}",
            detail.summary or "",
            "",
        ]
        for layer in detail.layers:
            lines.append(f"=== {layer.title} [{layer.name}]"
                         + ("  (encrypted payload)" if layer.encrypted else ""))
            for entry in layer.fields:
                lines.append(f"    {entry.name} = {entry.value}")
            lines.append("")
        if detail.raw_bytes:
            lines.append(f"=== Raw bytes ({len(detail.raw_bytes)})")
            lines.extend(f"    {line}" for line in self._hex_lines)
        else:
            lines.append(f"=== Raw bytes: {NOT_AVAILABLE}")
        return "\n".join(lines)

    def _write_file(self, text: str, stem: str, title: str) -> None:
        """Save text to a file chosen by the operator."""
        if not text:
            show_message(self, title, "There is nothing to export.", kind="info")
            return
        detail = self._detail
        suggested = f"{stem}_{detail.frame_index if detail else 0}.txt"
        path = filedialog.asksaveasfilename(
            parent=self, title=title, defaultextension=".txt",
            initialfile=suggested,
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
        except OSError as exc:
            show_message(self, title, f"Could not write the file:\n{exc}", kind="error")
            return
        show_message(self, title, f"Written to:\n{path}", kind="info")

    def _to_clipboard(self, text: str) -> None:
        """Put text on the clipboard, tolerating a display without one."""
        if not text:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except tk.TclError:  # pragma: no cover - no clipboard on this display
            pass

    @staticmethod
    def _safely(action: Callable[[], Any]) -> None:
        """Run a widget call that may arrive after the window has closed."""
        try:
            action()
        except tk.TclError:  # pragma: no cover - window already destroyed
            pass
