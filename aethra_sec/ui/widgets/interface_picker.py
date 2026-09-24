"""Capture-interface selector for Live Monitoring.

Choosing an interface is a one-off decision; watching packets is the work. So
this is a single compact control rather than a list: a list of every capture
device is eighteen rows on this machine, which pushed the packet table off the
page entirely.

Everything shown is read from the machine - the adapter name and medium come
from the operating system, the addresses from psutil, and the capture
identifier from TShark itself. Nothing is inferred from an adapter's name,
because operators rename adapters freely: on this development machine the
adapter labelled "Ethernet 3" is actually a VirtualBox host-only device.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable, Sequence
from tkinter import ttk
from typing import Any

from aethra_sec.ui.theme import METRICS, PALETTE

#: Order the groups appear in. Anything else follows, alphabetically.
GROUP_ORDER: tuple[str, ...] = ("Wi-Fi", "Ethernet", "Bluetooth", "Loopback", "Other")

#: Marks the interface the routing table uses.
DEFAULT_ROUTE_MARK = "DEFAULT ROUTE"


def _is_practical(interface: Any) -> bool:
    """True for an interface an operator would realistically capture on."""
    return bool(getattr(interface, "ipv4", ()) and getattr(interface, "is_up", False))


class InterfacePicker(ttk.Frame):
    """A compact dropdown over the real capture interfaces.

    The public shape is unchanged from the list this replaces, so the capture
    lifecycle around it - automatic start, switching, locking during a
    start/stop - needs no changes.
    """

    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_select: Callable[[Any], None] | None = None,
        surface: str = "",
        width: int = 34,
    ) -> None:
        """Create an empty picker; call :meth:`set_interfaces` to fill it."""
        super().__init__(parent, style="Card.TFrame")
        self._on_select = on_select
        self._surface = surface or PALETTE.surface
        self._interfaces: list[Any] = []
        self._selected: Any = None
        self._enabled = True
        self._by_label: dict[str, Any] = {}
        self._suppress = False

        self._var = tk.StringVar()
        self._combo = ttk.Combobox(
            self, textvariable=self._var, state="readonly", width=width
        )
        self._combo.pack(side="left")
        self._combo.bind("<<ComboboxSelected>>", self._on_combo)

        # One line of real detail for the current choice, so the medium and
        # link state stay visible without a row per adapter.
        self._detail = ttk.Label(self, text="", style="CardDim.TLabel")
        self._detail.pack(side="left", padx=(METRICS.space_sm, 0))

    # ------------------------------------------------------------------
    @staticmethod
    def _label_for(interface: Any) -> str:
        """The option text: name, address and why it leads the list."""
        parts = [str(interface.display_name)]
        address = str(getattr(interface, "primary_ipv4", "") or "")
        if address:
            parts.append(f"— {address}")
        if getattr(interface, "is_primary", False):
            parts.append(f"· {DEFAULT_ROUTE_MARK}")
        return " ".join(parts)

    def set_interfaces(
        self, interfaces: Sequence[Any], selected_name: str = ""
    ) -> None:
        """Render the picker from real enumerated interfaces."""
        # Grouped by medium so the wireless and wired adapters lead, with the
        # virtual ones after them - the enumeration already sorts within a
        # group, putting the routing interface first.
        ordered = sorted(
            interfaces,
            key=lambda i: (
                GROUP_ORDER.index(i.group) if i.group in GROUP_ORDER else 99,
                not getattr(i, "is_primary", False),
                not _is_practical(i),
                i.display_name.lower(),
            ),
        )
        self._interfaces = list(ordered)
        self._by_label = {}
        labels: list[str] = []
        for interface in ordered:
            label = self._label_for(interface)
            # Two adapters can share a display name; keep the entries distinct
            # so a selection always maps back to one device.
            if label in self._by_label:
                label = f"{label}  ({interface.name[-8:]})"
            self._by_label[label] = interface
            labels.append(label)

        self._combo.configure(values=labels)

        wanted = selected_name or str(getattr(self._selected, "name", "") or "")
        chosen = next((i for i in ordered if i.name == wanted), None)
        if chosen is None:
            # Default to the interface that can actually capture, which the
            # enumeration already sorted to the top.
            chosen = next(
                (i for i in ordered if _is_practical(i)),
                ordered[0] if ordered else None,
            )
        self._show(chosen)

    def _show(self, interface: Any) -> None:
        """Reflect a selection in the control without re-notifying."""
        self._selected = interface
        self._suppress = True
        try:
            if interface is None:
                self._var.set("")
                self._detail.configure(
                    text="No capture interfaces detected - install or repair Npcap."
                )
                return
            for label, entry in self._by_label.items():
                if entry.name == interface.name:
                    self._var.set(label)
                    break
            state = str(interface.status_text)
            detail = " · ".join(
                part for part in (
                    interface.group,
                    state,
                    str(getattr(interface, "link_speed", "") or ""),
                ) if part
            )
            self._detail.configure(
                text=detail,
                foreground=PALETTE.ok if state == "UP" else PALETTE.text_dim,
            )
        finally:
            self._suppress = False

    # ------------------------------------------------------------------
    def selected(self) -> Any:
        """The chosen interface, or None when none could be enumerated."""
        return self._selected

    def selected_name(self) -> str:
        """The identifier TShark expects, or an empty string."""
        return str(getattr(self._selected, "name", "") or "")

    def set_enabled(self, enabled: bool) -> None:
        """Lock the control while a start or stop is in flight."""
        self._enabled = enabled
        self._combo.configure(state="readonly" if enabled else "disabled")

    # ------------------------------------------------------------------
    def _on_combo(self, _event: tk.Event) -> None:
        """Selecting an entry chooses that interface."""
        if self._suppress or not self._enabled:
            return
        interface = self._by_label.get(self._var.get())
        if interface is None or (
            self._selected is not None and interface.name == self._selected.name
        ):
            return
        self._show(interface)
        if self._on_select is not None:
            self._on_select(interface)
