"""Transient toast notifications (§52, §108).

A toast is raised only by a real event that the application observed - a scan
finishing, a capture failing, an incident being correlated. Nothing schedules a
decorative toast, and a toast never reports a state the subsystem did not
report itself.

Toasts stack above the status bar in the bottom-right corner of the console,
newest at the bottom, and dismiss themselves after a few seconds. Clicking one
runs its action (usually: open the screen that owns the event).

A stored security notification is shown differently, through
``show_persistent``: centred in the application window, with no timer, and
with CLOSE and CHECK buttons. It stays until the operator acts on it, because
a detection that scrolled away unseen is a detection nobody acted on. CHECK
opens the screen the notification is about and dismisses it; CLOSE dismisses
it without going anywhere. Only one is visible at a time; the rest queue, and
a new one never dismisses or overwrites an unclosed one.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from aethra_sec.utils.logging import get_logger
from aethra_sec.ui.theme import PALETTE, Fonts

LOGGER = get_logger("ui.toast")

#: How long a toast stays on screen, by level.
DURATION_MS: dict[str, int] = {
    "INFO": 5000,
    "SUCCESS": 5000,
    "WARNING": 8000,
    "CRITICAL": 12000,
}

#: Accent colour per level. Every member of NotificationLevel appears here:
#: ERROR did not, so an error-level notification was drawn in the
#: informational blue, which states the opposite of what it is.
LEVEL_COLOURS: dict[str, str] = {
    "INFO": PALETTE.info,
    "SUCCESS": PALETTE.ok,
    "WARNING": PALETTE.medium,
    "ERROR": PALETTE.high,
    "CRITICAL": PALETTE.critical,
}

#: Most toasts on screen at once; older ones are dismissed to make room.
MAX_VISIBLE = 4

#: How many persistent notifications wait behind the visible one.
#: Bounded so a flood cannot build an unbounded queue of windows. Nothing is
#: lost by the bound: every one of these was written to the notifications
#: table before it was published, so the overflow stays readable in the
#: notification panel. The popup says how many are waiting.
MAX_PENDING = 20

#: The label on the dismiss button. Exact text, because the operator is told
#: to look for it.
CLOSE_LABEL = "CLOSE"

#: The label on the button that opens the Alerts screen.
CHECK_LABEL = "CHECK"


class ToastManager:
    """Owns the toast stack for one window."""

    def __init__(self, host: tk.Misc, fonts: Fonts) -> None:
        """Bind the manager to the frame toasts are placed in."""
        self._host = host
        self._fonts = fonts
        self._toasts: list[ttk.Frame] = []
        #: The one visible persistent popup, and the notifications waiting
        #: behind it. Kept apart from ``_toasts`` so the transient stack's
        #: eviction rule can never reach a popup the operator has not closed.
        self._persistent: ttk.Frame | None = None
        self._pending: list[dict[str, object]] = []
        self._pending_label: ttk.Label | None = None
        self._dropped = 0
        #: Called when a persistent popup becomes visible / is dismissed, with
        #: the popup's spec. The app uses these to start and stop the siren so
        #: the sound follows exactly the popup the operator can see, including
        #: when the queue advances to the next one. Set via on_persistent().
        self._on_present: Callable[[dict[str, object]], None] | None = None
        self._on_dismiss: Callable[[dict[str, object]], None] | None = None
        #: A fresh identity for every persistent popup, so a stop request from
        #: one popup can never silence the popup that replaced it.
        self._persistent_token: object | None = None

    def on_persistent(
        self,
        present: "Callable[[dict[str, object]], None] | None",
        dismiss: "Callable[[dict[str, object]], None] | None",
    ) -> None:
        """Register start/stop callbacks for the persistent popup's sound."""
        self._on_present = present
        self._on_dismiss = dismiss

    def show(
        self,
        title: str,
        message: str = "",
        *,
        level: str = "INFO",
        on_click: Callable[[], None] | None = None,
    ) -> None:
        """Raise a toast for a real event."""
        level = (level or "INFO").upper()
        colour = LEVEL_COLOURS.get(level, PALETTE.info)

        while len(self._toasts) >= MAX_VISIBLE:
            self._dismiss(self._toasts[0])

        try:
            frame = ttk.Frame(self._host, style="Toast.TFrame", padding=(0, 0))
        except tk.TclError:  # pragma: no cover - window is closing
            return

        accent = tk.Frame(frame, background=colour, width=3)
        accent.pack(side="left", fill="y")

        body = ttk.Frame(frame, style="Toast.TFrame", padding=(12, 9))
        body.pack(side="left", fill="both", expand=True)

        heading = ttk.Frame(body, style="Toast.TFrame")
        heading.pack(fill="x")
        title_label = ttk.Label(heading, text=title, style="Toast.TLabel")
        title_label.configure(foreground=colour)
        title_label.pack(side="left")
        close = ttk.Label(heading, text="✕", style="ToastBody.TLabel", cursor="hand2")
        close.pack(side="right", padx=(10, 0))
        close.bind("<Button-1>", lambda _event: self._dismiss(frame))

        message_label: ttk.Label | None = None
        if message:
            message_label = ttk.Label(
                body, text=message, style="ToastBody.TLabel",
                wraplength=330, justify="left",
            )
            message_label.pack(anchor="w", pady=(3, 0))

        if on_click is not None:
            for widget in (frame, body, heading, title_label, message_label):
                if widget is None:
                    continue
                widget.configure(cursor="hand2")
                widget.bind(
                    "<Button-1>",
                    lambda _event, action=on_click, target=frame: (
                        self._dismiss(target), action()
                    ),
                )

        self._toasts.append(frame)
        self._relayout()
        self._host.after(DURATION_MS.get(level, 5000), lambda: self._dismiss(frame))

    def show_persistent(
        self,
        title: str,
        message: str = "",
        *,
        level: str = "INFO",
        reference: str = "",
        on_check: Callable[[], None] | None = None,
        severity: str = "",
        is_detection: bool = False,
    ) -> bool:
        """Show a notification that stays until the operator closes it.

        Returns True if it was shown, False if it was queued behind one that
        is still open. A new notification never replaces an unclosed one: the
        operator decides what they have finished reading, not the next packet.

        Every string displayed is passed in by the caller from the event's own
        payload. Nothing is composed here, and a field the event did not carry
        is simply absent rather than guessed at.

        ``severity`` is the detection's own severity. ``level`` is the
        notification's urgency, used for colour and for ranking an escalation;
        it is never shown as the severity. A detection that arrives without a
        severity says UNKNOWN rather than borrowing the level.
        """
        spec: dict[str, object] = {
            "title": str(title or "Notification"),
            "message": str(message or ""),
            "level": (level or "INFO").upper(),
            "reference": str(reference or ""),
            "on_check": on_check,
            "severity": str(severity or "").strip().upper(),
            "is_detection": bool(is_detection),
        }
        if self._persistent is not None and self._supersedes(spec):
            # The same record, now worse than what is on screen. Replacing it
            # is a correction, not an interruption: leaving the old severity
            # up would state something about this attack that has stopped
            # being true.
            LOGGER.info(
                "A notification about %s escalated to %s; replacing the "
                "popup that still showed %s.",
                spec["reference"] or "the same record", spec["level"],
                (self._persistent.__dict__.get("_aethra_spec") or {}).get("level"),
            )
            self.close_persistent(self._persistent, advance=False)
            self._build_persistent(spec)
            return True
        if self._persistent is not None:
            if len(self._pending) < MAX_PENDING:
                self._pending.append(spec)
            else:
                # Bounded on purpose. The record itself is already stored, so
                # what is lost is the popup, not the notification.
                self._dropped += 1
            self._paint_pending()
            return False
        self._build_persistent(spec)
        return True

    #: Severity order, worst last. A level outside this list never
    #: supersedes anything, because its place in the order is unknown.
    _LEVEL_ORDER = ("INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL")

    def _supersedes(self, spec: dict[str, object]) -> bool:
        """True when this notification corrects the popup already on screen.

        Both must name the same record - that is what makes it a correction
        rather than one alert elbowing another aside - and the new one must
        rank higher. A different record, an unknown level, or a severity that
        has not risen all leave the visible popup alone.
        """
        current = self._persistent
        if current is None:
            return False
        reference = str(spec.get("reference") or "").strip()
        if not reference:
            return False
        shown = current.__dict__.get("_aethra_spec") or {}
        if str(shown.get("reference") or "").strip() != reference:
            return False
        try:
            new_rank = self._LEVEL_ORDER.index(str(spec.get("level")))
            old_rank = self._LEVEL_ORDER.index(str(shown.get("level")))
        except ValueError:
            return False
        return new_rank > old_rank

    @property
    def persistent_frame(self) -> ttk.Frame | None:
        """The visible persistent popup, if there is one."""
        return self._persistent

    @property
    def pending_count(self) -> int:
        """Notifications waiting behind the visible popup."""
        return len(self._pending)

    def _build_persistent(self, spec: dict[str, object]) -> None:
        """Draw one persistent popup, centred in the application window."""
        level = str(spec["level"])
        colour = LEVEL_COLOURS.get(level, PALETTE.info)
        try:
            frame = ttk.Frame(self._host, style="Toast.TFrame", padding=(0, 0))
        except tk.TclError:  # pragma: no cover - window is closing
            return

        accent = tk.Frame(frame, background=colour, width=4)
        accent.pack(side="left", fill="y")

        body = ttk.Frame(frame, style="Toast.TFrame", padding=(18, 14))
        body.pack(side="left", fill="both", expand=True)

        heading = ttk.Label(body, text=str(spec["title"]), style="Toast.TLabel")
        heading.configure(foreground=colour)
        heading.pack(anchor="w")

        # The detection's own severity. This line used to print the
        # notification LEVEL - an urgency ranking, which is ERROR for a HIGH
        # detection - so a HIGH alert read "Notification level: ERROR", as
        # though delivery had failed. The level still colours the popup; only
        # the severity is ever shown as one.
        # A notification that is not about a detection carries no severity
        # and shows no such line.
        severity = str(spec.get("severity") or "")
        if severity or spec.get("is_detection"):
            severity_line = ttk.Label(
                body, text=f"Severity Level: {severity or 'UNKNOWN'}",
                style="ToastBody.TLabel",
            )
            severity_line.configure(foreground=colour)
            severity_line.pack(anchor="w", pady=(2, 0))

        if spec["message"]:
            ttk.Label(
                body, text=str(spec["message"]), style="ToastBody.TLabel",
                wraplength=420, justify="left",
            ).pack(anchor="w", pady=(8, 0))

        if spec["reference"]:
            ttk.Label(
                body, text=str(spec["reference"]), style="ToastBody.TLabel",
            ).pack(anchor="w", pady=(6, 0))

        self._pending_label = ttk.Label(body, text="", style="ToastBody.TLabel")
        self._pending_label.pack(anchor="w", pady=(6, 0))

        actions = ttk.Frame(body, style="Toast.TFrame")
        actions.pack(anchor="e", pady=(14, 0))
        # CHECK first, CLOSE last: the operator reads left to right, and the
        # button that only dismisses sits after the one that acts.
        check = ttk.Button(
            actions, text=CHECK_LABEL, style="Accent.TButton",
            command=lambda: self._on_check(frame),
        )
        check.pack(side="left")
        close = ttk.Button(
            actions, text=CLOSE_LABEL, style="Ghost.TButton",
            command=lambda: self.close_persistent(frame),
        )
        close.pack(side="left", padx=(8, 0))

        token = object()
        self._persistent_token = token
        spec["_token"] = token
        frame.__dict__["_aethra_spec"] = spec
        self._persistent = frame
        self._place_persistent()
        self._paint_pending()
        if self._on_present is not None:
            try:
                self._on_present(spec)
            except Exception:  # noqa: BLE001 - sound is never worth a crash
                LOGGER.exception("The persistent popup present hook failed.")

    def _place_persistent(self) -> None:
        """Centre the popup in the host, which is the window's own body.

        ``relx``/``rely`` are fractions of the host, so Tk re-centres this
        itself when the window is resized, and the popup travels with the
        window when it is moved. There is no geometry to recompute and no way
        for it to end up off-screen.
        """
        frame = self._persistent
        if frame is None:
            return
        try:
            frame.place(relx=0.5, rely=0.5, anchor="center")
            frame.lift()
        except tk.TclError:  # pragma: no cover - window is closing
            self._persistent = None

    def _paint_pending(self) -> None:
        """Say how many notifications are waiting, using the real count."""
        label = self._pending_label
        if label is None:
            return
        try:
            if not label.winfo_exists():
                return
        except tk.TclError:  # pragma: no cover - window is closing
            return
        waiting = len(self._pending)
        parts = []
        if waiting:
            parts.append(
                f"{waiting} more notification{'s' if waiting != 1 else ''} "
                "waiting - CLOSE to see the next"
            )
        if self._dropped:
            parts.append(
                f"{self._dropped} further notification"
                f"{'s' if self._dropped != 1 else ''} not queued; "
                "all of them remain in the notification panel"
            )
        try:
            label.configure(text="  ·  ".join(parts))
        except tk.TclError:  # pragma: no cover - window is closing
            pass

    def _on_check(self, frame: ttk.Frame) -> None:
        """Open the screen this notification is about, then dismiss it.

        One press, one intention: the operator wants to go and look at the
        alert. Leaving the popup up afterwards left it covering the very
        screen they had just asked for, and made them click twice to get rid
        of it.

        If the navigation raises, the popup is kept and the failure logged.
        Dismissing it then would throw the notification away without ever
        having shown the operator what it was about.

        CLOSE remains the way to dismiss without going anywhere.
        """
        if frame is not self._persistent:
            # A callback left over from a popup that has already gone.
            return
        spec = frame.__dict__.get("_aethra_spec") or {}
        action = spec.get("on_check")
        if callable(action):
            try:
                action()
            except Exception:  # noqa: BLE001 - navigation is never worth a crash
                LOGGER.exception(
                    "A notification's CHECK action failed; the popup is kept."
                )
                self._place_persistent()
                return
        # Dismissed exactly as CLOSE would, so the queue advances the same way
        # and the alert record is equally untouched.
        self.close_persistent(frame)

    def close_persistent(
        self, frame: ttk.Frame | None = None, *, advance: bool = True
    ) -> None:
        """Dismiss the persistent popup, and only that popup.

        The frame is identity-checked against the one on screen so a stale
        button callback cannot destroy whatever has replaced it. Closing
        changes nothing about the alert: this dismisses a window, and the
        record, its severity, its addresses, its timestamps and its review
        status are all untouched.
        """
        current = self._persistent
        if current is None:
            return
        if frame is not None and frame is not current:
            return
        self._persistent = None
        self._pending_label = None
        spec = current.__dict__.get("_aethra_spec") or {}
        token = spec.get("_token")
        if self._persistent_token is token:
            self._persistent_token = None
        # Stop the sound before the next queued popup starts its own, so there
        # is never a moment with two sirens. Keyed by this popup's token, so a
        # stale callback cannot silence a popup that already replaced this one.
        if self._on_dismiss is not None:
            try:
                self._on_dismiss(spec)
            except Exception:  # noqa: BLE001
                LOGGER.exception("The persistent popup dismiss hook failed.")
        try:
            current.place_forget()
            current.destroy()
        except tk.TclError:  # pragma: no cover - window is closing
            pass
        # ``advance`` is False only when the caller is about to put a
        # corrected version of this same popup up itself; pulling the next
        # queued notification first would make it flash past.
        if advance and self._pending:
            self._build_persistent(self._pending.pop(0))

    def clear(self) -> None:
        """Dismiss every toast and popup (used on shutdown).

        The queue is emptied without being shown, because the window is going
        away. The notifications themselves are already stored; nothing here
        touches them.
        """
        for frame in list(self._toasts):
            self._dismiss(frame)
        self._pending.clear()
        self._dropped = 0
        self.close_persistent()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _dismiss(self, frame: ttk.Frame) -> None:
        """Remove one toast."""
        if frame not in self._toasts:
            return
        self._toasts.remove(frame)
        try:
            frame.destroy()
        except tk.TclError:
            pass
        self._relayout()

    def _relayout(self) -> None:
        """Stack the toasts from the bottom-right corner upwards."""
        offset = 0
        for frame in reversed(self._toasts):
            try:
                frame.place(relx=1.0, rely=1.0, anchor="se", x=-18, y=-18 - offset)
                frame.update_idletasks()
                offset += frame.winfo_reqheight() + 10
            except tk.TclError:  # pragma: no cover - window is closing
                return
