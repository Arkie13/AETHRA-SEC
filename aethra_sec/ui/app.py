"""Main console window: navigation shell and event pump (§61, §75, §105).

The window owns the single place where background events cross onto the Tk
thread. Producers publish to the :class:`EventBus` from worker threads; this
window drains the queued subscriptions on a ``root.after()`` tick and hands the
events to the visible screen. No widget is ever touched from a worker thread.

Navigation entries are filtered by the session's permissions, and the screens
themselves re-check permissions on every action - the sidebar is a convenience,
not the control (§8). The command palette is built from the same filtered list,
so it can never offer a screen the sidebar hides.

The shell is keyboard-driven as well as pointer-driven: Ctrl+K opens the
command palette, Ctrl+1..9 jump between screens, Ctrl+B collapses the sidebar to
an icon rail, F5 refreshes the visible screen and Escape closes any overlay.
"""

from __future__ import annotations

import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Any, Callable

from aethra_sec.core.application import ApplicationContext
from aethra_sec.core.events import Event, EventType
from aethra_sec.diagnostics import flood_probe
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.models.enums import Severity
from aethra_sec.ui import dispatch
from aethra_sec.ui.base import Screen
from aethra_sec.ui.state import (
    KEY_GEOMETRY,
    KEY_LAST_SCREEN,
    KEY_REDUCED_MOTION,
    KEY_THEME,
    KEY_SIDEBAR_COLLAPSED,
    UiState,
)
from aethra_sec.ui.theme import (
    ICONS,
    PALETTE,
    Fonts,
    apply_theme,
    current_theme,
    set_motion,
    set_theme,
)
from aethra_sec.ui.widgets.tooltip import Tooltip
from aethra_sec.ui.widgets.cards import ScrollableFrame
from aethra_sec.ui.widgets.chips import CountBadge, StatusChip, StatusRail
from aethra_sec.ui.widgets.dialogs import confirm
from aethra_sec.ui.widgets.palette import Command, CommandPalette
from aethra_sec.ui.widgets.toast import ToastManager
from aethra_sec.ui.widgets.tooltip import attach_tooltip
from aethra_sec.models.system import without_correlation_key
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import format_local, utcnow
from aethra_sec.version import APP_NAME, APP_VERSION

LOGGER = get_logger("ui.app")

#: Navigation entries: key, label, permission (empty = always available).
NAVIGATION: tuple[tuple[str, str, str], ...] = (
    ("dashboard", "Dashboard", Permission.DASHBOARD_VIEW),
    # "Live Monitoring" says what the screen is for; "Network Monitoring" said
    # only what it is about, and the two sat one above the other in the rail.
    ("traffic", "Live Monitoring", Permission.MONITOR_VIEW),
    ("vulnerabilities", "Vulnerabilities", Permission.SCAN_VIEW),
    ("hosts", "Hosts", Permission.HOST_VIEW),
    ("alerts", "Alerts", Permission.ALERT_VIEW),
    ("mitigation", "Mitigation", Permission.MITIGATION_VIEW),
    ("attack_statistics", "Attack Statistics", Permission.ALERT_VIEW),
    ("reports", "Reports", Permission.REPORT_GENERATE),
    ("logs", "Logs & Audit", Permission.LOG_VIEW),
    ("users", "Users", Permission.USER_MANAGE),
    ("health", "System Health", Permission.HEALTH_VIEW),
    ("settings", "Settings", Permission.SETTINGS_MANAGE),
    ("help", "Help", ""),
    ("about", "About", ""),
)

#: Sidebar grouping: heading, then the navigation keys under it.
#:
#: Grouped by the question an operator is asking rather than by the subsystem
#: that answers it. "What is happening?" (Monitor) comes before "what has been
#: found?" (Security), which comes before "on what?" (Assets) - and the two
#: groups nobody opens during an incident sit at the bottom.
NAV_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("MONITOR", ("dashboard", "traffic")),
    ("SECURITY", ("alerts", "attack_statistics", "mitigation")),
    ("ASSETS", ("hosts", "vulnerabilities")),
    ("REPORTING", ("reports", "logs")),
    ("ADMINISTRATION", ("users", "health", "settings")),
    ("HELP", ("help", "about")),
)

#: Screens that carry a live count badge in the sidebar, and where it comes
#: from. Each callable returns a real stored count - never an estimate.
BADGE_SOURCES: tuple[str, ...] = ("alerts", "users")

#: Records of each kind the command palette offers for one query. Enough to
#: recognise the one you meant, few enough not to bury the screen commands.
RECORD_SEARCH_LIMIT = 6

#: Sidebar widths, and the frames the slide between them takes.
SIDEBAR_WIDTH = 208
SIDEBAR_RAIL_WIDTH = 76
SIDEBAR_STEPS = 7
SIDEBAR_STEP_MS = 12

#: Resting text in the header's command bar.
SEARCH_PLACEHOLDER = "Search screens, hosts, alerts…"

#: Screens that have been removed, and where a link to one now leads.
#:
#: Threat Incidents was a second view of the same security events the IDS
#: Alerts screen already shows. It was removed rather than hidden; these
#: entries exist so a stale link, a saved "last screen" or an old bookmark
#: opens Alerts instead of failing.
RETIRED_SCREENS: dict[str, str] = {
    "incidents": "alerts",
    "incident_detail": "alerts",
    # Evaluation Runs was a separate test-run measurement system, not a
    # view of production security data. It was removed rather than
    # hidden; an old link lands on Reports, which is where the figures a
    # reader wants now come from - and from real stored records only.
    "evaluation": "reports",
}

#: Events every screen may want, drained on the UI tick.
_UI_EVENTS: tuple[str, ...] = (
    EventType.CAPTURE_STARTED, EventType.CAPTURE_STOPPED, EventType.CAPTURE_ERROR,
    EventType.PACKET_BATCH_PROCESSED, EventType.DISPLAY_VIEW_RESET,
    EventType.DISPLAY_VIEW_BATCH, EventType.TRAFFIC_STATS_UPDATED,
    EventType.TRAFFIC_ANOMALY_DETECTED, EventType.SNORT_ALERT_RECEIVED,
    EventType.SNORT_STATUS_CHANGED, EventType.NMAP_SCAN_STARTED,
    EventType.NMAP_SCAN_COMPLETED, EventType.NMAP_SCAN_FAILED,
    EventType.MITIGATION_GENERATED, EventType.DATABASE_STATUS_CHANGED,
    EventType.SERVICE_STATUS_CHANGED,
    EventType.REPORT_GENERATED, EventType.SYSTEM_ERROR,
)

#: Drained on the same tick, but through a buffer of its own.
#:
#: These used to share the queue above. The bus discards the oldest event
#: when a buffer fills, so during a flood the capture pipeline's packet
#: batches evicted stored notifications before the interface ever saw them -
#: the popup simply never happened, and nothing said so. A separate
#: subscription means traffic cannot reach this buffer, and ``dispatch_all``
#: serves subscriptions round-robin so neither can starve the other.
_NOTIFICATION_EVENTS: tuple[str, ...] = (EventType.NOTIFICATION_STORED,)


#: How each stored ``reference_type`` is named on a notification popup. These
#: are the values the notifications table actually holds; anything else, or
#: nothing at all, falls back to the notification's own id rather than an
#: invented reference.
#:
#: Deliberately absent: the correlated-group type that older rows carry.
#: That feature was withdrawn from the interface, nothing raises one now, and
#: naming it here would put retired terminology back in front of the
#: operator. Those legacy rows show their notification id instead.
REFERENCE_LABELS: dict[str, str] = {
    "alert": "Snort alert",
    "security_alert": "Snort alert",
    "anomaly": "Traffic anomaly",
    "scan": "Assessment",
    "report": "Report",
}


def _notification_reference(payload: Any) -> str:
    """Name the record this notification is about, from the payload alone.

    The payload carries ``reference_type`` and ``reference_id`` and nothing
    more about the detection - no addresses, no protocol, no detection
    timestamp - so this states the identifier and stops there. CHECK is how
    the operator gets to the full record.
    """
    kind = str(getattr(payload, "reference_type", "") or "").strip()
    reference_id = getattr(payload, "reference_id", None)
    label = REFERENCE_LABELS.get(kind)
    if label and reference_id:
        return f"{label} #{reference_id}"
    notification_id = getattr(payload, "notification_id", None)
    if notification_id:
        return f"Notification #{notification_id}"
    return ""


class MainWindow:
    """The application console."""

    #: Wall-clock limit for draining the event bus on one UI tick.
    #:
    #: The tick interval is at least 250 ms, so 60 ms leaves the rest of the
    #: tick - the status strip, the sidebar badges and the screen's own tick,
    #: together under 20 ms measured - plenty of room while keeping the main
    #: loop's worst case well inside what a person reads as responsive.
    #:
    #: Raising it lets a burst drain faster at the cost of a longer worst-case
    #: stall; lowering it defers more events to later ticks. Under sustained
    #: load heavier than this can drain, the bus's bounded queues shed the
    #: oldest events and count them, which is the pre-existing policy and is
    #: visible on the System Health screen as dropped_events.
    EVENT_BUDGET_MS = 60.0

    def __init__(
        self, root: tk.Tk, context: ApplicationContext, fonts: Fonts, session: Session
    ) -> None:
        """Build the console for a signed-in session."""
        self.root = root
        self.context = context
        self.fonts = fonts
        self.session = session
        context.set_session(session)

        self._screens: dict[str, Screen] = {}
        self._built: set[str] = set()
        self._nav_buttons: dict[str, ttk.Button] = {}
        self._nav_rows: dict[str, ttk.Frame] = {}
        self._nav_badges: dict[str, CountBadge] = {}
        self._nav_indicators: dict[str, tk.Frame] = {}
        self._nav_glyphs: dict[str, ttk.Label] = {}
        self._nav_group_headings: list[ttk.Label] = []
        self._nav_order: list[str] = []
        self._current: str = ""
        self._status_chips: dict[str, StatusChip] = {}
        self._tick_job: str | None = None
        self._closing = False
        self._sidebar_collapsed = False
        self._busy_jobs = 0
        self._sidebar_job: str | None = None
        #: Sidebar badge counts, refreshed off the Tk thread and painted from
        #: this cache on the tick. The tick must never issue a DB query itself:
        #: a synchronous read on the UI thread stalls every repaint behind a
        #: network round-trip, which is felt as the interface "lagging".
        self._badge_counts: dict[str, int] = {}
        self._badge_job_running = False
        self._badge_refreshed_at = 0.0
        #: The unread-notification count is a query, so it is asked on a
        #: worker. These keep one worker at a time; see refresh_notifications.
        self._notification_count_running = False
        self._notification_count_again = False
        #: How this console ended: "sign out" returns to the login window,
        #: "quit" exits the application. run_console() returns this.
        self.outcome = "quit"

        # Guarantee the worker-to-Tk bridge before any screen starts work: a
        # console built directly (a test, embedding code) would otherwise have
        # workers whose results could not be delivered.
        dispatch.ensure(root)

        self.state = UiState(Path(context.settings.log_dir))
        # Apply the stored motion preference before any screen animates.
        set_motion(not self.state.get_bool(KEY_REDUCED_MOTION, False))

        self.root.title(f"{APP_NAME} - {session.username} ({session.role})")
        self.root.configure(background=PALETTE.background)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.geometry(self._initial_geometry())
        self.root.minsize(1180, 720)

        self._build_layout()
        self._bind_shortcuts()
        self._subscription = context.event_bus.subscribe(
            _UI_EVENTS, self._on_event, queued=True, max_size=4000, name="main-window"
        )
        # Small on purpose: only notifications arrive here, they arrive at
        # human speed, and a buffer this size cannot fill from traffic. If it
        # ever did overflow, the bus now logs the loss rather than hiding it.
        self._notification_subscription = context.event_bus.subscribe(
            _NOTIFICATION_EVENTS, self._on_notification_event,
            queued=True, max_size=512, name="main-window-notifications",
        )
        # Prompt delivery. The queue above was drained only by the UI tick
        # (ui.refresh_interval_ms, 2,000 ms here), so a stored notification
        # waited up to two seconds - more when the tick ran long - before its
        # popup. This subscriber runs on the publishing thread and does no UI
        # work: it posts ONE drain request to the 40 ms worker-to-Tk
        # dispatcher (single-flight, so a burst cannot flood it). Rendering
        # stays on the Tk thread; the bounded queue stays the only buffer.
        self._notification_wake_pending = False
        self._notification_wake = context.event_bus.subscribe(
            _NOTIFICATION_EVENTS, self._wake_for_notification,
            queued=False, name="main-window-notification-wake",
        )
        if self.state.get_bool(KEY_SIDEBAR_COLLAPSED):
            self.toggle_sidebar()
        self.navigate(self._initial_screen())
        self._schedule_tick()
        self._start_stall_watchdog()
        self.root.deiconify()

    def _start_stall_watchdog(self) -> None:
        """Record where the Tk thread is stuck whenever it stops answering.

        The reported "crash under a high-severity attack" was Windows closing
        a window that had stopped responding (Event ID 1002, AppHangB1, 14 Oct
        2026 04:28:20), with nothing in the log. See
        :mod:`aethra_sec.diagnostics.ui_watchdog`.
        """
        from aethra_sec.diagnostics.ui_watchdog import UiStallWatchdog, install_on_tk

        bus = self.context.event_bus

        def backlog() -> str:
            details = bus.subscription_details()
            return "; ".join(
                f"{item.get('name')}: pending={item.get('pending')} "
                f"dropped={item.get('dropped')}"
                for item in details
            )

        try:
            self._cancel_watchdog = install_on_tk(
                self.root,
                UiStallWatchdog(self.context.settings.log_dir, context=backlog),
            )
        except Exception:  # noqa: BLE001 - a diagnostic must not stop the console
            self._cancel_watchdog = None
            LOGGER.warning("UI stall watchdog not started.", exc_info=True)

    def _initial_geometry(self) -> str:
        """Restore the last window geometry, or size to most of the screen."""
        remembered = self.state.get_str(KEY_GEOMETRY)
        if remembered and "x" in remembered:
            return remembered
        width = min(1680, max(1180, int(self.root.winfo_screenwidth() * 0.86)))
        height = min(1000, max(720, int(self.root.winfo_screenheight() * 0.86)))
        x = max(0, (self.root.winfo_screenwidth() - width) // 2)
        y = max(0, (self.root.winfo_screenheight() - height) // 2 - 20)
        return f"{width}x{height}+{x}+{y}"

    def _initial_screen(self) -> str:
        """The screen to open first: the last one used, if still permitted."""
        remembered = self.state.get_str(KEY_LAST_SCREEN)
        if remembered and remembered in self._nav_buttons:
            return remembered
        return "dashboard" if "dashboard" in self._nav_buttons else (
            self._nav_order[0] if self._nav_order else "about"
        )

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_layout(self) -> None:
        """Create the header, sidebar, content area and status bar."""
        self.header = ttk.Frame(self.root, style="Header.TFrame", padding=(16, 9))
        self.header.pack(fill="x", side="top")

        brand = ttk.Frame(self.header, style="Header.TFrame")
        brand.pack(side="left")
        self._sidebar_toggle = ttk.Button(
            brand, text="☰", style="HeaderIcon.TButton", width=3,
            command=self.toggle_sidebar,
        )
        self._sidebar_toggle.pack(side="left", padx=(0, 12))
        attach_tooltip(self._sidebar_toggle, "Collapse or expand the sidebar  (Ctrl+B)")
        # A mark, then the name, then what it is - read in that order.
        tk.Frame(brand, background=PALETTE.accent, width=4, height=22).pack(
            side="left", padx=(0, 10)
        )
        wordmark = ttk.Frame(brand, style="Header.TFrame")
        wordmark.pack(side="left")
        ttk.Label(
            wordmark, text=APP_NAME, style="Brand.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            wordmark, text="SECURITY OPERATIONS CONSOLE", style="BrandSub.TLabel"
        ).pack(anchor="w")

        self._header_divider(self.header)

        # The command bar is a real field, not a button dressed as one: typing
        # into it opens the palette already carrying what was typed, so the
        # first keystroke is never thrown away.
        search_host = ttk.Frame(self.header, style="SearchBar.TFrame", padding=(10, 6))
        search_host.pack(side="left", padx=(16, 0))
        ttk.Label(
            search_host, text=ICONS["search"], style="SearchIcon.TLabel"
        ).pack(side="left", padx=(0, 8))
        self._search_var = tk.StringVar()
        self._search_entry = ttk.Entry(
            search_host, textvariable=self._search_var, style="Search.TEntry",
            width=34, font=self.fonts.body,
        )
        self._search_entry.pack(side="left")
        self._search_entry.insert(0, SEARCH_PLACEHOLDER)
        self._search_placeholder_shown = True
        self._search_entry.bind("<FocusIn>", self._on_search_focus)
        self._search_entry.bind("<KeyRelease>", self._on_search_typed)
        ttk.Label(search_host, text="Ctrl+K", style="Kbd.TLabel").pack(
            side="left", padx=(10, 0)
        )
        attach_tooltip(
            self._search_entry,
            "Search screens, actions, hosts and alerts  (Ctrl+K)",
        )

        right = ttk.Frame(self.header, style="Header.TFrame")
        right.pack(side="right")

        ttk.Button(
            right, text="Sign out", style="Ghost.TButton", command=self._sign_out
        ).pack(side="right", padx=(8, 0))
        self._header_divider(right, side="right")

        # Theme control. An icon button rather than a labelled control: the
        # header is a fixed height and this must not add to it.
        self._theme_button = ttk.Button(
            right, text="", style="HeaderIcon.TButton", width=3,
            command=self._toggle_theme,
        )
        self._theme_button.pack(side="right", padx=(4, 4))
        self._paint_theme_button()

        # Reduced-motion control, beside the theme control for the same reason.
        self._motion_button = ttk.Button(
            right, text="", style="HeaderIcon.TButton", width=3,
            command=self._toggle_motion,
        )
        self._motion_button.pack(side="right", padx=(0, 2))
        self._paint_motion_button()

        bell_host = ttk.Frame(right, style="Header.TFrame")
        bell_host.pack(side="right", padx=(8, 4))
        self._notification_button = ttk.Button(
            bell_host, text="🔔", style="HeaderIcon.TButton", width=3,
            command=self._toggle_notifications,
        )
        self._notification_button.pack(side="left")
        self._notification_badge = CountBadge(
            bell_host, colour=PALETTE.critical, surface=PALETTE.surface_alt,
            fonts=self.fonts,
        )
        self._notification_badge.pack(side="left", padx=(2, 0))
        attach_tooltip(
            self._notification_button,
            "Notifications raised by real events  (Ctrl+N)",
        )

        # The signed-in account, shown as an identity block rather than a line
        # of text: who you are and what you may do are separate facts.
        user_host = ttk.Frame(right, style="Header.TFrame")
        user_host.pack(side="right", padx=(10, 14))
        self._user_label = ttk.Label(
            user_host, text=self.session.username, style="Header.TLabel",
            font=self.fonts.body_bold,
        )
        self._user_label.pack(anchor="e")
        ttk.Label(
            user_host, text=self.session.role, style="RoleBadge.TLabel"
        ).pack(anchor="e")

        self._header_divider(right, side="right")

        self._clock = ttk.Label(right, text="", style="Clock.TLabel")
        self._clock.pack(side="right", padx=(14, 14))

        # Subsystem state lives on the command bar, not on a row of its own.
        # The rail measures the width it is actually given and falls back from
        # "DB CONNECTED" to "DB" to a bare dot rather than letting the last
        # indicators fall off the end - a subsystem that is down has to stay
        # visible at 1280 wide, not only at 1920.
        self.status_strip = StatusRail(
            self.header, fonts=self.fonts, surface=PALETTE.surface_alt,
            on_click=lambda: self.navigate("health"),
        )
        self.status_strip.pack(side="left", padx=(18, 8), fill="x", expand=True)
        for key, label in (
            ("database", "DB"), ("nmap", "NMAP"), ("tshark", "TSHARK"),
            ("capture", "CAPTURE"), ("snort", "SNORT"),
        ):
            self._status_chips[key] = self.status_strip.add(
                key, label,
                tooltip_provider=lambda k=key: self._subsystem_detail(k),
            )

        body = ttk.Frame(self.root, style="TFrame")
        body.pack(fill="both", expand=True)

        self.sidebar = ttk.Frame(body, style="Sidebar.TFrame", width=SIDEBAR_WIDTH)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self._build_navigation()

        content_host = ttk.Frame(body, style="TFrame")
        content_host.pack(side="left", fill="both", expand=True)

        self.page_header = ttk.Frame(content_host, style="TFrame", padding=(20, 14, 20, 6))
        self.page_header.pack(fill="x")
        title_row = ttk.Frame(self.page_header, style="TFrame")
        title_row.pack(fill="x")
        self._page_icon = ttk.Label(
            title_row, text="", style="Title.TLabel", foreground=PALETTE.accent,
            font=(self.fonts.title[0], 20, "bold"), width=2, anchor="center",
        )
        self._page_icon.pack(side="left", padx=(0, 12), pady=(2, 0))
        titles = ttk.Frame(title_row, style="TFrame")
        titles.pack(side="left", fill="x", expand=True)
        self._page_title = ttk.Label(titles, text="", style="Title.TLabel")
        self._page_title.pack(anchor="w")
        self._page_subtitle = ttk.Label(titles, text="", style="Muted.TLabel")
        self._page_subtitle.pack(anchor="w", pady=(2, 0))

        self._page_actions = ttk.Frame(title_row, style="TFrame")
        self._page_actions.pack(side="right")
        refresh = ttk.Button(
            self._page_actions, text=f"{ICONS['refresh']}  Refresh",
            style="Ghost.TButton", command=self.refresh_current,
        )
        refresh.pack(side="right")
        attach_tooltip(refresh, "Reload this screen from the database  (F5)")

        self.content = ttk.Frame(content_host, style="TFrame", padding=(20, 4, 20, 10))
        self.content.pack(fill="both", expand=True)

        self.status_bar = ttk.Frame(self.root, style="Header.TFrame", padding=(16, 6))
        self.status_bar.pack(fill="x", side="bottom")
        self._busy_dot = ttk.Label(self.status_bar, text="", style="HeaderMuted.TLabel")
        self._busy_dot.pack(side="left", padx=(0, 8))
        self._status_message = ttk.Label(
            self.status_bar, text="Ready.", style="HeaderMuted.TLabel"
        )
        self._status_message.pack(side="left")
        self._uptime_label = ttk.Label(
            self.status_bar, text="", style="HeaderMuted.TLabel"
        )
        self._uptime_label.pack(side="right")

        # Overlays live above the whole body so they can cover any screen.
        self._overlay_host = body
        self._palette = CommandPalette(body, self._build_commands(), self.fonts)
        self._notification_panel = self._build_notification_panel(body)
        self._toasts = ToastManager(body, self.fonts)
        # The siren follows the visible popup: started when a detection popup
        # is shown, stopped the instant it is dismissed (CHECK, CLOSE, a
        # superseding escalation, or shutdown). Both hooks only signal the
        # audio worker, so neither holds the Tk thread.
        audio = getattr(self.context, "audio_alerts", None)
        if audio is not None:
            self._toasts.on_persistent(
                present=lambda spec: audio.begin_persistent(
                    spec.get("_token"), str(spec.get("level", "INFO")),
                    bool(spec.get("is_detection")),
                ),
                dismiss=lambda spec: audio.end_persistent(spec.get("_token")),
            )

    @staticmethod
    def _header_divider(parent: tk.Misc, side: str = "left") -> None:
        """A vertical rule separating one zone of the header from the next."""
        tk.Frame(parent, background=PALETTE.border_strong, width=1).pack(
            side=side, fill="y", pady=10
        )

    def _on_search_focus(self, _event: tk.Event) -> None:
        """Clear the placeholder the first time the field is used."""
        if self._search_placeholder_shown:
            self._search_entry.delete(0, "end")
            self._search_placeholder_shown = False

    def _on_search_typed(self, event: tk.Event) -> None:
        """Hand what was typed to the palette, which does the real searching.

        The header field is the way in; the palette is the interface. Passing
        the text across means the first keystrokes are not lost, which is what
        makes typing straight into the bar feel like it works.
        """
        if getattr(event, "keysym", "") in ("Escape",):
            self._reset_search_field()
            self.root.focus_set()
            return
        text = self._search_var.get().strip()
        if not text:
            return
        self.open_command_palette()
        self._palette.set_query(text)
        self._reset_search_field()

    def _reset_search_field(self) -> None:
        """Put the placeholder back once the palette has taken over."""
        try:
            self._search_entry.delete(0, "end")
            self._search_entry.insert(0, SEARCH_PLACEHOLDER)
        except tk.TclError:  # pragma: no cover - window closing
            return
        self._search_placeholder_shown = True

    def _build_navigation(self) -> None:
        """Create sidebar entries the session is permitted to open (§61)."""
        # The footer is packed first so it always keeps its space at the bottom,
        # however many navigation entries the session's role allows.
        self._sidebar_footer = ttk.Frame(
            self.sidebar, style="Sidebar.TFrame", padding=(16, 10)
        )
        self._sidebar_footer.pack(side="bottom", fill="x")
        ttk.Label(
            self._sidebar_footer, text=f"v{APP_VERSION}", style="CardDim.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            self._sidebar_footer, text="Authorised use only", style="CardDim.TLabel",
            wraplength=170, justify="left",
        ).pack(anchor="w")
        tk.Frame(self.sidebar, background=PALETTE.border, height=1).pack(
            side="bottom", fill="x", padx=12, pady=(8, 4)
        )

        ttk.Frame(self.sidebar, style="Sidebar.TFrame", height=8).pack(fill="x")

        # On a short window fourteen entries do not fit, and navigation that
        # has scrolled off the bottom is navigation the operator has lost. The
        # entries live in a scroller so every one of them stays reachable.
        self._nav_scroller = ScrollableFrame(
            self.sidebar, style="Sidebar.TFrame", background=PALETTE.surface
        )
        self._nav_scroller.pack(fill="both", expand=True)
        nav_host = self._nav_scroller.interior

        access = self.context.access
        labels = {key: label for key, label, _permission in NAVIGATION}
        permissions = {key: permission for key, _label, permission in NAVIGATION}

        for heading, keys in NAV_GROUPS:
            allowed = [
                key for key in keys
                if not permissions.get(key)
                or access is None
                or access.has(self.session, permissions[key])
            ]
            if not allowed:
                continue

            # Each group owns its heading and its entries, so collapsing the
            # sidebar only hides the headings - the order can never shuffle.
            group = ttk.Frame(nav_host, style="Sidebar.TFrame")
            group.pack(fill="x")
            # Letter-spaced, so a four-character heading still reads as a
            # section label rather than as another entry.
            group_label = ttk.Label(
                group, text=heading, style="NavGroup.TLabel",
            )
            group_label.pack(anchor="w", padx=16, pady=(12, 3))
            self._nav_group_headings.append(group_label)

            for key in allowed:
                self._add_nav_entry(group, key, labels[key])

    def _add_nav_entry(self, parent: tk.Misc, key: str, label: str) -> None:
        """One sidebar row: indicator, icon, label, and sometimes a badge."""
        row = ttk.Frame(parent, style="Sidebar.TFrame")
        row.pack(fill="x", padx=6, pady=0)

        # A filled background alone is easy to lose against a dark sidebar, so
        # the current page also carries an accent bar down its left edge.
        indicator = tk.Frame(row, background=PALETTE.surface, width=3)
        indicator.pack(side="left", fill="y", padx=(0, 4))
        indicator.pack_propagate(False)
        self._nav_indicators[key] = indicator

        index = len(self._nav_order) + 1
        shortcut = f"  (Ctrl+{index})" if index <= 9 else ""

        # The glyph sits in its own fixed-width cell so every label starts at
        # the same x, which is what makes the rail scannable top to bottom.
        glyph = ttk.Label(
            row, text=ICONS.get(key, "·"), style="NavGlyph.TLabel"
        )
        glyph.pack(side="left", fill="y")
        self._nav_glyphs[key] = glyph

        button = ttk.Button(
            row, text=label, style="Nav.TButton",
            command=lambda k=key: self.navigate(k),
        )
        button.pack(side="left", fill="x", expand=True)
        attach_tooltip(button, f"{label}{shortcut}")
        # The glyph is part of the entry, so clicking it navigates too.
        glyph.bind("<Button-1>", lambda _event, k=key: self.navigate(k))
        attach_tooltip(glyph, f"{label}{shortcut}")

        if key in BADGE_SOURCES:
            badge = CountBadge(
                row, colour=PALETTE.high, surface=PALETTE.surface, fonts=self.fonts
            )
            badge.pack(side="right", padx=(4, 6))
            self._nav_badges[key] = badge

        self._nav_buttons[key] = button
        self._nav_rows[key] = row
        self._nav_order.append(key)

    def _paint_nav_state(self) -> None:
        """Repaint every sidebar entry for the current page and layout."""
        labels = {key: label for key, label, _permission in NAVIGATION}
        for key, button in self._nav_buttons.items():
            active = key == self._current
            icon = ICONS.get(key, "·")
            glyph = self._nav_glyphs.get(key)
            if self._sidebar_collapsed:
                # Collapsed, the glyph cell is the entry, so the button empties.
                button.configure(
                    text="",
                    style="NavIconActive.TButton" if active else "NavIcon.TButton",
                )
            else:
                button.configure(
                    text=labels.get(key, key),
                    style="NavActive.TButton" if active else "Nav.TButton",
                )
            if glyph is not None:
                try:
                    glyph.configure(
                        text=icon,
                        style="NavGlyphActive.TLabel" if active else "NavGlyph.TLabel",
                    )
                except tk.TclError:  # pragma: no cover - window closing
                    pass
            row = self._nav_rows.get(key)
            if row is not None:
                try:
                    row.configure(
                        style="SidebarActive.TFrame" if active
                        else "Sidebar.TFrame"
                    )
                except tk.TclError:  # pragma: no cover - window closing
                    pass
            badge = self._nav_badges.get(key)
            if badge is not None:
                badge.set_surface(
                    PALETTE.surface_alt if active else PALETTE.surface
                )
            indicator = self._nav_indicators.get(key)
            if indicator is not None:
                try:
                    indicator.configure(
                        background=PALETTE.accent if active else PALETTE.surface
                    )
                except tk.TclError:  # pragma: no cover - window closing
                    pass

    # ------------------------------------------------------------------
    # Sidebar, overlays and shortcuts
    # ------------------------------------------------------------------
    def toggle_sidebar(self) -> None:
        """Collapse the sidebar to an icon rail, or expand it again."""
        self._sidebar_collapsed = not self._sidebar_collapsed
        self._paint_nav_state()
        self._animate_sidebar()

        for heading in self._nav_group_headings:
            if self._sidebar_collapsed:
                heading.pack_forget()
            else:
                # ``pack`` appends, so the heading lands after its own entries;
                # walk them back behind it to restore the group's order.
                heading.pack(anchor="w", padx=18, pady=(10, 3))
                previous: tk.Misc = heading
                for child in heading.master.winfo_children():
                    if child is heading:
                        continue
                    child.pack_configure(after=previous)
                    previous = child

        if self._sidebar_collapsed:
            self._sidebar_footer.pack_forget()
        else:
            self._sidebar_footer.pack(side="bottom", fill="x")

        self.state.set(KEY_SIDEBAR_COLLAPSED, self._sidebar_collapsed)

    def _animate_sidebar(self) -> None:
        """Slide the sidebar between its rail and full widths.

        Jumping straight to the new width makes the whole page appear to
        flinch. A handful of frames reads as the panel moving, which is what
        actually happened.
        """
        if self._sidebar_job is not None:
            try:
                self.root.after_cancel(self._sidebar_job)
            except (tk.TclError, ValueError):  # pragma: no cover - already fired
                pass
            self._sidebar_job = None
        target = SIDEBAR_RAIL_WIDTH if self._sidebar_collapsed else SIDEBAR_WIDTH
        try:
            current = int(self.sidebar.winfo_width()) or target
        except tk.TclError:  # pragma: no cover - window closing
            return
        self._step_sidebar(current, target, step=0)

    def _step_sidebar(self, start: int, target: int, step: int) -> None:
        """One frame of the sidebar slide."""
        if self._closing:
            return
        progress = min(1.0, (step + 1) / SIDEBAR_STEPS)
        eased = 1.0 - (1.0 - progress) ** 3
        width = int(start + (target - start) * eased)
        try:
            self.sidebar.configure(width=width)
        except tk.TclError:  # pragma: no cover - window closing
            return
        if progress < 1.0:
            self._sidebar_job = self.root.after(
                SIDEBAR_STEP_MS, lambda: self._step_sidebar(start, target, step + 1)
            )
        else:
            self._sidebar_job = None

    def _build_commands(self) -> list[Command]:
        """Every command the palette offers this session.

        Built from the permitted navigation entries plus the shell's own
        actions, so the palette can never reach a screen the sidebar hides.
        """
        labels = {key: label for key, label, _permission in NAVIGATION}
        commands: list[Command] = []
        for index, key in enumerate(self._nav_order, start=1):
            commands.append(
                Command(
                    key=key,
                    title=labels.get(key, key),
                    category="Go to",
                    shortcut=f"Ctrl+{index}" if index <= 9 else "",
                    run=lambda k=key: self.navigate(k),
                )
            )
        commands.extend(
            [
                Command(
                    "refresh", "Refresh this screen", "Action", shortcut="F5",
                    run=self.refresh_current,
                ),
                Command(
                    "sidebar", "Collapse or expand the sidebar", "Action",
                    shortcut="Ctrl+B", run=self.toggle_sidebar,
                ),
                Command(
                    "notifications", "Show notifications", "Action",
                    shortcut="Ctrl+N", run=self._toggle_notifications,
                ),
                Command(
                    "diagnostics", "Run system diagnostics", "Action",
                    run=lambda: self.navigate("health"),
                ),
                Command("signout", "Sign out", "Action", run=self._sign_out),
            ]
        )
        return commands

    def open_command_palette(self) -> None:
        """Show the command palette, refreshed for the current screen."""
        self._notification_panel.place_forget()
        self._palette.set_commands(self._build_commands())
        self._palette.set_search_provider(self._search_records)
        self._palette.open()

    def _search_records(self, query: str) -> None:
        """Look real hosts and alerts up for the palette (§61).

        The palette is the fastest way into a record an analyst already has a
        name for - an address, a reference, a signature. The lookup runs off the
        Tk thread because it is a database query, and every service call carries
        the session, so the palette can only surface records this role may read.
        """
        session = self.session
        if session is None:
            return

        def work() -> list[Command]:
            return self._record_commands(query)

        def deliver(commands: list[Command]) -> None:
            if not self._closing:
                self._palette.set_records(query, commands)

        def runner() -> None:
            try:
                found = work()
            except Exception:  # noqa: BLE001 - a search must not break the shell
                LOGGER.debug("Palette record search failed.", exc_info=True)
                found = []
            dispatch.post(lambda: deliver(found))

        threading.Thread(
            target=runner, name="palette-search", daemon=True
        ).start()

    def _record_commands(self, query: str) -> list[Command]:
        """Build palette entries from stored hosts and alerts."""
        session = self.session
        commands: list[Command] = []
        if session is None:
            return commands

        hosts = self.context.hosts
        if hosts is not None and self._may("host.view"):
            for host in self._safe_search(
                lambda: hosts.search(session, text=query, limit=RECORD_SEARCH_LIMIT)
            ):
                if host.id is None:
                    continue
                commands.append(
                    Command(
                        key=f"host-{host.id}",
                        title=host.display_name,
                        category="Host",
                        detail=f"{host.ip_address} · {host.risk_level}",
                        run=lambda identifier=host.id: self.navigate(
                            "hosts", focus_host=identifier
                        ),
                    )
                )

        snort = self.context.snort
        if snort is not None and self._may("alert.view"):
            for alert in self._safe_search(
                lambda: snort.search(session, text=query, limit=RECORD_SEARCH_LIMIT)
            ):
                commands.append(
                    Command(
                        key=f"alert-{alert.id}",
                        title=alert.message or alert.signature_text,
                        category="Alert",
                        detail=(
                            f"{alert.severity} · "
                            f"{alert.src_ip or '?'} -> {alert.dst_ip or '?'}"
                        ),
                        run=lambda value=alert.src_ip or alert.dst_ip: self.navigate(
                            "alerts", search=value
                        ),
                    )
                )
        return commands

    def _may(self, permission: str) -> bool:
        """True when this session holds a permission."""
        access = self.context.access
        return access is not None and access.has(self.session, permission)

    @staticmethod
    def _safe_search(action: Callable[[], list[Any]]) -> list[Any]:
        """Run one search, treating a failure as "no matches"."""
        try:
            return list(action() or [])
        except Exception:  # noqa: BLE001 - one subsystem must not break the rest
            LOGGER.debug("Palette search failed for one source.", exc_info=True)
            return []

    def _build_notification_panel(self, parent: tk.Misc) -> ttk.Frame:
        """Create the notification dropdown (hidden until requested)."""
        panel = ttk.Frame(parent, style="Overlay.TFrame", padding=(2, 2))
        header = ttk.Frame(panel, style="Overlay.TFrame", padding=(14, 10, 14, 6))
        header.pack(fill="x")
        ttk.Label(
            header, text="Notifications", style="OverlayHeading.TLabel"
        ).pack(side="left")
        ttk.Button(
            header, text=ICONS["close"], style="Icon.TButton", width=3,
            command=panel.place_forget,
        ).pack(side="right")
        self._notification_mark_read = ttk.Button(
            header, text="Mark all read", style="Tool.TButton",
            command=self._mark_notifications_read,
        )
        self._notification_mark_read.pack(side="right", padx=(0, 8))

        self._notification_body = ttk.Frame(
            panel, style="Overlay.TFrame", padding=(14, 0, 14, 12)
        )
        self._notification_body.pack(fill="both", expand=True)
        return panel

    def _bind_shortcuts(self) -> None:
        """Bind the console-wide keyboard shortcuts."""
        bindings: tuple[tuple[str, Callable[[tk.Event], Any]], ...] = (
            ("<Control-k>", lambda _event: self._shortcut(self.open_command_palette)),
            ("<Control-K>", lambda _event: self._shortcut(self.open_command_palette)),
            ("<Control-b>", lambda _event: self._shortcut(self.toggle_sidebar)),
            ("<Control-B>", lambda _event: self._shortcut(self.toggle_sidebar)),
            ("<Control-n>", lambda _event: self._shortcut(self._toggle_notifications)),
            ("<Control-N>", lambda _event: self._shortcut(self._toggle_notifications)),
            ("<F5>", lambda _event: self._shortcut(self.refresh_current)),
            ("<Control-r>", lambda _event: self._shortcut(self.refresh_current)),
            ("<Escape>", lambda _event: self._shortcut(self._close_overlays)),
        )
        for sequence, handler in bindings:
            self.root.bind_all(sequence, handler)

        for index in range(1, 10):
            self.root.bind_all(
                f"<Control-Key-{index}>",
                lambda _event, position=index: self._shortcut(
                    lambda: self._navigate_by_index(position)
                ),
            )

    @staticmethod
    def _shortcut(action: Callable[[], None]) -> str:
        """Run a shortcut action and stop the event propagating."""
        action()
        return "break"

    def _navigate_by_index(self, position: int) -> None:
        """Open the nth permitted navigation entry."""
        if 1 <= position <= len(self._nav_order):
            self.navigate(self._nav_order[position - 1])

    def _close_overlays(self) -> None:
        """Close the palette and the notification panel."""
        self._palette.close()
        self._notification_panel.place_forget()

    def refresh_current(self) -> None:
        """Reload the visible screen from the database."""
        screen = self._screens.get(self._current)
        if screen is None or not screen.is_alive:
            return
        refresh = getattr(screen, "refresh", None)
        if callable(refresh):
            try:
                refresh()
            except Exception:  # noqa: BLE001 - a refresh failure must not close the app
                LOGGER.exception("Screen '%s' failed to refresh.", self._current)
                self.set_status("This screen could not be refreshed. See the log.")
        else:
            self.set_status("This screen has nothing to reload.")

    def _subsystem_detail(self, key: str) -> str:
        """Tooltip text for a subsystem chip, from its latest probe."""
        health = self.context.health
        if health is None:
            return "Diagnostics are unavailable."
        status = health.statuses().get(key)
        if status is None:
            return "This subsystem has not been probed yet."
        detail = status.detail or "No further detail was reported."
        return f"{status.display_state} — {detail}\nClick to open System Health."

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------
    def navigate(self, screen_key: str, **kwargs: Any) -> None:
        """Switch to a screen, building it on first use."""
        if screen_key == self._current and not kwargs:
            return
        if screen_key in RETIRED_SCREENS:
            # An old link, a saved last-screen, or a bookmark to a screen that
            # no longer exists. It lands somewhere real rather than on a
            # broken page, and only the arguments that still mean something
            # there come with it: a search does, an incident id does not.
            screen_key = RETIRED_SCREENS[screen_key]
            kwargs = {k: v for k, v in kwargs.items() if k == "search"}
        if screen_key not in self._nav_buttons and screen_key not in (
            "host_detail",
        ):
            LOGGER.debug("Navigation to '%s' is not permitted.", screen_key)
            return

        previous = self._screens.get(self._current)
        if previous is not None:
            try:
                previous.on_hide()
            except Exception:  # noqa: BLE001
                LOGGER.exception("Screen '%s' failed on_hide.", self._current)
            previous.pack_forget()

        screen = self._get_screen(screen_key)
        if screen is None:
            return

        self._current = screen_key
        self._paint_nav_state()
        self._close_overlays()
        self._page_icon.configure(text=ICONS.get(screen_key, ""))
        self._page_title.configure(text=screen.title)
        self._page_subtitle.configure(text=screen.subtitle)
        if screen_key in self._nav_buttons:
            self.state.set(KEY_LAST_SCREEN, screen_key)
        screen.pack(fill="both", expand=True)

        for name, value in kwargs.items():
            setter = getattr(screen, f"set_{name}", None)
            if callable(setter):
                setter(value)

        try:
            screen.on_show()
        except Exception:  # noqa: BLE001
            LOGGER.exception("Screen '%s' failed on_show.", screen_key)

    # ------------------------------------------------------------------
    # Appearance
    # ------------------------------------------------------------------
    def _paint_theme_button(self) -> None:
        """Show the theme the button switches *to*, which is what it does."""
        going_to_light = current_theme() == "dark"
        self._theme_button.configure(text="☀" if going_to_light else "☾")
        tooltip = (
            "Switch to light theme" if going_to_light else "Switch to dark theme"
        )
        try:
            Tooltip(self._theme_button, tooltip)
        except Exception:  # noqa: BLE001 - a tooltip is never worth a crash
            pass

    def _toggle_theme(self) -> None:
        """Switch between the dark and light themes and remember the choice."""
        self.apply_appearance("light" if current_theme() == "dark" else "dark")

    def _paint_motion_button(self) -> None:
        """Show whether animation is on, and what the button will do."""
        from aethra_sec.ui.theme import motion_enabled

        on = motion_enabled()
        # A filled glyph while animation is on, an outline while it is reduced.
        self._motion_button.configure(text="◉" if on else "◯")
        tooltip = "Reduce motion (animations on)" if on else "Enable motion (reduced)"
        try:
            Tooltip(self._motion_button, tooltip)
        except Exception:  # noqa: BLE001
            pass

    def _toggle_motion(self) -> None:
        """Turn subtle animation on or off, and remember the choice."""
        from aethra_sec.ui.theme import motion_enabled, set_motion

        reduce_now = motion_enabled()  # currently on -> reduce it
        set_motion(not reduce_now)
        self.state.set(KEY_REDUCED_MOTION, reduce_now)
        self.state.save()
        self._paint_motion_button()
        # Repaint the status strip so any active dot starts/stops pulsing at
        # once rather than at the next probe.
        self._refresh_status_strip()
        self.set_status(
            "Reduced motion on." if reduce_now else "Animations on."
        )

    def apply_appearance(self, theme: str) -> None:
        """Adopt ``theme`` across the whole interface.

        There is one set of screens and one shell; only the tokens change. But
        ttk styles are configured from those tokens once, and every canvas
        widget - cards, chips, charts, the header rail - paints itself with the
        colours current when it was drawn. Restyling alone therefore leaves the
        chrome in the old theme.

        So the shell is rebuilt through the same methods that built it in the
        first place. There is no second code path and no duplicated layout: the
        switch re-runs :meth:`_build_layout`, which is what a fresh window runs.

        Screen state is deliberately not carried across. A rebuilt screen
        reloads from the repositories it always reads, so what comes back is
        the real current data rather than a snapshot preserved through a
        repaint.
        """
        applied = set_theme(theme)
        self.state.set(KEY_THEME, applied)
        # Written now rather than at shutdown: this is a deliberate preference,
        # and it has to survive the application not closing cleanly.
        self.state.save()

        remember_screen = self._current
        collapsed = self._sidebar_collapsed

        # Restyle ttk from the new tokens, then rebuild everything that painted
        # itself with the old ones.
        self.fonts = apply_theme(self.root)
        self._close_overlays()

        for screen in list(self._screens.values()):
            try:
                screen.destroy()
            except Exception:  # noqa: BLE001
                LOGGER.exception("A screen failed to close during a theme change.")
        self._screens.clear()
        self._current = ""

        for child in list(self.root.winfo_children()):
            try:
                child.destroy()
            except Exception:  # noqa: BLE001
                LOGGER.exception("Shell teardown failed during a theme change.")

        self.root.configure(background=PALETTE.background)
        self._sidebar_collapsed = False
        self._build_layout()
        if collapsed:
            self.toggle_sidebar()

        target = remember_screen if remember_screen in self._nav_buttons else ""
        self.navigate(target or self._initial_screen())
        self.set_status(f"{applied.capitalize()} theme applied.")

    def _get_screen(self, key: str) -> Screen | None:
        """Return a screen, constructing and building it on first use."""
        if key in self._screens:
            return self._screens[key]
        factory = self._screen_factories().get(key)
        if factory is None:
            LOGGER.warning("No screen registered for '%s'.", key)
            return None
        screen = factory(self.content, self)
        try:
            screen.build()
        except Exception:  # noqa: BLE001
            LOGGER.exception("Screen '%s' failed to build.", key)
        self._screens[key] = screen
        return screen

    @staticmethod
    def _screen_factories() -> dict[str, Callable[..., Screen]]:
        """Map navigation keys to screen classes (imported lazily)."""
        from aethra_sec.ui.screens.about import AboutScreen, HelpScreen
        from aethra_sec.ui.screens.alerts import AlertsScreen
        from aethra_sec.ui.screens.dashboard import DashboardScreen
        from aethra_sec.ui.screens.health import HealthScreen
        from aethra_sec.ui.screens.hosts import HostsScreen
        from aethra_sec.ui.screens.logs import LogsScreen
        from aethra_sec.ui.screens.attack_statistics import AttackStatisticsScreen
        from aethra_sec.ui.screens.mitigation import MitigationScreen
        from aethra_sec.ui.screens.reports import ReportsScreen
        from aethra_sec.ui.screens.settings import SettingsScreen
        from aethra_sec.ui.screens.traffic import TrafficScreen
        from aethra_sec.ui.screens.users import UsersScreen
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        return {
            "dashboard": DashboardScreen,
            "traffic": TrafficScreen,
            "vulnerabilities": VulnerabilitiesScreen,
            "hosts": HostsScreen,
            "alerts": AlertsScreen,
            "attack_statistics": AttackStatisticsScreen,
            "mitigation": MitigationScreen,
            "reports": ReportsScreen,
            "logs": LogsScreen,
            "users": UsersScreen,
            "health": HealthScreen,
            "settings": SettingsScreen,
            "help": HelpScreen,
            "about": AboutScreen,
        }

    # ------------------------------------------------------------------
    # Event pump (§75)
    # ------------------------------------------------------------------
    def _wake_for_notification(self, _event: Event) -> None:
        """Ask the Tk thread to drain notifications now (any thread)."""
        if self._notification_wake_pending or self._closing:
            return
        self._notification_wake_pending = True
        if not dispatch.post(self._drain_notifications):
            self._notification_wake_pending = False  # no dispatcher: tick drains

    def _drain_notifications(self) -> None:
        """Deliver queued notifications on the Tk thread, a bounded number."""
        self._notification_wake_pending = False
        if self._closing:
            return
        try:
            self.context.event_bus.dispatch(self._notification_subscription, 20)
        except Exception:  # noqa: BLE001 - the tick will retry
            LOGGER.exception("Prompt notification delivery failed.")

    def _on_notification_event(self, event: Event) -> None:
        """Announce one stored notification, on the Tk thread.

        Separated from :meth:`_on_event` so it waits in a buffer of its own.
        Sharing the main queue meant a flood of packet batches could evict a
        stored notification before the interface read it, and the popup for a
        real detection never happened.

        NOTIFICATION_STORED, not NOTIFICATION_RAISED: the latter is a request
        for a notification and only the backup service publishes one. The
        notification service converts requests, Snort alerts, detections,
        scans and subsystem failures into stored records, and this announces
        what was actually stored.
        """
        if event.type != EventType.NOTIFICATION_STORED:
            return
        payload = event.payload
        title = str(getattr(payload, "title", "Notification"))
        # The same rule the notification panel uses: the deduplication key the
        # service appends after an invisible marker is not part of the event
        # and is not shown.
        message = without_correlation_key(getattr(payload, "message", ""))
        notification_id = getattr(payload, "notification_id", None)

        # Sound is decided separately from the popup and on its own worker, so
        # this returns at once and a silent or missing audio device cannot
        # stop the popup below from being raised.
        audio = getattr(self.context, "audio_alerts", None)
        is_detection_sound = str(getattr(payload, "category", "")) == "alert"
        if audio is not None and not is_detection_sound:
            # Non-detection notifications keep their single system sound. A
            # detection's sound is the persistent siren, started by the popup
            # present hook below, so it is not also queued here (which would
            # double the first sound).
            queued = audio.notify(payload)
            LOGGER.info(
                "[NOTIFY] Sound %s: notification_id=%s ref=%s:%s",
                "queued" if queued else "not played",
                notification_id,
                getattr(payload, "reference_type", "") or "-",
                getattr(payload, "reference_id", None) or "-",
            )

        self.set_status(f"{title}: {message}")
        # Centred and persistent, with CLOSE and CHECK. A detection that timed
        # out of the corner of the screen while the operator was away is a
        # detection nobody saw, so this one waits to be acknowledged instead
        # of expiring. Neither button touches the alert record or its review
        # status.
        # The detection's own severity, carried on the event. A failure in
        # building the popup is caught and logged by the event bus, which
        # isolates every subscriber, so the next notification still arrives.
        severity = str(getattr(payload, "severity", "") or "")
        is_detection = str(getattr(payload, "category", "")) == "alert"
        shown = self._toasts.show_persistent(
            title, message,
            level=str(getattr(payload, "level", "INFO")).upper(),
            reference=_notification_reference(payload),
            on_check=lambda: self.navigate("alerts"),
            severity=severity,
            is_detection=is_detection,
        )
        LOGGER.info(
            "[NOTIFY] Popup %s: notification_id=%s severity=%s",
            "displayed" if shown else "queued behind an open popup",
            notification_id, severity or ("UNKNOWN" if is_detection else "-"),
        )
        self.refresh_notifications()

    def _on_event(self, event: Event) -> None:
        """Handle one event on the Tk thread."""
        if event.type in (
            EventType.SERVICE_STATUS_CHANGED,
            EventType.DATABASE_STATUS_CHANGED,
            EventType.SNORT_STATUS_CHANGED,
            EventType.CAPTURE_STARTED,
            EventType.CAPTURE_STOPPED,
        ):
            self._refresh_status_strip()

        # NOTIFICATION_STORED, not NOTIFICATION_RAISED. The latter is a
        # *request* for a notification - only the backup service publishes it -
        # and the notification service converts it, along with Snort alerts,
        # scans and subsystem failures, into a stored record. Sounding on the
        # request meant a real IDS alert never sounded at all, because nothing
        # ever requested one for it: the record was written and never announced.
        if event.type == EventType.NMAP_SCAN_COMPLETED:
            scan = getattr(event.payload, "scan", None)
            if scan is not None:
                self._toasts.show(
                    "Assessment complete",
                    f"{scan.target} · {scan.summary_line}",
                    level="SUCCESS",
                    on_click=lambda: self.navigate("vulnerabilities"),
                )
        elif event.type == EventType.NMAP_SCAN_FAILED:
            payload = event.payload
            self._toasts.show(
                "Assessment failed",
                str(getattr(payload, "message", "") or "See the Logs screen."),
                level="WARNING",
                on_click=lambda: self.navigate("vulnerabilities"),
            )
        elif event.type == EventType.CAPTURE_ERROR:
            payload = event.payload
            self._toasts.show(
                "Packet capture error",
                str(getattr(payload, "message", "") or "Capture stopped."),
                level="WARNING",
                on_click=lambda: self.navigate("traffic"),
            )
        elif event.type == EventType.SYSTEM_ERROR:
            payload = event.payload
            component = str(getattr(payload, "component", "system"))
            message = str(getattr(payload, "message", ""))
            self.set_status(f"{component}: {message}")
            self._toasts.show(
                f"{component} error", message, level="CRITICAL",
                on_click=lambda: self.navigate("health"),
            )

        screen = self._screens.get(self._current)
        if screen is not None and screen.is_alive:
            try:
                screen.handle_event(event)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Screen '%s' failed handling %s", self._current, event.type)

    def _schedule_tick(self) -> None:
        """Schedule the next UI tick."""
        if self._closing:
            return
        interval = self.context.settings.ui_refresh_ms
        settings_service = self.context.settings_service
        if settings_service is not None:
            interval = settings_service.get_int("ui.refresh_interval_ms", interval)
        self._tick_job = self.root.after(max(250, interval), self._tick)

    def _tick(self) -> None:
        """Drain the event bus and refresh time-based chrome."""
        if self._closing:
            return
        try:
            # Budgeted, because this runs on the Tk thread. During a real
            # Nmap port scan the capture pipeline raised events faster than
            # they could be handled and this call alone held the main loop for
            # up to 2,007 ms, which is the interface not answering the OS.
            # Events not reached stay queued and are handled on the next tick;
            # none is discarded here.
            self.context.event_bus.dispatch_all(
                limit_per_subscription=400,
                time_budget_ms=self.EVENT_BUDGET_MS,
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("Event dispatch failed.")

        now = utcnow()
        self._clock.configure(text=format_local(now, "%d %b %Y  %H:%M:%S"))
        if self.context.health is not None:
            self._uptime_label.configure(
                text=f"Uptime {self.context.health.uptime_text()}"
            )
        # Repaint the chips every tick as well as on transitions, so the strip
        # is correct even before the first status change is published.
        self._refresh_status_strip()
        self._refresh_nav_badges()

        screen = self._screens.get(self._current)
        if screen is not None and screen.is_alive:
            try:
                screen.on_tick()
            except Exception:  # noqa: BLE001
                LOGGER.exception("Screen '%s' tick failed.", self._current)

        self._schedule_tick()

    def _refresh_status_strip(self) -> None:
        """Repaint the header subsystem chips from the latest probe results."""
        health = self.context.health
        if health is None:
            return
        statuses = health.statuses()
        for key in self._status_chips:
            status = statuses.get(key)
            if status is None:
                continue
            self.status_strip.update_state(key, status.display_state)

    #: Least time between sidebar badge reads. The counts change at detection
    #: speed, not per tick, so a few seconds keeps them live without a
    #: DB query on the Tk thread every tick.
    BADGE_REFRESH_SECONDS = 4.0

    def _refresh_nav_badges(self) -> None:
        """Paint the sidebar counters from cache; refresh the cache off-thread.

        The paint is pure UI. The counts are read on a worker thread and cached,
        because reading them here would put three synchronous DB round-trips on
        the Tk thread every tick - the stall an operator feels as lag. An empty
        system shows no badges at all: a badge means "there is something here",
        and inventing one would misrepresent the state (§1).
        """
        colours = {
            "alerts": PALETTE.high,
            "users": PALETTE.medium,
        }
        for key, colour in colours.items():
            if key in self._nav_badges and key in self._badge_counts:
                self._nav_badges[key].set_count(self._badge_counts[key], colour=colour)
        self._maybe_refresh_badge_counts()

    def _maybe_refresh_badge_counts(self) -> None:
        """Read the badge counts on a worker thread, at most every few seconds."""
        if self._badge_job_running or self._closing:
            return
        now = time.monotonic()
        if now - self._badge_refreshed_at < self.BADGE_REFRESH_SECONDS:
            return
        self._badge_refreshed_at = now
        session = self.session
        snort = self.context.snort
        recovery = self.context.recovery
        may_approve = session is not None and session.has(
            Permission.USER_RESET_APPROVE
        )

        def work() -> dict[str, int]:
            counts: dict[str, int] = {}
            if snort is not None:
                try:
                    # AETHRA-SEC detections awaiting review: the Alerts
                    # screen lists those only, so its badge counts those only.
                    counts["alerts"] = snort.unreviewed_detection_count(session)
                except Exception:  # noqa: BLE001
                    pass
            # Only ask when the session may: an unauthorised read would be
            # refused and audited every refresh - a flood of denial records.
            if recovery is not None and may_approve:
                try:
                    counts["users"] = recovery.pending_count(session)
                except Exception:  # noqa: BLE001
                    pass
            return counts

        def runner() -> None:
            try:
                counts = work()
            except Exception:  # noqa: BLE001 - a badge read must not crash a worker
                counts = {}
            def deliver() -> None:
                self._badge_job_running = False
                if not self._closing:
                    self._badge_counts.update(counts)
            dispatch.post(deliver)

        self._badge_job_running = True
        threading.Thread(target=runner, name="nav-badges", daemon=True).start()

    def _set_busy(self, busy: bool) -> None:
        """Show or clear the activity marker in the status bar."""
        self._busy_jobs = max(0, self._busy_jobs + (1 if busy else -1))
        try:
            self._busy_dot.configure(
                text="⏳" if self._busy_jobs else "",
                foreground=PALETTE.accent,
            )
        except tk.TclError:  # pragma: no cover - window is closing
            pass

    # ------------------------------------------------------------------
    # Shell services used by screens
    # ------------------------------------------------------------------
    def set_status(self, message: str) -> None:
        """Show a message in the status bar (§108).

        Silently ignored once the window is closing, so a worker result that
        arrives during shutdown cannot raise.
        """
        if self._closing:
            return
        try:
            self._status_message.configure(text=message)
        except tk.TclError:
            LOGGER.debug("Status bar unavailable: %s", message)

    def refresh_notifications(self) -> None:
        """Update the unread badge on the bell, counting off the Tk thread.

        The count is a database query, and this is called from ``_on_event``
        for every stored notification. Running it inline put a query on the Tk
        thread on the busiest path there is: during a real Nmap port scan the
        capture pipeline raises notifications in bursts, and each one blocked
        the main loop for the duration of a round trip.

        Single-flight, because a burst would otherwise start a thread per
        notification to ask the same question. A refresh that arrives while one
        is in flight sets a flag and the worker asks once more on the way out,
        so the badge still ends up showing the latest count.
        """
        service = self.context.notifications
        if service is None:
            return
        if self._notification_count_running:
            self._notification_count_again = True
            return

        session = self.session

        def runner() -> None:
            while True:
                try:
                    count = service.unread_count(session)
                except Exception:  # noqa: BLE001 - the bell must not break the shell
                    count = None

                def deliver(value: int | None = count) -> None:
                    self._notification_count_running = False
                    if self._closing or value is None:
                        return
                    self._notification_badge.set_count(value)
                    if self._notification_panel.winfo_ismapped():
                        self._populate_notifications()

                if not self._notification_count_again:
                    dispatch.post(deliver)
                    return
                # Another refresh was requested while this one was out; ask
                # again rather than deliver a count already known to be stale.
                self._notification_count_again = False

        self._notification_count_running = True
        self._notification_count_again = False
        threading.Thread(
            target=runner, name="notification-count", daemon=True
        ).start()

    def _toggle_notifications(self, *, force_open: bool = False) -> None:
        """Show or hide the notification panel."""
        if self._notification_panel.winfo_ismapped() and not force_open:
            self._notification_panel.place_forget()
            return
        self._palette.close()
        self._populate_notifications()
        self._notification_panel.place(relx=1.0, rely=0.0, anchor="ne", x=-14, y=8,
                                       width=430)
        self._notification_panel.lift()

    def _populate_notifications(self) -> None:
        """Fill the panel with stored notifications (never invented ones)."""
        for child in self._notification_body.winfo_children():
            child.destroy()

        service = self.context.notifications
        if service is None:
            ttk.Label(
                self._notification_body,
                text="Notifications are unavailable: the service did not start.",
                style="OverlayMuted.TLabel", wraplength=380, justify="left",
            ).pack(anchor="w")
            return

        try:
            items = service.recent(self.session, limit=25)
        except Exception:  # noqa: BLE001
            items = []

        if not items:
            ttk.Label(
                self._notification_body, text="No notifications",
                style="OverlayMuted.TLabel",
            ).pack(anchor="w")
            ttk.Label(
                self._notification_body,
                text=(
                    "AETHRA-SEC raises a notification only for a real event: a "
                    "new alert, a completed or failed assessment, or a "
                    "subsystem failure. There have been none."
                ),
                style="OverlayDim.TLabel", wraplength=380, justify="left",
            ).pack(anchor="w", pady=(6, 0))
            self._notification_mark_read.state(["disabled"])
            return

        self._notification_mark_read.state(["!disabled"])
        for notification in items:
            row = ttk.Frame(self._notification_body, style="Overlay.TFrame")
            row.pack(fill="x", pady=(0, 8))
            colour = {
                "CRITICAL": PALETTE.critical, "WARNING": PALETTE.medium,
                "SUCCESS": PALETTE.ok,
            }.get(str(notification.level).upper(), PALETTE.info)
            tk.Frame(row, background=colour, width=3).pack(side="left", fill="y")
            body = ttk.Frame(row, style="Overlay.TFrame", padding=(8, 0, 0, 0))
            body.pack(side="left", fill="x", expand=True)
            heading = ttk.Label(
                body, text=notification.title, style="Overlay.TLabel",
                font=self.fonts.small_bold,
            )
            heading.configure(foreground=colour if not notification.is_read else PALETTE.text_muted)
            heading.pack(anchor="w")
            ttk.Label(
                body, text=notification.display_message,
                style="OverlayMuted.TLabel",
                wraplength=360, justify="left",
            ).pack(anchor="w")
            ttk.Label(
                body, text=format_local(notification.created_at),
                style="OverlayDim.TLabel",
            ).pack(anchor="w")

    def _mark_notifications_read(self) -> None:
        """Mark every notification read and refresh the badge."""
        service = self.context.notifications
        if service is None:
            return
        service.mark_all_read(self.session)
        self.refresh_notifications()
        self._populate_notifications()

    def toast(
        self,
        title: str,
        message: str = "",
        *,
        level: str = "INFO",
        on_click: Callable[[], None] | None = None,
    ) -> None:
        """Raise a toast from a screen (used for completed operator actions)."""
        if not self._closing:
            self._toasts.show(title, message, level=level, on_click=on_click)

    def severity_colour_for(self, severity: Severity) -> str:
        """Expose the palette to screens that draw their own chips."""
        from aethra_sec.ui.theme import severity_colour

        return severity_colour(severity)

    # ------------------------------------------------------------------
    # Sign out and shutdown
    # ------------------------------------------------------------------
    def _sign_out(self) -> None:
        """Sign out and return to the login window without leaving the app.

        The database pool, the scheduler and the other services stay up, so
        switching accounts is instant and never drops back to the shell. Only
        the console's own widgets and the current session are torn down.
        """
        if self._closing:
            return
        if not confirm(
            self.root, "Sign out", "Sign out of AETHRA-SEC?",
            detail=(
                "You will return to the sign-in screen so another operator can "
                "sign in. Live packet capture is stopped; data already written "
                "to the database is kept."
            ),
            confirm_label="Sign out",
        ):
            return

        self.outcome = "sign out"
        self._teardown(reason="sign out")
        try:
            self.context.sign_out("sign out")
        except Exception:  # noqa: BLE001
            LOGGER.exception("Sign-out failed.")
        self._destroy_widgets()
        # Leave the mainloop so run_console() returns and the desktop loop shows
        # the login window again. The root itself stays alive and is reused.
        try:
            self.root.quit()
        except tk.TclError:  # pragma: no cover - root already gone
            pass

    def _remember_window_state(self) -> None:
        """Store the window geometry and sidebar choice for the next run."""
        try:
            self.state.set(KEY_GEOMETRY, self.root.winfo_geometry())
        except tk.TclError:  # pragma: no cover - window already destroyed
            pass
        self.state.set(KEY_SIDEBAR_COLLAPSED, self._sidebar_collapsed)
        self.state.save()

    def _teardown(self, reason: str) -> None:
        """Stop this console's activity, shared by sign-out and quit.

        Stops live capture, remembers the window state, unsubscribes from the
        event bus and cancels the refresh tick. It does not stop the services
        or the dispatcher - both may outlive one sign-in.
        """
        self._closing = True
        self._remember_window_state()
        cancel_watchdog = getattr(self, "_cancel_watchdog", None)
        if cancel_watchdog is not None:
            cancel_watchdog()
            self._cancel_watchdog = None

        capture = self.context.capture
        if capture is not None and capture.is_running:
            try:
                capture.stop_for_shutdown(reason=reason)
            except Exception:  # noqa: BLE001 - teardown must not raise
                LOGGER.exception("Stopping capture during %s failed.", reason)

        if self._tick_job is not None:
            try:
                self.root.after_cancel(self._tick_job)
            except tk.TclError:
                pass
            self._tick_job = None
        try:
            self.context.event_bus.unsubscribe(self._subscription)
            self.context.event_bus.unsubscribe(self._notification_wake)
            self.context.event_bus.unsubscribe(
                self._notification_subscription
            )
        except Exception:  # noqa: BLE001
            pass

    def _destroy_widgets(self) -> None:
        """Destroy the console's widgets, leaving the root alive for reuse."""
        for child in list(self.root.winfo_children()):
            try:
                child.destroy()
            except tk.TclError:  # pragma: no cover - already gone
                pass

    def close(self, reason: str = "window closed") -> None:
        """Quit the application: stop every subsystem and destroy the root (§74)."""
        if self._closing:
            return
        capture = self.context.capture
        if capture is not None and capture.is_running:
            if not confirm(
                self.root, "Stop capture and exit?",
                "Packet capture is running.",
                detail=(
                    "Closing AETHRA-SEC stops live capture. Captured data "
                    "already written to the database is retained."
                ),
                confirm_label="Stop and exit", danger=True,
            ):
                return

        self.outcome = "quit"
        self._teardown(reason=reason)
        # Stop the worker-to-Tk bridge before the widgets go away, so a late
        # result cannot be delivered into a destroyed window.
        dispatch.shutdown()
        try:
            self.context.sign_out(reason)
        except Exception:  # noqa: BLE001
            LOGGER.exception("Sign-out failed during shutdown.")
        try:
            self.context.shutdown(reason)
        finally:
            try:
                self.root.quit()
            except tk.TclError:
                pass
            try:
                self.root.destroy()
            except tk.TclError:
                pass


def run_console(
    root: tk.Tk, context: ApplicationContext, fonts: Fonts, session: Session
) -> str:
    """Show the console and run the Tk main loop until it exits.

    Returns:
        ``"sign out"`` when the operator signed out (the caller should show the
        login window again), or ``"quit"`` when the application should exit.
    """
    window = MainWindow(root, context, fonts, session)
    window.refresh_notifications()
    window._refresh_status_strip()  # noqa: SLF001 - initial paint
    # Off unless AETHRA_FLOOD_PROBE is set, and it observes only: no capture
    # setting, queue or counter is touched by it. See diagnostics/flood_probe.
    probe = flood_probe.install(root, context, window)
    try:
        root.mainloop()
    finally:
        if probe is not None:
            probe.stop()
    return window.outcome
