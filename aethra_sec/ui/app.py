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
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Any, Callable

from aethra_sec.core.application import ApplicationContext
from aethra_sec.core.events import Event, EventType
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.models.enums import Severity
from aethra_sec.ui import dispatch
from aethra_sec.ui.base import Screen
from aethra_sec.ui.state import (
    KEY_GEOMETRY,
    KEY_LAST_SCREEN,
    KEY_SIDEBAR_COLLAPSED,
    UiState,
)
from aethra_sec.ui.theme import ICONS, PALETTE, Fonts
from aethra_sec.ui.widgets.cards import ScrollableFrame
from aethra_sec.ui.widgets.chips import CountBadge, StatusChip
from aethra_sec.ui.widgets.dialogs import confirm
from aethra_sec.ui.widgets.palette import Command, CommandPalette
from aethra_sec.ui.widgets.toast import ToastManager
from aethra_sec.ui.widgets.tooltip import attach_tooltip
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
    ("incidents", "Incidents", Permission.INCIDENT_VIEW),
    ("mitigation", "Mitigation", Permission.MITIGATION_VIEW),
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
    ("SECURITY", ("incidents", "alerts", "mitigation")),
    ("ASSETS", ("hosts", "vulnerabilities")),
    ("REPORTING", ("reports", "logs")),
    ("ADMINISTRATION", ("users", "health", "settings")),
    ("HELP", ("help", "about")),
)

#: Screens that carry a live count badge in the sidebar, and where it comes
#: from. Each callable returns a real stored count - never an estimate.
BADGE_SOURCES: tuple[str, ...] = ("alerts", "incidents", "users")

#: Records of each kind the command palette offers for one query. Enough to
#: recognise the one you meant, few enough not to bury the screen commands.
RECORD_SEARCH_LIMIT = 6

#: Sidebar widths, and the frames the slide between them takes.
SIDEBAR_WIDTH = 264
SIDEBAR_RAIL_WIDTH = 76
SIDEBAR_STEPS = 7
SIDEBAR_STEP_MS = 12

#: Resting text in the header's command bar.
SEARCH_PLACEHOLDER = "Search screens, hosts, incidents, alerts…"

#: Events every screen may want, drained on the UI tick.
_UI_EVENTS: tuple[str, ...] = (
    EventType.CAPTURE_STARTED, EventType.CAPTURE_STOPPED, EventType.CAPTURE_ERROR,
    EventType.PACKET_BATCH_PROCESSED, EventType.TRAFFIC_STATS_UPDATED,
    EventType.TRAFFIC_ANOMALY_DETECTED, EventType.SNORT_ALERT_RECEIVED,
    EventType.SNORT_STATUS_CHANGED, EventType.NMAP_SCAN_STARTED,
    EventType.NMAP_SCAN_COMPLETED, EventType.NMAP_SCAN_FAILED,
    EventType.INCIDENT_CREATED, EventType.INCIDENT_UPDATED,
    EventType.MITIGATION_GENERATED, EventType.DATABASE_STATUS_CHANGED,
    EventType.SERVICE_STATUS_CHANGED, EventType.NOTIFICATION_RAISED,
    EventType.REPORT_GENERATED, EventType.SYSTEM_ERROR,
)


class MainWindow:
    """The application console."""

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
        #: How this console ended: "sign out" returns to the login window,
        #: "quit" exits the application. run_console() returns this.
        self.outcome = "quit"

        # Guarantee the worker-to-Tk bridge before any screen starts work: a
        # console built directly (a test, embedding code) would otherwise have
        # workers whose results could not be delivered.
        dispatch.ensure(root)

        self.state = UiState(Path(context.settings.log_dir))

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
        if self.state.get_bool(KEY_SIDEBAR_COLLAPSED):
            self.toggle_sidebar()
        self.navigate(self._initial_screen())
        self._schedule_tick()
        self.root.deiconify()

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
            "Search screens, actions, hosts, incidents and alerts  (Ctrl+K)",
        )

        right = ttk.Frame(self.header, style="Header.TFrame")
        right.pack(side="right")

        ttk.Button(
            right, text="Sign out", style="Ghost.TButton", command=self._sign_out
        ).pack(side="right", padx=(8, 0))
        self._header_divider(right, side="right")

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

        # The subsystem chips get their own row so a long status string can
        # never squeeze the clock or the sign-out control off the header.
        self.status_strip = ttk.Frame(
            self.root, style="Header.TFrame", padding=(16, 0, 16, 9)
        )
        self.status_strip.pack(fill="x", side="top")
        ttk.Label(
            self.status_strip, text="SUBSYSTEMS", style="HeaderMuted.TLabel"
        ).pack(side="left", padx=(0, 12))
        for key, label in (
            ("database", "DATABASE"), ("nmap", "NMAP"), ("tshark", "TSHARK"),
            ("capture", "CAPTURE"), ("snort", "SNORT"),
        ):
            chip = StatusChip(
                self.status_strip, label, fonts=self.fonts,
                surface=PALETTE.surface_alt,
                on_click=lambda: self.navigate("health"),
                tooltip_provider=lambda k=key: self._subsystem_detail(k),
            )
            chip.pack(side="left", padx=(0, 8))
            self._status_chips[key] = chip

        body = ttk.Frame(self.root, style="TFrame")
        body.pack(fill="both", expand=True)

        self.sidebar = ttk.Frame(body, style="Sidebar.TFrame", width=SIDEBAR_WIDTH)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self._build_navigation()

        content_host = ttk.Frame(body, style="TFrame")
        content_host.pack(side="left", fill="both", expand=True)

        self.page_header = ttk.Frame(content_host, style="TFrame", padding=(26, 20, 26, 10))
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

        self.content = ttk.Frame(content_host, style="TFrame", padding=(26, 8, 26, 18))
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
                group, text=" ".join(heading), style="NavGroup.TLabel",
                font=self.fonts.small_bold,
            )
            group_label.pack(anchor="w", padx=20, pady=(14, 5))
            self._nav_group_headings.append(group_label)

            for key in allowed:
                self._add_nav_entry(group, key, labels[key])

    def _add_nav_entry(self, parent: tk.Misc, key: str, label: str) -> None:
        """One sidebar row: indicator, icon, label, and sometimes a badge."""
        row = ttk.Frame(parent, style="Sidebar.TFrame")
        row.pack(fill="x", padx=8, pady=2)

        # A filled background alone is easy to lose against a dark sidebar, so
        # the current page also carries an accent bar down its left edge.
        indicator = tk.Frame(row, background=PALETTE.surface, width=3)
        indicator.pack(side="left", fill="y", padx=(0, 5))
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
        """Look real hosts, incidents and alerts up for the palette (§61).

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
        """Build palette entries from stored hosts, incidents and alerts."""
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

        correlation = self.context.correlation
        if correlation is not None and self._may("incident.view"):
            for incident in self._safe_search(
                lambda: correlation.search(
                    session, text=query, limit=RECORD_SEARCH_LIMIT
                )
            ):
                if incident.id is None:
                    continue
                commands.append(
                    Command(
                        key=f"incident-{incident.id}",
                        title=f"{incident.reference}  {incident.title}",
                        category="Incident",
                        detail=f"{incident.severity} · {incident.status}",
                        run=lambda identifier=incident.id: self.navigate(
                            "incidents", focus_incident=identifier
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
        if screen_key not in self._nav_buttons and screen_key not in (
            "host_detail", "incident_detail"
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
        from aethra_sec.ui.screens.incidents import IncidentsScreen
        from aethra_sec.ui.screens.logs import LogsScreen
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
            "incidents": IncidentsScreen,
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

        if event.type == EventType.NOTIFICATION_RAISED:
            payload = event.payload
            title = str(getattr(payload, "title", "Notification"))
            message = str(getattr(payload, "message", ""))
            self.set_status(f"{title}: {message}")
            self._toasts.show(
                title, message,
                level=str(getattr(payload, "level", "INFO")).upper(),
                on_click=lambda: self._toggle_notifications(force_open=True),
            )
            self.refresh_notifications()
        elif event.type == EventType.INCIDENT_CREATED:
            incident = getattr(event.payload, "incident", None)
            if incident is not None:
                self.set_status(
                    f"Incident {incident.reference} created "
                    f"[{incident.severity}] {incident.title}"
                )
                self._toasts.show(
                    f"Incident {incident.reference} · {incident.severity}",
                    f"{incident.title}\nEvidence: {incident.source_label}",
                    level=(
                        "CRITICAL"
                        if str(incident.severity) in ("CRITICAL", "HIGH")
                        else "WARNING"
                    ),
                    on_click=lambda: self.navigate("incidents"),
                )
                self.refresh_notifications()
        elif event.type == EventType.NMAP_SCAN_COMPLETED:
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
            self.context.event_bus.dispatch_all(limit_per_subscription=400)
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
        for key, chip in self._status_chips.items():
            status = statuses.get(key)
            if status is None:
                continue
            chip.update_state(status.display_state)

    def refresh_nav_badges(self) -> None:
        """Public entry point for a screen to force an immediate badge repaint.

        The tick loop calls this on its own cadence already; screens use this
        after a bulk action (e.g. "mark all read") so the sidebar updates the
        moment the action completes rather than on the next tick.
        """
        self._refresh_nav_badges()

    def _refresh_nav_badges(self) -> None:
        """Update the sidebar counters from stored records only.

        An empty system shows no badges at all, because a badge means "there is
        something here" and inventing one would misrepresent the state (§1).
        """
        snort = self.context.snort
        if snort is not None and "alerts" in self._nav_badges:
            try:
                count = snort.unresolved_alert_count(self.session)
            except Exception:  # noqa: BLE001 - a badge must not break the shell
                count = 0
            self._nav_badges["alerts"].set_count(count, colour=PALETTE.high)

        correlation = self.context.correlation
        if correlation is not None and "incidents" in self._nav_badges:
            try:
                count = correlation.open_incident_count(self.session)
            except Exception:  # noqa: BLE001
                count = 0
            self._nav_badges["incidents"].set_count(count, colour=PALETTE.critical)

        recovery = self.context.recovery
        session = self.session
        if (
            recovery is not None
            and session is not None
            and "users" in self._nav_badges
            and session.has(Permission.USER_RESET_APPROVE)
        ):
            # Only ask when the session may: an unauthorised read would be
            # refused and audited on every tick, which is not a badge, it is a
            # flood of denial records.
            try:
                count = recovery.pending_count(session)
            except Exception:  # noqa: BLE001
                count = 0
            self._nav_badges["users"].set_count(count, colour=PALETTE.medium)

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
        """Update the unread badge on the bell."""
        service = self.context.notifications
        if service is None:
            return
        try:
            count = service.unread_count(self.session)
        except Exception:  # noqa: BLE001 - the bell must not break the shell
            return
        self._notification_badge.set_count(count)
        if self._notification_panel.winfo_ismapped():
            self._populate_notifications()

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
                    "new alert, a completed or failed assessment, a correlated "
                    "incident or a subsystem failure. There have been none."
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
                body, text=notification.message, style="OverlayMuted.TLabel",
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

        capture = self.context.capture
        if capture is not None and capture.is_running:
            try:
                capture.stop(reason=reason)
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
    root.mainloop()
    return window.outcome
