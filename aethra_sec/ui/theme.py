"""Dark security-operations theme for Tkinter/ttk (§60).

Design decision: AETHRA-SEC uses plain Tkinter with ttk rather than a
third-party widget toolkit. ``ttk.Treeview`` is required regardless for the
live packet table and every other record grid, and the conservative choice
keeps the desktop dependency surface to the Python standard library (§127).
The SOC appearance comes from an explicit ttk theme built here plus custom
Canvas drawing for charts.

Colour semantics follow the specification: red for critical, orange for high,
yellow for medium, green for healthy, blue for informational.
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from tkinter import font as tkfont
from tkinter import ttk

from aethra_sec.models.enums import (
    CheckResult,
    IncidentStatus,
    RiskLevel,
    ServiceState,
    Severity,
)


@dataclass(frozen=True)
class Palette:
    """The application colour palette.

    The surfaces form a deliberate ladder - page, panel, panel header, raised -
    and every panel is separated from the page by a **drawn border** rather
    than by a barely-different fill. On a console that is read for hours in a
    dim room, an edge you can see is what makes a layout scannable; a two-shade
    difference between a card and its background is not.
    """

    # Surfaces, in ascending elevation.
    #
    # A neutral graphite-slate base rather than a saturated navy: the old
    # #0A0F1E ladder pushed blue into every surface, which is what made the
    # console read as a themed hobby build rather than an enterprise tool.
    # Desaturating the base and leaning on it more subtly - separating panels
    # by a soft, low-contrast edge instead of a bright bordercolor - is what a
    # professional SOC console (Datadog, Grafana, CrowdStrike) actually does;
    # the accent and severity colours carry all the remaining saturation.
    background: str = "#0C0F14"
    surface: str = "#141821"
    surface_alt: str = "#181D27"
    surface_raised: str = "#1E2430"
    surface_hover: str = "#252C3A"
    surface_sunken: str = "#080A0E"
    overlay: str = "#181D27"
    border: str = "#232A36"
    border_strong: str = "#2E3644"

    # Text
    text: str = "#EDF0F5"
    text_muted: str = "#98A2B3"
    text_dim: str = "#636D7E"
    text_inverse: str = "#0C0F14"

    # Accents
    accent: str = "#3B82F6"
    accent_hover: str = "#60A5FA"
    accent_dim: str = "#1B2E4E"
    accent_soft: str = "#141F35"
    #: Second accent, for the far end of a gradient and for chart variety.
    accent_alt: str = "#2DD4BF"

    # Severity
    critical: str = "#F0475F"
    high: str = "#F2924B"
    medium: str = "#F0C24B"
    low: str = "#34D399"
    info: str = "#3B82F6"
    ok: str = "#34D399"
    offline: str = "#636D7E"

    # Severity fills: the tint a banded row takes, dark enough to sit under
    # body text without competing with it. Only the two severities worth
    # navigating a queue by are banded, so only those two have a fill.
    critical_soft: str = "#2A1720"
    high_soft: str = "#2A2018"

    # Chart series
    series: tuple[str, ...] = (
        "#3B82F6", "#34D399", "#F0C24B", "#F2924B", "#F0475F",
        "#2DD4BF", "#818CF8", "#F472B6", "#A3E635", "#E0B341",
    )
    grid: str = "#1B212C"


PALETTE = Palette()

#: Font families tried in order; the first available one is used.
_FONT_CANDIDATES = ("Segoe UI", "Inter", "Helvetica Neue", "DejaVu Sans", "Arial")
_MONO_CANDIDATES = ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Courier New")


@dataclass(frozen=True)
class Fonts:
    """Named fonts used across the interface.

    A console is read at a glance and then in detail, so the scale is
    deliberately wide: a metric has to be legible across a room, a table cell
    has to fit a hundred rows, and ``label`` - small, bold, upper-case - is what
    marks a section without spending a heading on it.
    """

    body: tuple[str, int]
    body_bold: tuple[str, int, str]
    small: tuple[str, int]
    small_bold: tuple[str, int, str]
    label: tuple[str, int, str]
    heading: tuple[str, int, str]
    subheading: tuple[str, int, str]
    title: tuple[str, int, str]
    metric: tuple[str, int, str]
    metric_small: tuple[str, int, str]
    mono: tuple[str, int]
    mono_small: tuple[str, int]

    @property
    def family(self) -> str:
        """The interface font family, for a one-off size the scale lacks."""
        return self.body[0]


def _first_available(root: tk.Misc, candidates: tuple[str, ...], fallback: str) -> str:
    """Return the first font family actually installed."""
    try:
        available = {name.lower() for name in tkfont.families(root)}
    except Exception:  # noqa: BLE001 - font enumeration can fail on odd displays
        return fallback
    for candidate in candidates:
        if candidate.lower() in available:
            return candidate
    return fallback


def build_fonts(root: tk.Misc) -> Fonts:
    """Choose fonts that exist on this machine."""
    family = _first_available(root, _FONT_CANDIDATES, "TkDefaultFont")
    mono = _first_available(root, _MONO_CANDIDATES, "TkFixedFont")
    return Fonts(
        body=(family, 11),
        body_bold=(family, 11, "bold"),
        small=(family, 10),
        small_bold=(family, 10, "bold"),
        label=(family, 9, "bold"),
        heading=(family, 13, "bold"),
        subheading=(family, 12, "bold"),
        title=(family, 18, "bold"),
        metric=(family, 27, "bold"),
        metric_small=(family, 18, "bold"),
        mono=(mono, 10),
        mono_small=(mono, 9),
    )


SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": PALETTE.critical,
    "HIGH": PALETTE.high,
    "MEDIUM": PALETTE.medium,
    "LOW": PALETTE.low,
    "INFO": PALETTE.info,
    "INFORMATIONAL": PALETTE.info,
}

STATE_COLOURS: dict[str, str] = {
    "RUNNING": PALETTE.ok,
    "CONNECTED": PALETTE.ok,
    "AVAILABLE": PALETTE.ok,
    "CAPTURING": PALETTE.ok,
    "STOPPED": PALETTE.medium,
    "UNKNOWN": PALETTE.offline,
    "DISABLED": PALETTE.offline,
    "OFFLINE": PALETTE.critical,
    "UNAVAILABLE": PALETTE.critical,
    "ERROR": PALETTE.critical,
    "PASS": PALETTE.ok,
    "WARNING": PALETTE.medium,
    "FAIL": PALETTE.critical,
    "SKIPPED": PALETTE.offline,
}

STATUS_COLOURS: dict[str, str] = {
    "NEW": PALETTE.info,
    "INVESTIGATING": PALETTE.medium,
    "ACKNOWLEDGED": PALETTE.accent,
    "RESOLVED": PALETTE.ok,
    "FALSE_POSITIVE": PALETTE.offline,
    "CLOSED": PALETTE.offline,
    "REVIEWED": PALETTE.ok,
    "ESCALATED": PALETTE.high,
    "SUPPRESSED": PALETTE.offline,
    "OPEN": PALETTE.medium,
    "ACTIVE": PALETTE.ok,
    "INACTIVE": PALETTE.offline,
    "LOCKED": PALETTE.critical,
    # Password recovery queue
    "PENDING": PALETTE.medium,
    "APPROVED": PALETTE.accent,
    "REJECTED": PALETTE.critical,
    "COMPLETED": PALETTE.ok,
    "EXPIRED": PALETTE.offline,
}


#: Glyphs used where a colour alone would not distinguish a value, so severity
#: stays readable for an operator who cannot separate red from orange.
SEVERITY_GLYPHS: dict[str, str] = {
    "CRITICAL": "◆",       # filled diamond
    "HIGH": "▲",           # filled triangle
    "MEDIUM": "■",         # filled square
    "LOW": "●",            # filled circle
    "INFO": "○",           # hollow circle
    "INFORMATIONAL": "○",
}

#: Navigation and status icons. Plain Unicode, so no image assets are needed
#: and the interface renders identically on a fresh Windows installation.
ICONS: dict[str, str] = {
    "dashboard": "▦",      # squared grid
    "traffic": "≈",        # almost equal to - flowing traffic
    "vulnerabilities": "⚑",  # flag
    "hosts": "▣",          # square with fill
    "alerts": "⚠",         # warning sign
    "incidents": "✦",      # four-pointed star
    "mitigation": "⚕",     # staff of Aesculapius - remedy
    "reports": "☰",        # trigram - stacked lines
    "logs": "≡",           # identical to - log lines
    "users": "☺",          # person
    "health": "♥",         # heart - health
    "settings": "⚙",       # gear
    "help": "?",
    "about": "ℹ",          # information source
    "search": "⌕",         # telephone recorder - magnifier stand-in
    "bell": "⚑",
    "collapse": "◀",
    "expand": "▶",
    "sort_asc": "▴",
    "sort_desc": "▾",
    "close": "✕",
    "copy": "⎘",
    "refresh": "↻",
    "check": "✓",
    "dot": "●",
}


def severity_glyph(value: object) -> str:
    """Shape prefix for a severity, empty when the value is not a severity."""
    key = str(value or "").upper()
    return SEVERITY_GLYPHS.get(key, "")


def _blend(colour: str, background: str, ratio: float) -> str:
    """Mix ``colour`` into ``background`` (0 = background, 1 = colour)."""
    def channels(value: str) -> tuple[int, int, int]:
        value = value.lstrip("#")
        return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)

    fr, fg, fb = channels(colour)
    br, bg, bb = channels(background)
    ratio = max(0.0, min(1.0, ratio))
    mixed = (
        round(br + (fr - br) * ratio),
        round(bg + (fg - bg) * ratio),
        round(bb + (fb - bb) * ratio),
    )
    return "#%02X%02X%02X" % mixed


def chip_colours(colour: str, *, surface: str = "") -> tuple[str, str]:
    """``(foreground, background)`` for a filled chip in the given accent.

    The background is the accent blended most of the way into the surface, so a
    chip reads as a tinted pill rather than a solid block of alarm colour.
    """
    base = surface or PALETTE.surface
    return colour, _blend(colour, base, 0.18)


def severity_colour(value: object) -> str:
    """Colour for a severity or risk level."""
    if isinstance(value, (Severity, RiskLevel)):
        key = str(value)
    else:
        key = str(value or "").upper()
    return SEVERITY_COLOURS.get(key, PALETTE.text_muted)


def state_colour(value: object) -> str:
    """Colour for a subsystem state or diagnostic result."""
    if isinstance(value, (ServiceState, CheckResult)):
        key = str(value)
    else:
        key = str(value or "").upper()
    return STATE_COLOURS.get(key, PALETTE.text_muted)


def status_colour(value: object) -> str:
    """Colour for a workflow status."""
    if isinstance(value, IncidentStatus):
        key = str(value)
    else:
        key = str(value or "").upper()
    return STATUS_COLOURS.get(key, PALETTE.text_muted)


def apply_theme(root: tk.Misc) -> Fonts:
    """Install the AETHRA-SEC ttk theme and return the chosen fonts."""
    fonts = build_fonts(root)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")  # 'clam' honours colour options on every platform
    except tk.TclError:  # pragma: no cover - exotic Tk builds
        pass

    p = PALETTE
    # Default fonts for the *classic* Tk widget classes only.
    #
    # This was once a blanket ``option_add("*Font", ...)``, which is a trap:
    # the option database sets a widget's own -font option, and a widget option
    # beats the ttk style that would otherwise supply it. Every style font
    # defined below - titles, metrics, section labels, the whole scale - was
    # therefore looked up correctly and then silently ignored, leaving the
    # interface rendering at one size throughout. Naming the classic classes
    # keeps plain tk.Label/Text/Listbox styled without touching ttk, whose
    # classes are TLabel, TEntry and so on.
    for widget_class in (
        "Label", "Button", "Entry", "Text", "Listbox", "Menu", "Menubutton",
        "Message", "Checkbutton", "Radiobutton", "Scale", "Spinbox", "Canvas",
    ):
        root.option_add(f"*{widget_class}.font", fonts.body)
    try:
        root.configure(background=p.background)
    except tk.TclError:
        pass

    style.configure(".", background=p.background, foreground=p.text,
                    fieldbackground=p.surface, bordercolor=p.border,
                    lightcolor=p.surface, darkcolor=p.surface, font=fonts.body)

    # --- Frames -----------------------------------------------------------
    style.configure("TFrame", background=p.background)
    style.configure("Surface.TFrame", background=p.surface)
    # Interiors stay flat: a panel draws one edge, and the rows and strips
    # inside it must not draw a second one within the first.
    style.configure("Card.TFrame", background=p.surface, relief="flat",
                    borderwidth=0)
    style.configure("CardAlt.TFrame", background=p.surface_alt, relief="flat",
                    borderwidth=0)
    style.configure("Raised.TFrame", background=p.surface_raised, relief="flat",
                    borderwidth=0)

    # Panels are drawn with a real edge. Two shades of dark are not a boundary
    # an operator can find at a glance; a one-pixel border is. These are the
    # styles a panel *itself* wears - never its contents.
    def _panel(name: str, fill: str, edge: str) -> None:
        style.configure(name, background=fill, borderwidth=1, relief="solid",
                        bordercolor=edge, lightcolor=edge, darkcolor=edge)

    _panel("Panel.TFrame", p.surface, p.border)
    _panel("PanelHover.TFrame", p.surface_alt, p.border_strong)
    _panel("PanelAccent.TFrame", p.surface, p.accent)
    _panel("PanelRaised.TFrame", p.surface_raised, p.border_strong)
    _panel("PanelSunken.TFrame", p.surface_sunken, p.border)
    style.configure("Sunken.TFrame", background=p.surface_sunken)
    # The one-pixel rule a bordered panel is drawn with.
    style.configure("Border.TFrame", background=p.border)
    style.configure("BorderStrong.TFrame", background=p.border_strong)
    style.configure("Accent.TFrame", background=p.accent)
    # Panel chrome: a header band distinct from the body it titles.
    style.configure("CardHeader.TFrame", background=p.surface_alt)
    style.configure("CardHeaderLabel.TLabel", background=p.surface_alt,
                    foreground=p.text, font=fonts.subheading)
    style.configure("CardHeaderMuted.TLabel", background=p.surface_alt,
                    foreground=p.text_dim, font=fonts.small)
    # Section headings that group panels on a page.
    style.configure("Section.TLabel", background=p.background,
                    foreground=p.text_muted, font=fonts.label)
    style.configure("SectionNote.TLabel", background=p.background,
                    foreground=p.text_dim, font=fonts.small)
    # The details drawer sits one level above the page, so its own chrome needs
    # labels on the raised surface rather than on the card or page surface.
    style.configure("DrawerHeading.TLabel", background=p.surface_raised,
                    foreground=p.text, font=fonts.heading)
    style.configure("DrawerMuted.TLabel", background=p.surface_raised,
                    foreground=p.text_muted, font=fonts.small)
    style.configure("DrawerDim.TLabel", background=p.surface_raised,
                    foreground=p.text_dim, font=fonts.small)
    style.configure("Sidebar.TFrame", background=p.surface)
    style.configure("Header.TFrame", background=p.surface_alt)
    style.configure("HeaderBand.TFrame", background=p.surface_alt,
                    borderwidth=0, relief="flat")
    style.configure("Separator.TFrame", background=p.border)

    # --- Labels -----------------------------------------------------------
    style.configure("TLabel", background=p.background, foreground=p.text)
    style.configure("Card.TLabel", background=p.surface, foreground=p.text)
    style.configure("CardMuted.TLabel", background=p.surface, foreground=p.text_muted,
                    font=fonts.small)
    style.configure("CardDim.TLabel", background=p.surface, foreground=p.text_dim,
                    font=fonts.small)
    style.configure("Metric.TLabel", background=p.surface, foreground=p.text,
                    font=fonts.metric)
    style.configure("Heading.TLabel", background=p.background, foreground=p.text,
                    font=fonts.heading)
    style.configure("CardHeading.TLabel", background=p.surface, foreground=p.text,
                    font=fonts.heading)
    # A panel's own name: small, bold and upper-case, so it reads as a label
    # rather than competing with the content underneath it.
    style.configure("CardTitle.TLabel", background=p.surface, foreground=p.text,
                    font=fonts.subheading)
    style.configure("Title.TLabel", background=p.background, foreground=p.text,
                    font=fonts.title)

    # Metric tiles, on their own elevated surface.
    style.configure("MetricValue.TLabel", background=p.surface,
                    foreground=p.text, font=(fonts.family, 34, "bold"))
    style.configure("MetricLabel.TLabel", background=p.surface,
                    foreground=p.text_muted, font=fonts.label)
    style.configure("MetricDetail.TLabel", background=p.surface,
                    foreground=p.text_dim, font=fonts.small)
    style.configure("MetricTrend.TLabel", background=p.surface,
                    foreground=p.text_dim, font=fonts.small_bold)

    # Summary strip: the count is the thing being read, the caption names it.
    style.configure("SummaryValue.TLabel", background=p.surface,
                    foreground=p.text, font=fonts.metric_small)
    style.configure("SummaryLabel.TLabel", background=p.surface,
                    foreground=p.text_dim, font=fonts.label)

    # ------------------------------------------------------------------
    # Sign-in
    #
    # The authentication window is the first thing an operator sees and the
    # only screen shown before a session exists, so it gets its own surface
    # and its own scale rather than borrowing the console's.
    # ------------------------------------------------------------------
    style.configure("Auth.TFrame", background=p.surface_sunken)
    style.configure("AuthPanel.TFrame", background=p.surface)
    style.configure("AuthBrand.TFrame", background=p.surface_alt)
    style.configure("AuthField.TFrame", background=p.surface, borderwidth=1,
                    relief="solid", bordercolor=p.border_strong,
                    lightcolor=p.border_strong, darkcolor=p.border_strong)
    style.configure("AuthFieldFocus.TFrame", background=p.surface, borderwidth=1,
                    relief="solid", bordercolor=p.accent,
                    lightcolor=p.accent, darkcolor=p.accent)
    style.configure("AuthTitle.TLabel", background=p.surface, foreground=p.text,
                    font=(fonts.family, 24, "bold"))
    style.configure("AuthSubtitle.TLabel", background=p.surface,
                    foreground=p.text_muted, font=fonts.body)
    style.configure("AuthLabel.TLabel", background=p.surface,
                    foreground=p.text_muted, font=fonts.label)
    style.configure("AuthLink.TLabel", background=p.surface, foreground=p.accent,
                    font=fonts.small)
    style.configure("AuthNote.TLabel", background=p.surface,
                    foreground=p.text_dim, font=fonts.small)
    style.configure("AuthWordmark.TLabel", background=p.surface_alt,
                    foreground=p.text, font=(fonts.family, 26, "bold"))
    style.configure("AuthTagline.TLabel", background=p.surface_alt,
                    foreground=p.accent, font=fonts.label)
    style.configure("AuthBrandBody.TLabel", background=p.surface_alt,
                    foreground=p.text_muted, font=fonts.small)
    style.configure("AuthBrandDim.TLabel", background=p.surface_alt,
                    foreground=p.text_dim, font=fonts.small)
    style.configure("AuthStatus.TLabel", background=p.surface_alt,
                    foreground=p.text_muted, font=fonts.small)
    style.configure("Auth.TEntry", fieldbackground=p.surface,
                    background=p.surface, foreground=p.text,
                    bordercolor=p.surface, lightcolor=p.surface,
                    darkcolor=p.surface, insertcolor=p.accent,
                    borderwidth=0, relief="flat", padding=(4, 11))
    style.configure("AuthReveal.TButton", background=p.surface,
                    foreground=p.text_dim, borderwidth=0, relief="flat",
                    font=fonts.small, padding=(6, 2))
    style.map("AuthReveal.TButton",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.accent)])
    style.configure("AuthPrimary.TButton", background=p.accent,
                    foreground="#FFFFFF", borderwidth=0, relief="flat",
                    font=fonts.body_bold, padding=(18, 15))
    style.map("AuthPrimary.TButton",
              background=[("disabled", p.accent_dim), ("active", p.accent_hover)],
              foreground=[("disabled", p.text_dim)])
    style.configure("AuthCheck.TCheckbutton", background=p.surface,
                    foreground=p.text_muted, font=fonts.small)
    style.map("AuthCheck.TCheckbutton",
              background=[("active", p.surface)],
              foreground=[("active", p.text)])
    style.configure("AuthError.TFrame", background=p.critical_soft, borderwidth=1,
                    relief="solid", bordercolor=p.critical,
                    lightcolor=p.critical, darkcolor=p.critical)
    style.configure("AuthErrorText.TLabel", background=p.critical_soft,
                    foreground=p.critical, font=fonts.small)
    style.configure("Muted.TLabel", background=p.background, foreground=p.text_muted,
                    font=fonts.small)
    style.configure("Header.TLabel", background=p.surface_alt, foreground=p.text)
    style.configure("HeaderMuted.TLabel", background=p.surface_alt,
                    foreground=p.text_muted, font=fonts.small)
    # Header identity block: the product name over what it is.
    style.configure("Brand.TLabel", background=p.surface_alt, foreground=p.text,
                    font=(fonts.heading[0], 13, "bold"))
    style.configure("BrandSub.TLabel", background=p.surface_alt,
                    foreground=p.text_dim, font=fonts.label)
    style.configure("Clock.TLabel", background=p.surface_alt,
                    foreground=p.text_muted, font=fonts.body)
    style.configure("RoleBadge.TLabel", background=p.surface_alt,
                    foreground=p.accent, font=fonts.label)
    # The header's command bar, drawn as a field rather than a button.
    style.configure("SearchBar.TFrame", background=p.surface_sunken,
                    borderwidth=1, relief="solid", bordercolor=p.border_strong,
                    lightcolor=p.border_strong, darkcolor=p.border_strong)
    style.configure("SearchIcon.TLabel", background=p.surface_sunken,
                    foreground=p.text_dim, font=fonts.body)
    style.configure("Search.TEntry", fieldbackground=p.surface_sunken,
                    foreground=p.text, insertcolor=p.accent, borderwidth=0,
                    relief="flat", padding=(0, 2))
    style.configure("Mono.TLabel", background=p.surface, foreground=p.text,
                    font=fonts.mono)
    for name, colour in (
        ("Critical", p.critical), ("High", p.high), ("Medium", p.medium),
        ("Low", p.low), ("Info", p.info), ("Ok", p.ok), ("Offline", p.offline),
    ):
        style.configure(f"{name}.TLabel", background=p.surface, foreground=colour)
        style.configure(f"{name}Bg.TLabel", background=p.background, foreground=colour)

    # --- Buttons ----------------------------------------------------------
    style.configure("TButton", background=p.surface_raised, foreground=p.text,
                    bordercolor=p.border_strong, focuscolor=p.accent,
                    padding=(18, 10), relief="flat", font=fonts.body)
    style.map("TButton",
              background=[("active", p.border_strong), ("disabled", p.surface_alt)],
              foreground=[("disabled", p.text_dim)])
    style.configure("Accent.TButton", background=p.accent, foreground="#FFFFFF",
                    bordercolor=p.accent, font=fonts.body_bold)
    style.map("Accent.TButton",
              background=[("active", p.accent_hover), ("disabled", p.accent_dim)],
              foreground=[("disabled", "#B9C7DA")])
    style.configure("Danger.TButton", background=p.critical, foreground="#FFFFFF",
                    bordercolor=p.critical, font=fonts.body_bold)
    style.map("Danger.TButton", background=[("active", "#FF6E66")])
    style.configure("Ghost.TButton", background=p.surface, foreground=p.text_muted,
                    bordercolor=p.border, padding=(16, 9))
    style.map("Ghost.TButton", background=[("active", p.surface_alt)],
              foreground=[("active", p.text)])
    # Section headings above each group of navigation entries.
    style.configure("NavGroup.TLabel", background=p.surface,
                    foreground=p.text_dim, font=fonts.small_bold)

    style.configure("Nav.TButton", background=p.surface, foreground=p.text_muted,
                    bordercolor=p.surface, anchor="w", padding=(14, 13),
                    relief="flat", font=fonts.body, borderwidth=0)
    style.map("Nav.TButton",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.text)])
    style.configure("NavActive.TButton", background=p.accent_dim, foreground=p.text,
                    bordercolor=p.accent, anchor="w", padding=(14, 13),
                    relief="flat", font=fonts.body_bold, borderwidth=0)
    style.map("NavActive.TButton",
              background=[("active", p.accent_dim)],
              foreground=[("active", p.text)])
    # The icon cell beside each entry: a fixed-width square so the labels line
    # up down the rail whatever glyph each screen uses.
    style.configure("NavGlyph.TLabel", background=p.surface,
                    foreground=p.text_dim, font=(fonts.body[0], 13),
                    anchor="center", width=2)
    style.configure("NavGlyphActive.TLabel", background=p.accent_dim,
                    foreground=p.accent_hover, font=(fonts.body[0], 13),
                    anchor="center", width=2)

    # Collapsed sidebar: the same entries as a centred icon rail.
    style.configure("NavIcon.TButton", background=p.surface, foreground=p.text_muted,
                    bordercolor=p.surface, anchor="center", padding=(4, 9),
                    relief="flat", font=(fonts.body[0], 13))
    style.map("NavIcon.TButton",
              background=[("active", p.surface_alt)],
              foreground=[("active", p.text)])
    style.configure("NavIconActive.TButton", background=p.accent_dim,
                    foreground=p.text, bordercolor=p.accent, anchor="center",
                    padding=(4, 9), relief="flat", font=(fonts.body[0], 13, "bold"))
    style.map("NavIconActive.TButton", background=[("active", p.accent_dim)])

    # Toolbar buttons sit directly on a card and stay quiet until hovered.
    style.configure("Tool.TButton", background=p.surface, foreground=p.text_muted,
                    bordercolor=p.surface, padding=(14, 8), relief="flat",
                    font=fonts.small)
    style.map("Tool.TButton",
              background=[("active", p.surface_hover), ("disabled", p.surface)],
              foreground=[("active", p.text), ("disabled", p.text_dim)])
    style.configure("ToolAccent.TButton", background=p.accent_soft,
                    foreground=p.accent_hover, bordercolor=p.accent_soft,
                    padding=(14, 8), relief="flat", font=fonts.small_bold)
    style.map("ToolAccent.TButton",
              background=[("active", p.accent_dim)],
              foreground=[("active", "#FFFFFF"), ("disabled", p.text_dim)])
    style.configure("Icon.TButton", background=p.surface_alt, foreground=p.text_muted,
                    bordercolor=p.surface_alt, padding=(10, 6), relief="flat")
    style.map("Icon.TButton",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.text)])
    style.configure("HeaderIcon.TButton", background=p.surface_alt,
                    foreground=p.text_muted, bordercolor=p.surface_alt,
                    padding=(11, 7), relief="flat")
    style.map("HeaderIcon.TButton",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.text)])
    style.configure("Search.TButton", background=p.surface, foreground=p.text_dim,
                    bordercolor=p.border, padding=(14, 8), relief="flat",
                    anchor="w", font=fonts.small)
    style.map("Search.TButton",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.text_muted)])

    # --- Chips and badges -------------------------------------------------
    for surface_name, surface_colour in (
        ("", p.surface), ("Header", p.surface_alt), ("Bg", p.background),
    ):
        for name, colour in (
            ("Critical", p.critical), ("High", p.high), ("Medium", p.medium),
            ("Low", p.low), ("Info", p.info), ("Ok", p.ok),
            ("Offline", p.offline), ("Accent", p.accent),
        ):
            foreground, chip_background = chip_colours(colour, surface=surface_colour)
            style.configure(
                f"{name}{surface_name}Chip.TLabel",
                background=chip_background, foreground=foreground,
                padding=(10, 4), font=fonts.small_bold,
            )
    style.configure("Badge.TLabel", background=p.accent, foreground="#FFFFFF",
                    padding=(8, 2), font=fonts.small_bold)
    style.configure("BadgeMuted.TLabel", background=p.surface_raised,
                    foreground=p.text_muted, padding=(8, 2), font=fonts.small_bold)
    style.configure("Kbd.TLabel", background=p.surface_raised, foreground=p.text_dim,
                    padding=(8, 3), font=fonts.mono_small)

    # --- Overlay surfaces (command palette, notification panel, toasts) ----
    style.configure("Overlay.TFrame", background=p.overlay)
    style.configure("Overlay.TLabel", background=p.overlay, foreground=p.text)
    style.configure("OverlayMuted.TLabel", background=p.overlay,
                    foreground=p.text_muted, font=fonts.small)
    style.configure("OverlayDim.TLabel", background=p.overlay,
                    foreground=p.text_dim, font=fonts.small)
    style.configure("OverlayHeading.TLabel", background=p.overlay, foreground=p.text,
                    font=fonts.heading)
    style.configure("Overlay.TEntry", fieldbackground=p.surface_alt,
                    foreground=p.text, bordercolor=p.border_strong,
                    insertcolor=p.accent, padding=8)
    style.configure("Toast.TFrame", background=p.surface_raised)
    style.configure("Toast.TLabel", background=p.surface_raised, foreground=p.text,
                    font=fonts.small_bold)
    style.configure("ToastBody.TLabel", background=p.surface_raised,
                    foreground=p.text_muted, font=fonts.small)

    # --- Inputs -----------------------------------------------------------
    style.configure("TEntry", fieldbackground=p.surface_alt, foreground=p.text,
                    bordercolor=p.border_strong, insertcolor=p.text,
                    padding=9, relief="flat")
    style.map("TEntry", bordercolor=[("focus", p.accent)])
    style.configure("TCombobox", fieldbackground=p.surface_alt, background=p.surface_alt,
                    foreground=p.text, arrowcolor=p.text_muted,
                    bordercolor=p.border_strong, padding=8)
    style.map("TCombobox",
              fieldbackground=[("readonly", p.surface_alt)],
              foreground=[("readonly", p.text)],
              bordercolor=[("focus", p.accent)])
    root.option_add("*TCombobox*Listbox.background", p.surface_alt)
    root.option_add("*TCombobox*Listbox.foreground", p.text)
    root.option_add("*TCombobox*Listbox.selectBackground", p.accent)
    root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")

    style.configure("TCheckbutton", background=p.surface, foreground=p.text,
                    indicatorcolor=p.surface_alt, focuscolor=p.accent)
    style.map("TCheckbutton",
              background=[("active", p.surface)],
              indicatorcolor=[("selected", p.accent)])
    style.configure("TRadiobutton", background=p.surface, foreground=p.text)
    style.configure("TSpinbox", fieldbackground=p.surface_alt, foreground=p.text,
                    bordercolor=p.border_strong, arrowcolor=p.text_muted, padding=7)

    # --- Tables -----------------------------------------------------------
    # Rows are given real height: a security table is read row by row, and a
    # cramped grid is where an analyst loses their place.
    style.configure("Treeview", background=p.surface, fieldbackground=p.surface,
                    foreground=p.text, bordercolor=p.border, rowheight=38,
                    font=fonts.body, relief="flat", borderwidth=0)
    style.map("Treeview",
              background=[("selected", p.accent_dim)],
              foreground=[("selected", "#FFFFFF")])
    style.configure("Treeview.Heading", background=p.surface_sunken,
                    foreground=p.text_dim, relief="flat", padding=(14, 13),
                    font=fonts.label, borderwidth=0)
    style.map("Treeview.Heading",
              background=[("active", p.surface_alt)],
              foreground=[("active", p.text)])
    style.configure("Mono.Treeview", font=fonts.mono_small, rowheight=27,
                    background=p.surface, fieldbackground=p.surface,
                    foreground=p.text, borderwidth=0)
    style.configure("Mono.Treeview.Heading", background=p.surface_sunken,
                    foreground=p.text_dim, relief="flat", padding=(12, 9),
                    font=fonts.label, borderwidth=0)
    style.map("Mono.Treeview.Heading",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.text)])

    # --- Scrollbars / notebooks / misc ------------------------------------
    # The thumb has to be findable against a dark trough without becoming the
    # brightest thing on the page; ``lightcolor``/``darkcolor`` are set too,
    # because clam draws the thumb's bevel from them and would otherwise paint
    # it near-white.
    for orientation in ("Vertical", "Horizontal"):
        style.configure(
            f"{orientation}.TScrollbar", background=p.border_strong,
            troughcolor=p.surface_sunken, bordercolor=p.surface_sunken,
            lightcolor=p.border_strong, darkcolor=p.border_strong,
            arrowcolor=p.text_dim, relief="flat", borderwidth=0, width=12,
        )
        style.map(
            f"{orientation}.TScrollbar",
            background=[("active", p.accent_dim), ("pressed", p.accent)],
            arrowcolor=[("active", p.text)],
        )

    style.configure("TNotebook", background=p.background, bordercolor=p.border,
                    tabmargins=(0, 4, 0, 0), borderwidth=0)
    style.configure("TNotebook.Tab", background=p.surface_sunken,
                    foreground=p.text_dim, padding=(20, 13), font=fonts.small_bold,
                    borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", p.surface_raised)],
              foreground=[("selected", p.text)])
    style.configure("TPanedwindow", background=p.background)
    style.configure("TLabelframe", background=p.surface, foreground=p.text_muted,
                    bordercolor=p.border)
    style.configure("TLabelframe.Label", background=p.surface, foreground=p.text_muted,
                    font=fonts.small_bold)
    style.configure("TSeparator", background=p.border)
    style.configure("Horizontal.TProgressbar", background=p.accent,
                    troughcolor=p.surface_alt, bordercolor=p.surface_alt,
                    lightcolor=p.accent, darkcolor=p.accent)
    return fonts


def configure_text_widget(widget: tk.Text, fonts: Fonts, *, mono: bool = False) -> None:
    """Apply the theme to a raw ``tk.Text`` (ttk has no text widget)."""
    widget.configure(
        background=PALETTE.surface,
        foreground=PALETTE.text,
        insertbackground=PALETTE.text,
        selectbackground=PALETTE.accent_dim,
        selectforeground=PALETTE.text,
        relief="flat",
        borderwidth=0,
        highlightthickness=1,
        highlightbackground=PALETTE.border,
        highlightcolor=PALETTE.accent,
        padx=10,
        pady=8,
        wrap="word",
        font=fonts.mono if mono else fonts.body,
    )


def configure_listbox(widget: tk.Listbox, fonts: Fonts) -> None:
    """Apply the theme to a raw ``tk.Listbox``."""
    widget.configure(
        background=PALETTE.surface,
        foreground=PALETTE.text,
        selectbackground=PALETTE.accent_dim,
        selectforeground=PALETTE.text,
        relief="flat",
        borderwidth=0,
        highlightthickness=1,
        highlightbackground=PALETTE.border,
        font=fonts.small,
        activestyle="none",
    )
