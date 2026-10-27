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
from dataclasses import dataclass, fields
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

    Surfaces are separated by **fill and whitespace**, not by a drawn box. The
    previous ladder relied on a visible border around every section, which is
    what made the console read as a grid of rectangles rather than as a
    workspace. Here the steps between page, surface and raised are wide enough
    to be read on their own, so a border is reserved for the few places an
    actual edge carries meaning - an input, a menu, a table's header rule.
    """

    # Surfaces, in ascending elevation. Charcoal-navy rather than blue-navy:
    # a near-neutral ground lets the severity colours be the only saturated
    # thing on screen, which is what an operator should be drawn to.
    background: str = "#0B0E14"
    surface: str = "#11151E"
    surface_alt: str = "#161B26"
    surface_raised: str = "#1B2130"
    surface_hover: str = "#1F2634"
    surface_sunken: str = "#080A0F"
    overlay: str = "#1B2130"
    #: Hairline. Deliberately close to the surfaces it divides - a separator
    #: should be found when looked for, not seen when not.
    border: str = "#1C2230"
    border_strong: str = "#2A3242"

    # Text
    text: str = "#E8ECF4"
    text_muted: str = "#8C97AC"
    text_dim: str = "#5C6678"
    text_inverse: str = "#0B0E14"
    #: Text drawn on a saturated severity or accent fill. White in both themes:
    #: those fills stay dark enough in the light theme to carry it, so this is
    #: a token for the intent, not a value that flips.
    text_on_accent: str = "#FFFFFF"
    #: What a raised surface's shadow is blended toward. Black under a dark
    #: page; a cool grey under a light one, where a black shadow reads as dirt.
    shadow: str = "#000000"

    # Accents
    accent: str = "#5B8DEF"
    accent_hover: str = "#7FA6F3"
    accent_dim: str = "#1A2942"
    accent_soft: str = "#131D30"
    #: Second accent, for the far end of a gradient and for chart variety.
    accent_alt: str = "#8B7CF0"

    # Severity
    critical: str = "#F2555A"
    high: str = "#F58A3C"
    medium: str = "#E8B93B"
    low: str = "#35C88A"
    info: str = "#5B8DEF"
    ok: str = "#35C88A"
    offline: str = "#5C6678"

    # Severity fills: the tint a banded row takes, dark enough to sit under
    # body text without competing with it. Only the two severities worth
    # navigating a queue by are banded, so only those two have a fill.
    critical_soft: str = "#2A161C"
    high_soft: str = "#2A1E14"

    # Chart series
    series: tuple[str, ...] = (
        "#5B8DEF", "#35C88A", "#E8B93B", "#F58A3C", "#F2555A",
        "#8B7CF0", "#37C2C2", "#E86FA8", "#8FC44E", "#C9A227",
    )
    grid: str = "#171D28"


#: The dark theme. This is the default: a security console is watched for
#: hours in a dim room, and a bright page in that setting is fatiguing.
DARK_PALETTE = Palette()

#: The light theme. Designed, not inverted - inverting a dark palette gives
#: muddy mid-greys and severity colours that vibrate against white. The
#: surfaces here are a cool near-white ladder, and every severity colour is
#: re-picked at a darker value so it carries the same weight on white that the
#: dark theme's brighter version carries on near-black.
LIGHT_PALETTE = Palette(
    # Surfaces, ascending elevation. The page is faintly cool so that white
    # panels sitting on it read as raised without needing a border.
    background="#EEF1F6",
    surface="#FFFFFF",
    surface_alt="#F5F7FA",
    surface_raised="#FFFFFF",
    surface_hover="#E9EEF6",
    surface_sunken="#E4E9F1",
    overlay="#FFFFFF",
    # A hairline that is found when looked for, not seen when not - the same
    # rule as the dark theme, at light-theme contrast.
    border="#DCE2EC",
    border_strong="#B9C2D2",

    # Text. Charcoal rather than black: pure black on white is harsher than it
    # needs to be over a long shift.
    text="#151A23",
    text_muted="#4E5769",
    text_dim="#7A8496",
    text_inverse="#FFFFFF",
    text_on_accent="#FFFFFF",
    shadow="#98A5BA",

    # Accents. The same AETHRA blue, darkened so it passes contrast on white.
    accent="#2C5FD0",
    accent_hover="#1E48A8",
    accent_dim="#C9D8F7",
    accent_soft="#E8EFFC",
    accent_alt="#6B4FD8",

    # Severity, re-picked for white. Each is dark enough for body text to sit
    # on the page beside it without the colour glowing.
    critical="#C42230",
    high="#B85C10",
    medium="#966A05",
    low="#0F7A46",
    info="#2C5FD0",
    ok="#0F7A46",
    offline="#7A8496",

    # Severity fills: the tint a banded row takes. Pale enough that dark body
    # text keeps its contrast on top.
    critical_soft="#FBE8EA",
    high_soft="#FDF0E3",

    # Chart series, darkened to sit on a light plot surface.
    series=(
        "#2C5FD0", "#0F7A46", "#966A05", "#B85C10", "#C42230",
        "#6B4FD8", "#0E7C7C", "#B33B7E", "#5A8A1E", "#8A6D12",
    ),
    grid="#E2E7EF",
)


class ActivePalette:
    """The palette the interface is currently drawn from.

    Every module does ``from aethra_sec.ui.theme import PALETTE`` and reads
    ``PALETTE.background`` and friends. That binds the *object*, so switching
    themes by rebinding the module attribute would leave thirty-odd modules
    still pointing at the old one. Instead this holder keeps the same identity
    for the life of the process and has its fields replaced in place, which
    every existing reference picks up with no call site changing.

    It carries exactly the fields of :class:`Palette`; there is one set of
    tokens and one interface, and only the values behind them change.
    """

    def __init__(self, palette: "Palette") -> None:
        """Adopt the starting theme."""
        self.adopt(palette)

    def adopt(self, palette: "Palette") -> None:
        """Replace every token with the ones from ``palette``."""
        for field_ in fields(Palette):
            setattr(self, field_.name, getattr(palette, field_.name))


#: Named themes, so a preference can be stored as a string.
THEMES: dict[str, Palette] = {"dark": DARK_PALETTE, "light": LIGHT_PALETTE}

#: The theme used when nothing has been chosen or a stored name is unknown.
DEFAULT_THEME = "dark"

_active_theme = DEFAULT_THEME

#: The live palette. Import this; never copy its values into a module global,
#: or that copy will not follow a theme change.
PALETTE = ActivePalette(THEMES[DEFAULT_THEME])


def current_theme() -> str:
    """Name of the theme in force."""
    return _active_theme


def set_theme(name: str) -> str:
    """Switch the active palette.

    Only the token values change - there is no second set of widgets and no
    second layout. Callers must still restyle ttk (:func:`apply_theme`) and
    rebuild anything that painted itself on a canvas, because those captured
    their colours when they were drawn.

    Args:
        name: ``dark`` or ``light``. An unknown name falls back to the default
            rather than leaving the interface half-themed.

    Returns:
        The name actually applied.
    """
    global _active_theme

    chosen = (name or "").strip().lower()
    if chosen not in THEMES:
        chosen = DEFAULT_THEME
    _active_theme = chosen
    PALETTE.adopt(THEMES[chosen])
    _refresh_colour_maps()
    return chosen


def _refresh_colour_maps() -> None:
    """Rebuild the derived colour lookups from the active palette.

    These are module-level dicts built from the palette, so they hold values
    from whichever theme was active when they were first built. They are
    updated in place for the same reason the palette is: other modules hold
    references to them.
    """
    SEVERITY_COLOURS.update({
        "CRITICAL": PALETTE.critical,
        "HIGH": PALETTE.high,
        "MEDIUM": PALETTE.medium,
        "LOW": PALETTE.low,
        "INFO": PALETTE.info,
        "INFORMATIONAL": PALETTE.info,
    })
    STATE_COLOURS.update({
        "RUNNING": PALETTE.ok,
        "CONNECTED": PALETTE.ok,
        "AVAILABLE": PALETTE.ok,
        "CAPTURING": PALETTE.ok,
        "READY": PALETTE.info,
        "PAUSED": PALETTE.medium,
        "STOPPING": PALETTE.medium,
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
    })
    STATUS_COLOURS.update({
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
        "PENDING": PALETTE.medium,
        "APPROVED": PALETTE.accent,
        "REJECTED": PALETTE.critical,
        "COMPLETED": PALETTE.ok,
        "EXPIRED": PALETTE.offline,
    })


@dataclass(frozen=True)
class Metrics:
    """Spacing, radius and control sizing - the layout half of the tokens.

    Before this existed every screen chose its own padding, which is why the
    console had no consistent rhythm: a card padded 12 sat beside one padded
    18, and neither related to the gap between them. These are the only values
    a screen should use, so spacing is a decision made once here rather than
    re-made on every page.
    """

    #: A 4px base step. Everything on screen is a multiple of it.
    space_xs: int = 4
    space_sm: int = 8
    space_md: int = 12
    space_lg: int = 16
    space_xl: int = 24
    space_2xl: int = 32

    #: Gutter between top-level regions of a page.
    gutter: int = 16
    #: Padding inside a section's body.
    section_pad: int = 14

    radius_sm: int = 4
    radius_md: int = 6
    radius_lg: int = 10

    #: Table row height. Compact enough for density, tall enough to click.
    row_height: int = 26
    #: Height of a single-line control (entry, button, select).
    control_height: int = 28
    #: Sidebar widths, expanded and collapsed.
    sidebar_width: int = 216
    sidebar_collapsed: int = 56
    #: Top bar height. One line of chrome, not two.
    topbar_height: int = 48


METRICS = Metrics()

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
        body=(family, 10),
        body_bold=(family, 10, "bold"),
        small=(family, 9),
        small_bold=(family, 9, "bold"),
        label=(family, 8, "bold"),
        heading=(family, 11, "bold"),
        subheading=(family, 10, "bold"),
        title=(family, 14, "bold"),
        metric=(family, 22, "bold"),
        metric_small=(family, 15, "bold"),
        mono=(mono, 9),
        mono_small=(mono, 8),
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
    # Live-capture states, as the capture service names them. IDLE means armed
    # but not started; STARTING is the window before the capture process has
    # been seen running; PAUSED means the display is held while capture
    # continues underneath; STOPPING is the shutdown window; FAILED means the
    # capture is not running and the reason is on screen.
    "IDLE": PALETTE.info,
    "STARTING": PALETTE.medium,
    "FAILED": PALETTE.critical,
    "READY": PALETTE.info,
    "PAUSED": PALETTE.medium,
    "STOPPING": PALETTE.medium,
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
    # Host reachability and automatic-assessment vocabulary (Vulnerability
    # Assessment automation). A missing or failed result is never coloured as
    # safe: only "NO FINDINGS" is green.
    "UP": PALETTE.ok,
    "QUEUED": PALETTE.info,
    "SCANNING": PALETTE.info,
    "NOT ASSESSED": PALETTE.offline,
    "NO FINDINGS": PALETTE.ok,
    "VULNERABLE": PALETTE.critical,
    "NO RESPONSE TO SCAN": PALETTE.medium,
    "SCAN FAILED": PALETTE.critical,
    "NOT AUTHORISED": PALETTE.offline,
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
    "mitigation": "⚕",     # staff of Aesculapius - remedy
    "attack_statistics": "▥",  # square with vertical fill - a bar chart
    "reports": "☰",        # trigram - stacked lines
    "evaluation": "⏱",     # stopwatch - measured detection time
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


def _relative_luminance(colour: str) -> float:
    """WCAG relative luminance of a ``#rrggbb`` colour."""
    raw = colour.lstrip("#")
    if len(raw) != 6:
        return 0.0

    def channel(value: int) -> float:
        v = value / 255.0
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4

    r, g, b = (int(raw[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def _contrast(one: str, two: str) -> float:
    """WCAG contrast ratio between two colours, 1.0 to 21.0."""
    a, b = sorted(
        (_relative_luminance(one), _relative_luminance(two)), reverse=True
    )
    return (a + 0.05) / (b + 0.05)


def text_on(fill: str) -> str:
    """The legible text colour to draw on ``fill``.

    Severity fills span a wide luminance range - a red is dark, an amber is
    bright - so no single fixed colour is legible on all of them. White on the
    dark theme's HIGH amber measures 2.4:1, well under the 3:1 a badge needs.

    Measured rather than guessed from a luminance threshold: a mid-orange sits
    close enough to any such cut-off that the answer would depend on where the
    line was drawn, so this simply takes whichever ink contrasts better.
    """
    dark_ink = "#101418"
    light_ink = PALETTE.text_on_accent
    if _contrast(dark_ink, fill) >= _contrast(light_ink, fill):
        return dark_ink
    return light_ink


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


def security_colour(value: object) -> str:
    """Colour for a host's security conclusion. Only "Safe" is coloured.

    Colour here is a claim, and only one of the three answers is a conclusion
    worth making at a glance: the assessment completed and found nothing it
    could confirm. "Vulnerable" is deliberately *not* coloured - the operator
    must open the row and read the evidence rather than triage on a red cell,
    and a red cell next to an unconfirmed finding is exactly the overstatement
    this column exists to avoid. "-" is not a state at all.

    Nothing here relies on colour alone: the cell always carries the word.
    """
    text = str(value or "").strip().upper()
    return PALETTE.ok if text == "SAFE" else PALETTE.text


def status_colour(value: object) -> str:
    """Colour for a workflow status."""
    if isinstance(value, IncidentStatus):
        key = str(value)
    else:
        key = str(value or "").upper()
    return STATUS_COLOURS.get(key, PALETTE.text_muted)


# ----------------------------------------------------------------------
# Motion (§ reduced-motion)
# ----------------------------------------------------------------------
#: Whether the interface may animate. A single switch every animated widget
#: consults, so "reduce motion" is one setting rather than a flag threaded
#: through thirty call sites. When off, animations jump straight to their end
#: state - nothing is hidden, only the transition is skipped.
_motion_enabled = True


def motion_enabled() -> bool:
    """True when subtle animations are allowed."""
    return _motion_enabled


def set_motion(enabled: bool) -> None:
    """Enable or disable animation across the whole interface."""
    global _motion_enabled
    _motion_enabled = bool(enabled)


#: Subsystem states that represent live, healthy activity. A status dot pulses
#: only for these, so motion on a dot means "this is working right now" rather
#: than decoration; every other state (STOPPED, OFFLINE, ERROR, UNKNOWN) is
#: drawn static.
ACTIVE_STATES: frozenset[str] = frozenset(
    {"RUNNING", "CAPTURING", "CONNECTED", "AVAILABLE", "SCANNING"}
)


def is_active_state(value: object) -> bool:
    """True when a subsystem state represents live activity worth a pulse."""
    return str(value or "").upper() in ACTIVE_STATES


def pulse_colour(colour: str, phase: float) -> str:
    """A dimmed shade of ``colour`` for a breathing pulse.

    ``phase`` runs 0..1; 1 is the full colour and 0 is dimmed most of the way
    toward the surface, so the dot never disappears - it only breathes.
    """
    ratio = 0.55 + 0.45 * max(0.0, min(1.0, phase))
    return _blend(colour, PALETTE.surface, ratio)


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
    # A section is not a box. It sits on the page ground and is separated
    # from its neighbours by whitespace and a header rule, so its frame takes
    # the page colour rather than a surface fill. Anything that genuinely is
    # an object - a metric tile, a menu - uses Tile/Panel/Raised instead.
    style.configure("Card.TFrame", background=p.background, relief="flat",
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
    style.configure("DrawerHeading.TLabel", background=p.background,
                    foreground=p.text, font=fonts.heading)
    style.configure("DrawerMuted.TLabel", background=p.background,
                    foreground=p.text_muted, font=fonts.small)
    style.configure("DrawerDim.TLabel", background=p.background,
                    foreground=p.text_dim, font=fonts.small)
    style.configure("Sidebar.TFrame", background=p.surface)
    # The active entry's row carries the same ground as its button, so the
    # indicator, glyph and label read as one selected band rather than as
    # stripes of two different greys.
    style.configure("SidebarActive.TFrame", background=p.surface_alt)
    style.configure("Header.TFrame", background=p.surface_alt)
    style.configure("HeaderBand.TFrame", background=p.surface_alt,
                    borderwidth=0, relief="flat")
    style.configure("Separator.TFrame", background=p.border)


    # A tile is a real object - it holds one figure and is clickable - so it
    # keeps a surface fill. This is the deliberate counterpart to a section,
    # which does not. Everything inside a tile takes these styles so its
    # interior never falls back to the page colour.
    style.configure("Tile.TFrame", background=p.surface, relief="flat",
                    borderwidth=0)
    style.configure("TileHover.TFrame", background=p.surface_hover, relief="flat",
                    borderwidth=0)
    style.configure("Tile.TLabel", background=p.surface, foreground=p.text)
    style.configure("TileMuted.TLabel", background=p.surface,
                    foreground=p.text_muted, font=fonts.small)
    style.configure("TileDim.TLabel", background=p.surface,
                    foreground=p.text_dim, font=fonts.small)
    style.configure("TileLabel.TLabel", background=p.surface,
                    foreground=p.text_muted, font=fonts.label)
    style.configure("TileValue.TLabel", background=p.surface, foreground=p.text,
                    font=fonts.metric)
    style.configure("TileValueSm.TLabel", background=p.surface, foreground=p.text,
                    font=fonts.metric_small)


    # KPI strip: a figure sized to be read at a glance without taking the
    # vertical space a display-size number does.
    style.configure("KpiValue.TLabel", background=p.background,
                    foreground=p.text, font=fonts.metric_small)
    style.configure("KpiTrend.TLabel", background=p.background,
                    foreground=p.text_dim, font=fonts.small_bold)
    # Hover surface for a clickable cell that is otherwise flat.
    style.configure("CardHover.TFrame", background=p.surface_alt,
                    relief="flat", borderwidth=0)

    # --- Labels -----------------------------------------------------------
    style.configure("TLabel", background=p.background, foreground=p.text)
    style.configure("Card.TLabel", background=p.background, foreground=p.text)
    style.configure("CardMuted.TLabel", background=p.background, foreground=p.text_muted,
                    font=fonts.small)
    style.configure("CardDim.TLabel", background=p.background, foreground=p.text_dim,
                    font=fonts.small)
    style.configure("Metric.TLabel", background=p.background, foreground=p.text,
                    font=fonts.metric)
    style.configure("Heading.TLabel", background=p.background, foreground=p.text,
                    font=fonts.heading)
    style.configure("CardHeading.TLabel", background=p.background, foreground=p.text,
                    font=fonts.heading)
    # A panel's own name: small, bold and upper-case, so it reads as a label
    # rather than competing with the content underneath it.
    style.configure("CardTitle.TLabel", background=p.background,
                    foreground=p.text_muted, font=fonts.label)
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
                    borderwidth=0, relief="flat", padding=(2, 7))
    style.configure("AuthReveal.TButton", background=p.surface,
                    foreground=p.text_dim, borderwidth=0, relief="flat",
                    font=fonts.small, padding=(6, 2))
    style.map("AuthReveal.TButton",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.accent)])
    style.configure("AuthPrimary.TButton", background=p.accent,
                    foreground="#FFFFFF", borderwidth=0, relief="flat",
                    font=fonts.body_bold, padding=(14, 11))
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
                    padding=(12, 6), relief="flat", font=fonts.body)
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
                    bordercolor=p.border, padding=(10, 5))
    style.map("Ghost.TButton", background=[("active", p.surface_alt)],
              foreground=[("active", p.text)])
    # Section headings above each group of navigation entries.
    # A section label, not a heading: small and quiet, so the entries under it
    # are what the eye lands on. It was previously letter-spaced by injecting
    # spaces between characters, which made a four-letter word wider than the
    # entries it introduced.
    style.configure("NavGroup.TLabel", background=p.surface,
                    foreground=p.text_dim, font=fonts.label)

    # Entries are ~26px rather than ~44px. The rail previously needed its own
    # scrollbar at eleven entries purely because each row was tall enough for
    # two; at this pitch the whole of it fits without one.
    #
    # ``focuscolor=""`` removes ttk's dotted focus ring, which drew a dashed
    # rectangle around whichever entry was clicked last and read as a rendering
    # fault rather than as focus.
    style.configure("Nav.TButton", background=p.surface, foreground=p.text_muted,
                    bordercolor=p.surface, anchor="w", padding=(10, 5),
                    relief="flat", font=fonts.body, borderwidth=0,
                    focuscolor="")
    style.map("Nav.TButton",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.text)])
    # The current page is marked by its accent bar, its lit label and a barely
    # raised ground - not by a saturated filled block, which at eleven entries
    # made the sidebar the loudest thing on screen.
    style.configure("NavActive.TButton", background=p.surface_alt,
                    foreground=p.text, bordercolor=p.surface_alt, anchor="w",
                    padding=(10, 5), relief="flat", font=fonts.body_bold,
                    borderwidth=0, focuscolor="")
    style.map("NavActive.TButton",
              background=[("active", p.surface_alt)],
              foreground=[("active", p.text)])
    # The icon cell beside each entry: a fixed-width square so the labels line
    # up down the rail whatever glyph each screen uses.
    style.configure("NavGlyph.TLabel", background=p.surface,
                    foreground=p.text_dim, font=(fonts.body[0], 11),
                    anchor="center", width=2)
    style.configure("NavGlyphActive.TLabel", background=p.surface_alt,
                    foreground=p.accent, font=(fonts.body[0], 11),
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
                    bordercolor=p.surface, padding=(10, 5), relief="flat",
                    font=fonts.small)
    style.map("Tool.TButton",
              background=[("active", p.surface_hover), ("disabled", p.surface)],
              foreground=[("active", p.text), ("disabled", p.text_dim)])
    style.configure("ToolAccent.TButton", background=p.accent_soft,
                    foreground=p.accent_hover, bordercolor=p.accent_soft,
                    padding=(10, 5), relief="flat", font=fonts.small_bold)
    style.map("ToolAccent.TButton",
              background=[("active", p.accent_dim)],
              foreground=[("active", "#FFFFFF"), ("disabled", p.text_dim)])
    style.configure("Icon.TButton", background=p.surface_alt, foreground=p.text_muted,
                    bordercolor=p.surface_alt, padding=(8, 4), relief="flat")
    style.map("Icon.TButton",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.text)])
    style.configure("HeaderIcon.TButton", background=p.surface_alt,
                    foreground=p.text_muted, bordercolor=p.surface_alt,
                    padding=(9, 5), relief="flat")
    style.map("HeaderIcon.TButton",
              background=[("active", p.surface_hover)],
              foreground=[("active", p.text)])
    style.configure("Search.TButton", background=p.surface, foreground=p.text_dim,
                    bordercolor=p.border, padding=(12, 5), relief="flat",
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
                padding=(8, 2), font=fonts.small_bold,
            )
    style.configure("Badge.TLabel", background=p.accent, foreground="#FFFFFF",
                    padding=(6, 0), font=fonts.small_bold)
    style.configure("BadgeMuted.TLabel", background=p.surface_raised,
                    foreground=p.text_muted, padding=(6, 0), font=fonts.small_bold)
    style.configure("Kbd.TLabel", background=p.surface_raised, foreground=p.text_dim,
                    padding=(6, 2), font=fonts.mono_small)

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
                    padding=6, relief="flat")
    style.map("TEntry", bordercolor=[("focus", p.accent)])
    style.configure("TCombobox", fieldbackground=p.surface_alt, background=p.surface_alt,
                    foreground=p.text, arrowcolor=p.text_muted,
                    bordercolor=p.border_strong, padding=5)
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
    # A toolbar sits on a card, which is a shade lighter than a plain surface;
    # a checkbox using the default background reads as a patch stuck on top.
    style.configure("Toolbar.TCheckbutton", background=p.surface_alt,
                    foreground=p.text_muted, indicatorcolor=p.surface,
                    focuscolor=p.accent, padding=(2, 2))
    style.map("Toolbar.TCheckbutton",
              background=[("active", p.surface_alt)],
              foreground=[("selected", p.text), ("active", p.text)],
              indicatorcolor=[("selected", p.accent)])
    style.configure("TRadiobutton", background=p.surface, foreground=p.text)
    style.configure("TSpinbox", fieldbackground=p.surface_alt, foreground=p.text,
                    bordercolor=p.border_strong, arrowcolor=p.text_muted, padding=4)

    # --- Tables -----------------------------------------------------------
    # Rows are given real height: a security table is read row by row, and a
    # cramped grid is where an analyst loses their place.
    style.configure("Treeview", background=p.surface, fieldbackground=p.surface,
                    foreground=p.text, bordercolor=p.border,
                    rowheight=METRICS.row_height,
                    font=fonts.body, relief="flat", borderwidth=0)
    style.map("Treeview",
              background=[("selected", p.accent_dim)],
              foreground=[("selected", "#FFFFFF")])
    # The heading shares the table's own fill and is separated from the rows
    # by a rule, so a table needs no outer border to be legible.
    style.configure("Treeview.Heading", background=p.surface,
                    foreground=p.text_muted, relief="flat", padding=(10, 7),
                    font=fonts.label, borderwidth=0)
    style.layout("Treeview.Heading", [
        ("Treeheading.cell", {"sticky": "nswe"}),
        ("Treeheading.border", {"sticky": "nswe", "children": [
            ("Treeheading.padding", {"sticky": "nswe", "children": [
                ("Treeheading.image", {"side": "right", "sticky": ""}),
                ("Treeheading.text", {"sticky": "we"}),
            ]}),
        ]}),
    ])
    style.map("Treeview.Heading",
              background=[("active", p.surface_alt)],
              foreground=[("active", p.text)])
    style.configure("Mono.Treeview", font=fonts.mono_small,
                    rowheight=METRICS.row_height - 2,
                    background=p.surface, fieldbackground=p.surface,
                    foreground=p.text, borderwidth=0)
    style.configure("Mono.Treeview.Heading", background=p.surface_sunken,
                    foreground=p.text_dim, relief="flat", padding=(10, 7),
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
    # Compact tabs. The selected one is carried by an accent underline rather
    # than by a raised slab, so the active tab is obvious at a glance without
    # each tab costing a row of height.
    style.configure("TNotebook.Tab", background=p.background,
                    foreground=p.text_dim, padding=(14, 6), font=fonts.small_bold,
                    borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", p.background), ("active", p.surface_sunken)],
              foreground=[("selected", p.accent), ("active", p.text)],
              bordercolor=[("selected", p.accent)],
              lightcolor=[("selected", p.accent)],
              darkcolor=[("selected", p.accent)])
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
