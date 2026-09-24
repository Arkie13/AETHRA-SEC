"""The dark/light theme system (§45).

Dark is the default because this console is watched for hours in a dim room.
Light is a designed palette rather than an inversion, so both are checked for
real contrast rather than assumed to be readable.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import re
from dataclasses import fields

import pytest

from aethra_sec.ui import theme as theme_module
from aethra_sec.ui.theme import (
    DARK_PALETTE,
    DEFAULT_THEME,
    LIGHT_PALETTE,
    PALETTE,
    SEVERITY_COLOURS,
    SEVERITY_GLYPHS,
    THEMES,
    Palette,
    current_theme,
    set_theme,
    text_on,
)

UI_ROOT = pathlib.Path(theme_module.__file__).parent


@pytest.fixture(autouse=True)
def _restore_theme():
    """Never leave another test looking at the wrong palette."""
    before = current_theme()
    yield
    set_theme(before)


def _channel(value: float) -> float:
    """One sRGB channel linearised, per the WCAG definition."""
    value /= 255.0
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def luminance(colour: str) -> float:
    """Relative luminance of a ``#rrggbb`` colour."""
    raw = colour.lstrip("#")
    r, g, b = (int(raw[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast(one: str, two: str) -> float:
    """WCAG contrast ratio between two colours, 1.0 to 21.0."""
    a, b = sorted((luminance(one), luminance(two)), reverse=True)
    return (a + 0.05) / (b + 0.05)


class TestThemeSwitching:
    """One palette object, swapped in place."""

    def test_dark_is_the_default(self) -> None:
        assert DEFAULT_THEME == "dark"
        assert THEMES[DEFAULT_THEME] is DARK_PALETTE

    def test_switching_keeps_the_same_palette_object(self) -> None:
        """Identity matters: thirty-odd modules hold this exact reference.

        Rebinding the module attribute would leave every one of them reading
        the old theme, which is why the tokens are replaced in place.
        """
        before = id(PALETTE)
        set_theme("light")
        assert id(PALETTE) == before
        set_theme("dark")
        assert id(PALETTE) == before

    def test_switching_replaces_every_token(self) -> None:
        set_theme("light")
        for field_ in fields(Palette):
            assert getattr(PALETTE, field_.name) == getattr(
                LIGHT_PALETTE, field_.name
            ), field_.name

    def test_an_unknown_theme_falls_back_rather_than_half_applying(self) -> None:
        set_theme("light")
        assert set_theme("solarized-neon") == DEFAULT_THEME
        assert PALETTE.background == DARK_PALETTE.background

    def test_derived_colour_maps_follow_the_theme(self) -> None:
        """These are built from the palette, so they must be rebuilt with it."""
        set_theme("light")
        assert SEVERITY_COLOURS["CRITICAL"] == LIGHT_PALETTE.critical
        set_theme("dark")
        assert SEVERITY_COLOURS["CRITICAL"] == DARK_PALETTE.critical


class TestLightIsDesignedNotInverted:
    """A light theme has to be picked, not computed from the dark one."""

    def test_light_surfaces_are_light_and_dark_surfaces_are_dark(self) -> None:
        assert luminance(LIGHT_PALETTE.background) > 0.7
        assert luminance(LIGHT_PALETTE.surface) > 0.8
        assert luminance(DARK_PALETTE.background) < 0.05
        assert luminance(DARK_PALETTE.surface) < 0.08

    def test_light_text_is_dark_and_dark_text_is_light(self) -> None:
        assert luminance(LIGHT_PALETTE.text) < 0.05
        assert luminance(DARK_PALETTE.text) > 0.7

    def test_the_light_theme_is_not_a_channel_inversion(self) -> None:
        """Inverting gives muddy mid-greys; these were chosen instead."""
        def inverted(colour: str) -> str:
            raw = colour.lstrip("#")
            return "#" + "".join(
                f"{255 - int(raw[i:i + 2], 16):02X}" for i in (0, 2, 4)
            )

        assert LIGHT_PALETTE.background.upper() != inverted(DARK_PALETTE.background)
        assert LIGHT_PALETTE.critical.upper() != inverted(DARK_PALETTE.critical)

    def test_severity_is_re_picked_darker_for_a_light_page(self) -> None:
        """A colour tuned for near-black glows against white."""
        for name in ("critical", "high", "medium", "low", "info"):
            light = getattr(LIGHT_PALETTE, name)
            dark = getattr(DARK_PALETTE, name)
            assert luminance(light) < luminance(dark), name


class TestContrast:
    """Both themes must actually be readable."""

    #: WCAG AA for body text.
    BODY = 4.5
    #: WCAG AA for large/bold text and non-text indicators.
    LARGE = 3.0

    @pytest.mark.parametrize("palette", [DARK_PALETTE, LIGHT_PALETTE])
    def test_primary_text_passes_on_every_surface(self, palette: Palette) -> None:
        for surface in (
            palette.background, palette.surface, palette.surface_alt,
            palette.surface_raised, palette.surface_sunken,
        ):
            assert contrast(palette.text, surface) >= self.BODY, surface

    @pytest.mark.parametrize("palette", [DARK_PALETTE, LIGHT_PALETTE])
    def test_secondary_text_stays_readable(self, palette: Palette) -> None:
        for surface in (palette.background, palette.surface, palette.surface_alt):
            assert contrast(palette.text_muted, surface) >= self.BODY, surface

    @pytest.mark.parametrize("palette", [DARK_PALETTE, LIGHT_PALETTE])
    def test_muted_text_clears_the_large_text_bar(self, palette: Palette) -> None:
        """The dimmest tier is used for captions, never for body copy."""
        for surface in (palette.background, palette.surface):
            assert contrast(palette.text_dim, surface) >= self.LARGE, surface

    @pytest.mark.parametrize("palette", [DARK_PALETTE, LIGHT_PALETTE])
    def test_every_severity_colour_is_legible_on_its_surfaces(
        self, palette: Palette
    ) -> None:
        for name in ("critical", "high", "medium", "low", "info", "ok"):
            colour = getattr(palette, name)
            for surface in (palette.background, palette.surface):
                assert contrast(colour, surface) >= self.LARGE, f"{name} on {surface}"

    @pytest.mark.parametrize("palette", [DARK_PALETTE, LIGHT_PALETTE])
    def test_the_accent_is_legible(self, palette: Palette) -> None:
        for surface in (palette.background, palette.surface):
            assert contrast(palette.accent, surface) >= self.LARGE, surface

    @pytest.mark.parametrize("theme", ["dark", "light"])
    def test_text_on_a_severity_fill_is_legible(self, theme: str) -> None:
        """Chips and badges draw text straight onto a severity colour.

        Severity fills span a wide luminance range - a red is dark, an amber
        is bright - so no single fixed colour is legible on all of them. White
        on the dark theme's HIGH amber measures 2.4:1; :func:`text_on` picks
        the readable extreme instead.
        """
        set_theme(theme)
        palette = THEMES[theme]
        for name in ("critical", "high", "medium", "low", "accent", "ok"):
            fill = getattr(palette, name)
            assert contrast(text_on(fill), fill) >= 3.0, f"{theme}/{name}"

    @pytest.mark.parametrize("palette", [DARK_PALETTE, LIGHT_PALETTE])
    def test_a_banded_row_still_carries_body_text(self, palette: Palette) -> None:
        for fill in (palette.critical_soft, palette.high_soft):
            assert contrast(palette.text, fill) >= self.BODY, fill

    @pytest.mark.parametrize("palette", [DARK_PALETTE, LIGHT_PALETTE])
    def test_chart_series_are_distinguishable_from_the_plot_surface(
        self, palette: Palette
    ) -> None:
        """A chart label or line that vanishes into its own background is a
        broken chart, which is the failure a theme switch most often causes."""
        for colour in palette.series:
            assert contrast(colour, palette.surface) >= 1.9, colour

    @pytest.mark.parametrize("palette", [DARK_PALETTE, LIGHT_PALETTE])
    def test_borders_are_visible_without_shouting(self, palette: Palette) -> None:
        """A hairline should be found when looked for, not seen when not."""
        ratio = contrast(palette.border, palette.surface)
        assert 1.03 <= ratio <= 2.2, ratio


class TestSeverityIsNotColourAlone:
    """Colour is never the only carrier of severity."""

    def test_every_severity_has_a_glyph(self) -> None:
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert SEVERITY_GLYPHS.get(name), name

    def test_the_glyphs_differ_from_each_other(self) -> None:
        glyphs = [SEVERITY_GLYPHS[n] for n in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        assert len(set(glyphs)) == len(glyphs)


class TestNoThemeCanBeFrozenAtImportTime:
    """The bug class that made a theme switch leave widgets behind."""

    def test_no_palette_value_is_used_as_a_default_argument(self) -> None:
        """A default argument is evaluated once, when the module is imported.

        ``def __init__(self, *, background: str = PALETTE.background)`` therefore
        pins whichever theme was active at import for the life of the process,
        and every widget built from that default keeps the old colour through a
        switch. Resolve inside the body instead.
        """
        offenders: list[str] = []
        for path in UI_ROOT.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                args = node.args
                for default in list(args.defaults) + list(args.kw_defaults):
                    if default is None:
                        continue
                    for sub in ast.walk(default):
                        if (
                            isinstance(sub, ast.Attribute)
                            and isinstance(sub.value, ast.Name)
                            and sub.value.id == "PALETTE"
                        ):
                            offenders.append(
                                f"{path.name}:{node.lineno} {node.name}"
                            )
        assert not offenders, (
            "palette values frozen at import time: " + ", ".join(sorted(set(offenders)))
        )

    def test_no_module_level_constant_copies_a_palette_value(self) -> None:
        """A module global built from the palette is a snapshot, not a token."""
        pattern = re.compile(r"^[A-Z_][A-Z_0-9]*\s*(?::[^=]+)?=\s*PALETTE\.", re.M)
        offenders = [
            path.name
            for path in UI_ROOT.rglob("*.py")
            if pattern.search(path.read_text(encoding="utf-8"))
        ]
        assert not offenders, offenders


class TestOneInterface:
    """There is one set of screens; only the tokens change."""

    def test_no_theme_specific_screen_or_widget_exists(self) -> None:
        names = [p.name.lower() for p in UI_ROOT.rglob("*.py")]
        assert not [
            n for n in names
            if n.startswith(("dark", "light")) and n != "light.py"
        ]

    def test_apply_theme_reads_the_live_palette(self) -> None:
        """It must not close over a palette captured when it was defined."""
        source = inspect.getsource(theme_module.apply_theme)
        assert "PALETTE" in source
