"""Desktop launcher and icon (§49).

The launcher's whole job is to work from wherever the folder happens to be, so
what is pinned here is the absence of baked-in paths and the presence of the
pieces the shortcut needs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = PROJECT_ROOT / "launcher"
SHORTCUT_SCRIPT = LAUNCHER / "create_shortcut.ps1"
ICON = PROJECT_ROOT / "assets" / "aethra-sec.ico"


def _code_only(path: Path) -> str:
    """Script text with comments stripped.

    The scripts explain the traps they avoid, so a naive substring search would
    find the very pattern the comment warns against.
    """
    lines: list[str] = []
    in_block = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("<#"):
            in_block = True
        if in_block:
            if line.endswith("#>"):
                in_block = False
            continue
        if line.startswith("#"):
            continue
        lines.append(raw)
    return chr(10).join(lines)


class TestFilesArePresent:
    """The structure the shortcut depends on."""

    def test_the_launcher_script_exists(self) -> None:
        assert SHORTCUT_SCRIPT.is_file()

    def test_the_icon_generator_exists(self) -> None:
        assert (LAUNCHER / "make_icon.py").is_file()

    def test_the_icon_is_committed(self) -> None:
        """A fresh clone must have an icon before anything is generated."""
        assert ICON.is_file()
        assert ICON.stat().st_size > 1000

    def test_run_bat_is_untouched_and_still_the_entry_point(self) -> None:
        """The shortcut wraps run.bat; it does not replace it."""
        text = (PROJECT_ROOT / "run.bat").read_text(encoding="utf-8", errors="replace")
        assert "aethra_sec.main" in text
        # pushd %~dp0 is what makes run.bat independent of the caller's cwd.
        assert "%~dp0" in text


class TestNoHardCodedPaths:
    """Moving the folder must not break the launcher."""

    def test_the_script_contains_no_absolute_user_path(self) -> None:
        text = SHORTCUT_SCRIPT.read_text(encoding="utf-8")
        # A literal drive path would pin the launcher to one machine.
        offenders = re.findall(r"[A-Za-z]:\\\\(?!\\)", text)
        assert not offenders, offenders
        assert "C:\\Users" not in text
        assert "AETHRA-SECNEW" not in text

    def test_paths_are_derived_from_the_script_location(self) -> None:
        text = SHORTCUT_SCRIPT.read_text(encoding="utf-8")
        assert "$MyInvocation.MyCommand.Path" in text
        assert "Join-Path" in text

    def test_the_desktop_is_resolved_not_assumed(self) -> None:
        """A OneDrive-redirected desktop is not %USERPROFILE%\\Desktop.

        Writing to the literal path would put the shortcut somewhere the
        operator never sees. This machine's desktop is redirected, which is how
        the bug would have shipped unnoticed.
        """
        code = _code_only(SHORTCUT_SCRIPT)
        assert "GetFolderPath('Desktop')" in code
        # Scanned with comments stripped: the script explains why it avoids
        # this path, and a naive search finds the warning itself.
        assert "USERPROFILE" not in code

    def test_the_icon_generator_resolves_its_own_root(self) -> None:
        text = (LAUNCHER / "make_icon.py").read_text(encoding="utf-8")
        assert "Path(__file__).resolve().parent.parent" in text
        assert "C:\\" not in text


class TestShortcutBehaviour:
    """Properties the .lnk must carry."""

    def test_it_starts_minimised_rather_than_hidden(self) -> None:
        """Hiding the console entirely would swallow run.bat's error pause."""
        text = SHORTCUT_SCRIPT.read_text(encoding="utf-8")
        assert "WindowStyle      = 7" in text or "WindowStyle = 7" in text

    def test_it_sets_a_working_directory(self) -> None:
        text = SHORTCUT_SCRIPT.read_text(encoding="utf-8")
        assert "WorkingDirectory" in text

    def test_it_overwrites_rather_than_duplicating(self) -> None:
        """Re-running setup must not leave AETHRA-SEC (1).lnk behind."""
        text = SHORTCUT_SCRIPT.read_text(encoding="utf-8")
        assert "CreateShortcut($shortcutPath)" in text

    def test_it_fails_loudly_when_run_bat_is_absent(self) -> None:
        text = SHORTCUT_SCRIPT.read_text(encoding="utf-8")
        assert "Test-Path -LiteralPath $runBat" in text
        assert "exit 2" in text


class TestSetupIntegration:
    """One setup path, not a competing one."""

    def test_setup_bat_creates_the_shortcut(self) -> None:
        text = (PROJECT_ROOT / "setup.bat").read_text(
            encoding="utf-8", errors="replace"
        )
        assert "create_shortcut.ps1" in text
        assert "make_icon.py" in text

    def test_a_shortcut_failure_does_not_fail_setup(self) -> None:
        """A missing shortcut is a nuisance; run.bat still works."""
        text = (PROJECT_ROOT / "setup.bat").read_text(
            encoding="utf-8", errors="replace"
        )
        assert "[WARN] The desktop shortcut could not be created." in text


class TestIconMatchesTheApplicationLogo:
    """The desktop icon must be the mark the application draws."""

    def test_the_icon_holds_every_size_windows_asks_for(self) -> None:
        pillow = pytest.importorskip("PIL.Image")
        with pillow.open(ICON) as image:
            stored = {tuple(size) for size in image.info["sizes"]}
        for expected in ((16, 16), (32, 32), (48, 48), (256, 256)):
            assert expected in stored, f"{expected} missing from the icon"

    def test_the_icon_has_a_transparent_ground(self) -> None:
        """A baked-in background would show as a tile on the wallpaper."""
        pillow = pytest.importorskip("PIL.Image")
        with pillow.open(ICON) as image:
            image.size = (256, 256)
            image.load()
            corner = image.convert("RGBA").getpixel((2, 2))
        assert corner[3] == 0, "the icon corner is not transparent"

    def test_the_generator_uses_the_shared_geometry(self) -> None:
        """Not a second copy of the coordinates that can drift."""
        text = (LAUNCHER / "make_icon.py").read_text(encoding="utf-8")
        assert "from aethra_sec.ui.brand import" in text
        assert "logo_points" in text

    def test_the_sign_in_screen_uses_the_same_geometry(self) -> None:
        text = (PROJECT_ROOT / "aethra_sec" / "ui" / "login.py").read_text(
            encoding="utf-8"
        )
        assert "flat_logo_points" in text
        # The old inline coordinates must be gone, or the two can diverge.
        assert "32, 4, 60, 16, 60, 36" not in text

    def test_the_shield_scales_linearly(self) -> None:
        from aethra_sec.ui.brand import logo_points

        small = logo_points(16)
        large = logo_points(64)
        assert len(small) == len(large)
        for (sx, sy), (lx, ly) in zip(small, large, strict=True):
            assert sx == pytest.approx(lx / 4)
            assert sy == pytest.approx(ly / 4)
