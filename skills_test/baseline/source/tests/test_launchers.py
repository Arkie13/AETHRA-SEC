"""The launcher scripts must stay usable on the platform they target.

``run.bat`` and ``setup.bat`` are the first thing a Windows operator touches,
and they cannot be executed here, so these tests check the properties that
actually break them: CRLF line endings, escaped parentheses inside ``echo``
lines, matched ``IF`` blocks, and the commands they invoke really existing.

``run.sh`` is executed for real by the shell-based checks in CI and by hand;
here it is only checked for the same structural properties.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BATCH_FILES = ("run.bat", "setup.bat")


@pytest.fixture(scope="module")
def batch_text() -> dict[str, str]:
    """The batch launchers, decoded."""
    texts = {}
    for name in BATCH_FILES:
        path = PROJECT_ROOT / name
        assert path.exists(), f"{name} is missing"
        texts[name] = path.read_bytes().decode("ascii")
    return texts


class TestBatchFilesAreWindowsSafe:
    """Properties cmd.exe depends on."""

    @pytest.mark.parametrize("name", BATCH_FILES)
    def test_crlf_line_endings(self, name: str) -> None:
        """cmd.exe can mis-parse a multi-line IF block written with bare LF."""
        raw = (PROJECT_ROOT / name).read_bytes()
        assert b"\r\n" in raw, f"{name} has no CRLF endings"
        assert not re.search(rb"(?<!\r)\n", raw), f"{name} has bare LF endings"

    @pytest.mark.parametrize("name", BATCH_FILES)
    def test_ascii_only(self, name: str) -> None:
        """A non-ASCII byte renders as mojibake in the default code page."""
        (PROJECT_ROOT / name).read_bytes().decode("ascii")

    @pytest.mark.parametrize("name", BATCH_FILES)
    def test_parentheses_in_echo_are_escaped(
        self, batch_text: dict[str, str], name: str
    ) -> None:
        """An unescaped ( or ) in an echo closes the enclosing IF block."""
        for number, line in enumerate(batch_text[name].splitlines(), start=1):
            stripped = line.strip()
            if not stripped.lower().startswith("echo "):
                continue
            without_escaped = stripped.replace("^(", "").replace("^)", "")
            assert "(" not in without_escaped and ")" not in without_escaped, (
                f"{name}:{number} has an unescaped parenthesis in an echo"
            )

    @pytest.mark.parametrize("name", BATCH_FILES)
    def test_if_blocks_balance(self, batch_text: dict[str, str], name: str) -> None:
        """Every block opened with ( is closed."""
        depth = 0
        for number, line in enumerate(batch_text[name].splitlines(), start=1):
            stripped = line.strip()
            if stripped.lower().startswith(("rem ", "echo ")) or stripped == "rem":
                continue
            depth += stripped.count("(") - stripped.count(")")
            assert depth >= 0, f"{name}:{number} closes a block that is not open"
        assert depth == 0, f"{name} leaves {depth} block(s) unclosed"

    @pytest.mark.parametrize("name", BATCH_FILES)
    def test_every_goto_has_a_label(self, batch_text: dict[str, str], name: str) -> None:
        """A goto to a missing label silently ends the script."""
        text = batch_text[name]
        labels = set(re.findall(r"(?m)^:(\w+)", text))
        for target in re.findall(r"(?mi)^\s*goto\s+:?(\w+)", text):
            assert target in labels, f"{name}: 'goto {target}' has no matching label"

    @pytest.mark.parametrize("name", BATCH_FILES)
    def test_runs_from_its_own_directory(
        self, batch_text: dict[str, str], name: str
    ) -> None:
        """Double-clicking from Explorer must not depend on the working directory."""
        assert 'pushd "%~dp0"' in batch_text[name]
        assert "popd" in batch_text[name]


class TestLaunchersInvokeRealEntryPoints:
    """Whatever the launchers call must exist in this repository."""

    def test_run_bat_starts_the_application(self, batch_text: dict[str, str]) -> None:
        """run.bat launches the module entry point and passes arguments on."""
        text = batch_text["run.bat"]
        assert "-m aethra_sec.main %*" in text
        assert (PROJECT_ROOT / "aethra_sec" / "main.py").exists()

    def test_setup_bat_runs_the_shared_setup(
        self, batch_text: dict[str, str]
    ) -> None:
        """setup.bat drives the same setup the installed application runs.

        It used to call three separate scripts, each with its own copy of a
        step. Those steps now live in :mod:`aethra_sec.setup`, and setup.bat
        invokes that - which is what stops the console path and the wizard path
        from drifting into producing different installations.
        """
        text = batch_text["setup.bat"]
        for entry_point in ("aethra_sec.setup.console", "aethra_sec.main --setup"):
            assert entry_point in text, f"setup.bat does not run {entry_point}"
        assert "requirements.txt" in text
        assert (PROJECT_ROOT / "requirements.txt").exists()

    def test_the_entry_points_setup_bat_names_are_importable(self) -> None:
        """A batch file naming a module that does not exist fails at run time."""
        import importlib

        for module in ("aethra_sec.setup.console", "aethra_sec.main"):
            assert importlib.import_module(module) is not None

    def test_the_sql_fallback_is_still_offered_somewhere_reachable(self) -> None:
        """When the account may not create a database, the SQL file is named.

        The message moved out of setup.bat and into the provisioning failure
        path, so it now reaches the wizard, the console and the installed
        application alike rather than only whoever ran the batch file.
        """
        import inspect

        from aethra_sec.setup import provisioning

        source = inspect.getsource(provisioning)
        assert "sql/aethra_sec_schema.sql" in source
        assert (PROJECT_ROOT / "sql" / "aethra_sec_schema.sql").exists()

    def test_run_sh_matches(self) -> None:
        """The Linux launcher runs the same entry point and stays LF."""
        raw = (PROJECT_ROOT / "run.sh").read_bytes()
        assert b"\r\n" not in raw, "run.sh must keep LF endings"
        text = raw.decode("utf-8")
        assert "-m aethra_sec.main" in text
        assert text.startswith("#!/usr/bin/env bash")


class TestLaunchersCarryNoSecrets:
    """A launcher is committed, so it must never hold a credential."""

    @pytest.mark.parametrize("name", [*BATCH_FILES, "run.sh"])
    def test_no_password_literals(self, name: str) -> None:
        """No password, and no credential-bearing command line."""
        text = (PROJECT_ROOT / name).read_bytes().decode("utf-8").lower()
        assert "aethra_db_password=" not in text
        assert "--password" not in text
        assert not re.search(r"identified by\s+'", text)
