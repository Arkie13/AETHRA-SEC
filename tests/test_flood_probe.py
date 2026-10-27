"""The flood probe measures a freeze instead of asking anyone to describe one.

A report that the application "became unresponsive" is not something the code
can be changed against. These tests hold the two properties that make the probe
worth trusting when it is pointed at a real authorised flood:

* it is **inert** unless explicitly armed, so an ordinary run pays nothing and
  no operator is silently profiled;
* it **actually detects a stall**, verified by blocking the Tk loop for a known
  interval and reading the number back out of the file.

The second is the one that matters. A diagnostic that quietly fails to see the
event it was written for is worse than none, because the absence of a spike
would be read as evidence that nothing happened.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from aethra_sec.diagnostics import flood_probe


class _Settings:
    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir


class _Context:
    """Only what the probe reads. Nothing is writable."""

    def __init__(self, log_dir: Path) -> None:
        self.settings = _Settings(log_dir)
        self.capture = None
        self.db = None


@pytest.fixture
def tk_root():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - headless CI
        pytest.skip(f"no display: {exc}")
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Inert by default
# ---------------------------------------------------------------------------
class TestItIsOffUnlessArmed:
    def test_it_is_disabled_without_the_environment_variable(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.delenv(flood_probe.ENV_FLAG, raising=False)
        assert flood_probe.enabled() is False

    def test_an_empty_value_is_not_armed(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.setenv(flood_probe.ENV_FLAG, "   ")
        assert flood_probe.enabled() is False

    def test_install_returns_nothing_when_not_armed(self, monkeypatch, tmp_path) -> None:  # noqa: ANN001
        monkeypatch.delenv(flood_probe.ENV_FLAG, raising=False)
        assert flood_probe.install(object(), _Context(tmp_path)) is None

    def test_no_file_is_written_when_not_armed(self, monkeypatch, tmp_path) -> None:  # noqa: ANN001
        monkeypatch.delenv(flood_probe.ENV_FLAG, raising=False)
        flood_probe.install(object(), _Context(tmp_path))
        assert list(tmp_path.glob("flood_probe_*.csv")) == []

    def test_an_unreadable_log_dir_falls_back_instead_of_raising(
        self, monkeypatch, tmp_path
    ) -> None:  # noqa: ANN001
        """A diagnostic must not be why the console will not open."""
        monkeypatch.setenv(flood_probe.ENV_FLAG, "1")
        monkeypatch.chdir(tmp_path)  # the fallback is the relative "logs"

        class Exploding:
            @property
            def settings(self):  # noqa: ANN202
                raise RuntimeError("boom")

        probe = flood_probe.install(object(), Exploding())
        assert probe is not None, "a readable default should still be probed"
        probe.stop()
        assert probe.path.parent == Path("logs")

    def test_install_returns_none_when_the_probe_cannot_be_built(
        self, monkeypatch, tmp_path
    ) -> None:  # noqa: ANN001
        """The last resort: no probe at all, rather than a failed startup."""
        monkeypatch.setenv(flood_probe.ENV_FLAG, "1")

        def explode(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
            raise RuntimeError("cannot open the file")

        monkeypatch.setattr(flood_probe, "FloodProbe", explode)
        assert flood_probe.install(object(), _Context(tmp_path)) is None


# ---------------------------------------------------------------------------
# It observes; it does not steer
# ---------------------------------------------------------------------------
class TestItOnlyObserves:
    def test_the_probe_never_writes_to_the_database(self) -> None:
        import inspect

        source = inspect.getsource(flood_probe)
        for statement in ("INSERT", "UPDATE ", "DELETE FROM", "execute("):
            assert statement not in source, (
                f"{statement!r} would make the probe a participant in the run "
                "it is supposed to be measuring"
            )

    def test_the_only_query_is_a_round_trip_ping(self) -> None:
        import inspect

        body = inspect.getsource(flood_probe.FloodProbe._ping_database)
        assert "SELECT 1 AS ok" in body

    def test_the_database_is_not_sampled_on_the_tk_thread(self) -> None:
        """A blocking write is a prime suspect; measuring it on the Tk thread
        would add the stall to the number meant to reveal it."""
        import inspect

        worker = inspect.getsource(flood_probe.FloodProbe._sample_system)
        assert "_ping_database" in worker
        tick = inspect.getsource(flood_probe.FloodProbe._tick)
        assert "_ping_database" not in tick


# ---------------------------------------------------------------------------
# It detects a real stall
# ---------------------------------------------------------------------------
class TestItDetectsAStall:
    def test_a_blocked_tk_loop_is_recorded_as_lag(self, monkeypatch, tmp_path, tk_root) -> None:  # noqa: ANN001
        """Block the loop for a known interval and read the number back."""
        monkeypatch.setenv(flood_probe.ENV_FLAG, "1")
        probe = flood_probe.install(tk_root, _Context(tmp_path))
        assert probe is not None

        stall_seconds = 1.2
        tk_root.after(400, lambda: time.sleep(stall_seconds))
        tk_root.after(2600, tk_root.quit)
        tk_root.mainloop()
        probe.stop()

        rows = probe.path.read_text(encoding="utf-8").strip().splitlines()
        header = rows[0].split(",")
        column = header.index("tk_lag_max_ms")
        worst = max(float(r.split(",")[column]) for r in rows[1:])

        floor_ms = stall_seconds * 1000 - flood_probe.TICK_MS * 2
        assert worst >= floor_ms, (
            f"a {stall_seconds}s freeze was recorded as only {worst:.0f}ms; "
            "the probe would miss the event it exists to catch"
        )

    def test_an_idle_loop_shows_almost_no_lag(self, monkeypatch, tmp_path, tk_root) -> None:  # noqa: ANN001
        """Otherwise every run would look like a freeze."""
        monkeypatch.setenv(flood_probe.ENV_FLAG, "1")
        probe = flood_probe.install(tk_root, _Context(tmp_path))
        tk_root.after(2300, tk_root.quit)
        tk_root.mainloop()
        probe.stop()

        rows = probe.path.read_text(encoding="utf-8").strip().splitlines()
        column = rows[0].split(",").index("tk_lag_max_ms")
        worst = max(float(r.split(",")[column]) for r in rows[1:])
        assert worst < 500, f"an idle loop reported {worst:.0f}ms of lag"

    def test_the_worst_tick_in_a_window_is_kept_not_the_last(self) -> None:
        """A stall between two samples would otherwise be invisible."""
        import inspect

        body = inspect.getsource(flood_probe.FloodProbe._tick)
        assert "max(self._lag_max" in body

    def test_the_header_names_every_column_it_writes(self, monkeypatch, tmp_path, tk_root) -> None:  # noqa: ANN001
        monkeypatch.setenv(flood_probe.ENV_FLAG, "1")
        probe = flood_probe.install(tk_root, _Context(tmp_path))
        tk_root.after(1300, tk_root.quit)
        tk_root.mainloop()
        probe.stop()

        rows = probe.path.read_text(encoding="utf-8").strip().splitlines()
        assert rows[0].split(",") == list(flood_probe.COLUMNS)
        for row in rows[1:]:
            assert len(row.split(",")) == len(flood_probe.COLUMNS)

    def test_missing_services_do_not_stop_the_recording(self, monkeypatch, tmp_path, tk_root) -> None:  # noqa: ANN001
        """The probe may be armed before capture has started."""
        monkeypatch.setenv(flood_probe.ENV_FLAG, "1")
        probe = flood_probe.install(tk_root, _Context(tmp_path))
        tk_root.after(1300, tk_root.quit)
        tk_root.mainloop()
        probe.stop()
        assert len(probe.path.read_text(encoding="utf-8").strip().splitlines()) >= 2


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------
class TestItIsWiredIntoTheConsole:
    def test_the_console_installs_and_stops_it(self) -> None:
        import inspect

        from aethra_sec.ui import app

        body = inspect.getsource(app.run_console)
        assert "flood_probe.install(" in body
        assert "probe.stop()" in body

    def test_the_probe_is_stopped_even_if_the_loop_raises(self) -> None:
        import inspect

        from aethra_sec.ui import app

        body = inspect.getsource(app.run_console)
        assert "finally:" in body, (
            "an exception out of mainloop would leave the file handle open"
        )
