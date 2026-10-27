"""The persistent notification siren (stability revision, 16 Oct 2026).

The sound a detection popup makes must loop while the popup is open and stop
the instant CHECK or CLOSE is pressed - the behaviour Part 6/7 of the brief
requires and the old single-clip design did not provide. These exercise the
loop controller, the service's begin/end API, and the popup hooks that drive
them. No real sound device is used; the player is a counting double.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from aethra_sec.services.audio_alert_service import AudioAlertService, _PersistentSiren


class _Player:
    """A play function double: counts calls, can be told to fail."""

    def __init__(self) -> None:
        self.calls = 0
        self.fail = False
        self._lock = threading.Lock()

    def __call__(self) -> bool:
        with self._lock:
            self.calls += 1
            if self.fail:
                raise RuntimeError("injected sound-device failure")
        return True

    @property
    def count(self) -> int:
        with self._lock:
            return self.calls


def _wait_until(predicate, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


# ---------------------------------------------------------------------------
# TEST D - the sound persists until acknowledgement
# ---------------------------------------------------------------------------
class TestD_SoundPersists:
    def test_it_plays_at_once_and_keeps_looping_until_stopped(self) -> None:
        player = _Player()
        siren = _PersistentSiren(player, interval=0.05)
        token = object()
        siren.start(token)
        # Immediate first play, then more without any further input.
        assert _wait_until(lambda: player.count >= 1)
        assert _wait_until(lambda: player.count >= 4), "a single clip did not end the sound"
        assert siren.active_token is token
        siren.stop()

    def test_one_clip_ending_is_not_the_end_of_the_sound(self) -> None:
        player = _Player()
        siren = _PersistentSiren(player, interval=0.08)
        siren.start(object())
        assert _wait_until(lambda: player.count >= 3, timeout=3.0), "sound stopped early"
        first = player.count
        assert _wait_until(lambda: player.count > first, timeout=2.0),             "the sound stopped on its own"
        siren.stop()


# ---------------------------------------------------------------------------
# TEST E / F - stop (CHECK / CLOSE) stops promptly and does not restart
# ---------------------------------------------------------------------------
class TestEF_StopPromptlyAndStayStopped:
    def test_stop_halts_the_loop_quickly(self) -> None:
        player = _Player()
        siren = _PersistentSiren(player, interval=0.05)
        siren.start(object())
        assert _wait_until(lambda: player.count >= 1)
        siren.stop()
        settled = player.count
        time.sleep(0.3)
        # At most one in-flight clip may land after stop; never a continuing loop.
        assert player.count <= settled + 1, "the sound kept playing after stop"
        assert siren.active_token is None

    def test_a_delayed_stop_callback_does_not_restart_it(self) -> None:
        player = _Player()
        siren = _PersistentSiren(player, interval=0.05)
        token = object()
        siren.start(token)
        siren.stop(token)
        time.sleep(0.2)
        before = player.count
        siren.stop(token)      # a second CLOSE after CHECK: nothing to do
        siren.stop(object())   # a stale token: nothing to do
        time.sleep(0.2)
        assert player.count == before


# ---------------------------------------------------------------------------
# TEST G - acknowledgement race conditions
# ---------------------------------------------------------------------------
class TestG_Races:
    def test_concurrent_stops_are_safe_and_leave_it_stopped(self) -> None:
        player = _Player()
        siren = _PersistentSiren(player, interval=0.02)
        siren.start(object())
        assert _wait_until(lambda: player.count >= 1)
        threads = [threading.Thread(target=siren.stop) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert siren.active_token is None
        settled = player.count
        time.sleep(0.2)
        assert player.count <= settled + 1

    def test_a_new_popup_supersedes_the_old_with_one_siren(self) -> None:
        player = _Player()
        siren = _PersistentSiren(player, interval=0.03)
        a, b = object(), object()
        siren.start(a)
        assert _wait_until(lambda: player.count >= 1)
        siren.start(b)  # escalation / next popup
        assert siren.active_token is b
        # Stopping with the OLD token must not silence the new siren.
        assert siren.stop(a) is False
        assert siren.active_token is b
        assert _wait_until(lambda: player.count >= 3)
        siren.stop(b)
        assert siren.active_token is None


# ---------------------------------------------------------------------------
# TEST I - a sound failure does not crash or stop the loop
# ---------------------------------------------------------------------------
class TestI_SoundFailure:
    def test_a_failing_player_keeps_the_loop_alive_and_crashes_nothing(self) -> None:
        player = _Player()
        player.fail = True
        siren = _PersistentSiren(player, interval=0.03)
        siren.start(object())
        # It keeps trying (and failing) without raising out of the thread.
        assert _wait_until(lambda: player.count >= 3)
        assert siren.active_token is not None
        player.fail = False
        siren.stop()


# ---------------------------------------------------------------------------
# Service-level: eligibility, and begin/end wiring
# ---------------------------------------------------------------------------
class _Settings:
    def __init__(self, **v):
        self._v = {"notifications.sound_enabled": True,
                   "notifications.sound_min_level": "WARNING", **v}

    def get(self, k, d=None):
        return self._v.get(k, d)

    def get_bool(self, k, d=False):
        return bool(self._v.get(k, d))

    def get_int(self, k, d=0):
        return int(self._v.get(k, d))

    def get_str(self, k, d=""):
        return str(self._v.get(k, d))

    def get_float(self, k, d=0.0):
        return float(self._v.get(k, d))


def _service(**settings):
    plays = []
    svc = AudioAlertService(
        _Settings(**settings),
        player=lambda level: plays.append(("system", level)),
        siren_player=lambda path: plays.append(("siren", str(path))),
    )
    return svc, plays


class TestServiceBeginEnd:
    def test_begin_persistent_sirens_only_for_eligible_detections(self) -> None:
        svc, plays = _service()
        try:
            assert svc.begin_persistent(object(), "ERROR", is_detection=True) is True
            svc.end_persistent()
            # Not a detection -> no siren (a system WARNING is handled by notify()).
            assert svc.begin_persistent(object(), "WARNING", is_detection=False) is False
        finally:
            svc.close()

    def test_below_min_level_does_not_siren(self) -> None:
        svc, _ = _service(**{"notifications.sound_min_level": "CRITICAL"})
        try:
            assert svc.begin_persistent(object(), "ERROR", is_detection=True) is False
        finally:
            svc.close()

    def test_disabled_sound_does_not_siren(self) -> None:
        svc, _ = _service(**{"notifications.sound_enabled": False})
        try:
            assert svc.begin_persistent(object(), "ERROR", is_detection=True) is False
        finally:
            svc.close()

    def test_begin_actually_plays_the_siren_and_end_stops_it(self) -> None:
        svc, plays = _service()
        try:
            svc.begin_persistent(object(), "ERROR", is_detection=True)
            assert _wait_until(lambda: any(p[0] == "siren" for p in plays))
            svc.end_persistent()
            assert svc.statistics["persistent_siren_active"] == 0
        finally:
            svc.close()

    # TEST L - shutdown stops the siren and leaves no worker running
    def test_close_stops_the_siren(self) -> None:
        svc, _ = _service()
        svc.begin_persistent(object(), "ERROR", is_detection=True)
        assert _wait_until(lambda: svc.statistics["persistent_siren_active"] == 1)
        svc.close()
        assert svc.statistics["persistent_siren_active"] == 0
        assert not any(
            t.name == "persistent-siren" and t.is_alive()
            for t in threading.enumerate()
        )


# ---------------------------------------------------------------------------
# Popup hooks: the siren follows the visible popup; CHECK and CLOSE stop it
# ---------------------------------------------------------------------------
class TestPopupHooksDriveTheSiren:
    @pytest.fixture
    def toast(self, tk_root):
        from aethra_sec.ui.theme import apply_theme
        from aethra_sec.ui.widgets.toast import ToastManager

        apply_theme(tk_root)
        started: list = []
        dismissed: list = []
        mgr = ToastManager(tk_root, SimpleNamespace())
        mgr.on_persistent(
            present=lambda spec: started.append(spec.get("_token")),
            dismiss=lambda spec: dismissed.append(spec.get("_token")),
        )
        return mgr, started, dismissed, tk_root

    def _detection(self, mgr, ref="anomaly #1"):
        return mgr.show_persistent("Attack", "msg", level="ERROR", reference=ref,
                                   severity="HIGH", is_detection=True,
                                   on_check=lambda: None)

    def test_present_hook_fires_on_show_dismiss_on_close(self, toast) -> None:
        mgr, started, dismissed, root = toast
        self._detection(mgr); root.update()
        assert len(started) == 1 and started[0] is not None
        mgr.close_persistent(); root.update()
        assert dismissed == started, "CLOSE did not stop this popup's siren"

    def test_check_also_dismisses_and_stops(self, toast) -> None:
        mgr, started, dismissed, root = toast
        self._detection(mgr); root.update()
        # Drive CHECK through the same path the button uses.
        mgr._on_check(mgr.persistent_frame); root.update()  # noqa: SLF001
        assert dismissed == started

    def test_the_siren_follows_the_queue_to_the_next_popup(self, toast) -> None:
        mgr, started, dismissed, root = toast
        self._detection(mgr, "anomaly #1"); root.update()   # shown
        self._detection(mgr, "anomaly #2"); root.update()   # queued, no siren yet
        assert len(started) == 1
        mgr.close_persistent(); root.update()               # advances to #2
        assert len(started) == 2, "the next popup did not start its own siren"
        assert dismissed[0] == started[0]
        assert started[1] is not started[0], "a fresh token per popup"
