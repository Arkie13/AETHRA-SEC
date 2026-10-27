"""The IDS siren: packaged, reproducible, and played by the existing rules.

A detection notification (category ``alert``) plays the siren; everything else
keeps its old sound. The existing settings, severity floor and dedup window
still decide whether anything plays. No test here makes a noise: a recording
player stands in for the sound card.
"""

from __future__ import annotations

import subprocess
import sys
import time
import wave
from pathlib import Path
from types import SimpleNamespace

import pytest

from aethra_sec.resources import IDS_SIREN_SOUND, ids_siren_sound
from aethra_sec.services.audio_alert_service import (
    AudioAlertService,
    SoundUnavailableError,
    play_wav_file,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class _Settings:
    def __init__(self, **values) -> None:  # noqa: ANN003
        self.values = {
            "notifications.sound_enabled": True,
            "notifications.quiet_mode": False,
            "notifications.sound_min_level": "WARNING",
            "notifications.sound_dedup_seconds": 30,
            "notifications.repeat_critical": False,
            **values,
        }

    def get(self, key, default=None):  # noqa: ANN001, ANN201
        return self.values.get(key, default)

    def get_bool(self, key, default=False):  # noqa: ANN001, ANN201
        return bool(self.values.get(key, default))

    def get_int(self, key, default=0):  # noqa: ANN001, ANN201
        return int(self.values.get(key, default))

    def get_str(self, key, default=""):  # noqa: ANN001, ANN201
        return str(self.values.get(key, default))


def _detection(ref: int, severity: str = "HIGH", level: str = "ERROR"):
    return SimpleNamespace(
        level=level, category="alert", reference_type="anomaly",
        reference_id=ref, severity=severity, title=f"{severity} detection",
    )


@pytest.fixture
def service_factory():
    made = []

    def make(**settings):  # noqa: ANN003, ANN202
        played, sirens = [], []
        svc = AudioAlertService(
            _Settings(**settings),
            player=lambda level: played.append(level),
            siren_player=lambda path: sirens.append(path),
        )
        made.append(svc)
        return svc, played, sirens

    yield make
    for svc in made:
        svc.close()


def _settle() -> None:
    time.sleep(0.3)


# --- the asset -------------------------------------------------------------
def test_the_siren_asset_exists_and_resolves() -> None:
    asset = ids_siren_sound()
    assert asset.name == IDS_SIREN_SOUND
    assert asset.available, asset.detail
    assert asset.path == PROJECT_ROOT / "assets" / IDS_SIREN_SOUND


def test_the_siren_is_a_short_valid_wav() -> None:
    with wave.open(str(ids_siren_sound().path)) as wav:
        seconds = wav.getnframes() / wav.getframerate()
        assert wav.getnchannels() == 1 and wav.getsampwidth() == 2
    assert 1.0 <= seconds <= 4.0


def test_the_siren_is_reproducible_from_its_generator() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/generate_siren.py", "--check"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# --- who gets it -----------------------------------------------------------
def test_an_eligible_detection_requests_the_siren(service_factory) -> None:  # noqa: ANN001
    svc, played, sirens = service_factory()
    assert svc.notify(_detection(1)) is True
    _settle()
    assert len(sirens) == 1 and played == []


def test_a_non_detection_keeps_the_system_sound(service_factory) -> None:  # noqa: ANN001
    svc, played, sirens = service_factory()
    svc.notify(SimpleNamespace(level="WARNING", category="system",
                               reference_type="", reference_id=None,
                               title="Capture stopped"))
    _settle()
    assert sirens == [] and played == ["WARNING"]


# --- existing settings still decide ----------------------------------------
def test_sound_disabled_plays_nothing(service_factory) -> None:  # noqa: ANN001
    svc, played, sirens = service_factory(**{"notifications.sound_enabled": False})
    assert svc.notify(_detection(2)) is False
    _settle()
    assert sirens == [] and played == []


def test_the_severity_floor_is_applied(service_factory) -> None:  # noqa: ANN001
    svc, _played, sirens = service_factory()
    # LOW maps to level INFO, below the WARNING floor.
    assert svc.notify(_detection(3, "LOW", "INFO")) is False
    _settle()
    assert sirens == []


def test_repeats_inside_the_window_fold(service_factory) -> None:  # noqa: ANN001
    svc, _played, sirens = service_factory()
    assert svc.notify(_detection(4)) is True
    assert svc.notify(_detection(4)) is False, "same alert, same severity"
    _settle()
    assert len(sirens) == 1


def test_an_escalation_sounds_once_more(service_factory) -> None:  # noqa: ANN001
    """MEDIUM then HIGH for the same alert: the HIGH was silent before."""
    svc, _played, sirens = service_factory()
    assert svc.notify(_detection(5, "MEDIUM", "WARNING")) is True
    assert svc.notify(_detection(5, "HIGH", "ERROR")) is True
    _settle()
    assert len(sirens) == 2


def test_one_alerts_dedup_does_not_silence_another(service_factory) -> None:  # noqa: ANN001
    svc, _played, sirens = service_factory()
    assert svc.notify(_detection(6)) is True
    assert svc.notify(_detection(7)) is True
    _settle()
    assert len(sirens) == 2


# --- failures are contained ------------------------------------------------
def test_a_failed_siren_falls_back_to_the_system_sound() -> None:
    played = []

    def broken(path) -> None:  # noqa: ANN001
        raise SoundUnavailableError("device refused")

    svc = AudioAlertService(_Settings(), player=played.append, siren_player=broken)
    try:
        assert svc.notify(_detection(8)) is True
        _settle()
        assert played == ["ERROR"], "the operator still hears something"
        ok, detail = svc.siren_status()
        assert not ok and "device refused" in detail
    finally:
        svc.close()


def test_a_missing_file_raises_a_handled_error(tmp_path: Path) -> None:
    with pytest.raises(SoundUnavailableError):
        play_wav_file(tmp_path / "absent.wav")


def test_notify_returns_at_once(service_factory) -> None:  # noqa: ANN001
    """Playback happens on the worker; queuing must not wait for it."""
    svc, _played, _sirens = service_factory()
    svc._siren_player = lambda path: time.sleep(2.0)  # noqa: SLF001
    started = time.perf_counter()
    svc.notify(_detection(9))
    assert time.perf_counter() - started < 0.2


def test_the_sound_test_hook_creates_no_record(service_factory) -> None:  # noqa: ANN001
    """The preview path queues a sound and nothing else."""
    svc, _played, sirens = service_factory()
    svc.test_sound("ERROR", detection=True)
    _settle()
    assert len(sirens) == 1
