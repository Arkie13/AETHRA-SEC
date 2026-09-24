"""The packaged security alert sound (§119).

An operator-supplied MP3 ships in ``assets/`` and is played when a security
notification is raised - and only then. Three things had to be true for that to
be worth having, and each is easy to get wrong in a way nobody notices until an
incident.

**It has to be findable.** The console is started from ``run.bat``, from a
desktop shortcut whose working directory is elsewhere, and from a terminal. A
path relative to the current directory works in one of those cases and fails
silently in the others, so every packaged file is resolved from the package's
own location on disk.

**It has to stay rare.** A console that makes the same noise for a completed
report, a stopped capture and an intrusion is one an operator mutes, and a
muted console is worse than a silent one. The sound is keyed on the category a
security service stamped on the record, never on how serious the level looks,
and a correlated run of failures sounds once rather than once per arrival.

**It must never be load-bearing.** A missing or unplayable file is a real
possibility - a partial copy, an antivirus quarantine, a machine with no audio
device. The alert is still raised, still stored and still shown; the operator
hears the system sound instead and the Settings screen says why.
"""

from __future__ import annotations

import ast
import inspect
import time
from pathlib import Path
from typing import Any

import pytest

from aethra_sec.models.enums import NotificationLevel
from aethra_sec.models.system import Notification
from aethra_sec.resources import (
    APPLICATION_ICON,
    SECURITY_ALERT_SOUND,
    Asset,
    assets_dir,
    resolve,
    security_alert_sound,
)
from aethra_sec.services.audio_alert_service import (
    SECURITY_CATEGORY,
    AudioAlertService,
    SoundUnavailableError,
    play_sound_file,
)

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
AUDIO = PACKAGE / "services" / "audio_alert_service.py"
SETTINGS_SCREEN = PACKAGE / "ui" / "screens" / "settings.py"


def _statements(path: Path) -> str:
    """Source with docstrings removed, so prose is not mistaken for code."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


class _Settings:
    """Operator preferences, in memory."""

    def __init__(self, **values: Any) -> None:
        self.values: dict[str, Any] = {
            "notifications.sound_enabled": True,
            "notifications.quiet_mode": False,
            "notifications.sound_min_level": "WARNING",
            "notifications.sound_dedup_seconds": 30,
            "notifications.repeat_critical": False,
            **values,
        }

    def get_bool(self, key: str, default: bool = False) -> bool:
        return bool(self.values.get(key, default))

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self.values.get(key, default))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


@pytest.fixture
def recorder():
    """A service whose playback is recorded rather than audible."""
    played: list[str] = []

    def build(settings: _Settings | None = None) -> AudioAlertService:
        service = AudioAlertService(settings or _Settings())
        service._player = lambda level: played.append(f"system:{level}")
        service._play_security_sound = lambda: (
            played.append("packaged") or True
        )
        return service

    build.played = played  # type: ignore[attr-defined]
    return build


def _note(level: Any, category: str, **extra: Any) -> Notification:
    return Notification(
        level=level, title=extra.pop("title", "t"), message="m",
        category=category, **extra,
    )


def _settle() -> None:
    """Let the playback worker drain."""
    time.sleep(0.6)


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------
class TestTheSoundIsPackaged:
    """It ships with the application, not from a path on one machine."""

    def test_the_file_is_in_the_assets_directory(self) -> None:
        asset = security_alert_sound()
        assert asset.available, asset.detail
        assert asset.path.parent == assets_dir()
        assert asset.path.name == SECURITY_ALERT_SOUND

    def test_it_is_a_real_audio_file(self) -> None:
        """Not a placeholder or an empty file."""
        asset = security_alert_sound()
        assert asset.size_bytes > 10_000
        header = asset.path.read_bytes()[:3]
        assert header in (b"ID3", b"\xff\xfb", b"\xff\xf3"), header

    def test_the_path_does_not_depend_on_the_working_directory(self) -> None:
        """The desktop shortcut starts the console from somewhere else."""
        source = inspect.getsource(assets_dir)
        assert "bundle_root()" in source
        code = _statements(PACKAGE / "resources.py")
        for relative in ("Path('assets')", 'Path("assets")', "os.getcwd", "./assets"):
            assert relative not in code

    def test_the_bundle_root_is_derived_from_the_build_not_the_cwd(self) -> None:
        """It has to be right for a checkout and for a packaged build alike.

        A frozen one-file build unpacks its assets into a temporary directory
        and reports it as ``sys._MEIPASS``; a checkout has them beside the
        package. Both are derived from where the code actually is, and neither
        is derived from where the process happened to start.
        """
        from aethra_sec.config import paths

        module_source = inspect.getsource(paths)
        assert "_MEIPASS" in module_source
        assert "getcwd" not in module_source

        source = inspect.getsource(paths.bundle_root)
        assert "__file__" in source

    def test_the_icon_resolves_the_same_way(self) -> None:
        """One resolver for everything packaged, not one per asset."""
        assert resolve(APPLICATION_ICON).path.parent == assets_dir()


class TestAMissingFileIsReportedNotFatal:
    """A sound effect must never be able to stop the console."""

    def test_a_missing_file_reports_unavailable(self) -> None:
        asset = resolve("definitely-not-here.mp3")
        assert not asset.available
        assert "not present" in asset.detail
        assert asset.size_bytes == 0

    def test_resolving_a_missing_file_does_not_raise(self) -> None:
        assert resolve("nothing.mp3") is not None

    def test_playing_a_missing_file_raises_a_handled_error(self) -> None:
        with pytest.raises(SoundUnavailableError):
            play_sound_file(Path("C:/nowhere/nothing.mp3"))

    def test_the_service_falls_back_to_the_system_sound(self) -> None:
        service = AudioAlertService(_Settings())
        service._sound = Asset(
            "security-alert.mp3", Path("C:/nowhere/security-alert.mp3"), False,
            "security-alert.mp3 is not present.",
        )
        fallbacks: list[str] = []
        service._player = fallbacks.append
        try:
            service.notify(_note(NotificationLevel.WARNING, SECURITY_CATEGORY))
            _settle()
            assert fallbacks == ["WARNING"], (
                "a missing sound file silenced a security alert entirely"
            )
        finally:
            service.close()

    def test_the_status_explains_why(self) -> None:
        service = AudioAlertService(_Settings())
        service._sound = Asset(
            "security-alert.mp3", Path("C:/nowhere/security-alert.mp3"), False,
            "security-alert.mp3 is not present in C:/nowhere.",
        )
        try:
            usable, detail = service.sound_status()
            assert not usable
            assert "not present" in detail
        finally:
            service.close()

    def test_a_healthy_file_reports_usable(self) -> None:
        service = AudioAlertService(_Settings())
        try:
            usable, detail = service.sound_status()
            assert usable
            assert SECURITY_ALERT_SOUND in detail
        finally:
            service.close()

    def test_nothing_on_this_path_can_raise_into_the_caller(self) -> None:
        code = _statements(AUDIO)
        emit = code[code.index("def _emit"):]
        emit = emit[: emit.index(chr(10) + "    def ", 1)]
        assert "except Exception" in emit


# ---------------------------------------------------------------------------
# What sounds, and what does not
# ---------------------------------------------------------------------------
class TestOnlySecurityNotificationsPlayIt:
    """The whole point: it must stay rare enough to mean something."""

    def test_a_security_notification_plays_the_packaged_sound(
        self, recorder
    ) -> None:
        service = recorder()
        try:
            service.notify(_note(NotificationLevel.WARNING, SECURITY_CATEGORY))
            _settle()
            assert recorder.played == ["packaged"]
        finally:
            service.close()

    @pytest.mark.parametrize(
        "category", ["reports", "scans", "capture", "system", "alerts", "traffic"]
    )
    def test_an_ordinary_notification_does_not(
        self, recorder, category: str
    ) -> None:
        service = recorder()
        try:
            service.notify(_note(NotificationLevel.WARNING, category))
            _settle()
            assert "packaged" not in recorder.played, (
                f"a {category} notification played the security sound"
            )
        finally:
            service.close()

    def test_the_choice_is_made_on_category_not_level(self) -> None:
        """A serious report is still a report."""
        source = inspect.getsource(AudioAlertService._is_security)
        assert "category" in source
        assert "level" not in source

    def test_a_critical_non_security_notification_does_not_play_it(
        self, recorder
    ) -> None:
        service = recorder()
        try:
            service.notify(_note(NotificationLevel.CRITICAL, "system"))
            _settle()
            assert "packaged" not in recorder.played
        finally:
            service.close()

    def test_packets_never_reach_this_service_at_all(self) -> None:
        """Capture publishes traffic statistics, not notifications."""
        code = _statements(AUDIO)
        for forbidden in ("CapturedPacket", "packet", "TRAFFIC_STATS"):
            assert forbidden not in code

    def test_the_service_cannot_invent_a_notification(self) -> None:
        code = _statements(AUDIO)
        for forbidden in ("INSERT", "repository", "Repository", "db."):
            assert forbidden not in code


class TestACorrelatedAlertSoundsOnce:
    """Eight failed sign-ins are one event, not eight."""

    def test_repeats_inside_the_window_are_folded(self, recorder) -> None:
        service = recorder()
        try:
            for _ in range(8):
                service.notify(
                    _note(
                        NotificationLevel.WARNING, SECURITY_CATEGORY,
                        title="Multiple failed login attempts",
                        reference_type="security_alert", reference_id=1,
                    )
                )
            _settle()
            assert recorder.played == ["packaged"], (
                f"the same correlated alert sounded {len(recorder.played)} times"
            )
            assert service.statistics["suppressed"] == 7
        finally:
            service.close()

    def test_a_different_alert_still_sounds(self, recorder) -> None:
        """Deduplication must not swallow a genuinely new event."""
        service = recorder()
        try:
            service.notify(
                _note(NotificationLevel.WARNING, SECURITY_CATEGORY,
                      reference_type="security_alert", reference_id=1)
            )
            service.notify(
                _note(NotificationLevel.WARNING, SECURITY_CATEGORY,
                      reference_type="security_alert", reference_id=2)
            )
            _settle()
            assert recorder.played == ["packaged", "packaged"]
        finally:
            service.close()

    def test_a_security_alert_does_not_repeat_on_a_timer(self) -> None:
        """Only CRITICAL re-sounds, and security alerts are WARNING."""
        from aethra_sec.services.notification_service import NotificationService

        source = inspect.getsource(NotificationService.raise_security_alert)
        assert "NotificationLevel.WARNING" in source
        code = _statements(AUDIO)
        assert "_REPEATABLE" in code and "CRITICAL" in code


class TestTheTestButtonFabricatesNothing:
    """Hearing the sound must not put a security record in the database."""

    def test_the_test_path_writes_nothing(self) -> None:
        source = inspect.getsource(AudioAlertService.test_sound)
        for forbidden in ("Notification(", "INSERT", "repository"):
            assert forbidden not in source

    def test_it_is_the_only_way_to_hear_it_without_an_event(
        self, recorder
    ) -> None:
        service = recorder()
        try:
            service.test_sound("CRITICAL", security=True)
            _settle()
            assert recorder.played == ["packaged"]
        finally:
            service.close()

    def test_the_screen_states_that_nothing_was_created(self) -> None:
        code = _statements(SETTINGS_SCREEN)
        assert "No notification or " in code


# ---------------------------------------------------------------------------
# The switch
# ---------------------------------------------------------------------------
class TestTheSoundSwitch:
    """One preference, stored, read by the service before every sound."""

    def test_both_positions_are_labelled(self) -> None:
        from aethra_sec.ui.screens.settings import (
            SOUND_OFF_LABEL,
            SOUND_ON_LABEL,
        )

        assert "Sound ON" in SOUND_ON_LABEL
        assert "Sound OFF" in SOUND_OFF_LABEL
        assert "\U0001f50a" in SOUND_ON_LABEL
        assert "\U0001f507" in SOUND_OFF_LABEL

    def test_the_label_reads_without_the_emoji(self) -> None:
        """A font that cannot draw the glyph must not leave a blank button."""
        from aethra_sec.ui.screens.settings import (
            SOUND_OFF_LABEL,
            SOUND_ON_LABEL,
        )

        for label in (SOUND_ON_LABEL, SOUND_OFF_LABEL):
            assert label.encode("ascii", "ignore").decode().strip()

    def test_it_writes_the_stored_setting(self) -> None:
        from aethra_sec.ui.screens.settings import SettingsScreen

        source = inspect.getsource(SettingsScreen._toggle_alert_sound)
        assert "settings.set(" in source
        assert "SETTING_SOUND_ENABLED" in source

    def test_the_switch_and_the_service_read_one_key(self) -> None:
        from aethra_sec.services.audio_alert_service import SETTING_ENABLED
        from aethra_sec.ui.screens.settings import SETTING_SOUND_ENABLED

        assert SETTING_SOUND_ENABLED == SETTING_ENABLED

    def test_the_key_is_a_declared_persisted_setting(self) -> None:
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY
        from aethra_sec.ui.screens.settings import SETTING_SOUND_ENABLED

        spec = SETTING_SPEC_BY_KEY.get(SETTING_SOUND_ENABLED)
        assert spec is not None, "the preference would not survive a restart"
        assert spec.value_type == "bool"

    def test_the_switch_reads_the_stored_value_not_a_local_flag(self) -> None:
        from aethra_sec.ui.screens.settings import SettingsScreen

        source = inspect.getsource(SettingsScreen._sound_is_on)
        assert "get_bool" in source

    @pytest.mark.parametrize(
        "settings",
        [
            _Settings(**{"notifications.sound_enabled": False}),
            _Settings(**{"notifications.quiet_mode": True}),
        ],
    )
    def test_a_silenced_console_plays_nothing(self, recorder, settings) -> None:
        service = recorder(settings)
        try:
            service.notify(_note(NotificationLevel.WARNING, SECURITY_CATEGORY))
            _settle()
            assert recorder.played == []
        finally:
            service.close()


# ---------------------------------------------------------------------------
# Playback
# ---------------------------------------------------------------------------
class TestPlaybackDoesNotBlock:
    """A five-second clip must not hold up capture or the event loop."""

    def test_the_player_returns_before_the_clip_ends(self) -> None:
        asset = security_alert_sound()
        if not asset.available:  # pragma: no cover
            pytest.skip("the packaged sound is not present")
        started = time.monotonic()
        try:
            play_sound_file(asset.path)
        except SoundUnavailableError:  # pragma: no cover - no audio device
            pytest.skip("this machine cannot play the packaged sound")
        assert (time.monotonic() - started) < 2.0

    def test_playback_needs_no_extra_dependency(self) -> None:
        """ctypes and winsound are both standard library."""
        code = _statements(AUDIO)
        for third_party in ("pygame", "playsound", "pydub", "simpleaudio"):
            assert third_party not in code

    def test_each_playback_uses_its_own_device_alias(self) -> None:
        """Two alerts a moment apart must not fight over one handle."""
        source = inspect.getsource(play_sound_file)
        assert "uuid" in source
        assert "close" in source

    def test_the_device_is_released(self) -> None:
        source = inspect.getsource(play_sound_file)
        assert "Timer" in source, "the MCI device is never closed"
