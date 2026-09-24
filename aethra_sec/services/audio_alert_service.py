"""Audible alerting for notifications that already exist (§52).

This does not detect anything. AETHRA-SEC already turns real events into
:class:`~aethra_sec.models.system.Notification` records through
:class:`~aethra_sec.services.notification_service.NotificationService`; this
service only decides whether a notification that has *already been raised from
real evidence* should also make a sound. There is deliberately no path here
that can invent an event - if the backend raised nothing, nothing sounds.

Two properties matter as much as the sound itself:

**It never blocks the interface.** Playback runs on a daemon worker fed by a
bounded queue, so a burst of alerts cannot stall packet capture, a scan, or
the Tk event loop. On Windows the sound itself is handed to ``winsound`` with
``SND_ASYNC``, which returns immediately.

**It never becomes noise.** A console that beeps continuously is one an
operator mutes, and a muted console is worse than a silent one. Repeats of the
same finding inside a short window are folded into the first sound, and only
levels the operator chose to hear are played at all.
"""

from __future__ import annotations

import queue
import threading
import time
import uuid
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Callable

from aethra_sec.models.enums import NotificationLevel
from aethra_sec.resources import security_alert_sound
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("services.audio_alerts")

#: Settings keys, so the screen and this service cannot disagree about them.
SETTING_ENABLED = "notifications.sound_enabled"
SETTING_QUIET = "notifications.quiet_mode"
SETTING_REPEAT_CRITICAL = "notifications.repeat_critical"
SETTING_MIN_LEVEL = "notifications.sound_min_level"
SETTING_DEDUP_SECONDS = "notifications.sound_dedup_seconds"

#: How loud each level is, expressed as a Windows system sound. These are the
#: sounds the operating system already uses for the same idea, so they are
#: familiar and respect the user's own sound scheme and mute state.
_WINDOWS_SOUNDS: dict[str, str] = {
    "CRITICAL": "SystemHand",       # the OS "stop" sound
    "ERROR": "SystemHand",
    "WARNING": "SystemExclamation",
    "SUCCESS": "SystemAsterisk",
    "INFO": "SystemAsterisk",
}

#: The notification category that gets the packaged security sound. Only a
#: notification a security service actually raised carries it - see
#: ``NotificationService.raise_security_alert``. Everything else keeps the
#: operating system's own sounds, which is what stops a routine report or a
#: service-status change from sounding like an intrusion.
SECURITY_CATEGORY = "security"

#: Levels in ascending order of urgency, for the "minimum level" setting.
_ORDER: tuple[str, ...] = ("INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL")

#: Levels that repeat while unacknowledged, when the operator enables it.
_REPEATABLE: frozenset[str] = frozenset({"CRITICAL"})

#: Seconds between repeats of an unacknowledged critical alert.
REPEAT_INTERVAL_SECONDS = 20.0

#: Fallback hold time when a clip will not report its own length.
MAX_CLIP_SECONDS = 8.0

#: Longest a queued sound may wait before it is dropped as stale. A beep for
#: something that happened a minute ago is worse than no beep.
MAX_SOUND_AGE_SECONDS = 10.0


class SoundUnavailableError(RuntimeError):
    """Raised when a packaged sound file cannot be played on this machine."""


def play_sound_file(path: Path) -> None:
    """Play an audio file, returning before it has finished.

    Windows is handled through MCI (``winmm.dll``) rather than ``winsound``,
    which decodes WAV only and would refuse an MP3 outright. MCI is reached
    with :mod:`ctypes` from the standard library, so packaging a sound costs
    the project no new dependency.

    Playback is asynchronous by construction: ``play`` returns as soon as the
    device has accepted the command, so a five-second alert never holds up the
    worker, the event bus or packet capture behind it. The device is opened
    under a unique alias each time and closed on the way out, so overlapping
    alerts cannot collide over one handle or leak a device.

    Raises:
        SoundUnavailableError: when this machine cannot play the file. The
            caller falls back to the system sound; nothing propagates further.
    """
    if not path.is_file():
        raise SoundUnavailableError(f"{path.name} is not present")

    try:
        import ctypes
    except ImportError as exc:  # pragma: no cover - ctypes is stdlib
        raise SoundUnavailableError("ctypes is unavailable") from exc

    winmm = getattr(ctypes, "windll", None)
    if winmm is None:
        # Not Windows. The terminal bell at least marks the event rather than
        # letting a security alert pass in silence.
        print("\a", end="", flush=True)
        return

    send = ctypes.windll.winmm.mciSendStringW
    # Unique per call: two alerts a moment apart must not fight over an alias.
    alias = f"aethra_alert_{uuid.uuid4().hex[:12]}"

    def command(text: str) -> int:
        return int(send(text, None, 0, None))

    # "mpegvideo" is the MCI device that decodes MP3. The path is quoted, so a
    # directory containing spaces - "C:\Program Files\..." - still opens.
    code = command(f'open "{path}" type mpegvideo alias {alias}')
    if code != 0:
        raise SoundUnavailableError(_mci_error(code))
    try:
        code = command(f"play {alias}")
        if code != 0:
            raise SoundUnavailableError(_mci_error(code))
    except SoundUnavailableError:
        command(f"close {alias}")
        raise
    # The device is left open for the length of the clip and then released.
    # Closing immediately would cut the sound off; never closing would leak a
    # device handle for every alert.
    threading.Timer(
        _clip_seconds(command, alias), lambda: command(f"close {alias}")
    ).start()


def _clip_seconds(command: Callable[[str], int], alias: str) -> float:
    """How long to leave the device open, from the clip's own length."""
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(64)
        if ctypes.windll.winmm.mciSendStringW(
            f"status {alias} length", buffer, 64, None
        ) == 0:
            milliseconds = int(buffer.value or 0)
            if 0 < milliseconds < 120_000:
                return milliseconds / 1000.0 + 0.5
    except Exception:  # noqa: BLE001
        pass
    return MAX_CLIP_SECONDS


def _mci_error(code: int) -> str:
    """MCI's own description of a failure, for the operator."""
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(256)
        ctypes.windll.winmm.mciGetErrorStringW(code, buffer, 256)
        return buffer.value or f"MCI error {code}"
    except Exception:  # noqa: BLE001
        return f"MCI error {code}"


@dataclass(frozen=True)
class SoundRequest:
    """One queued sound, with the moment it was raised.

    ``security`` decides *which* sound: the packaged alert file for a real
    security notification, the operating system's own sound for everything
    else. It is set from the notification's category, never from its level, so
    a routine WARNING cannot borrow the security sound.
    """

    level: str
    key: str
    raised_at: float
    security: bool = False


class AudioAlertService:
    """Plays a sound for notifications the backend has already raised."""

    def __init__(
        self,
        settings: Any,
        *,
        player: Callable[[str], None] | None = None,
    ) -> None:
        """Wire the service to settings and (optionally) a custom player.

        Args:
            settings: the settings service, read for the operator's choices.
            player: overrides the platform player. Tests pass a recorder here
                so the behaviour can be asserted without a sound card.
        """
        self._settings = settings
        self._player = player or self._play_platform_sound
        self._queue: "queue.Queue[SoundRequest]" = queue.Queue(maxsize=64)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        #: Last time a given dedup key was sounded, so a repeated finding
        #: folds into the first sound instead of beeping on every arrival.
        self._last_played: dict[str, float] = {}
        #: Critical notifications still unacknowledged, keyed for repeats.
        self._unacknowledged: dict[str, float] = {}
        self._played = 0
        self._suppressed = 0
        #: The packaged sound, resolved once at start-up. Kept as an Asset so
        #: the reason it is unusable can be shown rather than guessed at.
        self._sound = security_alert_sound()
        self._sound_failures = 0
        self._sound_error = ""
        if not self._sound.available:
            LOGGER.warning(
                "The security alert sound is unavailable: %s "
                "Security notifications will use the system sound instead.",
                self._sound.detail,
            )

        self._worker = threading.Thread(
            target=self._run, name="audio-alerts", daemon=True
        )
        self._worker.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def notify(self, notification: Any) -> bool:
        """Consider sounding for a notification the backend raised.

        Returns:
            True when a sound was queued. Never raises: an alerting failure
            must not propagate into the event bus that carries real work.
        """
        try:
            level = str(getattr(notification, "level", "INFO")).upper()
            if not self._should_sound(level):
                return False

            security = self._is_security(notification)
            key = self._dedup_key(notification)
            now = time.monotonic()
            with self._lock:
                last = self._last_played.get(key)
                if last is not None and (now - last) < self._dedup_window():
                    # The same finding again inside the window: the operator
                    # has already been told, and the count is preserved on the
                    # notification record itself.
                    self._suppressed += 1
                    return False
                self._last_played[key] = now
                if level in _REPEATABLE:
                    self._unacknowledged[key] = now

            self._queue.put_nowait(SoundRequest(level, key, now, security))
            return True
        except queue.Full:
            # Alerting is best-effort; losing a beep must never cost an event.
            self._suppressed += 1
            return False
        except Exception:  # noqa: BLE001 - never break the caller
            LOGGER.debug("Could not queue an alert sound.", exc_info=True)
            return False

    def acknowledge(self, key: str = "") -> None:
        """Stop repeating a critical alert (all of them when ``key`` is empty)."""
        with self._lock:
            if key:
                self._unacknowledged.pop(key, None)
            else:
                self._unacknowledged.clear()

    def test_sound(self, level: str = "CRITICAL", *, security: bool = False) -> None:
        """Play one sound for the settings screen's Test control.

        This is an audio check only. It creates no notification, no incident
        and no alert - nothing reaches the database - so the operator can
        verify the sound without a fabricated security record existing. It is
        also the one path that plays the security sound without a security
        event, which is why it is reachable only from a button an operator
        pressed and never from the event bus.
        """
        try:
            self._queue.put_nowait(
                SoundRequest(
                    str(level).upper(), "__test__", time.monotonic(), security
                )
            )
        except queue.Full:  # pragma: no cover - test is a single sound
            pass

    @property
    def statistics(self) -> dict[str, int]:
        """Counters, for the diagnostics screen."""
        with self._lock:
            return {
                "played": self._played,
                "suppressed": self._suppressed,
                "awaiting_acknowledgement": len(self._unacknowledged),
            }

    def close(self) -> None:
        """Stop the worker."""
        self._stop.set()
        try:
            self._queue.put_nowait(SoundRequest("", "__stop__", time.monotonic()))
        except queue.Full:  # pragma: no cover
            pass

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------
    def _should_sound(self, level: str) -> bool:
        """Whether this level is audible under the operator's settings."""
        if not self._settings.get_bool(SETTING_ENABLED, True):
            return False
        if self._settings.get_bool(SETTING_QUIET, False):
            return False
        minimum = str(
            self._settings.get(SETTING_MIN_LEVEL, "WARNING") or "WARNING"
        ).upper()
        try:
            return _ORDER.index(level) >= _ORDER.index(minimum)
        except ValueError:
            # An unrecognised level is treated as audible rather than silently
            # dropped: failing loud is the safer direction for an alert.
            return True

    @staticmethod
    def _is_security(notification: Any) -> bool:
        """Whether this notification gets the packaged security sound.

        Keyed on the category a security service stamped on the record, so the
        answer comes from what raised it rather than from how serious it looks.
        A notification about a completed report, a stopped capture or a
        subsystem going amber is not a security event and does not sound like
        one.
        """
        category = str(getattr(notification, "category", "") or "").strip().lower()
        return category == SECURITY_CATEGORY

    def _dedup_key(self, notification: Any) -> str:
        """What counts as "the same finding" for folding repeats."""
        reference_type = str(getattr(notification, "reference_type", "") or "")
        reference_id = getattr(notification, "reference_id", None)
        if reference_type and reference_id is not None:
            return f"{reference_type}:{reference_id}"
        # No reference: fall back to the text, which is what an operator would
        # themselves recognise as a repeat.
        return f"{getattr(notification, 'category', '')}:{getattr(notification, 'title', '')}"

    def _dedup_window(self) -> float:
        """Seconds within which the same finding stays folded."""
        return float(self._settings.get_int(SETTING_DEDUP_SECONDS, 30))

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------
    def _run(self) -> None:
        """Play queued sounds, and repeat unacknowledged critical ones."""
        while not self._stop.is_set():
            try:
                request = self._queue.get(timeout=1.0)
            except queue.Empty:
                self._repeat_due()
                continue
            if self._stop.is_set() or request.key == "__stop__":
                break
            # A sound for something that has scrolled well into the past is
            # dropped rather than played late.
            if (time.monotonic() - request.raised_at) > MAX_SOUND_AGE_SECONDS:
                continue
            self._emit(request.level, request.security)

    def _repeat_due(self) -> None:
        """Re-sound critical alerts the operator has not acknowledged."""
        if not self._settings.get_bool(SETTING_REPEAT_CRITICAL, True):
            return
        if not self._should_sound("CRITICAL"):
            return
        now = time.monotonic()
        due: list[str] = []
        with self._lock:
            for key, last in self._unacknowledged.items():
                if (now - last) >= REPEAT_INTERVAL_SECONDS:
                    due.append(key)
            for key in due:
                self._unacknowledged[key] = now
        for _ in due:
            self._emit("CRITICAL")

    def _emit(self, level: str, security: bool = False) -> None:
        """Play one sound, counting it, without ever raising.

        A security notification plays the packaged file. If that cannot be
        played - the file is missing, or this machine has no way to play an
        MP3 - the operator still hears the system sound rather than silence,
        and the reason is recorded once for the Settings screen to show.
        """
        try:
            if security and self._play_security_sound():
                with self._lock:
                    self._played += 1
                return
            self._player(level)
            with self._lock:
                self._played += 1
        except Exception:  # noqa: BLE001 - a missing sound device is not fatal
            LOGGER.debug("Could not play an alert sound.", exc_info=True)

    def _play_security_sound(self) -> bool:
        """Play the packaged alert file. False when it could not be played."""
        if not self._sound.available:
            return False
        try:
            play_sound_file(self._sound.path)
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._sound_failures += 1
                self._sound_error = str(exc)
            LOGGER.warning(
                "The security alert sound could not be played (%s); "
                "falling back to the system sound.", exc,
            )
            return False
        with self._lock:
            self._sound_error = ""
        return True

    def sound_status(self) -> tuple[bool, str]:
        """Whether the packaged sound is usable, and why not when it is not.

        Read by the Settings screen so a missing or unplayable file is stated
        plainly instead of being discovered as silence during an incident.
        """
        with self._lock:
            failures, error = self._sound_failures, self._sound_error
        if not self._sound.available:
            return False, self._sound.detail
        if error:
            return False, (
                f"{self._sound.name} is present but could not be played "
                f"({error}). {failures} attempt(s) fell back to the system "
                "sound."
            )
        return True, (
            f"{self._sound.name} ({self._sound.size_bytes:,} bytes) is "
            "packaged and playable."
        )

    @staticmethod
    def _play_platform_sound(level: str) -> None:
        """Play the OS sound for a level, returning immediately.

        ``winsound`` is in the standard library on Windows, so this adds no
        dependency. ``SND_ASYNC`` hands the sound to the OS and returns at
        once, which is what keeps the worker - and therefore the queue - from
        backing up behind playback. Elsewhere the terminal bell is used.
        """
        try:
            import winsound
        except ImportError:  # pragma: no cover - not Windows
            print("\a", end="", flush=True)
            return
        alias = _WINDOWS_SOUNDS.get(level, "SystemAsterisk")
        winsound.PlaySound(alias, winsound.SND_ALIAS | winsound.SND_ASYNC)
