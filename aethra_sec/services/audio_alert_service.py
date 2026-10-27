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
from aethra_sec.resources import ids_siren_sound, security_alert_sound
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

#: The notification category of an IDS detection - a Snort alert or an
#: AETHRA-SEC detection - which gets the siren.
DETECTION_CATEGORY = "alert"

#: Levels in ascending order of urgency, for the "minimum level" setting.
_ORDER: tuple[str, ...] = ("INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL")

#: Levels that repeat while unacknowledged, when the operator enables it.
_REPEATABLE: frozenset[str] = frozenset({"CRITICAL"})

#: Seconds between repeats of an unacknowledged critical alert.
REPEAT_INTERVAL_SECONDS = 20.0

#: Seconds between loops of the persistent siren tied to an open popup. Short
#: enough that a brief clip does not leave long silences while a detection
#: popup is up, long enough not to overlap a clip with itself.
PERSISTENT_SIREN_INTERVAL_SECONDS = 4.0

#: A persistent siren can never outlive its popup, but if a popup is somehow
#: never acknowledged (a wedged window), the loop stops itself after this many
#: seconds rather than sounding for ever. The detection stays recorded.
PERSISTENT_SIREN_MAX_SECONDS = 1800.0

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


def play_wav_file(path: Path) -> None:
    """Start a WAV file playing and return at once.

    ``winsound.PlaySound`` with ``SND_ASYNC`` hands the file to Windows and
    returns immediately, so the worker - and the queue behind it - is never
    held for the length of the clip. ``SND_NODEFAULT`` matters: without it a
    file Windows cannot play is silently replaced by the default beep, and a
    failure would masquerade as success. With it, a failure raises.

    Raises:
        SoundUnavailableError: the file is absent, or Windows refused it.
    """
    if not path.is_file():
        raise SoundUnavailableError(f"{path.name} is not present")
    try:
        import winsound
    except ImportError:  # pragma: no cover - not Windows
        print("\a", end="", flush=True)
        return
    try:
        winsound.PlaySound(
            str(path),
            winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT,
        )
    except RuntimeError as exc:
        raise SoundUnavailableError(f"Windows could not play {path.name}: {exc}") from exc


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
    #: An IDS detection (a notification of category ``alert``): plays the
    #: siren. Like ``security``, decided by what raised the notification,
    #: never by how urgent its level is.
    detection: bool = False


class _PersistentSiren:
    """Loops one popup's siren until that popup is acknowledged.

    The sound a detection popup makes must continue while the popup is open and
    unacknowledged, and stop the instant CHECK or CLOSE is pressed - not when
    one clip ends. The previous design played a single clip and only re-sounded
    CRITICAL notifications on a 20 s timer, so a HIGH detection (notification
    level ERROR) went silent within seconds while its popup stayed up. See
    evaluation/stability_revision/PERSISTENT_NOTIFICATION_SOUND_DESIGN.md.

    Exactly one siren is active at a time. Starting a new one (a superseding
    popup) stops the old one first, so popups can never pile up audio workers.

    The stop signal is a :class:`threading.Event`; the loop waits on it between
    iterations, so an acknowledgement stops the siren between loops immediately
    rather than after the current wait. Playback itself is the service's async
    player, so nothing here holds the GUI, the database or packet capture.
    """

    def __init__(self, play_once: Callable[[], bool], interval: float) -> None:
        self._play_once = play_once
        self._interval = max(0.5, float(interval))
        self._lock = threading.Lock()
        self._token: object | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.loops_played = 0

    @property
    def active_token(self) -> object | None:
        with self._lock:
            return self._token

    def start(self, token: object) -> None:
        """Begin (or replace) the loop for ``token``. Plays once immediately."""
        with self._lock:
            if self._token is token and self._thread is not None \
                    and self._thread.is_alive():
                return  # already sounding for this popup
            # Signal the previous loop to stop. It owns its own (old) Event and
            # exits on its own; we do not join here, so the Tk thread that calls
            # this on an escalation is never blocked. The old loop plays nothing
            # more because its token no longer matches and its Event is set.
            self._stop.set()
            self._token = token
            self._stop = threading.Event()    # a fresh signal for the new loop
            self._thread = threading.Thread(
                target=self._run, args=(token, self._stop), name="persistent-siren",
                daemon=True,
            )
            self._thread.start()

    def stop(self, token: object | None = None) -> bool:
        """Stop the loop. With a ``token``, only if it still owns the siren.

        Returns True when a loop was stopped. Idempotent: a second CLOSE, or a
        CLOSE after a CHECK, simply finds nothing to stop.
        """
        with self._lock:
            if self._token is None:
                return False
            if token is not None and token is not self._token:
                return False  # a stale button from a popup already superseded
            self._stop.set()
            self._token = None
            thread = self._thread
            self._thread = None
        # Join briefly so an orderly shutdown leaves no siren worker running.
        # The loop waits on the event, so it returns as soon as it is set; the
        # timeout only guards against a clip call that is mid-flight.
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        return True

    def _run(self, token: object, stop: threading.Event) -> None:
        started = time.monotonic()
        # The first sound is immediate; the popup appears and is heard at once.
        try:
            self._play_once()
            self.loops_played += 1
        except Exception:  # noqa: BLE001 - a bad sound device is never fatal
            LOGGER.debug("Persistent siren first play failed.", exc_info=True)
        while not stop.wait(self._interval):
            if (time.monotonic() - started) > PERSISTENT_SIREN_MAX_SECONDS:
                LOGGER.warning(
                    "[NOTIFY] Persistent siren stopped itself after %.0f s "
                    "without acknowledgement; the detection stays recorded.",
                    PERSISTENT_SIREN_MAX_SECONDS,
                )
                with self._lock:
                    if self._token is token:
                        self._token = None
                return
            try:
                self._play_once()
                self.loops_played += 1
            except Exception:  # noqa: BLE001
                LOGGER.debug("Persistent siren loop play failed.", exc_info=True)


class AudioAlertService:
    """Plays a sound for notifications the backend has already raised."""

    def __init__(
        self,
        settings: Any,
        *,
        player: Callable[[str], None] | None = None,
        siren_player: Callable[[Path], None] | None = None,
    ) -> None:
        """Wire the service to settings and (optionally) a custom player.

        Args:
            settings: the settings service, read for the operator's choices.
            player: overrides the platform player. Tests pass a recorder here
                so the behaviour can be asserted without a sound card.
            siren_player: overrides the siren player, for the same reason.
        """
        self._settings = settings
        self._player = player or self._play_platform_sound
        self._siren_player = siren_player or play_wav_file
        #: The IDS detection siren. A detection used to fall through to the
        #: Windows "SystemHand" alias - on this installation a soft chime
        #: ("Windows Foreground.wav"), or nothing at all under a "No Sounds"
        #: scheme - because only category "security" got a packaged file.
        self._siren = ids_siren_sound()
        self._siren_failures = 0
        self._siren_error = ""
        if not self._siren.available:
            LOGGER.warning(
                "The IDS siren is unavailable: %s Detections will use the "
                "system sound instead.", self._siren.detail,
            )
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

        #: Loops a detection popup's siren until CHECK/CLOSE. Plays the siren
        #: when available, otherwise the security sound, otherwise the system
        #: sound - the same fallback order as a one-shot detection sound.
        self._persistent = _PersistentSiren(
            self._play_detection_sound, PERSISTENT_SIREN_INTERVAL_SECONDS
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
            detection = self._is_detection(notification)
            key = self._dedup_key(notification)
            now = time.monotonic()
            with self._lock:
                last = self._last_played.get(key)
                if last is not None and (now - last) < self._dedup_window():
                    # The same finding again inside the window: the operator
                    # has already been told, and the count is preserved on the
                    # notification record itself.
                    self._suppressed += 1
                    LOGGER.info(
                        "[NOTIFY] Sound deduplicated: key=%s within %ss",
                        key, int(self._dedup_window()),
                    )
                    return False
                self._last_played[key] = now
                if level in _REPEATABLE:
                    self._unacknowledged[key] = now

            self._queue.put_nowait(
                SoundRequest(level, key, now, security, detection)
            )
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

    # ------------------------------------------------------------------
    # Persistent siren, tied to an open detection popup
    # ------------------------------------------------------------------
    def begin_persistent(self, token: object, level: str, is_detection: bool) -> bool:
        """Start looping the siren for a just-shown popup. Returns True if it did.

        Called from the Tk thread when a persistent popup is built. It only
        signals the siren thread, so it returns at once and never blocks the
        interface. The siren sounds only for an eligible detection popup under
        the operator's severity and sound settings; anything else is left to
        the one-shot :meth:`notify`.
        """
        try:
            if not is_detection or not self._should_sound(str(level).upper()):
                return False
            self._persistent.start(token)
            LOGGER.info("[NOTIFY] Persistent siren started for popup %s", token)
            return True
        except Exception:  # noqa: BLE001 - alerting must never break the UI
            LOGGER.debug("Could not start the persistent siren.", exc_info=True)
            return False

    def end_persistent(self, token: object | None = None) -> None:
        """Stop the persistent siren (CHECK, CLOSE, supersede or shutdown).

        With a ``token`` it stops only if that popup still owns the siren, so a
        stale callback from a popup that was already replaced cannot silence
        the new one. Returns at once; safe to call more than once.
        """
        try:
            if self._persistent.stop(token):
                LOGGER.info("[NOTIFY] Persistent siren stopped for popup %s",
                            token if token is not None else "(any)")
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not stop the persistent siren.", exc_info=True)

    def _play_detection_sound(self) -> bool:
        """One detection sound: siren, else security file, else system sound."""
        if self._play_siren():
            with self._lock:
                self._played += 1
            return True
        if self._play_security_sound():
            with self._lock:
                self._played += 1
            return True
        self._player("ERROR")
        with self._lock:
            self._played += 1
        return True

    def test_sound(
        self,
        level: str = "CRITICAL",
        *,
        security: bool = False,
        detection: bool = False,
    ) -> None:
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
                    str(level).upper(), "__test__", time.monotonic(), security,
                    detection,
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
                "persistent_siren_active": 1 if self._persistent.active_token is not None else 0,
                "persistent_siren_loops": self._persistent.loops_played,
            }

    def close(self) -> None:
        """Stop the siren and the worker."""
        self._persistent.stop()
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

    @staticmethod
    def _is_detection(notification: Any) -> bool:
        """Whether this notification is about an IDS detection - gets the siren.

        The notification service stamps category ``alert`` on every Snort
        alert and every AETHRA-SEC detection it announces, and on nothing
        else, so a report or a status change never sounds like an intrusion.
        """
        category = str(getattr(notification, "category", "") or "").strip().lower()
        return category == DETECTION_CATEGORY

    def _dedup_key(self, notification: Any) -> str:
        """What counts as "the same finding" for folding repeats.

        The alert's identifier, plus its severity when it carries one. Without
        the severity, a detection announced at MEDIUM and then escalated to
        HIGH two seconds later was folded into the MEDIUM sound and the HIGH
        escalation was silent (logged on 14 Oct: "Sound not played" for
        notification 2234). A repeat at the same severity still folds.
        """
        reference_type = str(getattr(notification, "reference_type", "") or "")
        reference_id = getattr(notification, "reference_id", None)
        severity = str(getattr(notification, "severity", "") or "").upper()
        if reference_type and reference_id is not None:
            if severity:
                return f"{reference_type}:{reference_id}:{severity}"
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
                LOGGER.info(
                    "[NOTIFY] Sound dropped as stale: key=%s", request.key
                )
                continue
            self._emit(request.level, request.security, request.detection)

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

    def _emit(
        self, level: str, security: bool = False, detection: bool = False
    ) -> None:
        """Play one sound, counting it, without ever raising.

        An IDS detection plays the siren; a security notification plays the
        packaged file. If either cannot be played - the file is missing, or
        the device refuses it - the operator still hears the system sound
        rather than silence, and the reason is recorded for the Settings
        screen to show. "Played" here means the device accepted the request;
        whether anyone heard it cannot be known from software.
        """
        try:
            if detection and self._play_siren():
                with self._lock:
                    self._played += 1
                return
            if security and self._play_security_sound():
                with self._lock:
                    self._played += 1
                return
            self._player(level)
            with self._lock:
                self._played += 1
        except Exception:  # noqa: BLE001 - a missing sound device is not fatal
            LOGGER.debug("Could not play an alert sound.", exc_info=True)

    def _play_siren(self) -> bool:
        """Request the IDS siren. False when it could not be started."""
        if not self._siren.available:
            return False
        try:
            self._siren_player(self._siren.path)
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._siren_failures += 1
                self._siren_error = str(exc)
            LOGGER.warning(
                "[NOTIFY] Siren playback FAILED (%s); falling back to the "
                "system sound.", exc,
            )
            return False
        with self._lock:
            self._siren_error = ""
        LOGGER.info("[NOTIFY] Siren playback requested: %s", self._siren.name)
        return True

    def siren_status(self) -> tuple[bool, str]:
        """Whether the IDS siren is usable, and why not when it is not."""
        with self._lock:
            failures, error = self._siren_failures, self._siren_error
        if not self._siren.available:
            return False, self._siren.detail
        if error:
            return False, (
                f"{self._siren.name} is present but could not be played "
                f"({error}). {failures} attempt(s) fell back to the system "
                "sound."
            )
        return True, (
            f"{self._siren.name} ({self._siren.size_bytes:,} bytes) is "
            "packaged and playable."
        )

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

    def diagnose(self, *, play: bool = True) -> list[tuple[str, bool, str]]:
        """Check the audio path stage by stage and report each result (§4).

        Returns a list of ``(stage, ok, detail)`` covering: the file is found,
        it is readable, playback initialised, playback completed. Each answer
        comes from actually attempting that step, and a failure carries the
        real error rather than a generic one.

        This is an audio check, not an alert. It creates no notification, no
        incident and no database record, so the sound can be verified without
        a fabricated security event existing to justify it. Pass
        ``play=False`` to check the file without making a noise.
        """
        stages: list[tuple[str, bool, str]] = []

        asset = self._sound
        found = bool(asset.available and asset.path and asset.path.is_file())
        stages.append((
            "AUDIO FILE FOUND",
            found,
            str(asset.path) if found else (asset.detail or "not resolved"),
        ))
        if not found:
            stages.append(("AUDIO FILE READABLE", False, "file not found"))
            stages.append(("AUDIO PLAYBACK INITIALIZED", False, "no file to play"))
            stages.append(("AUDIO PLAYBACK FAILED", False, "no file to play"))
            return stages

        try:
            with asset.path.open("rb") as handle:
                header = handle.read(4)
            stages.append((
                "AUDIO FILE READABLE",
                True,
                f"{asset.size_bytes:,} bytes, first bytes {header.hex()}",
            ))
        except OSError as exc:
            stages.append(("AUDIO FILE READABLE", False, str(exc)))
            stages.append(("AUDIO PLAYBACK INITIALIZED", False, "unreadable"))
            stages.append(("AUDIO PLAYBACK FAILED", False, "unreadable"))
            return stages

        if not play:
            stages.append((
                "AUDIO PLAYBACK INITIALIZED", True, "skipped (play=False)"
            ))
            return stages

        try:
            play_sound_file(asset.path)
            stages.append(("AUDIO PLAYBACK INITIALIZED", True, "device accepted"))
            stages.append((
                "AUDIO PLAYBACK COMPLETED",
                True,
                "handed to the device asynchronously; it returns before the "
                "sound finishes by design, so the worker is never held",
            ))
        except SoundUnavailableError as exc:
            # The actual error, never swallowed: this is the one place an
            # operator can find out why an incident was silent.
            stages.append(("AUDIO PLAYBACK INITIALIZED", False, str(exc)))
            stages.append(("AUDIO PLAYBACK FAILED", False, str(exc)))
        except Exception as exc:  # noqa: BLE001 - report whatever it was
            stages.append(("AUDIO PLAYBACK INITIALIZED", False, repr(exc)))
            stages.append(("AUDIO PLAYBACK FAILED", False, repr(exc)))
        return stages

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
