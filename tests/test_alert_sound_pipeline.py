"""A real alert reaches the speaker, and nothing else does.

The sound was wired to ``NOTIFICATION_RAISED``, which is a *request* for a
notification - only the backup service ever publishes it. Snort alerts, scans
and subsystem failures go the other way round: the notification service builds
the record itself and wrote it straight to the database. Nothing announced it
afterwards, so the interface never learned a notification existed, and the alert
sound never played. This installation had 101 stored alert notifications,
including SYN floods from the operator's own testing, every one silent.

``NOTIFICATION_STORED`` is the announcement, published after a successful
insert and carrying the real row id. These tests hold what that buys:

* a sound only for a notification that actually persisted;
* the same record driving the badge and the sound, rather than two guesses;
* an immutable identifier to fold repeats against, so a refresh, a re-poll or
  a page change cannot beep again;
* no loop, because the service that stores notifications does not listen for
  the event it publishes.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import Event, EventType, NotificationPayload
from aethra_sec.models.enums import NotificationLevel, Severity
from aethra_sec.models.system import Notification
from aethra_sec.services.notification_service import NotificationService


class _Repository:
    """Records inserts and hands back real-looking row ids."""

    def __init__(self, *, fail: bool = False) -> None:
        self.created: list[Notification] = []
        self._fail = fail
        self._next_id = 500

    def create(self, notification: Notification) -> int:
        if self._fail:
            raise RuntimeError("database is down")
        self.created.append(notification)
        self._next_id += 1
        return self._next_id

    def prune_excess(self, keep: int) -> None:  # noqa: ARG002
        return None

    def exists_since(self, reference_type: str, reference_key: str,
                     since) -> bool:  # noqa: ANN001, ARG002
        """The real repository's dedup contract, answered from what was stored.

        A key travels in the message behind the correlation marker; a match
        means this exact reference was already announced.
        """
        from aethra_sec.database.repositories.settings import _REFERENCE_MARKER

        needle = f"{_REFERENCE_MARKER}{reference_key}"
        return any(
            n.reference_type == reference_type and needle in n.message
            for n in self.created
        )


class _Settings:
    def __init__(self, **values: Any) -> None:
        self._values = values

    def get_bool(self, key: str, default: bool = False) -> bool:
        return bool(self._values.get(key, default))

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self._values.get(key, default))

    def get_str(self, key: str, default: str = "") -> str:
        return str(self._values.get(key, default))


class _Alert:
    def __init__(self, alert_id: int, severity: Severity = Severity.HIGH) -> None:
        self.id = alert_id
        self.severity = severity
        self.summary = "TCP SYN flood - possible DoS 198.51.100.7 -> 172.20.10.2"


class _AlertPayload:
    def __init__(self, alert: _Alert) -> None:
        self.alert = alert


@pytest.fixture
def wiring():
    bus = EventBus()
    repository = _Repository()
    # These tests exercise the announcement mechanism with a Snort alert as
    # input, so Snort popups are switched on. Since 15 Oct 2026 they are off
    # by default (AETHRA-SEC detections are the primary alerts); that default
    # is tested in tests/test_alert_source_and_statistics.py.
    service = NotificationService(
        repository, _Repository(),
        _Settings(**{"notifications.snort_popups": True}), bus,
    )
    announced: list[NotificationPayload] = []
    bus.subscribe(
        (EventType.NOTIFICATION_STORED,),
        lambda event: announced.append(event.payload),
        queued=False,
        name="test-listener",
    )
    yield bus, repository, service, announced
    service.close()


# ---------------------------------------------------------------------------
# A real alert is announced
# ---------------------------------------------------------------------------
class TestARealAlertIsAnnounced:
    def test_a_snort_alert_publishes_the_stored_event(self, wiring) -> None:  # noqa: ANN001
        bus, repository, _service, announced = wiring
        bus.publish(EventType.SNORT_ALERT_RECEIVED, _AlertPayload(_Alert(271)))
        assert len(repository.created) == 1
        assert len(announced) == 1, (
            "the notification was stored and never announced, which is exactly "
            "why no sound ever played for a real IDS alert"
        )

    def test_the_announcement_carries_the_real_row_id(self, wiring) -> None:  # noqa: ANN001
        bus, _repository, _service, announced = wiring
        bus.publish(EventType.SNORT_ALERT_RECEIVED, _AlertPayload(_Alert(271)))
        assert announced[0].notification_id is not None
        assert announced[0].notification_id > 0

    def test_the_announcement_references_the_alert(self, wiring) -> None:  # noqa: ANN001
        """The badge and the sound must key off the same record."""
        bus, _repository, _service, announced = wiring
        bus.publish(EventType.SNORT_ALERT_RECEIVED, _AlertPayload(_Alert(271)))
        assert announced[0].reference_type == "alert"
        assert announced[0].reference_id == 271

    def test_a_high_alert_is_a_warning_not_a_critical(self, wiring) -> None:  # noqa: ANN001
        """§8: CRITICAL is not IDS terminology and must not appear."""
        bus, _repository, _service, announced = wiring
        bus.publish(EventType.SNORT_ALERT_RECEIVED, _AlertPayload(_Alert(9)))
        # The point of this test is that HIGH is not over-escalated to
        # CRITICAL. It must also stay audible at the default WARNING sound
        # floor, which is the property the pipeline exists to deliver, so
        # both are asserted rather than one literal label.
        from aethra_sec.services.audio_alert_service import _ORDER
        from aethra_sec.services.notification_service import level_for_severity

        assert announced[0].level is not NotificationLevel.CRITICAL
        assert announced[0].level is level_for_severity(Severity.HIGH)
        assert _ORDER.index(str(announced[0].level)) >= _ORDER.index("WARNING")

    def test_a_scan_result_is_announced_too(self, wiring) -> None:  # noqa: ANN001
        """Every persisted notification announces; alerts are not special."""
        bus, _repository, _service, announced = wiring
        bus.publish(
            EventType.NOTIFICATION_RAISED,
            NotificationPayload(title="Backup complete", message="ok"),
        )
        assert len(announced) == 1


# ---------------------------------------------------------------------------
# Nothing else reaches the speaker
# ---------------------------------------------------------------------------
class TestNothingElseIsAnnounced:
    def test_a_failed_insert_announces_nothing(self) -> None:
        """No record, no sound: a beep for an alert that was never stored
        would tell the operator something exists when it does not."""
        bus = EventBus()
        service = NotificationService(
            _Repository(fail=True), _Repository(), _Settings(), bus
        )
        announced: list[Any] = []
        bus.subscribe(
            (EventType.NOTIFICATION_STORED,),
            lambda event: announced.append(event.payload),
            queued=False,
            name="test-listener",
        )
        bus.publish(EventType.SNORT_ALERT_RECEIVED, _AlertPayload(_Alert(1)))
        assert announced == []
        service.close()

    def test_an_alert_below_the_threshold_is_not_announced(self, wiring) -> None:  # noqa: ANN001
        bus, _repository, _service, announced = wiring
        bus.publish(
            EventType.SNORT_ALERT_RECEIVED,
            _AlertPayload(_Alert(5, severity=Severity.LOW)),
        )
        assert announced == []

    def test_notifications_disabled_announces_nothing(self) -> None:
        bus = EventBus()
        service = NotificationService(
            _Repository(), _Repository(),
            _Settings(**{"notifications.enabled": False}), bus,
        )
        announced: list[Any] = []
        bus.subscribe(
            (EventType.NOTIFICATION_STORED,),
            lambda event: announced.append(event.payload),
            queued=False, name="test-listener",
        )
        bus.publish(EventType.SNORT_ALERT_RECEIVED, _AlertPayload(_Alert(1)))
        assert announced == []
        service.close()

    def test_the_service_does_not_subscribe_to_its_own_announcement(self) -> None:
        """Otherwise storing a notification would store another, forever."""
        body = inspect.getsource(NotificationService.__init__)
        assert "NOTIFICATION_STORED" not in body


# ---------------------------------------------------------------------------
# Startup and repeats
# ---------------------------------------------------------------------------
class TestHistoryIsNotReplayed:
    def test_reading_history_cannot_publish(self) -> None:
        """§11: at startup the badge loads every historical notification. If
        any read path announced, the application would replay months of alerts
        as sound the moment it opened."""
        for name in ("recent", "unread_count", "mark_read", "mark_all_read"):
            method = getattr(NotificationService, name, None)
            if method is None:
                continue
            body = inspect.getsource(method)
            assert "NOTIFICATION_STORED" not in body, (
                f"{name}() announces, so opening the application would sound "
                "for alerts that arrived days ago"
            )

    def test_no_announcement_without_an_insert(self, wiring) -> None:
        """Nothing was stored, so nothing may have been announced."""
        _bus, repository, _service, announced = wiring
        assert repository.created == []
        assert announced == []

    def test_the_event_is_published_from_the_store_path_only(self) -> None:
        import aethra_sec.services.notification_service as module

        source = inspect.getsource(module)
        assert source.count("EventType.NOTIFICATION_STORED") == 1, (
            "more than one publisher would make it possible to announce a "
            "notification that was never written"
        )
        body = inspect.getsource(NotificationService._store)
        assert "EventType.NOTIFICATION_STORED" in body

    def test_it_is_published_after_the_insert_not_before(self) -> None:
        body = inspect.getsource(NotificationService._store)
        insert = body.index("self._repository.create")
        publish = body.index("NOTIFICATION_STORED")
        assert insert < publish

    def test_a_failed_announcement_does_not_undo_the_record(self) -> None:
        body = inspect.getsource(NotificationService._store)
        assert "except Exception" in body.split("NOTIFICATION_STORED")[0][-400:] \
            or "Could not announce" in body


# ---------------------------------------------------------------------------
# The interface listens to the announcement
# ---------------------------------------------------------------------------
class TestTheInterfaceListens:
    def test_the_window_subscribes_to_the_stored_event(self) -> None:
        from aethra_sec.ui import app

        # Notifications moved to a subscription of their own: sharing the
        # main queue let a flood of packet batches evict them before the
        # interface saw one. Either tuple satisfies "the window listens".
        assert EventType.NOTIFICATION_STORED in (
            app._UI_EVENTS + app._NOTIFICATION_EVENTS
        )

    def test_the_window_no_longer_sounds_on_the_request_event(self) -> None:
        """Sounding on the request is what made real alerts silent."""
        from aethra_sec.ui import app

        assert EventType.NOTIFICATION_RAISED not in app._UI_EVENTS

    def test_the_sound_is_triggered_from_the_stored_branch(self) -> None:
        from aethra_sec.ui.app import MainWindow

        body = inspect.getsource(MainWindow)
        branch = body.split("EventType.NOTIFICATION_STORED")[-1][:1200]
        assert "audio.notify(payload)" in branch

    def test_the_sound_call_is_logged_with_the_identifier(self) -> None:
        """§15: the pipeline has to be traceable without a debugger."""
        from aethra_sec.ui.app import MainWindow

        body = inspect.getsource(MainWindow)
        assert "[NOTIFY] Sound" in body
        assert "notification_id" in body

    def test_the_store_logs_what_it_persisted(self) -> None:
        body = inspect.getsource(NotificationService._store)
        assert "[NOTIFY] Stored" in body


# ---------------------------------------------------------------------------
# The sound itself
# ---------------------------------------------------------------------------
class TestTheSoundAsset:
    def test_the_packaged_sound_exists_and_is_readable(self) -> None:
        from aethra_sec.resources import security_alert_sound

        asset = security_alert_sound()
        assert asset.available, f"NOTIFICATION SOUND FILE MISSING: {asset.detail}"
        assert asset.path.exists()
        assert asset.path.stat().st_size > 0

    def test_the_path_is_resolved_not_hardcoded(self) -> None:
        """§3: no developer path may appear in the resolver."""
        import aethra_sec.resources as resources

        source = inspect.getsource(resources)
        for forbidden in ("C:\\\\Users", "C:\\\\xampp", "C:\\\\jay", "/home/"):
            assert forbidden not in source

    def test_the_assets_directory_is_packaged(self) -> None:
        """§13: the installed build must find the same file."""
        from pathlib import Path

        spec = Path(__file__).resolve().parents[1] / "packaging" / "AETHRA-SEC.spec"
        assert spec.exists()
        assert '"assets"' in spec.read_text(encoding="utf-8")

    def test_playback_runs_off_the_ui_thread(self) -> None:
        """§6: the Tk loop must never wait for audio."""
        from aethra_sec.services.audio_alert_service import AudioAlertService

        body = inspect.getsource(AudioAlertService.__init__)
        assert "threading.Thread" in body and "daemon=True" in body

    def test_the_sound_queue_is_bounded(self) -> None:
        """§7: a flood of alerts must not spawn unbounded audio work."""
        from aethra_sec.services.audio_alert_service import AudioAlertService

        body = inspect.getsource(AudioAlertService.__init__)
        assert "maxsize=" in body

    def test_repeats_fold_on_the_alert_identifier(self) -> None:
        """§10: the same database alert must not beep twice."""
        from aethra_sec.services.audio_alert_service import AudioAlertService

        body = inspect.getsource(AudioAlertService._dedup_key)
        assert "reference_type" in body and "reference_id" in body


# ---------------------------------------------------------------------------
# The §4 audio diagnostic
# ---------------------------------------------------------------------------
class TestTheAudioDiagnostic:
    """It must answer from attempts, not from assumptions."""

    @staticmethod
    def _service():  # noqa: ANN205
        from aethra_sec.services.audio_alert_service import AudioAlertService

        class _Stub:
            def get(self, key: str, default: Any = None) -> Any:
                return default

            def get_bool(self, key: str, default: bool = False) -> bool:
                return default

            def get_int(self, key: str, default: int = 0) -> int:
                return default

            def get_str(self, key: str, default: str = "") -> str:
                return default

        return AudioAlertService(_Stub(), player=lambda level: None)

    def test_it_reports_the_four_stages(self) -> None:
        service = self._service()
        try:
            stages = service.diagnose(play=False)
            names = [name for name, _ok, _detail in stages]
            assert "AUDIO FILE FOUND" in names
            assert "AUDIO FILE READABLE" in names
            assert any("PLAYBACK" in name for name in names)
        finally:
            service.close()

    def test_the_packaged_sound_passes_the_file_stages(self) -> None:
        service = self._service()
        try:
            stages = dict((name, ok) for name, ok, _ in service.diagnose(play=False))
            assert stages["AUDIO FILE FOUND"], "NOTIFICATION SOUND FILE MISSING"
            assert stages["AUDIO FILE READABLE"]
        finally:
            service.close()

    def test_it_creates_no_record(self) -> None:
        """A diagnostic must not fabricate a security event to justify itself."""
        body = inspect.getsource(
            __import__(
                "aethra_sec.services.audio_alert_service", fromlist=["x"]
            ).AudioAlertService.diagnose
        )
        for forbidden in ("_store", "Notification(", "publish("):
            assert forbidden not in body

    def test_a_real_error_is_reported_not_swallowed(self) -> None:
        body = inspect.getsource(
            __import__(
                "aethra_sec.services.audio_alert_service", fromlist=["x"]
            ).AudioAlertService.diagnose
        )
        assert "str(exc)" in body or "repr(exc)" in body
        assert "pass" not in body.split("except")[-1][:80]
