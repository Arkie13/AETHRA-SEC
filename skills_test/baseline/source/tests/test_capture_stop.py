"""Stopping capture is not held up by the capture service's own lock.

Found while timing the display-filter work against TShark on a real interface:
every stop took eight seconds, while TShark itself was gone in about a tenth of
one. The service held its lock while it stopped the reader. The reader thread's
last act is to report that it ended, and that report takes the same lock - so
the thread sat blocked until the reader's join timeout gave up on it, and only
then could the stop go on.

Measured on the same interface after the fix: a quarter of a second.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

import pytest

from aethra_sec.config.settings import CaptureSettings, ToolSettings
from aethra_sec.core.errors import CaptureError
from aethra_sec.core.event_bus import EventBus
from aethra_sec.models.traffic import CaptureState
from aethra_sec.services.packet_capture import PacketCaptureService

#: FieldCaptureReader.stop joins its thread for this long before giving up.
READER_JOIN_TIMEOUT = 8.0


class _Settings:
    def get(self, _key: str, default: Any = None) -> Any:
        return default

    def get_int(self, _key: str, default: int = 0) -> int:
        return default

    def get_bool(self, _key: str, default: bool = False) -> bool:
        return default

    def add_listener(self, _listener: Any) -> None:
        pass


class _Access:
    def require(self, session: Any, *_args: Any, **_kwargs: Any) -> Any:
        return session


class _Audit:
    def record(self, *_args: Any, **_kwargs: Any) -> None:
        pass


class _Counters:
    def snapshot(self) -> dict[str, Any]:
        return {}


class _Reader:
    """A reader thread with FieldCaptureReader's stop contract, and no capture.

    ``stop`` signals the thread and joins it with a timeout; the thread's
    ``finally`` reports that it ended through ``on_stopped``. That report is
    the part that needs the service's lock.
    """

    def __init__(self, on_stopped: Callable[[str], None]) -> None:
        self.counters = _Counters()
        self._on_stopped = on_stopped
        self._signal = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="reader-under-test", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        try:
            self._signal.wait()
        finally:
            self._on_stopped("operator request")

    @property
    def is_running(self) -> bool:
        return self._thread.is_alive()

    def capture_process_alive(self) -> bool:
        return not self._signal.is_set()

    def stop(self, timeout: float = READER_JOIN_TIMEOUT, reason: str = "") -> None:
        self._signal.set()
        self._thread.join(timeout=timeout)


def _service() -> PacketCaptureService:
    return PacketCaptureService(
        traffic=None, hosts=None, alerts=None,  # type: ignore[arg-type]
        settings=_Settings(),  # type: ignore[arg-type]
        event_bus=EventBus(),
        audit=_Audit(),  # type: ignore[arg-type]
        access=_Access(),  # type: ignore[arg-type]
        tools=ToolSettings(),
        capture_settings=CaptureSettings(),
    )


def _capturing() -> tuple[PacketCaptureService, _Reader]:
    service = _service()
    reader = _Reader(service._on_reader_stopped)  # noqa: SLF001
    service._reader = reader  # noqa: SLF001
    service._state = CaptureState.CAPTURING  # noqa: SLF001
    return service, reader


class TestAStopIsNotHeldUpByTheLock:
    def test_the_stop_finishes_when_the_reader_does(self) -> None:
        service, reader = _capturing()
        started = time.monotonic()
        service.stop(object(), "operator request")
        elapsed = time.monotonic() - started
        assert not reader.is_running
        assert elapsed < READER_JOIN_TIMEOUT / 4, (
            f"stop took {elapsed:.1f} s: the reader thread waited on the service lock"
        )

    def test_an_operator_stop_still_ends_stopped(self) -> None:
        """The reader now reports its end during STOPPING, which is no failure."""
        service, _reader = _capturing()
        service.stop(object(), "operator request")
        assert service.state is CaptureState.STOPPED
        assert service.statistics().last_error == ""


class TestNoStartWhileAStopIsUnderWay:
    def test_a_start_during_stopping_is_refused(self) -> None:
        """The stop has released the lock and has yet to join its worker."""
        service = _service()
        service._state = CaptureState.STOPPING  # noqa: SLF001
        with pytest.raises(CaptureError) as refused:
            service.start(object(), "capture-interface", "")
        assert refused.value.user_message == (
            "Packet capture is still stopping. Try again in a moment."
        )
        assert service._state is CaptureState.STOPPING  # noqa: SLF001
        assert service._reader is None  # noqa: SLF001
