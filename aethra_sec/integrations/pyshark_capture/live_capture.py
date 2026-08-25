"""Live packet capture through PyShark/TShark.

The reader owns one background thread that runs ``sniff_continuously()`` and
pushes mapped packets into a **bounded** queue. When the queue is full the
newest packet is dropped and a counter increments, which is what keeps a busy
LAN from turning into unbounded memory growth (§105, §106). The drop counter is
displayed, never hidden.

PyShark builds on asyncio, so the reader installs a fresh event loop on its own
thread before starting; this is what makes capture safe to run outside the main
thread.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from aethra_sec.core.errors import CaptureError, ToolUnavailableError
from aethra_sec.integrations.pyshark_capture.interfaces import (
    TSHARK_MISSING_MESSAGE,
    probe_tshark,
)
from aethra_sec.integrations.pyshark_capture.mapper import map_packet
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("integrations.pyshark.capture")


@dataclass
class CaptureCounters:
    """Live counters owned by the reader thread.

    Every value is a real measurement; ``dropped`` in particular is surfaced so
    the operator can see when the pipeline is shedding load.
    """

    captured: int = 0
    dropped: int = 0
    decode_errors: int = 0
    bytes_seen: int = 0
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    last_packet_at: datetime | None = None
    last_error: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict[str, Any]:
        """Thread-safe copy of the counters."""
        with self._lock:
            return {
                "captured": self.captured,
                "dropped": self.dropped,
                "decode_errors": self.decode_errors,
                "bytes_seen": self.bytes_seen,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "last_packet_at": self.last_packet_at,
                "last_error": self.last_error,
            }


class LiveCaptureReader:
    """Runs TShark through PyShark and yields mapped packets on a queue."""

    def __init__(
        self,
        interface: str,
        packet_queue: "queue.Queue[CapturedPacket]",
        *,
        bpf_filter: str = "",
        tshark_path: Path | None = None,
        use_json: bool = False,
        on_error: Callable[[str], None] | None = None,
        on_started: Callable[[], None] | None = None,
        on_stopped: Callable[[str], None] | None = None,
    ) -> None:
        """Create a (not yet started) reader.

        Args:
            interface: capture interface name exactly as TShark reports it.
            packet_queue: bounded queue the reader pushes into.
            bpf_filter: optional capture filter applied by TShark itself.
            tshark_path: explicit tshark executable.
            use_json: use TShark's JSON output; faster but exposes fewer
                fields. PDML (the default) is preferred for analysis fidelity.
            on_error / on_started / on_stopped: lifecycle callbacks invoked on
                the reader thread.
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.counters = CaptureCounters()
        self._queue = packet_queue
        self._tshark_path = tshark_path
        self._use_json = use_json
        self._on_error = on_error
        self._on_started = on_started
        self._on_stopped = on_stopped
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._capture: Any = None
        self._stop_reason = ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        """True while the reader thread is alive."""
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        """Start capture.

        Raises:
            ToolUnavailableError: when TShark/PyShark are not usable.
            CaptureError: when no interface was selected or capture is already
                running.
        """
        if self.is_running:
            raise CaptureError(
                "Capture is already running.",
                user_message="Packet capture is already running.",
            )
        if not self.interface:
            raise CaptureError(
                "No capture interface selected.",
                user_message=(
                    "Select a network interface before starting capture."
                ),
            )

        availability = probe_tshark(self._tshark_path)
        if not availability.available:
            raise ToolUnavailableError(
                "TShark",
                availability.detail or TSHARK_MISSING_MESSAGE,
                user_message=availability.detail or TSHARK_MISSING_MESSAGE,
            )

        self._stop.clear()
        self._stop_reason = ""
        self.counters.started_at = utcnow()
        self.counters.stopped_at = None
        self.counters.last_error = ""
        self._thread = threading.Thread(
            target=self._run,
            name=f"capture-reader-{self.interface}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 8.0, reason: str = "operator request") -> None:
        """Signal the reader to stop and wait briefly for it to finish.

        ``sniff_continuously()`` blocks until the next packet arrives, so on a
        quiet interface the stop flag alone could take minutes to take effect.
        Terminating the TShark child process makes the iterator return
        immediately, which is what lets the Stop button feel instant.
        """
        self._stop_reason = reason
        self._stop.set()
        self._terminate_tshark()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        self.counters.stopped_at = utcnow()

    def _terminate_tshark(self) -> None:
        """Terminate the TShark child process by pid.

        PyShark's own ``close()`` drives the capture's asyncio loop, which
        belongs to the reader thread; calling it from the UI thread is unsafe.
        Signalling the process by pid is thread-safe on both Windows and POSIX.
        """
        capture = self._capture
        if capture is None:
            return
        pids: list[int] = []
        for attribute in ("_running_processes", "_current_tshark"):
            candidate = getattr(capture, attribute, None)
            if candidate is None:
                continue
            processes = candidate if isinstance(candidate, (set, list, tuple)) else [candidate]
            for process in processes:
                pid = getattr(process, "pid", None)
                if isinstance(pid, int) and pid > 0:
                    pids.append(pid)

        for pid in set(pids):
            try:
                import psutil

                proc = psutil.Process(pid)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
            except Exception:  # noqa: BLE001 - already gone, or not ours
                LOGGER.debug("Could not terminate TShark pid %s.", pid, exc_info=True)

    # ------------------------------------------------------------------
    # Reader thread
    # ------------------------------------------------------------------
    def _run(self) -> None:
        """Reader thread body."""
        import asyncio

        try:
            import pyshark
        except Exception as exc:  # noqa: BLE001
            self._fail(f"PyShark is not importable: {exc}")
            return

        # PyShark drives TShark through asyncio; a worker thread has no loop of
        # its own, so one is installed before the capture object is built.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            kwargs: dict[str, Any] = {
                "interface": self.interface,
                "use_json": self._use_json,
                "include_raw": False,
                "eventloop": loop,
            }
            if self.bpf_filter:
                kwargs["bpf_filter"] = self.bpf_filter
            if self._tshark_path:
                kwargs["tshark_path"] = str(self._tshark_path)

            capture = pyshark.LiveCapture(**kwargs)
            self._capture = capture
        except Exception as exc:  # noqa: BLE001
            self._fail(self._explain(str(exc)))
            self._close_loop(loop)
            return

        if self._on_started:
            try:
                self._on_started()
            except Exception:  # noqa: BLE001
                LOGGER.exception("Capture start callback failed.")

        LOGGER.info(
            "Capture started on '%s'%s",
            self.interface,
            f" with filter '{self.bpf_filter}'" if self.bpf_filter else "",
        )

        try:
            for raw_packet in capture.sniff_continuously():
                if self._stop.is_set():
                    break
                self._handle(raw_packet)
        except (EOFError, StopIteration):
            pass
        except Exception as exc:  # noqa: BLE001
            if not self._stop.is_set():
                self._fail(self._explain(str(exc)))
                self._close_loop(loop)
                return
        finally:
            self._teardown(capture)
            # Drop the last strong reference before closing the loop: PyShark's
            # Capture.__del__ calls close(), which needs a live event loop.
            capture = None
            self._close_loop(loop)

        self.counters.stopped_at = utcnow()
        if self._on_stopped:
            try:
                self._on_stopped(self._stop_reason or "capture ended")
            except Exception:  # noqa: BLE001
                LOGGER.exception("Capture stop callback failed.")
        LOGGER.info(
            "Capture stopped on '%s' after %d packet(s), %d dropped.",
            self.interface,
            self.counters.captured,
            self.counters.dropped,
        )

    def _handle(self, raw_packet: Any) -> None:
        """Map one packet and enqueue it, applying backpressure when full."""
        mapped = map_packet(raw_packet, self.interface)
        if mapped is None:
            with self.counters._lock:  # noqa: SLF001 - counters own this lock
                self.counters.decode_errors += 1
            return

        with self.counters._lock:  # noqa: SLF001
            self.counters.captured += 1
            self.counters.bytes_seen += mapped.length
            self.counters.last_packet_at = mapped.captured_at

        try:
            self._queue.put_nowait(mapped)
        except queue.Full:
            # Drop the newest packet rather than blocking the reader: falling
            # behind TShark loses far more traffic than skipping one packet.
            with self.counters._lock:  # noqa: SLF001
                self.counters.dropped += 1

    def _teardown(self, capture: Any) -> None:
        """Close the PyShark capture object from its own thread.

        Called on the reader thread, where the capture's event loop lives, so
        ``close()`` is safe here even though it is not from the UI thread.
        """
        try:
            close = getattr(capture, "close", None)
            if callable(close):
                close()
        except Exception:  # noqa: BLE001 - TShark may already have exited
            LOGGER.debug("Capture close raised during teardown.", exc_info=True)
        finally:
            # We stop TShark by signalling it, so PyShark sees a non-zero exit
            # code and treats an ordinary stop as a crash. Clearing its process
            # references stops Capture.__del__ from re-running that cleanup -
            # and raising - later, at interpreter garbage-collection time, and
            # lets the subprocess transports be collected while the event loop
            # is still open.
            try:
                running = getattr(capture, "_running_processes", None)
                if isinstance(running, set):
                    running.clear()
                if hasattr(capture, "_current_tshark"):
                    capture._current_tshark = None  # noqa: SLF001
                tasks = getattr(capture, "_stderr_handling_tasks", None)
                if isinstance(tasks, list):
                    for task in tasks:
                        try:
                            task.cancel()
                        except Exception:  # noqa: BLE001
                            pass
                    tasks.clear()
            except Exception:  # noqa: BLE001
                LOGGER.debug("Could not clear PyShark process state.", exc_info=True)
        self._capture = None

    @staticmethod
    def _close_loop(loop: Any) -> None:
        """Close the reader thread's event loop cleanly.

        PyShark's subprocess transports close themselves when garbage
        collected, and that must happen while the loop is still open - so the
        capture object is collected first and the loop is given one turn to run
        the resulting callbacks before it is closed.
        """
        import asyncio
        import gc

        try:
            if not loop.is_closed():
                for task in asyncio.all_tasks(loop):
                    task.cancel()
                loop.run_until_complete(asyncio.sleep(0))
                gc.collect()
                loop.run_until_complete(asyncio.sleep(0))
                loop.run_until_complete(loop.shutdown_asyncgens())
                gc.collect()
                loop.run_until_complete(asyncio.sleep(0))
        except Exception:  # noqa: BLE001 - best-effort drain
            LOGGER.debug("Event loop drain raised.", exc_info=True)
        try:
            loop.close()
        except Exception:  # noqa: BLE001
            LOGGER.debug("Event loop close raised.", exc_info=True)

    def _fail(self, message: str) -> None:
        """Record a capture failure and notify the owner."""
        self.counters.last_error = message
        self.counters.stopped_at = utcnow()
        LOGGER.error("Capture failed on '%s': %s", self.interface, message)
        if self._on_error:
            try:
                self._on_error(message)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Capture error callback failed.")

    def _explain(self, message: str) -> str:
        """Translate a raw TShark/PyShark error into actionable guidance (§101)."""
        lowered = message.lower()
        if "permission" in lowered or "operation not permitted" in lowered:
            return (
                f"Permission denied opening '{self.interface}'. On Windows run "
                "AETHRA-SEC as Administrator (and install Npcap); on Linux run "
                "as root or grant capabilities: "
                "sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap). "
                f"Original error: {message}"
            )
        if "no such device" in lowered or "not found" in lowered:
            return (
                f"The interface '{self.interface}' is not available. Refresh "
                "the interface list on the Settings screen and select an "
                f"interface that TShark reports. Original error: {message}"
            )
        if "npcap" in lowered or "winpcap" in lowered:
            return (
                "The Npcap capture driver is missing or not working. Install "
                f"Npcap from https://npcap.com and restart. Original error: {message}"
            )
        if "tshark" in lowered and (
            "not found" in lowered or "could not be found" in lowered
        ):
            return TSHARK_MISSING_MESSAGE
        if "syntax error" in lowered or "bpf" in lowered or "filter" in lowered:
            return (
                f"The capture filter '{self.bpf_filter}' was rejected by "
                f"TShark. Check the BPF syntax. Original error: {message}"
            )
        return f"Packet capture failed: {message}"
