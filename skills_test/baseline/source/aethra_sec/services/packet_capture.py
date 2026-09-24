"""Live capture pipeline service (§11-§14, §36, §105, §106).

Wiring::

    TShark -> PyShark -> LiveCaptureReader -> bounded queue
                                                  |
                                        capture-worker thread
                                          |         |        |
                                 TrafficAnalyzer  rules   batched writes
                                          |         |        |
                                        EventBus  anomalies  MySQL

The worker is the only place packets are touched after decode. It owns
batching, sampling, host aggregation and anomaly persistence, so the reader
never blocks on the database and the Tk thread never touches a packet at all.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from aethra_sec.analytics.anomaly_rules import (
    AnomalyRuleEngine,
    DetectionThresholds,
    thresholds_from_settings,
)
from aethra_sec.analytics.display_filter import validate_filter
from aethra_sec.analytics.traffic_analyzer import TrafficAnalyzer, summarise_hosts
from aethra_sec.config.settings import CaptureSettings, ToolSettings
from aethra_sec.core.errors import CaptureError, ToolUnavailableError
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import (
    AnomalyPayload,
    CaptureStatusPayload,
    ErrorPayload,
    EventType,
    PacketBatchPayload,
    TrafficStatsPayload,
)
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.database.repositories.traffic import TrafficRepository
from aethra_sec.integrations.pyshark_capture import (
    CaptureInterface,
    LiveCaptureReader,
    list_capture_interfaces,
    probe_tshark,
    validate_capture_filter,
)
from aethra_sec.integrations.pyshark_capture.field_reader import (
    FieldCaptureReader,
)
from aethra_sec.analytics.host_naming import SOURCE_MDNS, announced_hostname
from aethra_sec.models.enums import EvidenceSource
from aethra_sec.models.traffic import (
    CapturedPacket,
    CaptureState,
    CaptureStatistics,
    TrafficAggregate,
)
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.packet_view import PacketView, ViewStatistics
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import (
    host_address_rejection,
    is_on_link,
    local_ipv4_networks,
)
from aethra_sec.utils.timeutil import to_db, utcnow

#: How long the capture child may take to appear before STARTING is
#: judged a failure. Long enough for TShark to spawn on a loaded
#: machine, short enough that a rejected start is reported promptly.
STARTUP_GRACE_SECONDS = 8.0

def _is_host_mac(mac: str) -> bool:
    """True when ``mac`` can be one host's own hardware address.

    Broadcast and multicast addresses belong to no single machine, and the
    destination MAC of an off-LAN frame is the router's, not the remote host's.
    Storing either against an address invents a hardware identity for it: the
    inventory ended up with hundreds of hosts sharing one gateway MAC, and
    hundreds more carrying ff:ff:ff:ff:ff:ff.
    """
    cleaned = (mac or "").strip().lower().replace("-", ":")
    if len(cleaned) < 17:
        return False
    try:
        first = int(cleaned.split(":")[0], 16)
    except ValueError:
        return False
    if cleaned == "ff:ff:ff:ff:ff:ff":
        return False
    # Bit 0 of the first octet marks a group (multicast) address.
    return not first & 0x01


LOGGER = get_logger("services.capture")


@dataclass
class PipelineCounters:
    """Counters owned by the processing worker."""

    processed: int = 0
    persisted_rows: int = 0
    sampled_out: int = 0
    anomalies_raised: int = 0
    anomalies_suppressed: int = 0
    write_failures: int = 0
    last_flush_at: datetime | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict[str, Any]:
        """Thread-safe copy."""
        with self._lock:
            return {
                "processed": self.processed,
                "persisted_rows": self.persisted_rows,
                "sampled_out": self.sampled_out,
                "anomalies_raised": self.anomalies_raised,
                "anomalies_suppressed": self.anomalies_suppressed,
                "write_failures": self.write_failures,
                "last_flush_at": self.last_flush_at,
            }


class PacketCaptureService:
    """Owns the live capture pipeline end to end."""

    def __init__(
        self,
        traffic: TrafficRepository,
        hosts: HostRepository,
        alerts: AlertRepository,
        settings: SettingsService,
        event_bus: EventBus,
        audit: AuditService,
        access: AccessControl,
        tools: ToolSettings,
        capture_settings: CaptureSettings,
        capture_dir: Path | None = None,
    ) -> None:
        """Wire the service to its collaborators."""
        self._traffic = traffic
        self._hosts = hosts
        self._alerts = alerts
        self._settings = settings
        self._bus = event_bus
        self._audit = audit
        self._access = access
        self._tools = tools
        self._capture_settings = capture_settings
        #: Directory each session's pcap is written into. Without it capture
        #: still runs; only packet inspection is unavailable, and the inspector
        #: says so rather than showing a summary dressed up as a decode.
        self._capture_dir = capture_dir
        #: The pcap the running session is writing to.
        self._capture_file: Path | None = None

        self.analyzer = TrafficAnalyzer(
            rate_window_seconds=settings.get_int("detection.rate_window_seconds", 5)
        )
        self.rules = AnomalyRuleEngine(thresholds_from_settings(settings.get))
        self.counters = PipelineCounters()
        #: Recent packets and the display filter applied to them. Owned here,
        #: beside the pipeline that feeds it, so what the table can show and
        #: the counts behind it do not depend on which screen happens to be
        #: open. It never feeds anything back into capture.
        self.view = PacketView(event_bus.publish)

        self._queue: "queue.Queue[CapturedPacket]" = queue.Queue(
            maxsize=settings.get_int("capture.queue_size", 20_000)
        )
        self._reader: LiveCaptureReader | None = None
        self._worker: threading.Thread | None = None
        self._stop_worker = threading.Event()
        self._lock = threading.RLock()
        self._interface = capture_settings.interface
        self._bpf = capture_settings.bpf_filter
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._last_error = ""
        #: The authoritative capture state. Every screen reads this rather
        #: than deciding for itself whether capture is running.
        self._state: CaptureState = CaptureState.IDLE
        self._aggregate_anchor: datetime | None = None
        self._host_flush_anchor = time.monotonic()
        self._minute_anchor = time.monotonic()
        self._minute_rows = 0
        self._pending_hosts: dict[str, dict[str, Any]] = {}
        #: Subnets of the *monitored* adapter, refreshed periodically so the
        #: answer stays right after the machine moves network. Only when that
        #: adapter cannot be identified does this fall back to every attached
        #: subnet - the discovery inventory then over-includes, but automatic
        #: assessment separately refuses to run without a resolved scope.
        self._local_networks: tuple[Any, ...] = ()
        self._local_networks_at = 0.0
        #: The operating-system adapter behind the capture device, resolved
        #: once when capture starts ("Wi-Fi", "Loopback Pseudo-Interface 1").
        self._monitored_adapter = ""
        #: Address -> on-link, so the membership test is a dict lookup on the
        #: per-packet path. Addresses repeat heavily, so this hits almost
        #: always; it is cleared with the subnets it was derived from.
        self._onlink_cache: dict[str, bool] = {}

        settings.add_listener(self._on_setting_changed)

    # ------------------------------------------------------------------
    # Availability and interfaces
    # ------------------------------------------------------------------
    def availability(self) -> Any:
        """Probe TShark/PyShark (§10, §101)."""
        return probe_tshark(self._tools.tshark_path)

    def list_interfaces(self) -> list[CaptureInterface]:
        """Enumerate capture interfaces exactly as TShark reports them."""
        return list_capture_interfaces(self._tools.tshark_path)

    @property
    def interface(self) -> str:
        """Currently selected capture interface."""
        return self._interface

    @property
    def bpf_filter(self) -> str:
        """Capture-level BPF filter, applied by TShark itself."""
        return self._bpf

    @property
    def is_running(self) -> bool:
        """True only while capture is genuinely active.

        Both halves are required. The thread being alive says the pipeline was
        started; the child process being alive says it is still capturing. A
        rejected filter leaves the first true and the second false, which is
        exactly the case that used to report CAPTURING.
        """
        reader = self._reader
        if reader is None or not reader.is_running:
            return False
        return reader.capture_process_alive()

    @property
    def state(self) -> CaptureState:
        """The pipeline's state, reconciled with the real process.

        Reading is where reconciliation happens, so a capture that dies on its
        own - a crashed process, an interface pulled out - is noticed the next
        time anything asks, rather than staying CAPTURING until someone presses
        Stop.
        """
        with self._lock:
            current = self._state
            reader = self._reader

        if current is CaptureState.STARTING:
            # Give the child a moment to appear before judging it.
            if reader is not None and reader.capture_process_alive():
                with self._lock:
                    self._state = CaptureState.CAPTURING
                return CaptureState.CAPTURING
            waited = (utcnow() - self._started_at).total_seconds() if self._started_at else 0.0
            if waited > STARTUP_GRACE_SECONDS:
                message = (
                    self._last_error
                    or "The capture process stopped immediately after starting."
                )
                with self._lock:
                    self._state = CaptureState.FAILED
                    self._last_error = message
                return CaptureState.FAILED
            return CaptureState.STARTING

        if current is CaptureState.CAPTURING:
            if reader is None or not reader.capture_process_alive():
                with self._lock:
                    self._state = CaptureState.FAILED
                    if not self._last_error:
                        self._last_error = (
                            "The capture process stopped unexpectedly."
                        )
                return CaptureState.FAILED

        return current

    def statistics(self) -> CaptureStatistics:
        """Real capture counters for the UI and health screen."""
        reader = self._reader
        reader_counters = reader.counters.snapshot() if reader else {}
        pipeline = self.counters.snapshot()
        # Read the property, not the field: it reconciles against the real
        # process, so a capture that has died is reported as FAILED here.
        current_state = self.state
        return CaptureStatistics(
            interface=self._interface,
            is_running=current_state is CaptureState.CAPTURING,
            state=str(current_state),
            started_at=self._started_at,
            stopped_at=self._stopped_at,
            total_packets=int(reader_counters.get("captured", 0)),
            total_bytes=int(reader_counters.get("bytes_seen", 0)),
            dropped=int(reader_counters.get("dropped", 0)),
            sampled_out=int(pipeline.get("sampled_out", 0)),
            persisted_rows=int(pipeline.get("persisted_rows", 0)),
            decode_errors=int(reader_counters.get("decode_errors", 0)),
            last_packet_at=reader_counters.get("last_packet_at"),
            queue_depth=self._queue.qsize(),
            last_error=str(reader_counters.get("last_error", "") or self._last_error),
            bpf_filter=self._bpf,
        )

    # ------------------------------------------------------------------
    # Display filter
    # ------------------------------------------------------------------
    def set_display_filter(
        self, session: Session, expression: str
    ) -> tuple[bool, str, int]:
        """Apply a display filter to captured packets.

        This is a viewing decision, so it needs only ``monitor.view``, and it
        touches nothing but the packet view: the reader, the capture process,
        detection and storage are exactly as they were. An invalid expression
        is refused before it reaches the view, so the filter already in force
        stays in force.

        Returns:
            ``(applied, error, generation)``. ``generation`` identifies the
            re-filtered table the view will publish; on refusal it is the
            current one.
        """
        self._access.require(session, Permission.MONITOR_VIEW)
        compiled, error = validate_filter(expression)
        if compiled is None:
            return False, error, self.view.generation
        return True, "", self.view.apply_filter(compiled)

    def refresh_display_view(self, session: Session) -> int:
        """Re-publish the current matches, e.g. after the display was paused."""
        self._access.require(session, Permission.MONITOR_VIEW)
        return self.view.refresh()

    def display_statistics(self) -> ViewStatistics:
        """The packet view's latest counts."""
        return self.view.statistics()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(
        self,
        session: Session,
        interface: str = "",
        bpf_filter: str | None = None,
    ) -> None:
        """Start live capture.

        Raises:
            PermissionDeniedError: without ``monitor.control``.
            CaptureError: when no interface is selected or capture is running.
            ToolUnavailableError: when TShark/PyShark are unusable.
        """
        live = self._access.require(
            session, Permission.MONITOR_CONTROL, target=interface or self._interface
        )
        with self._lock:
            # Guard on the state machine, not on is_running. Between the
            # reader thread starting and TShark actually appearing, is_running
            # is False while a capture is very much under way - so a second
            # start slipped through that window, overwrote the interface, the
            # filter and the state, and left a healthy capture reporting FAILED
            # while packets were still arriving. STARTING is busy too.
            if self.state.is_active:
                raise CaptureError(
                    "Capture already running.",
                    user_message="Packet capture is already running.",
                )
            # A stop still under way releases the lock while its reader
            # finishes and its worker drains. Starting in that window would
            # hand the stop a new reader and worker to tear down.
            if self._state is CaptureState.STOPPING:
                raise CaptureError(
                    "Capture is still stopping.",
                    user_message="Packet capture is still stopping. Try again in a moment.",
                )

            self._interface = (interface or self._interface).strip()
            if bpf_filter is not None:
                self._bpf = bpf_filter.strip()
            if not self._interface:
                raise CaptureError(
                    "No interface selected.",
                    user_message=(
                        "Select a network interface before starting capture. "
                        "Available interfaces are listed on the Network "
                        "Monitoring and Settings screens."
                    ),
                )

            # Compile the filter against this interface before anything is
            # started. PyShark does not report a rejected filter - dumpcap
            # exits and the reader thread waits for packets that never come -
            # so a filter that will fail has to be caught here, while the
            # failure can still be attributed to its cause.
            self._state = CaptureState.STARTING
            ok, reason = validate_capture_filter(
                self._interface, self._bpf, self._tools.tshark_path
            )
            if not ok:
                self._state = CaptureState.FAILED
                self._last_error = reason
                self._stopped_at = utcnow()
                self._audit.record(
                    AuditAction.CAPTURE_ERROR,
                    session=live,
                    category=AuditCategory.MONITORING,
                    target_type="interface",
                    target_id=self._interface,
                    result="FAILURE",
                    detail=reason,
                )
                self._bus.publish(
                    EventType.CAPTURE_ERROR, ErrorPayload("packet_capture", reason)
                )
                raise CaptureError(reason, user_message=reason)

            self._queue = queue.Queue(
                maxsize=self._settings.get_int("capture.queue_size", 20_000)
            )
            self.rules.update_thresholds(thresholds_from_settings(self._settings.get))
            self.rules.update_trusted(self._safe_trusted_addresses())
            self._resolve_monitored_adapter()
            self._last_error = ""
            self._stopped_at = None
            self._aggregate_anchor = utcnow()
            self._minute_anchor = time.monotonic()
            self._minute_rows = 0

            self._capture_file = self._new_capture_file()
            # A new session for the view: the previous capture's packets and
            # counts are dropped and this interface's addresses are read
            # again. The display filter is kept across the restart.
            self.view.begin_session(self._interface)
            # Two decode paths, one choice. Field extraction reads only the
            # fields the rules and the table use and measured 11x faster on
            # the same packets; PyShark's full decode remains selectable for
            # an installation that needs a field this list does not carry.
            # Detailed inspection is unaffected either way: it opens the
            # capture file, which is written in full by both paths.
            use_fields = self._settings.get_bool("capture.fast_field_decode", True)
            reader_options: dict[str, Any] = {
                "bpf_filter": self._bpf,
                "tshark_path": self._tools.tshark_path,
                "output_file": self._capture_file,
                "on_error": self._on_reader_error,
                "on_stopped": self._on_reader_stopped,
            }
            reader: Any
            if use_fields:
                # The protocol fields and TShark's Info column cost decode
                # time: ~30,000 packets/s with the core fields against ~12,000
                # with all of them, measured on the same capture. They default
                # on because the packet table, the display filter and the
                # detail pane use them. An installation that sees drops under a
                # flood can switch them off; detection needs only the core set.
                reader_options["extended_fields"] = self._settings.get_bool(
                    "capture.extended_field_decode", True
                )
                # Bound the evidence pcap. Measured on this machine's Wi-Fi,
                # one session wrote 31.8 MB in 150 seconds - about 18 GB a day
                # - into a single file with nothing to stop it. The ring caps
                # the total at filesize x files and lets TShark delete the
                # oldest; setting either to 0 restores the single file.
                reader_options["ring_filesize_kb"] = max(
                    0, self._settings.get_int("capture.pcap_ring_mb", 64)
                ) * 1024
                reader_options["ring_files"] = max(
                    0, self._settings.get_int("capture.pcap_ring_files", 8)
                )
                reader = FieldCaptureReader(self._interface, self._queue, **reader_options)
            else:
                reader = LiveCaptureReader(self._interface, self._queue, **reader_options)
            try:
                reader.start()
            except (CaptureError, ToolUnavailableError) as exc:
                self._state = CaptureState.FAILED
                self._last_error = exc.user_message
                self._audit.record(
                    AuditAction.CAPTURE_ERROR,
                    session=live,
                    category=AuditCategory.MONITORING,
                    target_type="interface",
                    target_id=self._interface,
                    result="FAILURE",
                    detail=exc.user_message,
                )
                self._bus.publish(
                    EventType.CAPTURE_ERROR,
                    ErrorPayload("packet_capture", exc.user_message),
                )
                raise

            self._reader = reader
            self._started_at = utcnow()
            self._stop_worker.clear()
            self._worker = threading.Thread(
                target=self._process_loop, name="capture-worker", daemon=True
            )
            self._worker.start()
            # One view thread for the life of the service; a second start is a
            # no-op, so restarting capture never adds a worker.
            self.view.start()

        self._audit.record(
            AuditAction.CAPTURE_STARTED,
            session=live,
            category=AuditCategory.MONITORING,
            target_type="interface",
            target_id=self._interface,
            detail=(
                f"Live capture started on '{self._interface}'"
                + (f" with filter '{self._bpf}'" if self._bpf else "")
                + "."
            ),
        )
        self._bus.publish(
            EventType.CAPTURE_STARTED,
            CaptureStatusPayload(
                interface=self._interface,
                detail="Capture started",
                started_at=self._started_at,
            ),
        )
        LOGGER.info("Capture pipeline started on '%s'.", self._interface)

    def stop(self, session: Session, reason: str = "operator request") -> None:
        """Stop capture on an operator's instruction.

        The session is required. This previously defaulted to ``None`` and
        checked the permission only ``if session is not None``, which made
        authorization opt-in: passing ``None`` stopped the capture pipeline
        with no check at all. Shutdown, the one caller that genuinely has no
        session, now says so by calling :meth:`stop_for_shutdown`.
        """
        live = self._access.require(session, Permission.MONITOR_CONTROL)
        self._stop(reason, live)

    def stop_for_shutdown(self, reason: str = "application shutdown") -> None:
        """Stop capture during teardown, where no session exists.

        Separate from :meth:`stop` so that "no session" is a deliberate
        internal path rather than something an untrusted caller can imitate.
        """
        self._stop(reason, None)

    def _stop(self, reason: str, live: Session | None) -> None:
        """Tear the pipeline down. Callers above decide who is allowed to."""
        with self._lock:
            if self._state.is_active:
                self._state = CaptureState.STOPPING
            reader = self._reader

        # The reader is stopped without holding the lock. Its thread's last act
        # is to report that it ended (_on_reader_stopped), and that report
        # takes the lock: holding it here left the thread blocked until the
        # join gave up, so every stop took the reader's whole join timeout -
        # eight seconds - however quickly TShark itself exited.
        if reader is not None:
            reader.stop(reason=reason)
        with self._lock:
            self._stop_worker.set()
            worker = self._worker
        if worker and worker.is_alive():
            worker.join(timeout=10)
        with self._lock:
            self._worker = None
            self._stopped_at = utcnow()
            # An operator-driven stop ends at STOPPED. A stop that followed a
            # failure keeps FAILED, so the reason stays on screen.
            if self._state is not CaptureState.FAILED:
                self._state = CaptureState.STOPPED

        self._flush_aggregate(force=True)
        self._flush_host_observations(force=True)

        statistics = self.statistics()
        self._audit.record(
            AuditAction.CAPTURE_STOPPED,
            session=live,
            category=AuditCategory.MONITORING,
            target_type="interface",
            target_id=self._interface,
            detail=(
                f"Capture stopped ({reason}). {statistics.total_packets} "
                f"packet(s) captured, {statistics.dropped} dropped, "
                f"{statistics.persisted_rows} metadata row(s) stored."
            ),
        )
        self._bus.publish(
            EventType.CAPTURE_STOPPED,
            CaptureStatusPayload(
                interface=self._interface,
                detail=reason,
                packets_captured=statistics.total_packets,
                started_at=self._started_at,
            ),
        )
        LOGGER.info("Capture pipeline stopped (%s).", reason)

    def shutdown(self) -> None:
        """Stop capture during application shutdown.

        Goes through :meth:`stop_for_shutdown`, which is the path that exists
        for a caller with no session. This used to call :meth:`stop` with
        ``None``; once that stopped accepting a missing session - so that
        authorization could not be skipped by passing one - every shutdown
        raised here instead of stopping the capture, and the dumpcap child
        outlived the console that started it.
        """
        if self.is_running or self._worker:
            try:
                self.stop_for_shutdown("application shutdown")
            except Exception:  # noqa: BLE001
                LOGGER.exception("Error stopping capture during shutdown.")
        try:
            self.view.stop()
        except Exception:  # noqa: BLE001
            LOGGER.exception("Error stopping the packet view during shutdown.")

    # ------------------------------------------------------------------
    # Reader callbacks
    # ------------------------------------------------------------------
    @property
    def capture_file(self) -> Path | None:
        """The pcap the current (or last) session wrote, if any."""
        return self._capture_file

    def _new_capture_file(self) -> Path | None:
        """Name this session's pcap, or ``None`` when none can be written.

        One file per session, stamped with the interface and start time, so a
        later session never appends to - or renumbers - frames an earlier one
        recorded and the inspector's frame indices stay meaningful.
        """
        if self._capture_dir is None:
            return None
        safe_interface = "".join(
            character if character.isalnum() else "_"
            for character in (self._interface or "capture")
        )[:40]
        stamp = utcnow().strftime("%Y%m%d_%H%M%S")
        return self._capture_dir / f"capture_{safe_interface}_{stamp}.pcapng"

    def _on_reader_error(self, message: str) -> None:
        """Record a capture failure and surface it truthfully."""
        self._last_error = message
        self._audit.record(
            AuditAction.CAPTURE_ERROR,
            category=AuditCategory.MONITORING,
            target_type="interface",
            target_id=self._interface,
            result="FAILURE",
            detail=message,
        )
        with self._lock:
            self._state = CaptureState.FAILED
        self._bus.publish(
            EventType.CAPTURE_ERROR, ErrorPayload("packet_capture", message)
        )

    def _on_reader_stopped(self, reason: str) -> None:
        """Note that the reader thread ended (possibly unexpectedly)."""
        self._stopped_at = utcnow()
        with self._lock:
            # The reader ending while the pipeline still believed it was
            # capturing is a failure, whatever ended it.
            if self._state.is_active:
                self._state = CaptureState.FAILED
                if not self._last_error:
                    self._last_error = (
                        f"The capture stopped unexpectedly ({reason})."
                        if reason else "The capture stopped unexpectedly."
                    )
        if reason and reason != "operator request":
            LOGGER.info("Capture reader ended: %s", reason)

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------
    def _process_loop(self) -> None:
        """Worker body: drain the queue, analyse, persist, publish."""
        batch_size = max(1, self._settings.get_int("capture.persist_batch_size", 200))
        flush_seconds = max(1, self._settings.get_int("capture.persist_flush_seconds", 2))
        persist = self._settings.get_bool("capture.persist_packet_metadata", True)

        pending_rows: list[tuple[Any, ...]] = []
        ui_batch: list[CapturedPacket] = []
        last_flush = time.monotonic()
        last_stats = time.monotonic()

        while not self._stop_worker.is_set() or not self._queue.empty():
            try:
                packet = self._queue.get(timeout=0.25)
            except queue.Empty:
                packet = None

            if packet is not None:
                self._handle_packet(packet, pending_rows, ui_batch, persist)

            now = time.monotonic()
            if pending_rows and (
                len(pending_rows) >= batch_size or (now - last_flush) >= flush_seconds
            ):
                self._write_rows(pending_rows)
                pending_rows.clear()
                last_flush = now

            if ui_batch and (len(ui_batch) >= 50 or (now - last_flush) >= 0.5):
                self._publish_batch(ui_batch)
                ui_batch = []

            if (now - last_stats) >= 1.0:
                self._publish_stats()
                self._flush_aggregate()
                self._flush_host_observations()
                last_stats = now

        if pending_rows:
            self._write_rows(pending_rows)
        if ui_batch:
            self._publish_batch(ui_batch)
        self._publish_stats()

    def _handle_packet(
        self,
        packet: CapturedPacket,
        pending_rows: list[tuple[Any, ...]],
        ui_batch: list[CapturedPacket],
        persist: bool,
    ) -> None:
        """Analyse one packet and queue it for storage and display."""
        with self.counters._lock:  # noqa: SLF001 - counters own this lock
            self.counters.processed += 1

        self.analyzer.observe(packet)
        ui_batch.append(packet)
        self._accumulate_host(packet)

        for anomaly in self.rules.evaluate(packet):
            self._store_anomaly(anomaly)

        if persist and self._allow_row():
            pending_rows.append(
                (
                    to_db(packet.captured_at), packet.interface[:96],
                    packet.src_ip[:45], packet.dst_ip[:45], packet.src_port,
                    packet.dst_port, packet.protocol[:16],
                    packet.app_protocol[:24], packet.length, packet.ttl,
                    packet.tcp_flags, packet.src_mac[:17], packet.dst_mac[:17],
                    packet.info[:255],
                )
            )

    def _allow_row(self) -> bool:
        """Rate-cap per-packet storage (§36).

        Above the configured rows-per-minute ceiling, packets are still fully
        analysed and counted in the aggregates - only row-level storage is
        skipped, and the skipped count is displayed so the operator knows.
        """
        limit = self._settings.get_int("capture.max_packet_rows_per_minute", 6000)
        if limit <= 0:
            return True
        now = time.monotonic()
        if (now - self._minute_anchor) >= 60.0:
            self._minute_anchor = now
            self._minute_rows = 0
        if self._minute_rows >= limit:
            with self.counters._lock:  # noqa: SLF001
                self.counters.sampled_out += 1
            return False
        self._minute_rows += 1
        return True

    def _write_rows(self, rows: list[tuple[Any, ...]]) -> None:
        """Persist a batch of packet metadata rows."""
        try:
            written = self._traffic.insert_batch(rows)
            with self.counters._lock:  # noqa: SLF001
                self.counters.persisted_rows += written
                self.counters.last_flush_at = utcnow()
        except Exception as exc:  # noqa: BLE001 - capture must survive a DB blip
            with self.counters._lock:  # noqa: SLF001
                self.counters.write_failures += 1
            LOGGER.error("Could not persist a packet batch: %s", exc)

    def _publish_batch(self, packets: list[CapturedPacket]) -> None:
        """Hand a batch of real packets to the packet view and the UI."""
        self.view.ingest(packets)
        statistics = self.statistics()
        self._bus.publish(
            EventType.PACKET_BATCH_PROCESSED,
            PacketBatchPayload(
                packets=tuple(packets),
                total_captured=statistics.total_packets,
                dropped=statistics.dropped,
            ),
        )

    def _publish_stats(self) -> None:
        """Publish a recomputed traffic snapshot."""
        try:
            snapshot = self.analyzer.snapshot(
                chart_points=self._settings.get_int("ui.chart_points", 60)
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not build a traffic snapshot.")
            return
        self._bus.publish(EventType.TRAFFIC_STATS_UPDATED, TrafficStatsPayload(snapshot))

    # ------------------------------------------------------------------
    # Anomalies
    # ------------------------------------------------------------------
    def _store_anomaly(self, anomaly: Any) -> None:
        """Persist a fired rule, folding repeats into the existing record."""
        try:
            suppression = self._settings.get_int(
                "detection.suppression_window_seconds", 120
            )
            since = utcnow() - timedelta(seconds=max(1, suppression))
            existing = self._alerts.recent_anomaly(
                (anomaly.rule_id, anomaly.src_ip, anomaly.dst_ip, anomaly.dst_port),
                since,
            )
            if existing and existing.id:
                self._alerts.update_anomaly_occurrence(
                    existing.id,
                    last_seen=anomaly.last_seen or utcnow(),
                    observed_value=anomaly.observed_value,
                )
                with self.counters._lock:  # noqa: SLF001
                    self.counters.anomalies_suppressed += 1
                return

            host_id = self._hosts.find_id_by_ip(anomaly.src_ip) if anomaly.src_ip else None
            anomaly.host_id = host_id
            anomaly.id = self._alerts.insert_anomaly(anomaly)
            with self.counters._lock:  # noqa: SLF001
                self.counters.anomalies_raised += 1
            self._bus.publish(
                EventType.TRAFFIC_ANOMALY_DETECTED,
                AnomalyPayload(anomaly=anomaly, source=EvidenceSource.PYSHARK),
            )
            LOGGER.info(
                "Traffic anomaly recorded: %s (%s -> %s, observed %.2f vs "
                "threshold %.2f)",
                anomaly.rule_id,
                anomaly.src_ip,
                anomaly.dst_ip or "-",
                anomaly.observed_value,
                anomaly.threshold_value,
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not store a traffic anomaly.")

    # ------------------------------------------------------------------
    # Host inventory and aggregates
    # ------------------------------------------------------------------
    #: Individual discovery records written per flush before summarising.
    _DISCOVERY_AUDIT_LIMIT = 25

    def _audit_discoveries(
        self, new_addresses: list[str], observed: dict[str, dict[str, Any]]
    ) -> None:
        """Audit hosts that entered the inventory for the first time.

        One record per new host, from the packet evidence that enrolled it,
        up to a limit per flush; beyond that a single summary record, so a
        busy segment cannot flood the audit trail. Re-observations of known
        hosts are not audited - they are not discoveries.
        """
        if not new_addresses:
            return
        try:
            for address in new_addresses[: self._DISCOVERY_AUDIT_LIMIT]:
                data = observed.get(address, {})
                protocols = ", ".join(sorted(p for p in data.get("protocols", ()) if p))
                self._audit.record(
                    AuditAction.HOST_DISCOVERED,
                    category=AuditCategory.MONITORING,
                    target_type="host",
                    target_id=address,
                    detail=(
                        f"Host {address} discovered on {self._interface}: "
                        f"transmitted {int(data.get('packets_sent', 0))} packet(s)"
                        + (f" ({protocols})" if protocols else "")
                        + (f", MAC {data['mac']}" if data.get("mac") else "")
                        + "."
                    ),
                )
            extra = len(new_addresses) - self._DISCOVERY_AUDIT_LIMIT
            if extra > 0:
                self._audit.record(
                    AuditAction.HOST_DISCOVERED,
                    category=AuditCategory.MONITORING,
                    target_type="host",
                    target_id="multiple",
                    detail=(
                        f"{extra} further host(s) discovered on {self._interface} "
                        "in the same interval."
                    ),
                )
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not audit discovered hosts.", exc_info=True)

    def _resolve_monitored_adapter(self) -> None:
        """Identify the OS adapter behind the capture device, once per start."""
        try:
            from aethra_sec.analytics.assessment_scope import attached_networks

            adapter, networks, _own, problem = attached_networks(self._interface)
        except Exception:  # noqa: BLE001 - never block capture on this
            LOGGER.debug("Could not resolve the monitored adapter.", exc_info=True)
            adapter, networks, problem = "", (), "resolution failed"
        self._monitored_adapter = adapter if networks else ""
        self._local_networks = tuple(networks)
        self._local_networks_at = time.monotonic() if networks else 0.0
        self._onlink_cache.clear()
        if problem:
            LOGGER.warning(
                "Monitored network for %s is unknown (%s); discovery falls back "
                "to every attached subnet.", self._interface, problem,
            )
        else:
            LOGGER.info(
                "Monitored network for %s: %s (%s).", self._interface,
                ", ".join(str(n) for n in networks), adapter,
            )

    @property
    def monitored_adapter(self) -> str:
        """The OS adapter capture is monitoring, or "" when unknown."""
        return self._monitored_adapter

    def _interface_label(self) -> str:
        """The interface a host was observed on, for its provenance record."""
        adapter = getattr(self, "_monitored_adapter", "") or ""
        interface = (self._interface or "").strip()
        if adapter and adapter != interface:
            return f"{interface} ({adapter})"[:190]
        return interface[:190]

    def _is_on_link(self, address: str) -> bool:
        """Whether an address shares a broadcast domain with the sensor.

        Consulted per packet, so the result is cached per address; the cache is
        discarded whenever the subnets are re-read.
        """
        cached = self._onlink_cache.get(address)
        if cached is not None:
            return cached
        now = time.monotonic()
        if not self._local_networks or (now - self._local_networks_at) > 60.0:
            adapter = getattr(self, "_monitored_adapter", "")
            networks: tuple[Any, ...] = ()
            if adapter:
                # A frame from another adapter's subnet (a ZeroTier peer, a
                # VMware guest) cannot arrive on this capture, and must not be
                # enrolled as a host of the monitored network if it somehow did.
                from aethra_sec.analytics.assessment_scope import adapter_networks

                networks = adapter_networks(adapter)
            self._local_networks = networks or local_ipv4_networks()
            self._local_networks_at = now
            self._onlink_cache.clear()
        result = is_on_link(address, self._local_networks)
        if len(self._onlink_cache) < 20_000:
            self._onlink_cache[address] = result
        return result

    def _record_announced_names(self, observed: dict[str, Any]) -> None:
        """Store the names devices published about themselves this interval.

        Runs after the hosts are upserted, so every address here already has a
        row. A failure is logged and dropped: a hostname is an improvement to
        an inventory entry, and losing one must never cost the observation
        that entry was built from.
        """
        for address, data in observed.items():
            name = str(data.get("announced_name") or "")
            if not name:
                continue
            try:
                if self._hosts.record_announced_hostname(
                    address, name, SOURCE_MDNS
                ):
                    LOGGER.info(
                        "%s announced itself as %r over mDNS.", address, name
                    )
            except Exception:  # noqa: BLE001 - never lose the observation
                LOGGER.debug(
                    "Could not record the announced name for %s.",
                    address, exc_info=True,
                )

    def _accumulate_host(self, packet: CapturedPacket) -> None:
        """Fold a packet into the pending per-host rollup.

        Both endpoints are counted for traffic, but only a *sender* is evidence
        that a host exists. Appearing as a destination is not: an ARP request
        names an address nobody has answered for, and a packet to an address
        that is down looks identical on the wire to one that is up.
        """
        for address, mac, sent in (
            (packet.src_ip, packet.src_mac, True),
            (packet.dst_ip, packet.dst_mac, False),
        ):
            if not address:
                continue
            record = self._pending_hosts.setdefault(
                address,
                {
                    "mac": "", "packets_sent": 0, "packets_received": 0,
                    "bytes_sent": 0, "bytes_received": 0,
                    "first_seen": packet.captured_at, "last_seen": packet.captured_at,
                    "protocols": set(), "transmitted": False,
                    "on_link": self._is_on_link(address),
                    "announced_name": "",
                },
            )
            if sent and not record["announced_name"]:
                # A name the device published about itself. Only from the
                # sender, and only from an mDNS announcement - see
                # analytics.host_naming for why a query and a service
                # instance label are both refused.
                record["announced_name"] = announced_hostname(packet)
            if sent:
                # This address put a frame on the wire. That is the only
                # observation that establishes a host exists.
                record["transmitted"] = True
                # A MAC identifies a host only when that host is on this link.
                # A frame from an off-link address was forwarded by a router,
                # so its source MAC is the *router's*: attaching it here gave
                # 1,491 internet servers a hardware address they do not have,
                # hundreds of them sharing the gateway's.
                if (
                    mac
                    and not record["mac"]
                    and _is_host_mac(mac)
                    and record["on_link"]
                ):
                    record["mac"] = mac
            if sent:
                record["packets_sent"] += 1
                record["bytes_sent"] += packet.length
            else:
                record["packets_received"] += 1
                record["bytes_received"] += packet.length
            if packet.captured_at < record["first_seen"]:
                record["first_seen"] = packet.captured_at
            if packet.captured_at > record["last_seen"]:
                record["last_seen"] = packet.captured_at
            if packet.protocol:
                record["protocols"].add(packet.protocol)

    def _flush_host_observations(self, force: bool = False) -> None:
        """Write accumulated host rollups to the inventory."""
        if not self._pending_hosts:
            return
        interval = max(1, self._settings.get_int("capture.aggregate_interval_seconds", 10))
        now = time.monotonic()
        if not force and (now - self._host_flush_anchor) < interval:
            return
        self._host_flush_anchor = now

        pending, self._pending_hosts = self._pending_hosts, {}
        # Only addresses seen transmitting enter the inventory. Recording a
        # destination as a discovered host asserted that it was UP on no
        # evidence at all - an ARP sweep of a /24 entered every address in it.
        # Two conditions, and both are about evidence.
        #
        # ``transmitted`` - the address put a frame on the wire, which is what
        # establishes that something is there at all.
        #
        # ``on_link`` - it is on a network this sensor is attached to. An
        # internet server the machine merely exchanged packets with is a
        # conversation peer, not a device on the monitored network; recording
        # it here made "Total hosts" 1,983 on a LAN of four, offered "Scan this
        # host" against Google, and counted 1,000 remote servers as ONLINE.
        # Those conversations are not lost - they remain in the traffic records
        # and in the top-talkers, which is where a remote endpoint belongs.
        # A third condition, about what an address *is* rather than what was
        # seen: multicast, broadcast, link-local and the unspecified address
        # are named on the wire constantly, and no device owns any of them.
        observed = {
            address: data
            for address, data in pending.items()
            if data["transmitted"]
            and data["on_link"]
            and not host_address_rejection(address, self._local_networks)
        }
        try:
            try:
                known = self._hosts.existing_addresses(list(observed))
            except Exception:  # noqa: BLE001 - the audit is secondary to storage
                known = None
            self._hosts.bulk_upsert_observed(
                (
                    (address, str(data["mac"]), data["last_seen"])
                    for address, data in observed.items()
                ),
                source=EvidenceSource.PYSHARK,
                interface=self._interface_label(),
                detail="seen transmitting",
            )
            if known is not None:
                self._audit_discoveries(
                    [a for a in observed if a not in known], observed
                )
            self._record_announced_names(observed)
            rows: list[tuple[Any, ...]] = []
            for address, data in observed.items():
                host_id = self._hosts.find_id_by_ip(address)
                if not host_id:
                    continue
                protocols = data["protocols"] or {""}
                for protocol in protocols:
                    rows.append(
                        (
                            host_id, self._interface[:96], str(protocol)[:16],
                            int(data["packets_sent"]), int(data["packets_received"]),
                            int(data["bytes_sent"]), int(data["bytes_received"]),
                            to_db(data["first_seen"]), to_db(data["last_seen"]),
                        )
                    )
            if rows:
                self._hosts.bulk_record_observations(rows)
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not flush host observations.")

    def _flush_aggregate(self, force: bool = False) -> None:
        """Persist one traffic aggregation interval."""
        interval = max(1, self._settings.get_int("capture.aggregate_interval_seconds", 10))
        now = utcnow()
        anchor = self._aggregate_anchor
        if anchor is None:
            self._aggregate_anchor = now
            return
        elapsed = (now - anchor).total_seconds()
        if not force and elapsed < interval:
            return
        if elapsed <= 0:
            return

        try:
            totals = self.analyzer.interval_totals(anchor, now, final=force)
            if totals["packet_count"] or force:
                self._traffic.insert_aggregate(
                    TrafficAggregate(
                        id=None,
                        interval_start=anchor,
                        interval_end=now,
                        interface=self._interface,
                        packet_count=int(totals["packet_count"]),
                        byte_count=int(totals["byte_count"]),
                        tcp_packets=int(totals["tcp_packets"]),
                        udp_packets=int(totals["udp_packets"]),
                        icmp_packets=int(totals["icmp_packets"]),
                        arp_packets=int(totals["arp_packets"]),
                        other_packets=int(totals["other_packets"]),
                        unique_sources=int(totals["unique_sources"]),
                        unique_destinations=int(totals["unique_destinations"]),
                        packets_per_second=float(totals["packets_per_second"]),
                        bytes_per_second=float(totals["bytes_per_second"]),
                        dropped_packets=0,
                    )
                )
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not persist a traffic aggregate.")
        finally:
            self._aggregate_anchor = now

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------
    def _on_setting_changed(self, key: str, value: Any) -> None:
        """Apply a threshold change immediately."""
        if key.startswith("detection."):
            self.rules.update_thresholds(thresholds_from_settings(self._settings.get))
            LOGGER.info("Detection thresholds reloaded after '%s' changed.", key)

    def _safe_trusted_addresses(self) -> set[str]:
        """Load registered trusted assets, tolerating a database outage."""
        try:
            return self._hosts.trusted_addresses()
        except Exception:  # noqa: BLE001
            LOGGER.debug("Trusted host list unavailable.", exc_info=True)
            return set()

    def refresh_trusted_hosts(self) -> None:
        """Reload trusted assets (called after an administrator edits them)."""
        self.rules.update_trusted(self._safe_trusted_addresses())

    def clear_statistics(self, session: Session) -> None:
        """Clear in-memory statistics without touching stored records."""
        self._access.require(session, Permission.MONITOR_CONTROL)
        self.analyzer.reset()
        self.rules.reset()
