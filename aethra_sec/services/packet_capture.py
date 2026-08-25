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
from typing import Any

from aethra_sec.analytics.anomaly_rules import (
    AnomalyRuleEngine,
    DetectionThresholds,
    thresholds_from_settings,
)
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
)
from aethra_sec.models.enums import EvidenceSource
from aethra_sec.models.traffic import (
    CapturedPacket,
    CaptureStatistics,
    TrafficAggregate,
)
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import to_db, utcnow

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

        self.analyzer = TrafficAnalyzer(
            rate_window_seconds=settings.get_int("detection.rate_window_seconds", 5)
        )
        self.rules = AnomalyRuleEngine(thresholds_from_settings(settings.get))
        self.counters = PipelineCounters()

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
        self._aggregate_anchor: datetime | None = None
        self._host_flush_anchor = time.monotonic()
        self._minute_anchor = time.monotonic()
        self._minute_rows = 0
        self._pending_hosts: dict[str, dict[str, Any]] = {}

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
        """True only while capture is genuinely active."""
        reader = self._reader
        return bool(reader and reader.is_running)

    def statistics(self) -> CaptureStatistics:
        """Real capture counters for the UI and health screen."""
        reader = self._reader
        reader_counters = reader.counters.snapshot() if reader else {}
        pipeline = self.counters.snapshot()
        return CaptureStatistics(
            interface=self._interface,
            is_running=self.is_running,
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
            if self.is_running:
                raise CaptureError(
                    "Capture already running.",
                    user_message="Packet capture is already running.",
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

            self._queue = queue.Queue(
                maxsize=self._settings.get_int("capture.queue_size", 20_000)
            )
            self.rules.update_thresholds(thresholds_from_settings(self._settings.get))
            self.rules.update_trusted(self._safe_trusted_addresses())
            self._last_error = ""
            self._stopped_at = None
            self._aggregate_anchor = utcnow()
            self._minute_anchor = time.monotonic()
            self._minute_rows = 0

            reader = LiveCaptureReader(
                self._interface,
                self._queue,
                bpf_filter=self._bpf,
                tshark_path=self._tools.tshark_path,
                on_error=self._on_reader_error,
                on_stopped=self._on_reader_stopped,
            )
            try:
                reader.start()
            except (CaptureError, ToolUnavailableError) as exc:
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

    def stop(self, session: Session | None = None, reason: str = "operator request") -> None:
        """Stop capture and flush any buffered data."""
        live = None
        if session is not None:
            live = self._access.require(session, Permission.MONITOR_CONTROL)

        with self._lock:
            reader = self._reader
            if reader is not None:
                reader.stop(reason=reason)
            self._stop_worker.set()
            worker = self._worker
        if worker and worker.is_alive():
            worker.join(timeout=10)
        with self._lock:
            self._worker = None
            self._stopped_at = utcnow()

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
        """Stop capture during application shutdown (no session required)."""
        if self.is_running or self._worker:
            try:
                self.stop(None, reason="application shutdown")
            except Exception:  # noqa: BLE001
                LOGGER.exception("Error stopping capture during shutdown.")

    # ------------------------------------------------------------------
    # Reader callbacks
    # ------------------------------------------------------------------
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
        self._bus.publish(
            EventType.CAPTURE_ERROR, ErrorPayload("packet_capture", message)
        )

    def _on_reader_stopped(self, reason: str) -> None:
        """Note that the reader thread ended (possibly unexpectedly)."""
        self._stopped_at = utcnow()
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
        """Hand a batch of real packets to the UI."""
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
    def _accumulate_host(self, packet: CapturedPacket) -> None:
        """Fold a packet into the pending per-host rollup."""
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
                    "protocols": set(),
                },
            )
            if mac and not record["mac"]:
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
        try:
            self._hosts.bulk_upsert_observed(
                (
                    (address, str(data["mac"]), data["last_seen"])
                    for address, data in pending.items()
                ),
                source=EvidenceSource.PYSHARK,
            )
            rows: list[tuple[Any, ...]] = []
            for address, data in pending.items():
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
            totals = self.analyzer.interval_totals(anchor, now)
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
