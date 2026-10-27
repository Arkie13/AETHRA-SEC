"""The live detection path: TShark field extraction (§63).

Profiling the capture pipeline showed the cost was not where it was assumed to
be. Of 28.6% CPU during a live capture, TShark and dumpcap accounted for 1.4%
and the Python process for 27.2% — the decode was cheap and the *parsing of the
decode* was expensive. PyShark asks TShark for PDML, a full XML rendering of
every field of every protocol layer, then rebuilds it in Python: 2,203 layer
objects for 400 packets, with ``str.translate`` over each packet's XML alone
costing a quarter of the total. The detector uses about a dozen fields.

This reader asks TShark for those fields and nothing else. Measured on the same
capture file, the same packets and the same fields:

    PyShark PDML + mapper    208 packets/s
    TShark -T fields       2,325 packets/s   (11.2x)

Full decode has not been given up, only moved. TShark still writes every frame
to the capture file, and the packet inspector opens that file when an analyst
asks for one packet's detail. The live path stays lean; the detailed path stays
complete. Nothing is discarded to achieve it - what is dropped is reported.
"""

from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from queue import Full, Queue
from typing import Any, Callable

from aethra_sec.core.errors import CaptureError, ToolUnavailableError
from aethra_sec.integrations.pyshark_capture import jobs
from aethra_sec.integrations.pyshark_capture.interfaces import find_tshark
from aethra_sec.integrations.pyshark_capture.mapper import application_protocol
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("integrations.pyshark.fields")

#: The fields the live path reads, in the order TShark emits them. Every one is
#: used: by a detection rule, by host discovery, by the packet table, by the
#: display filter or by the packet detail pane. Adding a field here costs CPU on
#: every packet, so it is a deliberate list rather than a convenient one.
#:
#: ``_ws.col.info`` must stay last. It is free text, and positional parsing of
#: everything before it is only safe if whatever it contains comes after.
FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "_ws.col.protocol",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "arp.src.hw_mac",
    "arp.dst.hw_mac",
    "arp.opcode",
    "tcp.seq",
    "tcp.ack",
    "icmp.type",
    "icmp.code",
    "icmpv6.type",
    "icmpv6.code",
    "dns.qry.name",
    "dns.flags.response",
    # The host an SRV record points at. Read for one purpose: a device on a
    # LAN announces itself over mDNS, and for most consumer hardware that
    # announcement is the only place it ever states a name - it holds no DNS
    # record, answers no reverse lookup and runs no NetBIOS.
    #
    # The *target* specifically, and not the record name beside it. RFC 2782
    # makes the target "the domain name of the target host", while the record
    # name is a service *instance* label the device may choose freely. Read
    # against this network's own captures the difference is stark: the targets
    # are "akii.local" and "Android_WTKS0CKK.local", while the instance labels
    # for the same two devices include "I0FRM0j8n14AAA" and
    # "nearby-presence-nsd-57469620-8721-4106-8e9d-3294c145da98". Taking the
    # instance label would have written a rotating identifier into the
    # inventory as though it were a device's name.
    "dns.srv.target",
    # The address a DNS answer resolved its name to. Without these two the
    # name a lookup produced can never be joined to the traffic that follows
    # it, because that traffic carries only addresses: measured on this
    # machine, a domain appears in about 1.4% of frames and an address in all
    # of them. They were dropped when dns.srv.target was added for mDNS
    # naming, which silently removed the only basis for that join.
    #
    # occurrence=f gives the first record of a multi-answer response, so a
    # name resolving to several addresses is learned for one of them. The
    # rest stay unattributed, which is the honest outcome: the alternative is
    # naming an address the capture never tied to the name.
    "dns.a",
    "dns.aaaa",
    "http.request.method",
    "http.request.uri",
    "http.host",
    "http.request.version",
    "http.response.code",
    "http.response.phrase",
    "http.response.version",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.record.version",
    "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
    "_ws.col.info",
)

#: How many of :data:`FIELDS` are the core set - addressing, transport and the
#: protocol chain - that detection, host discovery and the table's address
#: columns need. The rest are the protocol fields and TShark's Info column.
#: Core fields come first, so a row that carries only them parses unchanged.
CORE_FIELD_COUNT = 21

_INDEX = {name: position for position, name in enumerate(FIELDS)}


def fields_for(extended: bool) -> tuple[str, ...]:
    """The fields to request: all of them, or only the core set.

    Measured on one 60,000-frame capture: about 30,000 packets/s with the core
    set and about 12,000 with every field. Both are far above ordinary traffic;
    the difference matters only under a flood.
    """
    return FIELDS if extended else FIELDS[:CORE_FIELD_COUNT]


@dataclass
class FieldCaptureCounters:
    """Live counters owned by the reader thread.

    ``dropped`` is read from TShark's own reporting rather than inferred, so a
    shedding pipeline says so instead of quietly showing fewer packets.
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


def _text(parts: list[str], name: str) -> str:
    """One field's value, or an empty string when TShark emitted none."""
    position = _INDEX[name]
    if position >= len(parts):
        return ""
    return parts[position].strip()


def _number(parts: list[str], name: str) -> int | None:
    """An integer field, or None when absent or unparseable.

    TShark emits a comma-separated list when a field occurs more than once in
    one frame (tunnelled or malformed traffic); the first occurrence is the
    outermost and is the one the detector reasons about.
    """
    raw = _text(parts, name)
    if not raw:
        return None
    head = raw.split(",")[0].strip()
    try:
        return int(head, 0) if head.startswith("0x") else int(head)
    except ValueError:
        return None


def _address(parts: list[str], name: str) -> str:
    """An address field, taking the outermost when several are present."""
    raw = _text(parts, name)
    return raw.split(",")[0].strip() if raw else ""


def _flag(parts: list[str], name: str) -> bool | None:
    """A boolean field. TShark 4 prints True/False; older builds print 1/0."""
    raw = _text(parts, name).split(",")[0].strip().lower()
    if raw in ("true", "1"):
        return True
    if raw in ("false", "0"):
        return False
    return None


def _info(parts: list[str]) -> str:
    """TShark's Info column: everything from its position to the end of the row.

    It is the last field precisely so that a tab inside it - possible in a
    malformed request line - cannot shift any other column.
    """
    position = _INDEX["_ws.col.info"]
    if position >= len(parts):
        return ""
    return "\t".join(parts[position:]).strip()


def parse_line(line: str, interface: str, pcap_path: str = "") -> CapturedPacket | None:
    """Turn one tab-separated TShark row into a packet.

    Args:
        line: one row of ``tshark -T fields`` output.
        interface: the capture device the row came from.
        pcap_path: the capture file TShark is writing the same frames to, so
            the packet inspector can re-read this exact frame later.

    Returns None when the row carries nothing identifiable, which is counted as
    a decode error rather than recorded as an observation.
    """
    parts = line.split("\t")
    if len(parts) < 3:
        return None

    epoch = _text(parts, "frame.time_epoch")
    try:
        captured_at = datetime.fromtimestamp(float(epoch), tz=UTC)
    except (TypeError, ValueError):
        return None

    src_ip = _address(parts, "ip.src") or _address(parts, "ipv6.src")
    dst_ip = _address(parts, "ip.dst") or _address(parts, "ipv6.dst")
    ip_version: int | None = None
    if _address(parts, "ip.src"):
        ip_version = 4
    elif _address(parts, "ipv6.src"):
        ip_version = 6

    if not src_ip and not dst_ip:
        # ARP carries protocol addresses instead of an IP header.
        src_ip = _address(parts, "arp.src.proto_ipv4")
        dst_ip = _address(parts, "arp.dst.proto_ipv4")

    src_port = _number(parts, "tcp.srcport")
    dst_port = _number(parts, "tcp.dstport")
    transport = "TCP" if src_port is not None or dst_port is not None else ""
    if transport == "":
        src_port = _number(parts, "udp.srcport")
        dst_port = _number(parts, "udp.dstport")
        transport = "UDP" if src_port is not None or dst_port is not None else ""

    protocol = _text(parts, "_ws.col.protocol").upper() or "OTHER"
    layers = tuple(
        segment.upper()
        for segment in _text(parts, "frame.protocols").split(":")
        if segment
    )
    if "ARP" in layers:
        protocol = "ARP"

    src_mac = _address(parts, "eth.src").lower() or _address(parts, "arp.src.hw_mac").lower()
    dst_mac = _address(parts, "eth.dst").lower() or _address(parts, "arp.dst.hw_mac").lower()

    length = _number(parts, "frame.len") or 0
    if not layers and not length and not (src_ip or dst_ip or src_mac or dst_mac):
        return None

    icmp_type = _number(parts, "icmp.type")
    icmp_code = _number(parts, "icmp.code")
    if icmp_type is None:
        icmp_type = _number(parts, "icmpv6.type")
        icmp_code = _number(parts, "icmpv6.code")

    highest_layer = layers[-1] if layers else protocol
    return CapturedPacket(
        captured_at=captured_at,
        interface=interface,
        number=_number(parts, "frame.number"),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        transport=transport,
        highest_layer=highest_layer,
        # From the decoded protocol chain only. It used to be left empty on
        # this path, which silently disabled every view and rule keyed on it.
        app_protocol=application_protocol(layers, highest_layer),
        length=length,
        ttl=_number(parts, "ip.ttl"),
        tcp_flags=_number(parts, "tcp.flags"),
        src_mac=src_mac,
        dst_mac=dst_mac,
        ip_version=ip_version,
        layers=layers,
        # The capture file and the frame's position in it. Without the path
        # the inspector had no frame to re-read on this decode path.
        pcap_path=pcap_path,
        frame_index=_number(parts, "frame.number"),
        tshark_info=_info(parts),
        http_method=_text(parts, "http.request.method"),
        http_uri=_text(parts, "http.request.uri"),
        http_host=_text(parts, "http.host"),
        http_version=(
            _text(parts, "http.request.version")
            or _text(parts, "http.response.version")
        ),
        http_status=_number(parts, "http.response.code"),
        http_phrase=_text(parts, "http.response.phrase"),
        tls_handshake_type=_number(parts, "tls.handshake.type"),
        tls_sni=_text(parts, "tls.handshake.extensions_server_name"),
        tls_record_version=_number(parts, "tls.record.version"),
        tls_handshake_version=_number(parts, "tls.handshake.version"),
        tls_supported_version=_number(
            parts, "tls.handshake.extensions.supported_version"
        ),
        dns_query=_text(parts, "dns.qry.name"),
        dns_response=_flag(parts, "dns.flags.response"),
        dns_srv_target=_text(parts, "dns.srv.target"),
        # A over AAAA: both are recorded by the dissector when a response
        # carries both, and either alone is enough to join the name to a flow.
        dns_answer_address=(
            _address(parts, "dns.a") or _address(parts, "dns.aaaa")
        ),
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        arp_opcode=_number(parts, "arp.opcode"),
        arp_sender_mac=_address(parts, "arp.src.hw_mac").lower(),
        arp_target_mac=_address(parts, "arp.dst.hw_mac").lower(),
        tcp_seq=_number(parts, "tcp.seq"),
        tcp_ack=_number(parts, "tcp.ack"),
    )


class FieldCaptureReader:
    """Read live packets as extracted fields, on a worker thread.

    The public surface matches the PyShark reader, so the capture service can
    hold either without knowing which it has.
    """

    def __init__(
        self,
        interface: str,
        queue: Queue,
        *,
        bpf_filter: str = "",
        tshark_path: Path | str | None = None,
        output_file: Path | None = None,
        ring_filesize_kb: int = 0,
        ring_files: int = 0,
        on_error: Callable[[str], None] | None = None,
        on_stopped: Callable[[str], None] | None = None,
        extended_fields: bool = True,
    ) -> None:
        """Prepare the reader. Nothing is spawned until :meth:`start`.

        ``extended_fields`` requests the protocol fields and TShark's Info
        column as well as the core set. Without them detection is unchanged;
        the packet table shows less and the detail pane reports those fields
        as N/A.
        """
        self.interface = interface
        self._fields = fields_for(extended_fields)
        self.bpf_filter = bpf_filter
        self.counters = FieldCaptureCounters()
        self._queue = queue
        self._tshark_path = tshark_path
        self._output_file = output_file
        #: Ring-buffer bounds for the evidence pcap. Zero means one
        #: unbounded file, which is what this used to be: measured at
        #: 31.8 MB in 150 seconds on this machine's Wi-Fi, or roughly
        #: 18 GB a day, with nothing to stop it filling the disk.
        self._ring_filesize_kb = max(0, int(ring_filesize_kb))
        self._ring_files = max(0, int(ring_files))
        #: A ring needs both bounds. One alone leaves TShark writing the
        #: single file at ``-w``, so every site that asks "is this a ring?"
        #: has to agree, or the reader looks for rotated files that the
        #: command never asked for.
        self._ring_active = bool(self._ring_filesize_kb and self._ring_files)
        #: Recorded on every packet so the inspector can find its frame again.
        #:
        #: With ``-b`` TShark never creates the base path: it writes
        #: ``<base>_00001_<timestamp>.pcapng`` and so on. Seeding this with the
        #: base path would hand every packet captured before the first
        #: rotation - the first ``filesize`` kilobytes, 64 MB by default - a
        #: path that does not exist and never will, and their detail would
        #: read "the capture file is no longer present" while the capture was
        #: still running. So under a ring it starts unknown and
        #: :meth:`_follow_rotation` resolves it from the directory.
        self._pcap_text = (
            ""
            if output_file is None or self._ring_active
            else str(output_file)
        )
        #: Last frame number seen, to notice a rotation.
        self._last_frame_number: int | None = None
        self._on_error = on_error
        self._on_stopped = on_stopped
        self._stop = threading.Event()
        self._stop_reason = ""
        self._thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._process: subprocess.Popen | None = None
        self._adopted: set[int] = set()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        """True while the reader thread is alive."""
        thread = self._thread
        return bool(thread and thread.is_alive())

    def _command(self) -> list[str]:
        """The exact argument list. Never a string, so nothing can be injected."""
        tshark = find_tshark(Path(self._tshark_path) if self._tshark_path else None)
        if tshark is None:
            raise ToolUnavailableError(
                "TShark was not found.",
                user_message=(
                    "TShark could not be found. Install Wireshark, or set the "
                    "TShark path on the Settings screen."
                ),
            )
        command = [str(tshark), "-i", self.interface, "-l", "-n"]
        if self.bpf_filter:
            command += ["-f", self.bpf_filter]
        if self._output_file is not None:
            # Every frame is still written in full, so the packet inspector can
            # decode any one of them later. The live path reads fields; the
            # evidence path keeps the packet.
            command += ["-w", str(self._output_file)]
            if self._ring_active:
                # A ring, so a long session cannot fill the disk. Total on
                # disk is bounded by filesize x files; TShark deletes the
                # oldest itself. Frame numbers restart per file, and
                # _follow_rotation keeps each packet's recorded path pointing
                # at the file it was actually written to.
                command += [
                    "-b", f"filesize:{self._ring_filesize_kb}",
                    "-b", f"files:{self._ring_files}",
                ]
        # occurrence=f: one value per field, the outermost. Otherwise TShark joins
        # repeats with commas, and a URI or an Info string can itself contain a
        # comma, so splitting afterwards would cut real values apart.
        command += ["-T", "fields", "-E", "occurrence=f"]
        for name in self._fields:
            command += ["-e", name]
        return command

    def start(self) -> None:
        """Spawn TShark and begin reading fields."""
        if self.is_running:
            return
        command = self._command()
        try:
            self._process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # TShark writes UTF-8. Left to the default, the pipe is read in
                # the Windows ANSI code page: the Info column's arrow arrived as
                # "â†'", and a byte that code page leaves undefined - 0x81, the
                # second byte of "Á" - raised in the reader thread and failed
                # the capture. DNS names, HTTP hosts and URIs and TLS server
                # names are text other devices choose, so a malformed byte is
                # replaced rather than allowed to end the capture.
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            raise CaptureError(
                f"TShark could not be started: {exc}",
                user_message=(
                    "Packet capture could not start because TShark could not "
                    "be launched. Check that Wireshark is installed and that "
                    "you have permission to capture on this interface."
                ),
            ) from exc

        jobs.adopt(self._process.pid)
        self._adopted.add(self._process.pid)
        self.counters.started_at = utcnow()
        self._stop.clear()

        self._thread = threading.Thread(
            target=self._run, name=f"field-reader-{self.interface}", daemon=True
        )
        self._thread.start()
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, name="field-reader-stderr", daemon=True
        )
        self._stderr_thread.start()
        LOGGER.info(
            "Live capture started on %r (field extraction, %d fields).",
            self.interface, len(self._fields),
        )

    def stop(self, timeout: float = 8.0, reason: str = "operator request") -> None:
        """Signal the reader to stop and terminate TShark."""
        self._stop_reason = reason
        self._stop.set()
        self._terminate()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        self.counters.stopped_at = utcnow()

    # ------------------------------------------------------------------
    # Process
    # ------------------------------------------------------------------
    def _child_pids(self) -> list[int]:
        """Process ids of the capture children, adopted into the job on sight."""
        process = self._process
        if process is None or process.poll() is not None:
            return []
        found = [process.pid]
        try:
            import psutil

            found += [c.pid for c in psutil.Process(process.pid).children(recursive=True)]
        except Exception:  # noqa: BLE001 - psutil absent or the child exited
            pass
        for pid in found:
            if pid not in self._adopted:
                self._adopted.add(pid)
                jobs.adopt(pid)
        return sorted(set(found))

    def capture_process_alive(self) -> bool:
        """True while TShark is genuinely running.

        Asked on every interface tick, so it only looks. It must never be
        written as ``os.kill(pid, 0)``: on Windows signal 0 is CTRL_C_EVENT and
        that call delivers a real console interrupt.
        """
        process = self._process
        return bool(process and process.poll() is None)

    def _terminate(self) -> None:
        """Terminate TShark and everything it spawned."""
        process = self._process
        if process is None:
            return
        pids = self._child_pids()
        try:
            import psutil

            doomed = []
            for pid in pids:
                try:
                    target = psutil.Process(pid)
                except psutil.Error:
                    continue
                try:
                    doomed.extend(target.children(recursive=True))
                except psutil.Error:
                    pass
                doomed.append(target)
            for victim in doomed:
                try:
                    victim.terminate()
                except psutil.Error:
                    pass
            _, alive = psutil.wait_procs(doomed, timeout=3)
            for survivor in alive:
                try:
                    survivor.kill()
                except psutil.Error:
                    pass
        except Exception:  # noqa: BLE001
            try:
                process.terminate()
            except OSError:
                pass

    @property
    def pid(self) -> int | None:
        """The TShark child's process id while it is running, else None.

        Read from the process object rather than remembered, so a capture that
        has already ended reports nothing instead of a stale number that still
        looks alive.
        """
        process = self._process
        if process is None or process.poll() is not None:
            return None
        return process.pid

    # ------------------------------------------------------------------
    # Reader thread
    # ------------------------------------------------------------------
    def _follow_rotation(self, packet: CapturedPacket) -> None:
        """Keep ``pcap_path`` pointing at the ring file now being written.

        With ``-b`` TShark writes a series of files and deletes the oldest,
        which bounds the disk a long session can consume. Each file is its own
        capture: the frame numbers it reports restart at 1 for every one of
        them, measured against a real rotating capture on this machine - a
        file ending at frame 94 was followed by one beginning at frame 1.

        That restart is the rotation signal, and it costs nothing to watch. A
        frame number *lower* than the last is the only way TShark can have
        moved on, because within one file they strictly increase. So the
        directory is listed once per rotation - every ``filesize`` kilobytes -
        rather than once per packet, which at several hundred packets a second
        would be a stat() storm in the hot path.

        Getting this right is what keeps packet detail working: the inspector
        finds a frame by (file, index), and both halves stay true through a
        rotation. A frame whose file has since been recycled is reported as
        missing, which it is.
        """
        number = packet.number
        if number is None:
            return
        if not self._pcap_text:
            # Not resolved yet. The first file exists by the time its first
            # packet reaches us, but a capture that starts on a silent
            # interface can see the directory before TShark creates it, so
            # this retries per packet only while unresolved - never once a
            # path is known.
            self._resolve_current_ring_file()
        elif self._last_frame_number is not None and number < self._last_frame_number:
            self._resolve_current_ring_file()
        self._last_frame_number = number
        packet.pcap_path = self._pcap_text

    def _resolve_current_ring_file(self) -> None:
        """Point at the highest-numbered file of the ring.

        TShark names them ``<base>_NNNNN_<timestamp>.pcapng`` with an
        increasing counter, so the counter orders them exactly. Modification
        time would not: two files written inside the same second are common.
        """
        base = self._output_file
        if base is None:
            return
        try:
            candidates = sorted(
                base.parent.glob(f"{base.stem}_*{base.suffix}"),
                key=lambda path: path.name,
            )
        except OSError:  # pragma: no cover - directory went away
            return
        if candidates:
            self._pcap_text = str(candidates[-1])
            LOGGER.debug("Capture rotated to %s", candidates[-1].name)

    def _run(self) -> None:
        """Reader thread body: one line in, one packet out."""
        process = self._process
        assert process is not None and process.stdout is not None
        try:
            for line in process.stdout:
                if self._stop.is_set():
                    break
                line = line.rstrip("\r\n")
                if not line:
                    continue
                packet = parse_line(line, self.interface, self._pcap_text)
                if packet is None:
                    with self.counters._lock:  # noqa: SLF001
                        self.counters.decode_errors += 1
                    continue
                if self._ring_active:
                    self._follow_rotation(packet)
                with self.counters._lock:  # noqa: SLF001
                    self.counters.captured += 1
                    self.counters.bytes_seen += packet.length
                    self.counters.last_packet_at = packet.captured_at
                try:
                    self._queue.put_nowait(packet)
                except Full:
                    # The queue is the backpressure point. A shed packet is
                    # counted, never silently discarded.
                    with self.counters._lock:  # noqa: SLF001
                        self.counters.dropped += 1
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Field reader ended: %s", exc, exc_info=True)
            self._fail(str(exc))
        finally:
            reason = self._stop_reason or "capture ended"
            if self._on_stopped is not None:
                try:
                    self._on_stopped(reason)
                except Exception:  # noqa: BLE001
                    LOGGER.exception("Capture stop callback failed.")

    def _drain_stderr(self) -> None:
        """Read TShark's own reporting, including how much it dropped."""
        process = self._process
        if process is None or process.stderr is None:
            return
        for line in process.stderr:
            text = line.strip()
            if not text:
                continue
            lowered = text.lower()
            if "packets dropped" in lowered or "dropped:" in lowered:
                for token in text.replace(":", " ").split():
                    if token.isdigit():
                        with self.counters._lock:  # noqa: SLF001
                            self.counters.dropped += int(token)
                        break
                LOGGER.warning("TShark reported drops: %s", text[:120])
            elif "error" in lowered or "invalid" in lowered:
                self._fail(text[:200])

    def _fail(self, message: str) -> None:
        """Record a reader failure and tell the service."""
        with self.counters._lock:  # noqa: SLF001
            self.counters.last_error = message
        if self._on_error is not None:
            try:
                self._on_error(message)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Capture error callback failed.")
