"""Transports that receive **real** Snort alerts (§21).

Four implementations, all read-only consumers of what a running sensor emits:

``UnixSocketAlertTransport``
    The Alert Socket IPC named by the system design. Snort's ``alert_unixsock``
    output plugin sends a binary ``Alertpkt`` datagram per alert to a Unix
    datagram socket. Linux/WSL sensors.

``TcpAlertTransport``
    AETHRA-SEC listens on a TCP port for line-oriented alert text. Used when
    the sensor forwards its alert file over the network.

``SyslogAlertTransport``
    A UDP syslog listener for Snort's ``alert_syslog`` output. This is the
    practical path for a Windows sensor, which has no Unix domain sockets.

``AlertFileTransport``
    Tails a Snort alert file (``alert_fast``/``alert_csv``/``alert_json``),
    following truncation and rotation. The simplest reliable option on Windows.

None of these can produce an alert on their own. When no sensor is writing,
they sit idle and the interface reports "Snort unavailable" or shows no alerts.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from aethra_sec.core.errors import SnortIngestError
from aethra_sec.integrations.snort.alertpkt import DecodedAlertPkt, decode_alertpkt
from aethra_sec.integrations.snort.parser import (
    DEFAULT_CSV_COLUMNS,
    ParsedAlert,
    detect_csv_columns,
    parse_alert_line,
)
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("integrations.snort.transports")

#: Largest datagram we will read from the alert socket. Snort's Alertpkt is
#: roughly 66 KB with the default 65535-byte snap length.
MAX_DATAGRAM = 131_072

AlertCallback = Callable[[ParsedAlert | DecodedAlertPkt, str], None]
FailureCallback = Callable[[str], None]


@dataclass
class TransportStatus:
    """The transport's real, observed state."""

    name: str
    connected: bool = False
    endpoint: str = ""
    started_at: datetime | None = None
    last_alert_at: datetime | None = None
    alerts_received: int = 0
    parse_failures: int = 0
    last_error: str = ""
    detail: str = ""


class AlertTransport(ABC):
    """Base class for Snort alert transports."""

    name = "transport"

    def __init__(
        self,
        on_alert: AlertCallback,
        on_failure: FailureCallback | None = None,
    ) -> None:
        """Create a stopped transport.

        Args:
            on_alert: called with ``(alert, transport_name)`` for each real
                alert received.
            on_failure: called with an explanatory message when the transport
                cannot run or loses its source.
        """
        self._on_alert = on_alert
        self._on_failure = on_failure
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.status = TransportStatus(name=self.name)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        """True while the reader thread is alive."""
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        """Open the source and begin reading.

        Raises:
            SnortIngestError: when the source cannot be opened. The message
                explains how to configure it (§21).
        """
        if self.is_running:
            return
        self._stop.clear()
        self._open()
        self.status.started_at = utcnow()
        self.status.connected = True
        self.status.last_error = ""
        self._thread = threading.Thread(
            target=self._run, name=f"snort-{self.name}", daemon=True
        )
        self._thread.start()
        LOGGER.info("Snort %s transport started (%s).", self.name, self.status.endpoint)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop reading and release the source."""
        self._stop.set()
        self._close()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None
        self.status.connected = False
        LOGGER.info("Snort %s transport stopped.", self.name)

    def _run(self) -> None:
        """Reader thread body."""
        try:
            self._read_loop()
        except Exception as exc:  # noqa: BLE001 - report, never crash the app
            message = f"Snort {self.name} transport failed: {exc}"
            self.status.last_error = str(exc)
            self.status.connected = False
            LOGGER.error(message)
            if self._on_failure:
                self._on_failure(message)
        finally:
            self.status.connected = False

    def _emit(self, alert: ParsedAlert | DecodedAlertPkt) -> None:
        """Hand a decoded alert to the service layer."""
        self.status.alerts_received += 1
        self.status.last_alert_at = utcnow()
        try:
            self._on_alert(alert, self.name)
        except Exception:  # noqa: BLE001 - a consumer must not kill the reader
            LOGGER.exception("Snort alert consumer failed.")

    def _note_parse_failure(self, raw: str) -> None:
        """Count a line/datagram that could not be parsed."""
        self.status.parse_failures += 1
        LOGGER.debug("Unparsed Snort output (%s): %s", self.name, raw[:200])

    @abstractmethod
    def _open(self) -> None:
        """Open the underlying source."""

    @abstractmethod
    def _close(self) -> None:
        """Release the underlying source."""

    @abstractmethod
    def _read_loop(self) -> None:
        """Read until stopped."""


class UnixSocketAlertTransport(AlertTransport):
    """Snort ``alert_unixsock`` Alert Socket IPC (Linux/WSL)."""

    name = "unixsock"

    def __init__(
        self,
        socket_path: Path,
        on_alert: AlertCallback,
        on_failure: FailureCallback | None = None,
    ) -> None:
        """Bind to the socket path Snort will send to."""
        super().__init__(on_alert, on_failure)
        self._path = Path(socket_path)
        self._socket: socket.socket | None = None
        self.status.endpoint = str(self._path)

    def _open(self) -> None:
        """Create and bind the Unix datagram socket Snort writes to."""
        if not hasattr(socket, "AF_UNIX"):
            raise SnortIngestError(
                "Unix domain sockets are not available on this platform.",
                user_message=(
                    "Snort unavailable: the Unix alert socket transport is not "
                    "supported on Windows. Use the alert-file or syslog "
                    "transport instead - see docs/SNORT_INTEGRATION.md."
                ),
            )
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if self._path.exists():
                self._path.unlink()
        except OSError as exc:
            raise SnortIngestError(
                f"Could not prepare the alert socket path: {exc}",
                user_message=(
                    f"Snort unavailable: the alert socket path '{self._path}' "
                    f"could not be prepared ({exc}). Check the directory exists "
                    "and that AETHRA-SEC may write to it."
                ),
            ) from exc

        try:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            server.settimeout(1.0)
            server.bind(str(self._path))
            try:
                os.chmod(self._path, 0o660)
            except OSError:
                LOGGER.debug("Could not tighten alert socket permissions.")
            self._socket = server
        except OSError as exc:
            raise SnortIngestError(
                f"Could not bind the alert socket: {exc}",
                user_message=(
                    f"Snort unavailable: could not bind '{self._path}' ({exc}). "
                    "Confirm the path in AETHRA_SNORT_SOCKET_PATH matches the "
                    "logdir Snort was started with, and that no other process "
                    "already owns it."
                ),
            ) from exc
        self.status.detail = (
            f"Listening for Snort alert_unixsock datagrams on {self._path}"
        )

    def _close(self) -> None:
        """Close and unlink the socket."""
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        try:
            if self._path.exists():
                self._path.unlink()
        except OSError:
            LOGGER.debug("Could not remove the alert socket file.")

    def _read_loop(self) -> None:
        """Receive and decode Alertpkt datagrams until stopped."""
        server = self._socket
        if server is None:
            return
        while not self._stop.is_set():
            try:
                payload = server.recv(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                raise SnortIngestError(f"Alert socket read failed: {exc}") from exc
            if not payload:
                continue
            decoded = decode_alertpkt(payload)
            if decoded is None:
                self._note_parse_failure(repr(payload[:64]))
                continue
            self._emit(decoded)


class TcpAlertTransport(AlertTransport):
    """TCP listener for line-oriented alert text forwarded from a sensor."""

    name = "tcp"

    def __init__(
        self,
        host: str,
        port: int,
        on_alert: AlertCallback,
        on_failure: FailureCallback | None = None,
    ) -> None:
        """Bind a listening socket for forwarded alerts."""
        super().__init__(on_alert, on_failure)
        self._host = host
        self._port = int(port)
        self._server: socket.socket | None = None
        self._clients: list[socket.socket] = []
        self.status.endpoint = f"{host}:{port}"

    def _open(self) -> None:
        """Bind and listen."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(1.0)
            server.bind((self._host, self._port))
            server.listen(4)
            self._server = server
        except OSError as exc:
            raise SnortIngestError(
                f"Could not listen on {self._host}:{self._port}: {exc}",
                user_message=(
                    f"Snort unavailable: could not listen on {self._host}:"
                    f"{self._port} ({exc}). Choose a free port in "
                    "AETHRA_SNORT_TCP_PORT or stop the process using it."
                ),
            ) from exc
        self.status.detail = (
            f"Waiting for a sensor to connect to {self._host}:{self._port}"
        )

    def _close(self) -> None:
        """Close the listener and any connected sensors."""
        for client in list(self._clients):
            try:
                client.close()
            except OSError:
                pass
        self._clients.clear()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None

    def _read_loop(self) -> None:
        """Accept connections and read newline-delimited alerts."""
        server = self._server
        if server is None:
            return
        while not self._stop.is_set():
            try:
                client, address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            client.settimeout(1.0)
            self._clients.append(client)
            self.status.detail = f"Sensor connected from {address[0]}:{address[1]}"
            LOGGER.info("Snort alert sensor connected from %s", address)
            threading.Thread(
                target=self._serve_client,
                args=(client, address),
                name="snort-tcp-client",
                daemon=True,
            ).start()

    def _serve_client(self, client: socket.socket, address: tuple) -> None:
        """Read one connected sensor until it disconnects."""
        buffer = b""
        try:
            while not self._stop.is_set():
                try:
                    chunk = client.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self._handle_line(line.decode("utf-8", errors="replace"))
        finally:
            try:
                client.close()
            except OSError:
                pass
            if client in self._clients:
                self._clients.remove(client)
            LOGGER.info("Snort alert sensor disconnected (%s).", address)
            self.status.detail = f"Waiting for a sensor to connect to {self.status.endpoint}"

    def _handle_line(self, line: str) -> None:
        """Parse and emit one received line."""
        if not line.strip():
            return
        alert = parse_alert_line(line)
        if alert is None:
            self._note_parse_failure(line)
            return
        self._emit(alert)


class SyslogAlertTransport(AlertTransport):
    """UDP syslog listener for Snort's ``alert_syslog`` output."""

    name = "syslog"

    def __init__(
        self,
        host: str,
        port: int,
        on_alert: AlertCallback,
        on_failure: FailureCallback | None = None,
    ) -> None:
        """Bind a UDP socket for syslog-formatted alerts."""
        super().__init__(on_alert, on_failure)
        self._host = host
        self._port = int(port)
        self._socket: socket.socket | None = None
        self.status.endpoint = f"{host}:{port}/udp"

    def _open(self) -> None:
        """Bind the UDP socket."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(1.0)
            server.bind((self._host, self._port))
            self._socket = server
        except OSError as exc:
            raise SnortIngestError(
                f"Could not bind UDP {self._host}:{self._port}: {exc}",
                user_message=(
                    f"Snort unavailable: could not bind UDP {self._host}:"
                    f"{self._port} ({exc}). Ports below 1024 require elevated "
                    "privileges - 5514 is a good unprivileged choice."
                ),
            ) from exc
        self.status.detail = f"Listening for Snort syslog alerts on {self.status.endpoint}"

    def _close(self) -> None:
        """Close the UDP socket."""
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def _read_loop(self) -> None:
        """Receive and parse syslog datagrams until stopped."""
        server = self._socket
        if server is None:
            return
        while not self._stop.is_set():
            try:
                payload, address = server.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            text = payload.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            alert = parse_alert_line(text)
            if alert is None:
                self._note_parse_failure(text)
                continue
            if isinstance(alert, ParsedAlert) and not alert.sensor:
                alert.sensor = address[0]
            self._emit(alert)


class AlertFileTransport(AlertTransport):
    """Tails a Snort alert file, following truncation and rotation."""

    name = "file"

    def __init__(
        self,
        path: Path,
        on_alert: AlertCallback,
        on_failure: FailureCallback | None = None,
        *,
        poll_interval: float = 0.5,
        from_start: bool = False,
    ) -> None:
        """Tail an alert file.

        Args:
            path: the alert file Snort writes.
            poll_interval: seconds between reads when the file is idle.
            from_start: read existing content first. Default is false so a
                restart does not re-ingest history as if it were new.
        """
        super().__init__(on_alert, on_failure)
        self._path = Path(path)
        self._poll = max(0.05, poll_interval)
        self._from_start = from_start
        self._handle = None
        self._inode: int | None = None
        self._columns = DEFAULT_CSV_COLUMNS
        self.status.endpoint = str(self._path)

    def _open(self) -> None:
        """Open the alert file, waiting for it to appear if necessary."""
        if not self._path.exists():
            raise SnortIngestError(
                f"Alert file '{self._path}' does not exist.",
                user_message=(
                    f"Snort unavailable: the alert file '{self._path}' does not "
                    "exist yet. Start Snort with a file alert output (for "
                    "example '-A fast -l C:\\Snort\\log') and set "
                    "AETHRA_SNORT_ALERT_FILE to the file it writes."
                ),
            )
        try:
            handle = self._path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            raise SnortIngestError(
                f"Could not open '{self._path}': {exc}",
                user_message=(
                    f"Snort unavailable: could not read '{self._path}' ({exc}). "
                    "Check the file permissions."
                ),
            ) from exc

        if not self._from_start:
            handle.seek(0, os.SEEK_END)
        else:
            header = handle.readline()
            detected = detect_csv_columns(header)
            if detected:
                self._columns = detected
            else:
                handle.seek(0)

        self._handle = handle
        try:
            self._inode = self._path.stat().st_ino
        except OSError:
            self._inode = None
        self.status.detail = f"Tailing Snort alert file {self._path}"

    def _close(self) -> None:
        """Close the file handle."""
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                pass
            self._handle = None

    def _read_loop(self) -> None:
        """Read appended lines, reopening on rotation or truncation."""
        buffer = ""
        while not self._stop.is_set():
            handle = self._handle
            if handle is None:
                break
            chunk = handle.read()
            if chunk:
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    self._handle_line(line)
            else:
                self._check_rotation()
                self._stop.wait(self._poll)

    def _handle_line(self, line: str) -> None:
        """Parse and emit one alert line, honouring a CSV header if present."""
        text = line.strip()
        if not text:
            return
        if text.startswith("#") or text.lower().startswith("timestamp,"):
            detected = detect_csv_columns(text)
            if detected:
                self._columns = detected
            return
        alert = parse_alert_line(text, self._columns)
        if alert is None:
            self._note_parse_failure(text)
            return
        self._emit(alert)

    def _check_rotation(self) -> None:
        """Reopen the file if Snort rotated or truncated it."""
        handle = self._handle
        if handle is None:
            return
        try:
            stat = self._path.stat()
        except OSError:
            return
        rotated = self._inode is not None and stat.st_ino != self._inode
        truncated = stat.st_size < handle.tell()
        if not (rotated or truncated):
            return
        LOGGER.info(
            "Snort alert file %s; reopening %s.",
            "rotated" if rotated else "truncated",
            self._path,
        )
        self._close()
        try:
            self._handle = self._path.open("r", encoding="utf-8", errors="replace")
            self._inode = stat.st_ino
        except OSError as exc:
            self.status.last_error = str(exc)
            LOGGER.error("Could not reopen the alert file: %s", exc)


def build_transport(
    transport: str,
    *,
    socket_path: Path | None,
    tcp_host: str,
    tcp_port: int,
    syslog_host: str,
    syslog_port: int,
    alert_file: Path | None,
    on_alert: AlertCallback,
    on_failure: FailureCallback | None = None,
) -> AlertTransport | None:
    """Construct the configured transport.

    Returns:
        The transport, or ``None`` when ingest is disabled.

    Raises:
        SnortIngestError: when the selected transport lacks its configuration.
    """
    choice = (transport or "disabled").lower()
    if choice == "disabled":
        return None
    if choice == "unixsock":
        if not socket_path:
            raise SnortIngestError(
                "AETHRA_SNORT_SOCKET_PATH is not set.",
                user_message=(
                    "Snort unavailable: set AETHRA_SNORT_SOCKET_PATH to the "
                    "path of the snort_alert socket (usually "
                    "<snort logdir>/snort_alert)."
                ),
            )
        return UnixSocketAlertTransport(socket_path, on_alert, on_failure)
    if choice == "tcp":
        return TcpAlertTransport(tcp_host, tcp_port, on_alert, on_failure)
    if choice == "syslog":
        return SyslogAlertTransport(syslog_host, syslog_port, on_alert, on_failure)
    if choice == "file":
        if not alert_file:
            raise SnortIngestError(
                "AETHRA_SNORT_ALERT_FILE is not set.",
                user_message=(
                    "Snort unavailable: set AETHRA_SNORT_ALERT_FILE to the "
                    "alert file Snort writes (for example "
                    "C:\\Snort\\log\\alert.ids)."
                ),
            )
        return AlertFileTransport(alert_file, on_alert, on_failure)
    raise SnortIngestError(
        f"Unknown Snort transport '{transport}'.",
        user_message=(
            f"Snort unavailable: '{transport}' is not a recognised transport. "
            "Use unixsock, tcp, syslog, file or disabled."
        ),
    )
