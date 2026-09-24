"""Typed application settings assembled from the process environment.

Only *deployment* configuration lives here (credentials, tool paths, transport
selection, authorisation boundary). Operator-tunable behaviour (thresholds,
retention, refresh rates) lives in the ``system_settings`` database table and is
accessed through :class:`aethra_sec.services.settings_service.SettingsService`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from aethra_sec.config import paths
from aethra_sec.config.environment import (
    env_bool,
    env_int,
    env_list,
    env_path,
    env_str,
    load_env_file,
)

DEFAULT_AUTHORIZED_NETWORKS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "::1/128",
)

SNORT_TRANSPORTS: tuple[str, ...] = ("disabled", "unixsock", "tcp", "syslog", "file")


@dataclass(frozen=True)
class DatabaseSettings:
    """MySQL connection parameters.

    The password is read from the environment and is never written to logs,
    audit records, exports or the user interface.
    """

    host: str = "127.0.0.1"
    port: int = 3306
    database: str = "aethra_sec"
    user: str = "aethra_app"
    password: str = ""
    pool_size: int = 8
    connect_timeout: int = 10

    @property
    def is_configured(self) -> bool:
        """True when enough information exists to attempt a connection."""
        return bool(self.host and self.database and self.user)

    def redacted(self) -> dict[str, object]:
        """Connection description safe for diagnostics display and logging."""
        return {
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "user": self.user,
            "password": "(set)" if self.password else "(not set)",
            "pool_size": self.pool_size,
            "connect_timeout": self.connect_timeout,
        }


@dataclass(frozen=True)
class ToolSettings:
    """Filesystem locations of the external security tools.

    ``None`` means "discover on PATH / standard install locations".
    """

    nmap_path: Path | None = None
    tshark_path: Path | None = None
    snort_path: Path | None = None
    snort_config: Path | None = None


@dataclass(frozen=True)
class SnortSettings:
    """How real Snort alerts reach AETHRA-SEC.

    ``transport`` selects the ingest mechanism; see docs/SNORT_INTEGRATION.md.
    No transport ever generates an alert - each one only reads what a running
    Snort sensor produced.
    """

    transport: str = "disabled"
    socket_path: Path | None = None
    tcp_host: str = "127.0.0.1"
    tcp_port: int = 9000
    syslog_host: str = "127.0.0.1"
    syslog_port: int = 5514
    alert_file: Path | None = None

    @property
    def enabled(self) -> bool:
        """True when an ingest transport other than ``disabled`` is selected."""
        return self.transport != "disabled"

    def describe(self) -> str:
        """Human-readable one-line description of the configured transport."""
        if self.transport == "unixsock":
            return f"Unix alert socket: {self.socket_path or '(path not set)'}"
        if self.transport == "tcp":
            return f"TCP listener: {self.tcp_host}:{self.tcp_port}"
        if self.transport == "syslog":
            return f"UDP syslog listener: {self.syslog_host}:{self.syslog_port}"
        if self.transport == "file":
            return f"Alert file: {self.alert_file or '(path not set)'}"
        return "Disabled"


@dataclass(frozen=True)
class CaptureSettings:
    """Live capture deployment options."""

    interface: str = ""
    bpf_filter: str = ""


@dataclass(frozen=True)
class AuthorizationSettings:
    """The authorisation boundary enforced on every assessment target.

    AETHRA-SEC refuses Nmap targets outside these networks. ``allow_public``
    exists only for deliberately authorised laboratories that use public
    address space; it defaults to false.
    """

    networks: tuple[str, ...] = DEFAULT_AUTHORIZED_NETWORKS
    allow_public: bool = False

    @property
    def parsed_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        """Configured networks parsed into ``ipaddress`` objects.

        Malformed CIDR entries are skipped rather than crashing startup; the
        diagnostics screen reports the difference between configured and
        parsed entries.
        """
        parsed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw in self.networks:
            try:
                parsed.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue
        return tuple(parsed)

    @property
    def invalid_networks(self) -> tuple[str, ...]:
        """Configured entries that could not be parsed as CIDR networks."""
        invalid: list[str] = []
        for raw in self.networks:
            try:
                ipaddress.ip_network(raw, strict=False)
            except ValueError:
                invalid.append(raw)
        return tuple(invalid)


@dataclass(frozen=True)
class SmtpSettings:
    """Outbound email, used for notifications and for nothing else.

    AETHRA-SEC has no email step in its sign-in. A session is issued on a
    correct username and password, and no state of the mail configuration can
    grant access or withhold it. That separation is deliberate: an outage of a
    mail server is an operational inconvenience here, not a lockout.

    The password is read from the configuration file and is never written to a
    log, an audit record, an export or the interface.
    """

    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    mail_from: str = ""
    use_starttls: bool = True
    #: Where administrative and security notifications are sent. Falls back to
    #: the administrator's own registered address when left empty.
    recipient: str = ""
    timeout_seconds: int = 20

    @property
    def is_configured(self) -> bool:
        """True when a message could actually be addressed and sent.

        A host and a sender are the minimum. Authentication is optional - an
        internal relay that accepts unauthenticated mail from the LAN is a
        legitimate configuration, and demanding a username would rule it out.
        """
        return bool(self.host and self.mail_from)

    def status_text(self) -> str:
        """The exact configured status, in the words the interface displays.

        Two states only, and neither is optimistic: "configured" means the
        settings are complete enough to attempt delivery, never that delivery
        has been proven. Whether a message actually arrived is reported by the
        send itself, which is the only thing that knows.
        """
        if not self.is_configured:
            return "SMTP NOT CONFIGURED"
        security = "STARTTLS" if self.use_starttls else "implicit TLS"
        return f"SMTP CONFIGURED - {self.host}:{self.port} ({security})"


@dataclass(frozen=True)
class AppSettings:
    """Top-level settings aggregate handed to the application context."""

    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    tools: ToolSettings = field(default_factory=ToolSettings)
    snort: SnortSettings = field(default_factory=SnortSettings)
    capture: CaptureSettings = field(default_factory=CaptureSettings)
    authorization: AuthorizationSettings = field(default_factory=AuthorizationSettings)
    smtp: SmtpSettings = field(default_factory=SmtpSettings)
    log_dir: Path = field(default_factory=paths.log_dir)
    log_level: str = "INFO"
    report_dir: Path = field(default_factory=paths.report_dir)
    #: Where a capture session writes its pcap. The packet inspector re-reads
    #: individual frames from that file, which is what lets it show real
    #: decoded fields and real bytes rather than the summary the table holds.
    capture_dir: Path = field(default_factory=paths.capture_dir)
    ui_refresh_ms: int = 2000
    env_file: Path | None = None


def _resolve_dir(raw: str, fallback: Path) -> Path:
    """Resolve a configured directory, relative entries against the data dir.

    A relative path in the configuration file means "inside this installation's
    own data area", which is the project folder for a checkout and the
    application-data directory for an installed build. Resolving it against the
    working directory instead would put an operator's reports wherever the
    shortcut happened to start the process.
    """
    if not raw:
        return fallback
    candidate = Path(raw).expanduser()
    return candidate if candidate.is_absolute() else (paths.data_dir() / candidate)


def load_settings(env_file: Path | None = None) -> AppSettings:
    """Build :class:`AppSettings` from the environment (loading ``.env`` first).

    Args:
        env_file: optional explicit ``.env`` path.

    Returns:
        A fully populated, immutable settings aggregate. Missing values fall
        back to conservative defaults; nothing here fails startup, because the
        System Health screen is responsible for reporting what is unusable.
    """
    loaded = load_env_file(env_file)

    transport = env_str("AETHRA_SNORT_TRANSPORT", "disabled").lower()
    if transport not in SNORT_TRANSPORTS:
        transport = "disabled"

    networks = env_list("AETHRA_AUTHORIZED_NETWORKS") or DEFAULT_AUTHORIZED_NETWORKS

    return AppSettings(
        database=DatabaseSettings(
            host=env_str("AETHRA_DB_HOST", "127.0.0.1"),
            port=env_int("AETHRA_DB_PORT", 3306),
            database=env_str("AETHRA_DB_NAME", "aethra_sec"),
            user=env_str("AETHRA_DB_USER", "aethra_app"),
            password=env_str("AETHRA_DB_PASSWORD"),
            pool_size=max(1, min(32, env_int("AETHRA_DB_POOL_SIZE", 8))),
            connect_timeout=max(1, env_int("AETHRA_DB_CONNECT_TIMEOUT", 10)),
        ),
        tools=ToolSettings(
            nmap_path=env_path("AETHRA_NMAP_PATH"),
            tshark_path=env_path("AETHRA_TSHARK_PATH"),
            snort_path=env_path("AETHRA_SNORT_PATH"),
            snort_config=env_path("AETHRA_SNORT_CONFIG"),
        ),
        snort=SnortSettings(
            transport=transport,
            socket_path=env_path("AETHRA_SNORT_SOCKET_PATH"),
            tcp_host=env_str("AETHRA_SNORT_TCP_HOST", "127.0.0.1"),
            tcp_port=env_int("AETHRA_SNORT_TCP_PORT", 9000),
            syslog_host=env_str("AETHRA_SNORT_SYSLOG_HOST", "127.0.0.1"),
            syslog_port=env_int("AETHRA_SNORT_SYSLOG_PORT", 5514),
            alert_file=env_path("AETHRA_SNORT_ALERT_FILE"),
        ),
        capture=CaptureSettings(
            interface=env_str("AETHRA_CAPTURE_INTERFACE"),
            bpf_filter=env_str("AETHRA_CAPTURE_BPF"),
        ),
        authorization=AuthorizationSettings(
            networks=networks,
            allow_public=env_bool("AETHRA_ALLOW_PUBLIC_TARGETS", False),
        ),
        smtp=SmtpSettings(
            host=env_str("AETHRA_SMTP_HOST"),
            port=env_int("AETHRA_SMTP_PORT", 587),
            username=env_str("AETHRA_SMTP_USER"),
            password=env_str("AETHRA_SMTP_PASSWORD"),
            mail_from=env_str("AETHRA_SMTP_FROM"),
            use_starttls=env_bool("AETHRA_SMTP_STARTTLS", True),
            recipient=env_str("AETHRA_SMTP_TO"),
            timeout_seconds=max(5, env_int("AETHRA_SMTP_TIMEOUT_SECONDS", 20)),
        ),
        log_dir=_resolve_dir(env_str("AETHRA_LOG_DIR"), paths.log_dir()),
        log_level=env_str("AETHRA_LOG_LEVEL", "INFO").upper(),
        report_dir=_resolve_dir(
            env_str("AETHRA_REPORT_DIR"), paths.report_dir()
        ),
        capture_dir=_resolve_dir(
            env_str("AETHRA_CAPTURE_DIR"), paths.capture_dir()
        ),
        ui_refresh_ms=max(250, env_int("AETHRA_UI_REFRESH_MS", 2000)),
        env_file=loaded,
    )
