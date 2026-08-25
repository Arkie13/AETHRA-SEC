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

from aethra_sec.config.environment import (
    env_bool,
    env_int,
    env_list,
    env_path,
    env_str,
    load_env_file,
    project_root,
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
    pool_size: int = 5
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
class OtpSettings:
    """Optional email second factor.

    Disabled unless explicitly enabled *and* SMTP is configured. The System
    Health screen always reports the true status rather than implying that a
    second factor is active when it is not.
    """

    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    mail_from: str = ""
    use_starttls: bool = True
    ttl_seconds: int = 300

    @property
    def is_operational(self) -> bool:
        """True only when OTP delivery can actually be attempted."""
        return bool(self.enabled and self.smtp_host and self.mail_from)

    def status_text(self) -> str:
        """Exact configured status for display."""
        if not self.enabled:
            return "Disabled (AETHRA_OTP_ENABLED=false)"
        if not self.smtp_host:
            return "Enabled but not operational: SMTP host not configured"
        if not self.mail_from:
            return "Enabled but not operational: sender address not configured"
        return f"Enabled via {self.smtp_host}:{self.smtp_port}"


@dataclass(frozen=True)
class AppSettings:
    """Top-level settings aggregate handed to the application context."""

    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    tools: ToolSettings = field(default_factory=ToolSettings)
    snort: SnortSettings = field(default_factory=SnortSettings)
    capture: CaptureSettings = field(default_factory=CaptureSettings)
    authorization: AuthorizationSettings = field(default_factory=AuthorizationSettings)
    otp: OtpSettings = field(default_factory=OtpSettings)
    log_dir: Path = field(default_factory=lambda: project_root() / "logs")
    log_level: str = "INFO"
    report_dir: Path = field(default_factory=lambda: project_root() / "reports_output")
    ui_refresh_ms: int = 2000
    env_file: Path | None = None


def _resolve_dir(raw: str, fallback: Path) -> Path:
    """Resolve a configured directory relative to the project root."""
    if not raw:
        return fallback
    candidate = Path(raw).expanduser()
    return candidate if candidate.is_absolute() else (project_root() / candidate)


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
            pool_size=max(1, min(32, env_int("AETHRA_DB_POOL_SIZE", 5))),
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
        otp=OtpSettings(
            enabled=env_bool("AETHRA_OTP_ENABLED", False),
            smtp_host=env_str("AETHRA_SMTP_HOST"),
            smtp_port=env_int("AETHRA_SMTP_PORT", 587),
            smtp_user=env_str("AETHRA_SMTP_USER"),
            smtp_password=env_str("AETHRA_SMTP_PASSWORD"),
            mail_from=env_str("AETHRA_SMTP_FROM"),
            use_starttls=env_bool("AETHRA_SMTP_STARTTLS", True),
            ttl_seconds=max(30, env_int("AETHRA_OTP_TTL_SECONDS", 300)),
        ),
        log_dir=_resolve_dir(env_str("AETHRA_LOG_DIR"), project_root() / "logs"),
        log_level=env_str("AETHRA_LOG_LEVEL", "INFO").upper(),
        report_dir=_resolve_dir(
            env_str("AETHRA_REPORT_DIR"), project_root() / "reports_output"
        ),
        ui_refresh_ms=max(250, env_int("AETHRA_UI_REFRESH_MS", 2000)),
        env_file=loaded,
    )
