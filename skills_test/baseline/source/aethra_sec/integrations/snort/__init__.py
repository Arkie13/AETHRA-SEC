"""Snort integration: Alert Socket IPC, alternative transports and parsers."""

from __future__ import annotations

from aethra_sec.integrations.snort.alertpkt import (
    DecodedAlertPkt,
    build_alertpkt,
    decode_alertpkt,
)
from aethra_sec.integrations.snort.parser import (
    DEFAULT_CSV_COLUMNS,
    ParsedAlert,
    detect_csv_columns,
    parse_alert_line,
    parse_csv,
    parse_fast,
    parse_json,
    parse_syslog,
)
from aethra_sec.integrations.snort.transports import (
    AlertFileTransport,
    AlertTransport,
    SyslogAlertTransport,
    TcpAlertTransport,
    TransportStatus,
    UnixSocketAlertTransport,
    build_transport,
)

__all__ = [
    "AlertFileTransport",
    "AlertTransport",
    "DEFAULT_CSV_COLUMNS",
    "DecodedAlertPkt",
    "ParsedAlert",
    "SyslogAlertTransport",
    "TcpAlertTransport",
    "TransportStatus",
    "UnixSocketAlertTransport",
    "build_alertpkt",
    "build_transport",
    "decode_alertpkt",
    "detect_csv_columns",
    "parse_alert_line",
    "parse_csv",
    "parse_fast",
    "parse_json",
    "parse_syslog",
]
