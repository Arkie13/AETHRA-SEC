"""Parsers for Snort's text alert formats (§22).

Supported, auto-detected per line:

* ``alert_fast``  - the classic one-line format;
* ``alert_csv``   - configurable column list, header-driven when present;
* ``alert_json``  - Snort 3's JSON output;
* syslog-wrapped variants of any of the above (``alert_syslog``).

Every parser extracts only what the sensor actually wrote. Fields Snort did not
supply stay ``None``, and the raw line is always retained as evidence.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import from_epoch, utcnow

LOGGER = get_logger("integrations.snort.parser")

# 01/15-14:22:31.123456  [**] [1:2001219:19] ET SCAN ... [**]
# [Classification: Attempted Information Leak] [Priority: 2]
# {TCP} 192.168.1.50:44321 -> 192.168.1.25:22
_FAST_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"\[\*\*\]\s*"
    r"(?:\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*)?"
    r"(?P<message>.*?)\s*\[\*\*\]"
    r"(?:\s*\[Classification:\s*(?P<classification>[^\]]*)\])?"
    r"(?:\s*\[Priority:\s*(?P<priority>\d+)\])?"
    r"(?:\s*\{(?P<protocol>[A-Za-z0-9_-]+)\})?"
    r"(?:\s*(?P<src>[0-9a-fA-F:.]+?)(?::(?P<sport>\d+))?\s*->\s*"
    r"(?P<dst>[0-9a-fA-F:.]+?)(?::(?P<dport>\d+))?\s*)?$",
    re.DOTALL,
)

# A syslog line wrapping a fast-format alert.
_SYSLOG_RE = re.compile(
    r"^(?:<\d+>)?"                                     # optional priority
    r"(?:\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s+)?"      # optional timestamp
    r"(?:[\w.\-]+\s+)?"                                # optional hostname
    r"(?:snort(?:\[\d+\])?:\s*)?"                      # optional tag
    r"(?P<body>.*)$",
    re.DOTALL,
)

# snort[1234]: [1:2001219:19] ET SCAN ... [Classification: ...] [Priority: 2]:
# {TCP} 192.168.1.50:44321 -> 192.168.1.25:22
_SYSLOG_BODY_RE = re.compile(
    r"^\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*"
    r"(?P<message>.*?)"
    r"(?:\s*\[Classification:\s*(?P<classification>[^\]]*)\])?"
    r"(?:\s*\[Priority:\s*(?P<priority>\d+)\])?"
    r"\s*:?\s*"
    r"(?:\{(?P<protocol>[A-Za-z0-9_-]+)\}\s*)?"
    r"(?:(?P<src>[0-9a-fA-F:.]+?)(?::(?P<sport>\d+))?\s*->\s*"
    r"(?P<dst>[0-9a-fA-F:.]+?)(?::(?P<dport>\d+))?)?\s*$",
    re.DOTALL,
)

#: Default ``alert_csv`` column order used when the file carries no header.
DEFAULT_CSV_COLUMNS: tuple[str, ...] = (
    "timestamp", "sig_generator", "sig_id", "sig_rev", "msg", "proto",
    "src", "srcport", "dst", "dstport", "ethsrc", "ethdst", "ethlen",
    "tcpflags", "tcpseq", "tcpack", "tcplen", "tcpwindow", "ttl", "tos",
    "id", "dgmlen", "iplen", "icmptype", "icmpcode", "icmpid", "icmpseq",
)


@dataclass
class ParsedAlert:
    """One alert parsed from a text transport.

    Fields the sensor did not supply remain ``None`` - the alert detail view
    shows a dash rather than a filled-in guess.
    """

    message: str = ""
    timestamp: datetime | None = None
    generator_id: int | None = None
    signature_id: int | None = None
    revision: int | None = None
    classification: str = ""
    priority: int | None = None
    protocol: str = ""
    src_ip: str = ""
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    interface: str = ""
    sensor: str = ""
    raw: str = ""
    format: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_usable(self) -> bool:
        """True when enough was recovered to store a meaningful alert."""
        return bool(self.message or self.signature_id is not None)


def _to_int(value: Any) -> int | None:
    """Parse an integer field, returning ``None`` when absent or malformed."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 10)
    except ValueError:
        return None


def _parse_fast_timestamp(text: str, reference: datetime | None = None) -> datetime | None:
    """Parse the ``MM/DD-HH:MM:SS.ffffff`` timestamp of the fast format.

    The fast format omits the year, so the current year is used and a
    date in the future is rolled back one year (which happens across a New
    Year boundary). The parsed value is a real sensor timestamp; only the year
    is inferred, and :class:`ParsedAlert` records the format so the source of
    each field stays traceable.
    """
    if not text:
        return None
    now = reference or utcnow()
    candidate = text.strip()
    formats = (
        ("%m/%d/%y-%H:%M:%S.%f", True),
        ("%m/%d/%Y-%H:%M:%S.%f", True),
        ("%m/%d/%y-%H:%M:%S", True),
        ("%m/%d-%H:%M:%S.%f", False),
        ("%m/%d-%H:%M:%S", False),
    )
    for fmt, has_year in formats:
        try:
            parsed = datetime.strptime(candidate, fmt)
        except ValueError:
            continue
        if not has_year:
            parsed = parsed.replace(year=now.year)
            if parsed.replace(tzinfo=now.tzinfo) > now:
                parsed = parsed.replace(year=now.year - 1)
        return parsed.replace(tzinfo=now.tzinfo)
    return None


def parse_fast(line: str) -> ParsedAlert | None:
    """Parse one ``alert_fast`` line."""
    match = _FAST_RE.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    return ParsedAlert(
        message=(data.get("message") or "").strip(),
        timestamp=_parse_fast_timestamp(data.get("ts") or ""),
        generator_id=_to_int(data.get("gid")),
        signature_id=_to_int(data.get("sid")),
        revision=_to_int(data.get("rev")),
        classification=(data.get("classification") or "").strip(),
        priority=_to_int(data.get("priority")),
        protocol=(data.get("protocol") or "").upper(),
        src_ip=(data.get("src") or "").strip(),
        src_port=_to_int(data.get("sport")),
        dst_ip=(data.get("dst") or "").strip(),
        dst_port=_to_int(data.get("dport")),
        raw=line.strip(),
        format="alert_fast",
    )


def parse_syslog(line: str) -> ParsedAlert | None:
    """Parse a syslog-wrapped Snort alert."""
    outer = _SYSLOG_RE.match(line.strip())
    if not outer:
        return None
    body = (outer.group("body") or "").strip()
    if not body:
        return None

    fast = parse_fast(body)
    if fast and fast.is_usable:
        fast.raw = line.strip()
        fast.format = "alert_syslog"
        return fast

    match = _SYSLOG_BODY_RE.match(body)
    if not match:
        return None
    data = match.groupdict()
    alert = ParsedAlert(
        message=(data.get("message") or "").strip(),
        timestamp=None,
        generator_id=_to_int(data.get("gid")),
        signature_id=_to_int(data.get("sid")),
        revision=_to_int(data.get("rev")),
        classification=(data.get("classification") or "").strip(),
        priority=_to_int(data.get("priority")),
        protocol=(data.get("protocol") or "").upper(),
        src_ip=(data.get("src") or "").strip(),
        src_port=_to_int(data.get("sport")),
        dst_ip=(data.get("dst") or "").strip(),
        dst_port=_to_int(data.get("dport")),
        raw=line.strip(),
        format="alert_syslog",
    )
    return alert if alert.is_usable else None


def parse_json(line: str) -> ParsedAlert | None:
    """Parse a Snort 3 ``alert_json`` line."""
    text = line.strip()
    if not text.startswith("{"):
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    timestamp: datetime | None = None
    raw_time = data.get("timestamp") or data.get("seconds") or data.get("pkt_time")
    if isinstance(raw_time, (int, float)):
        try:
            timestamp = from_epoch(float(raw_time))
        except (OverflowError, OSError, ValueError):
            timestamp = None
    elif isinstance(raw_time, str):
        timestamp = _parse_fast_timestamp(raw_time)
        if timestamp is None:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    timestamp = datetime.strptime(raw_time, fmt).replace(
                        tzinfo=utcnow().tzinfo
                    )
                    break
                except ValueError:
                    continue

    known = {
        "timestamp", "seconds", "pkt_time", "msg", "gid", "sid", "rev",
        "class", "priority", "proto", "src_addr", "src_ap", "src_port",
        "dst_addr", "dst_ap", "dst_port", "iface", "interface", "action",
    }
    alert = ParsedAlert(
        message=str(data.get("msg") or "").strip(),
        timestamp=timestamp,
        generator_id=_to_int(data.get("gid")),
        signature_id=_to_int(data.get("sid")),
        revision=_to_int(data.get("rev")),
        classification=str(data.get("class") or "").strip(),
        priority=_to_int(data.get("priority")),
        protocol=str(data.get("proto") or "").upper(),
        src_ip=str(data.get("src_addr") or "").strip(),
        src_port=_to_int(data.get("src_port")),
        dst_ip=str(data.get("dst_addr") or "").strip(),
        dst_port=_to_int(data.get("dst_port")),
        interface=str(data.get("iface") or data.get("interface") or "").strip(),
        raw=text,
        format="alert_json",
        extra={k: v for k, v in data.items() if k not in known},
    )
    return alert if alert.is_usable else None


def parse_csv(
    line: str, columns: tuple[str, ...] = DEFAULT_CSV_COLUMNS
) -> ParsedAlert | None:
    """Parse an ``alert_csv`` line against a known column order."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    parts = [part.strip() for part in text.split(",")]
    if len(parts) < 3:
        return None
    values = dict(zip(columns, parts))
    if not any(values.get(key) for key in ("msg", "sig_id", "sig_generator")):
        return None

    known = set(columns[:10])
    alert = ParsedAlert(
        message=values.get("msg", "").strip('"'),
        timestamp=_parse_fast_timestamp(values.get("timestamp", "")),
        generator_id=_to_int(values.get("sig_generator")),
        signature_id=_to_int(values.get("sig_id")),
        revision=_to_int(values.get("sig_rev")),
        classification=values.get("class", "").strip('"'),
        priority=_to_int(values.get("priority")),
        protocol=values.get("proto", "").upper(),
        src_ip=values.get("src", ""),
        src_port=_to_int(values.get("srcport")),
        dst_ip=values.get("dst", ""),
        dst_port=_to_int(values.get("dstport")),
        raw=text,
        format="alert_csv",
        extra={k: v for k, v in values.items() if k not in known and v},
    )
    return alert if alert.is_usable else None


def parse_alert_line(
    line: str, csv_columns: tuple[str, ...] = DEFAULT_CSV_COLUMNS
) -> ParsedAlert | None:
    """Parse one alert line, detecting its format automatically.

    Returns:
        The parsed alert, or ``None`` when the line is not an alert (a blank
        line, a CSV header, or unrecognised output). Callers count ``None``
        results as parse failures and expose the count (§84).
    """
    text = (line or "").strip()
    if not text:
        return None

    if text.startswith("{"):
        return parse_json(text)

    fast = parse_fast(text)
    if fast and fast.is_usable:
        return fast

    if "[**]" in text or "snort" in text.lower() or text.startswith("<"):
        syslog = parse_syslog(text)
        if syslog and syslog.is_usable:
            return syslog

    if "," in text:
        return parse_csv(text, csv_columns)
    return None


def detect_csv_columns(header_line: str) -> tuple[str, ...] | None:
    """Read a CSV column order from a header line, when the file has one."""
    text = (header_line or "").strip().lstrip("#").strip()
    if not text or "," not in text:
        return None
    columns = tuple(part.strip().lower() for part in text.split(","))
    if "msg" in columns or "sig_id" in columns:
        return columns
    return None
