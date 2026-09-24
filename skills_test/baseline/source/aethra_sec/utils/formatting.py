"""Presentation helpers shared by the UI and the report writers."""

from __future__ import annotations

from typing import Any, Iterable, Sequence

EMPTY_PLACEHOLDER = "-"
NO_DATA_TEXT = "No data available"
WAITING_FOR_CAPTURE_TEXT = "Waiting for live network data..."


def dash(value: Any) -> str:
    """Render ``value``, substituting a dash for ``None``/empty values."""
    if value is None:
        return EMPTY_PLACEHOLDER
    text = str(value).strip()
    return text if text else EMPTY_PLACEHOLDER


def format_bytes(value: float | int | None) -> str:
    """Human-readable byte count (``1.4 MB``)."""
    if value is None:
        return EMPTY_PLACEHOLDER
    amount = float(value)
    if amount < 0:
        return EMPTY_PLACEHOLDER
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            precision = 0 if unit == "B" else 1
            return f"{amount:.{precision}f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"


def format_rate(value: float | None, unit: str = "pkt/s") -> str:
    """Human-readable rate with adaptive precision."""
    if value is None:
        return EMPTY_PLACEHOLDER
    if value >= 1000:
        return f"{value:,.0f} {unit}"
    if value >= 10:
        return f"{value:.1f} {unit}"
    return f"{value:.2f} {unit}"


def format_bandwidth(bytes_per_second: float | None) -> str:
    """Render a byte rate as bits per second, the usual bandwidth convention."""
    if bytes_per_second is None:
        return EMPTY_PLACEHOLDER
    bits = bytes_per_second * 8
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bits < 1000 or unit == "Gbps":
            precision = 0 if unit == "bps" else 2
            return f"{bits:.{precision}f} {unit}"
        bits /= 1000
    return f"{bits:.2f} Gbps"


def format_count(value: int | None) -> str:
    """Thousands-separated integer; ``0`` renders as ``0``, never as a dash."""
    if value is None:
        return EMPTY_PLACEHOLDER
    return f"{value:,}"


def format_percent(value: float | None, precision: int = 1) -> str:
    """Render a 0-100 percentage."""
    if value is None:
        return EMPTY_PLACEHOLDER
    return f"{value:.{precision}f}%"


def truncate(value: Any, length: int = 80, suffix: str = "...") -> str:
    """Shorten long text for table cells while keeping it readable."""
    text = dash(value)
    if len(text) <= length:
        return text
    return text[: max(0, length - len(suffix))] + suffix


def endpoint(ip: str | None, port: int | None) -> str:
    """Format an ``address:port`` endpoint, tolerating missing parts."""
    if not ip:
        return EMPTY_PLACEHOLDER
    if port is None:
        return str(ip)
    if ":" in str(ip):  # IPv6 literal
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def join_nonempty(values: Iterable[Any], separator: str = ", ") -> str:
    """Join the non-empty members of ``values``."""
    items = [str(v).strip() for v in values if v is not None and str(v).strip()]
    return separator.join(items) if items else EMPTY_PLACEHOLDER


def pluralize(count: int, singular: str, plural: str | None = None) -> str:
    """``1 alert`` / ``3 alerts``."""
    word = singular if count == 1 else (plural or f"{singular}s")
    return f"{count:,} {word}"


def sentence_list(values: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    cleaned = [v for v in values if v]
    if not cleaned:
        return EMPTY_PLACEHOLDER
    if len(cleaned) == 1:
        return cleaned[0]
    return f"{', '.join(cleaned[:-1])} and {cleaned[-1]}"


def tcp_flag_names(flags: int | None) -> str:
    """Decode a TCP flags byte into names (``SYN,ACK``)."""
    if flags is None:
        return EMPTY_PLACEHOLDER
    names = [
        (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
        (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
    ]
    active = [name for mask, name in names if flags & mask]
    return ",".join(active) if active else EMPTY_PLACEHOLDER
