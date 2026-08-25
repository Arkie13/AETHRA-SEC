"""Decoder for Snort's binary ``Alertpkt`` datagram - the Alert Socket IPC (§21).

Snort's ``alert_unixsock`` output plugin writes one C ``Alertpkt`` structure per
alert to a Unix datagram socket. Its layout (Snort 2.9 ``spo_alert_unixsock.h``)
is::

    typedef struct _Alertpkt {
        uint8_t  alertmsg[ALERTMSG_LENGTH];   /* 256 bytes, NUL padded  */
        struct pcap_pkthdr pkth;              /* timeval + caplen + len */
        uint32_t dlthdr;                      /* offset into pkt[]      */
        uint32_t nethdr;
        uint32_t transhdr;
        uint32_t data;
        uint32_t val;                         /* validity bitmask       */
        uint8_t  pkt[SNAPLEN];                /* the offending packet   */
        Event    event;                       /* gid/sid/rev/prio/...   */
    } Alertpkt;

Two details make a naive ``struct.unpack`` fragile, and both are handled here:

* ``SNAPLEN`` is a build-time constant, so the offset of ``event`` differs
  between Snort builds - and ``event`` is not reliably the *last* thing in the
  buffer either: Snort 2.9.20 on x86-64 sends 65,928 bytes with the event 96
  from the end and alignment padding after it. The decoder therefore searches
  a bounded window back from the end rather than anchoring on either edge.
* ``struct timeval`` is 8 bytes on 32-bit builds and 16 on 64-bit ones. Both
  layouts are attempted and the one producing plausible values is used.

The decoder never invents an alert: if a datagram cannot be decoded into
sensible values it returns ``None`` and the caller counts a parse failure,
which the interface displays.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import from_epoch

LOGGER = get_logger("integrations.snort.alertpkt")

ALERTMSG_LENGTH = 256

#: How far back from the end of a datagram the ``Event`` is searched for.
#: Snort 2.9.20 on x86-64 places it 96 bytes from the end; the window is wide
#: enough for that and for builds that pad differently, and narrow enough that
#: it cannot wander into packet bytes and decode noise as an event.
EVENT_SEARCH_BYTES = 256

#: ``Event`` is 7 uint32 fields plus a timeval; the two candidate encodings are
#: (32-bit timeval, no padding) and (64-bit timeval, 4 bytes of padding).
_EVENT_LAYOUTS: tuple[tuple[str, int], ...] = (
    ("<7I4xqq", 48),   # 64-bit build: 28 bytes + 4 pad + 2x int64
    ("<7Iii", 36),     # 32-bit build: 28 bytes + 2x int32
    ("<7III", 40),     # some builds pad the struct to an 8-byte multiple
)

#: ``struct pcap_pkthdr`` candidates: (format, size, description).
_PKTHDR_LAYOUTS: tuple[tuple[str, int], ...] = (
    ("<qqII", 24),     # 64-bit timeval
    ("<iiII", 16),     # 32-bit timeval
)

_MIN_PLAUSIBLE_EPOCH = 946_684_800      # 2000-01-01
_MAX_PLAUSIBLE_EPOCH = 4_102_444_800    # 2100-01-01


@dataclass
class DecodedAlertPkt:
    """One decoded Snort ``Alertpkt`` datagram."""

    message: str
    timestamp: datetime | None
    generator_id: int | None = None
    signature_id: int | None = None
    revision: int | None = None
    classification_id: int | None = None
    priority: int | None = None
    event_id: int | None = None
    event_reference: int | None = None
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = ""
    ttl: int | None = None
    packet_length: int = 0
    capture_length: int = 0
    layout: str = ""
    raw_size: int = 0
    packet_decoded: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def has_endpoints(self) -> bool:
        """True when addresses were recovered from the embedded packet."""
        return bool(self.src_ip and self.dst_ip)


def _plausible_event(values: tuple[int, ...]) -> bool:
    """Sanity-check candidate ``Event`` field values.

    Real Snort events have a small generator id, a bounded priority and a
    non-absurd signature id. This is what lets the decoder choose between the
    32-bit and 64-bit layouts without being told which build produced the data.
    """
    generator, signature, revision, classification, priority = values[:5]
    if not 0 < generator <= 10_000:
        return False
    # A real alert always carries a signature id. Requiring one keeps the
    # backwards search from settling on a run of zero padding.
    if not 0 < signature <= 100_000_000:
        return False
    if revision > 100_000:
        return False
    if classification > 1_000:
        return False
    if priority > 255:
        return False
    # Every candidate layout ends with the event's reference timeval. Requiring
    # its seconds to be a real date is what separates the true event from a
    # window a few bytes off it, which can otherwise satisfy every bound above
    # by reading classification as the signature id.
    if len(values) > 7 and not (
        _MIN_PLAUSIBLE_EPOCH <= values[7] <= _MAX_PLAUSIBLE_EPOCH
    ):
        return False
    return True


def _decode_event(payload: bytes) -> tuple[dict[str, int], str] | None:
    """Decode the ``Event`` structure near the end of the datagram.

    ``Event`` is *not* reliably the last thing in the buffer. Snort 2.9.20 on
    a 64-bit build sends a 65,928-byte ``Alertpkt`` whose event begins 96 bytes
    from the end, with alignment padding after it - so a decoder that only
    looked at ``payload[-size:]`` read zeroes, rejected them (correctly, since
    a real event has a non-zero generator) and reported every alert as
    ``[?:?:?]`` with no signature id at all.

    The event is therefore searched for rather than assumed: candidate offsets
    are walked back from the end on uint32 alignment, and the first layout that
    decodes to plausible field values wins.

    Returns:
        ``(fields, layout_name, start_offset)`` or ``None`` when no candidate
        layout fits. The offset is where the event begins, which is also where
        the embedded packet ends - the caller must not assume that is the end
        of the datagram.
    """
    for fmt, size in _EVENT_LAYOUTS:
        if len(payload) < size:
            continue
        limit = min(EVENT_SEARCH_BYTES, len(payload) - size)
        for back in range(0, limit + 1, 4):
            end = len(payload) - back
            try:
                unpacked = struct.unpack(fmt, payload[end - size:end])
            except struct.error:
                continue
            if not _plausible_event(unpacked):
                continue
            return (
                {
                    "sig_generator": unpacked[0],
                    "sig_id": unpacked[1],
                    "sig_rev": unpacked[2],
                    "classification": unpacked[3],
                    "priority": unpacked[4],
                    "event_id": unpacked[5],
                    "event_reference": unpacked[6],
                    "ref_time_sec": unpacked[7] if len(unpacked) > 7 else 0,
                },
                f"event:{fmt}@-{back}",
                end - size,
            )
    return None


def _decode_pkthdr(payload: bytes) -> tuple[dict[str, int], int, str] | None:
    """Decode ``struct pcap_pkthdr`` following the alert message.

    Returns:
        ``(fields, consumed_bytes, layout_name)`` or ``None``.
    """
    for fmt, size in _PKTHDR_LAYOUTS:
        if len(payload) < ALERTMSG_LENGTH + size:
            continue
        try:
            seconds, microseconds, caplen, length = struct.unpack(
                fmt, payload[ALERTMSG_LENGTH : ALERTMSG_LENGTH + size]
            )
        except struct.error:
            continue
        if not _MIN_PLAUSIBLE_EPOCH <= seconds <= _MAX_PLAUSIBLE_EPOCH:
            continue
        if not 0 <= microseconds < 1_000_000:
            continue
        if caplen > 262_144 or length > 262_144:
            continue
        return (
            {
                "ts_sec": seconds,
                "ts_usec": microseconds,
                "caplen": caplen,
                "len": length,
            },
            size,
            f"pkthdr:{fmt}",
        )
    return None


def _ip_to_text(raw: bytes) -> str:
    """Render 4 raw bytes as dotted-quad IPv4."""
    try:
        return socket.inet_ntoa(raw)
    except (OSError, ValueError):
        return ""


def _decode_embedded_packet(
    packet_bytes: bytes, net_offset: int, trans_offset: int
) -> dict[str, Any]:
    """Recover endpoints from the packet Snort attached to the alert.

    Uses the offsets Snort itself supplied rather than re-parsing the link
    layer, which keeps the decoder independent of the datalink type.
    """
    result: dict[str, Any] = {
        "src_ip": "", "dst_ip": "", "src_port": None, "dst_port": None,
        "protocol": "", "ttl": None, "decoded": False,
    }
    if net_offset <= 0 or net_offset + 20 > len(packet_bytes):
        return result

    header = packet_bytes[net_offset : net_offset + 20]
    version_ihl = header[0]
    version = version_ihl >> 4
    if version != 4:
        return result

    protocol_number = header[9]
    result["ttl"] = header[8]
    result["src_ip"] = _ip_to_text(header[12:16])
    result["dst_ip"] = _ip_to_text(header[16:20])
    result["protocol"] = {
        1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 47: "GRE",
        50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
    }.get(protocol_number, f"IP/{protocol_number}")
    result["decoded"] = bool(result["src_ip"] and result["dst_ip"])

    if protocol_number in (6, 17):
        offset = trans_offset if trans_offset > 0 else net_offset + ((version_ihl & 0x0F) * 4)
        if 0 < offset and offset + 4 <= len(packet_bytes):
            try:
                src_port, dst_port = struct.unpack(
                    "!HH", packet_bytes[offset : offset + 4]
                )
                result["src_port"] = src_port
                result["dst_port"] = dst_port
            except struct.error:
                pass
    return result


def _plausible_message(raw: bytes) -> str:
    """Decode the alert message field, refusing anything that is not text.

    Snort writes the rule message as printable text. Bytes that are not valid
    UTF-8, or that contain control characters, mean the datagram is not an
    Alertpkt - returning an empty string lets the caller refuse it rather than
    surface a row of replacement characters as an alert (§1, §84).
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    text = text.strip()
    if not text:
        return ""
    if any(not (character.isprintable() or character in " \t") for character in text):
        return ""
    return text


def decode_alertpkt(payload: bytes) -> DecodedAlertPkt | None:
    """Decode one ``Alertpkt`` datagram received on the alert socket.

    Args:
        payload: the exact bytes read from the Unix datagram socket.

    Returns:
        A :class:`DecodedAlertPkt`, or ``None`` when the datagram does not look
        like an Alertpkt at all. The caller records a parse failure so the
        alert-reliability counters stay truthful (§84).
    """
    if len(payload) < ALERTMSG_LENGTH + 32:
        return None

    warnings: list[str] = []

    message = payload[:ALERTMSG_LENGTH].split(b"\x00", 1)[0]
    message_text = _plausible_message(message)

    header = _decode_pkthdr(payload)
    timestamp: datetime | None = None
    caplen = 0
    packet_length = 0
    offsets_start = ALERTMSG_LENGTH
    pkthdr_layout = "pkthdr:unknown"
    if header is not None:
        fields, consumed, pkthdr_layout = header
        offsets_start = ALERTMSG_LENGTH + consumed
        caplen = int(fields["caplen"])
        packet_length = int(fields["len"])
        try:
            timestamp = from_epoch(
                fields["ts_sec"] + fields["ts_usec"] / 1_000_000.0
            )
        except (OverflowError, OSError, ValueError):
            timestamp = None
            warnings.append("packet timestamp out of range")
    else:
        warnings.append("pcap_pkthdr could not be decoded")

    net_offset = trans_offset = 0
    if len(payload) >= offsets_start + 20:
        try:
            _dlthdr, net_offset, trans_offset, _data, _val = struct.unpack(
                "<5I", payload[offsets_start : offsets_start + 20]
            )
        except struct.error:
            warnings.append("packet offsets could not be decoded")
    else:
        warnings.append("datagram too short for packet offsets")

    event = _decode_event(payload)
    event_fields: dict[str, int] = {}
    event_layout = "event:unknown"
    event_start = 0
    if event is not None:
        event_fields, event_layout, event_start = event
    else:
        warnings.append("Event structure could not be decoded")

    packet_start = offsets_start + 20
    packet_end = event_start if event_start else len(payload)
    packet_bytes = payload[packet_start:packet_end] if packet_end > packet_start else b""
    if caplen and 0 < caplen <= len(packet_bytes):
        packet_bytes = packet_bytes[:caplen]

    endpoints = _decode_embedded_packet(packet_bytes, net_offset, trans_offset)
    if not endpoints["decoded"]:
        warnings.append("embedded packet did not yield IPv4 endpoints")

    if not message_text and not event_fields:
        # Neither a message nor an event: this is not an Alertpkt.
        return None

    return DecodedAlertPkt(
        message=message_text,
        timestamp=timestamp,
        generator_id=event_fields.get("sig_generator"),
        signature_id=event_fields.get("sig_id"),
        revision=event_fields.get("sig_rev"),
        classification_id=event_fields.get("classification"),
        priority=event_fields.get("priority"),
        event_id=event_fields.get("event_id"),
        event_reference=event_fields.get("event_reference"),
        src_ip=str(endpoints["src_ip"]),
        dst_ip=str(endpoints["dst_ip"]),
        src_port=endpoints["src_port"],
        dst_port=endpoints["dst_port"],
        protocol=str(endpoints["protocol"]),
        ttl=endpoints["ttl"],
        packet_length=packet_length,
        capture_length=caplen,
        layout=f"{pkthdr_layout}|{event_layout}",
        raw_size=len(payload),
        packet_decoded=bool(endpoints["decoded"]),
        warnings=tuple(warnings),
    )


def build_alertpkt(
    message: str,
    *,
    generator_id: int = 1,
    signature_id: int = 1000001,
    revision: int = 1,
    classification: int = 1,
    priority: int = 2,
    event_id: int = 1,
    event_reference: int = 0,
    timestamp: float = 1_700_000_000.0,
    packet: bytes = b"",
    link_header_length: int = 14,
    snaplen: int = 1514,
    sixty_four_bit: bool = True,
) -> bytes:
    """Build an ``Alertpkt`` datagram in Snort's own wire format.

    This exists so the **test suite** can exercise the decoder against a byte
    layout identical to Snort's, and so an operator can validate their socket
    configuration end to end with ``scripts/snort_socket_probe.py``. It is
    never used by the running application to produce alerts - the alert
    pipeline only ever ingests bytes that a real sensor wrote.

    Args:
        message: alert text (truncated to 255 characters plus NUL).
        packet: the raw frame to embed, starting at the link header.
        link_header_length: size of the link header inside ``packet``.
        snaplen: size of the ``pkt`` array, mirroring Snort's build constant.
        sixty_four_bit: emit 64-bit ``timeval`` fields.
    """
    encoded = message.encode("utf-8")[: ALERTMSG_LENGTH - 1]
    buffer = bytearray(encoded.ljust(ALERTMSG_LENGTH, b"\x00"))

    seconds = int(timestamp)
    microseconds = int(round((timestamp - seconds) * 1_000_000))
    capture_length = min(len(packet), snaplen)
    if sixty_four_bit:
        buffer += struct.pack("<qqII", seconds, microseconds, capture_length, len(packet))
    else:
        buffer += struct.pack("<iiII", seconds, microseconds, capture_length, len(packet))

    net_offset = link_header_length if packet else 0
    trans_offset = 0
    if packet and len(packet) > net_offset + 20:
        ihl = (packet[net_offset] & 0x0F) * 4
        trans_offset = net_offset + ihl
    buffer += struct.pack("<5I", 0, net_offset, trans_offset, 0, 0)

    payload = bytearray(packet[:snaplen])
    payload.extend(b"\x00" * (snaplen - len(payload)))
    buffer += payload

    if sixty_four_bit:
        buffer += struct.pack(
            "<7I4xqq",
            generator_id, signature_id, revision, classification, priority,
            event_id, event_reference, seconds, microseconds,
        )
    else:
        buffer += struct.pack(
            "<7Iii",
            generator_id, signature_id, revision, classification, priority,
            event_id, event_reference, seconds, microseconds,
        )
    return bytes(buffer)
