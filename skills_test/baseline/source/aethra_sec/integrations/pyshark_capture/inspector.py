"""Full decode of a single captured frame, read back from the session pcap.

The live path keeps only a summary per packet (:class:`CapturedPacket`), which
is all the table needs and all it can afford at line rate. Inspection needs the
opposite: everything TShark can say about one frame. So the frame is read again
from the pcap the capture session wrote, with ``include_raw`` enabled, and the
decode below is TShark's own - field names, field values and byte offsets all
come from the capture file.

Nothing here synthesises a field. Where a value is genuinely absent from the
frame the caller is given :data:`NOT_AVAILABLE`, and where a payload is
encrypted it is reported as encrypted rather than guessed at. There is no
decryption, no key recovery and no credential recovery of any kind: a secret
that is not in the captured bytes cannot be produced by this module, and one
that *is* in them is redacted before it reaches the interface.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("integrations.pyshark.inspector")

#: Shown wherever the capture simply does not carry a value. Never a guess,
#: never a plausible default - the absence is itself the finding.
NOT_AVAILABLE = "Not available in capture"

#: Redacted stand-in. The bytes stay in the pcap; only the display is masked.
REDACTED = "[redacted - sensitive value]"

#: Field-name fragments whose value is treated as a credential or secret and
#: masked before display. Matched against TShark's own field names, so this
#: reacts to what the frame actually carries rather than to a guess about it.
_SENSITIVE_PATTERNS: tuple[str, ...] = (
    "authorization", "proxy_authenticate", "www_authenticate", "password",
    "passwd", "pwd", "cookie", "token", "api_key", "apikey", "secret",
    "session_id", "sessionid", "auth_token", "credential", "ntlmssp",
    "kerberos.cipher", "private_key", "pre_master", "bearer",
    # TShark decodes HTTP Basic credentials into these outright.
    "authbasic", "authpassword", "auth_password",
)

#: Values are redacted as well as names. A dissector routinely reports the same
#: bytes twice - once as a named header and once inside an aggregate field such
#: as ``http.request.line`` - and masking only the named field would publish the
#: credential anyway under a name that looks innocuous. These patterns mask the
#: secret *within* a larger value while leaving the rest of it readable.
_VALUE_REDACTIONS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)\b(authorization|proxy-authorization|www-authenticate|"
        r"proxy-authenticate|set-cookie|cookie)(\s*:\s*)([^,\r\n]+)"
    ),
    re.compile(
        r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|session|"
        r"auth[_-]?token)(\s*[=:]\s*)([^&\s,;\r\n]+)"
    ),
    # "Basic dXNlcjpwYXNz" / "Bearer eyJ..." wherever they appear.
    re.compile(r"(?i)\b(Basic|Bearer|Digest|NTLM|Negotiate)(\s+)([A-Za-z0-9+/=._-]{8,})"),
)


def redact_value(text: str) -> tuple[str, bool]:
    """Mask any credential embedded in a decoded value.

    Returns the display text and whether anything was masked. The capture file
    is untouched; only what reaches the screen is changed.
    """
    if not text:
        return (text, False)
    masked = text
    for pattern in _VALUE_REDACTIONS:
        masked = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", masked)
    return (masked, masked != text)

#: Layers whose payload is protected. The inspector shows their handshake and
#: metadata - which are legitimately in the clear - and states plainly that the
#: application data is encrypted instead of attempting to read it.
_ENCRYPTED_LAYERS: frozenset[str] = frozenset(
    {"TLS", "SSL", "QUIC", "SSH", "IPSEC", "ESP", "WIREGUARD", "DTLS"}
)

#: Layers that are structure rather than protocol, hidden from the tree.
_TREE_SKIP: frozenset[str] = frozenset({"FAKE_FIELD_WRAPPER"})

#: Cap on bytes rendered in the hex view. A jumbo frame is still fully read;
#: this only bounds what is formatted for display in one pass.
MAX_HEX_BYTES = 65_535


@dataclass(frozen=True)
class PacketField:
    """One decoded field, exactly as TShark reported it."""

    label: str
    value: str
    #: TShark's own field name (``tcp.seq``), shown so a value can be traced
    #: back to the dissector that produced it and used by "Copy field".
    name: str = ""
    #: Byte offset and length of this field inside the frame, when TShark
    #: reported them. Drives selection highlighting in the hex view.
    offset: int | None = None
    length: int | None = None
    #: True when the value was masked as a credential or secret.
    sensitive: bool = False
    #: Sub-fields TShark grouped under this one - the bits of ``tcp.flags``,
    #: the parts of ``ip.dsfield``. The nesting is the dissector's own, taken
    #: from its ``_tree`` grouping; it is never inferred from the field name.
    children: tuple["PacketField", ...] = ()


@dataclass(frozen=True)
class LayerNode:
    """One protocol layer and the fields decoded from it."""

    name: str
    title: str
    fields: tuple[PacketField, ...] = ()
    offset: int | None = None
    length: int | None = None
    #: Set when this layer's payload is protected by encryption.
    encrypted: bool = False


@dataclass
class PacketDetail:
    """Everything the capture legitimately says about one frame."""

    frame_index: int
    pcap_path: str
    layers: tuple[LayerNode, ...] = ()
    raw_bytes: bytes = b""
    summary: str = ""
    #: Populated when the frame could not be read; the interface shows this
    #: rather than an empty inspector that looks like a decoded packet.
    error: str = ""
    stream_kind: str = ""
    stream_index: int | None = None
    sensitive_fields: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """True when a real frame was decoded."""
        return not self.error and bool(self.layers)

    @property
    def encrypted_layers(self) -> tuple[str, ...]:
        """Names of layers whose payload is protected."""
        return tuple(layer.name for layer in self.layers if layer.encrypted)


def is_sensitive_name(name: str) -> bool:
    """True when a field name marks its value as a credential or secret."""
    lowered = (name or "").lower()
    return any(pattern in lowered for pattern in _SENSITIVE_PATTERNS)


def _text(value: Any, limit: int = 2048) -> str:
    """Render a field value as displayable text, without inventing one."""
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) > limit:
        return f"{text[:limit]} ... [{len(text) - limit} more characters]"
    return text


def _position(entry: Any) -> tuple[int | None, int | None]:
    """Byte offset and length from a TShark ``_raw`` entry.

    In ``use_json`` + ``include_raw`` mode every decoded field is accompanied
    by a ``<name>_raw`` entry of ``[hex, offset, length, bitmask, type]``. Only
    real entries are used; a field without one simply has no position, and the
    hex view then highlights nothing rather than a guessed range.
    """
    if isinstance(entry, (list, tuple)) and len(entry) >= 3:
        # A field present more than once (``tcp.port``) nests one entry per
        # occurrence; the layer's own span is the first of them.
        if entry and isinstance(entry[0], (list, tuple)):
            return _position(entry[0])
        try:
            return (int(entry[1]), int(entry[2]))
        except (TypeError, ValueError):
            return (None, None)
    return (None, None)


def _field_label(qualified: str) -> str:
    """A readable label from TShark's dotted field name."""
    tail = qualified.rsplit(".", 1)[-1]
    return tail.replace("_", " ")


def _build_field(key: str, value: Any, mapping: dict[str, Any], depth: int) -> PacketField:
    """One decoded field, with any sub-fields TShark grouped beneath it."""
    text = (
        ", ".join(_text(item, 400) for item in value)
        if isinstance(value, (list, tuple))
        else _text(value)
    )
    offset, length = _position(mapping.get(f"{key}_raw"))
    # Both gates apply: the field's name, and the value's own content. The
    # second is what catches a credential repeated inside an aggregate field
    # whose name says nothing about what it carries.
    if is_sensitive_name(key):
        display, sensitive = REDACTED, True
    else:
        display, sensitive = redact_value(text)

    sub = mapping.get(f"{key}_tree")
    children = tuple(_walk_fields(sub, depth + 1)) if isinstance(sub, dict) else ()
    return PacketField(
        label=_field_label(key),
        value=display,
        name=key,
        offset=offset,
        length=length,
        sensitive=sensitive,
        children=children,
    )


def _walk_fields(mapping: dict[str, Any], depth: int = 0) -> list[PacketField]:
    """Collect a layer's decoded fields, keeping TShark's own grouping.

    TShark's JSON output holds each field twice - once decoded and once as a
    ``_raw`` span - and nests grouped fields (the bits of ``tcp.flags``, the
    parts of ``ip.dsfield``) under a matching ``_tree`` entry. Each decoded
    value is paired with its span and its ``_tree`` children, so the hierarchy
    shown is the dissector's, not one invented from the field names.
    """
    if depth > 8:  # a malformed capture must not recurse without end
        return []
    out: list[PacketField] = []
    emitted: set[str] = set()

    for key, value in mapping.items():
        if key.endswith("_raw") or key.endswith("_tree"):
            continue
        if isinstance(value, dict):
            # A bare group with no scalar of its own: keep it as a parent so
            # its children are not orphaned, with no value of its own to show.
            children = _walk_fields(value, depth + 1)
            if children:
                out.append(
                    PacketField(
                        label=_field_label(key), value="", name=key,
                        children=tuple(children),
                    )
                )
                emitted.add(key)
            continue

        field_node = _build_field(key, value, mapping, depth)
        if not field_node.value and not field_node.children:
            continue
        out.append(field_node)
        emitted.add(key)

    # A ``_tree`` whose scalar parent was absent still carries real fields;
    # without this they would be silently dropped from the decode.
    for key, value in mapping.items():
        if not key.endswith("_tree") or not isinstance(value, dict):
            continue
        base = key[: -len("_tree")]
        if base in emitted:
            continue
        children = _walk_fields(value, depth + 1)
        if children:
            out.append(
                PacketField(
                    label=_field_label(base), value="", name=base,
                    children=tuple(children),
                )
            )
    return out


def flatten_fields(fields: Iterable[PacketField]) -> tuple[PacketField, ...]:
    """Every field in a layer, parents and sub-fields alike, depth first."""
    out: list[PacketField] = []
    for entry in fields:
        out.append(entry)
        if entry.children:
            out.extend(flatten_fields(entry.children))
    return tuple(out)


def _layer_position(
    fields: tuple[PacketField, ...]
) -> tuple[int | None, int | None]:
    """The byte span a layer occupies, derived from its own fields' spans.

    Every bound is a real offset TShark reported for a real field, so this
    describes where the layer actually sits in the frame rather than assuming
    a header size.
    """
    spans = [
        (entry.offset, entry.length)
        for entry in flatten_fields(fields)
        if entry.offset is not None and entry.length is not None
    ]
    if not spans:
        return (None, None)
    start = min(offset for offset, _ in spans)
    end = max(offset + length for offset, length in spans)
    return (start, max(0, end - start))


def _layer_fields(layer: Any) -> tuple[tuple[PacketField, ...], bool]:
    """Every field TShark decoded for one layer, with secrets masked.

    Returns the fields and whether any of them were masked.
    """
    collected: list[PacketField] = []
    try:
        all_fields = getattr(layer, "_all_fields", None)
        if isinstance(all_fields, dict) and all_fields:
            collected.extend(_walk_fields(all_fields))
        else:
            # PDML fallback: this build exposes fields by name instead.
            names: Iterable[str] = list(getattr(layer, "field_names", []) or [])
            for name in names:
                if not name or name.endswith("_raw"):
                    continue
                try:
                    text = _text(layer.get_field_value(name))
                except Exception:  # noqa: BLE001 - field will not read
                    continue
                if not text:
                    continue
                qualified = f"{str(getattr(layer, 'layer_name', '')).lower()}.{name}"
                if is_sensitive_name(qualified):
                    display, sensitive = REDACTED, True
                else:
                    display, sensitive = redact_value(text)
                collected.append(
                    PacketField(
                        label=_field_label(qualified),
                        value=display,
                        name=qualified,
                        sensitive=sensitive,
                    )
                )
    except Exception:  # noqa: BLE001 - a layer that will not introspect
        LOGGER.debug("Could not read fields from a layer.", exc_info=True)

    # Stable, de-duplicated order: TShark repeats some values across trees.
    seen: set[tuple[str, str]] = set()
    unique: list[PacketField] = []
    for entry in collected:
        key = (entry.name, entry.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    # Sub-fields count too: a credential masked inside a nested group is still
    # a credential this frame carries, and the header must say so.
    return tuple(unique), any(
        entry.sensitive for entry in flatten_fields(unique)
    )


def _frame_summary(packet: Any) -> str:
    """TShark's own one-line description of the frame, when it gave one."""
    for attribute in ("_packet_string", "summary_line"):
        try:
            value = getattr(packet, attribute, None)
        except Exception:  # noqa: BLE001
            continue
        text = _text(value, limit=400)
        if text:
            return text.replace("\n", " ")
    return ""


def _stream_identity(packet: Any) -> tuple[str, int | None]:
    """The TCP/UDP stream this frame belongs to, per TShark's own index."""
    for kind in ("tcp", "udp"):
        layer = getattr(packet, kind, None)
        if layer is None:
            continue
        raw: Any = None
        all_fields = getattr(layer, "_all_fields", None)
        if isinstance(all_fields, dict):
            raw = all_fields.get(f"{kind}.stream")
        if raw is None:
            try:
                raw = layer.get_field_value("stream")
            except Exception:  # noqa: BLE001
                raw = None
        try:
            return (kind, int(str(raw)))
        except (TypeError, ValueError):
            return (kind, None)
    return ("", None)


def _raw_bytes(packet: Any) -> bytes:
    """The frame's bytes as captured, or empty when raw mode was unavailable."""
    try:
        getter = getattr(packet, "get_raw_packet", None)
        if callable(getter):
            data = getter()
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
    except Exception:  # noqa: BLE001 - capture opened without include_raw
        LOGGER.debug("Raw bytes unavailable for this frame.", exc_info=True)
    return b""


def _close_loop(loop: Any) -> None:
    """Close a decode loop, letting PyShark's transports finalise first.

    PyShark's subprocess transports close themselves when garbage collected,
    and that has to happen while the loop is still open - so the collection is
    forced and the loop given a turn to run the resulting callbacks before it
    is closed. Without this a repeated inspection leaks a loop and its pipes.
    """
    import asyncio
    import gc

    try:
        if not loop.is_closed():
            for task in asyncio.all_tasks(loop):
                task.cancel()
            loop.run_until_complete(asyncio.sleep(0))
            gc.collect()
            loop.run_until_complete(asyncio.sleep(0))
            loop.run_until_complete(loop.shutdown_asyncgens())
            gc.collect()
            loop.run_until_complete(asyncio.sleep(0))
    except Exception:  # noqa: BLE001 - best-effort drain
        LOGGER.debug("Decode loop drain raised.", exc_info=True)
    try:
        loop.close()
    except Exception:  # noqa: BLE001
        LOGGER.debug("Decode loop close raised.", exc_info=True)


@contextmanager
def _tshark_session(
    pcap_path: Path, display_filter: str, tshark_path: Path | None, *, raw: bool
) -> Iterator[Any]:
    """A FileCapture on an event loop private to the calling thread.

    PyShark drives TShark through asyncio and reaches for the running thread's
    event loop. Inspection runs on a UI worker thread, which has none - on
    Python 3.10+ asking for one there raises ``RuntimeError: There is no
    current event loop``, which is what left the inspector blank. So a loop is
    created for the decode, handed to PyShark explicitly, and torn down with
    the capture afterwards; the thread is left exactly as it was found, so a
    worker reused for the next inspection starts clean.
    """
    import asyncio
    import pyshark

    try:
        previous = asyncio.get_event_loop()
    except RuntimeError:
        # The normal case on a worker thread: no loop was ever installed.
        previous = None

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    kwargs: dict[str, Any] = {
        "input_file": str(pcap_path),
        "display_filter": display_filter,
        "keep_packets": False,
        "eventloop": loop,
    }
    if tshark_path:
        kwargs["tshark_path"] = str(tshark_path)
    if raw:
        # include_raw requires JSON output; PyShark raises otherwise.
        kwargs["use_json"] = True
        kwargs["include_raw"] = True

    capture: Any = None
    try:
        capture = pyshark.FileCapture(**kwargs)
        yield capture
    finally:
        if capture is not None:
            _close(capture)
        _close_loop(loop)
        try:
            asyncio.set_event_loop(previous)
        except Exception:  # noqa: BLE001 - thread going away
            LOGGER.debug("Could not restore the previous loop.", exc_info=True)


def load_packet_detail(
    pcap_path: str | Path,
    frame_index: int,
    *,
    tshark_path: Path | None = None,
) -> PacketDetail:
    """Read and fully decode one frame from a capture file.

    Runs TShark over the pcap restricted to a single frame number, so the cost
    is one frame's decode rather than the whole capture's. Intended to be
    called off the interface thread.

    Args:
        pcap_path: the capture file the frame was written to.
        frame_index: the frame's 1-based position in that file.
        tshark_path: explicit tshark executable, when configured.

    Returns:
        A :class:`PacketDetail`. On any failure its ``error`` explains what was
        missing; no partial or invented decode is ever returned in its place.
    """
    detail = PacketDetail(frame_index=frame_index, pcap_path=str(pcap_path))

    if not pcap_path:
        detail.error = (
            "This packet was not written to a capture file, so there is "
            "nothing to re-read. Packet inspection needs a writable capture "
            "directory (AETHRA_CAPTURE_DIR)."
        )
        return detail

    path = Path(pcap_path)
    if not path.is_file():
        detail.error = f"The capture file is no longer present:\n{path}"
        return detail
    if frame_index is None or frame_index < 1:
        detail.error = "This packet has no recorded position in the capture file."
        return detail

    display_filter = f"frame.number == {int(frame_index)}"
    try:
        try:
            with _tshark_session(path, display_filter, tshark_path, raw=True) as capture:
                packet = next(iter(capture), None)
                # Everything is extracted while the capture is open: the layer
                # objects are backed by it, and reading them afterwards would
                # be reading a closed capture.
                if packet is not None:
                    return _describe(detail, packet)
        except Exception as raw_error:  # noqa: BLE001 - raw/JSON refused here
            LOGGER.debug(
                "Raw-mode decode failed (%s); retrying without it.",
                raw_error, exc_info=True,
            )
            with _tshark_session(path, display_filter, tshark_path, raw=False) as capture:
                packet = next(iter(capture), None)
                if packet is not None:
                    # Raw bytes are unavailable in this mode; the hex tab says
                    # so rather than showing an empty dump as though the frame
                    # carried no bytes.
                    return _describe(detail, packet)

        detail.error = (
            f"Frame {frame_index} is not in {path.name}. The capture file "
            "may have been rotated or truncated since this packet was seen."
        )
        return detail
    except Exception as exc:  # noqa: BLE001 - one bad frame must not crash the UI
        LOGGER.debug("Packet inspection failed.", exc_info=True)
        detail.error = f"This frame could not be decoded: {exc}"
        return detail


def _describe(detail: PacketDetail, packet: Any) -> PacketDetail:
    """Fill in a frame's decode from an open capture's packet object.

    Called while the capture is still open, because the layer objects are
    backed by it. Everything set here is read from that packet.
    """
    layers: list[LayerNode] = []
    sensitive: list[str] = []

    # The Frame section - packet number, timestamps, captured vs original
    # length, interface and encapsulation type - lives on frame_info rather
    # than in packet.layers, so it is collected first and shown first.
    frame_info = getattr(packet, "frame_info", None)
    if frame_info is not None:
        frame_fields, frame_sensitive = _layer_fields(frame_info)
        if frame_fields:
            layers.append(
                LayerNode(name="FRAME", title=_layer_title("FRAME"), fields=frame_fields)
            )
            if frame_sensitive:
                sensitive.extend(
                    f.name for f in flatten_fields(frame_fields) if f.sensitive
                )

    for layer in getattr(packet, "layers", []) or []:
        name = str(getattr(layer, "layer_name", "") or "").upper()
        # ``*_RAW`` layers are the byte spans behind the decoded layers,
        # already used for offsets and rendered by the hex view. Showing
        # them as protocol layers would double every entry in the tree.
        if not name or name in _TREE_SKIP or name.endswith("_RAW"):
            continue
        if name == "FRAME" and any(node.name == "FRAME" for node in layers):
            continue
        fields, had_sensitive = _layer_fields(layer)
        offset, length = _layer_position(fields)
        layers.append(
            LayerNode(
                name=name,
                title=_layer_title(name),
                fields=fields,
                offset=offset,
                length=length,
                encrypted=name in _ENCRYPTED_LAYERS,
            )
        )
        if had_sensitive:
            sensitive.extend(
                f.name for f in flatten_fields(fields) if f.sensitive
            )

    if not layers:
        detail.error = (
            f"Frame {detail.frame_index} was read but TShark decoded no layers "
            "from it. The frame may be malformed or truncated."
        )
        return detail

    detail.layers = tuple(layers)
    detail.raw_bytes = _raw_bytes(packet)
    detail.summary = _frame_summary(packet)
    detail.sensitive_fields = tuple(dict.fromkeys(sensitive))
    detail.stream_kind, detail.stream_index = _stream_identity(packet)
    return detail


def _close(capture: Any) -> None:
    """Close a FileCapture without letting teardown raise into the caller."""
    try:
        capture.close()
    except Exception:  # noqa: BLE001
        LOGGER.debug("FileCapture close raised.", exc_info=True)


#: Display names for the layers a lab capture routinely carries. A layer that
#: is not listed keeps TShark's own name rather than being relabelled.
_LAYER_TITLES: dict[str, str] = {
    "FRAME": "Frame",
    "ETH": "Ethernet II",
    "IP": "Internet Protocol Version 4",
    "IPV6": "Internet Protocol Version 6",
    "ARP": "Address Resolution Protocol",
    "TCP": "Transmission Control Protocol",
    "UDP": "User Datagram Protocol",
    "ICMP": "Internet Control Message Protocol",
    "ICMPV6": "Internet Control Message Protocol v6",
    "DNS": "Domain Name System",
    "MDNS": "Multicast DNS",
    "LLMNR": "Link-Local Multicast Name Resolution",
    "HTTP": "Hypertext Transfer Protocol",
    "HTTP2": "HTTP/2",
    "TLS": "Transport Layer Security",
    "SSL": "Secure Sockets Layer",
    "QUIC": "QUIC",
    "DHCP": "Dynamic Host Configuration Protocol",
    "BOOTP": "Bootstrap Protocol / DHCP",
    "DHCPV6": "DHCPv6",
    "NBNS": "NetBIOS Name Service",
    "SMB": "SMB",
    "SMB2": "SMB2",
    "SSDP": "Simple Service Discovery Protocol",
    "NTP": "Network Time Protocol",
    "SSH": "Secure Shell",
    "TELNET": "Telnet",
    "FTP": "File Transfer Protocol",
    "SMTP": "Simple Mail Transfer Protocol",
    "SNMP": "Simple Network Management Protocol",
    "SIP": "Session Initiation Protocol",
    "DATA": "Data",
}


def _layer_title(name: str) -> str:
    """A readable layer heading; unknown layers keep TShark's own name."""
    return _LAYER_TITLES.get(name, name)


def format_hex_dump(data: bytes, *, width: int = 16) -> tuple[str, ...]:
    """Render bytes as offset / hexadecimal / ASCII lines.

    The classic three-column layout: byte offset, ``width`` hex pairs, then the
    printable ASCII for the same bytes with unprintables shown as ``.``.
    """
    if not data:
        return ()
    chunk = data[:MAX_HEX_BYTES]
    lines: list[str] = []
    for start in range(0, len(chunk), width):
        row = chunk[start : start + width]
        hex_part = " ".join(f"{byte:02x}" for byte in row)
        # Pad so the ASCII column stays aligned on a short final row.
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in row
        )
        lines.append(f"{start:04x}  {hex_part}  {ascii_part}")
    if len(data) > len(chunk):
        lines.append(f"... {len(data) - len(chunk)} further byte(s) not rendered")
    return tuple(lines)


def hex_line_span(offset: int, length: int, *, width: int = 16) -> tuple[int, int]:
    """First and last hex-dump line covering a field's bytes."""
    if offset is None or length is None or offset < 0 or length <= 0:
        return (-1, -1)
    return (offset // width, (offset + length - 1) // width)


#: Printable-run extractor for the payload preview. Finds genuine text already
#: present in the bytes; it does not decode, decrypt or transform anything.
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")


def printable_strings(data: bytes, *, limit: int = 200) -> tuple[str, ...]:
    """Readable ASCII runs already present in the captured bytes."""
    if not data:
        return ()
    found = [match.group().decode("ascii", "replace") for match in _PRINTABLE_RUN.finditer(data)]
    return tuple(found[:limit])


@dataclass(frozen=True)
class StreamPacket:
    """One frame of a followed conversation."""

    frame_index: int
    source: str
    destination: str
    length: int
    payload: bytes
    encrypted: bool = False


def follow_stream(
    pcap_path: str | Path,
    kind: str,
    index: int,
    *,
    tshark_path: Path | None = None,
    limit: int = 400,
) -> tuple[tuple[StreamPacket, ...], str]:
    """Read one TCP/UDP conversation back from the capture file.

    Uses TShark's own stream index, so the conversation is the one TShark
    reassembled rather than one guessed at from addresses and ports.

    Returns:
        ``(packets, error)``. For an encrypted conversation the payload bytes
        are returned as captured and flagged encrypted - they are never
        decrypted, and no key recovery of any kind is attempted.
    """
    if kind not in ("tcp", "udp"):
        return ((), "Only TCP and UDP conversations can be followed.")
    if index is None:
        return ((), "TShark did not assign this packet a stream index.")

    path = Path(pcap_path or "")
    if not path.is_file():
        return ((), f"The capture file is no longer present:\n{path}")

    collected: list[StreamPacket] = []
    try:
        # Same event-loop discipline as a single-frame decode: this also runs
        # on a UI worker thread, which has no loop of its own.
        with _tshark_session(
            path, f"{kind}.stream == {int(index)}", tshark_path, raw=True
        ) as capture:
            for position, packet in enumerate(capture):
                if position >= limit:
                    break
                layer = getattr(packet, kind, None)
                payload = b""
                if layer is not None:
                    for attribute in ("payload", "segment_data"):
                        raw = _read_field(layer, f"{kind}.{attribute}", attribute)
                        if raw:
                            payload = _hex_string_to_bytes(
                                ", ".join(str(item) for item in raw)
                                if isinstance(raw, (list, tuple))
                                else str(raw)
                            )
                            if payload:
                                break
                layer_names = {
                    str(getattr(entry, "layer_name", "")).upper()
                    for entry in getattr(packet, "layers", []) or []
                }
                collected.append(
                    StreamPacket(
                        frame_index=_int_or(getattr(packet, "number", None), position + 1),
                        source=_endpoint(packet, "src"),
                        destination=_endpoint(packet, "dst"),
                        length=len(payload),
                        payload=payload,
                        encrypted=bool(layer_names & _ENCRYPTED_LAYERS),
                    )
                )
        if not collected:
            return ((), f"No frames of {kind.upper()} stream {index} are in this capture file.")
        return (tuple(collected), "")
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("Follow stream failed.", exc_info=True)
        return ((), f"The conversation could not be read: {exc}")


def _int_or(value: Any, fallback: int) -> int:
    """Best-effort int, falling back to a known-good value."""
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return fallback


def _read_field(layer: Any, qualified: str, short: str) -> Any:
    """Read one field from a layer in either JSON or PDML form."""
    if layer is None:
        return None
    all_fields = getattr(layer, "_all_fields", None)
    if isinstance(all_fields, dict):
        value = all_fields.get(qualified)
        if value is not None:
            return value
    try:
        return layer.get_field_value(short)
    except Exception:  # noqa: BLE001 - field absent from this dissector
        return None


def _endpoint(packet: Any, side: str) -> str:
    """The frame's address for one side, or the honest absence marker."""
    for layer_name in ("ip", "ipv6", "eth"):
        layer = getattr(packet, layer_name, None)
        if layer is None:
            continue
        text = _text(_read_field(layer, f"{layer_name}.{side}", side), limit=64)
        if text:
            return text
    return NOT_AVAILABLE


def _hex_string_to_bytes(raw: str) -> bytes:
    """Decode TShark's ``aa:bb:cc`` / ``aabbcc`` payload rendering."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw or "")
    if not cleaned or len(cleaned) % 2:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""
