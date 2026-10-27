"""Display filters over packets AETHRA-SEC actually captured.

Two filters exist in the Live Monitoring workflow, and they are different
things:

* a **capture filter** (BPF, e.g. ``tcp port 80``) is compiled by libpcap and
  applied by dumpcap before a frame is captured. What it excludes is never
  seen, never analysed and never stored, and changing it restarts capture.
* a **display filter** (this module, e.g. ``http && direction == incoming``) is
  applied to packets that have already been captured and decoded. It decides
  what the packet table shows. It never reaches TShark, never restarts capture,
  and never removes a packet from analysis, detection or storage.

The syntax follows Wireshark's display-filter language closely enough that an
analyst's habits carry over - ``ip.addr == 10.0.0.5``, ``tcp.port == 443``,
``dns || icmp``, ``!arp`` - over the fields the live pipeline extracts. It is
deliberately a subset: a field TShark knows but live capture does not extract
is refused with a message saying so, rather than silently matching nothing.

Safety
------
The expression is tokenised and parsed here, by a small recursive-descent
parser, into a tree of Python closures. It is never passed to ``eval``, never
compiled as Python, never interpolated into a shell command and never handed to
TShark. Length, token count and nesting depth are bounded, so a pathological
expression is refused rather than tying up a thread.

Semantics worth stating
-----------------------
* ``a == b`` is true when *any* value of ``a`` equals ``b``, so ``ip.addr``
  matches either endpoint, as in Wireshark.
* ``a != b`` means ``!(a == b)``, the meaning Wireshark gave it in 3.6.
* A comparison on a field the packet does not carry is false.
  ``tcp.port == 80`` never matches a UDP packet.
* Protocol names (``http``, ``tls``, ``dns``...) test the protocol chain TShark
  reported for the frame (``frame.protocols``). Nothing is inferred from a port:
  TCP to port 443 is not TLS unless TShark decoded TLS, and port 80 is not HTTP
  unless TShark decoded HTTP.
* ``http.*`` fields are scoped to frames whose protocol chain contains HTTP.
  SSDP (UPnP discovery) reuses HTTP message syntax and TShark fills ``http.*``
  for it; scoping keeps multicast discovery from being reported as web traffic.
  ``dns.*`` fields are scoped to DNS, mDNS and LLMNR, which all carry them.
* ``direction`` is an AETHRA-SEC field, not a Wireshark one. It holds the
  packet's relationship to the capture interface - ``incoming``, ``outgoing``,
  ``transit``, ``broadcast``, ``local`` or ``unknown`` - as decided by
  :mod:`aethra_sec.analytics.traffic_direction` from the interface's own
  addresses.
"""

from __future__ import annotations

import difflib
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Callable

from aethra_sec.models.traffic import tls_layer_in_chain

#: Longest expression accepted.
MAX_EXPRESSION_LENGTH = 512

#: Most tokens accepted in one expression.
MAX_TOKENS = 256

#: Deepest nesting of parentheses and negations accepted.
MAX_DEPTH = 32

#: Shown whenever an HTTPS/TLS view is active. Worded to make no claim about
#: content AETHRA-SEC cannot see.
HTTPS_NOTICE = (
    "HTTPS traffic is encrypted. AETHRA-SEC displays available TLS/network "
    "metadata but does not claim access to encrypted HTTP content."
)

#: Shown when a view that depends on seeing other devices' traffic is empty.
NOT_VISIBLE_NOTICE = (
    "Traffic is not visible from the current capture interface. On a switched "
    "or wireless network an adapter receives its own traffic plus broadcast "
    "and multicast; traffic between two other devices reaches it only through "
    "a switch mirror (SPAN) port, a network TAP, or when AETHRA-SEC sits in the "
    "traffic path. Nothing was filtered out - it was never delivered here."
)

Predicate = Callable[[Any], bool]


class FilterSyntaxError(ValueError):
    """An expression that cannot be used, with a message safe to display."""

    def __init__(self, message: str, position: int | None = None) -> None:
        """Record the message and, when known, where in the text it applies."""
        super().__init__(message)
        self.message = message
        self.position = position


@dataclass(frozen=True)
class CompiledFilter:
    """A validated expression, ready to test packets.

    ``predicate`` is ``None`` for the empty expression, which matches every
    packet - "all traffic" is the absence of a filter, not a filter that
    happens to match everything.
    """

    expression: str = ""
    predicate: Predicate | None = None
    fields: frozenset[str] = frozenset()

    @property
    def matches_everything(self) -> bool:
        """True for the empty filter."""
        return self.predicate is None

    def matches(self, packet: Any) -> bool:
        """Test one packet. Never raises."""
        if self.predicate is None:
            return True
        try:
            return bool(self.predicate(packet))
        except Exception:  # noqa: BLE001 - an odd packet must not break the view
            return False


MATCH_ALL = CompiledFilter()


# ---------------------------------------------------------------------------
# Fields
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FieldSpec:
    """One field the filter language can test.

    ``extract`` returns every value the packet carries for the field - an empty
    tuple when it carries none - so ``ip.addr`` can return both endpoints.
    """

    name: str
    kind: str
    extract: Callable[[Any], tuple[Any, ...]]
    description: str = ""


def _layers(packet: Any) -> tuple[str, ...]:
    return getattr(packet, "layers", ()) or ()


def _has_layer(packet: Any, names: tuple[str, ...]) -> bool:
    present = _layers(packet)
    return any(name in present for name in names)


def _present(value: Any) -> bool:
    return value is not None and value != ""


def _ip_field(attribute: str, version: int) -> Callable[[Any], tuple[Any, ...]]:
    def extract(packet: Any) -> tuple[Any, ...]:
        if getattr(packet, "ip_version", None) != version:
            return ()
        value = getattr(packet, attribute, "")
        return (value,) if value else ()

    return extract


def _ip_pair(version: int) -> Callable[[Any], tuple[Any, ...]]:
    source = _ip_field("src_ip", version)
    destination = _ip_field("dst_ip", version)
    return lambda packet: source(packet) + destination(packet)


def _transport_field(transport: str, attribute: str) -> Callable[[Any], tuple[Any, ...]]:
    def extract(packet: Any) -> tuple[Any, ...]:
        if getattr(packet, "transport", "") != transport:
            return ()
        value = getattr(packet, attribute, None)
        return (value,) if value is not None else ()

    return extract


def _transport_pair(transport: str) -> Callable[[Any], tuple[Any, ...]]:
    source = _transport_field(transport, "src_port")
    destination = _transport_field(transport, "dst_port")
    return lambda packet: source(packet) + destination(packet)


def _tcp_flag(bit: int) -> Callable[[Any], tuple[Any, ...]]:
    def extract(packet: Any) -> tuple[Any, ...]:
        flags = getattr(packet, "tcp_flags", None)
        if getattr(packet, "transport", "") != "TCP" or flags is None:
            return ()
        return (1 if flags & bit else 0,)

    return extract


def _scoped(layers: tuple[str, ...], attribute: str) -> Callable[[Any], tuple[Any, ...]]:
    """A field that exists only when one of ``layers`` was decoded."""

    def extract(packet: Any) -> tuple[Any, ...]:
        if not _has_layer(packet, layers):
            return ()
        value = getattr(packet, attribute, None)
        return (value,) if _present(value) else ()

    return extract


def _mac_field(attribute: str) -> Callable[[Any], tuple[Any, ...]]:
    def extract(packet: Any) -> tuple[Any, ...]:
        value = getattr(packet, attribute, "")
        return (value,) if value else ()

    return extract


def _presence(test: Callable[[Any], bool]) -> Callable[[Any], tuple[Any, ...]]:
    return lambda packet: (True,) if test(packet) else ()


_HTTP = ("HTTP",)
_TLS = ("TLS", "SSL")
_DNS_FAMILY = ("DNS", "MDNS", "LLMNR")
_ARP = ("ARP",)
_ICMP = ("ICMP",)
_ICMPV6 = ("ICMPV6",)


def _tls_column(packet: Any) -> bool:
    """True when TShark's Protocol column was written by its TLS dissector.

    A TCP segment carrying part of a TLS record, or a one-byte keep-alive on a
    TLS connection, is handled by the TLS dissector: TShark's own ``tls``
    filter matches it and the column reads SSL or TLSv1.x. The frame's protocol
    chain does not list TLS, because no complete record was decoded in that
    frame. Measured on a live capture, relying on the chain alone missed 8 of
    185 frames TShark's filter matched. This is still TShark's decode - DTLS,
    a different dissector, is not accepted, and a port number never is.
    """
    column = (getattr(packet, "protocol", "") or "").upper()
    return column == "SSL" or column.startswith("TLSV")


def tls_present(packet: Any) -> bool:
    """True when TShark identified TLS in this frame.

    The chain decides, less a TLS entry directly under DNS: TShark's DNS
    dissector parses the ECH setting of an HTTPS record with its TLS code, and
    its own ``tls`` filter does not match that frame (found by the live
    cross-check). Otherwise as :func:`_tls_column` describes.
    """
    return tls_layer_in_chain(_layers(packet)) or _tls_column(packet)


def _direction(packet: Any) -> tuple[Any, ...]:
    return ((getattr(packet, "direction", "") or "UNKNOWN").lower(),)


_FIELD_LIST: tuple[FieldSpec, ...] = (
    FieldSpec("frame.number", "uint", lambda p: (p.number,) if p.number is not None else (), "frame number"),
    FieldSpec("frame.len", "uint", lambda p: (p.length,) if p.length else (), "frame length in bytes"),
    FieldSpec("eth.src", "mac", _mac_field("src_mac"), "source MAC"),
    FieldSpec("eth.dst", "mac", _mac_field("dst_mac"), "destination MAC"),
    FieldSpec("eth.addr", "mac", lambda p: _mac_field("src_mac")(p) + _mac_field("dst_mac")(p), "either MAC"),
    FieldSpec("ip.src", "ipv4", _ip_field("src_ip", 4), "IPv4 source"),
    FieldSpec("ip.dst", "ipv4", _ip_field("dst_ip", 4), "IPv4 destination"),
    FieldSpec("ip.addr", "ipv4", _ip_pair(4), "either IPv4 endpoint"),
    FieldSpec("ip.ttl", "uint", lambda p: (p.ttl,) if p.ip_version == 4 and p.ttl is not None else (), "IPv4 TTL"),
    FieldSpec("ipv6.src", "ipv6", _ip_field("src_ip", 6), "IPv6 source"),
    FieldSpec("ipv6.dst", "ipv6", _ip_field("dst_ip", 6), "IPv6 destination"),
    FieldSpec("ipv6.addr", "ipv6", _ip_pair(6), "either IPv6 endpoint"),
    FieldSpec("tcp.srcport", "uint", _transport_field("TCP", "src_port"), "TCP source port"),
    FieldSpec("tcp.dstport", "uint", _transport_field("TCP", "dst_port"), "TCP destination port"),
    FieldSpec("tcp.port", "uint", _transport_pair("TCP"), "either TCP port"),
    FieldSpec("tcp.flags", "uint", lambda p: (p.tcp_flags,) if p.transport == "TCP" and p.tcp_flags is not None else (), "TCP flags"),
    FieldSpec("tcp.flags.fin", "bool", _tcp_flag(0x01), "TCP FIN"),
    FieldSpec("tcp.flags.syn", "bool", _tcp_flag(0x02), "TCP SYN"),
    FieldSpec("tcp.flags.reset", "bool", _tcp_flag(0x04), "TCP RST"),
    FieldSpec("tcp.flags.push", "bool", _tcp_flag(0x08), "TCP PSH"),
    FieldSpec("tcp.flags.ack", "bool", _tcp_flag(0x10), "TCP ACK flag"),
    FieldSpec("tcp.flags.urg", "bool", _tcp_flag(0x20), "TCP URG"),
    FieldSpec("tcp.seq", "uint", _transport_field("TCP", "tcp_seq"), "TCP sequence number (relative)"),
    FieldSpec("tcp.ack", "uint", _transport_field("TCP", "tcp_ack"), "TCP acknowledgement number (relative)"),
    FieldSpec("udp.srcport", "uint", _transport_field("UDP", "src_port"), "UDP source port"),
    FieldSpec("udp.dstport", "uint", _transport_field("UDP", "dst_port"), "UDP destination port"),
    FieldSpec("udp.port", "uint", _transport_pair("UDP"), "either UDP port"),
    FieldSpec("arp.opcode", "uint", _scoped(_ARP, "arp_opcode"), "ARP opcode (1 request, 2 reply)"),
    FieldSpec("arp.src.proto_ipv4", "ipv4", _scoped(_ARP, "src_ip"), "ARP sender IP"),
    FieldSpec("arp.dst.proto_ipv4", "ipv4", _scoped(_ARP, "dst_ip"), "ARP target IP"),
    FieldSpec("arp.src.hw_mac", "mac", _scoped(_ARP, "arp_sender_mac"), "ARP sender MAC"),
    FieldSpec("arp.dst.hw_mac", "mac", _scoped(_ARP, "arp_target_mac"), "ARP target MAC"),
    FieldSpec("icmp.type", "uint", _scoped(_ICMP, "icmp_type"), "ICMP type"),
    FieldSpec("icmp.code", "uint", _scoped(_ICMP, "icmp_code"), "ICMP code"),
    FieldSpec("icmpv6.type", "uint", _scoped(_ICMPV6, "icmp_type"), "ICMPv6 type"),
    FieldSpec("icmpv6.code", "uint", _scoped(_ICMPV6, "icmp_code"), "ICMPv6 code"),
    FieldSpec("dns.qry.name", "text", _scoped(_DNS_FAMILY, "dns_query"), "DNS query name"),
    FieldSpec("dns.flags.response", "bool", _scoped(_DNS_FAMILY, "dns_response"), "DNS response flag"),
    FieldSpec("http.request", "presence", _presence(lambda p: _has_layer(p, _HTTP) and bool(p.http_method)), "HTTP request"),
    FieldSpec("http.response", "presence", _presence(lambda p: _has_layer(p, _HTTP) and p.http_status is not None), "HTTP response"),
    FieldSpec("http.request.method", "text", _scoped(_HTTP, "http_method"), "HTTP method"),
    FieldSpec("http.request.uri", "text", _scoped(_HTTP, "http_uri"), "HTTP request URI"),
    FieldSpec("http.host", "text", _scoped(_HTTP, "http_host"), "HTTP Host header"),
    FieldSpec("http.request.version", "text", lambda p: _scoped(_HTTP, "http_version")(p) if p.http_method else (), "HTTP request version"),
    FieldSpec("http.response.version", "text", lambda p: _scoped(_HTTP, "http_version")(p) if p.http_status is not None else (), "HTTP response version"),
    FieldSpec("http.response.code", "uint", _scoped(_HTTP, "http_status"), "HTTP status code"),
    FieldSpec("http.response.phrase", "text", _scoped(_HTTP, "http_phrase"), "HTTP status phrase"),
    FieldSpec("tls.handshake.type", "uint", _scoped(_TLS, "tls_handshake_type"), "TLS handshake type (1 Client Hello, 2 Server Hello)"),
    FieldSpec("tls.handshake.extensions_server_name", "text", _scoped(_TLS, "tls_sni"), "TLS SNI server name"),
    FieldSpec("tls.record.version", "uint", _scoped(_TLS, "tls_record_version"), "TLS record-layer version"),
    FieldSpec("tls.handshake.version", "uint", _scoped(_TLS, "tls_handshake_version"), "TLS handshake legacy version"),
    FieldSpec("tls.handshake.extensions.supported_version", "uint", _scoped(_TLS, "tls_supported_version"), "TLS supported_versions extension (first value)"),
    FieldSpec("direction", "direction", _direction, "AETHRA-SEC: incoming, outgoing, transit, broadcast, local, unknown"),
)

FIELDS: dict[str, FieldSpec] = {spec.name: spec for spec in _FIELD_LIST}

#: Protocol names testable on their own, mapped to the layer names TShark puts
#: in ``frame.protocols`` (upper-cased by the decoder).
PROTOCOLS: dict[str, tuple[str, ...]] = {
    "eth": ("ETH",),
    "vlan": ("VLAN",),
    "arp": _ARP,
    "ip": ("IP",),
    "ipv6": ("IPV6",),
    "icmp": _ICMP,
    "icmpv6": _ICMPV6,
    "igmp": ("IGMP",),
    "tcp": ("TCP",),
    "udp": ("UDP",),
    "dns": ("DNS",),
    "mdns": ("MDNS",),
    "llmnr": ("LLMNR",),
    "nbns": ("NBNS",),
    "http": _HTTP,
    "tls": _TLS,
    "ssl": _TLS,
    "quic": ("QUIC",),
    "dhcp": ("DHCP", "BOOTP"),
    "bootp": ("DHCP", "BOOTP"),
    "dhcpv6": ("DHCPV6",),
    "ntp": ("NTP",),
    "ssdp": ("SSDP",),
    "ssh": ("SSH",),
    "ftp": ("FTP",),
    "telnet": ("TELNET",),
    "smtp": ("SMTP",),
    "snmp": ("SNMP",),
    "smb": ("SMB",),
    "smb2": ("SMB2",),
    "rdp": ("RDP",),
    "data": ("DATA",),
}

DIRECTION_VALUES: frozenset[str] = frozenset(
    {"incoming", "outgoing", "transit", "broadcast", "local", "unknown"}
)


def available_fields() -> tuple[str, ...]:
    """Every field name the language accepts, for help text."""
    return tuple(FIELDS)


def available_protocols() -> tuple[str, ...]:
    """Every protocol name the language accepts on its own."""
    return tuple(PROTOCOLS)


def protocol_present(packet: Any, name: str) -> bool:
    """Whether TShark identified protocol ``name`` in a packet.

    The protocol chain decides, with one addition for TLS - see
    :func:`_tls_column`. Shared by the filter language and the protocol
    statistics, so a count and a filter can never disagree about a packet.
    """
    if name in ("tls", "ssl"):
        return tls_present(packet)
    wanted = PROTOCOLS.get(name)
    return bool(wanted) and _has_layer(packet, wanted)


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------
_WORD_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:/-"
)
_KEYWORDS: dict[str, str] = {
    "and": "&&", "or": "||", "not": "!",
    "eq": "==", "ne": "!=", "gt": ">", "lt": "<", "ge": ">=", "le": "<=",
    "contains": "contains",
}
_COMPARISONS = frozenset({"==", "!=", ">", "<", ">=", "<=", "contains"})


@dataclass(frozen=True)
class _Token:
    kind: str  # "op", "word", "string", "lparen", "rparen"
    text: str
    position: int


def _tokenise(text: str) -> list[_Token]:
    """Split an expression into tokens, refusing anything unrecognised."""
    tokens: list[_Token] = []
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        if character.isspace():
            index += 1
            continue
        start = index
        if character == "(":
            tokens.append(_Token("lparen", "(", start))
            index += 1
        elif character == ")":
            tokens.append(_Token("rparen", ")", start))
            index += 1
        elif text.startswith("&&", index) or text.startswith("||", index):
            tokens.append(_Token("op", text[index:index + 2], start))
            index += 2
        elif character in "&|":
            raise FilterSyntaxError(
                f"'{character}' on its own is not an operator. Use '{character * 2}'.",
                start,
            )
        elif character in "=!<>":
            pair = text[index:index + 2]
            if pair in ("==", "!=", ">=", "<="):
                if text[index + 2:index + 3] == "=":
                    raise FilterSyntaxError(
                        f"'{pair}=' is not an operator. Use '{pair}'.", start
                    )
                tokens.append(_Token("op", pair, start))
                index += 2
            elif character == "=":
                raise FilterSyntaxError(
                    "A single '=' is not an operator. Use '==' to compare.", start
                )
            else:
                tokens.append(_Token("op", character, start))
                index += 1
        elif character == '"':
            index += 1
            collected: list[str] = []
            while index < length and text[index] != '"':
                if text[index] == "\\" and index + 1 < length and text[index + 1] in '"\\':
                    collected.append(text[index + 1])
                    index += 2
                    continue
                collected.append(text[index])
                index += 1
            if index >= length:
                raise FilterSyntaxError(
                    "A quoted value is missing its closing quote.", start
                )
            index += 1
            tokens.append(_Token("string", "".join(collected), start))
        elif character in _WORD_CHARACTERS:
            while index < length and text[index] in _WORD_CHARACTERS:
                index += 1
            word = text[start:index]
            keyword = _KEYWORDS.get(word.lower())
            tokens.append(
                _Token("op", keyword, start) if keyword else _Token("word", word, start)
            )
        else:
            raise FilterSyntaxError(
                f"Unexpected character '{character}' at position {start + 1}.", start
            )
        if len(tokens) > MAX_TOKENS:
            raise FilterSyntaxError(
                f"The filter is too long to evaluate (more than {MAX_TOKENS} parts).",
                start,
            )
    return tokens


# ---------------------------------------------------------------------------
# Value parsing
# ---------------------------------------------------------------------------
def _unknown_name_message(name: str) -> str:
    candidates = list(FIELDS) + list(PROTOCOLS)
    close = difflib.get_close_matches(name.lower(), candidates, n=2, cutoff=0.75)
    if close:
        return f"Unknown field '{name}'. Did you mean {' or '.join(close)}?"
    return (
        f"Unknown field '{name}'. Live display filters support protocols such as "
        "tcp, udp, icmp, arp, dns, http and tls, and fields such as ip.src, "
        "ip.dst, ip.addr, tcp.port, udp.port, http.host and direction."
    )


def _address_test(kind: str, raw: str, field_name: str, position: int) -> Callable[[Any], bool]:
    version = 4 if kind == "ipv4" else 6
    text = raw.strip()
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise FilterSyntaxError(
                f"'{text}' is not a valid IPv{version} network for {field_name}.",
                position,
            ) from None
        if network.version != version:
            raise FilterSyntaxError(
                f"{field_name} holds IPv{version} addresses; '{text}' is IPv{network.version}.",
                position,
            )

        def in_network(value: Any, net: Any = network) -> bool:
            try:
                return ipaddress.ip_address(str(value)) in net
            except ValueError:
                return False

        return in_network

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise FilterSyntaxError(
            f"'{text}' is not a valid IPv{version} address for {field_name}.", position
        ) from None
    if address.version != version:
        raise FilterSyntaxError(
            f"{field_name} holds IPv{version} addresses; '{text}' is IPv{address.version}.",
            position,
        )
    canonical = address.compressed

    def equal(value: Any, expected: str = canonical) -> bool:
        text_value = str(value)
        if text_value == expected:
            return True
        # TShark emits canonical text, so this is the rare path.
        try:
            return ipaddress.ip_address(text_value).compressed == expected
        except ValueError:
            return False

    return equal


def _parse_mac(raw: str, field_name: str, position: int) -> str:
    text = raw.strip().lower().replace("-", ":")
    parts = text.split(":")
    if len(parts) != 6 or not all(len(part) == 2 for part in parts):
        raise FilterSyntaxError(f"'{raw}' is not a valid MAC address for {field_name}.", position)
    try:
        for part in parts:
            int(part, 16)
    except ValueError:
        raise FilterSyntaxError(f"'{raw}' is not a valid MAC address for {field_name}.", position) from None
    return text


def _parse_uint(raw: str, field_name: str, position: int) -> int:
    text = raw.strip().lower()
    try:
        value = int(text, 16) if text.startswith("0x") else int(text, 10)
    except ValueError:
        raise FilterSyntaxError(f"'{raw}' is not a number for {field_name}.", position) from None
    if value < 0 or value >= 1 << 64:
        raise FilterSyntaxError(f"'{raw}' is out of range for {field_name}.", position)
    return value


def _parse_bool(raw: str, field_name: str, position: int) -> bool:
    text = raw.strip().lower()
    if text in ("1", "true"):
        return True
    if text in ("0", "false"):
        return False
    raise FilterSyntaxError(
        f"{field_name} is true or false; use 1, 0, true or false, not '{raw}'.", position
    )


_ORDERING: dict[str, Callable[[Any, Any], bool]] = {
    "==": lambda value, expected: value == expected,
    ">": lambda value, expected: value > expected,
    "<": lambda value, expected: value < expected,
    ">=": lambda value, expected: value >= expected,
    "<=": lambda value, expected: value <= expected,
}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
@dataclass
class _Parser:
    tokens: list[_Token]
    text: str
    index: int = 0
    referenced: set[str] = field(default_factory=set)

    def _peek(self) -> _Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self) -> _Token | None:
        token = self._peek()
        self.index += 1
        return token

    def _is_op(self, token: _Token | None, text: str) -> bool:
        return token is not None and token.kind == "op" and token.text == text

    def parse(self) -> Predicate:
        predicate = self._or(0)
        leftover = self._peek()
        if leftover is not None:
            if leftover.kind == "rparen":
                raise FilterSyntaxError(
                    "There is a ')' without a matching '('.", leftover.position
                )
            raise FilterSyntaxError(
                f"Unexpected '{leftover.text}' after a complete condition. "
                "Join conditions with && or ||.",
                leftover.position,
            )
        return predicate

    def _or(self, depth: int) -> Predicate:
        left = self._and(depth)
        while self._is_op(self._peek(), "||"):
            self._take()
            right = self._and(depth)
            left = lambda packet, a=left, b=right: a(packet) or b(packet)  # noqa: E731
        return left

    def _and(self, depth: int) -> Predicate:
        left = self._not(depth)
        while self._is_op(self._peek(), "&&"):
            self._take()
            right = self._not(depth)
            left = lambda packet, a=left, b=right: a(packet) and b(packet)  # noqa: E731
        return left

    def _not(self, depth: int) -> Predicate:
        if depth > MAX_DEPTH:
            raise FilterSyntaxError("The filter is nested too deeply.")
        token = self._peek()
        if self._is_op(token, "!"):
            self._take()
            if self._peek() is None:
                raise FilterSyntaxError(
                    "'!' must be followed by a condition.", token.position if token else None
                )
            inner = self._not(depth + 1)
            return lambda packet, f=inner: not f(packet)
        return self._primary(depth)

    def _primary(self, depth: int) -> Predicate:
        token = self._take()
        if token is None:
            raise FilterSyntaxError(
                "The filter ends where a condition was expected.", len(self.text)
            )
        if token.kind == "lparen":
            if depth + 1 > MAX_DEPTH:
                raise FilterSyntaxError("The filter is nested too deeply.", token.position)
            inner = self._or(depth + 1)
            closing = self._take()
            if closing is None or closing.kind != "rparen":
                raise FilterSyntaxError(
                    "A '(' is missing its closing ')'.", token.position
                )
            return inner
        if token.kind == "rparen":
            raise FilterSyntaxError(
                "There is a ')' without a matching '('.", token.position
            )
        if token.kind == "op":
            if token.text in ("&&", "||"):
                raise FilterSyntaxError(
                    f"'{token.text}' needs a condition on both sides.", token.position
                )
            raise FilterSyntaxError(
                f"'{token.text}' needs a field before it, for example ip.src {token.text} ...",
                token.position,
            )
        if token.kind == "string":
            raise FilterSyntaxError(
                "A quoted value must follow a field and an operator, for example "
                f'http.host == "{token.text}".',
                token.position,
            )

        operator = self._peek()
        if operator is not None and operator.kind == "op" and operator.text in _COMPARISONS:
            self._take()
            value = self._take()
            if value is None or value.kind not in ("word", "string"):
                raise FilterSyntaxError(
                    f"'{token.text} {operator.text}' needs a value to compare with.",
                    operator.position,
                )
            return self._comparison(token, operator, value)
        return self._presence(token)

    def _presence(self, token: _Token) -> Predicate:
        name = token.text.lower()
        if name in PROTOCOLS:
            self.referenced.add(name)
            return lambda packet, wanted=name: protocol_present(packet, wanted)
        spec = FIELDS.get(name)
        if spec is not None:
            if spec.kind == "direction":
                raise FilterSyntaxError(
                    "direction needs a value, for example: direction == incoming",
                    token.position,
                )
            self.referenced.add(spec.name)
            return lambda packet, extract=spec.extract: bool(extract(packet))
        if _looks_like_value(token.text):
            raise FilterSyntaxError(
                f"'{token.text}' needs a field, for example ip.addr == {token.text}",
                token.position,
            )
        raise FilterSyntaxError(_unknown_name_message(token.text), token.position)

    def _comparison(self, name_token: _Token, operator: _Token, value: _Token) -> Predicate:
        name = name_token.text.lower()
        spec = FIELDS.get(name)
        if spec is None:
            if name in PROTOCOLS:
                raise FilterSyntaxError(
                    f"'{name_token.text}' is a protocol, not a field with a value. "
                    f"Use it on its own, for example: {name}",
                    name_token.position,
                )
            raise FilterSyntaxError(_unknown_name_message(name_token.text), name_token.position)
        self.referenced.add(spec.name)

        op = operator.text
        raw = value.text
        negate = op == "!="
        base = "==" if negate else op
        kind = spec.kind

        if kind == "presence":
            raise FilterSyntaxError(
                f"{spec.name} is a presence test. Use it on its own: {spec.name}",
                name_token.position,
            )
        if base == "contains" and kind != "text":
            raise FilterSyntaxError(
                f"'contains' works on text fields such as http.host, not on {spec.name}.",
                operator.position,
            )
        if kind in ("ipv4", "ipv6", "mac", "bool", "direction") and base != "==":
            raise FilterSyntaxError(
                f"'{op}' cannot be used with {spec.name}. Use == or !=.", operator.position
            )
        if kind == "text" and base not in ("==", "contains"):
            raise FilterSyntaxError(
                f"'{op}' cannot be used with {spec.name}. Use ==, != or contains.",
                operator.position,
            )

        if kind in ("ipv4", "ipv6"):
            test = _address_test(kind, raw, spec.name, value.position)
        elif kind == "mac":
            expected_mac = _parse_mac(raw, spec.name, value.position)
            test = lambda v, e=expected_mac: str(v).lower().replace("-", ":") == e  # noqa: E731
        elif kind == "uint":
            number = _parse_uint(raw, spec.name, value.position)
            compare = _ORDERING[base]
            test = lambda v, n=number, c=compare: isinstance(v, int) and c(v, n)  # noqa: E731
        elif kind == "bool":
            flag = _parse_bool(raw, spec.name, value.position)
            test = lambda v, f=flag: bool(v) is f  # noqa: E731
        elif kind == "direction":
            wanted = raw.strip().lower()
            if wanted not in DIRECTION_VALUES:
                raise FilterSyntaxError(
                    f"'{raw}' is not a direction. Use one of: "
                    + ", ".join(sorted(DIRECTION_VALUES)) + ".",
                    value.position,
                )
            test = lambda v, w=wanted: v == w  # noqa: E731
        else:  # text
            if base == "contains":
                test = lambda v, needle=raw: needle in str(v)  # noqa: E731
            else:
                test = lambda v, expected=raw: str(v) == expected  # noqa: E731

        def predicate(packet: Any, extract: Any = spec.extract, check: Any = test) -> bool:
            return any(check(item) for item in extract(packet))

        if negate:
            return lambda packet, f=predicate: not f(packet)
        return predicate


def _looks_like_value(text: str) -> bool:
    """True for a bare address or number typed without a field."""
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass
    return text.isdigit()


def compile_filter(text: str | None) -> CompiledFilter:
    """Validate and compile an expression.

    Raises:
        FilterSyntaxError: with a message safe to display, when the expression
            cannot be used. Nothing is partially applied.
    """
    expression = (text or "").strip()
    if not expression:
        return MATCH_ALL
    if len(expression) > MAX_EXPRESSION_LENGTH:
        raise FilterSyntaxError(
            f"The filter is too long (the limit is {MAX_EXPRESSION_LENGTH} characters)."
        )
    tokens = _tokenise(expression)
    if not tokens:
        return MATCH_ALL
    parser = _Parser(tokens, expression)
    predicate = parser.parse()
    return CompiledFilter(
        expression=expression,
        predicate=predicate,
        fields=frozenset(parser.referenced),
    )


def validate_filter(text: str | None) -> tuple[CompiledFilter | None, str]:
    """``(compiled, "")`` for a usable expression, ``(None, reason)`` otherwise."""
    try:
        return compile_filter(text), ""
    except FilterSyntaxError as exc:
        return None, exc.message


# ---------------------------------------------------------------------------
# Presets and composition
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Preset:
    """A named view that is exactly one display-filter expression."""

    key: str
    label: str
    expression: str
    empty_text: str
    encrypted: bool = False


DIRECTION_PRESETS: tuple[Preset, ...] = (
    Preset("INCOMING", "Incoming", "direction == incoming", "No incoming traffic captured."),
    Preset("OUTGOING", "Outgoing", "direction == outgoing", "No outgoing traffic captured."),
    Preset("TRANSIT", "Transit", "direction == transit", "No transit traffic captured."),
)

PROTOCOL_PRESETS: tuple[Preset, ...] = (
    Preset("HTTP", "HTTP", "http", "No HTTP traffic captured."),
    Preset("HTTPS", "HTTPS/TLS", "tls", "No HTTPS/TLS traffic captured.", encrypted=True),
    # "WEB" ("http || tls") was removed with its button. HTTP and HTTPS/TLS
    # remain, and either expression can still be typed into the display filter
    # box, so nothing became unreachable - only the preset that duplicated two
    # of its neighbours went.
    # The names this computer connected to or looked up, each from a decoded
    # field: the server name in a TLS handshake (SNI), the Host header of an
    # HTTP request, and the name in a DNS query. DNS responses repeat the
    # question, mDNS and LLMNR are local service discovery, and reverse lookups
    # (.arpa) name addresses rather than sites, so none of those is listed.
    Preset(
        "SITES", "Sites",
        "tls.handshake.extensions_server_name || http.host || "
        '(dns && dns.qry.name && dns.flags.response == 0 && !(dns.qry.name contains ".arpa"))',
        "No site names captured (HTTPS server names, HTTP hosts or DNS lookups).",
        encrypted=True,
    ),
    Preset("TCP", "TCP", "tcp", "No TCP traffic captured."),
    Preset("UDP", "UDP", "udp", "No UDP traffic captured."),
    Preset("ICMP", "ICMP", "icmp || icmpv6", "No ICMP traffic captured."),
    Preset("DNS", "DNS", "dns", "No DNS traffic captured."),
    Preset("ARP", "ARP", "arp", "No ARP traffic captured."),
)

DIRECTION_BY_KEY: dict[str, Preset] = {preset.key: preset for preset in DIRECTION_PRESETS}
PROTOCOL_BY_KEY: dict[str, Preset] = {preset.key: preset for preset in PROTOCOL_PRESETS}

#: Where an IP or port search applies.
SCOPES: tuple[str, ...] = ("either", "source", "destination")

ALL_TRAFFIC_LABEL = "All traffic"


@dataclass(frozen=True)
class FilterRequest:
    """What the operator asked for, before it is validated."""

    direction: str = ""
    protocol: str = ""
    ip: str = ""
    ip_scope: str = "either"
    port: str = ""
    port_scope: str = "either"
    expression: str = ""

    @property
    def is_empty(self) -> bool:
        """True when nothing narrows the view."""
        return not (
            self.direction or self.protocol or self.ip.strip()
            or self.port.strip() or self.expression.strip()
        )


@dataclass(frozen=True)
class ComposedFilter:
    """A request turned into one validated expression.

    Attributes:
        request: what was asked for.
        expression: the single expression that is actually evaluated.
        label: a short human description, e.g. "HTTP · Incoming".
        empty_text: what the table says when nothing matches.
        encrypted: True when the view is about TLS, so the HTTPS notice shows.
        ip_value: the canonical address searched for, if any.
        compiled: the compiled expression.
    """

    request: FilterRequest
    expression: str
    label: str
    empty_text: str
    encrypted: bool
    ip_value: str
    compiled: CompiledFilter

    @property
    def is_all(self) -> bool:
        """True for "all traffic"."""
        return not self.expression


def _needs_parentheses(part: str) -> bool:
    return "||" in part or " or " in f" {part.lower()} "


def compose_filter(request: FilterRequest) -> ComposedFilter:
    """Turn presets, searches and a typed expression into one expression.

    Every part is ANDed. A preset is its expression; an IP search becomes
    ``ip.addr``/``ip.src``/``ip.dst`` (or the IPv6 equivalents); a port search
    becomes the TCP-or-UDP port fields. The typed expression is validated on
    its own first, so an error names the part the operator typed.

    Raises:
        FilterSyntaxError: when any part is invalid.
    """
    parts: list[str] = []
    labels: list[str] = []
    encrypted = False

    protocol = None
    if request.protocol:
        protocol = PROTOCOL_BY_KEY.get(request.protocol)
        if protocol is None:
            raise FilterSyntaxError(f"Unknown protocol view '{request.protocol}'.")
        parts.append(protocol.expression)
        labels.append(protocol.label)
        encrypted = protocol.encrypted

    direction = None
    if request.direction:
        direction = DIRECTION_BY_KEY.get(request.direction)
        if direction is None:
            raise FilterSyntaxError(f"Unknown direction view '{request.direction}'.")
        parts.append(direction.expression)
        labels.append(direction.label)

    ip_value = ""
    ip_text = request.ip.strip()
    if ip_text:
        scope = request.ip_scope if request.ip_scope in SCOPES else "either"
        try:
            parsed = (
                ipaddress.ip_network(ip_text, strict=False)
                if "/" in ip_text else ipaddress.ip_address(ip_text)
            )
        except ValueError:
            raise FilterSyntaxError(f"'{ip_text}' is not a valid IP address or network.") from None
        family = "ip" if parsed.version == 4 else "ipv6"
        suffix = {"either": "addr", "source": "src", "destination": "dst"}[scope]
        ip_value = parsed.compressed if hasattr(parsed, "compressed") else str(parsed)
        parts.append(f"{family}.{suffix} == {ip_value}")
        labels.append(f"IP {ip_value}" + ("" if scope == "either" else f" ({scope})"))

    port_text = request.port.strip()
    if port_text:
        scope = request.port_scope if request.port_scope in SCOPES else "either"
        if not port_text.isdigit() or not 0 <= int(port_text) <= 65535:
            raise FilterSyntaxError(f"'{port_text}' is not a port number (0-65535).")
        number = int(port_text)
        suffix = {"either": "port", "source": "srcport", "destination": "dstport"}[scope]
        parts.append(f"tcp.{suffix} == {number} || udp.{suffix} == {number}")
        labels.append(f"port {number}" + ("" if scope == "either" else f" ({scope})"))

    typed = request.expression.strip()
    if typed:
        compile_filter(typed)  # raises with a message about what was typed
        parts.append(typed)
        labels.append(typed)

    if len(parts) > 1:
        expression = " && ".join(
            f"({part})" if _needs_parentheses(part) else part for part in parts
        )
    else:
        expression = parts[0] if parts else ""

    compiled = compile_filter(expression)
    encrypted = encrypted or any(
        name in ("tls", "ssl") or name.startswith("tls.") for name in compiled.fields
    )

    if protocol and direction:
        empty_text = f"No {direction.label.lower()} {protocol.label} traffic captured."
    elif protocol:
        empty_text = protocol.empty_text
    elif direction:
        empty_text = direction.empty_text
    else:
        empty_text = "No captured packets match the display filter." if expression else ""
    if expression and (ip_text or port_text or typed) and (protocol or direction):
        empty_text = "No captured packets match the display filter."

    return ComposedFilter(
        request=request,
        expression=expression,
        label=" · ".join(labels) or ALL_TRAFFIC_LABEL,
        empty_text=empty_text,
        encrypted=encrypted,
        ip_value=ip_value,
        compiled=compiled,
    )


#: Protocol counts shown for the filtered set. Categories overlap on purpose -
#: a TLS packet is also a TCP packet - so each is "packets carrying X".
STATISTIC_PROTOCOLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("HTTP", ("http",)),
    ("TLS", ("tls",)),
    ("DNS", ("dns",)),
    ("TCP", ("tcp",)),
    ("UDP", ("udp",)),
    ("ICMP", ("icmp", "icmpv6")),
    ("ARP", ("arp",)),
)
