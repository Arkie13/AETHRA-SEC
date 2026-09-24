"""Mapping PyShark packet objects to :class:`CapturedPacket` (§11).

Real packets are irregular: an ARP frame has no IP layer, an ICMP packet has no
ports, a malformed frame may lack fields TShark normally provides. Every
accessor here is defensive - a missing field yields an empty/``None`` value and
never raises, and nothing is ever substituted with a plausible-looking guess.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from aethra_sec.models.traffic import CapturedPacket, without_parsed_tls
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import from_epoch, utcnow

LOGGER = get_logger("integrations.pyshark.mapper")

#: Layer names that identify an application protocol worth recording.
APPLICATION_LAYERS: tuple[str, ...] = (
    "HTTP", "HTTP2", "TLS", "SSL", "DNS", "MDNS", "LLMNR", "DHCP", "DHCPV6",
    "BOOTP", "FTP", "FTP-DATA", "SSH", "TELNET", "SMTP", "POP", "IMAP", "SNMP",
    "NTP", "SMB", "SMB2", "NBNS", "LDAP", "KERBEROS", "RDP", "SIP", "RTP",
    "TFTP", "SYSLOG", "QUIC", "MYSQL", "PGSQL", "VNC", "RADIUS", "MQTT",
)

#: Transport/network layers that are never treated as the application protocol.
_NON_APPLICATION_LAYERS: frozenset[str] = frozenset(
    {"ETH", "IP", "IPV6", "TCP", "UDP", "ICMP", "ICMPV6", "ARP", "SLL",
     "LOOP", "NULL", "DATA", "FRAME", "VLAN", "LLC", "RAW", "SLL2",
     "ETHERTYPE", "TCP.SEGMENTS", "DATA-TEXT-LINES", "MEDIA", "IGMP"}
)

# There is deliberately no port-to-protocol table here any more. One used to
# name a packet "HTTPS" because it went to port 443 and "HTTP" because it went
# to port 80, whether or not either protocol was present. The label then reached
# the packet table, the stored records and the detection rules as though TShark
# had decoded it. A port is where traffic went, not what it contained.


def _field(layer: Any, *names: str) -> str:
    """Read the first present field from a PyShark layer.

    Returns an empty string when the layer is absent or no name matched.
    """
    if layer is None:
        return ""
    for name in names:
        try:
            value = getattr(layer, name, None)
        except Exception:  # noqa: BLE001 - PyShark raises on unknown fields
            continue
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() != "none":
            return text
    return ""


def _int_field(layer: Any, *names: str) -> int | None:
    """Read an integer field, tolerating hex (``0x12``) and decimal forms."""
    raw = _field(layer, *names)
    if not raw:
        return None
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(raw, 10)
    except ValueError:
        try:
            return int(float(raw))
        except ValueError:
            return None


def _layer(packet: Any, name: str) -> Any:
    """Fetch a layer by name, or ``None`` when the packet does not carry it."""
    try:
        if name in packet:
            return packet[name]
    except Exception:  # noqa: BLE001 - PyShark's __contains__ can raise
        pass
    return getattr(packet, name.lower(), None)


def _layer_names(packet: Any) -> tuple[str, ...]:
    """Names of every decoded layer, in order."""
    try:
        return tuple(
            str(getattr(layer, "layer_name", "")).upper()
            for layer in packet.layers
            if getattr(layer, "layer_name", None)
        )
    except Exception:  # noqa: BLE001
        return ()


def _sniff_time(packet: Any) -> datetime:
    """The packet's own capture timestamp.

    Falls back to the current time only when TShark supplied nothing, which is
    recorded honestly rather than presented as the capture instant.
    """
    raw = getattr(packet, "sniff_timestamp", None)
    if raw:
        try:
            return from_epoch(float(raw))
        except (TypeError, ValueError):
            pass
    sniff_time = getattr(packet, "sniff_time", None)
    if isinstance(sniff_time, datetime):
        return sniff_time.astimezone() if sniff_time.tzinfo else sniff_time.replace(
            tzinfo=utcnow().tzinfo
        )
    return utcnow()


def application_protocol(layers: tuple[str, ...], highest_layer: str = "") -> str:
    """The application protocol TShark decoded for a frame, or ``""``.

    Read from the decoded protocol chain and nothing else. Layers after an ICMP
    header are the quoted packet an ICMP error carries, not this frame's own
    application, so the chain is cut there.
    """
    chain = tuple(layers)
    for marker in ("ICMP", "ICMPV6"):
        if marker in chain:
            chain = chain[: chain.index(marker) + 1]
            break
    # A DNS answer whose HTTPS record TShark parsed with its TLS code is DNS.
    chain = without_parsed_tls(chain)
    for name in reversed(chain):
        if name in _NON_APPLICATION_LAYERS or name.startswith("_WS."):
            continue
        if name in APPLICATION_LAYERS:
            return name
    upper = (highest_layer or "").upper()
    if (
        upper
        and upper in chain
        and upper not in _NON_APPLICATION_LAYERS
        and not upper.startswith("_WS.")
    ):
        return upper
    return ""


def map_packet(packet: Any, interface: str = "") -> CapturedPacket | None:
    """Convert one PyShark packet into a :class:`CapturedPacket`.

    Args:
        packet: a PyShark packet object from a live capture.
        interface: the capture interface name, recorded with the packet.

    Returns:
        The mapped packet, or ``None`` when the object could not be read at
        all (the caller counts these as decode errors and shows the count).
    """
    try:
        layers = _layer_names(packet)
        highest = str(getattr(packet, "highest_layer", "") or "").upper()
        transport = str(getattr(packet, "transport_layer", "") or "").upper()

        ip_layer = _layer(packet, "IP")
        ipv6_layer = _layer(packet, "IPV6") if ip_layer is None else None
        eth_layer = _layer(packet, "ETH")
        arp_layer = _layer(packet, "ARP")

        src_ip = dst_ip = ""
        ip_version: int | None = None
        ttl: int | None = None

        if ip_layer is not None:
            src_ip = _field(ip_layer, "src", "src_host", "addr")
            dst_ip = _field(ip_layer, "dst", "dst_host")
            ttl = _int_field(ip_layer, "ttl")
            ip_version = 4
        elif ipv6_layer is not None:
            src_ip = _field(ipv6_layer, "src", "src_host")
            dst_ip = _field(ipv6_layer, "dst", "dst_host")
            ttl = _int_field(ipv6_layer, "hlim")
            ip_version = 6
        elif arp_layer is not None:
            # ARP carries protocol addresses rather than an IP header.
            src_ip = _field(arp_layer, "src_proto_ipv4")
            dst_ip = _field(arp_layer, "dst_proto_ipv4")

        src_port = dst_port = None
        tcp_flags = None
        transport_layer_obj = None
        if transport == "TCP" or "TCP" in layers:
            transport_layer_obj = _layer(packet, "TCP")
            transport = "TCP"
            tcp_flags = _int_field(transport_layer_obj, "flags")
        elif transport == "UDP" or "UDP" in layers:
            transport_layer_obj = _layer(packet, "UDP")
            transport = "UDP"

        if transport_layer_obj is not None:
            src_port = _int_field(transport_layer_obj, "srcport", "port")
            dst_port = _int_field(transport_layer_obj, "dstport")

        if "ICMP" in layers:
            protocol = "ICMP"
        elif "ICMPV6" in layers:
            protocol = "ICMPv6"
        elif arp_layer is not None:
            protocol = "ARP"
        elif transport in ("TCP", "UDP"):
            protocol = transport
        elif ip_layer is not None or ipv6_layer is not None:
            protocol = "IP"
        else:
            protocol = highest or "OTHER"

        length = 0
        for source in (packet, _layer(packet, "FRAME")):
            value = _int_field(source, "length", "len", "cap_len")
            if value:
                length = value
                break

        src_mac = _field(eth_layer, "src", "src_resolved").lower()
        dst_mac = _field(eth_layer, "dst", "dst_resolved").lower()
        if not src_mac and arp_layer is not None:
            src_mac = _field(arp_layer, "src_hw_mac").lower()
            dst_mac = _field(arp_layer, "dst_hw_mac").lower()

        app_protocol = application_protocol(layers, highest)

        http_layer = _layer(packet, "HTTP")
        tls_layer = _layer(packet, "TLS")
        if tls_layer is None:
            tls_layer = _layer(packet, "SSL")
        dns_layer = None
        for dns_name in ("DNS", "MDNS", "LLMNR"):
            dns_layer = _layer(packet, dns_name)
            if dns_layer is not None:
                break
        icmp_layer = _layer(packet, "ICMP")
        if icmp_layer is None:
            icmp_layer = _layer(packet, "ICMPV6")
        dns_flag = _field(dns_layer, "flags_response").lower()

        if not layers and not length and not (src_ip or dst_ip or src_mac or dst_mac):
            # Nothing identifiable was read: no layers, no length, no endpoints.
            # Recording that as a packet would invent an observation (§1).
            LOGGER.debug("Ignoring an object with no readable packet fields.")
            return None

        return CapturedPacket(
            captured_at=_sniff_time(packet),
            interface=interface,
            number=_int_field(packet, "number"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            transport=transport,
            highest_layer=highest,
            app_protocol=app_protocol,
            length=length,
            ttl=ttl,
            tcp_flags=tcp_flags,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ip_version=ip_version,
            layers=layers,
            http_method=_field(http_layer, "request_method"),
            http_uri=_field(http_layer, "request_uri"),
            http_host=_field(http_layer, "host"),
            http_version=_field(http_layer, "request_version", "response_version"),
            http_status=_int_field(http_layer, "response_code"),
            http_phrase=_field(http_layer, "response_phrase"),
            tls_handshake_type=_int_field(tls_layer, "handshake_type"),
            tls_sni=_field(tls_layer, "handshake_extensions_server_name"),
            tls_record_version=_int_field(tls_layer, "record_version"),
            tls_handshake_version=_int_field(tls_layer, "handshake_version"),
            tls_supported_version=_int_field(
                tls_layer, "handshake_extensions_supported_version"
            ),
            dns_query=_field(dns_layer, "qry_name"),
            dns_response=(
                True if dns_flag in ("1", "true")
                else False if dns_flag in ("0", "false") else None
            ),
            icmp_type=_int_field(icmp_layer, "type"),
            icmp_code=_int_field(icmp_layer, "code"),
            arp_opcode=_int_field(arp_layer, "opcode"),
            arp_sender_mac=_field(arp_layer, "src_hw_mac").lower(),
            arp_target_mac=_field(arp_layer, "dst_hw_mac").lower(),
            tcp_seq=_int_field(transport_layer_obj, "seq") if transport == "TCP" else None,
            tcp_ack=_int_field(transport_layer_obj, "ack") if transport == "TCP" else None,
        )
    except Exception:  # noqa: BLE001 - one odd packet must not stop the capture
        LOGGER.debug("Could not map a captured packet.", exc_info=True)
        return None


def describe_packet(packet: Any) -> tuple[tuple[str, str], ...]:
    """Extract decoded layer/field detail for the packet detail panel (§12).

    Built on demand for the selected packet only - doing this for every packet
    would be far too expensive at line rate.

    Returns:
        ``(label, value)`` pairs. Empty when the packet cannot be introspected.
    """
    details: list[tuple[str, str]] = []
    try:
        for layer in packet.layers:
            name = str(getattr(layer, "layer_name", "") or "layer").upper()
            details.append((f"--- {name} ---", ""))
            try:
                field_names = list(getattr(layer, "field_names", []) or [])
            except Exception:  # noqa: BLE001
                field_names = []
            for field_name in field_names:
                try:
                    value = layer.get_field_value(field_name)
                except Exception:  # noqa: BLE001
                    continue
                if value is None:
                    continue
                text = str(value).strip()
                if text:
                    details.append((f"{name}.{field_name}", text[:300]))
    except Exception:  # noqa: BLE001
        LOGGER.debug("Could not describe a packet.", exc_info=True)
    return tuple(details)
