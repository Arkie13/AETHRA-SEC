"""The TShark field decoder: protocol fields, honest Info text, no port guessing.

Rows are built in ``tshark -T fields -E occurrence=f`` layout from field names,
so these tests stay correct whatever order :data:`FIELDS` is in. The value
formats (``True``/``False`` booleans, ``0x0303`` versions, relative sequence
numbers, SSDP carrying ``http.*`` fields) are the ones TShark 4.4.8 was observed
to print on real captures.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from queue import Queue

import pytest

from aethra_sec.integrations.pyshark_capture import field_reader, mapper
from aethra_sec.integrations.pyshark_capture.field_reader import (
    CORE_FIELD_COUNT,
    FIELDS,
    FieldCaptureReader,
    fields_for,
    parse_line,
)

ORIGINAL_CORE = (
    "frame.number", "frame.time_epoch", "frame.len", "_ws.col.protocol",
    "frame.protocols", "eth.src", "eth.dst", "ip.src", "ip.dst", "ip.ttl",
    "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "tcp.flags",
    "udp.srcport", "udp.dstport", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    "arp.src.hw_mac", "arp.dst.hw_mac",
)


def row(values: dict[str, str], fields: tuple[str, ...] = FIELDS) -> str:
    base = {"frame.number": "1", "frame.time_epoch": "1700000000.25", "frame.len": "120"}
    base.update(values)
    return "\t".join(base.get(name, "") for name in fields)


def tcp(values: dict[str, str]) -> dict[str, str]:
    base = {
        "eth.src": "02:00:00:00:00:10", "eth.dst": "02:00:00:00:00:20",
        "ip.src": "192.0.2.10", "ip.dst": "198.51.100.20",
        "tcp.srcport": "50000", "tcp.dstport": "80", "tcp.flags": "0x0018",
        "tcp.seq": "1", "tcp.ack": "1",
    }
    base.update(values)
    return base


class TestTheFieldList:
    def test_the_core_set_is_unchanged_and_first(self) -> None:
        assert FIELDS[:CORE_FIELD_COUNT] == ORIGINAL_CORE

    def test_the_info_column_is_last(self) -> None:
        assert FIELDS[-1] == "_ws.col.info"

    def test_the_command_asks_for_one_occurrence_and_every_field(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(field_reader, "find_tshark", lambda _path: Path("tshark"))
        command = FieldCaptureReader("eth0", Queue())._command()
        assert command[command.index("-E") + 1] == "occurrence=f"
        requested = [command[i + 1] for i, part in enumerate(command) if part == "-e"]
        assert tuple(requested) == FIELDS

    def test_the_core_only_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(field_reader, "find_tshark", lambda _path: Path("tshark"))
        command = FieldCaptureReader("eth0", Queue(), extended_fields=False)._command()
        requested = [command[i + 1] for i, part in enumerate(command) if part == "-e"]
        assert tuple(requested) == ORIGINAL_CORE == fields_for(False)

    def test_the_command_is_an_argument_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(field_reader, "find_tshark", lambda _path: Path("tshark"))
        assert isinstance(FieldCaptureReader("eth0", Queue())._command(), list)


class TestHttp:
    def test_a_request(self) -> None:
        packet = parse_line(row(tcp({
            "_ws.col.protocol": "HTTP", "frame.protocols": "eth:ethertype:ip:tcp:http",
            "http.request.method": "GET", "http.request.uri": "/login",
            "http.host": "example.com", "http.request.version": "HTTP/1.1",
            "_ws.col.info": "GET /login HTTP/1.1 ",
        })), "eth0", "capture.pcapng")
        assert packet is not None
        assert packet.is_http and packet.app_protocol == "HTTP"
        assert packet.info == "GET /login HTTP/1.1  Host: example.com"
        assert packet.pcap_path == "capture.pcapng"
        assert packet.tcp_seq == 1 and packet.tcp_ack == 1

    def test_a_response(self) -> None:
        packet = parse_line(row(tcp({
            "tcp.srcport": "80", "tcp.dstport": "50000",
            "_ws.col.protocol": "HTTP", "frame.protocols": "eth:ethertype:ip:tcp:http",
            "http.response.code": "200", "http.response.phrase": "OK",
            "http.response.version": "HTTP/1.1", "_ws.col.info": "HTTP/1.1 200 OK (text/html)",
        })), "eth0")
        assert packet is not None
        assert packet.http_status == 200
        assert packet.info == "HTTP/1.1 200 OK"

    def test_ssdp_carries_http_fields_but_is_not_http(self) -> None:
        packet = parse_line(row({
            "ip.src": "192.0.2.10", "ip.dst": "239.255.255.250",
            "udp.srcport": "50001", "udp.dstport": "1900",
            "_ws.col.protocol": "SSDP", "frame.protocols": "eth:ethertype:ip:udp:ssdp",
            "http.request.method": "M-SEARCH", "http.request.uri": "*",
            "http.request.version": "HTTP/1.1", "_ws.col.info": "M-SEARCH * HTTP/1.1 ",
        }), "eth0")
        assert packet is not None
        assert not packet.is_http
        assert packet.app_protocol == "SSDP"
        assert packet.info == "M-SEARCH * HTTP/1.1"

    def test_port_80_without_an_http_layer_is_not_http(self) -> None:
        packet = parse_line(row(tcp({
            "tcp.flags": "0x0002", "_ws.col.protocol": "TCP",
            "frame.protocols": "eth:ethertype:ip:tcp",
        })), "eth0")
        assert packet is not None
        assert packet.app_protocol == "" and not packet.is_http


class TestTls:
    def test_a_client_hello_states_no_negotiated_version(self) -> None:
        packet = parse_line(row(tcp({
            "tcp.dstport": "443", "_ws.col.protocol": "TLSv1.2",
            "frame.protocols": "eth:ethertype:ip:tcp:tls",
            "tls.handshake.type": "1", "tls.handshake.extensions_server_name": "example.com",
            "tls.record.version": "0x0301", "tls.handshake.version": "0x0303",
            "tls.handshake.extensions.supported_version": "0x1a1a",
            "_ws.col.info": "Client Hello (SNI=example.com)",
        })), "eth0")
        assert packet is not None
        assert packet.is_tls and packet.app_protocol == "TLS"
        assert packet.tls_handshake_name == "Client Hello"
        assert packet.tls_sni == "example.com"
        assert packet.tls_negotiated_version == ""
        assert packet.info == "Client Hello (SNI=example.com)"

    def test_a_server_hello_states_the_selected_version(self) -> None:
        packet = parse_line(row(tcp({
            "tcp.srcport": "443", "_ws.col.protocol": "TLSv1.3",
            "frame.protocols": "eth:ethertype:ip:tcp:tls",
            "tls.handshake.type": "2", "tls.record.version": "0x0303",
            "tls.handshake.version": "0x0303",
            "tls.handshake.extensions.supported_version": "0x0304",
            "_ws.col.info": "Server Hello, Change Cipher Spec, Application Data",
        })), "eth0")
        assert packet is not None
        assert packet.tls_negotiated_version == "TLS 1.3"

    def test_port_443_without_a_tls_layer_is_not_tls(self) -> None:
        packet = parse_line(row(tcp({
            "tcp.dstport": "443", "tcp.flags": "0x0002", "_ws.col.protocol": "TCP",
            "frame.protocols": "eth:ethertype:ip:tcp",
        })), "eth0")
        assert packet is not None
        assert packet.app_protocol == "" and not packet.is_tls

    def test_a_dns_https_answer_is_dns_not_tls(self) -> None:
        """Seen on real captures: TShark's DNS dissector parses the ECH setting
        of an HTTPS record with its TLS code, so the chain ends ``dns:tls`` -
        but TShark's own ``tls`` filter does not match the frame."""
        packet = parse_line(row({
            "ip.src": "198.51.100.1", "ip.dst": "192.0.2.10",
            "udp.srcport": "53", "udp.dstport": "50004",
            "_ws.col.protocol": "DNS", "frame.protocols": "eth:ethertype:ip:udp:dns:tls",
            "dns.qry.name": "example.com", "dns.flags.response": "True",
        }), "eth0")
        assert packet is not None
        assert not packet.is_tls
        assert packet.app_protocol == "DNS"

    def test_a_quic_handshake_fragment_is_still_tls(self) -> None:
        """QUIC carries the TLS handshake; a fragment has no handshake fields."""
        packet = parse_line(row({
            "ip.src": "192.0.2.10", "ip.dst": "198.51.100.20",
            "udp.srcport": "50005", "udp.dstport": "443",
            "_ws.col.protocol": "QUIC", "frame.protocols": "eth:ethertype:ip:udp:quic:tls",
        }), "eth0")
        assert packet is not None
        assert packet.is_tls

    def test_a_quic_client_hello_shows_its_server_name_first(self) -> None:
        """TShark's Info for a QUIC Initial never names the site; the field does."""
        quic_info = "Initial, DCID=0123456789abcdef, PKN: 3, CRYPTO, PADDING"
        packet = parse_line(row({
            "ip.src": "192.0.2.10", "ip.dst": "198.51.100.20",
            "udp.srcport": "50006", "udp.dstport": "443",
            "_ws.col.protocol": "QUIC", "frame.protocols": "eth:ethertype:ip:udp:quic:tls",
            "tls.handshake.type": "1", "tls.handshake.extensions_server_name": "example.com",
            "_ws.col.info": quic_info,
        }), "eth0")
        assert packet is not None
        assert packet.info == f"SNI=example.com  ·  {quic_info}"


class TestOtherProtocols:
    def test_dns_booleans_as_tshark_4_prints_them(self) -> None:
        packet = parse_line(row({
            "ip.src": "198.51.100.20", "ip.dst": "192.0.2.10",
            "udp.srcport": "53", "udp.dstport": "50002",
            "_ws.col.protocol": "DNS", "frame.protocols": "eth:ethertype:ip:udp:dns",
            "dns.qry.name": "example.com", "dns.flags.response": "True",
        }), "eth0")
        assert packet is not None
        assert packet.dns_query == "example.com" and packet.dns_response is True

    def test_an_icmp_error_is_not_labelled_with_the_quoted_application(self) -> None:
        packet = parse_line(row({
            "ip.src": "198.51.100.1", "ip.dst": "192.0.2.10",
            "udp.srcport": "50003", "udp.dstport": "5351",
            "_ws.col.protocol": "ICMP",
            "frame.protocols": "eth:ethertype:ip:icmp:ip:udp:portcontrol",
            "icmp.type": "3", "icmp.code": "3",
            "_ws.col.info": "Destination unreachable (Port unreachable)",
        }), "eth0")
        assert packet is not None
        assert packet.icmp_type == 3 and packet.icmp_code == 3
        assert packet.app_protocol == ""

    def test_arp_sender_and_target(self) -> None:
        packet = parse_line(row({
            "eth.src": "02:00:00:00:00:30", "eth.dst": "ff:ff:ff:ff:ff:ff",
            "_ws.col.protocol": "ARP", "frame.protocols": "eth:ethertype:arp",
            "arp.src.proto_ipv4": "192.0.2.30", "arp.dst.proto_ipv4": "192.0.2.40",
            "arp.src.hw_mac": "02:00:00:00:00:30", "arp.dst.hw_mac": "00:00:00:00:00:00",
            "arp.opcode": "1", "_ws.col.info": "Who has 192.0.2.40? Tell 192.0.2.30",
        }), "eth0")
        assert packet is not None
        assert packet.protocol == "ARP" and packet.arp_opcode == 1
        assert packet.arp_sender_mac == "02:00:00:00:00:30"
        assert packet.arp_target_mac == "00:00:00:00:00:00"
        assert packet.info == "Who has 192.0.2.40? Tell 192.0.2.30"


class TestTextOtherDevicesChoose:
    """TShark writes UTF-8, and the reader has to read it as UTF-8.

    Seen on a live capture: the Info column's arrow displayed as "â†'". The
    pipe was being read in the Windows ANSI code page, where some bytes of
    ordinary UTF-8 have no character at all - and reading one of those raised
    in the reader thread and failed the capture.
    """

    def test_non_ascii_text_arrives_intact_and_never_fails_the_capture(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        info = "50000 → 80 [PSH, ACK] Łódź Á"
        line = row(tcp({
            "_ws.col.protocol": "TCP", "frame.protocols": "eth:ethertype:ip:tcp",
            "_ws.col.info": info,
        }))
        # Written as bytes by a child process, the way TShark's pipe delivers
        # them. "Á" is C3 81 in UTF-8, and 0x81 is undefined in code page 1252.
        payload = (line + "\n").encode("utf-8").hex()
        queue: Queue = Queue()
        errors: list[str] = []
        ended = threading.Event()
        reader = FieldCaptureReader(
            "capture-interface", queue,
            on_error=errors.append, on_stopped=lambda _reason: ended.set(),
        )
        monkeypatch.setattr(reader, "_command", lambda: [
            sys.executable, "-c",
            f"import sys; sys.stdout.buffer.write(bytes.fromhex('{payload}'))",
        ])
        reader.start()
        try:
            assert ended.wait(30), "the reader thread never finished"
        finally:
            reader.stop()
        assert errors == []
        assert reader.counters.decode_errors == 0
        assert queue.get_nowait().info == info


class TestRobustness:
    def test_a_tab_inside_the_info_text_shifts_nothing(self) -> None:
        packet = parse_line(row(tcp({
            "frame.protocols": "eth:ethertype:ip:tcp", "_ws.col.info": "odd\ttext",
        })), "eth0")
        assert packet is not None
        assert packet.tshark_info == "odd\ttext"
        assert packet.dst_port == 80

    def test_a_core_only_row_parses_with_the_new_fields_empty(self) -> None:
        packet = parse_line(row(tcp({"frame.protocols": "eth:ethertype:ip:tcp"}), ORIGINAL_CORE), "eth0")
        assert packet is not None
        assert packet.tshark_info == "" and packet.http_method == "" and packet.tcp_seq is None

    def test_the_reader_records_its_capture_file_on_packets(self) -> None:
        reader = FieldCaptureReader("eth0", Queue(), output_file=Path("capture.pcapng"))
        assert reader._pcap_text == "capture.pcapng"  # noqa: SLF001


class TestNoPortGuessing:
    def test_the_port_table_is_gone(self) -> None:
        assert not hasattr(mapper, "_PORT_HINTS")

    @pytest.mark.parametrize("layers", [("ETH", "IP", "TCP"), ("ETH", "IP", "UDP")])
    def test_no_application_without_a_decoded_layer(self, layers: tuple[str, ...]) -> None:
        assert mapper.application_protocol(layers, layers[-1]) == ""


class TestTlsSegments:
    def test_a_segment_the_tls_dissector_marked_is_tls_without_a_tls_layer(self) -> None:
        packet = parse_line(row(tcp({
            "tcp.dstport": "443", "tcp.flags": "0x0010", "_ws.col.protocol": "SSL",
            "frame.protocols": "eth:ethertype:ip:tcp",
        })), "eth0")
        assert packet is not None
        assert packet.is_tls
        assert "TLS" not in packet.layers, "the recorded chain is left exactly as TShark gave it"
        assert packet.app_protocol == ""
