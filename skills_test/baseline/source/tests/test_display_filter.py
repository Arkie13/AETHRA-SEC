"""Display filters: real semantics over decoded fields, safe parsing, honest errors.

Packets here are built in the shape the TShark field decoder produces - the
layer chain from ``frame.protocols`` plus the decoded fields - using addresses
from the documentation ranges. The behaviour against real captured traffic is
verified separately, against TShark's own display filters on the same frames.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from typing import Any

import pytest

from aethra_sec.analytics import display_filter as module
from aethra_sec.analytics.display_filter import (
    DIRECTION_PRESETS,
    HTTPS_NOTICE,
    MATCH_ALL,
    PROTOCOL_PRESETS,
    FilterRequest,
    FilterSyntaxError,
    compile_filter,
    compose_filter,
    validate_filter,
)
from aethra_sec.models.traffic import CapturedPacket

MONITOR = "192.0.2.10"
SERVER = "198.51.100.20"
ATTACKER = "192.0.2.30"
TARGET = "192.0.2.40"


def make(name: str, **fields: Any) -> CapturedPacket:
    base: dict[str, Any] = {
        "captured_at": datetime.now(UTC),
        "interface": "test0",
        "ip_version": 4,
        "src_mac": "02:00:00:00:00:10",
        "dst_mac": "02:00:00:00:00:20",
    }
    base.update(fields)
    packet = CapturedPacket(**base)
    packet.raw_summary = name
    return packet


PACKETS: dict[str, CapturedPacket] = {
    "http_request": make(
        "http_request", src_ip=MONITOR, dst_ip=SERVER, src_port=50000, dst_port=80,
        transport="TCP", tcp_flags=0x18, layers=("ETH", "ETHERTYPE", "IP", "TCP", "HTTP"),
        http_method="GET", http_uri="/login", http_host="example.com",
        http_version="HTTP/1.1", direction="OUTGOING",
    ),
    "http_response": make(
        "http_response", src_ip=SERVER, dst_ip=MONITOR, src_port=80, dst_port=50000,
        transport="TCP", tcp_flags=0x18, layers=("ETH", "ETHERTYPE", "IP", "TCP", "HTTP"),
        http_status=200, http_phrase="OK", http_version="HTTP/1.1", direction="INCOMING",
    ),
    # TShark fills http.* for SSDP, but the protocol chain says SSDP.
    "ssdp": make(
        "ssdp", src_ip=MONITOR, dst_ip="239.255.255.250", src_port=50001, dst_port=1900,
        transport="UDP", layers=("ETH", "ETHERTYPE", "IP", "UDP", "SSDP"),
        http_method="M-SEARCH", http_uri="*", direction="OUTGOING",
    ),
    "tls_client_hello": make(
        "tls_client_hello", src_ip=MONITOR, dst_ip=SERVER, src_port=50002, dst_port=443,
        transport="TCP", tcp_flags=0x18, layers=("ETH", "ETHERTYPE", "IP", "TCP", "TLS"),
        tls_handshake_type=1, tls_sni="example.com", tls_record_version=0x0301,
        tls_supported_version=0x1A1A, direction="OUTGOING",
    ),
    "tls_server_hello": make(
        "tls_server_hello", src_ip=SERVER, dst_ip=MONITOR, src_port=443, dst_port=50002,
        transport="TCP", tcp_flags=0x10, layers=("ETH", "ETHERTYPE", "IP", "TCP", "TLS"),
        tls_handshake_type=2, tls_record_version=0x0303, tls_supported_version=0x0304,
        direction="INCOMING",
    ),
    # Port 443, but TShark decoded no TLS: this is not HTTPS.
    "tcp_443_syn": make(
        "tcp_443_syn", src_ip=MONITOR, dst_ip=SERVER, src_port=50003, dst_port=443,
        transport="TCP", tcp_flags=0x02, layers=("ETH", "ETHERTYPE", "IP", "TCP"),
        direction="OUTGOING",
    ),
    # Port 80, but no HTTP layer: this is not HTTP.
    "tcp_80_syn": make(
        "tcp_80_syn", src_ip=MONITOR, dst_ip=SERVER, src_port=50004, dst_port=80,
        transport="TCP", tcp_flags=0x02, layers=("ETH", "ETHERTYPE", "IP", "TCP"),
        direction="OUTGOING",
    ),
    "dns_query": make(
        "dns_query", src_ip=MONITOR, dst_ip=SERVER, src_port=50005, dst_port=53,
        transport="UDP", layers=("ETH", "ETHERTYPE", "IP", "UDP", "DNS"),
        dns_query="example.com", dns_response=False, direction="OUTGOING",
    ),
    "mdns": make(
        "mdns", src_ip=ATTACKER, dst_ip="224.0.0.251", src_port=5353, dst_port=5353,
        transport="UDP", layers=("ETH", "ETHERTYPE", "IP", "UDP", "MDNS"),
        dns_query="printer.local", dns_response=True, direction="BROADCAST",
    ),
    "icmp_echo": make(
        "icmp_echo", src_ip=MONITOR, dst_ip=SERVER,
        layers=("ETH", "ETHERTYPE", "IP", "ICMP", "DATA"), icmp_type=8, icmp_code=0,
        direction="OUTGOING",
    ),
    # An ICMP error quotes the offending packet, so UDP appears in the chain.
    "icmp_error": make(
        "icmp_error", src_ip=SERVER, dst_ip=MONITOR, src_port=50006, dst_port=5351,
        transport="UDP", layers=("ETH", "ETHERTYPE", "IP", "ICMP", "IP", "UDP", "PORTCONTROL"),
        icmp_type=3, icmp_code=3, direction="INCOMING",
    ),
    "arp_request": make(
        "arp_request", src_ip=ATTACKER, dst_ip=TARGET, ip_version=None,
        dst_mac="ff:ff:ff:ff:ff:ff", layers=("ETH", "ETHERTYPE", "ARP"), arp_opcode=1,
        arp_sender_mac="02:00:00:00:00:30", arp_target_mac="00:00:00:00:00:00",
        direction="BROADCAST",
    ),
    "transit": make(
        "transit", src_ip=ATTACKER, dst_ip=TARGET, src_port=40000, dst_port=22,
        transport="TCP", tcp_flags=0x02, layers=("ETH", "ETHERTYPE", "IP", "TCP"),
        direction="TRANSIT",
    ),
    "ipv6_udp": make(
        "ipv6_udp", src_ip="2001:db8::10", dst_ip="2001:db8::20", ip_version=6,
        src_port=50007, dst_port=123, transport="UDP",
        layers=("ETH", "ETHERTYPE", "IPV6", "UDP", "NTP"), direction="OUTGOING",
    ),
}


def matching(expression: str) -> set[str]:
    compiled = compile_filter(expression)
    return {name for name, packet in PACKETS.items() if compiled.matches(packet)}


class TestProtocolsComeFromTheDecodedChain:
    def test_http_is_the_http_layer_not_port_80_and_not_ssdp(self) -> None:
        assert matching("http") == {"http_request", "http_response"}

    def test_tls_is_the_tls_layer_not_port_443(self) -> None:
        assert matching("tls") == {"tls_client_hello", "tls_server_hello"}

    def test_ssl_is_an_alias_for_tls(self) -> None:
        assert matching("ssl") == matching("tls")

    def test_dns_is_dns_not_mdns(self) -> None:
        assert matching("dns") == {"dns_query"}
        assert matching("mdns") == {"mdns"}

    def test_icmp_includes_errors(self) -> None:
        assert matching("icmp") == {"icmp_echo", "icmp_error"}

    def test_udp_matches_a_udp_header_quoted_inside_an_icmp_error(self) -> None:
        """As in Wireshark: the quoted header is in the frame's protocol tree."""
        assert "icmp_error" in matching("udp")

    def test_arp(self) -> None:
        assert matching("arp") == {"arp_request"}


class TestFields:
    def test_ip_addr_matches_either_endpoint(self) -> None:
        assert matching(f"ip.addr == {SERVER}") == {
            "http_request", "http_response", "tls_client_hello", "tls_server_hello",
            "tcp_443_syn", "tcp_80_syn", "dns_query", "icmp_echo", "icmp_error",
        }

    def test_ip_src_and_ip_dst(self) -> None:
        assert matching(f"ip.src == {ATTACKER}") == {"mdns", "transit"}
        assert matching(f"ip.dst == {TARGET}") == {"transit"}

    def test_arp_endpoints_are_not_ip_fields(self) -> None:
        assert "arp_request" not in matching(f"ip.addr == {ATTACKER}")
        assert matching(f"arp.src.proto_ipv4 == {ATTACKER}") == {"arp_request"}

    def test_a_network_matches_by_containment(self) -> None:
        assert matching("ip.dst == 192.0.2.0/24") >= {"transit", "http_response"}

    def test_ipv6(self) -> None:
        assert matching("ipv6.addr == 2001:db8::20") == {"ipv6_udp"}

    def test_ports_are_transport_scoped(self) -> None:
        assert matching("tcp.port == 443") == {"tls_client_hello", "tls_server_hello", "tcp_443_syn"}
        assert matching("udp.dstport == 53") == {"dns_query"}

    def test_http_fields_are_scoped_to_http(self) -> None:
        assert matching('http.request.method == "GET"') == {"http_request"}
        assert matching('http.request.method == "M-SEARCH"') == set()
        assert matching("http.response.code == 200") == {"http_response"}
        assert matching('http.host contains "example"') == {"http_request"}
        assert matching("http.request") == {"http_request"}
        assert matching("http.response") == {"http_response"}

    def test_tls_fields(self) -> None:
        assert matching("tls.handshake.type == 1") == {"tls_client_hello"}
        assert matching("tls.handshake.extensions_server_name == example.com") == {"tls_client_hello"}

    def test_dns_fields_cover_mdns(self) -> None:
        assert matching("dns.flags.response == true") == {"mdns"}

    def test_tcp_flags(self) -> None:
        assert matching("tcp.flags.syn == 1") == {"tcp_443_syn", "tcp_80_syn", "transit"}

    def test_direction(self) -> None:
        assert matching("direction == transit") == {"transit"}
        assert matching("direction == broadcast") == {"mdns", "arp_request"}


class TestLogic:
    def test_and(self) -> None:
        assert matching("http && direction == outgoing") == {"http_request"}

    def test_or(self) -> None:
        assert matching("tls || dns") == {"tls_client_hello", "tls_server_hello", "dns_query"}

    def test_not(self) -> None:
        assert "arp_request" not in matching("!arp")
        assert len(matching("!arp")) == len(PACKETS) - 1

    def test_keywords(self) -> None:
        assert matching("tcp and not tcp.port eq 443") == matching("tcp && !(tcp.port == 443)")

    def test_parentheses(self) -> None:
        assert matching(f"(icmp || arp) && ip.src == {SERVER}") == {"icmp_error"}

    def test_not_equal_means_not_equal_to_any(self) -> None:
        """Wireshark 3.6+: a != b is !(a == b), so packets without the field match."""
        assert "dns_query" in matching("tcp.port != 443")
        assert "tcp_443_syn" not in matching("tcp.port != 443")


class TestTheEmptyFilter:
    def test_it_matches_every_packet(self) -> None:
        assert compile_filter("") is MATCH_ALL
        assert compile_filter("   ") is MATCH_ALL
        assert matching("") == set(PACKETS)


class TestInvalidFiltersAreRefusedWithAReason:
    @pytest.mark.parametrize(
        "expression",
        [
            "ip.src ===",
            "ip.src ==",
            "ip.src = 192.0.2.1",
            "tcp &&",
            "&& tcp",
            "(tcp",
            "tcp)",
            "tcp udp",
            "ip.src == 999.1.1.1",
            "ip.addr == 2001:db8::1",
            "ip.srcc == 192.0.2.1",
            "http.request.method > 5",
            "ip.addr contains 192",
            'http.host == "unterminated',
            "direction",
            "direction == sideways",
            "http == 1",
            "tcp.port == eighty",
            "no.such.field",
            "192.0.2.1",
            "tcp ; rm -rf /",
            "tcp & udp",
        ],
    )
    def test_refused(self, expression: str) -> None:
        with pytest.raises(FilterSyntaxError) as raised:
            compile_filter(expression)
        assert raised.value.message
        compiled, reason = validate_filter(expression)
        assert compiled is None and reason == raised.value.message

    def test_the_triple_equals_message(self) -> None:
        _compiled, reason = validate_filter("ip.src ===")
        assert reason == "'===' is not an operator. Use '=='."

    def test_a_close_misspelling_is_suggested(self) -> None:
        _compiled, reason = validate_filter("ip.srcc == 192.0.2.1")
        assert "ip.src" in reason

    def test_length_and_nesting_are_bounded(self) -> None:
        with pytest.raises(FilterSyntaxError):
            compile_filter("tcp || " * 100 + "tcp")
        with pytest.raises(FilterSyntaxError):
            compile_filter("(" * 40 + "tcp" + ")" * 40)


class TestSafety:
    def test_nothing_is_evaluated_as_code_or_run_as_a_command(self) -> None:
        source = inspect.getsource(module)
        for forbidden in ("eval(", "exec(", "compile(", "subprocess", "os.system", "Popen"):
            assert forbidden not in source.replace("compile_filter(", "")

    def test_a_filter_error_never_raises_during_matching(self) -> None:
        compiled = compile_filter("http.response.code > 100")
        assert compiled.matches(object()) is False


class TestPresetsAndComposition:
    def test_every_required_preset_exists(self) -> None:
        assert {p.key for p in PROTOCOL_PRESETS} == {"HTTP", "HTTPS", "WEB", "SITES", "TCP", "UDP", "ICMP", "DNS", "ARP"}
        assert {p.key for p in DIRECTION_PRESETS} == {"INCOMING", "OUTGOING", "TRANSIT"}

    def test_every_preset_compiles(self) -> None:
        for preset in PROTOCOL_PRESETS + DIRECTION_PRESETS:
            compile_filter(preset.expression)

    def test_web_is_http_plus_tls(self) -> None:
        web = compose_filter(FilterRequest(protocol="WEB"))
        assert {n for n, p in PACKETS.items() if web.compiled.matches(p)} == matching("http") | matching("tls")

    def test_http_and_incoming_combine(self) -> None:
        composed = compose_filter(FilterRequest(protocol="HTTP", direction="INCOMING"))
        assert composed.expression == "http && direction == incoming"
        assert composed.label == "HTTP · Incoming"
        assert composed.empty_text == "No incoming HTTP traffic captured."
        assert {n for n, p in PACKETS.items() if composed.compiled.matches(p)} == {"http_response"}

    def test_a_disjunctive_preset_is_parenthesised_when_combined(self) -> None:
        composed = compose_filter(FilterRequest(protocol="WEB", direction="OUTGOING"))
        assert composed.expression == "(http || tls) && direction == outgoing"

    @pytest.mark.parametrize(
        ("scope", "expected"),
        [("either", {"mdns", "transit"}), ("source", {"mdns", "transit"}), ("destination", set())],
    )
    def test_ip_search(self, scope: str, expected: set[str]) -> None:
        composed = compose_filter(FilterRequest(ip=ATTACKER, ip_scope=scope))
        assert {n for n, p in PACKETS.items() if composed.compiled.matches(p)} == expected
        assert composed.ip_value == ATTACKER

    def test_port_search_is_supplementary_not_a_protocol_claim(self) -> None:
        composed = compose_filter(FilterRequest(port="443"))
        matched = {n for n, p in PACKETS.items() if composed.compiled.matches(p)}
        assert "tcp_443_syn" in matched
        assert "tcp_443_syn" not in matching("tls")

    def test_tcp_and_source_ip(self) -> None:
        composed = compose_filter(FilterRequest(protocol="TCP", ip=ATTACKER, ip_scope="source"))
        assert {n for n, p in PACKETS.items() if composed.compiled.matches(p)} == {"transit"}

    def test_a_typed_expression_is_anded_in(self) -> None:
        composed = compose_filter(FilterRequest(protocol="TCP", expression="tcp.flags.syn == 1"))
        assert composed.expression == "tcp && tcp.flags.syn == 1"

    @pytest.mark.parametrize(
        "request_",
        [
            FilterRequest(ip="not-an-address"),
            FilterRequest(port="70000"),
            FilterRequest(port="http"),
            FilterRequest(expression="ip.src ==="),
            FilterRequest(protocol="GOPHER"),
            FilterRequest(direction="SIDEWAYS"),
        ],
    )
    def test_an_invalid_part_refuses_the_whole_request(self, request_: FilterRequest) -> None:
        with pytest.raises(FilterSyntaxError):
            compose_filter(request_)

    def test_the_https_views_are_marked_encrypted(self) -> None:
        assert compose_filter(FilterRequest(protocol="HTTPS")).encrypted
        assert compose_filter(FilterRequest(protocol="WEB")).encrypted
        assert compose_filter(FilterRequest(expression="tls.handshake.type == 1")).encrypted
        assert not compose_filter(FilterRequest(protocol="HTTP")).encrypted

    def test_the_https_notice_makes_no_claim_about_content(self) -> None:
        assert HTTPS_NOTICE == (
            "HTTPS traffic is encrypted. AETHRA-SEC displays available TLS/network "
            "metadata but does not claim access to encrypted HTTP content."
        )

    def test_nothing_requested_is_all_traffic(self) -> None:
        composed = compose_filter(FilterRequest())
        assert composed.is_all
        assert composed.label == "All traffic"
        assert composed.compiled is MATCH_ALL

    def test_empty_texts_name_what_was_asked_for(self) -> None:
        assert compose_filter(FilterRequest(protocol="HTTP")).empty_text == "No HTTP traffic captured."
        assert compose_filter(FilterRequest(protocol="HTTPS")).empty_text == "No HTTPS/TLS traffic captured."
        assert compose_filter(FilterRequest(direction="INCOMING")).empty_text == "No incoming traffic captured."


class TestTlsSegmentsTheTlsDissectorHandled:
    """Found on a live capture: segments of TLS records whose chain omits TLS."""

    def segment(self, column: str, length: int) -> CapturedPacket:
        return make(
            "tls_segment", src_ip=MONITOR, dst_ip=SERVER, src_port=50010, dst_port=443,
            transport="TCP", tcp_flags=0x10, layers=("ETH", "ETHERTYPE", "IP", "TCP"),
            protocol=column, length=length, direction="OUTGOING",
        )

    def test_a_segment_marked_by_the_tls_dissector_is_tls(self) -> None:
        compiled = compile_filter("tls")
        assert compiled.matches(self.segment("SSL", 55))
        assert compiled.matches(self.segment("TLSv1.2", 1466))
        assert compiled.matches(self.segment("TLSv1.3", 1466))

    def test_it_is_also_counted_as_https_and_web(self) -> None:
        packet = self.segment("SSL", 55)
        assert compose_filter(FilterRequest(protocol="HTTPS")).compiled.matches(packet)
        assert compose_filter(FilterRequest(protocol="WEB")).compiled.matches(packet)
        assert packet.is_tls

    def test_dtls_and_plain_tcp_to_443_are_not_tls(self) -> None:
        compiled = compile_filter("tls")
        assert not compiled.matches(self.segment("DTLSv1.2", 120))
        assert not compiled.matches(self.segment("TCP", 54))


class TestTlsTheDnsDissectorParsed:
    """Found by the live cross-check against TShark on real captures.

    A DNS answer of type HTTPS carries an ECH configuration, which TShark's DNS
    dissector parses with its TLS code. The frame's protocol chain then ends
    ``dns:tls``, but TShark's ``tls`` filter does not match it - and neither
    should the HTTPS/TLS view.
    """

    def answer(self) -> CapturedPacket:
        return make(
            "dns_https_answer", src_ip=SERVER, dst_ip=MONITOR, src_port=53, dst_port=50020,
            transport="UDP", layers=("ETH", "ETHERTYPE", "IP", "UDP", "DNS", "TLS"),
            protocol="DNS", dns_query="example.com", dns_response=True, direction="INCOMING",
        )

    def test_it_is_dns_and_not_tls(self) -> None:
        packet = self.answer()
        assert compile_filter("dns").matches(packet)
        assert not compile_filter("tls").matches(packet)
        assert not compile_filter("ssl").matches(packet)
        assert not packet.is_tls

    def test_it_is_in_neither_the_https_nor_the_web_view(self) -> None:
        packet = self.answer()
        assert not compose_filter(FilterRequest(protocol="HTTPS")).compiled.matches(packet)
        assert not compose_filter(FilterRequest(protocol="WEB")).compiled.matches(packet)

    def test_the_protocol_statistics_do_not_count_it_as_tls(self) -> None:
        packet = self.answer()
        assert not module.protocol_present(packet, "tls")
        assert module.protocol_present(packet, "dns")

    def test_tls_carried_by_quic_is_still_tls(self) -> None:
        packet = make(
            "quic_handshake", src_ip=MONITOR, dst_ip=SERVER, src_port=50021, dst_port=443,
            transport="UDP", layers=("ETH", "ETHERTYPE", "IP", "UDP", "QUIC", "TLS"),
            protocol="QUIC", direction="OUTGOING",
        )
        assert compile_filter("tls").matches(packet)
        assert packet.is_tls


class TestTheSitesView:
    """Names this computer connected to or looked up, each from a decoded field.

    HTTPS server names come from the TLS handshake (SNI), HTTP hosts from real
    HTTP requests and DNS names from queries. Responses repeat the question,
    mDNS and LLMNR are local service discovery, and reverse lookups name
    addresses rather than sites, so none of those is listed.
    """

    def sites(self) -> Any:
        return compose_filter(FilterRequest(protocol="SITES"))

    def test_it_lists_https_names_http_hosts_and_dns_queries(self) -> None:
        compiled = self.sites().compiled
        assert {name for name, packet in PACKETS.items() if compiled.matches(packet)} == {
            "tls_client_hello", "http_request", "dns_query",
        }

    def test_responses_local_discovery_and_reverse_lookups_are_not_sites(self) -> None:
        compiled = self.sites().compiled
        common: dict[str, Any] = {
            "src_ip": MONITOR, "dst_ip": SERVER, "src_port": 50030, "dst_port": 53,
            "transport": "UDP", "direction": "OUTGOING",
        }
        for packet in (
            make("dns_response", layers=("ETH", "ETHERTYPE", "IP", "UDP", "DNS"),
                 dns_query="example.com", dns_response=True, **common),
            make("mdns_query", layers=("ETH", "ETHERTYPE", "IP", "UDP", "MDNS"),
                 dns_query="printer.local", dns_response=False, **common),
            make("llmnr_query", layers=("ETH", "ETHERTYPE", "IP", "UDP", "LLMNR"),
                 dns_query="printer", dns_response=False, **common),
            make("reverse_lookup", layers=("ETH", "ETHERTYPE", "IP", "UDP", "DNS"),
                 dns_query="20.100.51.198.in-addr.arpa", dns_response=False, **common),
        ):
            assert not compiled.matches(packet), packet.raw_summary

    def test_a_client_hello_without_a_server_name_is_not_listed(self) -> None:
        packet = make(
            "hello_without_sni", src_ip=MONITOR, dst_ip=SERVER, src_port=50031, dst_port=443,
            transport="TCP", layers=("ETH", "ETHERTYPE", "IP", "TCP", "TLS"),
            tls_handshake_type=1, direction="OUTGOING",
        )
        assert not self.sites().compiled.matches(packet)

    def test_an_ssdp_host_header_is_not_a_site(self) -> None:
        """SSDP borrows HTTP syntax, Host header included; it is not HTTP."""
        packet = make(
            "ssdp_notify", src_ip=MONITOR, dst_ip="239.255.255.250", src_port=50032,
            dst_port=1900, transport="UDP", layers=("ETH", "ETHERTYPE", "IP", "UDP", "SSDP"),
            http_method="NOTIFY", http_host="239.255.255.250:1900", direction="OUTGOING",
        )
        assert not self.sites().compiled.matches(packet)

    def test_it_shows_the_https_notice_and_combines_with_a_direction(self) -> None:
        composed = compose_filter(FilterRequest(protocol="SITES", direction="INCOMING"))
        assert self.sites().encrypted and composed.encrypted
        assert composed.label == "Sites · Incoming"
        assert not composed.compiled.matches(PACKETS["tls_client_hello"])  # outgoing
