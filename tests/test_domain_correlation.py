"""A domain is attributed from observed evidence, or not at all.

Measured on this machine's own browsing, a domain name appears in about 1.4% of
frames while an address appears in all of them: the name rides the handshake
and nothing after it. Correlating the two is the difference between labelling a
handful of rows and labelling the session - measured at 4.7% of outbound frames
before and 48.2% after, on one real 941-packet capture.

The risk in closing that gap is inventing the join. These tests hold the lines
that keep the correlation honest:

* no evidence means no answer, never a plausible one;
* the most recent lookup does not explain an unrelated connection;
* an address whose evidence has aged out goes back to unknown, because
  addresses are reassigned and a stale name is worse than none;
* exact evidence (a ClientHello addressed to the server it names) is never
  overwritten by weaker inference;
* memory is bounded, so a long capture cannot end in an unbounded map.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta

import pytest

from aethra_sec.analytics.domain_correlation import (
    DEFAULT_TTL_SECONDS,
    SOURCE_DNS,
    SOURCE_HTTP_HOST,
    SOURCE_SNI,
    UNKNOWN,
    Attribution,
    DomainResolver,
    learn_from_packet,
)

T0 = datetime(2026, 9, 25, 12, 0, 0)


def _later(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


class _Packet:
    """Only the attributes the learner reads."""

    def __init__(self, **kwargs) -> None:  # noqa: ANN003
        self.captured_at = kwargs.get("captured_at", T0)
        self.dst_ip = kwargs.get("dst_ip", "")
        self.tls_sni = kwargs.get("tls_sni", "")
        self.http_host = kwargs.get("http_host", "")
        self.dns_query = kwargs.get("dns_query", "")
        self.dns_answer_address = kwargs.get("dns_answer_address", "")
        self.dns_response = kwargs.get("dns_response", None)


# ---------------------------------------------------------------------------
# Nothing is invented
# ---------------------------------------------------------------------------
class TestItNeverGuesses:
    def test_an_unseen_address_is_unknown(self) -> None:
        resolver = DomainResolver()
        assert resolver.domain_for("93.184.216.34", T0) == UNKNOWN
        assert resolver.attribution_for("93.184.216.34", T0) is None

    def test_an_empty_address_is_unknown(self) -> None:
        assert DomainResolver().domain_for("", T0) == UNKNOWN

    def test_a_blank_name_is_not_learned(self) -> None:
        resolver = DomainResolver()
        resolver.observe_sni("1.2.3.4", "   ", T0)
        assert resolver.domain_for("1.2.3.4", T0) == UNKNOWN

    def test_the_last_lookup_does_not_explain_another_address(self) -> None:
        """The explicit requirement: recency is not evidence."""
        resolver = DomainResolver()
        resolver.observe_dns_answer("93.184.216.34", "example.com", T0)
        # A connection to a different server, moments later.
        assert resolver.domain_for("151.101.1.140", _later(0.2)) == UNKNOWN

    def test_knowing_one_address_reveals_nothing_about_its_neighbours(self) -> None:
        resolver = DomainResolver()
        resolver.observe_sni("10.0.0.5", "intranet.example", T0)
        assert resolver.domain_for("10.0.0.6", T0) == UNKNOWN


# ---------------------------------------------------------------------------
# Evidence and its strength
# ---------------------------------------------------------------------------
class TestEvidence:
    def test_sni_attributes_the_server_it_was_addressed_to(self) -> None:
        resolver = DomainResolver()
        resolver.observe_sni("93.184.216.34", "example.com", T0)
        found = resolver.attribution_for("93.184.216.34", _later(5))
        assert found is not None
        assert found.domain == "example.com"
        assert found.source == SOURCE_SNI
        assert found.is_exact

    def test_a_dns_answer_is_recorded_as_weaker_evidence(self) -> None:
        resolver = DomainResolver()
        resolver.observe_dns_answer("93.184.216.34", "example.com", T0)
        found = resolver.attribution_for("93.184.216.34", _later(5))
        assert found is not None and found.source == SOURCE_DNS
        assert not found.is_exact, (
            "a DNS answer proves the name resolves here, not that this flow "
            "used that name; presenting it as exact would overstate it"
        )

    def test_exact_evidence_is_not_downgraded_by_a_later_dns_answer(self) -> None:
        resolver = DomainResolver()
        resolver.observe_sni("93.184.216.34", "example.com", T0)
        resolver.observe_dns_answer("93.184.216.34", "cdn.example.net", _later(1))
        found = resolver.attribution_for("93.184.216.34", _later(2))
        assert found is not None
        assert found.source == SOURCE_SNI and found.domain == "example.com"

    def test_fresher_exact_evidence_does_replace_older(self) -> None:
        resolver = DomainResolver()
        resolver.observe_sni("1.2.3.4", "first.example", T0)
        resolver.observe_sni("1.2.3.4", "second.example", _later(30))
        assert resolver.domain_for("1.2.3.4", _later(31)) == "second.example"

    def test_a_trailing_dot_is_normalised(self) -> None:
        """DNS carries the root label; the interface should not show it."""
        resolver = DomainResolver()
        resolver.observe_dns_answer("1.2.3.4", "example.com.", T0)
        assert resolver.domain_for("1.2.3.4", T0) == "example.com"

    def test_an_http_host_port_is_dropped(self) -> None:
        resolver = DomainResolver()
        learn_from_packet(
            resolver, _Packet(dst_ip="1.2.3.4", http_host="example.com:8080")
        )
        assert resolver.domain_for("1.2.3.4", T0) == "example.com"

    def test_describe_names_the_source(self) -> None:
        entry = Attribution("example.com", SOURCE_SNI, T0)
        assert "example.com" in entry.describe() and SOURCE_SNI in entry.describe()


# ---------------------------------------------------------------------------
# Time awareness
# ---------------------------------------------------------------------------
class TestItExpires:
    def test_an_aged_entry_returns_to_unknown(self) -> None:
        resolver = DomainResolver(ttl_seconds=60)
        resolver.observe_sni("1.2.3.4", "example.com", T0)
        assert resolver.domain_for("1.2.3.4", _later(59)) == "example.com"
        assert resolver.domain_for("1.2.3.4", _later(61)) == UNKNOWN

    def test_an_expired_entry_is_dropped_not_merely_hidden(self) -> None:
        resolver = DomainResolver(ttl_seconds=10)
        resolver.observe_sni("1.2.3.4", "example.com", T0)
        resolver.domain_for("1.2.3.4", _later(11))
        assert len(resolver) == 0

    def test_purge_removes_every_aged_entry(self) -> None:
        resolver = DomainResolver(ttl_seconds=10)
        for n in range(5):
            resolver.observe_sni(f"1.2.3.{n}", f"h{n}.example", T0)
        resolver.observe_sni("9.9.9.9", "fresh.example", _later(20))
        assert resolver.purge_expired(_later(21)) == 5
        assert len(resolver) == 1

    def test_the_default_ttl_is_short_enough_for_reassigned_addresses(self) -> None:
        assert 60 <= DEFAULT_TTL_SECONDS <= 3600


# ---------------------------------------------------------------------------
# Bounded memory
# ---------------------------------------------------------------------------
class TestItIsBounded:
    def test_the_map_never_exceeds_its_cap(self) -> None:
        resolver = DomainResolver(max_entries=50)
        for n in range(500):
            resolver.observe_sni(f"10.0.{n // 256}.{n % 256}", f"h{n}.example", T0)
        assert len(resolver) == 50

    def test_eviction_is_least_recently_used(self) -> None:
        resolver = DomainResolver(max_entries=3)
        for n in (1, 2, 3):
            resolver.observe_sni(f"1.1.1.{n}", f"h{n}.example", T0)
        resolver.domain_for("1.1.1.1", T0)  # touch the oldest
        resolver.observe_sni("1.1.1.4", "h4.example", T0)
        assert resolver.domain_for("1.1.1.1", T0) == "h1.example"
        assert resolver.domain_for("1.1.1.2", T0) == UNKNOWN

    def test_evictions_are_counted_not_silent(self) -> None:
        resolver = DomainResolver(max_entries=2)
        for n in range(6):
            resolver.observe_sni(f"1.1.1.{n}", f"h{n}.example", T0)
        assert resolver.statistics()["evicted"] == 4

    def test_statistics_report_real_counters(self) -> None:
        resolver = DomainResolver(max_entries=10, ttl_seconds=30)
        resolver.observe_sni("1.2.3.4", "example.com", T0)
        resolver.domain_for("1.2.3.4", T0)
        resolver.domain_for("9.9.9.9", T0)
        stats = resolver.statistics()
        assert stats["entries"] == 1
        assert stats["hits"] == 1 and stats["misses"] == 1
        assert stats["max_entries"] == 10 and stats["ttl_seconds"] == 30


# ---------------------------------------------------------------------------
# Reading packets
# ---------------------------------------------------------------------------
class TestLearningFromPackets:
    def test_a_client_hello_teaches_the_server_address(self) -> None:
        resolver = DomainResolver()
        learn_from_packet(
            resolver, _Packet(dst_ip="93.184.216.34", tls_sni="example.com")
        )
        assert resolver.domain_for("93.184.216.34", T0) == "example.com"

    def test_a_dns_response_teaches_the_resolved_address(self) -> None:
        resolver = DomainResolver()
        learn_from_packet(
            resolver,
            _Packet(
                dst_ip="172.20.10.2",
                dns_query="example.com",
                dns_answer_address="93.184.216.34",
                dns_response=True,
            ),
        )
        assert resolver.domain_for("93.184.216.34", T0) == "example.com"

    def test_a_dns_query_teaches_nothing_because_it_carries_no_address(self) -> None:
        resolver = DomainResolver()
        learn_from_packet(
            resolver,
            _Packet(dst_ip="172.20.10.1", dns_query="example.com", dns_response=False),
        )
        assert len(resolver) == 0

    def test_a_packet_without_a_timestamp_is_ignored(self) -> None:
        resolver = DomainResolver()
        packet = _Packet(dst_ip="1.2.3.4", tls_sni="example.com")
        packet.captured_at = None
        learn_from_packet(resolver, packet)
        assert len(resolver) == 0

    def test_an_ordinary_data_frame_teaches_nothing(self) -> None:
        """The 98.6% case: an address and no name anywhere in the frame."""
        resolver = DomainResolver()
        learn_from_packet(resolver, _Packet(dst_ip="93.184.216.34"))
        assert len(resolver) == 0


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
class TestItIsSafeAcrossThreads:
    def test_concurrent_learning_and_reading_do_not_corrupt_it(self) -> None:
        """The capture worker writes while the UI reads."""
        resolver = DomainResolver(max_entries=256)
        errors: list[BaseException] = []

        def writer(base: int) -> None:
            try:
                for n in range(400):
                    resolver.observe_sni(f"10.{base}.{n // 256}.{n % 256}",
                                         f"h{n}.example", T0)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        def reader() -> None:
            try:
                for n in range(400):
                    resolver.domain_for(f"10.1.{n // 256}.{n % 256}", T0)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        assert len(resolver) <= 256


# ---------------------------------------------------------------------------
# The capture path supplies what this needs
# ---------------------------------------------------------------------------
class TestTheCaptureCarriesTheEvidence:
    def test_the_dns_answer_fields_are_requested(self) -> None:
        """Removed on 2026-09-22 with the mDNS work; without them the join
        between a name and later traffic cannot be made at all."""
        from aethra_sec.integrations.pyshark_capture.field_reader import FIELDS

        assert "dns.a" in FIELDS
        assert "dns.aaaa" in FIELDS

    def test_the_packet_model_carries_the_answer_address(self) -> None:
        from aethra_sec.models.traffic import CapturedPacket

        assert "dns_answer_address" in CapturedPacket.__dataclass_fields__

    def test_the_info_column_is_still_last(self) -> None:
        """Positional parsing is only safe while free text comes last."""
        from aethra_sec.integrations.pyshark_capture.field_reader import FIELDS

        assert FIELDS[-1] == "_ws.col.info"

    def test_the_core_field_set_is_unchanged(self) -> None:
        from aethra_sec.integrations.pyshark_capture.field_reader import (
            CORE_FIELD_COUNT,
            FIELDS,
        )

        assert FIELDS[CORE_FIELD_COUNT - 1] == "arp.dst.hw_mac"
        assert FIELDS.index("dns.a") >= CORE_FIELD_COUNT
