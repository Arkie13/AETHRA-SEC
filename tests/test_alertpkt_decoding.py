"""Decoding a real Snort ``Alertpkt`` datagram (§21).

The fixture beside this file is a genuine datagram captured from Snort 2.9.20
on x86-64 over ``alert_unixsock``, produced by a real ICMP echo request against
the loopback interface matching a local rule. Only the zeroed middle of the
packet buffer has been blanked, so every byte the decoder reads is Snort's own.

It exists because two assumptions in the decoder were wrong, and both were
invisible without a real sensor to test against:

* ``Event`` was read from the exact end of the datagram. On this build it
  begins 100 bytes from the end, with alignment padding after it, so the
  decoder read zeroes, correctly rejected them, and reported every alert as
  ``[?:?:?]`` with no signature id.
* Once the event was searched for rather than assumed, the field bounds alone
  were too weak to identify it: a window a few bytes off the true event
  satisfied every one of them and decoded ``classification`` as the signature
  id, turning sid 1000001 into sid 29. The reference timeval is what settles
  it, because only the true alignment yields a plausible date.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aethra_sec.integrations.snort.alertpkt import (
    EVENT_SEARCH_BYTES,
    _decode_event,
    _plausible_event,
    decode_alertpkt,
)

FIXTURE = Path(__file__).parent / "fixtures" / "alertpkt_snort2920_x86_64.bin"

#: What Snort actually reported for the captured alert.
EXPECTED_MESSAGE = "ICMP echo request"
EXPECTED_GENERATOR = 1
EXPECTED_SID = 1000001
EXPECTED_REVISION = 1
EXPECTED_PRIORITY = 3


@pytest.fixture(scope="module")
def datagram() -> bytes:
    """The captured Alertpkt bytes."""
    return FIXTURE.read_bytes()


class TestRealDatagram:
    """What the decoder must get right on a real sensor's output."""

    def test_the_fixture_is_the_size_snort_actually_sends(
        self, datagram: bytes
    ) -> None:
        """65,928 bytes - larger than a 65,535 receive buffer would hold."""
        assert len(datagram) == 65_928

    def test_the_alert_message_is_recovered(self, datagram: bytes) -> None:
        """The rule's msg option, read from the head of the struct."""
        decoded = decode_alertpkt(datagram)
        assert decoded is not None
        assert decoded.message == EXPECTED_MESSAGE

    def test_the_signature_identity_is_recovered(self, datagram: bytes) -> None:
        """gid:sid:rev is what makes an alert traceable back to its rule.

        Without it the console showed "[?:?:?]" and stored no signature id.
        """
        decoded = decode_alertpkt(datagram)
        assert decoded is not None
        assert decoded.generator_id == EXPECTED_GENERATOR
        assert decoded.signature_id == EXPECTED_SID
        assert decoded.revision == EXPECTED_REVISION

    def test_the_signature_id_is_not_the_classification(
        self, datagram: bytes
    ) -> None:
        """The specific false positive the timeval check rules out.

        A window 8 bytes off the true event decodes classification (29) as the
        signature id, and every field bound still passes.
        """
        decoded = decode_alertpkt(datagram)
        assert decoded is not None
        assert decoded.signature_id != 29

    def test_the_priority_is_recovered(self, datagram: bytes) -> None:
        """Priority drives the severity the alert is stored with."""
        decoded = decode_alertpkt(datagram)
        assert decoded is not None
        assert decoded.priority == EXPECTED_PRIORITY

    def test_the_embedded_packet_yields_endpoints(self, datagram: bytes) -> None:
        """An alert without addresses cannot be correlated to a host."""
        decoded = decode_alertpkt(datagram)
        assert decoded is not None
        assert decoded.src_ip == "127.0.0.1"
        assert decoded.dst_ip == "127.0.0.1"
        assert decoded.protocol == "ICMP"

    def test_the_layout_it_chose_is_reported(self, datagram: bytes) -> None:
        """So a mis-decode on another build can be diagnosed from the record."""
        decoded = decode_alertpkt(datagram)
        assert decoded is not None
        assert "event:" in decoded.layout
        assert "pkthdr:" in decoded.layout


class TestEventLocation:
    """The event is searched for, not assumed to be at either edge."""

    def test_the_event_is_not_at_the_end_of_this_datagram(
        self, datagram: bytes
    ) -> None:
        """Which is exactly why anchoring on the tail failed."""
        found = _decode_event(datagram)
        assert found is not None
        _fields, _layout, start = found
        assert start < len(datagram) - 48

    def test_the_reported_offset_is_where_the_signature_id_lives(
        self, datagram: bytes
    ) -> None:
        """Ground truth: the sid appears 4 bytes into the event."""
        found = _decode_event(datagram)
        assert found is not None
        _fields, _layout, start = found
        assert datagram[start + 4:start + 8] == struct.pack("<I", EXPECTED_SID)

    def test_the_search_window_is_bounded(self) -> None:
        """A wider search could decode packet bytes as an event."""
        assert 0 < EVENT_SEARCH_BYTES <= 1024


class TestPlausibility:
    """What the decoder will and will not accept as an event."""

    def _event(self, **overrides: int) -> tuple[int, ...]:
        """The captured event's field values, with optional damage."""
        fields = {
            "generator": EXPECTED_GENERATOR, "signature": EXPECTED_SID,
            "revision": EXPECTED_REVISION, "classification": 29,
            "priority": EXPECTED_PRIORITY, "event_id": 1, "reference": 1,
            "ref_time": 1_787_277_934,
        }
        fields.update(overrides)
        return tuple(fields.values())

    def test_the_captured_event_is_accepted(self) -> None:
        """The baseline the other cases are damage against."""
        assert _plausible_event(self._event())

    def test_zero_padding_is_rejected(self) -> None:
        """A run of zeroes must never be read as an alert."""
        assert not _plausible_event((0,) * 8)

    def test_an_event_without_a_signature_id_is_rejected(self) -> None:
        """Every real alert carries one; a zero means wrong alignment."""
        assert not _plausible_event(self._event(signature=0))

    def test_an_impossible_reference_time_is_rejected(self) -> None:
        """The check that separates the true event from a near miss."""
        assert not _plausible_event(self._event(ref_time=1))
        assert not _plausible_event(self._event(ref_time=2**40))

    def test_an_absurd_generator_is_rejected(self) -> None:
        """Reading the sid as the generator is the classic misalignment."""
        assert not _plausible_event(self._event(generator=1_000_001))


class TestFailureIsReported:
    """A datagram that cannot be decoded is never guessed at."""

    def test_noise_decodes_to_nothing(self) -> None:
        """The caller counts a parse failure, which the interface shows."""
        assert decode_alertpkt(b"\x00" * 4096) is None

    def test_an_empty_datagram_decodes_to_nothing(self) -> None:
        """Rather than raising into the read loop and killing the transport."""
        assert decode_alertpkt(b"") is None

    def test_a_truncated_datagram_does_not_raise(self, datagram: bytes) -> None:
        """A short read must not take the ingest down.

        The decoder raising StopIteration here is what stopped the transport
        dead, reporting only an empty error message.
        """
        for cut in (64, 512, 4096, 65_535):
            decode_alertpkt(datagram[:cut])
