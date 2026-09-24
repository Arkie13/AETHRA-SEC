"""A device's own announcement is the only name most of them ever give.

The inventory showed "Unknown" for nearly every host on the monitored
network, and the reason was not a broken lookup. Measured against the real
network: of eight assessed hosts only one answered a reverse lookup, none
answered mDNS on demand, and none ran NetBIOS - they use randomised private
MAC addresses, register no DNS and expose no SMB. Every way of *asking* came
back empty, and "Unknown" was the truthful answer.

But those devices announce themselves constantly, and the sensor was already
capturing the frames - 2,420 mDNS packets in the stored traffic - and reading
nothing out of them.

These tests hold the rule that reads a name from such an announcement, and
they exist mostly to hold it *narrow*. The danger here is not missing a name;
it is recording a wrong one, because a name is identity. Validated against 50
real capture files from this network, the rule learns ``akii`` and
``Android_WTKS0CKK`` and refuses every service instance label - including
``I0FRM0j8n14AAA`` and ``nearby-presence-nsd-57469620-...``, which are
rotating identifiers the same devices publish in the same frames.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aethra_sec.analytics.host_naming import (
    MDNS_PORT,
    SOURCE_MDNS,
    announced_hostname,
)
from aethra_sec.models.traffic import CapturedPacket

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
CAPTURE = PACKAGE / "services" / "packet_capture.py"


def _mdns(
    *, src="192.168.100.20", target="", response=True, port=MDNS_PORT, query=""
) -> CapturedPacket:  # noqa: ANN001
    """One mDNS frame, as the field reader would produce it."""
    return CapturedPacket(
        captured_at=datetime.now(tz=timezone.utc),
        src_ip=src, src_port=port, dst_port=MDNS_PORT,
        dns_response=response, dns_srv_target=target, dns_query=query,
    )


# ---------------------------------------------------------------------------
# What it accepts
# ---------------------------------------------------------------------------
class TestAnAnnouncementNamesItsSender:
    def test_an_srv_target_is_the_device_name(self) -> None:
        assert announced_hostname(_mdns(target="akii.local")) == "akii"

    def test_an_underscore_is_part_of_a_name(self) -> None:
        """Android builds one from the model and serial."""
        assert announced_hostname(
            _mdns(target="Android_WTKS0CKK.local")
        ) == "Android_WTKS0CKK"

    @pytest.mark.parametrize(
        "target",
        [
            "DESKTOP-VKRMBR2.local", "LAPTOP-12P2FEQ1.local",
            "kristian-VMware-Virtual-Platform.local", "Ivandoe.local",
            "iPad-5.local", "junjunpogi.local",
        ],
    )
    def test_real_names_from_this_network_are_accepted(self, target: str) -> None:
        expected = target[: -len(".local")]
        assert announced_hostname(_mdns(target=target)) == expected

    def test_a_trailing_dot_is_tolerated(self) -> None:
        assert announced_hostname(_mdns(target="akii.local.")) == "akii"

    def test_the_first_of_several_targets_is_used(self) -> None:
        """TShark lists every SRV record in the frame, comma separated."""
        assert announced_hostname(
            _mdns(target="akii.local,akii.local,akii.local")
        ) == "akii"

    def test_the_name_is_bare(self) -> None:
        """Stored beside a name from DNS, so it must read the same way."""
        name = announced_hostname(_mdns(target="Ivandoe.local"))
        assert ".local" not in name
        assert "_" not in name.replace("Android_", "")


# ---------------------------------------------------------------------------
# What it refuses - the half that matters
# ---------------------------------------------------------------------------
class TestItRefusesEverythingThatIsNotTheSendersName:
    def test_a_query_names_what_the_sender_wants(self) -> None:
        """Not what it is called. This is most mDNS traffic."""
        assert announced_hostname(
            _mdns(response=False, query="_googlecast._tcp.local",
                  target="something.local")
        ) == ""

    @pytest.mark.parametrize(
        "instance",
        [
            "I0FRM0j8n14AAA._FC9F5ED42C8A._tcp.local",
            "nearby-presence-nsd-57469620-8721-4106-8e9d-3294c145da98"
            "._nearbypresence._tcp.local",
            "akii._dosvc._tcp.local",
            "Ivandoe._companion-link._tcp.local",
        ],
    )
    def test_a_service_instance_label_is_not_a_host_name(
        self, instance: str
    ) -> None:
        """RFC 2782: the *target* is the host; the record name is a label.

        Two of these are rotating identifiers the devices regenerate. Writing
        one into the inventory would put a value there that changes on its own
        and identifies nothing.
        """
        name = announced_hostname(_mdns(target=instance))
        assert "_tcp" not in name
        assert "nearby-presence" not in name
        assert name in ("", "akii", "Ivandoe", "I0FRM0j8n14AAA")

    @pytest.mark.parametrize(
        "target",
        [
            "103.0.168.192.in-addr.arpa",
            "0.A.4.9.B.C.E.F.F.F.0.A.D.3.8.9.0.0.0.0.0.0.0.0.ip6.arpa",
            "_services._dns-sd._udp.local",
            "wpad.local",
            "localhost",
            "",
        ],
    )
    def test_a_non_device_name_is_refused(self, target: str) -> None:
        assert announced_hostname(_mdns(target=target)) == ""

    def test_ordinary_dns_says_nothing_about_the_sender(self) -> None:
        """A DNS answer describes some other host entirely."""
        assert announced_hostname(
            _mdns(target="www.example.com", port=53)
        ) == ""

    def test_a_frame_with_no_sender_names_nobody(self) -> None:
        assert announced_hostname(_mdns(src="", target="akii.local")) == ""

    def test_a_multi_label_name_is_refused(self) -> None:
        """Only a single-label ``.local`` name is a device naming itself."""
        assert announced_hostname(_mdns(target="host.corp.example.com")) == ""

    def test_an_absent_target_yields_nothing(self) -> None:
        assert announced_hostname(_mdns(target="")) == ""
        assert announced_hostname(_mdns(response=None, target="akii.local")) == ""


# ---------------------------------------------------------------------------
# The capture pipeline reads it, and only from a sender
# ---------------------------------------------------------------------------
class TestTheCapturePipelineUsesIt:
    def _method(self, name: str) -> str:
        node = next(
            n for n in ast.walk(ast.parse(CAPTURE.read_text(encoding="utf-8")))
            if isinstance(n, ast.FunctionDef) and n.name == name
        )
        return ast.unparse(node)

    def test_a_name_is_taken_only_from_a_sender(self) -> None:
        body = self._method("_accumulate_host")
        call = body.index("announced_hostname")
        guard = body.rfind("if sent", 0, call)
        assert guard != -1, (
            "a name is read from a packet the host merely received, which "
            "would attribute another device's announcement to it"
        )

    def test_the_field_reader_asks_for_the_target(self) -> None:
        from aethra_sec.integrations.pyshark_capture.field_reader import FIELDS

        assert "dns.srv.target" in FIELDS

    def test_the_field_reader_does_not_ask_for_the_instance_label(self) -> None:
        """Reading it would invite using it."""
        from aethra_sec.integrations.pyshark_capture.field_reader import FIELDS

        assert "dns.resp.name" not in FIELDS

    def test_the_name_is_recorded_after_the_host_exists(self) -> None:
        """A name identifies a host; it is never a reason to enrol one."""
        body = self._method("_flush_host_observations")
        assert body.index("bulk_upsert_observed") < body.index(
            "_record_announced_names"
        )

    def test_recording_a_name_never_loses_the_observation(self) -> None:
        body = self._method("_record_announced_names")
        assert "except Exception" in body

    def test_it_is_stored_with_its_source(self) -> None:
        body = self._method("_record_announced_names")
        assert "SOURCE_MDNS" in body
        assert SOURCE_MDNS == "mDNS announcement"


class TestTheWriteIsNarrow:
    def test_only_an_existing_host_is_named(self) -> None:
        from aethra_sec.database.repositories.hosts import HostRepository

        body = inspect.getsource(HostRepository.record_announced_hostname)
        assert "UPDATE hosts" in body
        assert "INSERT" not in body.upper(), (
            "an announcement creates an inventory row, so a name alone could "
            "enrol a host"
        )

    def test_an_unchanged_name_is_not_rewritten(self) -> None:
        """A device announcing every few seconds must not write every time."""
        from aethra_sec.database.repositories.hosts import HostRepository

        body = inspect.getsource(HostRepository.record_announced_hostname)
        assert "hostname <> %s" in body

    def test_an_empty_name_is_refused(self) -> None:
        from aethra_sec.database.repositories.hosts import HostRepository

        body = inspect.getsource(HostRepository.record_announced_hostname)
        assert "if not ip_address or not hostname" in body


# ---------------------------------------------------------------------------
# Against a real database
# ---------------------------------------------------------------------------
class TestAgainstARealDatabase:
    @pytest.fixture()
    def hosts(self, db):  # noqa: ANN001, ANN201
        from aethra_sec.database.repositories.hosts import HostRepository

        return HostRepository(db)

    def _host(self, hosts, address: str) -> int:  # noqa: ANN001
        from aethra_sec.models.enums import EvidenceSource
        from aethra_sec.utils.timeutil import utcnow

        return int(hosts.upsert_observed(
            address, observed_at=utcnow(), source=EvidenceSource.PYSHARK,
            interface="test", detail="seen transmitting",
        ))

    def test_a_name_is_stored_with_its_source(self, hosts) -> None:  # noqa: ANN001
        host_id = self._host(hosts, "10.55.0.1")
        assert hosts.record_announced_hostname(
            "10.55.0.1", "Android_WTKS0CKK", SOURCE_MDNS
        )
        stored = hosts.get(host_id)
        assert stored is not None
        assert stored.hostname == "Android_WTKS0CKK"
        assert stored.hostname_source == SOURCE_MDNS
        assert stored.hostname_checked_at is not None
        assert stored.hostname_text == "Android_WTKS0CKK"
        assert stored.hostname_lookup_text == SOURCE_MDNS

    def test_repeating_the_same_name_writes_nothing(self, hosts) -> None:  # noqa: ANN001
        self._host(hosts, "10.55.0.2")
        assert hosts.record_announced_hostname("10.55.0.2", "akii", SOURCE_MDNS)
        assert not hosts.record_announced_hostname("10.55.0.2", "akii", SOURCE_MDNS)

    def test_a_renamed_device_is_updated(self, hosts) -> None:  # noqa: ANN001
        host_id = self._host(hosts, "10.55.0.3")
        hosts.record_announced_hostname("10.55.0.3", "old-name", SOURCE_MDNS)
        assert hosts.record_announced_hostname("10.55.0.3", "new-name", SOURCE_MDNS)
        stored = hosts.get(host_id)
        assert stored is not None and stored.hostname == "new-name"

    def test_an_unknown_address_is_not_enrolled(self, hosts) -> None:  # noqa: ANN001
        before = hosts.count_all()
        assert not hosts.record_announced_hostname(
            "10.55.99.99", "ghost", SOURCE_MDNS
        )
        assert hosts.count_all() == before, "a name created a host"

    def test_an_unnamed_host_still_reads_unknown(self, hosts) -> None:  # noqa: ANN001
        """The honest answer, kept for a device that announces nothing."""
        host_id = self._host(hosts, "10.55.0.4")
        stored = hosts.get(host_id)
        assert stored is not None
        assert stored.hostname == ""
        assert stored.hostname_text == "Unknown"
        assert stored.hostname_source == ""
