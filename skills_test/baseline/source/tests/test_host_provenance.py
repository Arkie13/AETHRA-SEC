"""Where a host record came from, and what it is allowed to claim.

The inventory had grown to 2,005 rows on a laboratory network of a few
devices. Tracing them showed three separate ways a row could assert more than
had been observed:

* ``discovery_source`` defaulted to PYSHARK, so a row inserted without naming
  a source was stamped as a packet-capture discovery it never had;
* addresses no device can own - multicast groups, ``fe80::`` link-local, the
  subnet broadcast - were enrolled as hosts;
* an earlier capture pipeline entered an address it had only seen *named* on
  the wire, so when something swept 192.168.1.0/24 all 256 addresses became
  "hosts" in about seven seconds, most with no MAC.

These tests hold the boundary: a row states how it was established, and an
address that was never observed transmitting never claims to have been.
"""

from __future__ import annotations

import inspect

from aethra_sec.models.enums import EvidenceSource
from aethra_sec.utils.net import host_address_rejection


class TestAnAddressMustBeAHost:
    """Rule 13: validate before insertion, without over-rejecting."""

    def test_a_multicast_group_is_not_a_host(self) -> None:
        for address in ("224.0.0.251", "239.255.255.250", "ff02::fb", "ff02::1"):
            assert "multicast" in host_address_rejection(address), address

    def test_link_local_is_not_a_host(self) -> None:
        for address in ("fe80::1", "169.254.10.4"):
            assert host_address_rejection(address), address

    def test_the_unspecified_and_loopback_addresses_are_not_hosts(self) -> None:
        assert host_address_rejection("0.0.0.0")
        assert host_address_rejection("::")
        assert host_address_rejection("127.0.0.1")
        assert host_address_rejection("")

    def test_malformed_input_is_rejected_without_raising(self) -> None:
        assert host_address_rejection("not-an-ip")
        assert host_address_rejection("192.168.1.999")

    def test_the_subnet_broadcast_and_network_are_not_hosts(self) -> None:
        import ipaddress

        networks = (ipaddress.ip_network("192.168.1.0/24"),)
        assert "broadcast" in host_address_rejection("192.168.1.255", networks)
        assert "network" in host_address_rejection("192.168.1.0", networks)
        assert host_address_rejection("255.255.255.255") == "the broadcast address"

    def test_an_ordinary_private_address_is_accepted(self) -> None:
        """Including one with no hostname - rule 6."""
        import ipaddress

        networks = (ipaddress.ip_network("192.168.1.0/24"),)
        for address in ("192.168.1.193", "192.168.1.1", "10.0.0.7", "172.16.4.9"):
            assert host_address_rejection(address, networks) == "", address

    def test_a_point_to_point_link_has_no_broadcast_address(self) -> None:
        """A /31 is all usable; rejecting either end would lose a real host."""
        import ipaddress

        networks = (ipaddress.ip_network("10.0.0.0/31"),)
        assert host_address_rejection("10.0.0.0", networks) == ""
        assert host_address_rejection("10.0.0.1", networks) == ""


class TestProvenanceIsStatedNotAssumed:
    def test_the_column_no_longer_defaults_to_a_subsystem(self) -> None:
        """A default of PYSHARK invents provenance for anything that omits it."""
        from aethra_sec.database import schema

        assert "discovery_source    VARCHAR(16)  NOT NULL DEFAULT 'LEGACY'" in (
            schema.HOSTS
        )

    def test_every_writer_names_its_source(self) -> None:
        """No default on the write path either."""
        from aethra_sec.database.repositories.hosts import HostRepository

        for method in (
            HostRepository.upsert_observed,
            HostRepository.bulk_upsert_observed,
        ):
            parameter = inspect.signature(method).parameters["source"]
            assert parameter.default is inspect.Parameter.empty, (
                f"{method.__name__} can insert a host without stating its source"
            )

    def test_an_unreadable_source_falls_back_to_legacy(self) -> None:
        """Not to a subsystem: that is how a row acquires a false origin."""
        source = inspect.getsource(
            inspect.getmodule(EvidenceSource)  # sanity: the enum carries LEGACY
        )
        assert "LEGACY" in source
        assert EvidenceSource.parse("nonsense", EvidenceSource.LEGACY) is (
            EvidenceSource.LEGACY
        )

    def test_legacy_is_not_treated_as_evidence(self) -> None:
        assert EvidenceSource.LEGACY.is_evidenced is False
        for real in (
            EvidenceSource.PYSHARK, EvidenceSource.NMAP,
            EvidenceSource.SNORT, EvidenceSource.MANUAL,
        ):
            assert real.is_evidenced is True

    def test_legacy_says_so_rather_than_naming_a_tool(self) -> None:
        label = EvidenceSource.LEGACY.label.lower()
        assert "unknown" in label
        for tool in ("pyshark", "nmap", "snort"):
            assert tool not in label


class TestNmapDownIsNotAnObservation:
    """Rules 9 and 12: probing is not observing."""

    def test_a_host_nmap_found_down_is_not_created(self) -> None:
        source = inspect.getsource(
            _nmap_persist()
        )
        assert "find_id_by_ip" in source, (
            "a host Nmap reported down is still being inserted, which is how "
            "scanning a /24 enrols every address in it"
        )

    def test_last_seen_only_moves_when_the_host_answered(self) -> None:
        source = inspect.getsource(_nmap_persist())
        upsert = source.index("upsert_observed")
        guard = source.rindex("if answered:", 0, upsert)
        assert guard < upsert, "last_seen is bumped for a host that never replied"


def _nmap_persist():
    """The Nmap result-persistence routine, whatever it is called."""
    from aethra_sec.services import nmap_service

    for name, member in inspect.getmembers(nmap_service.NmapService):
        if not inspect.isfunction(member):
            continue
        try:
            body = inspect.getsource(member)
        except OSError:  # pragma: no cover
            continue
        if "upsert_observed" in body:
            return member
    raise AssertionError("no method persists Nmap hosts")


class TestTheOfflineNoteDoesNotOutliveTheCondition:
    """Rule 8: a row must not read UP beside 'offline: not observed'."""

    def test_returning_to_up_clears_the_queue_note(self) -> None:
        from aethra_sec.database.repositories.hosts import HostRepository

        for method in (
            HostRepository.upsert_observed,
            HostRepository.bulk_upsert_observed,
        ):
            source = inspect.getsource(method)
            assert "assessment_detail = IF(status = 'DOWN', '', assessment_detail)" in (
                source
            ), f"{method.__name__} leaves the stale offline note in place"

    def test_the_note_is_cleared_before_status_is_set(self) -> None:
        """MySQL evaluates these left to right; order is the whole fix."""
        from aethra_sec.database.repositories.hosts import HostRepository

        source = inspect.getsource(HostRepository.upsert_observed)
        assert source.index("assessment_detail = IF(status") < source.index(
            "\"status = 'UP', \""
        )


class TestLegacyRowsAreKeptButNotScanned:
    """Rules 10 and 11: retain the history, stop acting on it."""

    def test_the_queue_refuses_a_row_it_cannot_vouch_for(self) -> None:
        from aethra_sec.services.assessment_queue import AssessmentQueueService

        source = inspect.getsource(AssessmentQueueService.eligibility)
        assert "EvidenceSource.LEGACY" in source

    def test_the_migration_deletes_nothing(self) -> None:
        from aethra_sec.database import migrations

        source = inspect.getsource(migrations._apply_host_provenance)
        assert "DELETE" not in source.upper().replace("DELETED", ""), (
            "a provenance correction must not remove historical rows"
        )
        # first_seen/last_seen are the observation timeline and are not rewritten.
        for column in ("first_seen", "last_seen"):
            assert f"SET {column}" not in source
            assert f"{column} =" not in source
