"""Interface selection for Nmap scans (§39).

Regression cover for a scan that reported a live host as down. Two adapters
claimed 192.168.1.0/24 - a VMware adapter on 192.168.1.1 and Wi-Fi on
192.168.1.7 - and Nmap's route metric preferred the VMware one, which cannot
reach the LAN. Measured against a live host at 192.168.1.33 within seconds of
each other:

    nmap -sn -e eth8 192.168.1.33  ->  Host is up (0.063s latency)
    nmap -sn -e eth5 192.168.1.33  ->  Host seems down

"0 hosts up" was then recorded as a fact about the network.
"""

from __future__ import annotations

import pytest

from aethra_sec.integrations.nmap import routing
from aethra_sec.integrations.nmap.routing import RouteChoice, resolve_route


class _Interface:
    """Stand-in for one entry of ``nmap --iflist``."""

    def __init__(self, device: str, address: str) -> None:
        self.device = device
        self.address = address


#: The contested subnet exactly as this machine reports it.
INTERFACES = (
    _Interface("eth5", "192.168.1.1/24"),   # VMware, wins the route metric
    _Interface("eth8", "192.168.1.7/24"),   # Wi-Fi, actually reaches the LAN
)


class TestTargetsWithoutOneRoute:
    """A target with no single route must not be pinned to a guess."""

    @pytest.mark.parametrize(
        "target", ["192.168.1.0/24", "192.168.1.1-50", "scanme.nmap.org", ""]
    )
    def test_declines_rather_than_guessing(self, target: str) -> None:
        choice = resolve_route(target, INTERFACES)
        assert choice.device == ""
        assert choice.resolved is False
        # An unresolved choice still has to explain itself to the operator.
        assert choice.reason


class TestRouteBasedSelection:
    """The OS route decides, not the adapter's name or address order."""

    def test_route_picks_the_matching_device(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(routing, "arp_source_address", lambda _t: "")
        monkeypatch.setattr(
            routing, "_windows_route", lambda _t: ("192.168.1.7", "Wi-Fi")
        )
        choice = resolve_route("192.168.1.33", INTERFACES)
        assert choice.device == "eth8"
        assert choice.resolved is True

    def test_unmatched_source_is_not_pinned(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A source address no Nmap device reports must not be forced."""
        monkeypatch.setattr(routing, "arp_source_address", lambda _t: "")
        monkeypatch.setattr(
            routing, "_windows_route", lambda _t: ("10.9.9.9", "Some adapter")
        )
        choice = resolve_route("192.168.1.33", INTERFACES)
        assert choice.device == ""
        assert choice.resolved is False
        assert "10.9.9.9" in choice.reason

    def test_no_route_at_all_is_not_pinned(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(routing, "arp_source_address", lambda _t: "")
        monkeypatch.setattr(routing, "_windows_route", lambda _t: ("", ""))
        monkeypatch.setattr(routing, "_source_address_via_socket", lambda _t: "")
        choice = resolve_route("192.168.1.33", INTERFACES)
        assert choice.device == ""
        assert choice.resolved is False


class TestArpEvidenceWins:
    """An ARP entry is evidence; the route metric is only a preference."""

    def test_arp_overrides_a_route_to_an_adapter_that_cannot_reach(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The exact failure that reported a live host as down.

        The routing table prefers the VMware adapter, but the target's ARP
        entry sits on Wi-Fi - that adapter has demonstrably reached it at layer
        two, so the probe belongs there.
        """
        monkeypatch.setattr(
            routing, "_windows_route", lambda _t: ("192.168.1.1", "VMnet1")
        )
        monkeypatch.setattr(
            routing, "arp_source_address", lambda _t: "192.168.1.7"
        )
        choice = resolve_route("192.168.1.33", INTERFACES)
        assert choice.device == "eth8"
        assert choice.resolved is True
        assert "ARP" in choice.reason

    def test_without_an_arp_entry_the_route_still_decides(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No ARP entry is not evidence of anything, so it must not veto."""
        monkeypatch.setattr(routing, "arp_source_address", lambda _t: "")
        monkeypatch.setattr(
            routing, "_windows_route", lambda _t: ("192.168.1.1", "VMnet1")
        )
        choice = resolve_route("192.168.1.33", INTERFACES)
        assert choice.device == "eth5"


class TestArpParsing:
    """Only a complete ARP entry counts as evidence."""

    def _arp(self, monkeypatch: pytest.MonkeyPatch, stdout: str, code: int = 0):
        class _Done:
            returncode = code

        done = _Done()
        done.stdout = stdout
        monkeypatch.setattr(routing.os, "name", "nt")
        monkeypatch.setattr(routing.subprocess, "run", lambda *a, **k: done)
        return routing.arp_source_address("192.168.1.33")

    def test_reads_the_interface_holding_the_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = (
            "\nInterface: 192.168.1.7 --- 0x5\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.33          e0-e2-58-ac-df-e6     dynamic\n"
        )
        assert self._arp(monkeypatch, out) == "192.168.1.7"

    def test_an_entry_without_a_hardware_address_is_not_evidence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An incomplete entry means ARP was attempted and got no answer."""
        out = (
            "\nInterface: 192.168.1.7 --- 0x5\n"
            "  192.168.1.33          incomplete\n"
        )
        assert self._arp(monkeypatch, out) == ""

    def test_a_different_address_is_not_taken_as_the_target(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = (
            "\nInterface: 192.168.1.7 --- 0x5\n"
            "  192.168.1.34          e0-e2-58-ac-df-e6     dynamic\n"
        )
        assert self._arp(monkeypatch, out) == ""

    def test_a_failed_command_yields_no_evidence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert self._arp(monkeypatch, "", code=1) == ""


class TestRouteChoiceDefaults:
    """An unresolved choice must be inert."""

    def test_empty_choice_pins_nothing(self) -> None:
        choice = RouteChoice()
        assert choice.device == ""
        assert choice.resolved is False


class TestParserFailureIsNotAFinding:
    """A parsing fault must never be recorded as "0 hosts up"."""

    def test_hosts_nmap_found_but_we_could_not_read_is_a_failure(self) -> None:
        from aethra_sec.services.nmap_service import is_parser_failure

        assert is_parser_failure(reported_up=1, persisted_up=0) is True
        assert is_parser_failure(reported_up=3, persisted_up=0) is True

    def test_a_genuinely_quiet_target_is_not_a_parser_failure(self) -> None:
        """Nmap reporting nothing up, and nothing stored, is a real result."""
        from aethra_sec.services.nmap_service import is_parser_failure

        assert is_parser_failure(reported_up=0, persisted_up=0) is False

    def test_a_host_that_parsed_successfully_is_not_a_failure(self) -> None:
        from aethra_sec.services.nmap_service import is_parser_failure

        assert is_parser_failure(reported_up=1, persisted_up=1) is False
        assert is_parser_failure(reported_up=2, persisted_up=2) is False
