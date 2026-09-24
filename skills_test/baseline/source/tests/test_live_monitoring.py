"""Live Monitoring capture workflow (§38).

These pin the two defects that made capture unreliable rather than merely
inconvenient: TShark being located by one code path and not another, and a
capture proposal built from an adapter's name instead of its medium.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aethra_sec.integrations.pyshark_capture.interfaces import (
    CaptureInterface,
    list_capture_interfaces,
)
from aethra_sec.utils.net import AdapterDetail


class TestInterfaceIdentity:
    """The GUID join and the medium classification."""

    def test_guid_extracted_from_npf_device_name(self) -> None:
        """The Windows device name yields the GUID that joins to the OS list."""
        interface = CaptureInterface(
            name=r"\Device\NPF_{2B4A77CE-A29A-41CE-844D-D378853A0D82}"
        )
        assert interface.guid == "{2B4A77CE-A29A-41CE-844D-D378853A0D82}"

    def test_guid_empty_for_non_npf_devices(self) -> None:
        """USBPcap, ETW and POSIX interfaces have no GUID and must not fake one."""
        for name in ("etwdump", r"\\.\USBPcap1", "eth0"):
            assert CaptureInterface(name=name).guid == ""

    @pytest.mark.parametrize(
        ("media", "physical", "expected"),
        [
            ("Native 802.11", "Native 802.11", "Wi-Fi"),
            ("802.3", "802.3", "Ethernet"),
            # A Bluetooth PAN also presents as 802.3, so the physical medium
            # has to win or it would be listed as Ethernet.
            ("802.3", "BlueTooth", "Bluetooth"),
            ("", "", "Other"),
        ],
    )
    def test_medium_decides_the_kind(
        self, media: str, physical: str, expected: str
    ) -> None:
        """Classification comes from the reported medium, never the name."""
        detail = AdapterDetail(
            guid="{X}", media_type=media, physical_media=physical
        )
        assert detail.kind == expected

    def test_kind_ignores_a_misleading_adapter_name(self) -> None:
        """An adapter named "Ethernet 3" that is wireless is still Wi-Fi.

        Operators rename adapters, and on the development machine the adapter
        labelled "Ethernet 3" is a VirtualBox host-only device. Naming must
        never drive classification.
        """
        detail = AdapterDetail(
            guid="{X}",
            friendly_name="Ethernet 3",
            media_type="Native 802.11",
            physical_media="Native 802.11",
        )
        assert detail.kind == "Wi-Fi"

    def test_display_name_prefers_the_os_name(self) -> None:
        """The picker shows the adapter name, not the NPF device string."""
        interface = CaptureInterface(
            name=r"\Device\NPF_{ABC}", description="Wi-Fi", friendly_name="Wi-Fi"
        )
        assert interface.display_name == "Wi-Fi"
        # The capture identifier is preserved separately for TShark.
        assert interface.name.startswith(r"\Device\NPF_")


class TestTsharkDiscovery:
    """Enumeration must find TShark wherever the availability probe does."""

    def test_enumeration_resolves_tshark_outside_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A Wireshark install absent from PATH must still enumerate.

        Regression: ``probe_tshark`` searched the standard Wireshark
        directories while ``tshark_interfaces`` only consulted PATH. Capture
        was therefore reported AVAILABLE while the interface list silently fell
        back to operating-system names - and PyShark cannot capture on those on
        Windows, so every capture started from that list failed.
        """
        module = "aethra_sec.integrations.pyshark_capture.interfaces"
        resolved = Path(r"C:\Program Files\Wireshark\tshark.exe")
        seen: list[object] = []

        monkeypatch.setattr(f"{module}.find_tshark", lambda _p: resolved)
        monkeypatch.setattr(f"{module}.list_interfaces", lambda: [])
        monkeypatch.setattr(f"{module}.windows_adapter_details", lambda: {})
        monkeypatch.setattr(f"{module}.primary_outbound_address", lambda: "")

        def fake_tshark_interfaces(path: object) -> list[tuple[str, str]]:
            seen.append(path)
            return [(r"\Device\NPF_{ABC}", "Wi-Fi")]

        monkeypatch.setattr(f"{module}.tshark_interfaces", fake_tshark_interfaces)

        result = list_capture_interfaces(None)

        # The resolved executable is what enumeration was given, not the None
        # it was called with.
        assert seen == [resolved]
        assert [i.name for i in result] == [r"\Device\NPF_{ABC}"]


class TestPrimaryInterface:
    """The default selection follows the routing table."""

    def test_routing_interface_is_marked_and_sorted_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The interface carrying the default route leads the picker.

        Several adapters can be up with an address at once - VirtualBox, VMware
        and ZeroTier all qualify - so "first with an address" picked an adapter
        that carries no traffic.
        """
        module = "aethra_sec.integrations.pyshark_capture.interfaces"
        from aethra_sec.utils.net import NetworkInterface

        monkeypatch.setattr(f"{module}.find_tshark", lambda _p: Path("tshark"))
        monkeypatch.setattr(f"{module}.windows_adapter_details", lambda: {})
        monkeypatch.setattr(
            f"{module}.primary_outbound_address", lambda: "192.168.1.7"
        )
        monkeypatch.setattr(
            f"{module}.list_interfaces",
            lambda: [
                NetworkInterface(
                    name="Ethernet 3",
                    ipv4_addresses=("192.168.56.1",),
                    is_up=True,
                ),
                NetworkInterface(
                    name="Wi-Fi", ipv4_addresses=("192.168.1.7",), is_up=True
                ),
            ],
        )
        monkeypatch.setattr(
            f"{module}.tshark_interfaces",
            lambda _p: [("Ethernet 3", "Ethernet 3"), ("Wi-Fi", "Wi-Fi")],
        )

        result = list_capture_interfaces(None)

        assert result[0].name == "Wi-Fi"
        assert result[0].is_primary is True
        assert result[1].is_primary is False

    def test_no_route_marks_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With no route, no interface is claimed to be the primary one."""
        module = "aethra_sec.integrations.pyshark_capture.interfaces"
        from aethra_sec.utils.net import NetworkInterface

        monkeypatch.setattr(f"{module}.find_tshark", lambda _p: Path("tshark"))
        monkeypatch.setattr(f"{module}.windows_adapter_details", lambda: {})
        monkeypatch.setattr(f"{module}.primary_outbound_address", lambda: "")
        monkeypatch.setattr(
            f"{module}.list_interfaces",
            lambda: [
                NetworkInterface(
                    name="Wi-Fi", ipv4_addresses=("192.168.1.7",), is_up=True
                )
            ],
        )
        monkeypatch.setattr(
            f"{module}.tshark_interfaces", lambda _p: [("Wi-Fi", "Wi-Fi")]
        )

        assert all(not i.is_primary for i in list_capture_interfaces(None))
