"""Network visibility, and port-scan detection between other hosts.

Three different questions get confused constantly, and every test here exists
to keep one of them honest:

**Network visibility** - do the packets reach the capture interface at all?
A switch forwards a unicast frame only towards its destination, so an ordinary
switched port receives this host's own traffic plus broadcast and multicast,
and nothing else. Wireshark at the same point sees exactly as much. Only a
mirror/SPAN destination port or a TAP changes that, and no amount of software
can.

**Packet capture** - can Npcap/TShark read the frames that do arrive?

**Application content** - is the payload readable? For TLS it is not,
whatever the capture point is.

Measured on this installation on an ordinary switched port, 3,987 frames:
3,835 involved this host, 152 were broadcast or multicast, and **0** were
between two other devices - while 20 other devices were demonstrably present,
because their broadcast arrived. That is the limitation these tests pin.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from aethra_sec.analytics.capture_visibility import (
    MINIMUM_FRAMES_FOR_A_VERDICT,
    CaptureVisibility,
    VisibilityState,
    derive,
)
from aethra_sec.analytics.peer_visibility import VisibilityReport
from aethra_sec.integrations.snort.parser import parse_fast

ROOT = Path(__file__).resolve().parent.parent
SNORT_DIR = ROOT / "deploy" / "snort"


# ---------------------------------------------------------------------------
# Visibility is derived from evidence, never from a selection
# ---------------------------------------------------------------------------
class TestVisibilityComesFromCapturedFrames:
    def test_an_idle_capture_is_unknown_not_local_only(self) -> None:
        """Too few frames is "we have not measured", not "nothing is there"."""
        state = derive(VisibilityReport(frames=10))
        assert state.state is CaptureVisibility.UNKNOWN

    def test_local_traffic_only_is_reported_as_such(self) -> None:
        state = derive(
            VisibilityReport(
                frames=MINIMUM_FRAMES_FOR_A_VERDICT + 1,
                own_frames=MINIMUM_FRAMES_FOR_A_VERDICT,
                group_frames=1,
            )
        )
        assert state.state is CaptureVisibility.LOCAL_ONLY
        assert state.transit_text == "NOT OBSERVED"

    def test_peer_unicast_is_what_proves_transit(self) -> None:
        state = derive(
            VisibilityReport(frames=5000, peer_frames=120, peer_hosts=4)
        )
        assert state.state is CaptureVisibility.TRANSIT_OBSERVED
        assert state.transit_observed is True
        assert state.state.sees_other_hosts is True

    @pytest.mark.parametrize("frames", [0, 50, 5_000, 1_000_000])
    def test_declaring_a_monitoring_role_never_proves_transit(
        self, frames: int
    ) -> None:
        """The decisive guard.

        An operator saying "this NIC is my SPAN destination" is an intention.
        It must never become a claim that third-party traffic is being seen -
        the mirror session may not exist, may be down, or may mirror the wrong
        port, and only an actual transit frame settles it.
        """
        state = derive(
            VisibilityReport(frames=frames, peer_frames=0),
            monitoring_declared=True,
        )
        assert state.state is not CaptureVisibility.TRANSIT_OBSERVED
        assert state.transit_observed is False
        assert state.state.sees_other_hosts is False

    def test_a_declared_monitor_is_labelled_as_selected_not_as_mirroring(
        self,
    ) -> None:
        """Wording matters: the UI must not read "SPAN CONFIGURED"."""
        state = derive(
            VisibilityReport(frames=5000), monitoring_declared=True
        )
        assert state.state is CaptureVisibility.MIRRORED_TRAFFIC
        assert "SELECTED" in state.state.label.upper()
        assert "CONFIGURED" not in state.state.label.upper()

    def test_capture_unavailable_outranks_everything(self) -> None:
        state = derive(
            VisibilityReport(frames=9000, peer_frames=500),
            capture_available=False,
        )
        assert state.state is CaptureVisibility.CAPTURE_UNAVAILABLE
        assert state.state.sees_other_hosts is False

    def test_silent_peers_are_explained_not_reported_as_a_fault(self) -> None:
        """Devices present but unobservable is the finding, not an error."""
        state = derive(
            VisibilityReport(frames=4000, group_only_hosts=20)
        )
        assert state.state is CaptureVisibility.LOCAL_ONLY
        assert "20 other device" in state.detail
        assert "mirror" in state.detail.lower() or "span" in state.detail.lower()

    def test_no_state_claims_to_see_other_hosts_without_peer_frames(self) -> None:
        for state in CaptureVisibility:
            if state is CaptureVisibility.TRANSIT_OBSERVED:
                continue
            assert state.sees_other_hosts is False, (
                f"{state.value} would let the UI claim network-wide visibility "
                "without a single third-party frame"
            )


# ---------------------------------------------------------------------------
# A port-scan alert between two other hosts must survive the parser
# ---------------------------------------------------------------------------
class TestSnortPortScanAlertsParse:
    """sfportscan is what detects distinct-port scanning; GID 122.

    Its alert_fast line reports the pseudo-packet as ``{PROTO:255}`` and
    carries no ports. The protocol character class did not admit the colon, so
    the whole line failed to match and ``parse_fast`` returned ``None`` - every
    port-scan alert the preprocessor raised was dropped before the database.
    """

    SCAN_LINE = (
        "10/06-21:50:11.001122  [**] [122:1:0] (portscan) TCP Portscan [**] "
        "[Priority: 3] {PROTO:255} 192.168.100.10 -> 192.168.100.222"
    )

    def test_a_portscan_alert_parses(self) -> None:
        alert = parse_fast(self.SCAN_LINE)
        assert alert is not None, "the port-scan alert was silently discarded"

    def test_both_endpoints_are_the_other_hosts(self) -> None:
        """Part 6: AETHRA must not substitute itself for either endpoint."""
        alert = parse_fast(self.SCAN_LINE)
        assert alert.src_ip == "192.168.100.10"
        assert alert.dst_ip == "192.168.100.222"

    def test_the_signature_identity_is_preserved(self) -> None:
        alert = parse_fast(self.SCAN_LINE)
        assert alert.generator_id == 122
        assert alert.signature_id == 1
        assert "Portscan" in alert.message

    @pytest.mark.parametrize(
        "line",
        [
            "10/06-21:50:12.0  [**] [122:3:0] (portscan) TCP Portsweep [**] "
            "[Priority: 3] {PROTO:255} 10.0.0.5 -> 10.0.0.9",
            "10/06-21:50:13.0  [**] [122:5:0] (portscan) TCP Filtered Portscan "
            "[**] [Priority: 3] {PROTO:255} 10.0.0.5 -> 10.0.0.9",
            "10/06-21:50:14.0  [**] [122:17:0] (portscan) UDP Portscan [**] "
            "[Priority: 3] {PROTO:255} 10.0.0.5 -> 10.0.0.9",
        ],
    )
    def test_every_portscan_variant_parses(self, line: str) -> None:
        alert = parse_fast(line)
        assert alert is not None
        assert alert.src_ip == "10.0.0.5"
        assert alert.dst_ip == "10.0.0.9"

    def test_an_ordinary_rule_alert_still_parses(self) -> None:
        """No regression: this is the shape already in the live alert file."""
        alert = parse_fast(
            "10/06-21:49:01.887690  [**] [1:1000002:2] TCP SYN (any port) [**] "
            "[Classification: Attempted Information Leak] [Priority: 2] "
            "{TCP} 192.168.100.254:58737 -> 192.168.100.31:7070"
        )
        assert alert is not None
        assert alert.protocol == "TCP"
        assert alert.src_port == 58737
        assert alert.dst_port == 7070


# ---------------------------------------------------------------------------
# The detector counts connection attempts, not replies
# ---------------------------------------------------------------------------
class TestPortScanCountsConnectionAttemptsOnly:
    """Measured before this gate: of 173 inbound "port scan" detections on
    this installation, 0 touched a well-known service port, all 173 hit only
    client-side ports, and the median share of consecutive port numbers was
    95% - a server answering this host's own outbound connections.
    """

    def _engine(self):  # noqa: ANN202
        from aethra_sec.analytics.anomaly_rules import AnomalyRuleEngine

        return AnomalyRuleEngine

    class _Packet:
        def __init__(self, **fields) -> None:  # noqa: ANN003
            self.__dict__.update(fields)

    def test_a_tcp_syn_is_an_attempt(self) -> None:
        engine = self._engine()
        assert engine._initiates(  # noqa: SLF001
            self._Packet(is_syn_only=True, dst_port=80), "TCP"
        )

    def test_established_tcp_traffic_is_not(self) -> None:
        engine = self._engine()
        assert not engine._initiates(  # noqa: SLF001
            self._Packet(is_syn_only=False, dst_port=53419), "TCP"
        )

    def test_udp_to_a_service_port_counts(self) -> None:
        engine = self._engine()
        assert engine._initiates(self._Packet(dst_port=53), "UDP")  # noqa: SLF001

    def test_udp_to_an_ephemeral_port_does_not(self) -> None:
        """A reply arrives at the ephemeral port the client chose."""
        engine = self._engine()
        assert not engine._initiates(  # noqa: SLF001
            self._Packet(dst_port=53419), "UDP"
        )

    def test_the_rule_is_gated_in_the_dispatch(self) -> None:
        engine = self._engine()
        body = inspect.getsource(engine.inspect) if hasattr(engine, "inspect") else ""
        if not body:
            body = inspect.getsource(engine)
        index = body.index("_check_port_scan")
        preceding = body[:index]
        assert "_initiates" in preceding, (
            "the port-scan check must sit behind the connection-attempt gate, "
            "or reply traffic is counted as scanning again"
        )


# ---------------------------------------------------------------------------
# Snort configuration
# ---------------------------------------------------------------------------
class TestSnortPortScanConfiguration:
    def test_the_endpoint_config_detects_port_scans(self) -> None:
        text = (SNORT_DIR / "snort.wsl.conf").read_text(encoding="utf-8")
        assert "sfportscan" in text, (
            "no rule in local.rules can express 'many DISTINCT ports from one "
            "source'; threshold counts events, so the preprocessor is required"
        )

    def test_the_endpoint_config_still_protects_one_host(self) -> None:
        """No regression: widening this file would widen every rule with it."""
        text = (SNORT_DIR / "snort.wsl.conf").read_text(encoding="utf-8")
        assert "include /mnt/c/Snort-wsl/home_net.conf" in text

    def test_a_separate_monitoring_config_exists(self) -> None:
        monitor = SNORT_DIR / "snort.monitor.conf"
        assert monitor.is_file()
        text = monitor.read_text(encoding="utf-8")
        assert "sfportscan" in text
        # It must NOT reuse the endpoint HOME_NET file, which the Windows-side
        # updater rewrites with this host's own /32 - that would silently
        # narrow monitoring mode back to a single host.
        assert "home_net.monitor.conf" in text
        assert "include /mnt/c/Snort-wsl/home_net.conf" not in text

    def test_the_monitoring_home_net_example_is_a_range(self) -> None:
        example = SNORT_DIR / "home_net.monitor.conf.example"
        assert example.is_file()
        text = example.read_text(encoding="utf-8")
        assert "ipvar HOME_NET" in text
        assert "/32" not in text, (
            "a /32 here cannot match a scan between two other hosts"
        )

    def test_no_duplicate_sids_in_local_rules(self) -> None:
        text = (SNORT_DIR / "local.rules").read_text(encoding="utf-8")
        sids = [
            line.split("sid:")[1].split(";")[0].strip()
            for line in text.splitlines()
            if line.strip().startswith("alert") and "sid:" in line
        ]
        assert len(sids) == len(set(sids)), f"duplicate SID in local.rules: {sids}"

    def test_rules_are_not_fabricating_alerts(self) -> None:
        """Every rule must key on a real, observable packet property.

        That property may live in the rule OPTIONS (flags, itype, threshold,
        dsize, content) or in the rule HEADER - a rule whose header pins a
        specific destination port, such as ``-> $HOME_NET 53``, is keyed on
        the port of an actual packet just as firmly.
        """
        text = (SNORT_DIR / "local.rules").read_text(encoding="utf-8")
        checked = 0
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("alert"):
                continue
            checked += 1
            options = any(
                token in stripped
                for token in (
                    "flags:", "itype:", "threshold:", "dsize:", "content:",
                    "icode:", "flow:",
                )
            )
            # header: "alert <proto> <src> <sport> -> <dst> <dport> ("
            header = stripped.split("(", 1)[0].split()
            pinned_port = len(header) >= 7 and header[6] != "any"
            assert options or pinned_port, (
                f"rule matches on nothing observable: {stripped[:80]}"
            )
        assert checked >= 5, "the rule file was not actually inspected"


# ---------------------------------------------------------------------------
# Interface roles: management vs monitoring
# ---------------------------------------------------------------------------
class _Adapter:
    """Stands for one capture-service interface record."""

    def __init__(self, name, display_name="", mac_address="", is_up=True):  # noqa: ANN001
        self.name = name
        self.display_name = display_name or name
        self.description = display_name or name
        self.mac_address = mac_address
        self.ipv4_addresses = ()
        self.is_up = is_up


WIFI = r"\Device\NPF_{AAAAAAAA-0000-0000-0000-000000000001}"
SPAN = r"\Device\NPF_{BBBBBBBB-0000-0000-0000-000000000002}"


@pytest.fixture
def adapters():
    # Locally-administered, deliberately synthetic MACs. An earlier version of
    # this fixture reused MACs copied from the development machine, and the
    # address join - which reads the real adapters - then found a real IPv4
    # address for the "SPAN" adapter and the test failed against its own
    # fixture rather than against the code.
    return [
        _Adapter(WIFI, "Wi-Fi", "02:00:5e:00:53:01"),
        _Adapter(SPAN, "Ethernet 2", "02:00:5e:00:53:02"),
    ]


class TestInterfaceRoles:
    def test_roles_are_recorded_by_stable_device_not_display_name(self) -> None:
        """A friendly name is a user-editable label Windows renumbers.

        The capture feeding Snort on this installation is launched as
        `tshark -i 2`, a positional index, and index 2 no longer resolves to
        the adapter it did when that process started. Roles must not repeat
        that mistake.
        """
        from aethra_sec.analytics import interface_roles as roles

        source = inspect.getsource(roles.resolve)
        assert "name" in source
        assert "display_name" not in source, (
            "resolution must key on the stable device, not the label"
        )

    def test_the_monitoring_interface_is_selected_independently(
        self, adapters
    ) -> None:  # noqa: ANN001
        from aethra_sec.analytics.interface_roles import InterfaceRole, resolve

        assignment = resolve(adapters, monitoring_device=SPAN)
        assert assignment.monitoring is not None
        assert assignment.monitoring.device == SPAN
        assert assignment.monitoring.role is InterfaceRole.MONITORING
        assert assignment.management is None

    def test_both_roles_can_be_different_adapters(self, adapters) -> None:  # noqa: ANN001
        from aethra_sec.analytics.interface_roles import resolve

        assignment = resolve(
            adapters, monitoring_device=SPAN, management_device=WIFI
        )
        assert assignment.roles_are_separate is True
        assert assignment.has_dedicated_monitoring is True

    def test_one_adapter_in_both_roles_is_reported_not_rejected(
        self, adapters
    ) -> None:  # noqa: ANN001
        """A single-NIC endpoint sensor is a valid configuration."""
        from aethra_sec.analytics.interface_roles import resolve

        assignment = resolve(
            adapters, monitoring_device=WIFI, management_device=WIFI
        )
        assert assignment.roles_are_separate is False
        assert "both roles" in assignment.describe()

    def test_an_absent_device_is_reported_not_silently_replaced(
        self, adapters
    ) -> None:  # noqa: ANN001
        """Falling back is how a sensor watches the wrong segment."""
        from aethra_sec.analytics.interface_roles import resolve

        missing_device = r"\Device\NPF_{CCCCCCCC-0000-0000-0000-000000000003}"
        assignment = resolve(adapters, monitoring_device=missing_device)
        assert assignment.monitoring is None
        assert missing_device in assignment.missing
        assert "not present" in assignment.describe()

    def test_a_monitoring_interface_without_an_address_is_normal(
        self, adapters
    ) -> None:  # noqa: ANN001
        """A SPAN destination port is receive-only and usually has no IP."""
        from aethra_sec.analytics.interface_roles import resolve

        assignment = resolve(adapters, monitoring_device=SPAN)
        assert assignment.monitoring.ipv4_text == "N/A"
        assert assignment.has_dedicated_monitoring is True

    def test_nothing_here_alters_routing_or_adapter_configuration(self) -> None:
        """Capture must never change the machine's networking."""
        from aethra_sec.analytics import interface_roles as roles

        source = inspect.getsource(roles)
        for forbidden in (
            "subprocess", "netsh", "route ", "ipconfig", "SetDefaultGateway",
            "os.system",
        ):
            assert forbidden not in source, (
                f"interface roles must not touch host networking ({forbidden})"
            )


class TestDeclaringAMonitorIsNotEvidence:
    """The join between Part 3 and Part 4, held explicitly."""

    def test_health_requires_both_declared_and_present(self) -> None:
        from aethra_sec.services.health_service import HealthService

        body = inspect.getsource(HealthService._capture_visibility)  # noqa: SLF001
        assert "span_declared" in body
        assert "has_dedicated_monitoring" in body, (
            "a declaration about an absent adapter must not raise visibility"
        )

    def test_a_declared_span_still_cannot_report_transit(self) -> None:
        from aethra_sec.analytics.capture_visibility import (
            CaptureVisibility,
            derive,
        )

        state = derive(
            VisibilityReport(frames=500_000, peer_frames=0),
            monitoring_declared=True,
        )
        assert state.state is not CaptureVisibility.TRANSIT_OBSERVED
        assert state.transit_observed is False
