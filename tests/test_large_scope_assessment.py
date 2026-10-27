"""Large authorised networks: accepted, not enumerated, still bounded.

Two limits stopped a campus range being assessed. ``validate_target`` refused
any CIDR above 4,096 addresses, and for every CIDR it built a tuple of every
address in the network - 65,534 strings for a /16 - whose only consumer was
the authorisation check. Nmap is handed the CIDR text and walks the range
itself, so that tuple was built and discarded.

No test here contacts a host or runs Nmap. Target parsing, authorisation and
counting are pure functions of their input.
"""

from __future__ import annotations

import ipaddress
import time
import tracemalloc

import pytest

from aethra_sec.config.settings import AuthorizationSettings
from aethra_sec.utils.net import (
    network_within_authorization,
    unauthorized_addresses,
)
from aethra_sec.utils.validation import (
    CHEAP_ENUMERATION_ADDRESSES,
    MAX_TARGET_ADDRESSES,
    ValidationError,
    validate_target,
)

LAB = AuthorizationSettings(networks=("10.0.0.0/8", "192.168.0.0/16"))


class TestATargetValidation:
    """TEST A: the forms a target may take, and what each covers."""

    @pytest.mark.parametrize(
        ("target", "kind", "covers"),
        [
            ("192.168.1.10", "ip", 1),
            ("192.168.1.0/24", "cidr", 256),
            ("10.0.0.0/20", "cidr", 4_096),
            ("10.0.0.0/16", "cidr", 65_536),
            ("10.0.0.0/12", "cidr", 1_048_576),
        ],
    )
    def test_the_address_count_is_the_size_of_the_range(
        self, target: str, kind: str, covers: int
    ) -> None:
        spec = validate_target(target)
        assert spec.kind == kind
        assert spec.address_count == covers

    def test_a_count_is_not_a_claim_about_live_hosts(self) -> None:
        """address_count sizes the range; nothing here has contacted anything."""
        spec = validate_target("10.0.0.0/16")
        assert spec.address_count == 65_536
        assert spec.addresses == (), "no host was enumerated, let alone probed"

    @pytest.mark.parametrize(
        "bad",
        ["", "   ", "999.1.1.1/24", "10.0.0.0/33", "10.0.0.0/-1", "not a target"],
    )
    def test_invalid_targets_are_refused(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            validate_target(bad)

    def test_a_network_beyond_the_ceiling_is_refused(self) -> None:
        """A mistyped prefix must not become an unintended sweep."""
        with pytest.raises(ValidationError) as excinfo:
            validate_target("10.0.0.0/8")
        assert "exceeds" in str(excinfo.value)

    def test_the_ceiling_is_a_twelve(self) -> None:
        assert MAX_TARGET_ADDRESSES == 1 << 20
        assert ipaddress.ip_network("10.0.0.0/12").num_addresses == MAX_TARGET_ADDRESSES


class TestBLargeTargetsAreNotExpanded:
    """TEST B: a large range must not become a large in-memory structure."""

    def test_a_small_network_is_still_enumerated(self) -> None:
        """Existing behaviour for the sizes that always worked."""
        spec = validate_target("192.168.1.0/24")
        assert spec.enumerated
        assert len(spec.addresses) == 254
        assert "192.168.1.1" in spec.addresses

    def test_a_large_network_carries_itself_instead(self) -> None:
        spec = validate_target("10.0.0.0/16")
        assert not spec.enumerated
        assert spec.addresses == ()
        assert spec.network == ipaddress.ip_network("10.0.0.0/16")

    def test_the_boundary_is_the_documented_one(self) -> None:
        at = validate_target(f"10.0.0.0/{32 - CHEAP_ENUMERATION_ADDRESSES.bit_length() + 1}")
        assert at.address_count == CHEAP_ENUMERATION_ADDRESSES
        assert at.enumerated, "at the limit the addresses are still listed"
        above = validate_target("10.0.0.0/19")
        assert above.address_count == CHEAP_ENUMERATION_ADDRESSES * 2
        assert not above.enumerated

    def test_a_sixteen_costs_almost_nothing(self) -> None:
        """Enumerating a /16 measured 959 ms and 3.83 MB before this change."""
        tracemalloc.start()
        started = time.perf_counter()
        spec = validate_target("10.0.0.0/16")
        elapsed = time.perf_counter() - started
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert spec.address_count == 65_536
        assert peak < 256 * 1024, f"{peak:,} bytes retained for a /16"
        assert elapsed < 0.1, f"{elapsed:.3f}s to validate a /16"


class TestJAuthorizedScope:
    """TEST J: the boundary, and that speed did not cost correctness."""

    @pytest.mark.parametrize(
        ("network", "authorised"),
        [
            ("10.0.0.0/16", True),
            ("10.5.0.0/20", True),
            ("192.168.0.0/16", True),
            ("172.16.0.0/16", False),
            ("8.8.8.0/24", False),
        ],
    )
    def test_containment_decides_the_boundary(
        self, network: str, authorised: bool
    ) -> None:
        assert network_within_authorization(
            ipaddress.ip_network(network), LAB
        ) is authorised

    def test_containment_agrees_with_the_per_address_check(self) -> None:
        """The fast path must not authorise anything the slow path refuses."""
        for cidr in ("10.1.2.0/24", "192.168.9.0/24", "172.20.5.0/24",
                     "203.0.113.0/24"):
            network = ipaddress.ip_network(cidr)
            by_network = network_within_authorization(network, LAB)
            addresses = tuple(str(h) for h in network.hosts())
            by_address = not unauthorized_addresses(addresses, LAB)
            assert by_network == by_address, (
                f"{cidr}: containment said {by_network}, "
                f"per-address said {by_address}"
            )

    def test_an_unauthorised_large_network_is_refused(self) -> None:
        assert not network_within_authorization(
            ipaddress.ip_network("172.16.0.0/16"), LAB
        )

    def test_allow_public_is_honoured(self) -> None:
        """The existing escape hatch keeps working, and stays opt-in."""
        public = AuthorizationSettings(networks=("10.0.0.0/8",), allow_public=True)
        assert network_within_authorization(
            ipaddress.ip_network("203.0.113.0/24"), public
        )
        assert not network_within_authorization(
            ipaddress.ip_network("203.0.113.0/24"), LAB
        )

    def test_a_mixed_version_network_does_not_crash(self) -> None:
        """An IPv6 target against IPv4 authorisation is refused, not an error."""
        assert not network_within_authorization(
            ipaddress.ip_network("2001:db8::/64"), LAB
        )


class TestSafetyControlsRemain:
    """What was deliberately left in place."""

    def test_automatic_assessment_still_has_a_scope_limit(self) -> None:
        """Raised, not removed: the default still suits a laboratory."""
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY

        spec = SETTING_SPEC_BY_KEY["assessment.max_scope_addresses"]
        assert spec.default == 1024, "the safe default must not have moved"
        assert spec.maximum == 1_048_576, "an operator may raise it to a /12"

    def test_concurrency_is_still_bounded(self) -> None:
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY

        spec = SETTING_SPEC_BY_KEY["assessment.max_concurrent"]
        assert spec.minimum >= 1
        assert spec.maximum <= 8, (
            "automatic assessment must not be able to run an unbounded "
            "number of Nmap processes"
        )
