"""Input validation, Nmap profile construction and the authorisation boundary.

These tests defend the two hard security boundaries of the assessment path:
operator input must never reach a command line as free text (§97), and targets
outside the configured networks must be refused (§2).
"""

from __future__ import annotations

import pytest

from aethra_sec.integrations.nmap.profiles import (
    ALLOWED_SCRIPT_CATEGORIES,
    DEFAULT_PROFILE,
    FORBIDDEN_SCRIPT_CATEGORIES,
    PROFILES,
    available_profiles,
    build_scan_request,
)
from aethra_sec.utils.net import is_authorized_target, unauthorized_addresses
from aethra_sec.utils.validation import (
    ValidationError,
    safe_filename,
    validate_password,
    validate_port,
    validate_port_range,
    validate_target,
    validate_username,
)


class TestPortRangeValidation:
    """A port specification is the only operator text Nmap ever receives."""

    @pytest.mark.parametrize(
        "value", ["80", "22,80,443", "1-1024", "1-65535", "22, 80 , 443"]
    )
    def test_accepts_valid_specifications(self, value: str) -> None:
        """Well-formed specifications are normalised and accepted."""
        assert validate_port_range(value)

    @pytest.mark.parametrize(
        "value",
        [
            "1-10; rm -rf /",
            "80 && whoami",
            "$(id)",
            "22|nc -e /bin/sh",
            "`reboot`",
            "80\n443",
            "--script=exploit",
            "80;",
            "abc",
            "",
            "0",
            "70000",
            "100-50",
        ],
    )
    def test_refuses_injection_and_malformed_input(self, value: str) -> None:
        """Anything outside the strict numeric grammar is refused."""
        with pytest.raises(ValidationError):
            validate_port_range(value)

    def test_port_bounds(self) -> None:
        """Ports must be within 1-65535."""
        assert validate_port("443") == 443
        for bad in ("0", "65536", "-1", "x"):
            with pytest.raises(ValidationError):
                validate_port(bad)


class TestTargetValidation:
    """Targets are parsed into concrete addresses before authorisation."""

    def test_single_address(self) -> None:
        """A single IP resolves to itself."""
        spec = validate_target("192.168.1.25")
        assert spec.kind == "ip"
        assert spec.addresses == ("192.168.1.25",)

    def test_cidr_expansion(self) -> None:
        """A CIDR expands to its host addresses."""
        spec = validate_target("192.168.1.0/29")
        assert spec.kind == "cidr"
        assert len(spec.addresses) == 6
        assert "192.168.1.1" in spec.addresses

    def test_hyphen_range(self) -> None:
        """An IPv4 hyphen range expands inclusively."""
        spec = validate_target("10.0.0.5-8")
        assert spec.kind == "range"
        assert spec.addresses == ("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8")

    def test_hostname(self) -> None:
        """A hostname is accepted but not expanded here."""
        spec = validate_target("server.lab.local")
        assert spec.kind == "hostname"
        assert spec.addresses == ()

    def test_refuses_oversized_network(self) -> None:
        """An unreasonably large network is refused rather than attempted."""
        with pytest.raises(ValidationError):
            validate_target("10.0.0.0/8")

    @pytest.mark.parametrize(
        "value", ["192.168.1.1; ls", "host && id", "$(hostname)", "a b c", ""]
    )
    def test_refuses_metacharacters(self, value: str) -> None:
        """Shell metacharacters never survive validation."""
        with pytest.raises(ValidationError):
            validate_target(value)


class TestAuthorizationBoundary:
    """The boundary decides on addresses, not names (§2)."""

    def test_private_addresses_are_authorised(self, lab_authorization) -> None:
        """Configured networks are permitted."""
        for address in ("192.168.1.25", "10.4.5.6", "127.0.0.1"):
            assert is_authorized_target(address, lab_authorization)

    def test_public_addresses_are_refused(self, lab_authorization) -> None:
        """Anything outside the configured networks is refused."""
        for address in ("8.8.8.8", "1.1.1.1", "203.0.113.9"):
            assert not is_authorized_target(address, lab_authorization)

    def test_reports_every_unauthorised_address(self, lab_authorization) -> None:
        """A mixed target reports each offending address."""
        outside = unauthorized_addresses(
            ("192.168.1.1", "8.8.8.8", "10.0.0.1", "1.1.1.1"), lab_authorization
        )
        assert set(outside) == {"8.8.8.8", "1.1.1.1"}

    def test_allow_public_opt_in(self) -> None:
        """The public opt-in is honoured only when explicitly enabled."""
        from aethra_sec.config.settings import AuthorizationSettings

        opted_in = AuthorizationSettings(networks=("192.168.0.0/16",), allow_public=True)
        assert is_authorized_target("8.8.8.8", opted_in)


class TestScanRequestBuilder:
    """Argument lists are assembled from a fixed catalogue (§97)."""

    def test_default_profile_arguments(self) -> None:
        """The standard profile produces the documented argument list."""
        request = build_scan_request("192.168.1.25", DEFAULT_PROFILE, timing="T4")
        assert "-sT" in request.arguments
        assert "-sV" in request.arguments
        assert "-T4" in request.arguments
        assert "--host-timeout" in request.arguments

    def test_custom_ports_reach_nmap_only_after_validation(self) -> None:
        """A validated port spec is placed after ``-p``."""
        request = build_scan_request(
            "192.168.1.25", "custom_ports", port_spec="22,80,443"
        )
        arguments = list(request.arguments)
        assert arguments[arguments.index("-p") + 1] == "22,80,443"

    @pytest.mark.parametrize("value", ["1;id", "80 && ls", "$(id)"])
    def test_injection_never_reaches_the_argument_list(self, value: str) -> None:
        """Injection attempts are refused before any argument is built."""
        with pytest.raises(ValidationError):
            build_scan_request("192.168.1.25", "custom_ports", port_spec=value)

    @pytest.mark.parametrize("category", sorted(FORBIDDEN_SCRIPT_CATEGORIES))
    def test_intrusive_script_categories_are_refused(self, category: str) -> None:
        """Exploit, brute-force and DoS NSE categories are never permitted."""
        with pytest.raises(ValidationError):
            build_scan_request("192.168.1.25", "standard", script_categories=(category,))

    def test_permitted_script_categories(self) -> None:
        """Assessment-only NSE categories are allowed when requested."""
        request = build_scan_request(
            "192.168.1.25", "standard", script_categories=("safe",)
        )
        assert "--script" in request.arguments
        assert request.script_categories == ("safe",)
        assert set(ALLOWED_SCRIPT_CATEGORIES) >= set(request.script_categories)

    def test_unknown_profile_refused(self) -> None:
        """Only catalogued profiles can be requested."""
        with pytest.raises(ValidationError):
            build_scan_request("192.168.1.25", "definitely-not-a-profile")

    def test_privileged_profiles_hidden_without_privilege(self) -> None:
        """Profiles needing raw sockets are withheld when unprivileged."""
        unprivileged = {p.key for p in available_profiles(privileged=False)}
        privileged = {p.key for p in available_profiles(privileged=True)}
        assert privileged - unprivileged
        assert all(
            not p.requires_privilege for p in available_profiles(privileged=False)
        )

    def test_no_profile_performs_exploitation(self) -> None:
        """No catalogued profile carries an exploit or brute-force argument."""
        forbidden = ("--script=exploit", "brute", "dos", "--script=vuln,exploit")
        for profile in PROFILES:
            joined = " ".join(profile.arguments).lower()
            assert not any(token in joined for token in forbidden)


class TestCredentialValidation:
    """Account input rules."""

    @pytest.mark.parametrize("value", ["analyst", "lab.user", "user_1", "a-b-c"])
    def test_valid_usernames(self, value: str) -> None:
        """Reasonable usernames are accepted."""
        assert validate_username(value) == value

    @pytest.mark.parametrize("value", ["", "a", "ab", "_leading", "trailing_", "has space", "x" * 40])
    def test_invalid_usernames(self, value: str) -> None:
        """Malformed usernames are refused."""
        with pytest.raises(ValidationError):
            validate_username(value)

    def test_password_policy(self) -> None:
        """Length plus three character classes are required."""
        assert validate_password("CorrectHorse!2026")
        for weak in ("short1!A", "alllowercase123", "ALLUPPERCASE123", ""):
            with pytest.raises(ValidationError):
                validate_password(weak)

    def test_password_never_appears_in_the_error(self) -> None:
        """A rejected password is not echoed back in the message."""
        secret = "hunter2hunter2"
        try:
            validate_password(secret)
        except ValidationError as exc:
            assert secret not in str(exc)


class TestFilenameSafety:
    """Export filenames cannot escape their directory (§97)."""

    @pytest.mark.parametrize(
        "value", ["../../etc/passwd", "a/b/c", "C:\\Windows\\System32", "..\\..\\x"]
    )
    def test_traversal_is_stripped(self, value: str) -> None:
        """Path separators and traversal sequences are removed."""
        cleaned = safe_filename(value)
        assert "/" not in cleaned
        assert "\\" not in cleaned
        assert ".." not in cleaned

    def test_resolve_within_refuses_escape(self, tmp_path) -> None:
        """A resolved export path always stays inside its directory."""
        from aethra_sec.utils.validation import resolve_within

        resolved = resolve_within(tmp_path, "../../escape.csv")
        assert tmp_path in resolved.parents
