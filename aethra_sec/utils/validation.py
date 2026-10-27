"""Input validation.

Every value that crosses an application boundary (user input, tool output,
socket payload) passes through this module before it reaches SQL, a subprocess
argument list, or a filesystem path.

Two rules are absolute:

* nothing here builds a shell string - callers receive validated *values* which
  they place into an ``argv`` list;
* nothing here interpolates into SQL - repositories use bound parameters only.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

# Characters that must never appear in a value handed to a subprocess or used
# to build a filename, regardless of platform quoting rules.
_SHELL_METACHARACTERS = set(";&|`$><\n\r\t\\\"'*?!{}[]()~^%")

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,30}[A-Za-z0-9])$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]{1,63}(\.[^@\s.]{1,63})+$")
_PORT_RANGE_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class ValidationError(ValueError):
    """Raised when operator-supplied input fails validation."""


@dataclass(frozen=True)
class TargetSpec:
    """A validated Nmap target.

    Attributes:
        raw: the operator's original text, retained for audit records.
        kind: ``"ip"``, ``"cidr"``, ``"range"`` or ``"hostname"``.
        addresses: concrete addresses covered by the target when they can be
            enumerated cheaply; empty for hostnames, which are resolved by
            Nmap, and empty for a network above
            :data:`CHEAP_ENUMERATION_ADDRESSES`, whose ``network`` is carried
            instead. Check :attr:`enumerated` before relying on it.
        network: the parsed network for a CIDR target, else ``None``.
    """

    raw: str
    kind: str
    addresses: tuple[str, ...]
    #: The parsed network, for a CIDR target. Carried so a caller can reason
    #: about the whole range - authorisation, address count, display - without
    #: enumerating it. ``None`` for every other kind of target.
    network: "ipaddress.IPv4Network | ipaddress.IPv6Network | None" = None

    @property
    def address_count(self) -> int:
        """How many addresses the target covers.

        Taken from the network for a CIDR, so it is correct even when the
        addresses were deliberately not enumerated. This is the size of the
        range, NOT a count of live hosts - nothing here has contacted
        anything.
        """
        if self.network is not None:
            return int(self.network.num_addresses)
        return len(self.addresses)

    @property
    def enumerated(self) -> bool:
        """True when :attr:`addresses` lists every address in the target."""
        if self.network is None:
            return True
        return len(self.addresses) > 0


def contains_shell_metacharacters(value: str) -> bool:
    """True when ``value`` contains a character unsafe for tool invocation."""
    return any(char in _SHELL_METACHARACTERS for char in value)


def require_no_metacharacters(value: str, field: str) -> str:
    """Return ``value`` unchanged, or raise if it carries unsafe characters."""
    if contains_shell_metacharacters(value):
        raise ValidationError(
            f"{field} contains characters that are not permitted: "
            "only letters, digits, dots, colons, hyphens and slashes are allowed."
        )
    return value


def validate_username(value: str) -> str:
    """Validate a login name (3-32 chars, alphanumeric plus ``._-``)."""
    candidate = (value or "").strip()
    if not candidate:
        raise ValidationError("Username is required.")
    if not _USERNAME_RE.match(candidate):
        raise ValidationError(
            "Username must be 3-32 characters and may contain letters, digits, "
            "dots, underscores and hyphens (not at the start or end)."
        )
    return candidate


def validate_email(value: str, *, allow_empty: bool = True) -> str:
    """Validate an optional email address."""
    candidate = (value or "").strip()
    if not candidate:
        if allow_empty:
            return ""
        raise ValidationError("Email address is required.")
    if not _EMAIL_RE.match(candidate):
        raise ValidationError("Enter a valid email address.")
    return candidate


def validate_password(value: str, *, min_length: int = 12) -> str:
    """Validate password complexity.

    The policy requires length plus three of four character classes. The
    password itself is never logged, echoed back, or included in an exception
    message.
    """
    if not value:
        raise ValidationError("Password is required.")
    if len(value) < min_length:
        raise ValidationError(
            f"Password must be at least {min_length} characters long."
        )
    if len(value) > 256:
        raise ValidationError("Password must be at most 256 characters long.")
    classes = sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )
    if classes < 3:
        raise ValidationError(
            "Password must combine at least three of: lowercase letters, "
            "uppercase letters, digits, and symbols."
        )
    return value


def validate_ip(value: str) -> str:
    """Validate a single IPv4/IPv6 address and return its canonical form."""
    candidate = (value or "").strip()
    if not candidate:
        raise ValidationError("IP address is required.")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise ValidationError(f"'{candidate}' is not a valid IP address.") from exc


def is_ip_address(value: str) -> bool:
    """True when ``value`` parses as an IP address."""
    try:
        ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return True


def validate_port(value: int | str) -> int:
    """Validate a TCP/UDP port number (1-65535)."""
    try:
        port = int(str(value).strip(), 10)
    except (TypeError, ValueError) as exc:
        raise ValidationError("Port must be a number between 1 and 65535.") from exc
    if not 1 <= port <= 65_535:
        raise ValidationError("Port must be between 1 and 65535.")
    return port


def validate_port_range(value: str) -> str:
    """Validate an Nmap port specification such as ``22,80,443`` or ``1-1024``.

    Returns the normalised specification. Anything not matching the strict
    numeric grammar is rejected, so no free text ever reaches the Nmap
    argument list.
    """
    candidate = (value or "").strip().replace(" ", "")
    if not candidate:
        raise ValidationError("Port range is required for this scan profile.")
    if not _PORT_RANGE_RE.match(candidate):
        raise ValidationError(
            "Port range must look like '80', '22,80,443' or '1-1024'."
        )
    for part in candidate.split(","):
        if "-" in part:
            low_raw, high_raw = part.split("-", 1)
            low, high = validate_port(low_raw), validate_port(high_raw)
            if low > high:
                raise ValidationError(
                    f"Port range '{part}' is inverted: {low} is greater than {high}."
                )
        else:
            validate_port(part)
    return candidate


def validate_hostname(value: str) -> str:
    """Validate a DNS hostname."""
    candidate = (value or "").strip().rstrip(".")
    if not candidate:
        raise ValidationError("Hostname is required.")
    require_no_metacharacters(candidate, "Hostname")
    if not _HOSTNAME_RE.match(candidate):
        raise ValidationError(f"'{candidate}' is not a valid hostname.")
    return candidate


def _expand_hyphen_range(value: str) -> tuple[str, ...]:
    """Expand an ``a.b.c.d-e`` style IPv4 range into concrete addresses."""
    head, _, tail = value.rpartition("-")
    base = ipaddress.ip_address(head.strip())
    if base.version != 4:
        raise ValidationError("Hyphen ranges are supported for IPv4 only.")
    try:
        last_octet = int(tail.strip(), 10)
    except ValueError as exc:
        raise ValidationError(f"'{value}' is not a valid address range.") from exc
    first_octet = int(str(base).rsplit(".", 1)[1], 10)
    if not 0 <= last_octet <= 255 or last_octet < first_octet:
        raise ValidationError(f"'{value}' is not a valid address range.")
    if last_octet - first_octet > 1024:
        raise ValidationError("Address range is too large; use CIDR notation.")
    prefix = str(base).rsplit(".", 1)[0]
    return tuple(f"{prefix}.{octet}" for octet in range(first_octet, last_octet + 1))


#: Largest network whose addresses are listed out in :attr:`TargetSpec.addresses`.
#: Above this the network is carried instead: enumerating a /16 costs 959 ms
#: and 3.83 MB to produce a list whose only consumer is an authorisation
#: check that a containment test answers without it.
CHEAP_ENUMERATION_ADDRESSES = 4096

#: Largest network a single assessment target may cover. This is a guard
#: against a mistyped prefix turning into an unintended sweep - /12 is already
#: far larger than a campus segment - and not a statement about how long such
#: a scan would take. The authorisation boundary, not this number, is what
#: decides whether a network may be assessed at all.
MAX_TARGET_ADDRESSES = 1 << 20


def validate_target(
    value: str, *, max_hosts: int = MAX_TARGET_ADDRESSES
) -> TargetSpec:
    """Validate an assessment target and describe what it covers.

    Accepted forms: a single IP address, a CIDR network, an IPv4 hyphen range,
    or a hostname. Authorisation (is this target inside a network we are
    permitted to assess?) is a separate check performed by
    :func:`aethra_sec.utils.net.is_authorized_target`.

    Raises:
        ValidationError: on malformed input or an unreasonably large network.
    """
    candidate = (value or "").strip()
    if not candidate:
        raise ValidationError("A scan target is required.")
    if len(candidate) > 255:
        raise ValidationError("Target is too long.")
    require_no_metacharacters(candidate, "Target")

    if "/" in candidate:
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise ValidationError(f"'{candidate}' is not a valid network.") from exc
        if network.num_addresses > max_hosts:
            raise ValidationError(
                f"Network {network} covers {network.num_addresses:,} "
                f"addresses, which exceeds the {max_hosts:,}-address limit "
                "for a single target. Assess it as several smaller networks."
            )
        if network.num_addresses > CHEAP_ENUMERATION_ADDRESSES:
            # Carried, not enumerated. Nmap is handed the CIDR text and walks
            # the range itself, and the authorisation check has a containment
            # test for exactly this case, so listing the addresses would cost
            # time and memory to produce something nothing reads.
            return TargetSpec(
                raw=candidate, kind="cidr", addresses=(), network=network
            )
        hosts = tuple(str(h) for h in network.hosts()) or (str(network.network_address),)
        return TargetSpec(
            raw=candidate, kind="cidr", addresses=hosts, network=network
        )

    if "-" in candidate and not candidate.replace("-", "").replace(".", "").isalpha():
        head = candidate.rpartition("-")[0].strip()
        if is_ip_address(head):
            return TargetSpec(
                raw=candidate, kind="range", addresses=_expand_hyphen_range(candidate)
            )

    if is_ip_address(candidate):
        return TargetSpec(
            raw=candidate, kind="ip", addresses=(validate_ip(candidate),)
        )

    return TargetSpec(raw=validate_hostname(candidate), kind="hostname", addresses=())


def validate_choice(value: str, allowed: tuple[str, ...], field: str) -> str:
    """Validate that ``value`` is one of ``allowed`` (case-insensitive)."""
    candidate = (value or "").strip()
    lookup = {item.lower(): item for item in allowed}
    if candidate.lower() not in lookup:
        raise ValidationError(
            f"{field} must be one of: {', '.join(allowed)}."
        )
    return lookup[candidate.lower()]


def validate_int_range(
    value: int | str, minimum: int, maximum: int, field: str
) -> int:
    """Validate an integer inside an inclusive range."""
    try:
        parsed = int(str(value).strip(), 10)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field} must be a whole number.") from exc
    if not minimum <= parsed <= maximum:
        raise ValidationError(f"{field} must be between {minimum} and {maximum}.")
    return parsed


def safe_filename(value: str, *, default: str = "aethra_export") -> str:
    """Reduce arbitrary text to a safe filename component.

    Path separators, traversal sequences and reserved characters are removed
    rather than escaped, so the result can never escape its target directory.
    """
    cleaned = _SAFE_FILENAME_RE.sub("_", (value or "").strip()).strip("._")
    cleaned = cleaned[:120]
    return cleaned or default


def resolve_within(base: Path, filename: str) -> Path:
    """Join ``filename`` to ``base``, guaranteeing the result stays inside it.

    Raises:
        ValidationError: if the resolved path escapes ``base``.
    """
    base_resolved = base.resolve()
    candidate = (base_resolved / safe_filename(filename)).resolve()
    if base_resolved not in candidate.parents and candidate != base_resolved:
        raise ValidationError("Resolved path escapes its permitted directory.")
    return candidate
