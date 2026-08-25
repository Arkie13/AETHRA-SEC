"""Password hashing.

Argon2id is used when ``argon2-cffi`` is installed (the documented dependency).
If it is missing, AETHRA-SEC falls back to PBKDF2-HMAC-SHA256 from the standard
library rather than refusing to start or - far worse - storing anything weaker.
The active algorithm is reported on the System Health screen so the operator
always knows which one is in force.

Plaintext passwords are never stored, logged, echoed, exported or included in
an exception message.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("security.password")

ALGORITHM_ARGON2 = "argon2id"
ALGORITHM_PBKDF2 = "pbkdf2_sha256"

# PBKDF2 parameters for the fallback path. 600k iterations matches current
# OWASP guidance for PBKDF2-HMAC-SHA256.
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_SALT_BYTES = 16
_PBKDF2_DK_BYTES = 32

try:  # pragma: no cover - depends on the installation
    from argon2 import PasswordHasher
    from argon2.exceptions import (
        InvalidHashError,
        VerificationError,
        VerifyMismatchError,
    )

    ARGON2_AVAILABLE = True
    ARGON2_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover
    PasswordHasher = None  # type: ignore[assignment,misc]
    InvalidHashError = VerificationError = VerifyMismatchError = Exception  # type: ignore[misc,assignment]
    ARGON2_AVAILABLE = False
    ARGON2_IMPORT_ERROR = str(exc)


@dataclass(frozen=True)
class HashResult:
    """A stored credential: the encoded hash plus the algorithm that made it."""

    hash: str
    algorithm: str


class PasswordHashService:
    """Hashes and verifies passwords, with transparent algorithm upgrades."""

    def __init__(self, *, prefer_argon2: bool = True) -> None:
        """Create the service.

        Args:
            prefer_argon2: use Argon2id when the library is importable. Set to
                false only in tests that need the deterministic fallback.
        """
        self._use_argon2 = bool(prefer_argon2 and ARGON2_AVAILABLE)
        self._hasher = (
            PasswordHasher(
                time_cost=3,
                memory_cost=64 * 1024,  # 64 MiB
                parallelism=2,
                hash_len=32,
                salt_len=16,
            )
            if self._use_argon2
            else None
        )
        if not self._use_argon2 and prefer_argon2:
            LOGGER.warning(
                "argon2-cffi is not available (%s); using PBKDF2-HMAC-SHA256 "
                "with %d iterations instead.",
                ARGON2_IMPORT_ERROR,
                _PBKDF2_ITERATIONS,
            )

    @property
    def algorithm(self) -> str:
        """Name of the algorithm this service produces."""
        return ALGORITHM_ARGON2 if self._use_argon2 else ALGORITHM_PBKDF2

    @property
    def algorithm_description(self) -> str:
        """Human-readable description shown on the System Health screen."""
        if self._use_argon2:
            return "Argon2id (time_cost=3, memory=64 MiB, parallelism=2)"
        return f"PBKDF2-HMAC-SHA256 ({_PBKDF2_ITERATIONS:,} iterations)"

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------
    def hash(self, password: str) -> HashResult:
        """Hash a password with the active algorithm.

        Raises:
            ValueError: when the password is empty.
        """
        if not password:
            raise ValueError("Password must not be empty.")
        if self._use_argon2 and self._hasher is not None:
            return HashResult(self._hasher.hash(password), ALGORITHM_ARGON2)
        return HashResult(self._hash_pbkdf2(password), ALGORITHM_PBKDF2)

    @staticmethod
    def _hash_pbkdf2(password: str, salt: bytes | None = None) -> str:
        """Produce a ``pbkdf2_sha256$iterations$salt$hash`` encoded string."""
        salt_bytes = salt or secrets.token_bytes(_PBKDF2_SALT_BYTES)
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt_bytes,
            _PBKDF2_ITERATIONS,
            dklen=_PBKDF2_DK_BYTES,
        )
        return "$".join(
            (
                ALGORITHM_PBKDF2,
                str(_PBKDF2_ITERATIONS),
                base64.b64encode(salt_bytes).decode("ascii"),
                base64.b64encode(derived).decode("ascii"),
            )
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def verify(self, password: str, stored_hash: str) -> bool:
        """Check a password against a stored hash.

        The encoding of ``stored_hash`` decides which verifier runs, so an
        installation that gains or loses argon2-cffi can still authenticate
        accounts created under the other algorithm.

        Returns:
            True on a match. Never raises for a wrong password or malformed
            hash - both are simply a failed verification.
        """
        if not password or not stored_hash:
            return False
        if stored_hash.startswith("$argon2"):
            return self._verify_argon2(password, stored_hash)
        if stored_hash.startswith(f"{ALGORITHM_PBKDF2}$"):
            return self._verify_pbkdf2(password, stored_hash)
        LOGGER.warning("Stored credential uses an unrecognised hash format.")
        return False

    def _verify_argon2(self, password: str, stored_hash: str) -> bool:
        """Verify an Argon2 hash."""
        if not ARGON2_AVAILABLE or self._hasher is None:
            LOGGER.error(
                "An Argon2 credential exists but argon2-cffi is not installed; "
                "install it (pip install argon2-cffi) to authenticate this account."
            )
            return False
        try:
            self._hasher.verify(stored_hash, password)
            return True
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
        except Exception:  # noqa: BLE001 - never leak verifier internals
            LOGGER.exception("Unexpected error verifying an Argon2 credential")
            return False

    @staticmethod
    def _verify_pbkdf2(password: str, stored_hash: str) -> bool:
        """Verify a PBKDF2 hash in constant time."""
        try:
            algorithm, iterations_text, salt_b64, hash_b64 = stored_hash.split("$", 3)
            if algorithm != ALGORITHM_PBKDF2:
                return False
            iterations = int(iterations_text, 10)
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
        except (ValueError, TypeError):
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected)
        )
        return hmac.compare_digest(derived, expected)

    def needs_rehash(self, stored_hash: str) -> bool:
        """True when a stored credential should be upgraded on next login.

        A PBKDF2 credential on an Argon2-capable installation, or an Argon2
        credential whose parameters no longer match the configured cost.
        """
        if not stored_hash:
            return False
        if self._use_argon2 and self._hasher is not None:
            if not stored_hash.startswith("$argon2"):
                return True
            try:
                return bool(self._hasher.check_needs_rehash(stored_hash))
            except Exception:  # noqa: BLE001
                return False
        return False


def generate_temporary_password(length: int = 16) -> str:
    """Generate a random password for an administrator-initiated reset.

    The result always satisfies the complexity policy (three of four character
    classes) so a reset never produces a password the policy would reject.
    """
    alphabet_lower = "abcdefghijkmnopqrstuvwxyz"
    alphabet_upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    digits = "23456789"
    symbols = "!@#$%^&*-_=+"
    pool = alphabet_lower + alphabet_upper + digits + symbols
    size = max(12, int(length))
    chars = [
        secrets.choice(alphabet_lower),
        secrets.choice(alphabet_upper),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    chars.extend(secrets.choice(pool) for _ in range(size - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


#: Alphabet for recovery codes: upper-case letters and digits with the
#: ambiguous pairs (O/0, I/1, S/5) removed, because the code is read aloud or
#: copied by hand from an administrator to the account owner.
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRTUVWXYZ2346789"


def generate_recovery_code(groups: int = 4, group_size: int = 4) -> str:
    """Generate a one-time password-recovery authorisation code.

    Sixteen characters from a 30-symbol alphabet is roughly 78 bits of entropy,
    drawn from :mod:`secrets`. The code is shown to the approving administrator
    once; only :func:`code_fingerprint` of it is ever stored.
    """
    count = max(2, int(groups))
    size = max(3, int(group_size))
    return "-".join(
        "".join(secrets.choice(_CODE_ALPHABET) for _ in range(size))
        for _ in range(count)
    )


def normalise_recovery_code(code: str) -> str:
    """Canonicalise a typed code so formatting differences never reject it.

    Spaces, hyphens and case are cosmetic; the value that is hashed is the bare
    upper-case alphabet.
    """
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def code_fingerprint(code: str) -> str:
    """SHA-256 fingerprint of a normalised recovery code.

    The database stores the fingerprint, never the code, so reading the table
    does not yield anything that can be presented at the sign-in screen.
    """
    return hashlib.sha256(normalise_recovery_code(code).encode("utf-8")).hexdigest()


def token_fingerprint(token: str) -> str:
    """SHA-256 fingerprint of a session token.

    The database stores the fingerprint, never the token itself, so a database
    read cannot be replayed as a valid session.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
