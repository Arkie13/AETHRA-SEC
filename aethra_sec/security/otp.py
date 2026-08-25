"""Optional email one-time-password second factor (§6, §62).

The second factor is **off** unless it is both enabled and fully configured.
:meth:`OtpService.status` returns the exact configured state, which the login
screen and System Health page display verbatim - the interface never implies a
second factor is protecting an account when it is not.
"""

from __future__ import annotations

import secrets
import smtplib
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.message import EmailMessage

from aethra_sec.config.settings import OtpSettings
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("security.otp")

_CODE_DIGITS = 6
_MAX_ATTEMPTS = 5


@dataclass
class PendingChallenge:
    """An issued OTP awaiting verification."""

    user_id: int
    code: str
    expires_at: datetime
    attempts: int = 0
    delivered: bool = False
    delivery_error: str = ""


@dataclass(frozen=True)
class OtpStatus:
    """Truthful description of the second-factor configuration."""

    enabled: bool
    operational: bool
    detail: str

    @property
    def display(self) -> str:
        """Status text for the interface."""
        return self.detail


class OtpService:
    """Issues and verifies email one-time passwords when SMTP is configured."""

    def __init__(self, settings: OtpSettings) -> None:
        """Bind the service to the deployment's OTP settings."""
        self._settings = settings
        self._lock = threading.Lock()
        self._pending: dict[int, PendingChallenge] = {}

    @property
    def is_enabled(self) -> bool:
        """True when the operator asked for a second factor."""
        return self._settings.enabled

    @property
    def is_operational(self) -> bool:
        """True only when a challenge could actually be delivered."""
        return self._settings.is_operational

    def status(self) -> OtpStatus:
        """Report the exact configured state, never an optimistic one."""
        return OtpStatus(
            enabled=self._settings.enabled,
            operational=self._settings.is_operational,
            detail=self._settings.status_text(),
        )

    def required_for(self, email: str) -> bool:
        """True when this account must complete a second factor.

        An account without an email address cannot receive a code, so requiring
        one would lock it out. That case is reported as a configuration warning
        on the System Health screen instead.
        """
        return bool(self.is_operational and email)

    def issue(self, user_id: int, email: str) -> PendingChallenge:
        """Generate and send a challenge.

        Returns:
            The pending challenge. ``delivered`` is false and
            ``delivery_error`` explains why when SMTP delivery failed - the
            caller must not treat an undelivered challenge as satisfied.
        """
        code = f"{secrets.randbelow(10 ** _CODE_DIGITS):0{_CODE_DIGITS}d}"
        challenge = PendingChallenge(
            user_id=user_id,
            code=code,
            expires_at=utcnow() + timedelta(seconds=self._settings.ttl_seconds),
        )
        try:
            self._send(email, code)
            challenge.delivered = True
        except Exception as exc:  # noqa: BLE001 - report, never crash login
            challenge.delivery_error = str(exc)
            LOGGER.error("Could not deliver the OTP challenge: %s", exc)
        with self._lock:
            self._pending[user_id] = challenge
        return challenge

    def verify(self, user_id: int, code: str) -> tuple[bool, str]:
        """Verify a submitted code.

        Returns:
            ``(ok, reason)``. ``reason`` is a safe message for the login
            screen when verification failed.
        """
        with self._lock:
            challenge = self._pending.get(user_id)
            if challenge is None:
                return False, "No verification code is pending. Sign in again."
            if utcnow() >= challenge.expires_at:
                self._pending.pop(user_id, None)
                return False, "The verification code has expired. Sign in again."
            challenge.attempts += 1
            if challenge.attempts > _MAX_ATTEMPTS:
                self._pending.pop(user_id, None)
                return False, "Too many incorrect codes. Sign in again."
            if secrets.compare_digest(challenge.code, (code or "").strip()):
                self._pending.pop(user_id, None)
                return True, ""
            return False, "The verification code is incorrect."

    def cancel(self, user_id: int) -> None:
        """Discard a pending challenge (used when a login is abandoned)."""
        with self._lock:
            self._pending.pop(user_id, None)

    def _send(self, recipient: str, code: str) -> None:
        """Deliver a code by SMTP.

        Raises:
            RuntimeError: when SMTP is not configured.
            Exception: any SMTP failure, surfaced to the caller as-is.
        """
        settings = self._settings
        if not settings.is_operational:
            raise RuntimeError(
                "Email second factor is not operational: SMTP is not configured."
            )
        if not recipient:
            raise RuntimeError("The account has no email address on file.")

        message = EmailMessage()
        message["Subject"] = "AETHRA-SEC sign-in verification code"
        message["From"] = settings.mail_from
        message["To"] = recipient
        message.set_content(
            "Your AETHRA-SEC verification code is:\n\n"
            f"    {code}\n\n"
            f"It expires in {settings.ttl_seconds // 60} minute(s).\n\n"
            "If you did not attempt to sign in, tell your administrator: "
            "someone may know your password."
        )

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            if settings.use_starttls:
                smtp.starttls()
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(message)
        LOGGER.info("Delivered an OTP challenge to a configured recipient.")
