"""Outbound email for administrative and security notifications.

This is a notification channel and nothing else. AETHRA-SEC's sign-in is a
username and a password; no state of this service can grant access or withhold
it, and a mail server that is down is an operational inconvenience rather than
a lockout. That is the whole reason it is a separate service from
authentication instead of a step inside it.

Two rules shape everything here:

* **A send is reported as it happened.** :meth:`EmailNotifier.send` returns a
  :class:`DeliveryResult` that says whether the server actually accepted the
  message. Nothing in this module ever reports "sent" for a message that was
  not handed to a server, and a configuration that is merely *present* is
  described as configured, never as proven.
* **The credential never leaves this module.** It is read from the
  configuration, held for the duration of a connection and never written to a
  log line, an audit record, an exception message or the interface. Server
  errors are rewritten before they are recorded, because SMTP libraries are
  perfectly willing to quote the failed command back at you.

Delivery runs on a worker thread. An SMTP server that has stopped answering
takes as long as its timeout to say so, and the console must not stop repainting
while that happens.
"""

from __future__ import annotations

import queue
import re
import smtplib
import ssl
import threading
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Callable

from aethra_sec.config.settings import SmtpSettings
from aethra_sec.utils.logging import get_logger
from aethra_sec.version import APP_NAME

LOGGER = get_logger("services.email")

#: Anything in an exception string that looks like it might carry a credential.
_SECRET_PATTERN = re.compile(r"(?i)\b(password|passwd|auth|credential|token)\S*")

#: Queued messages held while the sender is busy. A burst of alerts must not be
#: able to grow this without bound; beyond it, sends are dropped and *said* to
#: be dropped rather than silently accumulating in memory.
MAX_QUEUE_DEPTH = 200


@dataclass(frozen=True)
class DeliveryResult:
    """What actually happened to one message.

    Attributes:
        delivered: True only when a mail server accepted the message. Never
            set optimistically - a queued message that has not been handed to
            a server yet is not delivered.
        detail: operator-facing description. Safe to display and to log; the
            credential has already been stripped.
        recipient: where it was addressed, for the audit record.
    """

    delivered: bool
    detail: str
    recipient: str = ""

    @property
    def status_text(self) -> str:
        """One line for the interface."""
        return "SENT" if self.delivered else "NOT SENT"


def describe_smtp_error(exc: Exception) -> str:
    """Describe an SMTP failure in a way that helps and discloses nothing.

    The common Gmail failure is worth naming explicitly: an ordinary account
    password is rejected where a 16-character App Password is required, and the
    server's own message does not say so.
    """
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return (
            "The mail server rejected the sign-in. For Gmail this usually "
            "means an ordinary account password was used where a 16-character "
            "App Password is required, and that 2-Step Verification must be "
            "enabled on the sending account before one can be created."
        )
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "The mail server refused the destination address."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return (
            "The mail server refused the sender address. It usually has to "
            "match the account the message is sent from."
        )
    if isinstance(exc, ssl.SSLError):
        return (
            "The TLS handshake failed. Port 587 expects STARTTLS and port 465 "
            "expects implicit TLS; check that the port and the TLS setting agree."
        )
    if isinstance(exc, (smtplib.SMTPConnectError, TimeoutError, OSError)):
        return (
            "The mail server could not be reached. Check the host and port, "
            "and that outbound SMTP is not blocked on this network."
        )
    return _SECRET_PATTERN.sub("[redacted]", str(exc))[:200]


class EmailNotifier:
    """Sends notification email, when and only when SMTP is configured."""

    def __init__(
        self,
        settings: SmtpSettings,
        *,
        audit: Callable[[bool, str, str], None] | None = None,
    ) -> None:
        """Bind the notifier to its configuration.

        Args:
            settings: SMTP deployment settings.
            audit: optional ``(delivered, recipient, detail)`` callback used to
                record the outcome. Optional so the setup wizard and the tests
                can send without an audit trail to write to.
        """
        self._settings = settings
        self._audit = audit
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple[str, str, str]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._sent = 0
        self._failed = 0
        self._dropped = 0
        self._last_error = ""

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    @property
    def is_configured(self) -> bool:
        """True when a message could be addressed and a server contacted."""
        return self._settings.is_configured

    def status_text(self) -> str:
        """``SMTP CONFIGURED`` / ``SMTP NOT CONFIGURED``, verbatim."""
        return self._settings.status_text()

    def statistics(self) -> dict[str, object]:
        """Real counters for the System Health screen."""
        with self._lock:
            return {
                "configured": self._settings.is_configured,
                "status": self._settings.status_text(),
                "sent": self._sent,
                "failed": self._failed,
                "dropped": self._dropped,
                "queued": self._queue.qsize(),
                "last_error": self._last_error,
            }

    def default_recipient(self, fallback: str = "") -> str:
        """Where notifications go: the configured address, else ``fallback``."""
        return self._settings.recipient or fallback

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------
    def send(self, recipient: str, subject: str, body: str) -> DeliveryResult:
        """Send one message now, on the calling thread.

        Blocks for up to the configured timeout. Used by the setup wizard,
        where the operator is waiting for the answer and a truthful "it did not
        work" is the entire point of the step.
        """
        if not self._settings.is_configured:
            return DeliveryResult(False, "SMTP NOT CONFIGURED", recipient)
        destination = (recipient or "").strip()
        if not destination:
            return DeliveryResult(
                False, "No destination address is configured.", ""
            )

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self._settings.mail_from
        message["To"] = destination
        message["Date"] = formatdate(localtime=True)
        message["Message-ID"] = make_msgid()
        message["Auto-Submitted"] = "auto-generated"
        message.set_content(body)

        try:
            self._transmit(message)
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            detail = describe_smtp_error(exc)
            with self._lock:
                self._failed += 1
                self._last_error = detail
            LOGGER.warning("Notification email was not delivered: %s", detail)
            self._record(False, destination, detail)
            return DeliveryResult(False, detail, destination)

        with self._lock:
            self._sent += 1
            self._last_error = ""
        LOGGER.info("Notification email delivered to %s.", _mask(destination))
        detail = f"Delivered to {_mask(destination)}."
        self._record(True, destination, detail)
        return DeliveryResult(True, detail, destination)

    def send_async(self, recipient: str, subject: str, body: str) -> bool:
        """Queue a message for the sender thread.

        Returns:
            True when the message was queued - which is *not* a claim that it
            was delivered. The outcome is recorded by the worker and shows up
            in :meth:`statistics` and in the audit trail.
        """
        if not self._settings.is_configured:
            return False
        if self._queue.qsize() >= MAX_QUEUE_DEPTH:
            with self._lock:
                self._dropped += 1
            LOGGER.warning(
                "Notification email dropped: %d already queued.", MAX_QUEUE_DEPTH
            )
            return False
        self._ensure_worker()
        self._queue.put((recipient, subject, body))
        return True

    def _transmit(self, message: EmailMessage) -> None:
        """Hand the message to the server. Raises on any failure."""
        context = ssl.create_default_context()
        host = self._settings.host
        port = self._settings.port
        timeout = self._settings.timeout_seconds

        if self._settings.use_starttls:
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if self._settings.username:
                    server.login(self._settings.username, self._settings.password)
                server.send_message(message)
        else:
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as server:
                if self._settings.username:
                    server.login(self._settings.username, self._settings.password)
                server.send_message(message)

    def _record(self, delivered: bool, recipient: str, detail: str) -> None:
        """Write the outcome to the audit trail, if one was supplied."""
        if self._audit is None:
            return
        try:
            self._audit(delivered, _mask(recipient), detail)
        except Exception:  # noqa: BLE001 - auditing must not break sending
            LOGGER.debug("Could not audit the email outcome.", exc_info=True)

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------
    def _ensure_worker(self) -> None:
        """Start the sender thread if it is not already running."""
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._stop.clear()
            self._worker = threading.Thread(
                target=self._run, name="aethra-email", daemon=True
            )
            self._worker.start()

    def _run(self) -> None:
        """Drain the queue until asked to stop."""
        while not self._stop.is_set():
            try:
                recipient, subject, body = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.send(recipient, subject, body)
            except Exception:  # noqa: BLE001 - one bad send must not end the thread
                LOGGER.exception("The email sender thread hit an unexpected error.")

    def close(self, timeout: float = 5.0) -> None:
        """Stop the sender thread during shutdown."""
        self._stop.set()
        worker = self._worker
        if worker is not None and worker.is_alive():
            worker.join(timeout=timeout)
        self._worker = None


def mask_email(address: str) -> str:
    """``a*****@example.com`` - enough to identify, not enough to disclose.

    Used wherever an address is shown back to whoever is at the keyboard. The
    interface can then confirm *which* address is registered without printing
    it for anyone standing behind the operator.
    """
    local, _, domain = (address or "").partition("@")
    if not local or not domain:
        return "the configured address"
    return f"{local[0]}{'*' * max(1, len(local) - 1)}@{domain}"


#: Internal alias kept for the call sites inside this module.
_mask = mask_email


def test_message_body(destination: str) -> str:
    """The body of the delivery test the setup wizard sends."""
    return (
        f"{APP_NAME} is configured to send administrative and security "
        f"notifications to {destination}.\n\n"
        "This message confirms that delivery works. No action is needed.\n\n"
        f"{APP_NAME} does not use email for signing in. Nobody will ever be "
        "sent a login code, and no message from this system will ask for a "
        "password.\n"
    )
