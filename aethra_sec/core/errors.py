"""Exception hierarchy.

Every exception carries a ``user_message`` that is safe to display: it never
contains credentials, SQL, stack details, or information about whether a
username exists. The full technical detail goes to the diagnostic log.
"""

from __future__ import annotations


class AethraError(Exception):
    """Base class for all AETHRA-SEC errors."""

    default_message = "An unexpected error occurred."

    def __init__(self, message: str = "", *, user_message: str | None = None) -> None:
        super().__init__(message or self.default_message)
        self.user_message = user_message or message or self.default_message


def user_facing(exc: BaseException) -> str:
    """A message safe to put in front of an operator.

    Every error AETHRA-SEC raises deliberately carries a ``user_message``
    written for the person reading it, and that text is returned unchanged.

    Anything else reaching this function is a defect - an exception nobody
    anticipated - and its text was written for a developer, not an operator.
    Rendering it verbatim is how internals escape: ``FileNotFoundError`` prints
    the full path it tried to open, ``KeyError`` prints the name of the missing
    environment variable, and a driver error prints the statement it choked on.
    None of that is actionable to the person looking at the dialog, and all of
    it is exactly what must not be disclosed.

    The real exception is not discarded - callers log it with a traceback
    before calling this. What changes is only what the *screen* says.
    """
    if isinstance(exc, AethraError):
        return exc.user_message
    return (
        "An unexpected error occurred. The details have been recorded in the "
        "application log; the System Health screen reports ongoing problems."
    )


class ConfigurationError(AethraError):
    """Deployment configuration is missing or invalid."""

    default_message = "Configuration is incomplete or invalid."


class DatabaseError(AethraError):
    """A database operation failed."""

    default_message = "The database operation could not be completed."


class DatabaseUnavailableError(DatabaseError):
    """The database cannot be reached at all."""

    default_message = "DATABASE OFFLINE - the MySQL server could not be reached."


class SchemaError(DatabaseError):
    """The schema is missing, outdated, or inconsistent."""

    default_message = "The AETHRA-SEC database schema is missing or out of date."


class AuthenticationError(AethraError):
    """Authentication failed.

    The message is deliberately identical for unknown users and wrong
    passwords so that account existence is not disclosed (§62).
    """

    default_message = "Invalid username or password."


class AccountLockedError(AuthenticationError):
    """The account is locked after repeated failed attempts."""

    default_message = (
        "This account is temporarily locked. Contact an administrator or try "
        "again after the lockout period."
    )


class AccountInactiveError(AuthenticationError):
    """The account exists but has been deactivated."""

    default_message = "This account is not active. Contact an administrator."


class SessionExpiredError(AethraError):
    """The session token is unknown, expired, or was invalidated."""

    default_message = "Your session has expired. Please sign in again."


class PermissionDeniedError(AethraError):
    """The authenticated user lacks the required permission."""

    default_message = "You do not have permission to perform this action."

    def __init__(self, permission: str = "", *, user_message: str | None = None) -> None:
        detail = f"Permission denied: {permission}" if permission else ""
        # The technical detail goes to the log; the operator sees the generic
        # message unless the caller supplies something more specific.
        super().__init__(detail, user_message=user_message or self.default_message)
        self.permission = permission


class ValidationFailedError(AethraError):
    """Operator input failed validation."""

    default_message = "The information provided is not valid."


class AuthorizationBoundaryError(AethraError):
    """A target lies outside the networks the operator is authorised to assess."""

    default_message = (
        "The requested target is outside the authorised networks configured "
        "for this installation. Assessment refused."
    )


class ToolUnavailableError(AethraError):
    """A required external tool is missing or not executable."""

    default_message = "A required external tool is not available."

    def __init__(
        self, tool: str = "", detail: str = "", *, user_message: str | None = None
    ) -> None:
        message = f"{tool} unavailable: {detail}" if tool else detail
        super().__init__(message, user_message=user_message or message)
        self.tool = tool
        self.detail = detail


class CaptureError(AethraError):
    """Packet capture could not start or stopped unexpectedly."""

    default_message = "Packet capture could not be started."


class ScanError(AethraError):
    """An Nmap assessment failed."""

    default_message = "The vulnerability assessment could not be completed."


class ScanTimeoutError(ScanError):
    """Nmap did not finish inside the time the assessment was allowed.

    Kept distinct from :class:`ScanError` because the two mean different things
    about the target: a failure says the tool could not run, a timeout says it
    ran and the host did not let it finish. Neither is a result about security,
    and a timeout must never be recorded as a completed scan with no findings.
    """

    default_message = "The assessment timed out before Nmap finished."


class SnortIngestError(AethraError):
    """The Snort alert transport failed."""

    default_message = "The Snort alert transport is not available."


class ReportError(AethraError):
    """Report generation or export failed."""

    default_message = "The report could not be generated."


class IntegrityError(AethraError):
    """An integrity verification check failed."""

    default_message = "LOG INTEGRITY WARNING - stored records failed verification."
