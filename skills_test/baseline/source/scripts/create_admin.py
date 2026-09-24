"""Create the first AETHRA-SEC administrator account.

    python scripts/create_admin.py
    python scripts/create_admin.py --username soc.lead --role ADMIN

The password is read with :func:`getpass.getpass`, so it is never echoed, never
passed on the command line and never written to a log. Only the Argon2id (or
PBKDF2) hash reaches the database (§35, §98).

Once an administrator exists, create further accounts from the User Management
screen, where every creation is audited against the acting operator.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aethra_sec.config.settings import load_settings  # noqa: E402
from aethra_sec.core.errors import AethraError  # noqa: E402
from aethra_sec.database.connection import DatabaseManager  # noqa: E402
from aethra_sec.database.migrations import verify_schema  # noqa: E402
from aethra_sec.database.repositories.audit import AuditRepository  # noqa: E402
from aethra_sec.database.repositories.users import UserRepository  # noqa: E402
from aethra_sec.security.audit import (  # noqa: E402
    AuditAction,
    AuditCategory,
    AuditService,
)
from aethra_sec.security.password import PasswordHashService  # noqa: E402
from aethra_sec.utils.validation import (  # noqa: E402
    ValidationError,
    validate_password,
    validate_username,
)
from aethra_sec.version import APP_NAME, APP_VERSION  # noqa: E402


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse command-line arguments. The password is never an argument."""
    parser = argparse.ArgumentParser(
        prog="create_admin",
        description="Create an AETHRA-SEC account with the ADMIN role.",
        epilog="The password is prompted for; it cannot be passed on the command line.",
    )
    parser.add_argument("--username", default="", help="account name to create")
    parser.add_argument("--full-name", default="", help="display name (optional)")
    parser.add_argument("--email", default="", help="email address (optional)")
    parser.add_argument(
        "--role", default="ADMIN", choices=("ADMIN", "USER"),
        help="role to assign (default: ADMIN)",
    )
    parser.add_argument(
        "--must-change-password", action="store_true",
        help="require the account to set a new password at first sign-in",
    )
    return parser.parse_args(argv)


def _prompt_username(supplied: str) -> str:
    """Return a validated username, prompting until one is acceptable."""
    candidate = supplied
    while True:
        if not candidate:
            candidate = input("Username: ").strip()
        try:
            return validate_username(candidate)
        except ValidationError as exc:
            print(f"  {exc}")
            candidate = ""


def _prompt_password() -> str:
    """Read and confirm a password without echoing it."""
    while True:
        password = getpass.getpass("Password: ")
        try:
            validate_password(password)
        except ValidationError as exc:
            print(f"  {exc}")
            continue
        if password != getpass.getpass("Confirm password: "):
            print("  The two entries did not match.")
            continue
        return password


def main(argv: Sequence[str] | None = None) -> int:
    """Create the account described by the arguments and the prompts."""
    arguments = _parse_arguments(argv)
    settings = load_settings()
    print(f"{APP_NAME} {APP_VERSION} - create account")
    print(
        f"Target: {settings.database.user}@{settings.database.host}"
        f":{settings.database.port}/{settings.database.database}"
    )

    try:
        db = DatabaseManager(settings.database)
    except AethraError as exc:
        print(f"\nFailed: {exc.user_message}", file=sys.stderr)
        return 2

    try:
        schema_ok, detail = verify_schema(db)
        if not schema_ok:
            print(
                f"\nThe schema is not ready ({detail}).\n"
                "Run 'python scripts/init_db.py' first.",
                file=sys.stderr,
            )
            return 2

        users = UserRepository(db)
        role = users.get_role_by_name(arguments.role)
        if role is None or role.id is None:
            print(
                f"\nRole '{arguments.role}' is not present. Run "
                "'python scripts/init_db.py' to seed the roles.",
                file=sys.stderr,
            )
            return 2

        username = _prompt_username(arguments.username)
        if users.get_by_username(username) is not None:
            print(f"\nAn account named '{username}' already exists.", file=sys.stderr)
            return 2

        password = _prompt_password()
        passwords = PasswordHashService()
        hashed = passwords.hash(password)
        del password

        user_id = users.create_user(
            username=username,
            password_hash=hashed.hash,
            password_algorithm=hashed.algorithm,
            role_id=role.id,
            full_name=arguments.full_name,
            email=arguments.email,
            must_change_password=arguments.must_change_password,
        )

        audit = AuditService(AuditRepository(db))
        audit.record(
            AuditAction.USER_CREATED,
            username="(setup script)",
            category=AuditCategory.ADMINISTRATION,
            target_type="user",
            target_id=user_id,
            detail=(
                f"Account '{username}' created with role {arguments.role} by "
                "scripts/create_admin.py."
            ),
            source="SCRIPT",
        )

        print(
            f"\nCreated account '{username}' (id {user_id}) with role "
            f"{arguments.role}, hashed with {passwords.algorithm_description}."
        )
        print("Sign in with 'python -m aethra_sec.main'.")
        return 0
    except AethraError as exc:
        print(f"\nFailed: {exc.user_message}", file=sys.stderr)
        return 2
    except ValidationError as exc:
        print(f"\nFailed: {exc}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled; no account was created.")
        return 1
    finally:
        db.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
