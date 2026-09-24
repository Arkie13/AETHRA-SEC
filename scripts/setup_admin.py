"""Administrator and deployment setup, from the command line.

    python scripts/setup_admin.py
    python scripts/setup_admin.py --defaults
    python scripts/setup_admin.py --check-only

This is a thin front door. Every decision it makes - what a valid password is,
how it is hashed, how the configuration file is written, how the database is
created and migrated, how the dependencies are verified - lives in
:mod:`aethra_sec.setup`, which is the same code the graphical wizard and
``setup.bat`` run.

That is deliberate and it is the point of the module. This file used to carry
its own copy of the prompts, its own ``.env`` writer and its own SMTP test, and
a second implementation of "create the administrator" is exactly the thing that
drifts: the console path and the wizard path would sooner or later disagree
about what a valid account is, and the disagreement would surface as an
operator who cannot sign in to the account setup told them it had created.

**There is no two-factor authentication.** Earlier versions of this script
configured an email one-time-password step and could switch on a requirement
that refused administrator sign-in when mail delivery failed. That feature has
been removed from AETHRA-SEC. Sign-in is a username and a password; email is a
notification channel and nothing about it can grant or withhold access.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aethra_sec.setup.console import main as setup_main  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    """Run the shared console setup."""
    return setup_main(argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
