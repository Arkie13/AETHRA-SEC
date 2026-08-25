"""Input validation.

EMAIL_RE is copied verbatim from aethra_sec/utils/validation.py so this
service's notion of a valid email stays consistent with the desktop app's,
without importing the desktop app's package.
"""

from __future__ import annotations

import re

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]{1,63}(\.[^@\s.]{1,63})+$")

MAX_NAME_LENGTH = 120
MAX_EMAIL_LENGTH = 254


def is_valid_email(value: str) -> bool:
    return bool(value) and len(value) <= MAX_EMAIL_LENGTH and bool(EMAIL_RE.match(value))


def is_valid_name(value: str) -> bool:
    stripped = value.strip()
    return bool(stripped) and len(stripped) <= MAX_NAME_LENGTH
