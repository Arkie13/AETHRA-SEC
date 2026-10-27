"""Filling a stored procedure's placeholders from the record being viewed.

The knowledge base stores commands with ``<SOURCE_IP>``, ``<TARGET_IP>``,
``<PORT>`` and ``<PROTOCOL>`` in them, because a command with somebody else's
address in it is worse than no command at all. Three screens show those
procedures - the alert detail dialog, the Mitigation screen and the
Vulnerability Assessment drawer - and each is looking at a different kind of
record, so the filling lives here rather than in any one of them.

The rule throughout: a value the record does not carry is never guessed, never
borrowed from another record, and never quietly deleted. Its placeholder stays
on screen, and the caller is given the means to say why.
"""

from __future__ import annotations

from typing import Any

#: Every placeholder a stored procedure may carry.
PLACEHOLDERS = ("<SOURCE_IP>", "<TARGET_IP>", "<PORT>", "<PROTOCOL>")


def _text(record: Any, *names: str) -> str:
    """The first of these attributes the record actually carries.

    A traffic anomaly names its addresses ``src_ip`` and ``dst_ip``; a
    vulnerability finding has one address, ``ip_address``, which is the host
    the finding is about and therefore the target. Trying each name in turn
    keeps the three screens from having to know about each other.
    """
    for name in names:
        value = getattr(record, name, None)
        if value in (None, "", 0):
            continue
        return str(value).strip()
    return ""


def guide_context(record: Any) -> dict[str, str]:
    """The values this record can legitimately supply to a procedure.

    Only fields the record carries. A missing field is absent from the
    mapping, so its placeholder survives into the displayed text and the
    operator can see what they still have to establish for themselves.
    """
    if record is None:
        return {}
    context: dict[str, str] = {}
    source = _text(record, "src_ip")
    target = _text(record, "dst_ip", "ip_address")
    protocol = _text(record, "protocol")
    port = _text(record, "dst_port", "port")
    if source:
        context["<SOURCE_IP>"] = source
    if target:
        context["<TARGET_IP>"] = target
    if protocol:
        context["<PROTOCOL>"] = protocol
    if port:
        context["<PORT>"] = port
    return context


def apply_guide_context(text: str, context: dict[str, str]) -> str:
    """Substitute the values this record supplied, and only those."""
    if not text:
        return ""
    for placeholder, value in context.items():
        text = text.replace(placeholder, value)
    return text


def unfilled_placeholders(text: str) -> list[str]:
    """Placeholders still present, so the gap can be named rather than hidden."""
    return [name for name in PLACEHOLDERS if name in (text or "")]


def placeholder_note(outstanding: list[str]) -> str:
    """The sentence that explains why a placeholder is still on screen.

    Without it an operator reads a half-finished command and reasonably
    assumes the system failed to fill it in. With it, the gap is the message:
    these are the values you have to establish before running anything.
    """
    if not outstanding:
        return ""
    named = ", ".join(
        name.strip("<>").replace("_", " ").lower() for name in outstanding
    )
    return (
        f"This detection did not record {named}. Those placeholders are left "
        "in place on purpose - establish the real values before running any "
        "command. Nothing has been filled in from another alert."
    )
