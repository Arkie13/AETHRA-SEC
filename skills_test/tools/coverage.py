"""Tie a behavioural test to the code it exercises.

A failing test says "the system misbehaves". To say "paste this into that
function" the diagnosis needs to know which function the test was about, and
guessing from the traceback is not good enough: the professor may change a
condition deep in a helper while the assertion fires in a caller.

So each test declares its target. The decorator is the whole mechanism:

    @covers("aethra_sec/models/host.py", "derive_security_result",
            feature="Vulnerability Assessment", action="Security result")
    def test_an_offline_host_is_not_safe() -> None:
        ...

When that test fails, the runner reads the target off the test function and
pulls the baseline text of exactly that function.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

#: Attribute the decorator attaches, read by the pytest hook.
ATTRIBUTE = "__skills_target__"


@dataclass(frozen=True)
class Target:
    """What a test is about, in the terms the student repairs in."""

    path: str
    qualname: str = ""
    feature: str = ""
    action: str = ""
    extra: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path, "qualname": self.qualname,
            "feature": self.feature, "action": self.action,
            "extra": list(self.extra),
        }


def covers(
    path: str,
    qualname: str = "",
    *,
    feature: str = "",
    action: str = "",
    also: tuple[str, ...] = (),
) -> Callable[[F], F]:
    """Declare the file and function a test exercises.

    Args:
        path: repository-relative path, e.g. ``aethra_sec/models/host.py``.
        qualname: ``function`` or ``Class.method`` inside that file.
        feature: the screen or subsystem, for the student-facing summary.
        action: the specific behaviour, e.g. ``"Mark reviewed"``.
        also: further ``"path::qualname"`` targets worth showing.
    """

    def decorate(function: F) -> F:
        setattr(function, ATTRIBUTE, Target(
            path=path, qualname=qualname, feature=feature,
            action=action, extra=tuple(also),
        ))
        return function

    return decorate
