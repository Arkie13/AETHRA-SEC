"""The AETHRA-SEC mark, defined once.

The sign-in screen draws this on a Tk canvas and the Windows icon is rendered
from the same numbers, so the shortcut on the desktop is the same shield the
application shows rather than a lookalike that drifts the next time either is
touched.

Coordinates are given on a 64x64 grid and scale linearly, which is what lets
one definition serve a 16px taskbar icon and a 256px Explorer tile.
"""

from __future__ import annotations

#: The grid the coordinates below are expressed on.
LOGO_CANVAS = 64

#: A shield: flat top, angled shoulders, point at the bottom. Pairs of
#: ``(x, y)`` on the 64x64 grid, in drawing order.
LOGO_POLYGON: tuple[tuple[int, int], ...] = (
    (32, 4),
    (60, 16),
    (60, 36),
    (32, 60),
    (4, 36),
    (4, 16),
)

#: The letter inside the shield.
LOGO_LETTER = "A"

#: Outline thickness on the 64x64 grid, scaled with everything else.
LOGO_OUTLINE_WIDTH = 2


def logo_points(size: int = LOGO_CANVAS) -> list[tuple[float, float]]:
    """The shield outline scaled to a ``size`` x ``size`` square."""
    factor = size / LOGO_CANVAS
    return [(x * factor, y * factor) for x, y in LOGO_POLYGON]


def flat_logo_points(size: int = LOGO_CANVAS) -> list[float]:
    """The shield outline as the flat ``x1, y1, x2, y2, ...`` Tk wants."""
    return [value for point in logo_points(size) for value in point]
