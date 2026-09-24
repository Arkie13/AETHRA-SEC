"""Render assets/aethra-sec.ico from the application's own logo definition.

There is no logo image in the repository - the sign-in screen draws the mark on
a canvas. So rather than invent an icon, this renders the same shield from
:mod:`aethra_sec.ui.brand` in the same palette colours the interface uses, at
every size Windows asks for.

Run directly, or through ``setup.bat``. Safe to re-run: it overwrites.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from PIL import Image, ImageDraw, ImageFont

    from aethra_sec.ui.brand import (
        LOGO_LETTER,
        LOGO_OUTLINE_WIDTH,
        logo_points,
    )
    from aethra_sec.ui.theme import DARK_PALETTE
except ImportError as exc:  # pragma: no cover - a broken install, not a bug
    # A raw traceback here is noise during setup. The shortcut still works
    # without an icon, so say what is missing and stop cleanly.
    print(f"  Cannot render the icon: {exc}")
    print("  Run setup.bat first so the dependencies are installed.")
    raise SystemExit(1) from exc

#: Sizes Windows selects between - 16 in the taskbar, 256 in Explorer's
#: largest tile. All are stored in the one .ico.
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)

#: Rendered at 8x and downsampled, because Pillow has no anti-aliased polygon
#: drawing: a 16px shield drawn directly has visibly ragged diagonals.
SUPERSAMPLE = 8


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """A bold face for the letter, falling back to Pillow's own."""
    for name in ("segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def render(size: int) -> Image.Image:
    """One square icon image with a transparent ground.

    Transparent rather than the sign-in screen's panel colour: the icon sits on
    whatever wallpaper the operator has, and a baked-in background would show
    as a coloured tile around the shield.
    """
    work = size * SUPERSAMPLE
    image = Image.new("RGBA", (work, work), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    points = logo_points(work)
    draw.polygon(
        points,
        fill=DARK_PALETTE.accent_soft,
        outline=DARK_PALETTE.accent,
        width=max(1, round(LOGO_OUTLINE_WIDTH * work / 64)),
    )

    # The letter is sized against the shield, not the canvas, so it keeps its
    # proportion at every size.
    letter_font = _font(round(work * 0.46))
    box = draw.textbbox((0, 0), LOGO_LETTER, font=letter_font)
    draw.text(
        (
            (work - (box[2] - box[0])) / 2 - box[0],
            # Nudged up slightly: the shield's point sits below centre, so
            # optical centring is a little above geometric centring.
            (work - (box[3] - box[1])) / 2 - box[1] - work * 0.03,
        ),
        LOGO_LETTER,
        font=letter_font,
        fill=DARK_PALETTE.accent,
    )
    return image.resize((size, size), Image.LANCZOS)


def main() -> int:
    """Write the multi-resolution icon."""
    target = PROJECT_ROOT / "assets" / "aethra-sec.ico"
    target.parent.mkdir(parents=True, exist_ok=True)

    largest = render(max(ICON_SIZES))
    largest.save(
        target,
        format="ICO",
        sizes=[(size, size) for size in ICON_SIZES],
    )
    print(f"  Wrote {target.relative_to(PROJECT_ROOT)} "
          f"({', '.join(f'{s}x{s}' for s in ICON_SIZES)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
