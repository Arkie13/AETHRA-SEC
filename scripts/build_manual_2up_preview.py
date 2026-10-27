"""Build 2-up print previews of the Letter manual.

These exist only to SHOW what the printer will do. The manual itself stays
Letter, one Letter page per manual page; the imposition below is the printer's
job and is reproduced here so the result can be checked before paper is used.

Two portrait Letter pages placed side by side are WIDTH-limited, so the
sheet's long edge decides the reduction, and the reduction decides how large
the body text ends up on paper:

    short bond  (8.5 x 11 landscape)  ->  ~0.61  ->  11 pt prints at ~6.7 pt
    long bond   (8.5 x 13 landscape)  ->  ~0.73  ->  11 pt prints at ~8.0 pt

Both are generated so the difference can be judged on paper rather than
argued about. Nothing here changes the manual: it remains Letter.

Output: docs/AETHRA-SEC_User_Manual_2UP_PrintPreview.pdf
        docs/AETHRA-SEC_User_Manual_2UP_PrintPreview_LongBond.pdf
"""

from __future__ import annotations

from pathlib import Path

import pymupdf

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "AETHRA-SEC_User_Manual_Letter_BW.pdf"
OUT = ROOT / "docs" / "AETHRA-SEC_User_Manual_2UP_PrintPreview.pdf"

#: Sheets to impose onto, landscape, in inches.
SHEETS: dict[str, tuple[float, float]] = {
    "": (11.0, 8.5),            # Letter / short bond
    "_LongBond": (13.0, 8.5),   # Philippine long bond
}

#: Printer-safe gutter around each imposed page, so nothing lands in the
#: unprintable edge of an ordinary laser printer.
GUTTER = 12.0


def impose(src, sheet_w: float, sheet_h: float, out_path: Path) -> float:  # noqa: ANN001
    """Lay the Letter pages out two to a sheet. Returns the reduction factor."""
    out = pymupdf.open()
    first = src[0].rect
    half_w = sheet_w / 2
    scale = min(
        (half_w - 2 * GUTTER) / first.width,
        (sheet_h - 2 * GUTTER) / first.height,
    )
    placed_w, placed_h = first.width * scale, first.height * scale
    y0 = (sheet_h - placed_h) / 2

    for index in range(0, src.page_count, 2):
        sheet = out.new_page(width=sheet_w, height=sheet_h)
        for slot in (0, 1):
            page_no = index + slot
            if page_no >= src.page_count:
                break
            x0 = slot * half_w + (half_w - placed_w) / 2
            sheet.show_pdf_page(
                pymupdf.Rect(x0, y0, x0 + placed_w, y0 + placed_h),
                src, page_no,
            )
        # Hairline down the centre, marking the fold/cut line. Preview only -
        # it does not exist in the Letter manual.
        sheet.draw_line(
            pymupdf.Point(half_w, 18), pymupdf.Point(half_w, sheet_h - 18),
            color=(0.72, 0.72, 0.72), width=0.4, dashes="[2 3] 0",
        )

    out.save(str(out_path))
    out.close()
    return scale


def main() -> int:
    if not SOURCE.is_file():
        print(f"source not found: {SOURCE}")
        return 1

    src = pymupdf.open(str(SOURCE))
    first = src[0].rect
    print(f"source page : {first.width:.0f} x {first.height:.0f} pt "
          f"({first.width / 72:.2f} x {first.height / 72:.2f} in), "
          f"{src.page_count} pages")

    for suffix, (w_in, h_in) in SHEETS.items():
        path = OUT.with_name(OUT.stem + suffix + OUT.suffix)
        scale = impose(src, w_in * 72, h_in * 72, path)
        print(f"  {path.name}")
        print(f"      sheet {w_in:.2f} x {h_in:.2f} in landscape · "
              f"reduction {scale:.3f} · 11 pt body prints at "
              f"{11 * scale:.1f} pt · {(src.page_count + 1) // 2} sheets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
