"""Print-layout post-process for the manual. PDF only.

The ReportLab generator is left untouched, so rebuilding still produces the
designed back cover; this is applied afterwards and is reversible from the
backup it keeps. Two changes:

1. A blank leaf after the front cover. This is the cover's verso, the page
   that faces the reader when the manual is opened - conventionally blank so
   the cover is not backed by text.

2. The last page becomes a copy of the front cover, replacing the designed
   back cover, so the manual is bookended by the same artwork.

The last page is REPLACED rather than appended, because appending would add a
page and the page count governs how cleanly the manual prints two pages to a
sheet. The resulting parity is reported rather than silently accepted.

Output: docs/AETHRA-SEC_User_Manual_Letter_BW.pdf (rewritten)
"""

from __future__ import annotations

import os
from pathlib import Path

import pymupdf

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "docs" / "AETHRA-SEC_User_Manual_Letter_BW.pdf"
BACKUP = ROOT / "docs" / "AETHRA-SEC_User_Manual_Letter_BW_designed_back.pdf"
TEMP = TARGET.with_suffix(".tmp.pdf")


def main() -> int:
    if not TARGET.is_file():
        print(f"not found: {TARGET}")
        return 1

    src = pymupdf.open(str(TARGET))
    before = src.page_count
    rect = src[0].rect

    if not BACKUP.is_file():
        src.save(str(BACKUP))
        print(f"kept the designed-back-cover version as {BACKUP.name}")

    out = pymupdf.open()
    # 1. front cover
    out.insert_pdf(src, from_page=0, to_page=0)
    # 2. blank verso
    out.new_page(width=rect.width, height=rect.height)
    # 3. body, up to but not including the old last page
    out.insert_pdf(src, from_page=1, to_page=src.page_count - 2)
    # 4. the front cover again, as the new last page
    page = out.new_page(width=rect.width, height=rect.height)
    page.show_pdf_page(page.rect, src, 0)

    # Save to a temporary file first: the source is still open on the target
    # path, and MuPDF cannot replace a file it is reading.
    out.save(str(TEMP), garbage=3, deflate=True)
    after = out.page_count
    out.close()
    src.close()
    os.replace(TEMP, TARGET)

    print(f"pages {before} -> {after}   even: {after % 2 == 0}")
    print("  page 1      front cover")
    print("  page 2      blank (cover verso)")
    print(f"  page {after}     copy of the front cover")
    if after % 2:
        print("\n  NOTE: the count is odd, so printing two pages to a sheet "
              "leaves the final sheet half empty.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
