"""Build the AETHRA-SEC installation and user manual as a real PDF.

Everything in the manual is read from, or verified against, this repository:
the installer's own Inno Setup script, the setup wizard's step titles, the
settings registry, the health service's component names, the screen classes'
own titles and subtitles, and the buttons the screens actually create. Where a
feature was removed the manual says so rather than describing it, and where a
capability depends on the network rather than the software the manual says
that too.

Screenshots are captures of the running application taken against a live
database. None are mock-ups.

Output: docs/AETHRA-SEC_User_Manual.pdf
"""

from __future__ import annotations

import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

ROOT = Path(__file__).resolve().parents[1]
_SCRATCH = Path(
    r"C:\Users\mark4\AppData\Local\Temp\claude"
    r"\c--xampp-htdocs-AETHRA-SECNEW\7f89d659-e265-4858-98fa-5f23b8e384c9"
    r"\scratchpad"
)
#: Annotated captures: numbered callouts placed from real widget
#: geometry, so a circle cannot point at the wrong control.
SHOTS = _SCRATCH / "shots2"
CALLOUTS = SHOTS / "callouts.json"
OUT = ROOT / "docs" / "AETHRA-SEC_User_Manual.pdf"

INK = colors.HexColor("#161A22")
MUTED = colors.HexColor("#5C6373")
ACCENT = colors.HexColor("#1E3F99")
RULE = colors.HexColor("#D6DBE4")
BAND = colors.HexColor("#EEF1F7")
WARN_BG = colors.HexColor("#FBEEDC")
WARN_EDGE = colors.HexColor("#9B5600")
NOTE_BG = colors.HexColor("#E7EEFB")

APP_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# A font with circled numerals
# ---------------------------------------------------------------------------
#: Helvetica has no U+2460, so the legends would print empty boxes next to
#: explanations while the screenshots carried real circles. Segoe UI Symbol
#: ships with Windows and covers the range; it is used for the numeral column
#: only. If it cannot be registered the legend falls back to (1), (2), ... so
#: the document is still correct, just less pretty.
CIRCLE_FONT = "Helvetica-Bold"
try:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont as _TTFont

    for _name, _file in (("SegoeSymbol", r"C:\Windows\Fonts\seguisym.ttf"),):
        if Path(_file).is_file():
            pdfmetrics.registerFont(_TTFont(_name, _file))
            CIRCLE_FONT = _name
            break
except Exception:  # noqa: BLE001 - a missing font must not fail the build
    pass

HAS_CIRCLE_GLYPHS = CIRCLE_FONT != "Helvetica-Bold"


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
_base = getSampleStyleSheet()

S = {
    "body": ParagraphStyle(
        "body", parent=_base["BodyText"], fontName="Helvetica", fontSize=9.5,
        leading=13.5, textColor=INK, alignment=TA_JUSTIFY, spaceAfter=5,
    ),
    "h1": ParagraphStyle(
        "h1", fontName="Helvetica-Bold", fontSize=17, leading=21,
        textColor=ACCENT, spaceBefore=0, spaceAfter=8,
    ),
    "h2": ParagraphStyle(
        "h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15,
        textColor=INK, spaceBefore=10, spaceAfter=4,
    ),
    "mono": ParagraphStyle(
        "mono", fontName="Courier", fontSize=8.2, leading=11.4,
        textColor=INK, backColor=BAND, borderPadding=5, spaceAfter=6,
    ),
    "caption": ParagraphStyle(
        "caption", fontName="Helvetica-Oblique", fontSize=8, leading=10.5,
        textColor=MUTED, alignment=TA_CENTER, spaceBefore=3, spaceAfter=8,
    ),
    "cell": ParagraphStyle(
        "cell", fontName="Helvetica", fontSize=8.3, leading=11, textColor=INK,
    ),
    "cellh": ParagraphStyle(
        "cellh", fontName="Helvetica-Bold", fontSize=8.3, leading=11,
        textColor=colors.white,
    ),
    "callout": ParagraphStyle(
        "callout", fontName="Helvetica", fontSize=8.8, leading=12.2,
        textColor=INK,
    ),
    "legendNum": ParagraphStyle(
        "legendNum", fontName=CIRCLE_FONT, fontSize=15,
        leading=13, textColor=ACCENT, alignment=TA_CENTER,
    ),
    "step": ParagraphStyle(
        "step", fontName="Helvetica-Bold", fontSize=12, leading=15,
        textColor=INK, spaceBefore=9, spaceAfter=4,
    ),
    "toc1": ParagraphStyle(
        "toc1", fontName="Helvetica-Bold", fontSize=9.5, leading=15,
        textColor=INK,
    ),
    "coverTitle": ParagraphStyle(
        "coverTitle", fontName="Helvetica-Bold", fontSize=30, leading=34,
        textColor=ACCENT, alignment=TA_CENTER,
    ),
    "coverSub": ParagraphStyle(
        "coverSub", fontName="Helvetica", fontSize=13, leading=18,
        textColor=MUTED, alignment=TA_CENTER,
    ),
    "coverName": ParagraphStyle(
        "coverName", fontName="Helvetica-Bold", fontSize=17, leading=22,
        textColor=INK, alignment=TA_CENTER,
    ),
}


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------
_counter = {"section": 0, "figure": 0}


def h1(text: str) -> list:
    _counter["section"] += 1
    number = _counter["section"]
    paragraph = Paragraph(f"{number}.&nbsp;&nbsp;{text}", S["h1"])
    paragraph._bookmark = (0, f"{number}. {text}")  # noqa: SLF001
    return [paragraph]


def h2(text: str) -> Paragraph:
    return Paragraph(text, S["h2"])


def p(text: str) -> Paragraph:
    return Paragraph(text, S["body"])


def mono(text: str) -> Paragraph:
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(escaped.replace("\n", "<br/>"), S["mono"])


def bullets(items: list[str]) -> list:
    return [
        Paragraph(f"&bull;&nbsp;&nbsp;{item}", S["body"]) for item in items
    ]


def table(header: list[str], rows: list[list[str]], widths: list[float]) -> Table:
    data = [[Paragraph(c, S["cellh"]) for c in header]]
    data += [[Paragraph(str(c), S["cell"]) for c in row] for row in rows]
    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BAND]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]))
    return t


def callout(kind: str, text: str) -> Table:
    background, edge = (
        (WARN_BG, WARN_EDGE) if kind.lower().startswith(("warn", "import"))
        else (NOTE_BG, ACCENT)
    )
    body = Paragraph(f"<b>{kind.upper()}</b><br/>{text}", S["callout"])
    t = Table([[body]], colWidths=[165 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background),
        ("LINEBEFORE", (0, 0), (0, -1), 2.4, edge),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def figure(stem: str, caption: str) -> list:
    """A real screenshot, scaled to the text width, kept with its caption."""
    path = SHOTS / f"{stem}.png"
    if not path.is_file():
        return [callout("note", f"Screenshot {stem}.png was not available.")]
    _counter["figure"] += 1
    reader = ImageReader(str(path))
    source_w, source_h = reader.getSize()
    width = 165 * mm
    height = width * source_h / source_w
    maximum = 132 * mm
    if height > maximum:
        height, width = maximum, maximum * source_w / source_h
    image = Image(str(path), width=width, height=height)
    image.hAlign = "CENTER"
    return [KeepTogether([
        image,
        Paragraph(f"Figure {_counter['figure']}. {caption}", S["caption"]),
    ])]


# ---------------------------------------------------------------------------
# Page furniture
# ---------------------------------------------------------------------------
#: Circled numerals matching the circles drawn on the screenshots. One style
#: throughout, so a reader never has to work out which scheme is in use.
CIRCLES = "\u2460\u2461\u2462\u2463\u2464\u2465\u2466\u2467\u2468\u2469\u246a\u246b"


def circle(n: int) -> str:
    """The circled numeral for n, or (n) beyond the glyph range."""
    if HAS_CIRCLE_GLYPHS and 1 <= n <= len(CIRCLES):
        return CIRCLES[n - 1]
    return f"({n})"


def step_heading(text: str):  # noqa: ANN201
    return Paragraph(text.upper(), S["step"])


def legend(entries) -> list:  # noqa: ANN001
    """The numbered explanations that sit under an annotated figure.

    A table rather than a list, so the numeral column stays aligned and the
    reader can match a circle in the image to its line without counting.
    """
    if not entries:
        return []
    rows = [
        [
            Paragraph(circle(e["n"]), S["legendNum"]),
            Paragraph(f"<b>{e['label']}</b><br/>{e['text']}", S["cell"]),
        ]
        for e in entries
    ]
    t = Table(rows, colWidths=[13 * mm, 152 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, RULE),
    ]))
    return [Spacer(1, 2 * mm), t]


def steps(items: list[str]) -> list:
    """A numbered procedure, in the order the reader performs it."""
    rows = [
        [Paragraph(f'<font face="Helvetica-Bold">{i}</font>', S["legendNum"]),
         Paragraph(text, S["cell"])]
        for i, text in enumerate(items, start=1)
    ]
    t = Table(rows, colWidths=[9 * mm, 156 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), BAND),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return [Spacer(1, 2 * mm), Paragraph("<b>Instructions</b>", S["h2"]), t]


def detail(key: str, caption: str) -> list:
    """An enlarged crop of one region, at a size its text can be read at.

    A 1898-pixel console scaled into a 165 mm column renders the packet table
    at roughly 1.4 pt. The crop shows the same real pixels, larger.
    """
    path = SHOTS / f"{key}.detail.png"
    if not path.is_file():
        return []
    _counter["figure"] += 1
    reader = ImageReader(str(path))
    source_w, source_h = reader.getSize()
    width = 165 * mm
    height = width * source_h / source_w
    image = Image(str(path), width=width, height=height)
    image.hAlign = "CENTER"
    return [KeepTogether([
        Spacer(1, 2 * mm),
        image,
        Paragraph(f"Figure {_counter['figure']}. {caption}", S["caption"]),
    ])]


def shot(key: str, caption: str, *, legend_entries=None) -> list:  # noqa: ANN001
    """An annotated screenshot with its caption and numbered explanations."""
    import json

    entries = legend_entries
    if entries is None:
        try:
            entries = json.loads(CALLOUTS.read_text(encoding="utf-8")).get(key, [])
        except Exception:  # noqa: BLE001
            entries = []
    return figure(key, caption) + legend(entries)


def _chrome(canvas, doc) -> None:  # noqa: ANN001
    canvas.saveState()
    width, height = A4
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(20 * mm, height - 12 * mm, "AETHRA-SEC")
    canvas.drawRightString(
        width - 20 * mm, height - 12 * mm,
        f"Installation and User Manual  \u00b7  v{APP_VERSION}",
    )
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(20 * mm, height - 14 * mm, width - 20 * mm, height - 14 * mm)
    canvas.line(20 * mm, 14 * mm, width - 20 * mm, 14 * mm)
    canvas.drawString(20 * mm, 10 * mm, "Authorised use only")
    canvas.drawRightString(width - 20 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _cover(canvas, doc) -> None:  # noqa: ANN001
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(ACCENT)
    canvas.rect(0, height - 58 * mm, width, 58 * mm, stroke=0, fill=1)
    icon = ROOT / "assets" / "aethra-sec.ico"
    if icon.is_file():
        try:
            canvas.drawImage(
                str(icon), (width - 22 * mm) / 2, height - 44 * mm,
                22 * mm, 22 * mm, mask="auto",
            )
        except Exception:  # noqa: BLE001 - an icon must not fail the build
            pass
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(20 * mm, 14 * mm, width - 20 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(20 * mm, 10 * mm, "Authorised use only")
    canvas.restoreState()


class Manual(BaseDocTemplate):
    """Adds the entries the table of contents is built from."""

    def afterFlowable(self, flowable) -> None:  # noqa: ANN001
        bookmark = getattr(flowable, "_bookmark", None)
        if bookmark is not None:
            level, text = bookmark
            key = f"sec{self.page}-{id(flowable)}"
            self.canv.bookmarkPage(key)
            self.notify("TOCEntry", (level, text, self.page, key))


def build_document(story: list) -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc = Manual(
        str(OUT), pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=20 * mm, bottomMargin=20 * mm,
        title="AETHRA-SEC Installation and User Manual",
        author="AETHRA-SEC", subject="Installation and operation",
    )
    frame = Frame(
        doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main"
    )
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[frame], onPage=_cover),
        PageTemplate(id="body", frames=[frame], onPage=_chrome),
    ])
    doc.multiBuild(story)
    return doc.page


def main() -> int:
    from manual_content import build_story  # noqa: PLC0415

    story = build_story()
    pages = build_document(story)
    size = OUT.stat().st_size / 1048576
    print(f"  wrote {OUT}")
    print(f"  {pages} pages, {size:.2f} MB, {_counter['section']} sections, "
          f"{_counter['figure']} figures")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))
    raise SystemExit(main())
