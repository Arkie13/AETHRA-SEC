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
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
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
OUT = ROOT / "docs" / "AETHRA-SEC_User_Manual_Letter_BW.pdf"

# Black, white and grayscale only. The manual is printed two Letter pages to
# one sheet of bond paper, often on a mono laser or a photocopier, so nothing
# in the document design may carry meaning by colour alone - importance is
# shown by rule weight, fill value and bold type instead.
#
# Genuine application screenshots keep their own UI colours; recolouring them
# would misrepresent what the operator actually sees on screen.
INK = colors.HexColor("#000000")
MUTED = colors.HexColor("#4A4A4A")
ACCENT = colors.HexColor("#000000")
RULE = colors.HexColor("#8C8C8C")
BAND = colors.HexColor("#E6E6E6")
#: IMPORTANT / WARNING callouts keep the warm cream fill and brown rule, by
#: request. They are the one place in the body where colour carries weight,
#: and they still read correctly in mono: the fill drops to a light grey and
#: the rule to a dark one, so the box and its bar remain distinct from the
#: page and from the NOTE boxes.
WARN_BG = colors.HexColor("#FBEEDC")
WARN_EDGE = colors.HexColor("#9B5600")
NOTE_BG = colors.HexColor("#F7F7F7")
#: Table header fill. Dark enough to separate, light enough that bold black
#: header text stays legible after a 2-up reduction and a photocopy.
HEADER_BAND = colors.HexColor("#CFCFCF")
#: Cover band only. Deliberately NOT ACCENT: headings, rules, callout numbers
#: and the cover title all draw with ACCENT, and that stays black so the body
#: of the manual still prints as a black-and-white document. This one colour
#: is confined to the masthead behind the brand mark.
COVER_BAND = colors.HexColor("#1E3F99")

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
        "body", parent=_base["BodyText"], fontName="Helvetica", fontSize=11,
        leading=15.5, textColor=INK, alignment=TA_JUSTIFY, spaceAfter=5,
    ),
    "h1": ParagraphStyle(
        "h1", fontName="Helvetica-Bold", fontSize=20, leading=24,
        textColor=ACCENT, spaceBefore=0, spaceAfter=8,
    ),
    "h2": ParagraphStyle(
        "h2", fontName="Helvetica-Bold", fontSize=14, leading=18,
        textColor=INK, spaceBefore=10, spaceAfter=4,
    ),
    "mono": ParagraphStyle(
        "mono", fontName="Courier", fontSize=9.5, leading=13,
        textColor=INK, backColor=BAND, borderPadding=5, spaceAfter=6,
    ),
    "caption": ParagraphStyle(
        "caption", fontName="Helvetica-Oblique", fontSize=9.5, leading=12.5,
        textColor=MUTED, alignment=TA_CENTER, spaceBefore=3, spaceAfter=8,
    ),
    "cell": ParagraphStyle(
        "cell", fontName="Helvetica", fontSize=9.5, leading=12.5, textColor=INK,
    ),
    "cellh": ParagraphStyle(
        # Black on the light grey header band. The original design put white
        # text on a saturated blue fill; keeping white over a grey band left
        # the header all but invisible, and invisible on a photocopy entirely.
        "cellh", fontName="Helvetica-Bold", fontSize=9.5, leading=12.5,
        textColor=INK,
    ),
    "callout": ParagraphStyle(
        "callout", fontName="Helvetica", fontSize=10, leading=13.5,
        textColor=INK,
    ),
    "legendNum": ParagraphStyle(
        "legendNum", fontName=CIRCLE_FONT, fontSize=16,
        leading=13, textColor=ACCENT, alignment=TA_CENTER,
    ),
    "step": ParagraphStyle(
        "step", fontName="Helvetica-Bold", fontSize=13.5, leading=17,
        textColor=INK, spaceBefore=9, spaceAfter=4,
    ),
    "toc1": ParagraphStyle(
        # 30 entries have to sit on one page. At leading 16 the last line
        # ("30. Security considerations and limitations") spilled alone onto
        # page 3, which then held nothing else - the single worst piece of
        # white space in the document, and a wasted half-sheet when printed
        # two-up. 14 closes the gap without crowding the list.
        "toc1", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
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
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BAND),
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
    width, height = LETTER
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
    width, height = LETTER
    canvas.setFillColor(COVER_BAND)
    canvas.rect(0, height - 58 * mm, width, 58 * mm, stroke=0, fill=1)
    # The brand mark keeps its colour on the cover, by request. It is the one
    # deliberate exception to the black-and-white document design; everything
    # else - headings, rules, tables, note boxes, callouts - stays monochrome.
    # It still reproduces cleanly on a mono printer: the mark is light on a
    # black band, so the contrast survives the conversion to grey.
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


def _back_cover(canvas, doc) -> None:  # noqa: ANN001
    """Masthead only, matching the front cover.

    No footer rule and no folio: a back cover carries no page number, and the
    front cover's "Authorised use only" strip would duplicate the statement
    already set in the IMPORTANT box on this page.
    """
    canvas.saveState()
    width, height = LETTER
    canvas.setFillColor(COVER_BAND)
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
        str(OUT), pagesize=LETTER,
        leftMargin=0.70 * inch, rightMargin=0.70 * inch,
        topMargin=0.65 * inch, bottomMargin=0.65 * inch,
        title="AETHRA-SEC Installation and User Manual",
        author="AETHRA-SEC", subject="Installation and operation",
    )
    frame = Frame(
        doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main"
    )
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[frame], onPage=_cover),
        PageTemplate(id="body", frames=[frame], onPage=_chrome),
        # Paints nothing: no header, no footer, no rule, no folio. Used for
        # the trailing blank page, which has to be genuinely blank.
        PageTemplate(id="blank", frames=[frame], onPage=lambda c, d: None),
        PageTemplate(id="back", frames=[frame], onPage=_back_cover),
    ])
    doc.multiBuild(story)
    return doc.page


def main() -> int:
    # manual_content does `from build_user_manual import ...` to get the
    # styles and palette. Registering THIS module under that name makes it
    # resolve here, so the content picks up the Letter/grayscale styles
    # instead of the original blue A4 ones - without forking the content
    # module or disturbing the existing colour generator.
    import sys as _sys  # noqa: PLC0415

    _sys.modules["build_user_manual"] = _sys.modules[__name__]
    from manual_content import build_story  # noqa: PLC0415

    story = build_story()

    # Back cover. Mirrors the front so the printed manual is bookended, and
    # keeps the page count even, so printing two pages to a sheet produces
    # whole sheets with no half-empty last one.
    #
    # Every line here is already established elsewhere in the project - the
    # product name and version from the application, the institution from the
    # manuscript, and the authorisation statement verbatim from the front
    # cover. Nothing is introduced that is not already documented.
    story.append(NextPageTemplate("back"))
    story.append(PageBreak())
    story.append(Spacer(1, 42 * mm))
    story.append(Paragraph("AETHRA-SEC", S["coverTitle"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("Security Operations Console", S["coverSub"]))
    story.append(Spacer(1, 9 * mm))
    story.append(Paragraph(f"Version {APP_VERSION}", S["coverSub"]))
    story.append(Spacer(1, 16 * mm))
    story.append(Paragraph(
        "Isabela State University – Echague", S["coverName"]))
    story.append(Spacer(1, 1 * mm))
    story.append(Paragraph("CCSICT", S["coverSub"]))
    story.append(Spacer(1, 22 * mm))
    story.append(callout(
        "Important",
        "AETHRA-SEC must only be operated against networks, hosts and "
        "interfaces you are explicitly authorised to monitor or assess. It "
        "performs no exploitation, no credential attacks and no automated "
        "mitigation. All mitigation output is advisory and requires a human "
        "decision.",
    ))

    pages = build_document(story)
    size = OUT.stat().st_size / 1048576
    print(f"  wrote {OUT}")
    print(f"  {pages} pages, {size:.2f} MB, {_counter['section']} sections, "
          f"{_counter['figure']} figures")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))
    raise SystemExit(main())
