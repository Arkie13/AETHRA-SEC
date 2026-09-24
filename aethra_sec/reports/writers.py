"""Report writers: CSV, Excel and PDF (§50).

Each writer renders a :class:`ReportDocument` built from real records. When a
section has no rows it writes "No records available" rather than leaving a
blank table that could be mistaken for a rendering failure.

Excel and PDF need optional libraries. If one is missing the writer raises a
:class:`ReportError` that names the package to install - it never silently
falls back to a different format.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Sequence

from aethra_sec.core.errors import ReportError
from aethra_sec.reports.builder import NO_RECORDS_TEXT, ReportDocument
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("reports.writers")


#: Characters that make a spreadsheet treat a cell as a formula rather than as
#: text. Tab and carriage return are included because Excel strips leading
#: whitespace before deciding, so " =cmd|..." is a formula too.
_FORMULA_LEAD = ("=", "+", "-", "@", chr(9), chr(13))


def _is_number(text: str) -> bool:
    """True when the text is an ordinary number, including a negative one."""
    try:
        float(text.replace(",", ""))
    except ValueError:
        return False
    return True


def _stringify(value: Any) -> str:
    """Render a cell value as text that a spreadsheet will not execute.

    Every string in a report can come from an attacker. A hostname is whatever
    a device announces over DHCP, mDNS or NetBIOS; a Snort alert message, an
    incident title and a service banner are all equally external. Excel,
    LibreOffice and Google Sheets treat a cell beginning ``=``, ``+``, ``-`` or
    ``@`` as a formula, so a device named ``=cmd|'/c calc'!A1`` runs a command
    on the analyst's workstation the moment they open the export.

    Prefixing with an apostrophe is the standard neutralisation: the cell reads
    as the original text and is never evaluated. Plain numbers are left alone,
    so a negative figure stays a figure.
    """
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in _FORMULA_LEAD and not _is_number(text):
        return "'" + text
    return text


def write_csv(document: ReportDocument, path: Path) -> Path:
    """Write a report as CSV.

    Sections are written sequentially with a header row each, which keeps a
    multi-section report readable in a single file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(["AETHRA-SEC report"])
            for label, value in document.metadata_rows():
                writer.writerow([label, _stringify(value)])
            writer.writerow([])

            if document.highlights:
                writer.writerow(["Summary"])
                for label, value in document.highlights:
                    writer.writerow([label, _stringify(value)])
                writer.writerow([])

            for section in document.sections:
                writer.writerow([_stringify(section.title)])
                writer.writerow([_stringify(c) for c in section.columns])
                if section.has_rows:
                    for row in section.rows:
                        writer.writerow([_stringify(cell) for cell in row])
                else:
                    writer.writerow([NO_RECORDS_TEXT])
                if section.note:
                    writer.writerow(["Note", _stringify(section.note)])
                writer.writerow([])

            if document.observations:
                writer.writerow(["Observations"])
                for note in document.observations:
                    writer.writerow([_stringify(note)])
                writer.writerow([])
            writer.writerow(["Conclusion", _stringify(document.conclusion)])
    except OSError as exc:
        raise ReportError(
            f"Could not write {path}: {exc}",
            user_message=f"The CSV report could not be written: {exc}",
        ) from exc
    LOGGER.info("CSV report written to %s", path)
    return path


def write_rows_csv(
    columns: Sequence[str], rows: Sequence[Sequence[Any]], path: Path
) -> Path:
    """Write an arbitrary record set as CSV (used by the Export buttons).

    Raises:
        ReportError: when the file cannot be written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow([_stringify(c) for c in columns])
            if rows:
                for row in rows:
                    writer.writerow([_stringify(cell) for cell in row])
            else:
                writer.writerow(["No records available for export."])
    except OSError as exc:
        raise ReportError(
            f"Could not write {path}: {exc}",
            user_message=f"The export could not be written: {exc}",
        ) from exc
    return path


def write_excel(document: ReportDocument, path: Path) -> Path:
    """Write a report as an Excel workbook, one sheet per section.

    Raises:
        ReportError: when openpyxl is unavailable or writing fails.
    """
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError as exc:
        raise ReportError(
            f"openpyxl is not installed: {exc}",
            user_message=(
                "Excel export needs the 'openpyxl' package. Install it with: "
                "pip install openpyxl"
            ),
        ) from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    workbook = Workbook()
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="1F3A5F")
    title_font = Font(bold=True, size=12)

    overview = workbook.active
    overview.title = "Overview"
    overview.append(["AETHRA-SEC report"])
    overview["A1"].font = title_font
    for label, value in document.metadata_rows():
        overview.append([label, _stringify(value)])
    overview.append([])
    if document.highlights:
        overview.append(["Summary"])
        overview.cell(row=overview.max_row, column=1).font = title_font
        for label, value in document.highlights:
            overview.append([label, _stringify(value)])
    overview.append([])
    if document.observations:
        overview.append(["Observations"])
        overview.cell(row=overview.max_row, column=1).font = title_font
        for note in document.observations:
            overview.append([note])
    overview.append([])
    overview.append(["Conclusion", document.conclusion])
    overview.column_dimensions["A"].width = 28
    overview.column_dimensions["B"].width = 110
    for row in overview.iter_rows(min_col=2, max_col=2):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")

    used_titles: set[str] = {"Overview"}
    for section in document.sections:
        title = _sheet_title(section.title, used_titles)
        used_titles.add(title)
        sheet = workbook.create_sheet(title)
        sheet.append(list(section.columns))
        for index, _ in enumerate(section.columns, start=1):
            cell = sheet.cell(row=1, column=index)
            cell.font = header_font
            cell.fill = header_fill
        if section.has_rows:
            for row in section.rows:
                sheet.append([_stringify(cell) for cell in row])
        else:
            sheet.append([NO_RECORDS_TEXT])
        if section.note:
            sheet.append([])
            sheet.append(["Note", section.note])
        sheet.freeze_panes = "A2"
        for index, column in enumerate(section.columns, start=1):
            width = max(
                len(str(column)) + 2,
                *(
                    min(60, len(_stringify(row[index - 1])) + 2)
                    for row in section.rows[:200]
                    if len(row) >= index
                ),
                12,
            )
            sheet.column_dimensions[get_column_letter(index)].width = min(60, width)

    try:
        workbook.save(path)
    except OSError as exc:
        raise ReportError(
            f"Could not write {path}: {exc}",
            user_message=f"The Excel report could not be written: {exc}",
        ) from exc
    LOGGER.info("Excel report written to %s", path)
    return path


def _sheet_title(title: str, used: set[str]) -> str:
    """Produce a unique, Excel-legal worksheet name."""
    cleaned = "".join(c for c in title if c not in "[]:*?/\\")[:28] or "Section"
    candidate = cleaned
    counter = 2
    while candidate in used:
        candidate = f"{cleaned[:26]}_{counter}"
        counter += 1
    return candidate


def write_pdf(document: ReportDocument, path: Path) -> Path:
    """Write a report as PDF.

    Raises:
        ReportError: when reportlab is unavailable or writing fails.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise ReportError(
            f"reportlab is not installed: {exc}",
            user_message=(
                "PDF export needs the 'reportlab' package. Install it with: "
                "pip install reportlab"
            ),
        ) from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "AethraTitle", parent=styles["Title"], fontSize=18, spaceAfter=6,
        textColor=colors.HexColor("#0F2740"),
    )
    subtitle_style = ParagraphStyle(
        "AethraSubtitle", parent=styles["Normal"], fontSize=9,
        textColor=colors.HexColor("#4A5A6A"), spaceAfter=10,
    )
    heading_style = ParagraphStyle(
        "AethraHeading", parent=styles["Heading2"], fontSize=12,
        textColor=colors.HexColor("#1F3A5F"), spaceBefore=10, spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "AethraBody", parent=styles["BodyText"], fontSize=8.5, leading=11,
        alignment=TA_LEFT,
    )
    cell_style = ParagraphStyle(
        "AethraCell", parent=styles["BodyText"], fontSize=7, leading=8.5,
    )
    note_style = ParagraphStyle(
        "AethraNote", parent=body_style, fontSize=7.5,
        textColor=colors.HexColor("#4A5A6A"), leftIndent=4,
    )

    story: list[Any] = [
        Paragraph(document.title, title_style),
        Paragraph(
            "AETHRA-SEC - unified assessment, monitoring and detection console",
            subtitle_style,
        ),
    ]

    metadata_rows = [
        [Paragraph(f"<b>{label}</b>", cell_style), Paragraph(_stringify(value), cell_style)]
        for label, value in document.metadata_rows()
    ]
    metadata_table = Table(metadata_rows, colWidths=[35 * mm, 220 * mm])
    metadata_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#DDE3EA")),
            ]
        )
    )
    story.extend([metadata_table, Spacer(1, 6)])

    if document.highlights:
        story.append(Paragraph("Summary", heading_style))
        highlight_rows = [
            [Paragraph(f"<b>{label}</b>", cell_style), Paragraph(_stringify(value), cell_style)]
            for label, value in document.highlights
        ]
        highlight_table = Table(highlight_rows, colWidths=[70 * mm, 60 * mm])
        highlight_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F7FA")),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D4E0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#DDE3EA")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.extend([highlight_table, Spacer(1, 8)])

    for section in document.sections:
        story.append(Paragraph(section.title, heading_style))
        if section.summary:
            story.append(Paragraph(section.summary, body_style))
        if section.has_rows:
            header = [Paragraph(f"<b>{column}</b>", cell_style) for column in section.columns]
            body = [
                [Paragraph(_stringify(cell)[:400], cell_style) for cell in row]
                for row in section.rows[:400]
            ]
            table = Table([header, *body], repeatRows=1)
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C9D4E0")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                         [colors.white, colors.HexColor("#F7F9FB")]),
                        ("TOPPADDING", (0, 0), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ]
                )
            )
            story.append(table)
            if section.row_count > 400:
                story.append(
                    Paragraph(
                        f"Showing the first 400 of {section.row_count:,} records. "
                        "Export to CSV or Excel for the complete set.",
                        note_style,
                    )
                )
        else:
            story.append(Paragraph(NO_RECORDS_TEXT, body_style))
        if section.note:
            story.append(Paragraph(f"<i>{section.note}</i>", note_style))
        story.append(Spacer(1, 8))

    if document.observations:
        story.append(Paragraph("Observations", heading_style))
        for note in document.observations:
            story.append(Paragraph(f"&bull; {note}", body_style))
        story.append(Spacer(1, 6))

    story.append(Paragraph("Conclusion", heading_style))
    story.append(Paragraph(document.conclusion, body_style))

    def _footer(canvas: Any, doc: Any) -> None:
        """Draw the page footer with page number and generation stamp."""
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#6B7A8A"))
        canvas.drawString(
            15 * mm, 10 * mm,
            f"AETHRA-SEC - generated by {document.generated_by or 'unknown'}",
        )
        canvas.drawRightString(
            doc.pagesize[0] - 15 * mm, 10 * mm, f"Page {canvas.getPageNumber()}"
        )
        canvas.restoreState()

    try:
        template = SimpleDocTemplate(
            str(path),
            pagesize=landscape(A4),
            leftMargin=15 * mm, rightMargin=15 * mm,
            topMargin=13 * mm, bottomMargin=15 * mm,
            title=document.title,
            author="AETHRA-SEC",
        )
        template.build(story, onFirstPage=_footer, onLaterPages=_footer)
    except Exception as exc:  # noqa: BLE001 - reportlab raises assorted types
        raise ReportError(
            f"Could not write {path}: {exc}",
            user_message=f"The PDF report could not be written: {exc}",
        ) from exc
    LOGGER.info("PDF report written to %s", path)
    return path
