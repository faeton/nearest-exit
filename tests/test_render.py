import csv
import io

import pytest

from nearest_exit.render import CSV, MARKDOWN, TABLE, render

COLS = ["country", "city", "relays"]


def test_table_aligns_on_the_widest_cell_including_the_header():
    out = render(COLS, [["DE", "Berlin", "11"], ["US", "X", "2"]], TABLE)
    lines = out.splitlines()

    # "country" is wider than any value under it, so the header sets the width.
    offset = len("country") + 2
    assert lines[0][offset:].startswith("city")
    assert lines[1][offset:].startswith("Berlin")
    assert lines[2][offset:].startswith("X")


@pytest.mark.parametrize(
    "value",
    [
        "Washington, D.C.",   # a comma would otherwise become a column break
        'He said "hi"',       # quotes need doubling
        "line\nbreak",        # a newline would otherwise become a row break
    ],
)
def test_csv_survives_a_round_trip(value):
    out = render(COLS, [["US", value, "1"]], CSV)

    parsed = list(csv.reader(io.StringIO(out)))

    assert parsed[0] == COLS
    assert parsed[1] == ["US", value, "1"]


def test_markdown_escapes_pipes_so_columns_do_not_shift():
    """An unescaped pipe ends the cell early and shifts every column after it,
    which corrupts the table rather than merely uglifying it."""
    out = render(COLS, [["US", "a|b", "1"]], MARKDOWN)
    row = out.splitlines()[2]

    assert "a\\|b" in row
    # Two outer pipes plus one separator per column boundary, and no more.
    assert row.count("|") - row.count("\\|") == len(COLS) + 1


def test_markdown_has_a_header_separator():
    out = render(COLS, [["DE", "Berlin", "11"]], MARKDOWN)
    lines = out.splitlines()

    assert lines[1] == "|---|---|---|"
    assert len(lines) == 3


def test_every_format_handles_no_rows():
    for fmt in (TABLE, CSV, MARKDOWN):
        out = render(COLS, [], fmt)
        assert "country" in out
