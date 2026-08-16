from __future__ import annotations

import csv
import io
from collections.abc import Sequence

TABLE = "table"
CSV = "csv"
MARKDOWN = "markdown"
JSON = "json"

# `json` is handled by callers, which have the structured objects and can emit
# richer nesting than a row of strings. The three here are all flat by nature.
ROW_FORMATS = (TABLE, CSV, MARKDOWN)
FORMATS = (TABLE, CSV, MARKDOWN, JSON)


def _table(cols: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [
        max(len(c), max((len(r[i]) for r in rows), default=0))
        for i, c in enumerate(cols)
    ]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    return "\n".join([fmt.format(*cols)] + [fmt.format(*r) for r in rows])


def _csv(cols: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    # QUOTE_MINIMAL with the default dialect, so a city called "Washington,
    # D.C." survives the round trip instead of becoming two columns.
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(cols)
    writer.writerows(rows)
    return buf.getvalue().rstrip("\n")


def _markdown(cols: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    def cell(value: str) -> str:
        # An unescaped pipe silently ends the cell and shifts every column
        # after it, which corrupts the table rather than merely uglifying it.
        return str(value).replace("|", "\\|")

    out = [
        "| " + " | ".join(cell(c) for c in cols) + " |",
        "|" + "|".join("---" for _ in cols) + "|",
    ]
    out.extend("| " + " | ".join(cell(v) for v in r) + " |" for r in rows)
    return "\n".join(out)


def render(cols: Sequence[str], rows: Sequence[Sequence[str]], fmt: str) -> str:
    """Render flat rows as an aligned table, CSV, or a Markdown table.

    One renderer rather than three call sites formatting by hand, so a column
    added to a report appears in every format instead of only the one the
    author happened to be looking at.
    """
    if fmt == CSV:
        return _csv(cols, rows)
    if fmt == MARKDOWN:
        return _markdown(cols, rows)
    return _table(cols, rows)
