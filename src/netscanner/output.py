"""Output formatting for scan results: aligned table, JSON, and CSV."""

from __future__ import annotations

import csv
import io
import json
from typing import Dict, Iterable, List, Sequence, Tuple

# Column definitions: (result_key, header)
HOST_COLUMNS: List[Tuple[str, str]] = [
    ("ip", "IP Address"),
    ("mac", "MAC Address"),
    ("vendor", "Vendor"),
    ("hostname", "Hostname"),
]

PORT_COLUMNS: List[Tuple[str, str]] = [
    ("ip", "IP Address"),
    ("port", "Port"),
    ("service", "Service"),
    ("state", "State"),
]


def _cell(value) -> str:
    return "" if value is None else str(value)


def format_table(results: Iterable[Dict], columns: Sequence[Tuple[str, str]]) -> str:
    """Render results as a right-aligned, fixed-width table."""
    rows = [[_cell(r.get(key)) for key, _ in columns] for r in results]
    headers = [header for _, header in columns]

    widths = [len(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    lines = ["  ".join(header.ljust(widths[i]) for i, header in enumerate(headers))]
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines)


def format_json(results: Iterable[Dict]) -> str:
    """Render results as pretty-printed JSON."""
    return json.dumps(list(results), indent=2)


def format_csv(results: Iterable[Dict], columns: Sequence[Tuple[str, str]]) -> str:
    """Render results as CSV with a human-readable header row."""
    keys = [key for key, _ in columns]
    headers = [header for _, header in columns]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)
    for result in results:
        writer.writerow([result.get(key) for key in keys])
    return buf.getvalue()


def write_output(text: str, path: str) -> None:
    """Write formatted output to a file (utf-8)."""
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
