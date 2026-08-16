#!/usr/bin/env python
"""Re-download the IEEE OUI database and refresh the bundled copy.

Usage:
    python tools/update_oui_db.py

Downloads the official IEEE MA-L CSV and writes a gzip-compressed copy to
src/netscanner/data/oui.csv.gz. Run this occasionally to pick up new
vendor assignments.
"""

from __future__ import annotations

import gzip
import os
import shutil
import sys
import tempfile
import urllib.request

URL = "https://standards-oui.ieee.org/oui/oui.csv"
DEST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src",
    "netscanner",
    "data",
    "oui.csv.gz",
)


def main() -> int:
    tmp_csv = os.path.join(tempfile.gettempdir(), "netscanner_oui_download.csv")
    try:
        print(f"Downloading {URL} ...")
        # A descriptive User-Agent is required; the IEEE server rejects the
        # default Python-urllib agent (HTTP 418).
        request = urllib.request.Request(
            URL,
            headers={"User-Agent": "netscanner-oui-updater/2.0 (https://github.com/anishalx/netscanner)"},
        )
        with urllib.request.urlopen(request, timeout=120) as response, open(tmp_csv, "wb") as out:
            shutil.copyfileobj(response, out)
        size = os.path.getsize(tmp_csv)
        print(f"Downloaded {size:,} bytes; compressing ...")
        with open(tmp_csv, "rb") as f_in, gzip.open(DEST, "wb", compresslevel=9) as f_out:
            shutil.copyfileobj(f_in, f_out)
        print(f"Wrote {DEST} ({os.path.getsize(DEST):,} bytes)")
        return 0
    finally:
        if os.path.exists(tmp_csv):
            os.remove(tmp_csv)


if __name__ == "__main__":
    sys.exit(main())
