#!/usr/bin/env python
"""Legacy entry point for NetScanner.

Keeps the v1 workflow working: `python netscanner.py -t 192.168.1.0/24`.
The real implementation lives in the `netscanner` package under src/.
"""

import os
import sys

if __name__ == "__main__":
    # When run as a script, make the package importable from src/ and delegate.
    # (When this file is merely imported, e.g. from the repo root, it stays
    # inert so it never shadows the real package.)
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

    from netscanner.cli import main  # noqa: E402

    sys.exit(main())
