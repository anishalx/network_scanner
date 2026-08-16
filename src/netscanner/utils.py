"""Shared helpers: logging, privilege checks, hostname resolution, formatting."""

from __future__ import annotations

import logging
import os
import socket
import sys
import time
from typing import Optional

LOG = logging.getLogger("netscanner")

_COLORS = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "reset": "\033[0m",
}


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure the netscanner logger: -v enables debug, -q silences warnings."""
    if quiet:
        level = logging.CRITICAL
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    LOG.setLevel(level)


def colorize(text: str, name: str) -> str:
    """Wrap text in an ANSI color, unless output is not a TTY or NO_COLOR is set."""
    code = _COLORS.get(name)
    if not code:
        return text
    if os.environ.get("NO_COLOR"):
        return text
    try:
        if not sys.stdout.isatty():
            return text
    except (AttributeError, ValueError):
        return text
    return f"{code}{text}{_COLORS['reset']}"


def is_admin() -> bool:
    """Return True if the process runs with administrator/root privileges."""
    try:
        if os.name == "nt":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except (AttributeError, OSError, ImportError):
        return False


def resolve_hostname(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Best-effort reverse-DNS lookup with a short socket timeout.

    Never raises; returns None when the lookup fails or times out.
    """
    if not ip or ip.startswith(("127.", "0.")):
        return None
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name or None
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (socket.error, OSError, UnicodeError):
        return None


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lowercase colon-separated form (aa:bb:cc:dd:ee:ff)."""
    if not mac:
        return ""
    cleaned = "".join(ch for ch in mac.strip() if ch.isalnum())
    if len(cleaned) != 12:
        return mac.strip()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).lower()


def _stderr_is_tty() -> bool:
    try:
        return sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


class ProgressReporter:
    """Single-line scan progress indicator written to stderr.

    On a TTY it redraws in place (rate-limited); otherwise it stays quiet
    during the scan. Either way, scans with at least MIN_ITEMS items finish
    with a one-line summary, so long scans give feedback even when piped.
    Writing to stderr keeps stdout clean for table/json/jsonl data.
    """

    MIN_ITEMS = 50
    _DRAW_INTERVAL = 0.1

    def __init__(self, label: str = "Scan", enabled: bool = True):
        self.label = label
        self._enabled = enabled
        self._tty = _stderr_is_tty()
        self._start = time.monotonic()
        self._last_draw = 0.0
        self._finished = False

    @property
    def callback(self):
        """A (done, total) callback suitable for the scan functions."""
        return self._update

    def _update(self, done: int, total: int) -> None:
        if not self._enabled:
            return
        if total < self.MIN_ITEMS:
            return  # too small to bother reporting
        if done >= total:
            self._finish(total)
            return
        now = time.monotonic()
        if self._tty and now - self._last_draw >= self._DRAW_INTERVAL:
            self._last_draw = now
            pct = done / total * 100 if total else 100.0
            print(
                f"\r{self.label}: {done}/{total} ({pct:3.0f}%) [{now - self._start:5.1f}s]",
                end="",
                file=sys.stderr,
                flush=True,
            )

    def _finish(self, total: int) -> None:
        if self._finished:
            return
        self._finished = True
        if self._tty:
            print("\r" + " " * 79 + "\r", end="", file=sys.stderr, flush=True)
        print(
            f"{self.label}: completed {total}/{total} in {time.monotonic() - self._start:.1f}s",
            file=sys.stderr,
        )
