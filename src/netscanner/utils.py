"""Shared helpers: logging, privilege checks, hostname resolution, formatting."""

from __future__ import annotations

import logging
import os
import socket
import sys
from typing import Optional

LOG = logging.getLogger("netscanner")

_COLORS = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "reset": "\033[0m",
}


def setup_logging(verbose: bool = False) -> None:
    """Configure the root logger so warnings land on stderr and -v enables debug."""
    level = logging.DEBUG if verbose else logging.INFO
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
