"""Lightweight OS fingerprinting from SYN-ACK replies.

Three-tier heuristic, nmap-style. The observed IP TTL is mapped to a likely
initial TTL bucket (64 / 128 / 255, since the observed value is decremented by
each hop), then matched against:

  Tier 1 - full signature: TTL bucket + window + TCP options (MSS, WScale,
           SACK-permitted, timestamps). This disambiguates hosts that share a
           TTL/window, e.g. macOS (wscale 3) vs Linux (wscale 7).
  Tier 2 - window signature: TTL bucket + window size.
  Tier 3 - TTL-only family fallback.

Far less accurate than nmap -O, but free - the data is already in the SYN-ACK
that a SYN scan receives.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

# Tier 1: (ttl bucket, window, mss, wscale, sack-permitted, timestamps) -> guess.
SYN_ACK_OPT_SIGNATURES: Tuple[Tuple[int, int, int, int, bool, bool, str], ...] = (
    # Windows
    (128, 64240, 1460, 8, True, True, "Windows 10/11"),
    (128, 64240, 1350, 8, True, True, "Windows 10/11 (low MTU)"),
    (128, 8192, 1460, 8, True, True, "Windows 7/8"),
    (128, 16384, 1460, 8, True, True, "Windows 8/10"),
    (128, 65535, 1460, 0, True, False, "Windows XP/Server 2003"),
    # Linux
    (64, 64240, 1460, 7, True, True, "Linux (modern)"),
    (64, 29200, 1460, 7, True, True, "Linux (modern)"),
    (64, 28960, 1460, 7, True, True, "Linux (modern)"),
    (64, 65535, 1460, 7, True, True, "Linux (modern)"),
    (64, 5840, 1460, 4, True, True, "Linux (Android / older kernel)"),
    (64, 5840, 1460, 2, True, True, "Linux (older kernel)"),
    # macOS (same TTL/window as Linux; wscale 3 is the tell)
    (64, 65535, 1460, 3, True, True, "macOS"),
    # Network gear (no window scaling)
    (255, 4128, 1460, 0, False, False, "Cisco IOS (router/switch)"),
    (255, 8760, 1460, 0, True, False, "Cisco IOS (router/switch)"),
)

# Tier 2: (ttl bucket, TCP window size) -> guess, most specific first.
SYN_ACK_SIGNATURES: Tuple[Tuple[int, int, str], ...] = (
    # Network devices / Unix servers (TTL 255)
    (255, 8760, "Cisco IOS (router/switch)"),
    (255, 4128, "Cisco IOS (router/switch)"),
    (255, 16384, "Cisco IOS (network device)"),
    (255, 29200, "Solaris"),
    (255, 65535, "Solaris / SunOS"),
    # Windows (TTL 128)
    (128, 64240, "Windows 10/11"),
    (128, 8192, "Windows 7/8"),
    (128, 16384, "Windows 8/10"),
    (128, 65535, "Windows XP/Server 2003"),
    # Unix-like (TTL 64)
    (64, 5720, "macOS"),
    (64, 65535, "Linux / macOS"),
    (64, 5840, "Linux (Android / older kernel)"),
    (64, 29200, "Linux 2.4/2.6"),
    (64, 64240, "Linux (recent)"),
    (64, 32768, "Linux (embedded)"),
)

# Tier 3: fallback guesses keyed by initial TTL bucket.
TTL_ONLY: dict = {
    64: "Unix-like (TTL 64)",
    128: "Windows-like (TTL 128)",
    255: "Network device (TTL 255)",
}


def _initial_ttl(observed: int) -> Optional[int]:
    """Bucket an observed TTL to its most likely initial value (1-2 hops)."""
    if observed <= 0:
        return None
    if observed <= 64:
        return 64
    if observed <= 128:
        return 128
    return 255


def parse_tcp_options(
    options: List[Tuple[object, object]],
) -> Tuple[Optional[int], Optional[int], bool, bool]:
    """Extract (mss, wscale, sack-permitted, timestamps) from scapy TCP options.

    Scapy parses TCP options into (kind, value) pairs with string kinds such
    as "MSS", "WScale", "SAckOK", and "Timestamp". Missing optional fields
    come back as None/False.
    """
    mss: Optional[int] = None
    wscale: Optional[int] = None
    sack = False
    timestamps = False
    for kind, value in options or ():
        if kind == "MSS":
            mss = int(value)
        elif kind == "WScale":
            wscale = int(value)
        elif kind == "SAckOK":
            sack = True
        elif kind == "Timestamp":
            timestamps = True
    return mss, wscale, sack, timestamps


def guess_os(
    observed_ttl: Optional[int],
    window: Optional[int],
    mss: Optional[int] = None,
    wscale: Optional[int] = None,
    sack: Optional[bool] = None,
    timestamps: Optional[bool] = None,
) -> Optional[str]:
    """Guess the OS family from a SYN-ACK's TTL, window, and TCP options.

    Uses the most specific signature tier that matches. Returns None when
    there is not enough signal (missing/invalid TTL, or a zero window).
    """
    if observed_ttl is None or window is None or window <= 0:
        return None
    initial = _initial_ttl(observed_ttl)
    if initial is None:
        return None

    # Tier 1: full option signature (only when MSS is present - virtually all
    # SYN-ACKs carry it). A missing WScale option means no window scaling (0).
    if mss is not None:
        wscale_n = wscale if wscale is not None else 0
        sig = (initial, window, mss, wscale_n, bool(sack), bool(timestamps))
        for ttl_bucket, win, m, ws, sk, tm, name in SYN_ACK_OPT_SIGNATURES:
            if (ttl_bucket, win, m, ws, sk, tm) == sig:
                return name

    # Tier 2: window match.
    for ttl_bucket, win, name in SYN_ACK_SIGNATURES:
        if ttl_bucket == initial and win == window:
            return name

    # Tier 3: TTL family fallback.
    return TTL_ONLY.get(initial)
