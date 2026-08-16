"""Lightweight OS fingerprinting from SYN-ACK replies (TTL + TCP window).

Heuristic, nmap-style: the observed IP TTL of the reply is mapped to a likely
initial TTL bucket (64 / 128 / 255, since the observed value is decremented by
each hop), then combined with the TCP window size to guess the operating
system family. Far less accurate than nmap -O, but free - the data is already
in the SYN-ACK that a SYN scan receives.
"""

from __future__ import annotations

from typing import Optional, Tuple

# (initial TTL bucket, TCP window size) -> guess, most specific first.
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

# Fallback guesses keyed by initial TTL bucket when no window match is found.
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


def guess_os(
    observed_ttl: Optional[int], window: Optional[int]
) -> Optional[str]:
    """Guess the OS family from a SYN-ACK's TTL and window size.

    Returns None when there is not enough signal (missing/invalid TTL, or a
    zero window). Otherwise returns a specific signature match or a TTL-only
    family fallback.
    """
    if observed_ttl is None or window is None or window <= 0:
        return None
    initial = _initial_ttl(observed_ttl)
    if initial is None:
        return None
    for ttl_bucket, win, name in SYN_ACK_SIGNATURES:
        if ttl_bucket == initial and win == window:
            return name
    return TTL_ONLY.get(initial)
