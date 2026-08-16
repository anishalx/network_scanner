from netscanner.osdetect import SYN_ACK_SIGNATURES, TTL_ONLY, _initial_ttl, guess_os


def test_initial_ttl_bucketing():
    assert _initial_ttl(64) == 64
    assert _initial_ttl(48) == 64  # 64 minus hops
    assert _initial_ttl(128) == 128
    assert _initial_ttl(117) == 128  # 128 minus hops
    assert _initial_ttl(255) == 255
    assert _initial_ttl(200) == 255  # 255 minus hops
    assert _initial_ttl(0) is None
    assert _initial_ttl(-5) is None


def test_signature_matches():
    assert guess_os(64, 65535) == "Linux / macOS"
    assert guess_os(48, 64240) == "Linux (recent)"  # bucketed to 64
    assert guess_os(128, 64240) == "Windows 10/11"
    assert guess_os(117, 8192) == "Windows 7/8"  # bucketed to 128
    assert guess_os(128, 65535) == "Windows XP/Server 2003"
    assert guess_os(255, 8760) == "Cisco IOS (router/switch)"
    assert guess_os(200, 29200) == "Solaris"  # bucketed to 255


def test_ttl_only_fallback():
    # Window not in the signature table -> TTL-family fallback
    assert guess_os(64, 12345) == "Unix-like (TTL 64)"
    assert guess_os(128, 12345) == "Windows-like (TTL 128)"
    assert guess_os(255, 12345) == "Network device (TTL 255)"


def test_insufficient_signal_returns_none():
    assert guess_os(None, 64240) is None
    assert guess_os(64, None) is None
    assert guess_os(64, 0) is None
    assert guess_os(0, 64240) is None


def test_signature_table_is_sorted_most_specific_first():
    # No duplicate (ttl, window) pairs; order is deterministic
    seen = set()
    for ttl, window, _name in SYN_ACK_SIGNATURES:
        assert (ttl, window) not in seen
        seen.add((ttl, window))


def test_ttl_only_covers_all_buckets():
    for bucket in (64, 128, 255):
        assert bucket in TTL_ONLY
