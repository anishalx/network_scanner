import sys

from netscanner.utils import ProgressReporter, normalize_mac, resolve_hostname


# --- normalize_mac ---


def test_normalize_mac_separators():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_invalid_passthrough():
    assert normalize_mac("garbage") == "garbage"
    assert normalize_mac("") == ""


# --- resolve_hostname ---


def test_resolve_hostname_loopback_is_none():
    assert resolve_hostname("127.0.0.1") is None
    assert resolve_hostname("0.0.0.0") is None


def test_resolve_hostname_unresolvable_returns_none():
    # 192.0.2.0/24 is TEST-NET-1, never assigned, so no PTR record
    assert resolve_hostname("192.0.2.1", timeout=0.1) is None


# --- ProgressReporter ---


def test_progress_reporter_small_scan_silent(capsys):
    reporter = ProgressReporter("Scan")
    reporter.callback(1, 10)
    reporter.callback(10, 10)
    assert capsys.readouterr().err == ""


def test_progress_reporter_disabled_is_silent(capsys):
    reporter = ProgressReporter("Scan", enabled=False)
    reporter.callback(50, 100)
    reporter.callback(100, 100)
    assert capsys.readouterr().err == ""


def test_progress_reporter_large_scan_summary_on_stderr(capsys):
    reporter = ProgressReporter("Scan")
    reporter.callback(50, 100)
    reporter.callback(100, 100)
    err = capsys.readouterr().err
    assert "completed 100/100" in err


def test_progress_reporter_tty_redraws(monkeypatch):
    writes = []

    class FakeStderr:
        isatty = lambda self: True

        def write(self, text):
            writes.append(text)

        def flush(self):
            pass

    monkeypatch.setattr(sys, "stderr", FakeStderr())
    reporter = ProgressReporter("Scan")
    reporter.callback(50, 100)
    assert any(w.startswith("\rScan: 50/100") for w in writes)
    reporter.callback(100, 100)
    assert any("completed 100/100" in w for w in writes)


def test_progress_reporter_finish_once(capsys):
    reporter = ProgressReporter("Scan")
    reporter.callback(100, 100)
    reporter.callback(100, 100)  # second finish must be a no-op
    assert capsys.readouterr().err.count("completed 100/100") == 1
