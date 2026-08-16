import json

import pytest

from netscanner import cli
from netscanner.scanner import ScanError

FAKE_HOSTS = [
    {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff", "vendor": None, "hostname": None}
]

FAKE_PORTS = [
    {"ip": "192.168.1.10", "port": 80, "service": "http", "state": "open"}
]


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "netscanner" in capsys.readouterr().out


def test_arp_flow_table(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: FAKE_HOSTS)
    code = cli.main(["-t", "192.168.1.0/24", "-m", "arp"])
    assert code == 0
    out = capsys.readouterr().out
    assert "192.168.1.10" in out
    assert "aa:bb:cc:dd:ee:ff" in out


def test_no_banner_flag(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: FAKE_HOSTS)
    code = cli.main(["-t", "192.168.1.10", "--no-banner"])
    assert code == 0
    assert "Version" not in capsys.readouterr().out


def test_json_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: FAKE_HOSTS)
    code = cli.main(["-t", "192.168.1.10", "-m", "ping", "-f", "json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out) == FAKE_HOSTS


def test_csv_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: FAKE_HOSTS)
    code = cli.main(["-t", "192.168.1.10", "-f", "csv"])
    assert code == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("IP Address,MAC Address")


def test_jsonl_output_from_host_discovery(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: FAKE_HOSTS)
    code = cli.main(["-t", "192.168.1.10", "-f", "jsonl"])
    assert code == 0
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0]) == FAKE_HOSTS[0]


def test_jsonl_port_scan_streams_to_stdout(monkeypatch, capsys):
    monkeypatch.setattr(cli, "port_scan", lambda *a, **k: iter(FAKE_PORTS))
    code = cli.main(["-t", "192.168.1.10", "-m", "tcp", "-p", "80", "-f", "jsonl"])
    assert code == 0
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.strip()]
    assert json.loads(lines[0]) == FAKE_PORTS[0]


def test_jsonl_port_scan_streams_to_file(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "port_scan", lambda *a, **k: iter(FAKE_PORTS))
    out_file = tmp_path / "scan.jsonl"
    code = cli.main(
        ["-t", "192.168.1.10", "-m", "tcp", "-p", "80", "-f", "jsonl", "-o", str(out_file)]
    )
    assert code == 0
    parsed = [json.loads(line) for line in out_file.read_text().splitlines() if line.strip()]
    assert parsed == FAKE_PORTS
    assert "scan.jsonl" in capsys.readouterr().out


def test_jsonl_empty_port_scan_prints_message_to_stderr(monkeypatch, capsys):
    monkeypatch.setattr(cli, "port_scan", lambda *a, **k: iter([]))
    code = cli.main(["-t", "192.168.1.10", "-m", "tcp", "-p", "80", "-f", "jsonl"])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.out == ""  # stdout stays pure JSONL
    assert "No open ports found" in captured.err


def test_port_scan_flow(monkeypatch, capsys):
    monkeypatch.setattr(cli, "port_scan", lambda *a, **k: FAKE_PORTS)
    code = cli.main(["-t", "192.168.1.10", "-m", "tcp", "-p", "80"])
    assert code == 0
    out = capsys.readouterr().out
    assert "80" in out
    assert "http" in out


def test_ports_flag_implies_port_scan(monkeypatch, capsys):
    monkeypatch.setattr(cli, "port_scan", lambda *a, **k: FAKE_PORTS)
    code = cli.main(["-t", "192.168.1.10", "-p", "80,443"])
    assert code == 0
    assert "http" in capsys.readouterr().out


def test_udp_scan_flow(monkeypatch, capsys):
    fake = [
        {"ip": "192.168.1.10", "port": 53, "service": "domain", "state": "open|filtered"}
    ]
    monkeypatch.setattr(cli, "udp_scan", lambda *a, **k: fake)
    code = cli.main(["-t", "192.168.1.10", "-m", "udp", "-p", "53,161"])
    assert code == 0
    out = capsys.readouterr().out
    assert "53" in out
    assert "open|filtered" in out


def test_syn_scan_flow(monkeypatch, capsys):
    monkeypatch.setattr(cli, "syn_scan", lambda *a, **k: FAKE_PORTS)
    code = cli.main(["-t", "192.168.1.10", "-m", "syn", "-p", "80"])
    assert code == 0
    out = capsys.readouterr().out
    assert "http" in out


def test_syn_jsonl_stream(monkeypatch, capsys):
    monkeypatch.setattr(cli, "syn_scan", lambda *a, **k: iter(FAKE_PORTS))
    code = cli.main(["-t", "192.168.1.10", "-m", "syn", "-p", "80", "-f", "jsonl"])
    assert code == 0
    out = capsys.readouterr().out
    assert json.loads(out.splitlines()[0]) == FAKE_PORTS[0]


def test_no_os_flag_passed_to_syn_scan(monkeypatch):
    captured = {}

    def fake_syn_scan(*a, **k):
        captured["fingerprint"] = k.get("fingerprint")
        return []

    monkeypatch.setattr(cli, "syn_scan", fake_syn_scan)
    code = cli.main(["-t", "192.168.1.10", "-m", "syn", "-p", "80", "--no-os"])
    assert code == 0
    assert captured["fingerprint"] is False

    code = cli.main(["-t", "192.168.1.10", "-m", "syn", "-p", "80"])
    assert code == 0
    assert captured["fingerprint"] is True


def test_syn_scan_table_includes_os_column(monkeypatch, capsys):
    fake = [
        {
            "ip": "192.168.1.10",
            "port": 80,
            "service": "http",
            "state": "open",
            "os": "Windows 10/11",
            "ttl": 128,
            "window": 64240,
        }
    ]
    monkeypatch.setattr(cli, "syn_scan", lambda *a, **k: fake)
    code = cli.main(["-t", "192.168.1.10", "-m", "syn", "-p", "80"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Windows 10/11" in out
    assert "TTL" in out
    assert "Window" in out


def test_udp_probes_flag_merges_builtin_and_custom(monkeypatch, tmp_path):
    probe_file = tmp_path / "probes.json"
    probe_file.write_text('{"500": "deadbeef"}')
    captured = {}

    def fake_udp_scan(*a, **k):
        captured["probes"] = k.get("probes")
        return []

    monkeypatch.setattr(cli, "udp_scan", fake_udp_scan)
    code = cli.main(["-t", "192.168.1.10", "-m", "udp", "-p", "53,500", "--probes", str(probe_file)])
    assert code == 0
    probes = captured["probes"]
    assert probes[500] == b"\xde\xad\xbe\xef"  # custom override
    assert probes[53] == cli.UDP_PROBES[53]  # built-in still present


def test_udp_no_probes_flag(monkeypatch, capsys):
    captured = {}

    def fake_udp_scan(*a, **k):
        captured["probes"] = k.get("probes")
        return []

    monkeypatch.setattr(cli, "udp_scan", fake_udp_scan)
    code = cli.main(["-t", "192.168.1.10", "-m", "udp", "-p", "53", "--no-probes"])
    assert code == 0
    assert captured["probes"] == {}


def test_udp_no_probes_plus_custom_file(monkeypatch, tmp_path):
    probe_file = tmp_path / "probes.json"
    probe_file.write_text('{"500": "deadbeef"}')
    captured = {}

    def fake_udp_scan(*a, **k):
        captured["probes"] = k.get("probes")
        return []

    monkeypatch.setattr(cli, "udp_scan", fake_udp_scan)
    code = cli.main(
        ["-t", "192.168.1.10", "-m", "udp", "-p", "500", "--no-probes", "--probes", str(probe_file)]
    )
    assert code == 0
    assert captured["probes"] == {500: b"\xde\xad\xbe\xef"}  # built-ins off, custom only


def test_invalid_probe_file_exits_1(tmp_path, capsys):
    probe_file = tmp_path / "probes.json"
    probe_file.write_text("not json")
    code = cli.main(["-t", "192.168.1.10", "-m", "udp", "-p", "53", "--probes", str(probe_file)])
    assert code == 1
    assert "probe" in capsys.readouterr().err.lower()


def test_probes_flag_ignored_for_tcp_scan(monkeypatch, tmp_path, caplog):
    probe_file = tmp_path / "probes.json"
    probe_file.write_text('{"500": "deadbeef"}')
    captured = {}

    def fake_port_scan(*a, **k):
        captured["probes"] = k.get("probes")
        return []

    monkeypatch.setattr(cli, "port_scan", fake_port_scan)
    code = cli.main(["-t", "192.168.1.10", "-m", "tcp", "-p", "80", "--probes", str(probe_file)])
    assert code == 0
    assert captured["probes"] is None  # never passed to tcp
    assert "only affect -m udp" in caplog.text


def test_udp_include_closed_flag_passed(monkeypatch, capsys):
    captured = {}

    def fake_udp_scan(*a, **k):
        captured["include_closed"] = k.get("include_closed")
        return []

    monkeypatch.setattr(cli, "udp_scan", fake_udp_scan)
    code = cli.main(["-t", "192.168.1.10", "-m", "udp", "--include-closed"])
    assert code == 0
    assert captured["include_closed"] is True


def test_invalid_target_exits_1(capsys):
    code = cli.main(["-t", "banana"])
    assert code == 1
    assert "ERROR" in capsys.readouterr().err


def test_invalid_ports_exits_1(capsys):
    code = cli.main(["-t", "192.168.1.1", "-m", "tcp", "-p", "abc"])
    assert code == 1
    assert "ERROR" in capsys.readouterr().err


def test_scan_error_exits_1(monkeypatch, capsys):
    def boom(*a, **k):
        raise ScanError("no raw sockets available")

    monkeypatch.setattr(cli, "discover_hosts", boom)
    code = cli.main(["-t", "192.168.1.1"])
    assert code == 1
    assert "no raw sockets available" in capsys.readouterr().err


def test_output_file_written(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: FAKE_HOSTS)
    out_file = tmp_path / "scan.json"
    code = cli.main(["-t", "192.168.1.10", "-f", "json", "-o", str(out_file)])
    assert code == 0
    assert json.loads(out_file.read_text()) == FAKE_HOSTS
    assert "scan.json" in capsys.readouterr().out


def test_empty_results_message(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: [])
    code = cli.main(["-t", "192.168.1.0/24", "-m", "arp"])
    assert code == 0
    assert "No devices found" in capsys.readouterr().out


def test_missing_target_arg_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_progress_summary_shown_by_default(monkeypatch, capsys):
    def fake_discover(*a, **k):
        progress = k.get("progress")
        if progress:
            progress(100, 100)
        return []

    monkeypatch.setattr(cli, "discover_hosts", fake_discover)
    code = cli.main(["-t", "192.168.1.0/24"])
    assert code == 0
    assert "completed 100/100" in capsys.readouterr().err


def test_quiet_suppresses_progress(monkeypatch, capsys):
    def fake_discover(*a, **k):
        progress = k.get("progress")
        if progress:
            progress(100, 100)
        return []

    monkeypatch.setattr(cli, "discover_hosts", fake_discover)
    code = cli.main(["-t", "192.168.1.0/24", "-q"])
    assert code == 0
    assert capsys.readouterr().err == ""


def test_quiet_suppresses_warnings(monkeypatch, caplog):
    monkeypatch.setattr(cli, "is_admin", lambda: False)
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: [])
    code = cli.main(["-t", "192.168.1.10", "-m", "arp", "-q"])
    assert code == 0
    assert "administrator/root privileges" not in caplog.text


def test_warning_shown_by_default(monkeypatch, caplog):
    monkeypatch.setattr(cli, "is_admin", lambda: False)
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: [])
    code = cli.main(["-t", "192.168.1.10", "-m", "arp"])
    assert code == 0
    assert "administrator/root privileges" in caplog.text


def test_quiet_and_verbose_mutually_exclusive(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["-t", "192.168.1.10", "-q", "-v"])
    assert exc.value.code == 2
