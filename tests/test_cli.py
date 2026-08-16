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
