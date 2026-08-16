import json

from netscanner.output import (
    HOST_COLUMNS,
    PORT_COLUMNS,
    format_csv,
    format_json,
    format_table,
    write_output,
)

HOSTS = [
    {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Test Vendor", "hostname": None},
    {"ip": "192.168.1.2", "mac": None, "vendor": None, "hostname": None},
]


def test_table_contains_headers_and_values():
    text = format_table(HOSTS, HOST_COLUMNS)
    assert "IP Address" in text
    assert "MAC Address" in text
    assert "192.168.1.1" in text
    assert "aa:bb:cc:dd:ee:ff" in text
    assert "Test Vendor" in text


def test_table_empty_only_headers():
    text = format_table([], HOST_COLUMNS)
    assert "IP Address" in text
    assert "192.168.1.1" not in text


def test_json_roundtrip():
    assert json.loads(format_json(HOSTS)) == HOSTS


def test_json_empty_is_array():
    assert json.loads(format_json([])) == []


def test_csv_header_and_rows():
    text = format_csv(HOSTS, HOST_COLUMNS)
    lines = [line for line in text.strip().splitlines() if line]
    assert lines[0].startswith("IP Address,MAC Address,Vendor,Hostname")
    assert "aa:bb:cc:dd:ee:ff" in lines[1]
    assert lines[2].startswith("192.168.1.2,,")


def test_port_columns_csv():
    ports = [{"ip": "10.0.0.1", "port": 80, "service": "http", "state": "open"}]
    text = format_csv(ports, PORT_COLUMNS)
    assert text.splitlines()[0].startswith("IP Address,Port,Service,State")


def test_write_output(tmp_path):
    out = tmp_path / "scan.txt"
    write_output("hello\nworld", str(out))
    assert out.read_text() == "hello\nworld"
