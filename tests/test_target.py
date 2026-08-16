import socket

import pytest

from netscanner.target import TargetError, parse_ports, parse_targets


def test_single_ip():
    assert [str(a) for a in parse_targets(["192.168.1.1"])] == ["192.168.1.1"]


def test_cidr():
    hosts = parse_targets(["192.168.1.0/24"])
    assert len(hosts) == 254
    assert str(hosts[0]) == "192.168.1.1"
    assert str(hosts[-1]) == "192.168.1.254"


def test_cidr_31_and_32():
    assert len(parse_targets(["192.168.1.0/31"])) == 2
    assert [str(a) for a in parse_targets(["192.168.1.7/32"])] == ["192.168.1.7"]


def test_full_range():
    hosts = parse_targets(["192.168.1.1-192.168.1.5"])
    assert [str(a) for a in hosts] == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.4",
        "192.168.1.5",
    ]


def test_partial_range():
    hosts = parse_targets(["192.168.1.1-5"])
    assert len(hosts) == 5
    assert str(hosts[0]) == "192.168.1.1"
    assert str(hosts[-1]) == "192.168.1.5"


def test_reversed_range_rejected():
    with pytest.raises(TargetError):
        parse_targets(["192.168.1.5-192.168.1.1"])


def test_invalid_ip_rejected():
    with pytest.raises(TargetError):
        parse_targets(["999.999.999.999"])


def test_invalid_string_rejected():
    with pytest.raises(TargetError):
        parse_targets(["not-an-ip"])


def test_comma_separated_and_dedupe():
    hosts = parse_targets(["192.168.1.1,192.168.1.1,192.168.1.2"])
    assert [str(a) for a in hosts] == ["192.168.1.1", "192.168.1.2"]


def test_hostname_resolution(monkeypatch):
    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        assert host == "router.local"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert [str(a) for a in parse_targets(["router.local"])] == ["192.168.1.1"]


def test_unresolvable_hostname(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(TargetError):
        parse_targets(["does-not-exist.invalid"])


def test_host_limit_enforced():
    with pytest.raises(TargetError):
        parse_targets(["0.0.0.0/1"])


def test_ports_single():
    assert parse_ports("80") == [80]


def test_ports_list():
    assert parse_ports("80,443,8080") == [80, 443, 8080]


def test_ports_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_ports_mixed_and_dedupe():
    assert parse_ports("22,1-3,22") == [1, 2, 3, 22]


@pytest.mark.parametrize("bad", ["abc", "70000", "80-70", "-1", "0", ""])
def test_ports_invalid(bad):
    with pytest.raises(TargetError):
        parse_ports(bad)
