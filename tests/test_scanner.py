import errno
import socket

import pytest

from netscanner import scanner
from netscanner.scanner import (
    ScanError,
    arp_scan,
    discover_hosts,
    icmp_ping,
    port_scan,
    syn_scan,
    udp_scan,
)


class FakeAnswered:
    def __init__(self, psrc, hwsrc):
        self.psrc = psrc
        self.hwsrc = hwsrc


class FakeReply:
    pass


# --- ARP ---


def test_arp_scan_discovers_hosts(monkeypatch):
    fake_answered = [("sent", FakeAnswered("192.168.1.10", "aa:bb:cc:dd:ee:ff"))]
    monkeypatch.setattr(scanner, "srp", lambda *a, **k: (fake_answered, []))
    results = arp_scan(["192.168.1.10"])
    assert results == [
        {
            "ip": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": None,
            "hostname": None,
        }
    ]


def test_arp_scan_normalizes_mac_and_looks_up_vendor(monkeypatch):
    fake_answered = [("sent", FakeAnswered("192.168.1.2", "B8-27-EB-12-34-56"))]
    monkeypatch.setattr(scanner, "srp", lambda *a, **k: (fake_answered, []))
    results = arp_scan(["192.168.1.2"])
    assert results[0]["mac"] == "b8:27:eb:12:34:56"
    assert results[0]["vendor"] == "Raspberry Pi Foundation"


def test_arp_scan_empty(monkeypatch):
    monkeypatch.setattr(scanner, "srp", lambda *a, **k: ([], []))
    assert arp_scan(["192.168.1.10"]) == []


def test_arp_scan_sorts_by_ip(monkeypatch):
    def fake_srp(pkt, *a, **k):
        ip = pkt[scanner.ARP].pdst
        if ip == "192.168.1.20":
            return ([("s", FakeAnswered("192.168.1.20", "aa:aa:aa:aa:aa:aa"))], [])
        return ([("s", FakeAnswered("192.168.1.3", "bb:bb:bb:bb:bb:bb"))], [])

    monkeypatch.setattr(scanner, "srp", fake_srp)
    results = arp_scan(["192.168.1.20", "192.168.1.3"])
    assert [r["ip"] for r in results] == ["192.168.1.3", "192.168.1.20"]


def test_arp_scan_dedupes_overlapping_targets(monkeypatch):
    fake_answered = [("s", FakeAnswered("192.168.1.1", "aa:aa:aa:aa:aa:aa"))]
    monkeypatch.setattr(scanner, "srp", lambda *a, **k: (fake_answered, []))
    results = arp_scan(["192.168.1.1", "192.168.1.1/32"])
    assert len(results) == 1


def test_arp_scan_privilege_error(monkeypatch):
    def boom(*a, **k):
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(scanner, "srp", boom)
    with pytest.raises(ScanError, match="administrator/root"):
        arp_scan(["192.168.1.10"])


def test_arp_scan_oserror(monkeypatch):
    def boom(*a, **k):
        raise OSError("no libpcap")

    monkeypatch.setattr(scanner, "srp", boom)
    with pytest.raises(ScanError):
        arp_scan(["192.168.1.10"])


# --- ICMP ---


def test_ping_alive(monkeypatch):
    monkeypatch.setattr(scanner, "sr1", lambda *a, **k: FakeReply())
    results = icmp_ping(["192.168.1.10"])
    assert results == [
        {"ip": "192.168.1.10", "mac": None, "vendor": None, "hostname": None}
    ]


def test_ping_dead(monkeypatch):
    monkeypatch.setattr(scanner, "sr1", lambda *a, **k: None)
    assert icmp_ping(["192.168.1.10"]) == []


def test_ping_privilege_error(monkeypatch):
    def boom(*a, **k):
        raise PermissionError()

    monkeypatch.setattr(scanner, "sr1", boom)
    with pytest.raises(ScanError):
        icmp_ping(["192.168.1.10"])


# --- TCP ---


class FakeSocket:
    """Minimal stand-in for socket.socket (connect_ex is read-only in 3.13)."""

    def __init__(self, *args, **kwargs):
        pass

    def settimeout(self, timeout):
        pass

    def connect_ex(self, addr):
        return 0 if addr[1] == 80 else 1

    def close(self):
        pass


def test_port_scan_open_and_closed(monkeypatch):
    monkeypatch.setattr(socket, "socket", FakeSocket)
    results = port_scan(["192.168.1.10"], [80, 443], timeout=0.1)
    assert results == [
        {"ip": "192.168.1.10", "port": 80, "service": "http", "state": "open"}
    ]


def test_port_scan_no_open_ports(monkeypatch):
    class ClosedSocket(FakeSocket):
        def connect_ex(self, addr):
            return 1

    monkeypatch.setattr(socket, "socket", ClosedSocket)
    assert port_scan(["192.168.1.10"], [80, 443], timeout=0.1) == []


def test_port_scan_stream_returns_generator(monkeypatch):
    import types

    monkeypatch.setattr(socket, "socket", FakeSocket)
    gen = port_scan(["192.168.1.10"], [80, 443], timeout=0.1, stream=True)
    assert isinstance(gen, types.GeneratorType)
    results = list(gen)
    assert results == [
        {"ip": "192.168.1.10", "port": 80, "service": "http", "state": "open"}
    ]


def test_udp_scan_stream_yields_entries(monkeypatch):
    monkeypatch.setattr(socket, "socket", FakeUDPSocket)
    results = list(udp_scan(["192.168.1.10"], [53, 161], timeout=0.1, stream=True))
    assert all(r["state"] == "open|filtered" for r in results)
    assert len(results) == 2


# --- UDP ---


class FakeUDPSocket:
    """Minimal UDP socket; recvfrom times out by default (open|filtered)."""

    def __init__(self, *args, **kwargs):
        pass

    def settimeout(self, timeout):
        pass

    def connect(self, addr):
        pass

    def send(self, data):
        pass

    def recvfrom(self, bufsize):
        raise socket.timeout()

    def close(self):
        pass


def test_udp_scan_open(monkeypatch):
    class OpenUDPSocket(FakeUDPSocket):
        def recvfrom(self, bufsize):
            return (b"response", ("192.168.1.10", 53))

    monkeypatch.setattr(socket, "socket", OpenUDPSocket)
    results = udp_scan(["192.168.1.10"], [53])
    assert results == [
        {"ip": "192.168.1.10", "port": 53, "service": "domain", "state": "open"}
    ]


def test_udp_scan_no_reply_is_open_filtered(monkeypatch):
    monkeypatch.setattr(socket, "socket", FakeUDPSocket)
    results = udp_scan(["192.168.1.10"], [53])
    assert results == [
        {"ip": "192.168.1.10", "port": 53, "service": "domain", "state": "open|filtered"}
    ]


def test_udp_scan_closed_hidden_by_default(monkeypatch):
    class ClosedUDPSocket(FakeUDPSocket):
        def recvfrom(self, bufsize):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

    monkeypatch.setattr(socket, "socket", ClosedUDPSocket)
    assert udp_scan(["192.168.1.10"], [53]) == []


def test_udp_scan_include_closed(monkeypatch):
    class ClosedUDPSocket(FakeUDPSocket):
        def recvfrom(self, bufsize):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

    monkeypatch.setattr(socket, "socket", ClosedUDPSocket)
    results = udp_scan(["192.168.1.10"], [53], include_closed=True)
    assert results == [
        {"ip": "192.168.1.10", "port": 53, "service": "domain", "state": "closed"}
    ]


def test_udp_scan_windows_reset_is_closed(monkeypatch):
    class ResetUDPSocket(FakeUDPSocket):
        def recvfrom(self, bufsize):
            raise ConnectionResetError(10054, "WSAECONNRESET")

    monkeypatch.setattr(socket, "socket", ResetUDPSocket)
    results = udp_scan(["192.168.1.10"], [53], include_closed=True)
    assert results == [
        {"ip": "192.168.1.10", "port": 53, "service": "domain", "state": "closed"}
    ]


def test_udp_scan_sorts_by_ip_and_port(monkeypatch):
    monkeypatch.setattr(socket, "socket", FakeUDPSocket)
    results = udp_scan(["192.168.1.10"], [80, 53])
    assert [r["port"] for r in results] == [53, 80]


# --- SYN ---


class FakeTCPReply:
    """Minimal stand-in for a scapy reply packet carrying TCP flags."""

    def __init__(self, flags):
        self._flags = flags

    def haslayer(self, layer):
        return layer is scanner.TCP

    def __getitem__(self, layer):
        if layer is scanner.TCP:
            return self
        raise KeyError(layer)

    @property
    def flags(self):
        return self._flags


def test_syn_scan_open(monkeypatch):
    monkeypatch.setattr(scanner, "sr1", lambda *a, **k: FakeTCPReply(0x12))  # SYN-ACK
    rst_sent = []
    monkeypatch.setattr(
        scanner, "send", lambda *a, **k: rst_sent.append(a) or None
    )
    results = syn_scan(["192.168.1.10"], [80])
    assert results == [
        {"ip": "192.168.1.10", "port": 80, "service": "http", "state": "open"}
    ]
    assert len(rst_sent) == 1  # half-open connection was closed with a RST


def test_syn_scan_closed(monkeypatch):
    monkeypatch.setattr(scanner, "sr1", lambda *a, **k: FakeTCPReply(0x04))  # RST
    assert syn_scan(["192.168.1.10"], [80]) == []
    results = syn_scan(["192.168.1.10"], [80], include_closed=True)
    assert results[0]["state"] == "closed"


def test_syn_scan_filtered_no_reply(monkeypatch):
    monkeypatch.setattr(scanner, "sr1", lambda *a, **k: None)
    assert syn_scan(["192.168.1.10"], [80]) == []
    results = syn_scan(["192.168.1.10"], [80], include_closed=True)
    assert results[0]["state"] == "filtered"


def test_syn_scan_privilege_error(monkeypatch):
    def boom(*a, **k):
        raise PermissionError()

    monkeypatch.setattr(scanner, "sr1", boom)
    with pytest.raises(ScanError, match="administrator/root"):
        syn_scan(["192.168.1.10"], [80])


def test_syn_scan_stream(monkeypatch):
    import types

    monkeypatch.setattr(scanner, "sr1", lambda *a, **k: FakeTCPReply(0x12))
    monkeypatch.setattr(scanner, "send", lambda *a, **k: None)
    gen = syn_scan(["192.168.1.10"], [80], stream=True)
    assert isinstance(gen, types.GeneratorType)
    assert [r["port"] for r in gen] == [80]


def test_syn_scan_sorts_by_ip_and_port(monkeypatch):
    monkeypatch.setattr(scanner, "sr1", lambda *a, **k: FakeTCPReply(0x12))
    monkeypatch.setattr(scanner, "send", lambda *a, **k: None)
    results = syn_scan(["192.168.1.10"], [443, 80])
    assert [r["port"] for r in results] == [80, 443]


# --- discover_hosts ---


def test_discover_all_merges_and_sorts(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "srp",
        lambda *a, **k: (
            [("sent", FakeAnswered("192.168.1.2", "b8:27:eb:12:34:56"))],
            [],
        ),
    )
    monkeypatch.setattr(scanner, "sr1", lambda *a, **k: FakeReply())

    results = discover_hosts(["192.168.1.1", "192.168.1.2"], method="all")
    assert [r["ip"] for r in results] == ["192.168.1.1", "192.168.1.2"]
    by_ip = {r["ip"]: r for r in results}
    # ARP data (mac + vendor) is kept for the host ARP found
    assert by_ip["192.168.1.2"]["mac"] == "b8:27:eb:12:34:56"
    assert by_ip["192.168.1.2"]["vendor"] == "Raspberry Pi Foundation"
    # Ping found .1 but no ARP response, so no MAC
    assert by_ip["192.168.1.1"]["mac"] is None


def test_discover_all_degrades_to_tcp_fallback(monkeypatch):
    def boom_srp(*a, **k):
        raise PermissionError()

    def boom_sr1(*a, **k):
        raise PermissionError()

    monkeypatch.setattr(scanner, "srp", boom_srp)
    monkeypatch.setattr(scanner, "sr1", boom_sr1)
    monkeypatch.setattr(socket, "socket", FakeSocket)

    results = discover_hosts(["192.168.1.10"], method="all", common_ports=[80, 443])
    assert [r["ip"] for r in results] == ["192.168.1.10"]
    assert results[0]["mac"] is None


def test_discover_explicit_method_raises_on_failure(monkeypatch):
    def boom(*a, **k):
        raise PermissionError()

    monkeypatch.setattr(scanner, "srp", boom)
    with pytest.raises(ScanError):
        discover_hosts(["192.168.1.10"], method="arp")


def test_discover_explicit_ping(monkeypatch):
    monkeypatch.setattr(scanner, "sr1", lambda *a, **k: FakeReply())
    results = discover_hosts(["192.168.1.10"], method="ping")
    assert [r["ip"] for r in results] == ["192.168.1.10"]
