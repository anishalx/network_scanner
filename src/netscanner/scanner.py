"""Scanning backends: ARP host discovery, ICMP ping sweep, and TCP/UDP port scans.

All workers run concurrently (ThreadPoolExecutor). Scapy is imported lazily at
module load with a graceful fallback so the CLI can still run TCP/UDP scans and
report clear errors when the library is missing.
"""

from __future__ import annotations

import errno
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Iterable, List, Optional, Tuple

try:
    from scapy.all import ARP, Ether, ICMP, IP, TCP, send, sr1, srp  # noqa: F401
    from scapy.error import Scapy_Exception

    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

from . import vendor as vendor_mod
from .utils import LOG, normalize_mac, resolve_hostname

# Used for TCP liveness probing in "all" mode and as the default port set.
COMMON_PORTS = [22, 53, 80, 443, 445, 3389, 8080]

def _ip_key(ip: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in ip.split("."))


def _dedupe_and_sort(results: List[Dict]) -> List[Dict]:
    """Drop duplicate hosts (overlapping targets can produce repeats) and sort by IP."""
    unique: Dict[str, Dict] = {}
    for entry in results:
        unique.setdefault(entry["ip"], entry)
    return sorted(unique.values(), key=lambda r: _ip_key(r["ip"]))


class ScanError(RuntimeError):
    """Raised when a scan cannot be performed (privileges, missing driver, etc.)."""


def _require_scapy() -> None:
    if not HAVE_SCAPY:
        raise ScanError(
            "Scapy is required for this scan method. Install it with: pip install scapy"
        )


def _map_scan(
    worker: Callable[[object], Tuple[List[Dict], Optional[str]]],
    items: List[object],
    concurrency: int,
) -> List[Dict]:
    """Run worker(item) concurrently.

    worker returns (results, error_message_or_None). If every item fails, the
    first error is raised as ScanError; if only some fail, a warning is logged
    and the partial results are returned.
    """
    results: List[Dict] = []
    errors: List[str] = []
    workers = max(1, min(int(concurrency), len(items) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, item) for item in items]
        for future in as_completed(futures):
            batch, error = future.result()
            results.extend(batch)
            if error:
                errors.append(error)
    if errors and not results:
        raise ScanError(errors[0])
    if errors:
        LOG.warning("%d probe(s) failed: %s", len(errors), errors[0])
    return results


def _stream_scan(
    worker: Callable[[object], Tuple[List[Dict], Optional[str]]],
    items: List[object],
    concurrency: int,
) -> Iterable[Dict]:
    """Run worker(item) concurrently, yielding each result as it arrives.

    Yields entries in completion order (unordered). Raises ScanError if every
    item failed and nothing was yielded.
    """
    errors: List[str] = []
    yielded_any = False
    workers = max(1, min(int(concurrency), len(items) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, item) for item in items]
        for future in as_completed(futures):
            batch, error = future.result()
            if batch:
                yielded_any = True
                for entry in batch:
                    yield entry
            if error:
                errors.append(error)
    if errors and not yielded_any:
        raise ScanError(errors[0])
    if errors:
        LOG.warning("%d probe(s) failed: %s", len(errors), errors[0])


def arp_scan(
    targets: Iterable[str],
    timeout: float = 2.0,
    retries: int = 1,
    iface: Optional[str] = None,
    concurrency: int = 32,
    resolve: bool = False,
    vendor_db: Optional[Dict[str, str]] = None,
) -> List[Dict]:
    """Discover hosts on the local network segment via ARP requests.

    Each result: {"ip", "mac", "vendor", "hostname"}. Requires raw sockets
    (administrator/root; Npcap on Windows).
    """
    _require_scapy()
    targets = [str(t) for t in targets]

    def worker(ip: str) -> Tuple[List[Dict], Optional[str]]:
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = srp(
                broadcast / arp_request,
                timeout=timeout,
                retry=max(0, retries - 1),
                iface=iface,
                verbose=False,
            )[0]
        except PermissionError:
            return [], "ARP scanning requires administrator/root privileges."
        except (OSError, RuntimeError, Scapy_Exception) as exc:
            return [], (
                "ARP scan failed (raw sockets unavailable; on Windows install "
                f"Npcap and run as administrator): {exc}"
            )
        except Exception as exc:  # noqa: BLE001 - surface platform quirks cleanly
            return [], f"ARP scan failed for {ip}: {exc}"

        entries: List[Dict] = []
        for _, received in answered:
            ip_addr = str(getattr(received, "psrc", ""))
            mac = normalize_mac(str(getattr(received, "hwsrc", "")))
            entries.append(
                {
                    "ip": ip_addr,
                    "mac": mac or None,
                    "vendor": vendor_mod.lookup_vendor(mac, vendor_db) if mac else None,
                    "hostname": resolve_hostname(ip_addr) if resolve else None,
                }
            )
        return entries, None

    results = _map_scan(worker, list(targets), concurrency)
    return _dedupe_and_sort(results)


def icmp_ping(
    targets: Iterable[str],
    timeout: float = 2.0,
    retries: int = 1,
    concurrency: int = 32,
    resolve: bool = False,
) -> List[Dict]:
    """Probe hosts with ICMP echo requests.

    Each result: {"ip", "mac": None, "vendor": None, "hostname"}. Requires raw
    sockets on most platforms (administrator/root).
    """
    _require_scapy()
    targets = [str(t) for t in targets]

    def worker(ip: str) -> Tuple[List[Dict], Optional[str]]:
        try:
            reply = sr1(
                IP(dst=ip) / ICMP(),
                timeout=timeout,
                retry=max(0, retries - 1),
                verbose=False,
            )
        except PermissionError:
            return [], "ICMP ping requires administrator/root privileges."
        except (OSError, RuntimeError, Scapy_Exception) as exc:
            return [], f"ICMP ping failed (raw sockets unavailable): {exc}"
        except Exception as exc:  # noqa: BLE001 - surface platform quirks cleanly
            return [], f"ICMP ping failed for {ip}: {exc}"
        if reply is None:
            return [], None
        return (
            [
                {
                    "ip": ip,
                    "mac": None,
                    "vendor": None,
                    "hostname": resolve_hostname(ip) if resolve else None,
                }
            ],
            None,
        )

    results = _map_scan(worker, list(targets), concurrency)
    return _dedupe_and_sort(results)


def _service_name(port: int) -> Optional[str]:
    try:
        return socket.getservbyport(port)
    except OSError:
        return None


def _udp_state_from_error(exc: OSError) -> str:
    """Map the OS error raised by a UDP probe to an nmap-style state.

    Closed ports surface as ICMP port-unreachable, which Python reports as
    ConnectionRefusedError (POSIX ECONNREFUSED) or ConnectionResetError
    (Windows WSAECONNRESET). Host/network unreachable means filtered.
    """
    if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
        return "closed"
    if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
        return "filtered"
    if exc.errno == errno.ETIMEDOUT:
        return "open|filtered"
    return "filtered"


def port_scan(
    targets: Iterable[str],
    ports: Iterable[int],
    timeout: float = 1.0,
    concurrency: int = 100,
    resolve: bool = False,
    stream: bool = False,
) -> Iterable[Dict]:
    """Scan ports on targets using TCP connect (no privileges required).

    Each result: {"ip", "port", "service", "state": "open"}. With
    stream=True, returns a generator yielding results as they are discovered
    (completion order) instead of a sorted list - useful for very large scans.
    """
    targets = [str(t) for t in targets]
    ports = list(ports)

    def worker(job: Tuple[str, int]) -> Tuple[List[Dict], Optional[str]]:
        ip, port = job
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                return (
                    [
                        {
                            "ip": ip,
                            "port": port,
                            "service": _service_name(port),
                            "state": "open",
                        }
                    ],
                    None,
                )
            return [], None
        except socket.error:
            return [], None
        finally:
            sock.close()

    jobs = [(ip, port) for ip in targets for port in ports]
    if stream:
        return _stream_scan(worker, jobs, concurrency)
    results = _map_scan(worker, jobs, concurrency)
    results.sort(key=lambda r: (_ip_key(r["ip"]), r["port"]))
    return results


def udp_scan(
    targets: Iterable[str],
    ports: Iterable[int],
    timeout: float = 2.0,
    concurrency: int = 64,
    include_closed: bool = False,
    stream: bool = False,
) -> Iterable[Dict]:
    """Scan ports on targets with a UDP datagram probe (no privileges required).

    UDP has no handshake, so states are inferred from ICMP errors and silence:
      * "open"          - the service replied with data (rare without a
                          protocol-specific probe, e.g. DNS, SNMP, NTP)
      * "open|filtered" - no reply and no ICMP error within the timeout
      * "closed"        - ICMP port unreachable
      * "filtered"      - ICMP host/network unreachable or admin-prohibited

    By default only open and open|filtered ports are reported; pass
    include_closed=True to also list closed/filtered results. With
    stream=True, returns a generator yielding results as discovered.
    """
    targets = [str(t) for t in targets]
    ports = list(ports)

    def worker(job: Tuple[str, int]) -> Tuple[List[Dict], Optional[str]]:
        ip, port = job
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            # connect() is required so ICMP unreachable errors are delivered
            # to the socket (sendto/recvfrom on an unconnected socket misses them)
            sock.connect((ip, port))
            sock.send(b"")
            try:
                sock.recvfrom(1024)
                state = "open"
            except socket.timeout:
                state = "open|filtered"
            except OSError as exc:
                state = _udp_state_from_error(exc)
        except OSError:
            return [], None  # could not reach the host at all
        finally:
            sock.close()

        if state in ("closed", "filtered") and not include_closed:
            return [], None
        return (
            [{"ip": ip, "port": port, "service": _service_name(port), "state": state}],
            None,
        )

    jobs = [(ip, port) for ip in targets for port in ports]
    if stream:
        return _stream_scan(worker, jobs, concurrency)
    results = _map_scan(worker, jobs, concurrency)
    results.sort(key=lambda r: (_ip_key(r["ip"]), r["port"]))
    return results


def _send_rst(ip: str, port: int) -> None:
    """Best-effort RST to close a half-open TCP connection; never raises."""
    try:
        send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=False)
    except (OSError, RuntimeError, Scapy_Exception):
        pass


def syn_scan(
    targets: Iterable[str],
    ports: Iterable[int],
    timeout: float = 2.0,
    retries: int = 1,
    iface: Optional[str] = None,
    concurrency: int = 32,
    include_closed: bool = False,
    stream: bool = False,
) -> Iterable[Dict]:
    """Half-open TCP SYN scan (-sS style) using raw sockets (requires admin/root).

    Sends a SYN and infers the state from the reply without completing the
    handshake, so the target application never sees an established connection:
      * "open"     - SYN-ACK received (a RST is sent to close the half-open
                      connection)
      * "closed"   - RST received
      * "filtered" - no reply after retries, or an ICMP error

    By default only open ports are reported; pass include_closed=True to also
    list closed/filtered results. Requires raw sockets (Npcap on Windows).
    With stream=True, returns a generator yielding results as discovered.
    """
    _require_scapy()
    targets = [str(t) for t in targets]
    ports = list(ports)

    def worker(job: Tuple[str, int]) -> Tuple[List[Dict], Optional[str]]:
        ip, port = job
        try:
            reply = sr1(
                IP(dst=ip) / TCP(dport=port, flags="S"),
                timeout=timeout,
                retry=max(0, retries - 1),
                iface=iface,
                verbose=False,
            )
        except PermissionError:
            return [], "SYN scanning requires administrator/root privileges."
        except (OSError, RuntimeError, Scapy_Exception) as exc:
            return [], (
                "SYN scan failed (raw sockets unavailable; on Windows install "
                f"Npcap and run as administrator): {exc}"
            )
        except Exception as exc:  # noqa: BLE001 - surface platform quirks cleanly
            return [], f"SYN scan failed for {ip}:{port}: {exc}"

        state = "filtered"
        if reply is not None and reply.haslayer(TCP):
            flags = int(reply[TCP].flags)
            if flags & 0x12:  # SYN-ACK -> open
                state = "open"
                _send_rst(ip, port)
            elif flags & 0x04:  # RST -> closed
                state = "closed"
        # no reply or ICMP unreachable -> filtered

        if state in ("closed", "filtered") and not include_closed:
            return [], None
        return (
            [{"ip": ip, "port": port, "service": _service_name(port), "state": state}],
            None,
        )

    jobs = [(ip, port) for ip in targets for port in ports]
    if stream:
        return _stream_scan(worker, jobs, concurrency)
    results = _map_scan(worker, jobs, concurrency)
    results.sort(key=lambda r: (_ip_key(r["ip"]), r["port"]))
    return results


def discover_hosts(
    targets: Iterable[str],
    method: str = "all",
    timeout: float = 2.0,
    retries: int = 1,
    iface: Optional[str] = None,
    concurrency: int = 32,
    resolve: bool = False,
    vendor_db: Optional[Dict[str, str]] = None,
    common_ports: Optional[Iterable[int]] = None,
) -> List[Dict]:
    """Discover live hosts, merging results from multiple methods by IP.

    method:
      * "arp"  - ARP only (local segment). Raises ScanError if unavailable.
      * "ping" - ICMP only. Raises ScanError if unavailable.
      * "all"  - ARP then ICMP, degrading gracefully if either fails; if
                 nothing is found, falls back to a TCP connect on common
                 ports (works without privileges).

    Each result: {"ip", "mac", "vendor", "hostname"}.
    """
    _require_scapy()
    targets = [str(t) for t in targets]
    results: Dict[str, Dict] = {}

    def run(method_name: str) -> None:
        if method_name == "arp":
            entries = arp_scan(
                targets,
                timeout=timeout,
                retries=retries,
                iface=iface,
                concurrency=concurrency,
                resolve=resolve,
                vendor_db=vendor_db,
            )
        elif method_name == "ping":
            entries = icmp_ping(
                targets,
                timeout=timeout,
                retries=retries,
                concurrency=concurrency,
                resolve=resolve,
            )
        else:  # tcp liveness probe
            ports = list(common_ports) if common_ports else COMMON_PORTS
            entries = [
                {
                    "ip": entry["ip"],
                    "mac": None,
                    "vendor": None,
                    "hostname": resolve_hostname(entry["ip"]) if resolve else None,
                }
                for entry in port_scan(targets, ports, timeout=timeout, concurrency=concurrency)
            ]
        for entry in entries:
            results.setdefault(entry["ip"], entry)

    if method == "all":
        for name in ("arp", "ping"):
            try:
                run(name)
            except ScanError as exc:
                LOG.warning("Host discovery via %s unavailable: %s", name, exc)
        if not results:
            LOG.info("ARP/ICMP found no hosts; trying TCP connect on common ports...")
            run("tcp")
    elif method == "arp":
        run("arp")
    elif method == "ping":
        run("ping")
    else:
        raise ValueError(f"Unknown discovery method: {method}")

    return sorted(results.values(), key=lambda r: _ip_key(r["ip"]))
