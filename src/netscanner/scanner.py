"""Scanning backends: ARP host discovery, ICMP ping sweep, and TCP port scan.

All workers run concurrently (ThreadPoolExecutor). Scapy is imported lazily at
module load with a graceful fallback so the CLI can still run TCP scans and
report clear errors when the library is missing.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Iterable, List, Optional, Tuple

try:
    from scapy.all import ARP, Ether, ICMP, IP, sr1, srp  # noqa: F401
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


def port_scan(
    targets: Iterable[str],
    ports: Iterable[int],
    timeout: float = 1.0,
    concurrency: int = 100,
    resolve: bool = False,
) -> List[Dict]:
    """Scan ports on targets using TCP connect (no privileges required).

    Each result: {"ip", "port", "service", "state": "open"}.
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
