"""Target and port-range parsing.

Accepts single IPs, CIDR blocks, hyphen ranges (full or partial octets),
hostnames, and comma-separated combinations of all of the above.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Iterable, List

MAX_HOSTS = 65535

_HYPHEN_RANGE_RE = re.compile(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})-(.+)$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


class TargetError(ValueError):
    """Raised when a target or port specification is invalid."""


def _expand_single(value: str, out: List[ipaddress.IPv4Address], errors: List[str]) -> None:
    value = value.strip()
    if not value:
        return

    # CIDR block or plain IP
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.num_addresses - 2 > MAX_HOSTS:
                errors.append(
                    f"{value} expands to more than {MAX_HOSTS} hosts - narrow the range"
                )
                return
            out.extend(network.hosts())
            return
        addr = ipaddress.ip_address(value)
        if addr.version == 4:
            out.append(addr)
        else:
            errors.append(value)  # IPv6 not supported
        return
    except ValueError:
        pass

    # Hyphen range: 192.168.1.1-192.168.1.50 or 192.168.1.1-50
    match = _HYPHEN_RANGE_RE.match(value)
    if match:
        try:
            start = ipaddress.ip_address(match.group(1))
            raw_end = match.group(2)
            if start.version != 4:
                errors.append(value)
                return
            if "." not in raw_end:
                if not raw_end.isdigit():
                    raise ValueError(raw_end)
                raw_end = ".".join(str(start).split(".")[:-1] + [raw_end])
            end = ipaddress.ip_address(raw_end)
            if end.version != 4 or end < start:
                raise ValueError(raw_end)
            start_int, end_int = int(start), int(end)
            if end_int - start_int + 1 > MAX_HOSTS:
                errors.append(f"{value} expands to more than {MAX_HOSTS} hosts - narrow the range")
                return
            for n in range(start_int, end_int + 1):
                out.append(ipaddress.IPv4Address(n))
            return
        except ValueError:
            pass

    # Hostname
    if _HOSTNAME_RE.match(value):
        try:
            infos = socket.getaddrinfo(value, None, socket.AF_INET)
            seen = set()
            for info in infos:
                ip = info[4][0]
                if ip not in seen:
                    seen.add(ip)
                    out.append(ipaddress.ip_address(ip))
            if not infos:
                errors.append(value)
            return
        except socket.gaierror:
            errors.append(value)
            return

    errors.append(value)


def parse_targets(targets: Iterable[str]) -> List[ipaddress.IPv4Address]:
    """Expand one or more target strings into a deduplicated, ordered list of IPv4 addresses."""
    out: List[ipaddress.IPv4Address] = []
    errors: List[str] = []
    for raw in targets:
        for chunk in raw.split(","):
            _expand_single(chunk, out, errors)

    if errors:
        raise TargetError("Invalid target(s): " + ", ".join(errors))

    seen = set()
    deduped = []
    for addr in out:
        if addr not in seen:
            seen.add(addr)
            deduped.append(addr)

    if not deduped:
        raise TargetError("No valid targets provided.")
    if len(deduped) > MAX_HOSTS:
        raise TargetError(
            f"Target expands to {len(deduped)} hosts, exceeding the limit of {MAX_HOSTS}. "
            "Narrow the range."
        )
    return deduped


def parse_ports(spec: str) -> List[int]:
    """Parse a port specification like '80', '80,443', or '1-1000' into a sorted list."""
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            raise TargetError(f"Invalid port specification: '{spec}'")
        if "-" in chunk:
            try:
                start_s, end_s = chunk.split("-", 1)
                start, end = int(start_s), int(end_s)
            except ValueError as exc:
                raise TargetError(f"Invalid port range: '{chunk}'") from exc
            if start > end:
                raise TargetError(f"Invalid port range (start > end): '{chunk}'")
            if start < 1 or end > 65535:
                raise TargetError(f"Ports must be between 1 and 65535: '{chunk}'")
            if end - start + 1 > 65535:
                raise TargetError(f"Port range too large: '{chunk}'")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise TargetError(f"Invalid port: '{chunk}'") from exc
            if not 1 <= port <= 65535:
                raise TargetError(f"Port out of range (1-65535): '{port}'")
            ports.add(port)

    if not ports:
        raise TargetError(f"No valid ports in specification: '{spec}'")
    return sorted(ports)
