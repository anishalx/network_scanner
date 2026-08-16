"""Command-line interface for NetScanner."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from . import __version__
from .output import (
    HOST_COLUMNS,
    PORT_COLUMNS,
    format_csv,
    format_json,
    format_table,
    write_output,
)
from .scanner import COMMON_PORTS, ScanError, discover_hosts, port_scan
from .target import TargetError, parse_ports, parse_targets
from .utils import colorize, is_admin, setup_logging
from .vendor import BUILTIN_OUI, load_vendor_db

LOG = logging.getLogger("netscanner")

BANNER = r"""
                )           (                   )    )     (
             ( /(      *   ))\ )  (    (     ( /( ( /(     )\ )
             )\())(  ` )  /(()/(  )\   )\    )\()))\())(  (()/(
            ((_)\ )\  ( )(_))(_)|((_|(((_)( ((_)\\((_)\ )\  /(_))
             _((_|(_)(_(_()|_)) )\___)\ _ )\ _((_)_((_|(_)(_))
            | \| | __|_   _/ __((/ __(_)_\(_) \| | \| | __| _ \
            | .` | _|  | | \__ \| (__ / _ \ | .` | .` | _||   /
            |_|\_|___| |_| |___/ \___/_/ \_\_|_|\_|_|\_|___|_|_\
        =============================================================
                    Version: 2.0     Twitter: anishalx7
        =============================================================
"""


def print_banner() -> None:
    """Print the ASCII banner; art in red, separators/version in yellow."""
    for line in BANNER.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("=") or "Version" in line or "Twitter" in line:
            print(colorize(line, "yellow"))
        else:
            print(colorize(line, "red"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscanner",
        description="Discover devices and open ports on your network (ARP, ICMP, TCP).",
        epilog=(
            "examples:\n"
            "  netscanner -t 192.168.1.0/24                     # auto: ARP + ICMP + TCP fallback\n"
            "  netscanner -t 192.168.1.0/24 -m arp              # local segment, needs admin/root\n"
            "  netscanner -t 192.168.1.0/24 -m ping             # ICMP sweep\n"
            "  netscanner -t 192.168.1.5 -m tcp -p 1-1000       # port scan (no privileges needed)\n"
            "  netscanner -t 192.168.1.1-50 -f json -o out.json # JSON to file\n"
            "  netscanner -t myrouter.local -m arp              # resolve a hostname first\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target",
        required=True,
        metavar="TARGET",
        help=(
            "IP, CIDR range (192.168.1.0/24), hyphen range (192.168.1.1-50), "
            "hostname, or comma-separated list"
        ),
    )
    parser.add_argument(
        "-m",
        "--method",
        dest="method",
        choices=["arp", "ping", "tcp", "all"],
        default="all",
        help="Scan method (default: all)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        dest="ports",
        default=None,
        metavar="PORTS",
        help="Ports for -m tcp: '22', '80,443', '1-1000' (default: common ports)",
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="fmt",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        metavar="FILE",
        help="Write results to a file",
    )
    parser.add_argument(
        "--iface",
        dest="iface",
        default=None,
        metavar="IFACE",
        help="Network interface for ARP/ping (e.g. eth0, Wi-Fi)",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Timeout per probe in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--retries",
        dest="retries",
        type=int,
        default=1,
        metavar="N",
        help="Probe retries (default: 1)",
    )
    parser.add_argument(
        "--concurrency",
        dest="concurrency",
        type=int,
        default=32,
        metavar="N",
        help="Number of parallel probes (default: 32)",
    )
    parser.add_argument(
        "--resolve",
        dest="resolve",
        action="store_true",
        help="Resolve hostnames for discovered hosts (slower)",
    )
    parser.add_argument(
        "--vendor-db",
        dest="vendor_db",
        default=None,
        metavar="FILE",
        help="Custom OUI vendor database (lines of 'OUI,Vendor' or 'OUI - Vendor')",
    )
    parser.add_argument(
        "--no-banner",
        dest="banner",
        action="store_false",
        help="Suppress the ASCII banner",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Verbose (debug) logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    setup_logging(verbose="-v" in argv_list or "--verbose" in argv_list)
    args = build_parser().parse_args(argv_list)

    try:
        targets = parse_targets([args.target])
    except TargetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    vendor_db = None
    if args.vendor_db:
        try:
            vendor_db = {**BUILTIN_OUI, **load_vendor_db(args.vendor_db)}
        except (OSError, ValueError) as exc:
            print(f"ERROR: could not load vendor database: {exc}", file=sys.stderr)
            return 1

    is_port_scan = args.method == "tcp" or args.ports is not None
    if is_port_scan and args.method != "tcp":
        LOG.info("Ports were specified; performing a TCP port scan")

    if not is_port_scan and not is_admin():
        LOG.warning(
            "ARP/ICMP scans require administrator/root privileges on most systems; "
            "use -m tcp if you lack them."
        )

    try:
        if is_port_scan:
            ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
            results = port_scan(
                targets,
                ports,
                timeout=args.timeout,
                concurrency=args.concurrency,
                resolve=args.resolve,
            )
            columns = PORT_COLUMNS
        else:
            results = discover_hosts(
                targets,
                method=args.method,
                timeout=args.timeout,
                retries=args.retries,
                iface=args.iface,
                concurrency=args.concurrency,
                resolve=args.resolve,
                vendor_db=vendor_db,
            )
            columns = HOST_COLUMNS
    except TargetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except ScanError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.fmt == "json":
        text = format_json(results)
    elif args.fmt == "csv":
        text = format_csv(results, columns)
    else:
        text = format_table(results, columns)

    if args.banner and args.fmt == "table":
        print_banner()

    if args.output:
        try:
            write_output(text, args.output)
        except OSError as exc:
            print(f"ERROR: could not write output file: {exc}", file=sys.stderr)
            return 1
        noun = "open port(s)" if is_port_scan else "device(s)"
        print(f"Wrote {len(results)} {noun} to {args.output}")
        return 0

    if args.fmt == "table" and not results:
        empty_msg = "No open ports found." if is_port_scan else "No devices found."
        print(empty_msg)
        if not is_port_scan:
            print("Tip: try -m ping or -m tcp if ARP is blocked, or run with admin/root privileges.")
        return 0

    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
