# NetScanner

```bash
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
```

## Overview

**NetScanner** is a fast, cross-platform network discovery and port-scanning tool built with Python and [Scapy](https://scapy.readthedocs.io/). Discover devices on your local network, sweep subnets with ICMP, or scan for open TCP ports — all from a clean command-line interface.

### Why Use NetScanner?

- **User-Friendly**: Designed for both beginners and experienced users.
- **Versatile**: ARP host discovery, ICMP ping sweeps, and TCP port scans in one tool.
- **Fast**: Concurrent probes with tunable thread counts and timeouts.
- **Scriptable**: Table, JSON, or CSV output, with optional file export.

## Features (v2)

- **Three scan methods** (`arp`, `ping`, `tcp`) plus automatic `all` mode:
  - `arp` — Layer-2 host discovery on your local segment (IP + MAC + vendor)
  - `ping` — ICMP echo sweep
  - `tcp` — privilege-free TCP connect port scan (works without admin/root)
  - `all` — runs ARP and ICMP, degrading gracefully if either needs privileges; if nothing is found, falls back to a TCP scan of common ports
- **Flexible targets**: single IP, CIDR (`192.168.1.0/24`), hyphen ranges (`192.168.1.1-50`), hostnames, and comma-separated combinations
- **MAC vendor lookup** from a built-in OUI database (plus custom `--vendor-db` support)
- **Output formats**: aligned table, JSON, or CSV, written to stdout or a file (`-o`)
- **Concurrency & tuning**: `--concurrency`, `--timeout`, `--retries`, `--iface`
- **Hostname resolution** for discovered devices (`--resolve`)
- **Structured error handling**: clear messages for bad targets, missing privileges, and missing drivers — never a raw traceback
- **Fully unit-tested** (66 tests, all network calls mocked), with CI across Python 3.9–3.13

## Installation

### Prerequisites

- **Python 3.8+**
- **Scapy**: `pip install scapy`
- **For `arp`/`ping` on Windows**: [Npcap](https://npcap.com/) (with "WinPcap API-compatible Mode") and an **administrator** shell. On Linux/macOS, `arp`/`ping` need **root** (or CAP_NET_RAW). `tcp` scans work everywhere with no special privileges.

### Install as a package (recommended)

```bash
git clone https://github.com/anishalx/net-scanner.git   # or your fork
cd netscanner
pip install -e .           # installs the `netscanner` command
```

### Or run straight from the repo (v1-style)

```bash
python netscanner.py -t 192.168.1.0/24
```

## Usage

```bash
netscanner -t <target> [options]
```

### Examples

```bash
# Discover devices on the local /24 (auto: ARP + ICMP + TCP fallback)
netscanner -t 192.168.1.0/24

# Classic ARP-only scan of the local segment (needs admin/root)
netscanner -t 192.168.1.0/24 -m arp

# ICMP sweep of a range
netscanner -t 192.168.1.1-192.168.1.50 -m ping

# Port scan a single host (no privileges needed)
netscanner -t 192.168.1.5 -m tcp -p 1-1000

# Port scan with a custom port list
netscanner -t 192.168.1.5 -m tcp -p 22,80,443,8000-9000

# Machine-readable output to a file
netscanner -t 192.168.1.0/24 -f json -o scan.json
netscanner -t 192.168.1.0/24 -f csv -o scan.csv

# Resolve hostnames and show MAC vendors
netscanner -t 192.168.1.0/24 -m arp --resolve

# Use a custom OUI vendor database (lines of "OUI,Vendor" or "OUI - Vendor")
netscanner -t 192.168.1.0/24 -m arp --vendor-db oui.csv

# Scan faster/slower by tuning concurrency and timeouts
netscanner -t 10.0.0.0/24 --concurrency 64 --timeout 1
```

### Example Output

```
IP Address    MAC Address       Vendor                  Hostname
-----------   ----------------  ---------------------   --------
192.168.1.1   aa:bb:cc:dd:ee:ff TP-Link
192.168.1.10  b8:27:eb:12:34:56 Raspberry Pi Foundation
192.168.1.20
```

### Options

```
-t, --target TARGET   IP, CIDR range, hyphen range, hostname, or comma list
-m, --method          arp | ping | tcp | all   (default: all)
-p, --ports PORTS     Ports for -m tcp: '22', '80,443', '1-1000'
-f, --format          table | json | csv       (default: table)
-o, --output FILE     Write results to a file
    --iface IFACE     Network interface for ARP/ping (e.g. eth0, Wi-Fi)
    --timeout SECS    Timeout per probe          (default: 2.0)
    --retries N       Probe retries              (default: 1)
    --concurrency N   Parallel probes            (default: 32)
    --resolve         Reverse-DNS hostnames (slower)
    --vendor-db FILE  Custom OUI vendor database
    --no-banner       Suppress the ASCII banner
-v, --verbose         Debug logging
    --version         Show version
```

Run `netscanner -h` for the full help text.

## Development

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"      # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest             # run the test suite
```

All tests mock network access, so they run anywhere — no root or Npcap needed.

## Operating Systems

- **Windows**: Command Prompt or PowerShell (Npcap + admin shell for ARP/ping).
- **macOS / Linux**: Any terminal (root or `CAP_NET_RAW` for ARP/ping).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `ARP scan failed ... winpcap is not installed` | Install [Npcap](https://npcap.com/) and run as administrator |
| `ICMP ping requires administrator/root privileges` | Run as root/admin, or use `-m tcp` |
| `No devices found` | Try `-m ping` or `-m tcp`; the auto `all` mode does this for you |
| `Invalid target(s)` | Use IPv4, e.g. `192.168.1.0/24`, `192.168.1.1-50`, or a resolvable hostname |
| Unknown MAC vendors | Provide a full IEEE OUI CSV via `--vendor-db` |

## Contributing

We welcome contributions! Please:

1. Fork the repository.
2. Create a branch (`git checkout -b feature/YourFeature`).
3. Make your changes and add tests under `tests/`.
4. Run `pytest` and push.
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Special thanks to [Scapy](https://scapy.readthedocs.io/en/latest/) for powering this tool.
- Inspired by various network scanning tools and the open-source community.
