"""MAC address vendor (OUI) lookup.

Two-tier lookup:
  1. A small curated table of common vendors with friendly names (fast,
     checked first, so e.g. "Raspberry Pi Foundation" wins over IEEE's
     official legal name).
  2. The full IEEE MA-L OUI database, bundled as `data/oui.csv.gz` and
     loaded lazily on the first miss (~40k assignments, ~100 ms).

Refresh the bundled database with `python tools/update_oui_db.py`.
Source: https://standards.ieee.org/products-programs/regauth/oui/
"""

from __future__ import annotations

import csv
import gzip
import os
from functools import lru_cache
from typing import Dict, Optional

# 24-bit OUIs (6 hex chars, uppercase). Curated to high-confidence entries
# with friendly names that read better than IEEE legal names.
BUILTIN_OUI: Dict[str, str] = {
    # Networking hardware
    "00000C": "Cisco",
    "00156D": "Ubiquiti",
    "24A43C": "Ubiquiti",
    "488F5A": "MikroTik",
    "6C3B6B": "MikroTik",
    "50FA84": "TP-Link",
    "C04A00": "TP-Link",
    "001B11": "D-Link",
    "28107B": "D-Link",
    "204E7F": "Netgear",
    "A06391": "Netgear",
    "001BFC": "ASUSTek Computer",
    "485B39": "ASUSTek Computer",
    "3CD92B": "HP",
    "F8BC12": "Dell",
    "001422": "Dell",
    "0004AC": "IBM",
    "001018": "Broadcom",
    "00E04C": "Realtek Semiconductor",
    "0002B3": "Intel",
    "0013E8": "Intel",
    "001B21": "Intel",
    "3C970E": "Intel",
    # Consumer / IoT
    "001A11": "Google",
    "3C5AB4": "Google",
    "18B430": "Google/Nest",
    "74C246": "Amazon Technologies",
    "F0272D": "Amazon Technologies",
    "000393": "Apple",
    "000A27": "Apple",
    "001124": "Apple",
    "001CB3": "Apple",
    "3C0754": "Apple",
    "ACBC32": "Apple",
    "F01898": "Apple",
    "640980": "Xiaomi",
    "240AC4": "Espressif",
    "246F28": "Espressif",
    "30AEA4": "Espressif",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    "28CDC1": "Raspberry Pi Foundation",
    # Virtualization / hypervisors
    "005056": "VMware",
    "000569": "VMware",
    "000C29": "VMware",
    "00163E": "Xen",
    "525400": "QEMU/KVM",
    "080027": "VirtualBox",
    "00155D": "Microsoft Hyper-V",
    "0050F2": "Microsoft",
}

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
OUI_CSV_GZ = os.path.join(_DATA_DIR, "oui.csv.gz")


@lru_cache(maxsize=1)
def _ieee_oui_table() -> Dict[str, str]:
    """Lazily load the bundled IEEE MA-L database (thread-safe via lru_cache)."""
    return load_ieee_oui_db(OUI_CSV_GZ)


def normalize_oui(mac: str) -> str:
    """Extract the first 24 bits of a MAC as an uppercase hex string."""
    cleaned = "".join(ch for ch in mac if ch.isalnum()).upper()
    return cleaned[:6]


def lookup_vendor(mac: str, db: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Return the vendor for a MAC address, or None when unknown/invalid.

    Priority: custom db (if given) > curated friendly names > full IEEE OUI db.
    Never raises; returns None if the bundled database is unavailable.
    """
    if not mac:
        return None
    oui = normalize_oui(mac)
    if len(oui) < 6:
        return None
    if db and oui in db:
        return db[oui]
    if oui in BUILTIN_OUI:
        return BUILTIN_OUI[oui]
    try:
        return _ieee_oui_table().get(oui)
    except OSError:
        return None


def load_ieee_oui_db(path: Optional[str] = None) -> Dict[str, str]:
    """Parse an IEEE OUI CSV into {OUI (6 hex): organization name}.

    Accepts the raw CSV from standards-oui.ieee.org or a gzip-compressed copy
    (detected by the .gz extension). Skips the header row and malformed lines.
    """
    if path is None:
        path = OUI_CSV_GZ
    table: Dict[str, str] = {}
    if str(path).endswith(".gz"):
        opener = gzip.open
    else:
        opener = open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for row in csv.reader(fh):
            if not row or len(row) < 3:
                continue
            registry = row[0].strip()
            if not registry or registry.lower() == "registry":
                continue  # header row
            name = row[2].strip()
            oui = "".join(ch for ch in row[1] if ch.isalnum()).upper()
            if len(oui) >= 6 and name:
                table[oui[:6]] = name
    return table


def load_vendor_db(path: str) -> Dict[str, str]:
    """Load OUI -> vendor mappings from a file.

    Accepts lines of "OUI,Vendor" or "OUI - Vendor"; '#' starts a comment.
    Returns only the entries parsed from the file (does not merge with other
    tables - lookups layer custom entries over the built-in databases).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Vendor database not found: {path}")

    table: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "," in line:
                oui, vendor = line.split(",", 1)
            elif " - " in line:
                oui, vendor = line.split(" - ", 1)
            else:
                continue
            oui = "".join(ch for ch in oui if ch.isalnum()).upper()
            if len(oui) >= 6:
                table[oui[:6]] = vendor.strip()
    return table
