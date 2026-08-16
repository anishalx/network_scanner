"""MAC address vendor (OUI) lookup.

The built-in table is a curated subset of common consumer, enterprise, and
virtualization vendors. For full coverage, download the IEEE OUI database
(https://standards.ieee.org/products-programs/regauth/oui/) and load it with
the --vendor-db option (lines of "OUI,Vendor" or "OUI - Vendor").
"""

from __future__ import annotations

import os
from typing import Dict, Optional

# 24-bit OUIs (6 hex chars, uppercase). Curated to high-confidence entries.
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


def normalize_oui(mac: str) -> str:
    """Extract the first 24 bits of a MAC as an uppercase hex string."""
    cleaned = "".join(ch for ch in mac if ch.isalnum()).upper()
    return cleaned[:6]


def lookup_vendor(mac: str, db: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Return the vendor for a MAC address, or None when unknown/invalid."""
    if not mac:
        return None
    oui = normalize_oui(mac)
    if len(oui) < 6:
        return None
    table = db if db is not None else BUILTIN_OUI
    return table.get(oui)


def load_vendor_db(path: str) -> Dict[str, str]:
    """Load OUI -> vendor mappings from a file.

    Accepts lines of "OUI,Vendor" or "OUI - Vendor"; '#' starts a comment.
    Returns only the entries parsed from the file (does not merge the builtin
    table - callers can merge with {**BUILTIN_OUI, **custom}).
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
