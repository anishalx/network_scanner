import os

import pytest

from netscanner.vendor import (
    OUI_CSV_GZ,
    load_ieee_oui_db,
    load_vendor_db,
    lookup_vendor,
    normalize_oui,
)


# --- curated table ---


def test_lookup_raspberry_pi():
    assert lookup_vendor("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"


def test_lookup_case_insensitive_and_separators():
    assert lookup_vendor("B8-27-EB-00-00-00") == "Raspberry Pi Foundation"
    assert lookup_vendor("B827EB000000") == "Raspberry Pi Foundation"


def test_lookup_invalid_input():
    assert lookup_vendor("") is None
    assert lookup_vendor("zz") is None
    assert lookup_vendor(None) is None


# --- full IEEE database (bundled oui.csv.gz) ---


def test_bundled_db_file_exists():
    assert os.path.exists(OUI_CSV_GZ)
    assert os.path.getsize(OUI_CSV_GZ) > 100_000


def test_ieee_db_contains_major_vendors():
    table = load_ieee_oui_db()
    assert len(table) > 10_000
    assert table["000000"] == "XEROX CORPORATION"
    assert table["00000C"] == "Cisco Systems, Inc"
    assert table["B827EB"].lower() == "raspberry pi foundation"
    assert table["286FB9"] == "Nokia Shanghai Bell Co., Ltd."


def test_lookup_full_ieee_db_fallback():
    # 28:6F:B9 is in the bundled IEEE database but not the curated table.
    vendor = lookup_vendor("28:6f:b9:12:34:56")
    assert vendor == load_ieee_oui_db()["286FB9"]


def test_lookup_unknown_oui_is_none():
    # DE:AD:BE:EF is not assigned in the full IEEE database either.
    assert lookup_vendor("de:ad:be:ef:00:01") is None
    assert lookup_vendor("ff:ff:ff:ff:ff:ff") is None


def test_lookup_custom_db_overrides_and_layers():
    db = {"001122": "Custom Vendor"}
    assert lookup_vendor("00:11:22:33:44:55", db) == "Custom Vendor"
    # Custom db is an override layer, not a replacement: known OUIs still resolve.
    assert lookup_vendor("b8:27:eb:00:00:00", db) == "Raspberry Pi Foundation"
    assert lookup_vendor("28:6f:b9:00:00:00", db) == load_ieee_oui_db()["286FB9"]


# --- parsing ---


def test_normalize_oui():
    assert normalize_oui("b8:27:eb:12:34:56") == "B827EB"


def test_load_ieee_oui_db_plain_csv(tmp_path):
    db_file = tmp_path / "oui.csv"
    db_file.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,001122,"Test, Inc.",Nowhere\n'
        "MA-L,00AABB,Other Co,Elsewhere\n"
        "garbage\n"
    )
    table = load_ieee_oui_db(str(db_file))
    assert table == {"001122": "Test, Inc.", "00AABB": "Other Co"}


def test_load_vendor_db(tmp_path):
    db_file = tmp_path / "oui.csv"
    db_file.write_text(
        "# comment line\n"
        "00:11:22,Test Vendor\n"
        "00 AA BB - Other Vendor\n"
        "garbage-line-without-separator\n"
    )
    table = load_vendor_db(str(db_file))
    assert table["001122"] == "Test Vendor"
    assert table["00AABB"] == "Other Vendor"


def test_load_vendor_db_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_vendor_db(str(tmp_path / "nope.csv"))
