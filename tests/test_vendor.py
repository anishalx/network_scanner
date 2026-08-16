import pytest

from netscanner.vendor import load_vendor_db, lookup_vendor, normalize_oui


def test_lookup_raspberry_pi():
    assert lookup_vendor("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"


def test_lookup_case_insensitive_and_separators():
    assert lookup_vendor("B8-27-EB-00-00-00") == "Raspberry Pi Foundation"
    assert lookup_vendor("B827EB000000") == "Raspberry Pi Foundation"


def test_lookup_unknown():
    assert lookup_vendor("de:ad:be:ef:00:01") is None


def test_lookup_invalid_input():
    assert lookup_vendor("") is None
    assert lookup_vendor("zz") is None
    assert lookup_vendor(None) is None


def test_lookup_custom_db():
    db = {"001122": "Custom Vendor"}
    assert lookup_vendor("00:11:22:33:44:55", db) == "Custom Vendor"
    assert lookup_vendor("b8:27:eb:00:00:00", db) is None


def test_normalize_oui():
    assert normalize_oui("b8:27:eb:12:34:56") == "B827EB"


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
    assert "001122" in table


def test_load_vendor_db_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_vendor_db(str(tmp_path / "nope.csv"))
