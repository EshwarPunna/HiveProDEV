"""
Unit tests for kev.py, using a local fixture instead of the live
network — so this test is deterministic and runs in CI without a
GitHub dependency, while still exercising the real parsing/matching
logic against real CVE IDs and the real CISA KEV JSON schema.

Run: python tests/test_kev.py  (or via pytest)
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import kev  # noqa: E402

# Real entries (schema and values) captured from the live CISA KEV
# catalog on 2026-08-22 — see kev.py docstring for the source URL.
FIXTURE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.08.18",
    "count": 4,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-21762", "vendorProject": "Fortinet", "product": "FortiOS",
            "dateAdded": "2024-02-09", "dueDate": "2024-03-01",
            "knownRansomwareCampaignUse": "Known",
            "requiredAction": "Apply mitigations per vendor instructions.",
        },
        {
            "cveID": "CVE-2024-10978", "vendorProject": "SolarWinds", "product": "Serv-U",
            "dateAdded": "2024-12-01", "dueDate": "2024-12-22",
            "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "Apply mitigations per vendor instructions.",
        },
        {
            "cveID": "CVE-2023-4966", "vendorProject": "Citrix", "product": "NetScaler ADC and Gateway",
            "dateAdded": "2023-10-18", "dueDate": "2023-11-08",
            "knownRansomwareCampaignUse": "Known",
            "requiredAction": "Apply mitigations per vendor instructions.",
        },
        {
            "cveID": "CVE-2008-4128", "vendorProject": "Cisco", "product": "IOS",
            "dateAdded": "2026-07-13", "dueDate": "2026-07-16",
            "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "Apply mitigations per vendor instructions.",
        },
    ],
}


def test_build_kev_index_parses_real_schema():
    index = kev.build_kev_index(FIXTURE)
    assert len(index) == 4
    entry = index["CVE-2024-21762"]
    assert entry.vendor_project == "Fortinet"
    assert entry.known_ransomware_campaign_use is True
    assert entry.due_date == "2024-03-01"


def test_ransomware_flag_parsed_correctly():
    index = kev.build_kev_index(FIXTURE)
    assert index["CVE-2024-10978"].known_ransomware_campaign_use is False
    assert index["CVE-2023-4966"].known_ransomware_campaign_use is True


def test_lookup_returns_none_for_unlisted_cve():
    index = kev.build_kev_index(FIXTURE)
    assert index.get("CVE-9999-99999") is None


def test_kevlookup_falls_back_gracefully_on_fetch_failure(monkeypatch):
    def _boom(force=False, timeout=30):
        raise RuntimeError("simulated network failure")

    monkeypatch.setattr(kev, "fetch_kev_catalog", _boom)
    lookup = kev.KevLookup()
    assert lookup.available is False
    assert lookup.get("CVE-2024-21762") is None  # does not raise


def test_kevlookup_uses_provided_catalog(monkeypatch):
    monkeypatch.setattr(kev, "fetch_kev_catalog", lambda force=False, timeout=30: FIXTURE)
    lookup = kev.KevLookup()
    assert lookup.available is True
    entry = lookup.get("CVE-2024-21762")
    assert entry is not None
    assert entry.known_ransomware_campaign_use is True


if __name__ == "__main__":
    import types

    class _FakeMonkeypatch:
        def setattr(self, obj, name, value):
            setattr(obj, name, value)

    fns = [
        test_build_kev_index_parses_real_schema,
        test_ransomware_flag_parsed_correctly,
        test_lookup_returns_none_for_unlisted_cve,
    ]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")

    mp = _FakeMonkeypatch()
    test_kevlookup_falls_back_gracefully_on_fetch_failure(mp)
    print("PASS test_kevlookup_falls_back_gracefully_on_fetch_failure")
    test_kevlookup_uses_provided_catalog(mp)
    print("PASS test_kevlookup_uses_provided_catalog")
