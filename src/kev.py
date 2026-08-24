"""
CISA Known Exploited Vulnerabilities (KEV) catalog — required Type 2
retrieval source per the assignment brief, alongside NIST SP 800-53.

Earlier version of this system treated the KEV cross-check as a
documented-but-unfixed gap ("if a CVE isn't in threat_intelligence.csv,
we won't flag it as actively exploited even if it is"). This module
closes that gap: it downloads the real, live KEV catalog independently
of threat_intelligence.csv, so a CVE gets flagged as actively exploited
if *either* source confirms it — and the two sources cross-verify each
other rather than one silently standing in for both.

Source (verified working, confirmed against the assignment's own
citation of https://github.com/cisagov/kev-data):
    https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json

Schema (real, as published by CISA): each entry has cveID,
vendorProject, product, dateAdded, requiredAction, dueDate,
knownRansomwareCampaignUse ("Known" | "Unknown"), notes, cwes.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

import requests

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(HERE), "data")
CACHE_PATH = os.path.join(DATA_DIR, "kev_catalog_cache.json")


@dataclass
class KevEntry:
    cve_id: str
    vendor_project: str
    product: str
    date_added: str
    due_date: str
    known_ransomware_campaign_use: bool  # True iff CISA's field == "Known"
    required_action: str


def fetch_kev_catalog(force: bool = False, timeout: int = 30) -> dict:
    """Downloads (or loads cached) KEV catalog. Cache avoids hitting
    GitHub on every process start; delete data/kev_catalog_cache.json
    or pass force=True to refresh."""
    if os.path.exists(CACHE_PATH) and not force:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    resp = requests.get(KEV_URL, timeout=timeout)
    resp.raise_for_status()
    catalog = resp.json()

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(catalog, f)
    return catalog


def build_kev_index(catalog: Optional[dict] = None) -> dict:
    """Returns {cve_id: KevEntry} for O(1) lookup during scoring."""
    if catalog is None:
        catalog = fetch_kev_catalog()
    index: dict = {}
    for v in catalog.get("vulnerabilities", []):
        index[v["cveID"]] = KevEntry(
            cve_id=v["cveID"],
            vendor_project=v.get("vendorProject", ""),
            product=v.get("product", ""),
            date_added=v.get("dateAdded", ""),
            due_date=v.get("dueDate", ""),
            known_ransomware_campaign_use=(v.get("knownRansomwareCampaignUse", "Unknown") == "Known"),
            required_action=v.get("requiredAction", ""),
        )
    return index


class KevLookup:
    """Thin wrapper so callers (scoring.py) don't need to know about
    caching/fetching — just `KevLookup().get(cve_id)`. Falls back to
    an empty index (never crashes the pipeline) if KEV is unreachable,
    logging why, since flaw-remediation-catalog uptime shouldn't be a
    single point of failure for the whole risk briefing."""

    def __init__(self):
        try:
            self._index = build_kev_index()
            self.available = True
        except Exception as e:  # noqa: BLE001
            print(f"[kev.py] Could not load CISA KEV catalog ({type(e).__name__}: {e}); "
                  f"KEV cross-check disabled for this run, falling back to threat_intelligence.csv only.")
            self._index = {}
            self.available = False

    def get(self, cve_id: str) -> Optional[KevEntry]:
        return self._index.get(cve_id)


if __name__ == "__main__":
    lookup = KevLookup()
    print(f"KEV catalog loaded: {lookup.available}, {len(lookup._index)} entries")

    import pandas as pd

    vulns = pd.read_csv(os.path.join(DATA_DIR, "vulnerabilities.csv"))
    matched, ransomware = 0, 0
    for cve in vulns["cve"]:
        entry = lookup.get(cve)
        if entry:
            matched += 1
            if entry.known_ransomware_campaign_use:
                ransomware += 1
    print(f"{matched}/{len(vulns)} CVEs in vulnerabilities.csv are real KEV-listed entries")
    print(f"{ransomware}/{matched} of those are KEV-confirmed ransomware-associated")
