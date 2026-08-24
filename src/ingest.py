"""
Ingestion layer for TawasolPay Cyber Risk Assistant.

Loads the structured data pack (assets, vulnerabilities, threat intel,
business services, remediation hints) and the free-text MDR advisory,
and produces a single denormalized DataFrame: one row per open
vulnerability, joined with its asset, business service, and any
matching threat-intel record(s).

This is the "structured records" half of the system's data split
(see README, Supporting Question 1). Nothing here touches an LLM or
an embedding model — it's plain pandas joins and filters, because the
underlying data is already structured and precise. An LLM adds
nothing here except latency and a chance to hallucinate a number.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


@dataclass
class DataPack:
    assets: pd.DataFrame
    vulnerabilities: pd.DataFrame
    threat_intel: pd.DataFrame
    business_services: pd.DataFrame
    remediation_hints: pd.DataFrame
    threat_report_text: str
    joined: pd.DataFrame
    kev_available: bool = False


def load_data_pack(data_dir: str = DATA_DIR, use_kev: bool = True) -> DataPack:
    """use_kev=True (default): cross-references vulnerabilities.csv
    against the live CISA KEV catalog (see kev.py) as a second,
    independent confirmation of active exploitation, alongside
    threat_intelligence.csv. Set False to skip the network call
    (e.g. offline dev) — the pipeline still runs correctly, just
    without KEV corroboration.
    """
    assets = pd.read_csv(os.path.join(data_dir, "assets.csv"))
    vulnerabilities = pd.read_csv(os.path.join(data_dir, "vulnerabilities.csv"))
    threat_intel = pd.read_csv(os.path.join(data_dir, "threat_intelligence.csv"))
    business_services = pd.read_csv(os.path.join(data_dir, "business_services.csv"))
    remediation_hints = pd.read_csv(os.path.join(data_dir, "remediation_guidance.csv"))

    report_path = os.path.join(data_dir, "synthetic_threat_report.md")
    threat_report_text = ""
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            threat_report_text = f.read()

    # Light normalization — strip whitespace, standardize Yes/No casing.
    for df in (assets, vulnerabilities, threat_intel, business_services):
        for col in df.columns[df.dtypes == object]:
            df[col] = df[col].astype(str).str.strip()

    kev_lookup, kev_available = None, False
    if use_kev:
        try:
            from kev import KevLookup

            kev_lookup = KevLookup()
            kev_available = kev_lookup.available
        except Exception as e:  # noqa: BLE001
            print(f"[ingest.py] KEV lookup unavailable ({type(e).__name__}: {e}); continuing without it.")

    joined = build_joined_view(assets, vulnerabilities, threat_intel, business_services, kev_lookup=kev_lookup)

    return DataPack(
        assets=assets,
        vulnerabilities=vulnerabilities,
        threat_intel=threat_intel,
        business_services=business_services,
        remediation_hints=remediation_hints,
        threat_report_text=threat_report_text,
        joined=joined,
        kev_available=kev_available,
    )


def build_joined_view(
    assets: pd.DataFrame,
    vulnerabilities: pd.DataFrame,
    threat_intel: pd.DataFrame,
    business_services: pd.DataFrame,
    kev_lookup=None,
) -> pd.DataFrame:
    """One row per (open) vulnerability, enriched with asset, business
    service, and threat-intel context. Threat intel is left-joined and
    may produce multiple rows per vuln if more than one campaign
    targets the same CVE (e.g. CrimsonJackal's two-CVE Gateway
    Breaker campaign) — callers should group back to vuln_id when
    scoring so a vuln isn't double-counted, but can inspect all
    matched campaigns for the explanation text.

    kev_lookup (optional): a kev.KevLookup instance. When provided,
    two columns are added independently of threat_intelligence.csv:
    `kev_listed` and `kev_ransomware`. This is deliberately a *second*,
    independent evidence source (see kev.py's docstring) — a CVE can
    be threat-intel-matched, KEV-listed, both, or neither, and scoring
    treats "confirmed by two independent sources" as stronger evidence
    than either alone.
    """
    open_vulns = vulnerabilities[vulnerabilities["status"].str.lower() == "open"].copy()

    df = open_vulns.merge(assets, on="asset_id", how="left", suffixes=("", "_asset"))
    df = df.merge(business_services, on="business_service", how="left", suffixes=("", "_biz"))

    ti = threat_intel.rename(columns={"matched_cve_or_control": "cve"})
    df = df.merge(
        ti[
            [
                "cve",
                "threat_actor",
                "campaign_name",
                "target_region",
                "target_sector",
                "exploit_maturity",
                "active_last_seen",
                "ransomware_association",
                "confidence",
                "summary",
            ]
        ],
        on="cve",
        how="left",
        suffixes=("", "_ti"),
    )

    if kev_lookup is not None:
        df["kev_listed"] = df["cve"].apply(lambda c: kev_lookup.get(c) is not None)
        df["kev_ransomware"] = df["cve"].apply(
            lambda c: bool(e.known_ransomware_campaign_use) if (e := kev_lookup.get(c)) else False
        )
        df["kev_due_date"] = df["cve"].apply(lambda c: (e.due_date if (e := kev_lookup.get(c)) else None))
    else:
        df["kev_listed"] = False
        df["kev_ransomware"] = False
        df["kev_due_date"] = None

    return df


if __name__ == "__main__":
    pack = load_data_pack()
    print(f"Assets: {len(pack.assets)}")
    print(f"Open vulnerabilities: {(pack.vulnerabilities['status'].str.lower() == 'open').sum()} / {len(pack.vulnerabilities)}")
    print(f"Threat intel records: {len(pack.threat_intel)}")
    print(f"Business services: {len(pack.business_services)}")
    print(f"Joined view rows: {len(pack.joined)}")
    print(f"Joined rows with a threat-intel match: {pack.joined['threat_actor'].notna().sum()}")
