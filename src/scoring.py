"""
Risk scoring engine — Thing 1: "Prioritise risks intelligently."

Design choice (see README Q1 / Q3): scoring is a deterministic,
auditable rubric over structured fields, NOT an LLM call. An LLM
asked to "rank these 114 vulnerabilities" will not reliably apply a
consistent weighting across all of them, and re-running it would not
guarantee the same order twice. A CISO briefing a Board in 48 hours
needs a ranking that is reproducible and that a security engineer can
challenge line by line ("why is this #3 and not #5?") — a formula
supports that; a black-box LLM judgment does not.

The LLM's job (see llm.py) is downstream of this: turning the top-5
rows this module produces into a fluent explanation and pulling the
right NIST control, not deciding the order.

Scoring formula
----------------
score = 100 * weighted_sum(factors), each factor normalized to [0,1]

Factors and weights (chosen to satisfy the assignment's explicit
requirement that ranking NOT be CVSS-driven):

  internet_exposure     0.20   asset + vuln both say internet-facing
  active_threat_intel   0.30   matched campaign; scaled up further for
                                confirmed ransomware association + high
                                confidence — this is the single
                                heaviest factor, because "an active
                                ransomware campaign is pointing at
                                this CVE right now" is exactly the
                                signal the MDR advisory says matters
                                most this week
  business_criticality  0.20   asset criticality + business service
                                impact/compliance scope/customer-facing
  exploit_availability  0.10   public/weaponized exploit exists
  compensating_controls 0.15   gaps: no EDR, no auth required, no
                                patch available, stale/unmonitored asset
  cvss_base             0.05   included, but deliberately small — this
                                is what stops a bare CVSS 10 on an
                                internal dev box from ever reaching #1
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

WEIGHTS = {
    "internet_exposure": 0.20,
    "active_threat_intel": 0.30,
    "business_criticality": 0.20,
    "exploit_availability": 0.10,
    "compensating_controls": 0.15,
    "cvss_base": 0.05,
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9


@dataclass
class RiskFactor:
    name: str
    weight: float
    raw_score: float  # 0..1
    reason: str


@dataclass
class ScoredRisk:
    vuln_id: str
    asset_id: str
    asset_name: str
    business_service: str
    cve: str
    vulnerability_name: str
    cvss: float
    severity: str
    total_score: float
    factors: list = field(default_factory=list)
    matched_campaigns: list = field(default_factory=list)  # list of dicts
    finding_type_hint: Optional[str] = None
    row: dict = field(default_factory=dict)  # raw joined row for downstream use
    also_affects: list = field(default_factory=list)  # other (asset_id, asset_name, vuln_id) sharing this CVE
    kev_listed: bool = False
    kev_ransomware: bool = False
    kev_due_date: Optional[str] = None

    def explanation(self) -> str:
        """Deterministic, template-based plain-English explanation.
        This is the guaranteed-to-exist explanation — the LLM (llm.py)
        is used to produce a more polished version, but if the LLM
        call fails, this is what ships instead of an empty field.
        """
        parts = []
        exposure = next(f for f in self.factors if f.name == "internet_exposure")
        ti = next(f for f in self.factors if f.name == "active_threat_intel")
        biz = next(f for f in self.factors if f.name == "business_criticality")
        comp = next(f for f in self.factors if f.name == "compensating_controls")

        if exposure.raw_score >= 0.9:
            parts.append(f"{self.asset_name} is internet-exposed")
        if ti.raw_score > 0 and self.matched_campaigns:
            camp = self.matched_campaigns[0]
            ransom = " (ransomware-associated)" if camp.get("ransomware_association") == "Yes" else ""
            kev_note = ", confirmed in the CISA KEV catalog" if self.kev_listed else ""
            parts.append(
                f"CVE {self.cve} is being actively exploited by {camp.get('threat_actor')}'s "
                f"\"{camp.get('campaign_name')}\" campaign{ransom} at {camp.get('confidence', 'unknown')} confidence{kev_note}"
            )
        elif self.kev_listed:
            ransom = " and is associated with known ransomware use" if self.kev_ransomware else ""
            parts.append(f"CVE {self.cve} is listed in the CISA Known Exploited Vulnerabilities catalog{ransom}")
        if biz.raw_score >= 0.7:
            parts.append(f"it sits on {self.business_service}, a business-critical service")
        if comp.raw_score >= 0.5:
            parts.append("compensating controls are weak or missing (" + comp.reason + ")")

        if not parts:
            parts.append(f"CVSS {self.cvss} on {self.asset_name}")

        sentence = "; ".join(parts) + "."
        return sentence[0].upper() + sentence[1:]


def _norm_yesno(val: str) -> float:
    return 1.0 if str(val).strip().lower() == "yes" else 0.0


def _score_internet_exposure(row: pd.Series) -> RiskFactor:
    asset_exposed = _norm_yesno(row.get("internet_exposed", "No"))
    vuln_exposure = 1.0 if str(row.get("asset_exposure", "")).strip().lower() == "internet" else 0.0
    raw = max(asset_exposed, vuln_exposure)
    reason = "internet-facing asset & vuln" if raw == 1.0 else "internal-only"
    return RiskFactor("internet_exposure", WEIGHTS["internet_exposure"], raw, reason)


def _score_threat_intel(row: pd.Series, campaigns: list) -> RiskFactor:
    kev_listed = bool(row.get("kev_listed", False))
    kev_ransomware = bool(row.get("kev_ransomware", False))

    if not campaigns and not kev_listed:
        return RiskFactor("active_threat_intel", WEIGHTS["active_threat_intel"], 0.0, "no matching campaign, not KEV-listed")

    # Take the strongest matching campaign for this CVE (threat_intelligence.csv).
    best = 0.0
    best_camp = campaigns[0] if campaigns else None
    for c in campaigns:
        conf = str(c.get("confidence", "")).lower()
        ransom = str(c.get("ransomware_association", "")).lower() == "yes"
        maturity = str(c.get("exploit_maturity", "")).lower()
        s = 0.5  # base for any match at all
        s += 0.2 if conf == "high" else (0.1 if conf == "medium" else 0.0)
        s += 0.2 if ransom else 0.0
        s += 0.1 if maturity == "weaponized" else 0.0
        s = min(s, 1.0)
        if s > best:
            best, best_camp = s, c

    # KEV listing independently confirms active exploitation even with
    # no threat_intelligence.csv match (closes the gap: a CVE that's
    # genuinely KEV-listed but simply wasn't in the provided threat-intel
    # file no longer scores as "no active exploitation").
    if kev_listed and not campaigns:
        best = 0.5 + (0.2 if kev_ransomware else 0.0)

    reason_bits = []
    if best_camp:
        reason_bits.append(f"{best_camp.get('threat_actor')} / {best_camp.get('campaign_name')}")
    if kev_listed:
        best = min(best + 0.15, 1.0)  # bonus for independent corroboration by both sources
        reason_bits.append("CISA KEV-listed" + (" (confirmed ransomware use)" if kev_ransomware else ""))
    elif campaigns:
        reason_bits.append("not in CISA KEV catalog")

    return RiskFactor("active_threat_intel", WEIGHTS["active_threat_intel"], best, "; ".join(reason_bits))


def _score_business_criticality(row: pd.Series) -> RiskFactor:
    crit_map = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
    crit = crit_map.get(str(row.get("criticality", "")).strip().lower(), 0.25)

    impact_map = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
    revenue = impact_map.get(str(row.get("revenue_impact", "")).strip().lower(), 0.25)

    customer_facing = _norm_yesno(row.get("customer_facing", "No")) * 0.15
    compliance = str(row.get("compliance_scope", "") or "")
    compliance_bonus = 0.1 if compliance.strip() not in ("", "nan") else 0.0

    raw = min(0.5 * crit + 0.35 * revenue + customer_facing + compliance_bonus, 1.0)
    reason_bits = [f"asset criticality={row.get('criticality')}", f"revenue impact={row.get('revenue_impact')}"]
    if customer_facing:
        reason_bits.append("customer-facing")
    if compliance_bonus:
        reason_bits.append(f"compliance scope: {compliance}")
    return RiskFactor("business_criticality", WEIGHTS["business_criticality"], raw, ", ".join(reason_bits))


def _score_exploit_availability(row: pd.Series) -> RiskFactor:
    raw = _norm_yesno(row.get("exploit_available", "No"))
    return RiskFactor(
        "exploit_availability", WEIGHTS["exploit_availability"], raw,
        "public exploit available" if raw else "no known public exploit",
    )


def _score_compensating_controls(row: pd.Series) -> RiskFactor:
    gaps = []
    score = 0.0
    if _norm_yesno(row.get("edr_installed", "Yes")) == 0.0:
        gaps.append("no EDR")
        score += 0.35
    if str(row.get("auth_required", "Yes")).strip().lower() == "no":
        gaps.append("no authentication required to exploit")
        score += 0.35
    if str(row.get("patch_available", "Yes")).strip().lower() == "no":
        gaps.append("no vendor patch yet available")
        score += 0.15
    try:
        last_seen = float(row.get("last_seen_days", 0) or 0)
    except (TypeError, ValueError):
        last_seen = 0
    if last_seen > 30:
        gaps.append(f"asset unseen for {int(last_seen)} days (possibly unmonitored/stale)")
        score += 0.15
    score = min(score, 1.0)
    return RiskFactor("compensating_controls", WEIGHTS["compensating_controls"], score, ", ".join(gaps) or "controls in place")


def _score_cvss(row: pd.Series) -> RiskFactor:
    try:
        cvss = float(row.get("cvss", 0) or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    raw = min(cvss / 10.0, 1.0)
    return RiskFactor("cvss_base", WEIGHTS["cvss_base"], raw, f"CVSS {cvss}")


def score_vulnerability(vuln_id: str, group: pd.DataFrame) -> ScoredRisk:
    """`group` = all joined rows for one vuln_id (1 row normally, >1 if
    multiple threat-intel campaigns matched the same CVE)."""
    row = group.iloc[0]

    campaigns = []
    seen = set()
    for _, r in group.iterrows():
        if pd.notna(r.get("threat_actor")) and str(r.get("threat_actor")) not in ("nan", ""):
            key = (r.get("threat_actor"), r.get("campaign_name"))
            if key not in seen:
                seen.add(key)
                campaigns.append(
                    {
                        "threat_actor": r.get("threat_actor"),
                        "campaign_name": r.get("campaign_name"),
                        "confidence": r.get("confidence"),
                        "ransomware_association": r.get("ransomware_association"),
                        "exploit_maturity": r.get("exploit_maturity"),
                        "target_region": r.get("target_region"),
                        "summary": r.get("summary"),
                    }
                )

    factors = [
        _score_internet_exposure(row),
        _score_threat_intel(row, campaigns),
        _score_business_criticality(row),
        _score_exploit_availability(row),
        _score_compensating_controls(row),
        _score_cvss(row),
    ]
    total = sum(f.weight * f.raw_score for f in factors) * 100

    return ScoredRisk(
        vuln_id=vuln_id,
        asset_id=row.get("asset_id"),
        asset_name=row.get("asset_name"),
        business_service=row.get("business_service"),
        cve=row.get("cve"),
        vulnerability_name=row.get("vulnerability_name"),
        cvss=float(row.get("cvss", 0) or 0),
        severity=row.get("severity"),
        total_score=round(total, 2),
        factors=factors,
        matched_campaigns=campaigns,
        finding_type_hint=row.get("vulnerability_name"),
        row=row.to_dict(),
        kev_listed=bool(row.get("kev_listed", False)),
        kev_ransomware=bool(row.get("kev_ransomware", False)),
        kev_due_date=row.get("kev_due_date") if pd.notna(row.get("kev_due_date")) else None,
    )


def rank_risks(joined: pd.DataFrame, top_n: int = 5, dedupe_by_cve: bool = True) -> list:
    """Score every open vulnerability, then rank.

    dedupe_by_cve: the same CVE often hits multiple near-identical
    assets (e.g. two VPN nodes behind the same LB). For a top-5 *risk*
    list meant for a Board briefing, five slots eaten by the same
    underlying flaw on twin boxes is less useful than five distinct
    risk stories. When True (default), we keep only the highest-scoring
    instance of each CVE and roll the other affected assets into
    `also_affects`, so nothing is silently dropped — it's visible, just
    not consuming a separate top-5 slot. Set False to see the raw,
    ungrouped per-asset ranking (e.g. for the eval/audit trail).
    """
    scored = [score_vulnerability(vid, grp) for vid, grp in joined.groupby("vuln_id")]
    scored.sort(key=lambda s: s.total_score, reverse=True)

    if not dedupe_by_cve:
        return scored[:top_n]

    best_by_cve: dict = {}
    for s in scored:
        key = s.cve
        if key not in best_by_cve:
            best_by_cve[key] = s
        else:
            best_by_cve[key].also_affects.append(
                {"asset_id": s.asset_id, "asset_name": s.asset_name, "vuln_id": s.vuln_id, "business_service": s.business_service}
            )

    deduped = sorted(best_by_cve.values(), key=lambda s: s.total_score, reverse=True)
    return deduped[:top_n]


if __name__ == "__main__":
    from ingest import load_data_pack

    pack = load_data_pack()
    top5 = rank_risks(pack.joined, top_n=5)
    for i, r in enumerate(top5, 1):
        print(f"\n#{i}  score={r.total_score}  {r.cve}  {r.asset_name}  ({r.business_service})")
        if r.also_affects:
            print(f"    also affects: {[a['asset_name'] for a in r.also_affects]}")
        print(f"    {r.explanation()}")
        for f in r.factors:
            print(f"      - {f.name}: {f.raw_score:.2f} x {f.weight} = {f.raw_score*f.weight*100:.1f}  ({f.reason})")
