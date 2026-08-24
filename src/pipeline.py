"""
Wires the whole system together: Thing 1 (rank) -> Thing 2 (retrieve
NIST guidance) -> LLM explanation -> Thing 3 (readable structured
output). This is what app.py calls.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Optional

from ingest import DataPack, load_data_pack
from scoring import ScoredRisk, rank_risks
from nist_rag import NistRetriever, build_query_for_risk
from llm import explain_risk
from tracing import RunTrace

RANKING_MODE = os.environ.get("RANKING_MODE", "deterministic").lower()  # deterministic | agentic


@dataclass
class RiskReportEntry:
    rank: int
    vuln_id: str
    asset: str
    business_service: str
    cve: str
    vulnerability_name: str
    cvss: float
    severity: str
    risk_score: float
    also_affects: list
    matched_threat_intel: list
    explanation: str
    nist_control_id: Optional[str]
    nist_control_title: Optional[str]
    nist_control_rationale: Optional[str]
    nist_control_text: Optional[str]
    explanation_source: str  # "llm" or "fallback"
    ranking_note: Optional[str] = None  # only set in agentic mode


def generate_report(
    top_n: int = 5,
    data_dir: Optional[str] = None,
    refresh_nonce: Optional[str] = None,
) -> list:
    trace = RunTrace("generate_report")

    with trace.step("ingest", top_n=top_n) as s:
        pack: DataPack = load_data_pack(data_dir) if data_dir else load_data_pack()
        s.meta["open_vulnerabilities"] = int(len(pack.joined["vuln_id"].unique()))
        s.meta["kev_available"] = pack.kev_available

    ranking_note_by_risk = {}
    with trace.step("rank", mode=RANKING_MODE) as s:
        if RANKING_MODE == "agentic":
            from agent_ranker import agentic_rank

            pairs = agentic_rank(pack.joined, top_n=top_n)
            top_risks = [r for r, _ in pairs]
            ranking_note_by_risk = {r.vuln_id: note for r, note in pairs}
        else:
            top_risks = rank_risks(pack.joined, top_n=top_n)
        s.meta["ranked_vuln_ids"] = [r.vuln_id for r in top_risks]
        s.meta["scores"] = [r.total_score for r in top_risks]

    with trace.step("load_nist_index") as s:
        try:
            retriever = NistRetriever()
            s.meta["backend"] = retriever.backend
            s.meta["passage_count"] = len(retriever.passages)
        except FileNotFoundError as e:
            print(f"[pipeline.py] {e}")
            retriever = None
            s.meta["error"] = str(e)

    entries = []
    for i, risk in enumerate(top_risks, 1):
        with trace.step(f"explain_finding_{i}", vuln_id=risk.vuln_id, cve=risk.cve) as s:
            candidates = retriever.search(build_query_for_risk(risk), top_k=3) if retriever else []
            llm_out = explain_risk(risk, candidates, variation_seed=refresh_nonce)
            s.meta["retrieved_controls"] = [c.control_id for c in candidates]
            s.meta["selected_control"] = llm_out.selected_control_id
            s.meta["explanation_source"] = llm_out.source

            selected = next((c for c in candidates if c.control_id == llm_out.selected_control_id), None)

            entries.append(
                RiskReportEntry(
                    rank=i,
                    vuln_id=risk.vuln_id,
                    asset=risk.asset_name,
                    business_service=risk.business_service,
                    cve=risk.cve,
                    vulnerability_name=risk.vulnerability_name,
                    cvss=risk.cvss,
                    severity=risk.severity,
                    risk_score=risk.total_score,
                    also_affects=risk.also_affects,
                    matched_threat_intel=risk.matched_campaigns,
                    explanation=llm_out.explanation,
                    nist_control_id=selected.label if selected else llm_out.selected_control_id,
                    nist_control_title=selected.title if selected else None,
                    nist_control_rationale=llm_out.control_rationale,
                    nist_control_text=(selected.text[:800] if selected else None),
                    explanation_source=llm_out.source,
                    ranking_note=ranking_note_by_risk.get(risk.vuln_id),
                )
            )

    run_id = trace.finish(summary={"top_5_cves": [e.cve for e in entries], "kev_available": pack.kev_available})
    print(f"[pipeline.py] run {run_id} — trace written to data/traces/{run_id}.json")
    return entries


def report_to_dicts(entries: list) -> list:
    return [asdict(e) for e in entries]


if __name__ == "__main__":
    entries = generate_report(top_n=5)
    for e in entries:
        print(f"\n{'='*70}\n#{e.rank}  [{e.risk_score}/100]  {e.cve} — {e.asset}  ({e.business_service})")
        if e.also_affects:
            print(f"Also affects: {', '.join(a['asset_name'] for a in e.also_affects)}")
        print(f"\n{e.explanation}")
        print(f"\nRecommended control: {e.nist_control_id} — {e.nist_control_title}")
        print(f"{e.nist_control_rationale}")
