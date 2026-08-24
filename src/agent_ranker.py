"""
Agentic ranking mode (opt-in, RANKING_MODE=agentic).

The assignment's default and recommended mode is scoring.rank_risks()
— a deterministic rubric (see scoring.py for why). This module exists
because the take-home also asked which of three designs is most
"efficient": pure deterministic, LLM-driven ranking, or a hybrid. This
implements the LLM-driven option so all three actually exist in the
codebase and can be compared, rather than just described.

How it works: we don't let the LLM rank all 114 vulnerabilities from
scratch (expensive, and nothing constrains it to stay grounded in the
data across that many rows). Instead we hand it the top-15 candidates
by deterministic score — a pre-filtered, evidence-rich shortlist — and
ask it to independently choose and order its own top 5 from within
that set, with reasoning, in structured JSON. This is a real
agentic/LLM-reasoning step (it can and sometimes does reorder relative
to the deterministic score), but it can't promote a vulnerability the
deterministic pass never surfaced as plausible, which bounds the
damage a bad LLM call can do.

Compare this file's output against scoring.rank_risks() for the same
data — see README Q2/Q3 for what we observed when we did.
"""
from __future__ import annotations

import json
import os

from llm import PROVIDER, _call_gemini, _parse_json_response  # reuse provider plumbing
from scoring import rank_risks

AGENT_SYSTEM_PROMPT = """You are a senior cybersecurity risk analyst. You are given a shortlist of \
candidate vulnerability findings, each with a deterministic risk score and its contributing factors \
(internet exposure, active threat-intel/campaign match, business criticality, exploit availability, \
compensating control gaps, CVSS). Independently select and rank the TOP 5 as the risks you would brief \
to the Board in the next 48 hours, using your own judgement about severity, exploitability, business \
impact, and active threats — you do not have to match the deterministic order, but you must only choose \
from the candidates given, and every ranking decision must be justified by fields present in the input, \
not invented.

Respond with ONLY valid JSON: {"ranking": [{"vuln_id": "...", "rank": 1, "justification": "..."}, ...]} \
with exactly 5 entries, rank 1 = highest priority.
"""


def _candidate_summary(risk) -> dict:
    return {
        "vuln_id": risk.vuln_id,
        "cve": risk.cve,
        "asset": risk.asset_name,
        "business_service": risk.business_service,
        "cvss": risk.cvss,
        "deterministic_score": risk.total_score,
        "factors": {f.name: {"raw": round(f.raw_score, 2), "reason": f.reason} for f in risk.factors},
        "matched_campaigns": [
            {"actor": c["threat_actor"], "campaign": c["campaign_name"], "ransomware": c["ransomware_association"], "confidence": c["confidence"]}
            for c in risk.matched_campaigns
        ],
    }


def agentic_rank(joined, top_n: int = 5, shortlist_size: int = 15):
    shortlist = rank_risks(joined, top_n=shortlist_size)
    by_id = {r.vuln_id: r for r in shortlist}

    prompt = json.dumps([_candidate_summary(r) for r in shortlist], indent=2)

    if PROVIDER == "none":
        # No LLM configured — agentic mode degrades to the deterministic
        # shortlist order, clearly labeled, rather than failing.
        return [(r, "no LLM provider configured — deterministic order used") for r in shortlist[:top_n]]

    try:
        if PROVIDER == "groq":
            raw = _call_groq_agent(prompt)
        elif PROVIDER == "gemini":
            raw = _call_gemini(AGENT_SYSTEM_PROMPT + "\n\nCANDIDATES:\n" + prompt)
        else:
            raise ValueError(f"Unknown provider {PROVIDER}")
        parsed = _parse_json_response(raw)
        ranking = sorted(parsed["ranking"], key=lambda r: r["rank"])[:top_n]
        out = []
        for entry in ranking:
            risk = by_id.get(entry["vuln_id"])
            if risk is None:
                continue  # LLM referenced a vuln_id outside the candidate set — drop it, don't trust it
            out.append((risk, entry.get("justification", "")))
        if len(out) < top_n:
            # Backfill from deterministic order if the LLM returned fewer
            # than 5 valid, in-set entries.
            used = {r.vuln_id for r, _ in out}
            for r in shortlist:
                if r.vuln_id not in used:
                    out.append((r, "backfilled — LLM ranking omitted or invalidated this slot"))
                if len(out) >= top_n:
                    break
        return out
    except Exception as e:  # noqa: BLE001
        print(f"[agent_ranker.py] agentic ranking failed ({type(e).__name__}: {e}); falling back to deterministic order")
        return [(r, "agentic ranking failed — deterministic order used") for r in shortlist[:top_n]]


def _call_groq_agent(candidates_json: str) -> str:
    import requests

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY not set")
    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b"),
            "messages": [
                {"role": "system", "content": AGENT_SYSTEM_PROMPT},
                {"role": "user", "content": "CANDIDATES:\n" + candidates_json},
            ],
            "temperature": 0.3,
            "response_format": {"type": "json_object"},
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]
