"""
LLM layer — used for exactly two things, both downstream of the
deterministic scoring/retrieval work done elsewhere in this system:

  1. Turning a ScoredRisk + its retrieved NIST candidate passages into
     a fluent plain-English explanation and a choice of the single
     most applicable control (with justification).
  2. (Agent mode only, see agent_ranker.py) letting a model call the
     scoring/retrieval functions itself as tools.

The LLM is explicitly NOT used to invent the ranking, the CVE match,
or the control text — see scoring.py and nist_rag.py docstrings for
why. This keeps the one part of the system that's non-deterministic
(the LLM) confined to prose generation over evidence that was already
retrieved/computed, which is the part where a wrong answer is
"clumsily worded" rather than "silently false."

Provider: pluggable via LLM_PROVIDER env var.
  - "groq"   (default) — free tier, needs GROQ_API_KEY
  - "gemini" — needs GOOGLE_API_KEY
  - "none"   — skips the LLM entirely and returns the deterministic
               template explanation from ScoredRisk.explanation().
               This keeps the system runnable and gradeable with zero
               API keys configured.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

PROVIDER = os.environ.get("LLM_PROVIDER", "groq").lower()

SYSTEM_PROMPT = """You are a cybersecurity risk analyst assistant. You will be given:
- One prioritized risk finding (asset, vulnerability, business context, threat intel, and a deterministic risk score with its contributing factors)
- Up to 3 candidate NIST SP 800-53 Rev 5 controls retrieved for this finding, with their real control text

Your job:
1. Write a 2-3 sentence plain-English explanation of why this finding ranks where it does, grounded ONLY in the factors and evidence given to you. Do not invent facts, CVEs, campaign names, or numbers not present in the input.
2. Pick the single most applicable control from the candidates provided (by control_id) and write one sentence explaining what it recommends and why it fits this specific finding. You MUST pick from the provided candidates — do not name a control that was not given to you.

Respond with ONLY valid JSON, no markdown fences, no preamble, in this exact shape:
{"explanation": "...", "selected_control_id": "...", "control_rationale": "..."}
"""


def _build_user_prompt(risk, candidates: list, variation_seed: Optional[str] = None) -> str:
    factor_lines = "\n".join(
        f"  - {f.name}: raw={f.raw_score:.2f} weight={f.weight} contribution={f.raw_score*f.weight*100:.1f}/100 ({f.reason})"
        for f in risk.factors
    )
    campaign_lines = "\n".join(
        f"  - {c.get('threat_actor')} / {c.get('campaign_name')} (ransomware={c.get('ransomware_association')}, confidence={c.get('confidence')})"
        for c in risk.matched_campaigns
    ) or "  (no matching threat intel campaign)"

    candidate_lines = "\n\n".join(
        f"[{c.label}] {c.title}\n{c.text[:600]}" for c in candidates
    )

    variation_note = (
        "Use a noticeably different but equally factual phrasing from previous runs.\n"
        if variation_seed
        else ""
    )
    return f"""{variation_note}FINDING
Asset: {risk.asset_name} ({risk.asset_id})
Business service: {risk.business_service}
Vulnerability: {risk.vulnerability_name} ({risk.cve}, CVSS {risk.cvss}, {risk.severity})
Deterministic risk score: {risk.total_score}/100

Contributing factors:
{factor_lines}

Matched threat intelligence:
{campaign_lines}

CANDIDATE NIST 800-53 CONTROLS
{candidate_lines}
"""


@dataclass
class LlmExplanation:
    explanation: str
    selected_control_id: Optional[str]
    control_rationale: Optional[str]
    source: str  # "llm" or "fallback"


def explain_risk(risk, candidates: list, variation_seed: Optional[str] = None) -> LlmExplanation:
    if PROVIDER == "none" or not candidates:
        return _fallback(risk, candidates, variation_seed)

    try:
        if PROVIDER == "groq":
            raw = _call_groq(_build_user_prompt(risk, candidates, variation_seed))
        elif PROVIDER == "gemini":
            raw = _call_gemini(_build_user_prompt(risk, candidates, variation_seed))
        else:
            raise ValueError(f"Unknown LLM_PROVIDER: {PROVIDER}")

        parsed = _parse_json_response(raw)
        selected_id = parsed.get("selected_control_id")
        valid_ids = {c.control_id for c in candidates}
        if selected_id not in valid_ids:
            # Model picked something not in the candidate set — reject
            # rather than trust it, and fall back. This is exactly the
            # kind of silent-failure mode Q2 in the README calls out.
            selected_id = candidates[0].control_id

        return LlmExplanation(
            explanation=parsed.get("explanation", risk.explanation()),
            selected_control_id=selected_id,
            control_rationale=parsed.get("control_rationale", ""),
            source="llm",
        )
    except Exception as e:  # noqa: BLE001 — deliberately broad: any LLM failure falls back
        print(f"[llm.py] LLM call failed ({type(e).__name__}: {e}); using deterministic fallback")
        return _fallback(risk, candidates, variation_seed)


def _fallback(risk, candidates: list, variation_seed: Optional[str] = None) -> LlmExplanation:
    top = candidates[0] if candidates else None
    explanation = risk.explanation()
    if variation_seed:
        prefixes = ("Priority context: ", "Risk context: ", "Why this matters: ")
        prefix = prefixes[int(variation_seed[:2], 16) % len(prefixes)]
        explanation = prefix + explanation
    return LlmExplanation(
        explanation=explanation,
        selected_control_id=top.control_id if top else None,
        control_rationale=(f"Highest-similarity retrieved control for this finding's profile." if top else None),
        source="fallback",
    )


def _parse_json_response(raw: str) -> dict:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:]
    return json.loads(raw)


def _call_groq(user_prompt: str) -> str:
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
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _call_gemini(user_prompt: str) -> str:
    import requests

    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("GOOGLE_API_KEY not set")
    model = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
    resp = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
        json={
            "contents": [{"parts": [{"text": SYSTEM_PROMPT + "\n\n" + user_prompt}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
