"""
Golden-set eval for the NIST retrieval step — NOT a unit test (it
needs the built index and, ideally, a real embedding model, so it's
kept separate from pytest's `test_*` files and run manually / in CI
as a distinct step). This is the "evaluation mindset" artifact the
JD asks for: a small labeled set of (query, expected control) pairs
representative of the finding types this system actually produces,
scored for retrieval accuracy so a change to the query builder,
the chunking strategy, or the embedding model can be checked for
regression before it ships.

Run: python tests/eval_nist_retrieval.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from nist_rag import NistRetriever

# Each case: a realistic risk-finding query (same shape build_query_for_risk
# produces) paired with the control we consider a correct top-3 hit.
# Grounded in the 5 controls the assignment itself names as most relevant.
GOLDEN_SET = [
    {
        "query": "Remote Access VPN Authentication Bypass CVE-2024-55591 active exploitation ransomware campaign internet-facing exposed system remote access",
        "expected_any": ["AC-17"],
        "note": "VPN remote-access finding should surface AC-17 (Remote Access)",
    },
    {
        "query": "Outdated software with known exploited CVE, no vendor patch available yet, flaw remediation overdue",
        "expected_any": ["SI-2", "SI-2(2)", "RA-5"],
        "note": "unpatched flaw should surface SI-2 (Flaw Remediation) or RA-5 (Vulnerability Monitoring)",
    },
    {
        "query": "Ransomware campaign incident containment lateral movement detection response",
        "expected_any": ["IR-4"],
        "note": "active ransomware campaign should surface IR-4 (Incident Handling)",
    },
    {
        "query": "Shared account no MFA excessive privileges account review overdue",
        "expected_any": ["AC-2", "AC-2(1)"],
        "note": "account-hygiene finding should surface AC-2 (Account Management)",
    },
    {
        "query": "End of life unsupported vendor product no longer receiving security updates",
        "expected_any": ["SA-22"],
        "note": "EOL/unsupported component should surface SA-22 (Unsupported System Components)",
    },
]


def run_eval(top_k: int = 3) -> dict:
    retriever = NistRetriever()
    results = []
    hits = 0
    for case in GOLDEN_SET:
        retrieved = retriever.search(case["query"], top_k=top_k)
        retrieved_ids = [r.label for r in retrieved]
        hit = any(exp in retrieved_ids for exp in case["expected_any"])
        hits += int(hit)
        results.append(
            {
                "query": case["query"][:60] + "...",
                "expected_any": case["expected_any"],
                "retrieved": retrieved_ids,
                "hit": hit,
                "note": case["note"],
            }
        )
    accuracy = hits / len(GOLDEN_SET)
    return {"accuracy": accuracy, "hits": hits, "total": len(GOLDEN_SET), "results": results}


if __name__ == "__main__":
    report = run_eval()
    for r in report["results"]:
        status = "PASS" if r["hit"] else "FAIL"
        print(f"[{status}] {r['note']}")
        print(f"       expected one of {r['expected_any']}, got {r['retrieved']}")
    print(f"\nRetrieval@3 accuracy: {report['hits']}/{report['total']} ({report['accuracy']*100:.0f}%)")
    if report["accuracy"] < 0.6:
        print("WARNING: below 60% — check embedding backend, chunking, or query builder before shipping.")
        sys.exit(1)
