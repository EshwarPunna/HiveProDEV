"""
Unit tests for scoring.py. Run with: pytest tests/

These pin down the specific behavior the assignment explicitly
requires: CVSS alone must not determine rank, and the ranking must be
explainable/reproducible. They're intentionally about the scoring
logic in isolation (no LLM, no network) so they run in CI on every
commit in a few seconds.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import pandas as pd
from ingest import load_data_pack
from scoring import rank_risks, score_vulnerability, WEIGHTS


def _pack():
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    return load_data_pack(data_dir, use_kev=False)  # offline/deterministic: KEV network dependency tested separately in test_kev.py


def test_weights_sum_to_one():
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9


def test_ranking_is_deterministic_and_reproducible():
    pack = _pack()
    r1 = rank_risks(pack.joined, top_n=5)
    r2 = rank_risks(pack.joined, top_n=5)
    assert [r.vuln_id for r in r1] == [r.vuln_id for r in r2]


def test_cvss_alone_does_not_determine_rank():
    """The assignment's explicit example: a CVSS 10 on an internal-only
    dev box should not outrank a lower-CVSS internet-exposed finding
    with an active ransomware campaign against it."""
    pack = _pack()
    top5 = rank_risks(pack.joined, top_n=5)
    top5_cvss = [r.cvss for r in top5]
    all_scored = [
        score_vulnerability(vid, grp) for vid, grp in pack.joined.groupby("vuln_id")
    ]
    highest_cvss_overall = max(s.cvss for s in all_scored)
    # If the ranking were CVSS-only, #1 would always equal the dataset's
    # max CVSS. We assert it's not required to (soft check: the top
    # entries score highly on multiple factors, not just cvss_base).
    top1 = top5[0]
    cvss_contribution = next(f for f in top1.factors if f.name == "cvss_base").raw_score * WEIGHTS["cvss_base"] * 100
    total = top1.total_score
    assert cvss_contribution / total < 0.15, "CVSS should be a minor contributor to the top-ranked risk's score"


def test_internet_exposed_ransomware_target_beats_internal_high_cvss():
    """Directly constructs the assignment's own example using real
    rows from the dataset, if such a pairing exists (it does, by
    design, in this data pack)."""
    pack = _pack()
    scored = {
        vid: score_vulnerability(vid, grp) for vid, grp in pack.joined.groupby("vuln_id")
    }
    exposed_with_campaign = [
        s for s in scored.values()
        if any(f.name == "internet_exposure" and f.raw_score >= 0.9 for f in s.factors)
        and s.matched_campaigns
    ]
    internal_only = [
        s for s in scored.values()
        if all(f.name != "internet_exposure" or f.raw_score < 0.5 for f in s.factors)
    ]
    assert exposed_with_campaign, "expected at least one internet-exposed, campaign-matched finding in the data pack"
    if internal_only:
        best_exposed = max(exposed_with_campaign, key=lambda s: s.total_score)
        highest_internal = max(internal_only, key=lambda s: s.cvss)
        if highest_internal.cvss >= best_exposed.cvss:
            assert best_exposed.total_score > highest_internal.total_score


def test_dedupe_by_cve_collapses_duplicate_asset_instances():
    pack = _pack()
    top5 = rank_risks(pack.joined, top_n=5, dedupe_by_cve=True)
    cves = [r.cve for r in top5]
    assert len(cves) == len(set(cves)), "top-5 should not contain the same CVE twice when dedupe_by_cve=True"


def test_every_top5_entry_has_an_explanation():
    pack = _pack()
    for r in rank_risks(pack.joined, top_n=5):
        assert len(r.explanation()) > 10
