"""
Builds the NIST SP 800-53 Rev 5 retrieval corpus and vector index.

Run this once (or whenever you want to refresh the corpus):

    python scripts/build_nist_index.py

What it does
------------
1. Downloads the OFFICIAL NIST OSCAL JSON catalog directly from NIST's
   GitHub org (usnistgov/oscal-content) — the same machine-readable
   source NIST itself publishes and links from csrc.nist.gov. This is
   the real document, not a paraphrase or the LLM's training data.
2. Walks the OSCAL control tree and extracts, per control (and per
   control enhancement): id, title, the control "statement" prose, and
   the "guidance" prose. Assessment-objective/assessment-method nodes
   are skipped — they're 800-53A audit procedures, not remediation
   guidance, and including them would triple the corpus size with
   text that isn't useful for "what should I do about this risk."
3. Chunks each control into one retrieval passage (statement +
   guidance together — splitting them apart loses the "what to do"
   vs "why" pairing that makes a control useful as an answer).
4. Embeds every passage with sentence-transformers (local, free, no
   API key) and writes a flat numpy index + metadata to
   data/nist_index/.

This is the "embed" half of the data split (see README Q1): NIST
800-53 is 1,000+ controls of unstructured prose. There's no clean key
to look it up by — "what control covers an internet-exposed VPN with
an active ransomware campaign against it" is a semantic question, not
a filter. That's what embeddings are for.
"""
from __future__ import annotations

import json
import os
import re
import sys

import requests

NIST_CATALOG_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(HERE), "data")
RAW_CATALOG_PATH = os.path.join(DATA_DIR, "nist_800_53_catalog_raw.json")
INDEX_DIR = os.path.join(DATA_DIR, "nist_index")


def download_catalog(force: bool = False) -> dict:
    if os.path.exists(RAW_CATALOG_PATH) and not force:
        print(f"Using cached catalog at {RAW_CATALOG_PATH}")
        with open(RAW_CATALOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    print(f"Downloading NIST SP 800-53 Rev 5 OSCAL catalog from {NIST_CATALOG_URL} ...")
    resp = requests.get(NIST_CATALOG_URL, timeout=60)
    resp.raise_for_status()
    catalog = resp.json()
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(RAW_CATALOG_PATH, "w", encoding="utf-8") as f:
        json.dump(catalog, f)
    print(f"Saved raw catalog ({len(resp.content) / 1e6:.1f} MB) to {RAW_CATALOG_PATH}")
    return catalog


def _clean_prose(text: str) -> str:
    # Strip OSCAL parameter-insertion placeholders like
    # "{{ insert: param, ac-01_odp.03 }}" down to something readable.
    text = re.sub(r"\{\{\s*insert:\s*param,\s*[^}]+\}\}", "[organization-defined parameter]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _collect_statement_prose(part: dict) -> list:
    out = []
    if part.get("name") in ("statement",) or part.get("name") == "item":
        if part.get("prose"):
            out.append(_clean_prose(part["prose"]))
    for sub in part.get("parts", []) or []:
        out.extend(_collect_statement_prose(sub))
    return out


def extract_controls(catalog: dict) -> list:
    """Returns a flat list of {id, title, family, statement, guidance}."""
    controls_out = []

    def walk_control(ctrl: dict, family_title: str):
        cid = ctrl.get("id", "")
        title = ctrl.get("title", "")
        statement_parts, guidance_parts = [], []
        for part in ctrl.get("parts", []) or []:
            name = part.get("name")
            if name == "statement":
                statement_parts.extend(_collect_statement_prose(part))
            elif name == "guidance" and part.get("prose"):
                guidance_parts.append(_clean_prose(part["prose"]))

        label = None
        for p in ctrl.get("props", []) or []:
            if p.get("name") == "label" and p.get("class") != "sp800-53a":
                label = p.get("value")
                break
        label = label or cid.upper()

        if statement_parts or guidance_parts:
            controls_out.append(
                {
                    "id": cid,
                    "label": label,
                    "title": title,
                    "family": family_title,
                    "statement": " ".join(statement_parts),
                    "guidance": " ".join(guidance_parts),
                }
            )

        # Recurse into control enhancements (nested "controls").
        for sub in ctrl.get("controls", []) or []:
            walk_control(sub, family_title)

    for group in catalog["catalog"].get("groups", []):
        family_title = group.get("title", group.get("id", ""))
        for ctrl in group.get("controls", []) or []:
            walk_control(ctrl, family_title)

    return controls_out


def build_passages(controls: list) -> list:
    passages = []
    for c in controls:
        text = f"{c['label']} {c['title']}. {c['statement']} {c['guidance']}".strip()
        if len(text) < 20:
            continue
        passages.append(
            {
                "control_id": c["id"],
                "label": c["label"],
                "title": c["title"],
                "family": c["family"],
                "text": text,
            }
        )
    return passages


def embed_and_save(passages: list):
    os.makedirs(INDEX_DIR, exist_ok=True)
    try:
        from sentence_transformers import SentenceTransformer
        import numpy as np

        print("Embedding passages with sentence-transformers (all-MiniLM-L6-v2) ...")
        model = SentenceTransformer("all-MiniLM-L6-v2")
        texts = [p["text"] for p in passages]
        embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)
        np.save(os.path.join(INDEX_DIR, "embeddings.npy"), embeddings)
        backend = "sentence-transformers/all-MiniLM-L6-v2"
    except ImportError:
        print(
            "sentence-transformers not installed — falling back to a pure-Python "
            "TF-IDF index (still real retrieval, just a weaker similarity model). "
            "Install sentence-transformers for better retrieval quality."
        )
        from tfidf_fallback import build_tfidf_index

        build_tfidf_index([p["text"] for p in passages], INDEX_DIR)
        backend = "tfidf-fallback"

    with open(os.path.join(INDEX_DIR, "passages.json"), "w", encoding="utf-8") as f:
        json.dump(passages, f)
    with open(os.path.join(INDEX_DIR, "meta.json"), "w", encoding="utf-8") as f:
        json.dump({"backend": backend, "count": len(passages)}, f)

    print(f"Indexed {len(passages)} NIST 800-53 controls/enhancements using backend={backend}")


if __name__ == "__main__":
    force = "--force" in sys.argv
    catalog = download_catalog(force=force)
    controls = extract_controls(catalog)
    print(f"Extracted {len(controls)} controls/enhancements from the catalog")
    passages = build_passages(controls)
    embed_and_save(passages)
