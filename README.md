---
title: TawasolPay AI Cyber Risk Assistant
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
app_port: 7860
pinned: false
short_description: Prioritized cyber risk briefing with NIST guidance
---

# TawasolPay AI-Powered Cyber Risk Assistant

Takes TawasolPay's asset/vulnerability/threat-intel/business-service data pack, ranks the
top 5 risks using a multi-factor rubric (not CVSS alone), cross-verifies active exploitation
against both the provided threat-intel feed *and* the live CISA KEV catalog, retrieves the
most applicable NIST SP 800-53 Rev 5 control for each via real semantic search over the
official NIST catalog, and renders a readable briefing a technical manager can act on without
further processing. Every run writes a structured trace so any output can be explained after
the fact.

**Live demo:** `<add your deployed URL here>`
**Repo:** `<add your GitHub URL here>`

**Deploying to a public URL:** see [`DEPLOY.md`](DEPLOY.md) — free Hugging Face Spaces
deployment, no credit card, ~5 minutes end to end.

## Quickstart

```bash
git clone <this repo>
cd tawasolpay-risk
pip install -r requirements.txt
cp .env.example .env          # fill in GROQ_API_KEY (free: https://console.groq.com), or leave
                               # LLM_PROVIDER=none to run fully offline
python scripts/build_nist_index.py   # downloads the real NIST catalog + builds the retrieval index (~2 min)
uvicorn app:app --reload
```

The first real pipeline run also fetches and caches the live CISA KEV catalog
(`data/kev_catalog_cache.json`, ~1,670 entries, ~1MB) — no setup needed, it happens
automatically in `ingest.py`. Delete that file (or set `use_kev=False` in `load_data_pack()`)
to skip it; the system still runs correctly without it, just without KEV corroboration (see
Supporting Question 2, item 1, for the tradeoff that creates).

Open `http://localhost:8000` for the HTML briefing, or `http://localhost:8000/api/report` for JSON.

Run the tests:
```bash
pip install -r requirements-dev.txt
pytest tests/test_scoring.py -v          # deterministic scoring unit tests (offline)
pytest tests/test_kev.py -v              # CISA KEV integration unit tests (offline fixture)
python tests/eval_nist_retrieval.py      # NIST retrieval golden-set eval
python src/pipeline.py                   # end-to-end CLI run, prints the top-5 + writes a trace
```

Every `python src/pipeline.py` / app run writes a full trace (per-step timing, evidence
retrieved, control selected) to `data/traces/<run_id>.json` — see `src/tracing.py`. CI
(`.github/workflows/ci.yml`) runs both test suites plus an offline end-to-end smoke test on
every push.

If you don't want to install `sentence-transformers`/torch, comment that line out of
`requirements.txt` — `build_nist_index.py` auto-falls-back to a pure-Python TF-IDF index
(`scripts/tfidf_fallback.py`), so the system still runs with zero heavy dependencies, just
with weaker semantic matching.

## How it works

```
data pack (CSVs + MDR advisory)  +  live CISA KEV catalog (src/kev.py)
        │
        ▼
  src/ingest.py        — pandas joins: vuln + asset + business_service + threat_intel + KEV
        │
        ▼
  src/scoring.py        — Thing 1: deterministic multi-factor risk score (see below)
        │
        ▼
  src/nist_rag.py        — Thing 2: embed the finding → cosine search over the real
        │                   NIST SP 800-53 Rev 5 catalog (fetched fresh, not hardcoded)
        ▼
  src/llm.py            — LLM turns (finding + retrieved controls) into plain-English
        │                   explanation + control selection, structured JSON output
        ▼
  src/pipeline.py + app.py — Thing 3: readable HTML/JSON briefing (src/tracing.py logs every step)
```

Three ranking strategies are implemented (`scoring.py` is the default; see file docstrings):
- **`RANKING_MODE=deterministic`** (default) — the rubric decides order; LLM only explains.
- **`RANKING_MODE=agentic`** — an LLM independently re-ranks a deterministic top-15 shortlist
  (`src/agent_ranker.py`). Useful for comparing against the deterministic order.
- The default mode is itself already a **hybrid**: deterministic score is ground truth for
  ranking, LLM must justify against the actual retrieved evidence and is rejected if it
  cites a NIST control that wasn't in its candidate set (see `llm.py::explain_risk`).

We chose deterministic-by-default because a Board briefing needs a ranking a security
engineer can challenge line by line and get the same answer twice — see `scoring.py`'s
docstring for the full rationale and the weight table.

### Two independent confirmation sources for "actively exploited"

`vulnerabilities.csv` + `threat_intelligence.csv` alone can only flag a CVE as under active
exploitation if TawasolPay's own threat-intel feed happened to catch it. `src/kev.py` closes
that gap by cross-referencing every CVE against the live, authoritative CISA KEV catalog
(fetched fresh from `github.com/cisagov/kev-data`, not hardcoded — confirmed live and current
during development: 1,670 entries as of Aug 18 2026) independently of the provided CSV. A
finding scores highest when *both* sources agree — see `scoring.py::_score_threat_intel` —
which is why, in testing, a CVE confirmed by both the provided threat-intel feed and live KEV
outranked a similarly-severe CVE that only one source had flagged.

---

## Supporting Question 1 — The data split

**Embedded (NIST SP 800-53, ~1,000+ controls' prose):** there's no structured key to look
this up by — "what control fits an internet-exposed VPN with an active ransomware campaign
against it" is a semantic question, not a filter, and the corpus is too large and too
prose-heavy to hardcode a lookup table. Embeddings let a vaguely-worded finding retrieve the
right control even when the finding's vocabulary doesn't literally match the control's.

**Queried as structured records (assets, vulnerabilities, threat intel, business services, and
the live CISA KEV catalog):** this data is already precisely keyed (`asset_id`, `cve`,
`business_service`, `cveID`) with exact values that matter for correctness — an LLM asked "is
this asset internet-exposed" over free text risks getting it wrong or inconsistent across
runs, where a pandas filter/dict lookup never does. Joins and scoring belong in code
specifically because the assignment requires the ranking to be reproducible, not a matter of
an LLM's mood that day.

## Supporting Question 2 — Where it goes wrong

1. **The cached CISA KEV catalog can go stale without anyone noticing.** `src/kev.py`
   downloads the live KEV catalog once and caches it to `data/kev_catalog_cache.json`
   indefinitely — there's no TTL or staleness check. If the app runs for weeks without a
   redeploy, a CVE added to KEV last week won't be reflected, and the system has no way of
   flagging "this KEV data might be out of date" to the reader; it just silently keeps using
   the cached snapshot. **What I'd do:** store `dateReleased` from the KEV response alongside
   the cache and surface it in the UI footer ("KEV data as of ..."), and add a cheap staleness
   check (re-fetch if the cache is older than 24h) rather than caching forever.

2. **The NIST control selection can pick a plausible-sounding but not-actually-best
   control** when the top-3 retrieved candidates are all a mediocre semantic match — e.g. a
   finding about a stale, unowned asset with no clean single-control mapping. The system will
   still confidently return whichever of the 3 scored highest, with no signal to the reader
   that "this was the best of a weak set" versus "this was a strong, confident match."
   **What I'd do:** surface the raw cosine-similarity score in the UI (currently computed but
   not displayed) and add a visible low-confidence flag below some threshold, so the reader
   knows to double-check rather than trust it at face value.

3. **`build_query_for_risk()` over-weights internet exposure in the query text** whenever a
   finding is internet-facing (see `nist_rag.py`), which can crowd out other relevant signals
   like "no patch available" or "missing EDR" in the retrieval query — verified against our
   own eval index, where several genuinely internet-exposed findings all pulled toward AC-17
   (Remote Access) even when a flaw-remediation or account-management control was arguably a
   tighter fit. This is a query-construction bias, not a data problem, so it's silent: the
   retrieved control is real and relevant, just not necessarily the *most* relevant one.
   **What I'd do:** retrieve separately per top-2 contributing factor (not one blended query)
   and let the LLM choose among a union of both result sets, rather than one query trying to
   represent every factor at once.

## Supporting Question 3 — One thing I'd change

I'd replace the single blended NIST query per finding (see failure mode #3 above) with
**multi-query retrieval keyed to each finding's top contributing factors**, and add a
retrieved-similarity confidence threshold shown to the user. Right now the system produces
one query per finding and trusts whatever comes back in the top-3; a security team reading
this briefing has no way to tell "this control is a precise fit" from "this was the least-bad
of three weak matches." Between those two, the confidence signal matters more for trust in a
system a CISO is going to cite to a Board — a wrong ranking is bad, but a wrong ranking
presented as equally confident as a right one is worse, because it removes the reader's
instinct to double-check.

## Data pack notes

- `synthetic_threat_report.md` (the MDR advisory) is provided as ingest input but not
  currently parsed into structured signal — the campaign names/CVEs it describes are already
  present in `threat_intelligence.csv`, so the system's actual matching runs off the CSV. The
  markdown is surfaced as-is at ingest time (`ingest.py::load_data_pack().threat_report_text`)
  for future use (e.g. summarizing it verbatim into the briefing header) but isn't yet wired
  into scoring.
- 3/60 assets have `last_seen_days` > 30 (stale/possibly-abandoned), and 1/60 has no
  `owner_team` — these show up in the `compensating_controls` factor rather than being
  filtered out, since a stale, unowned asset is itself a risk signal, not noise to discard.
- CI lint/type-check steps (`ruff`, `mypy`) run non-blocking for now — I didn't have a way to
  validate them against this exact CI runner before submitting, so I'd rather flag that
  honestly than claim an enforced gate I haven't actually verified passes.
