"""
FastAPI app for the TawasolPay AI-Powered Cyber Risk Assistant.

Run locally:
    uvicorn app:app --reload

Endpoints:
    GET /                 - human-readable HTML risk report (Thing 3)
    GET /api/report       - same data as JSON
    GET /api/report?n=8   - control the number of ranked risks returned
    GET /healthz          - liveness check for deployment platforms
"""
from __future__ import annotations

import os
import sys
import time
import uuid

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pipeline import generate_report, report_to_dicts  # noqa: E402

app = FastAPI(title="TawasolPay Cyber Risk Assistant", version="1.0.0")
templates = Jinja2Templates(directory="templates")

_cache = {"entries": None, "generated_at": None}


def _get_report(top_n: int, force: bool = False):
    if force or _cache["entries"] is None or len(_cache["entries"]) < top_n:
        _cache["entries"] = generate_report(
            top_n=max(top_n, 5),
            refresh_nonce=uuid.uuid4().hex[:8] if force else None,
        )
        _cache["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    return _cache["entries"][:top_n], _cache["generated_at"]


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/api/report")
def api_report(n: int = Query(5, ge=1, le=20), refresh: bool = False):
    entries, generated_at = _get_report(n, force=refresh)
    return JSONResponse(
        {
            "generated_at": generated_at,
            "ranking_mode": os.environ.get("RANKING_MODE", "deterministic"),
            "llm_provider": os.environ.get("LLM_PROVIDER", "groq"),
            "count": len(entries),
            "risks": report_to_dicts(entries),
        }
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request, n: int = Query(5, ge=1, le=20), refresh: bool = False):
    entries, generated_at = _get_report(n, force=refresh)
    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "request": request,
            "entries": entries,
            "generated_at": generated_at,
            "ranking_mode": os.environ.get("RANKING_MODE", "deterministic"),
            "n": n,
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 7860)))
