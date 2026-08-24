"""
Run tracing — addresses the JD's explicit requirement: "Instrument
what you build so every run can be traced, measured, and explained
afterwards" and "Everything an agent does is traceable. If you cannot
explain how it reached an answer, it is not finished."

This is deliberately NOT a wrapper around a hosted observability
platform (Langfuse/Helicone/etc.) — those need accounts and API keys
this take-home shouldn't require. Instead it's a minimal, dependency-
free structured trace: every pipeline run gets a run_id, and every
step (ingest, score, retrieve, explain per-finding) gets a timestamped
entry with its inputs/outputs summarized and its duration. The trace
is written as JSON to data/traces/<run_id>.json and is what you'd
point a real tracer at if you swapped this out for one.

Usage: wrap pipeline.py's steps in `with trace.step("name", meta=...)`.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
TRACE_DIR = os.path.join(os.path.dirname(HERE), "data", "traces")


@dataclass
class StepRecord:
    name: str
    started_at: float
    ended_at: Optional[float] = None
    duration_ms: Optional[float] = None
    meta: dict = field(default_factory=dict)
    error: Optional[str] = None


class RunTrace:
    def __init__(self, run_name: str = "generate_report"):
        self.run_id = uuid.uuid4().hex[:12]
        self.run_name = run_name
        self.started_at = time.time()
        self.steps: list = []

    @contextmanager
    def step(self, name: str, **meta: Any):
        record = StepRecord(name=name, started_at=time.time(), meta=dict(meta))
        self.steps.append(record)
        try:
            yield record
        except Exception as e:  # noqa: BLE001 — record then re-raise, tracing must not swallow errors
            record.error = f"{type(e).__name__}: {e}"
            raise
        finally:
            record.ended_at = time.time()
            record.duration_ms = round((record.ended_at - record.started_at) * 1000, 1)

    def finish(self, summary: Optional[dict] = None) -> str:
        """Writes the trace to disk and returns the run_id. Never raises
        — a failed trace write should not fail the actual pipeline run
        the trace was describing."""
        try:
            os.makedirs(TRACE_DIR, exist_ok=True)
            payload = {
                "run_id": self.run_id,
                "run_name": self.run_name,
                "started_at": self.started_at,
                "total_duration_ms": round((time.time() - self.started_at) * 1000, 1),
                "steps": [
                    {
                        "name": s.name,
                        "duration_ms": s.duration_ms,
                        "meta": s.meta,
                        "error": s.error,
                    }
                    for s in self.steps
                ],
                "summary": summary or {},
            }
            with open(os.path.join(TRACE_DIR, f"{self.run_id}.json"), "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
        except Exception as e:  # noqa: BLE001
            print(f"[tracing.py] failed to write trace (non-fatal): {type(e).__name__}: {e}")
        return self.run_id

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "steps": [
                {"name": s.name, "duration_ms": s.duration_ms, "meta": s.meta, "error": s.error}
                for s in self.steps
            ],
        }


if __name__ == "__main__":
    trace = RunTrace("demo")
    with trace.step("fake_ingest", rows=114):
        time.sleep(0.01)
    with trace.step("fake_score", top_n=5):
        time.sleep(0.02)
    run_id = trace.finish(summary={"top_risk_cve": "CVE-2024-21762"})
    print(f"Wrote trace {run_id} to {TRACE_DIR}/{run_id}.json")
    with open(os.path.join(TRACE_DIR, f"{run_id}.json")) as f:
        print(f.read())
