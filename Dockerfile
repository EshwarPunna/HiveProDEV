FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Build the NIST index at image build time so the container has no
# runtime dependency on GitHub being reachable. Requires network
# access during `docker build`.
RUN python scripts/build_nist_index.py

# data/ needs to be writable at runtime for the CISA KEV cache
# (kev_catalog_cache.json) and run traces (data/traces/*.json).
# Hugging Face Spaces runs containers as a non-root user by default,
# so make these paths world-writable and switch to that user —
# Render/Railway/other hosts run fine here too since they typically
# already run as non-root.
RUN mkdir -p data/traces data/nist_index && chmod -R 777 data
RUN useradd -m -u 1000 appuser
USER appuser

# 7860 is Hugging Face Spaces' expected container port. Other hosts
# (Render, Railway, Fly.io, ...) inject their own $PORT at runtime,
# which the ${PORT:-7860} fallback below picks up automatically.
ENV PORT=7860
EXPOSE 7860

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-7860}"]
