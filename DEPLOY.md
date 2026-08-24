# Deploying to a public URL (free tier)

Two free options, both work with this repo as-is. **Hugging Face Spaces is the
recommended path** — it's Docker-native, needs no credit card, and gives you a
public URL (`https://<you>-<space-name>.hf.space`) in one push.

## Option A — Hugging Face Spaces (recommended)

1. **Get a free LLM key.** Go to [console.groq.com](https://console.groq.com), sign up
   (no credit card), create an API key. This repo defaults to `openai/gpt-oss-120b` —
   open-weight, and as of Aug 2026 the model with the highest free-tier daily token
   budget on Groq (200K tokens/day). See `.env.example` for alternatives.

2. **Create the Space.** Go to [huggingface.co/new-space](https://huggingface.co/new-space):
   - SDK: **Docker**
   - Space hardware: **CPU basic (free)**
   - Visibility: Public

3. **Add your secret.** In the new Space → Settings → Variables and secrets → add
   secret `GROQ_API_KEY` with your key from step 1. (Never commit the key itself —
   `.env` is gitignored for exactly this reason.)

4. **Push this repo to the Space.** Hugging Face Spaces are git repos:
   ```bash
   cd tawasolpay-risk
   git init                                   # skip if already a git repo
   git add .
   git commit -m "TawasolPay AI Cyber Risk Assistant"
   git remote add hf https://huggingface.co/spaces/<your-username>/<space-name>
   git push hf main
   ```
   The Space will build the Docker image automatically (~3-5 min — it installs
   `sentence-transformers`/torch and downloads the real NIST 800-53 catalog during
   the build step, see `Dockerfile`). Watch progress under the Space's "Logs" tab.

5. **Done.** Your public URL is `https://<your-username>-<space-name>.hf.space`.

If you also want this on GitHub (recommended for the assignment's "Repo:" link), push
the same commit to a normal GitHub repo too — the two remotes don't conflict:
```bash
git remote add origin https://github.com/<you>/tawasolpay-risk.git
git push origin main
```

## Option B — Render.com (also free, no Docker knowledge needed)

1. Push this repo to GitHub first.
2. [render.com](https://render.com) → New → Web Service → connect the repo.
3. Environment: **Docker** (Render auto-detects the `Dockerfile`).
4. Add environment variable `GROQ_API_KEY` under the service's Environment tab.
5. Deploy. Render gives you a `https://<service-name>.onrender.com` URL.
   Free tier note: Render's free web services sleep after 15 min of inactivity and
   take ~30-60s to wake on the next request — fine for a demo/grading link, not for
   production traffic.

## Running fully offline / without any LLM key

Set `LLM_PROVIDER=none` (already the case if you skip the Groq key) and the system
still produces a complete, correct top-5 briefing using the deterministic template
explanations from `scoring.py::ScoredRisk.explanation()` — useful for confirming the
deployment works before wiring up the LLM step.
