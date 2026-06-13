# ThreatIntelligenceSystem

**AI-Powered Android Malware Analysis & Banking Trojan Detection Platform**

A comprehensive malware analysis system that combines static & dynamic APK
analysis, machine learning, malware DNA fingerprinting, intent-spoof detection,
and GenAI-powered reverse engineering to detect Android malware, banking
trojans, and fake banking applications.

---

## Architecture

The system has four moving parts. The two you run yourself live in this repo;
the other two are external services the backend talks to over HTTP.

```
                         ┌─────────────────────────────┐
   Browser ── :5173 ──▶  │  frontend/  (Vite + React)  │
                         └──────────────┬──────────────┘
                                        │ HTTP + SSE
                         ┌──────────────▼──────────────┐
                         │  backend/   (FastAPI :8001) │
                         │  scoring · fusion · GenAI   │
                         └───────┬───────────────┬─────┘
                                 │               │
                    ┌────────────▼──────┐  ┌─────▼──────────────┐
                    │ MobSF  (:8000)    │  │ Ollama  (:11434)   │
                    │ static + dynamic  │  │ local LLM (gemma3) │
                    └───────────────────┘  └────────────────────┘
```

| Component   | Path         | What it is                                                            |
|-------------|--------------|-----------------------------------------------------------------------|
| Backend     | `backend/`   | FastAPI app (`main.py`) on **:8001** — orchestrates the analysis pipeline (single worker, in-memory job queue + SSE progress). |
| Frontend    | `frontend/`  | Vite + React + Tailwind console on **:5173** (dev) / served by the backend in prod. |
| MobSF       | external     | Mobile Security Framework on **:8000** — does the actual static & dynamic APK analysis. Run via Docker. |
| Ollama      | external     | Local LLM runtime on **:11434** — powers the GenAI reverse-engineering / report layer. No API key, runs offline. |
| ML model    | `backend/model/` | Prototype synthetic-trained classifier. Standalone — degrades gracefully if its deps are missing. |
| Sample APKs | `BankAPKS/`  | Genuine bank APKs used for testing (gitignored — not in the repo, see below). |

---

## Prerequisites

Install these once on each machine:

- **Python 3.11+** (developed on 3.13) — for the backend
- **Node.js 18+** (developed on 22) + npm — for the frontend
- **MobSF** — installed locally (this repo's `mobsf/`) or run via Docker
- **[Ollama](https://ollama.com)** — local LLM runtime for the GenAI layer
- **Android emulator** (Android SDK + an AVD) — **required for dynamic analysis**

---

## Setup

### 1. Clone

```bash
git clone https://github.com/ShravniThakur/ThreatIntelligenceSystem.git
cd ThreatIntelligenceSystem
```

> **Note:** `mobsf/` and `BankAPKS/` are intentionally **not** committed (~2.7 GB
> combined). You install MobSF separately (step 3) and supply your own test APKs.

### 2. Backend (FastAPI)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # then edit .env (see Configuration below)
```

### 3. MobSF (static + dynamic analysis engine)

MobSF runs as its own server — it does **not** go in the backend venv. Leave it
running in its own terminal.

**Local install (needed for dynamic analysis):**

```bash
cd ~/Desktop/BankOfIndiaHackathon/mobsf
./run.sh 127.0.0.1:8000
```

**Or Docker (static analysis only — no emulator support):**

```bash
docker run -it --rm -p 8000:8000 \
  opensecurity/mobile-security-framework-mobsf:latest
```

Check it's up at <http://localhost:8000/>.

**Sync the API key into `backend/.env`.** A local install derives the key from
`~/.MobSF/secret`. Print the live key and make sure `MOBSF_API_KEY` in your
`.env` matches it:

```bash
python3 -c "import hashlib; print(hashlib.sha256(open('$HOME/.MobSF/secret').read().encode()).hexdigest())"
```

(For the Docker image, copy the **API Key** shown in the top-right of the MobSF
web UI instead.)

### 3b. Android emulator (required for dynamic analysis)

Dynamic analysis runs the APK on a live emulator, which must be launched with
`-writable-system`. In its own terminal:

```bash
~/Library/Android/sdk/emulator/emulator -avd Pixel_6_API_30 -writable-system -no-snapshot
```

Replace `Pixel_6_API_30` with your AVD name (`emulator -list-avds`). The
emulator id (default `emulator-5554`) must match `EMULATOR_NAME` /
`MOBSF_ANALYZER_IDENTIFIER` in `.env`.

### 4. Ollama (local GenAI layer)

```bash
# install from https://ollama.com, then:
ollama serve                        # starts the API on http://localhost:11434
ollama pull gemma3                  # download the model (or `ollama pull phi` for a smaller one)
```

### 5. Frontend (Vite + React)

```bash
cd frontend
npm install                         # if the npm cache is root-owned: npm install --cache /tmp/npmcache
```

---

## Running

Start each service in its own terminal:

```bash
# 1. MobSF       cd mobsf && ./run.sh 127.0.0.1:8000   (step 3 above)
# 2. Emulator    ~/Library/Android/sdk/emulator/emulator -avd Pixel_6_API_30 -writable-system -no-snapshot
# 3. Ollama      ollama serve
# 4. Backend
cd backend && source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8001 --workers 1   # MUST be a single worker

# 5. Frontend
cd frontend && npm run dev          # http://localhost:5173
```

Then open <http://localhost:5173> and upload an APK.

> ⚠️ The backend keeps job state in process memory, so it **must** run with
> `--workers 1`. Don't scale it up.

### Running the pipeline directly (CLI)

You can also run the analysis pipeline without the web UI — useful for batch
runs or debugging. With MobSF + the emulator up and the venv active:

```bash
cd backend
source .venv/bin/activate

# analyze one APK and save the full report under reports/
python feature_store_pipeline.py samples/app-debug.apk --save-report

# analyze and also export the extracted feature vector to CSV
python feature_store_pipeline.py samples/your-app.apk --save-report --export features.csv
```

### Production build (single-origin)

`backend/main.py` serves `frontend/dist` at <http://localhost:8001/> when it
exists, so you can run everything off the backend port:

```bash
cd frontend
VITE_API_BASE= npm run build        # empty API base -> relative, same-origin calls
# now just run the backend; open http://localhost:8001
```

---

## Configuration

All backend config lives in `backend/.env` (copied from `backend/.env.example`).

| Variable                     | Default                  | Purpose                                              |
|------------------------------|--------------------------|------------------------------------------------------|
| `MOBSF_API_KEY`              | —                        | **Required.** MobSF REST API key (from the MobSF UI).|
| `MOBSF_URL`                  | `http://localhost:8000`  | Where MobSF is reachable.                            |
| `MOBSF_HTTP_TIMEOUT`         | `300`                    | HTTP timeout (s) for MobSF calls.                    |
| `EMULATOR_NAME`              | `emulator-5554`          | Android emulator id (dynamic analysis only).         |
| `MOBSF_ANALYZER_IDENTIFIER`  | `emulator-5554`          | MobSF analyzer device id (dynamic analysis only).    |
| `MOBSF_DYNAMIC_RUN_SECONDS`  | `90`                     | How long to run the APK during dynamic analysis.     |
| `FEATURE_STORE_DB`           | `feature_store.sqlite`   | SQLite feature store (created automatically).         |
| `OLLAMA_URL`                 | `http://localhost:11434` | Local Ollama API.                                    |
| `OLLAMA_MODEL`               | `gemma3`                 | Model name (must be `ollama pull`-ed first).         |
| `OLLAMA_TIMEOUT`             | `600`                    | LLM call timeout (s).                                |

The frontend reads `VITE_API_BASE` (build-time): unset → defaults to
`http://localhost:8001`; set to empty for a same-origin production build.

---

## Project structure

```
.
├── backend/                  FastAPI service + analysis pipeline
│   ├── main.py               API entrypoint (:8001) — job queue + SSE
│   ├── feature_store_pipeline.py   MobSF orchestration + feature extraction
│   ├── fusion.py             combines all detector scores
│   ├── risk_scorer.py        deterministic risk scoring
│   ├── reverse_engineer.py   GenAI reverse-engineering (Ollama)
│   ├── social_engineer.py    social-engineering / phishing analysis
│   ├── intent_spoof.py       fake-banking-app / intent-spoof detection
│   ├── dna_fingerprint.py    APK DNA fingerprinting (repackaged-clone detection)
│   ├── campaign_store.py     campaign clustering across analyses
│   ├── report_generator.py   final GenAI report
│   ├── model/                prototype ML classifier (predict.py / train.py)
│   ├── bank_whitelist.json   known-good bank app fingerprints
│   ├── requirements.txt
│   └── .env.example          ← copy to .env
├── frontend/                 Vite + React + Tailwind console (:5173)
│   └── src/{pages,panels,components,lib}
├── BankAPKS/                 test APKs (gitignored)
└── mobsf/                    MobSF install (gitignored — run via Docker)
```

---

## Troubleshooting

- **`MOBSF_API_KEY` error on startup** — the backend refuses to start without it.
  Make sure MobSF is running and the key is in `backend/.env`.
- **`npm install` EACCES** — the npm cache may be root-owned; use
  `npm install --cache /tmp/npmcache`.
- **GenAI sections empty** — Ollama isn't running or the model isn't pulled
  (`ollama serve` + `ollama pull gemma3`).
- **ML classifier shows "unavailable"** — `pandas`/`scikit-learn`/`lightgbm`
  aren't installed. It's optional; the rest of the pipeline still works.
