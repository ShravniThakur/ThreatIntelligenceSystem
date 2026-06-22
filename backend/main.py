"""
main.py — FastAPI backend for the GenAI APK malware-analysis system.
====================================================================

Ties together the deterministic scorer (risk_scorer), the GenAI layer
(reverse_engineer) and the existing MobSF feature pipeline (feature_store_pipeline)
behind an async HTTP API + SSE progress stream.

Concurrency model (READ THIS):
------------------------------
A full analysis takes minutes (MobSF static, then dynamic, then 3 LLM calls), so
we cannot block the request. The pattern is:

  * An in-memory ``JOBS: dict[str, JobState]`` registry holds per-job state and a
    per-job ``asyncio.Queue`` of progress events. Because it lives in process
    memory, the server MUST run with a SINGLE worker:

        uvicorn main:app --host 0.0.0.0 --port 8001 --workers 1

  * POST /analyze saves the APK, registers a job, kicks off ``run_job`` OFF the
    event loop via ``asyncio.create_task(asyncio.to_thread(run_job, ...))`` (the
    blocking MobSF/requests code must never run inside an async handler — it would
    freeze the SSE stream), and returns ``{"job_id": ...}`` immediately.

  * EventSource is GET-only, so the browser opens GET /progress/{job_id} (SSE) to
    watch ``stage`` events; the final ``done`` event carries ``apk_hash``, after
    which the browser GETs /analyses/{apk_hash} for the full result.

Backend on :8001; MobSF on :8000.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import risk_scorer
import reverse_engineer
import social_engineer
import intent_spoof
import dna_fingerprint
import campaign_store
import fusion
import report_generator
from feature_store_pipeline import FeatureStorePipeline
from model import predict as ml_predict   # ML classifier (real-dataset-trained, experimental)

LOG = logging.getLogger("malware_api")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(HERE, "reports")
SAMPLES_DIR = os.path.join(HERE, "samples")
# Serve the Vite build output (run `npm run build` in frontend/). Falls back to
# the raw frontend dir if dist/ hasn't been built yet, so the mount never 404s
# the whole UI during local dev (where the SPA is usually served by Vite :5173).
_FRONTEND_ROOT = os.path.join(os.path.dirname(HERE), "frontend")
_FRONTEND_DIST = os.path.join(_FRONTEND_ROOT, "dist")
FRONTEND_DIR = _FRONTEND_DIST if os.path.isdir(_FRONTEND_DIST) else _FRONTEND_ROOT

# Human-readable label per pipeline stage, surfaced to the progress bar.
# New two-score order: static -> dynamic -> feature score -> reverse engineering
# -> analysis of scores -> done.
STAGE_LABELS = {
    "mobsf_static": "Static analysis",
    "mobsf_dynamic": "Dynamic analysis",
    "intent_spoofing": "Intent spoofing check",
    "feature_score": "Feature-store score",
    "ml_classification": "ML threat classification",
    "dna_fingerprinting": "DNA fingerprinting",
    "campaign_clustering": "Campaign clustering",
    "reverse_engineering": "Reverse engineering",
    "social_engineering": "Social engineering detection",
    "analysis_of_scores": "Score analysis",
    "report_generation": "Final report",
    "done": "Done",
    "error": "Error",
}


# --------------------------------------------------------------------------- #
# In-memory job registry
# --------------------------------------------------------------------------- #


@dataclass
class JobState:
    """Per-job state shared between the worker thread and the SSE generator."""

    job_id: str
    queue: "asyncio.Queue[dict]" = field(default_factory=asyncio.Queue)
    stage: str = "queued"
    status: str = "running"           # running | done | error
    apk_hash: Optional[str] = None
    detail: Optional[str] = None


JOBS: Dict[str, JobState] = {}

app = FastAPI(title="GenAI APK Malware Analysis", version="1.0")

# Permissive CORS for the hackathon demo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Startup
# --------------------------------------------------------------------------- #


@app.on_event("startup")
def _startup() -> None:
    """Create working dirs and warn (do not crash) on missing keys."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    if not os.environ.get("MOBSF_API_KEY"):
        LOG.warning("MOBSF_API_KEY is not set — /analyze will surface a connection "
                    "error event until MobSF is reachable and the key is configured.")
    if not reverse_engineer._ollama_available():
        LOG.warning("Ollama not reachable at %s (model=%s) — LLM steps will degrade "
                    "gracefully and the deterministic score will still return. "
                    "Start it with `ollama serve` and `ollama pull %s`.",
                    reverse_engineer.OLLAMA_URL, reverse_engineer.OLLAMA_MODEL,
                    reverse_engineer.OLLAMA_MODEL)


# --------------------------------------------------------------------------- #
# The blocking pipeline (runs in a worker thread)
# --------------------------------------------------------------------------- #


def run_job(apk_path: str, job: JobState, emit: Callable[[dict], None]) -> None:
    """Run the full analysis pipeline for one APK, emitting SSE stage events.

    Executes in a worker thread (off the event loop). ``emit`` is a thread-safe
    callback that schedules an event onto the job's asyncio.Queue. On any
    exception it emits a final ``{"stage":"error","detail": ...}`` event so the
    SSE stream never hangs.
    """
    try:
        base = os.path.splitext(os.path.basename(apk_path))[0]

        # --- Stage 1+2: MobSF static then dynamic ------------------------- #
        # The pipeline's analyze_apk() performs static THEN best-effort dynamic in
        # one blocking call and returns the FeatureVector. We surface "static" up
        # front (the long wait happens here) and mark "dynamic" once it returns,
        # reading whether dynamic actually ran from the vector.
        job.stage = "mobsf_static"
        emit({"stage": "mobsf_static"})
        pipeline = FeatureStorePipeline()
        fv = pipeline.analyze_apk(apk_path, run_dynamic=True, report_dir=REPORTS_DIR)

        job.stage = "mobsf_dynamic"
        emit({"stage": "mobsf_dynamic",
              "dynamic_ran": bool(getattr(fv, "dynamic_analysis_success", 0))})

        # The pipeline dumps raw JSON keyed by APK basename (NOT hash).
        static_path = os.path.join(REPORTS_DIR, f"{base}.static.json")
        static_json = _read_json(static_path)

        # Feature row = the 85-feature vector as a dict; add package_name for
        # convenience (harmless extra key used by the result/UI).
        feature_row = dataclasses.asdict(fv)
        package_name = static_json.get("package_name", "")
        feature_row["package_name"] = package_name
        apk_hash = fv.apk_hash
        job.apk_hash = apk_hash

        # --- Stage 3.5: intent spoofing check (deterministic, whitelist-based) #
        # Fast and definitive — surface it early. Standalone signal: persisted &
        # displayed, NOT fed into fusion. Degrades cleanly if the whitelist is
        # missing (error field set, never raises).
        job.stage = "intent_spoofing"
        emit({"stage": "intent_spoofing"})
        spoof_result = intent_spoof.detect_impersonation(static_json)
        emit({"stage": "intent_spoofing",
              "is_impersonation": spoof_result.is_impersonation,
              "confidence": spoof_result.confidence})

        # --- Stage 3: Feature-Store Score (deterministic) ----------------- #
        job.stage = "feature_score"
        emit({"stage": "feature_score"})
        fs_result = risk_scorer.score(feature_row, static_json)
        emit({"stage": "feature_score", "fs_score": fs_result.score,
              "fs_band": fs_result.risk_band})

        # --- Stage 3.55: ML threat classification (LightGBM, real-dataset-trained) #
        # Multi-label classifier over the same feature_row (threat categories taken
        # from the trained model). Standalone & experimental: surfaced with a
        # prototype disclaimer and NOT fed into fusion. Degrades to available=False
        # if the ML deps/model are missing — never raises.
        job.stage = "ml_classification"
        emit({"stage": "ml_classification"})
        ml_result = ml_predict.classify(feature_row)
        emit({"stage": "ml_classification",
              "available": ml_result.get("available", False),
              "top_label": ml_result.get("top_label", "")})

        # --- Stage 3.6: APK DNA fingerprinting (structural malware-family match) #
        # Standalone signal (does NOT feed fusion). Builds the static fingerprint
        # vector, compares to the seeded malware-family DB, and stores this APK's
        # own fingerprint for future Campaign-Store clustering. Degrades to an
        # error field if numpy/the reference DB is missing — never raises.
        job.stage = "dna_fingerprinting"
        emit({"stage": "dna_fingerprinting"})
        dna_result = dna_fingerprint.analyze_dna(
            feature_row, apk_path, apk_hash, apk_filename=fv.apk_filename)
        emit({"stage": "dna_fingerprinting",
              "top_family": dna_result.top_family,
              "top_similarity": dna_result.top_similarity})

        # --- Stage 3.7: campaign clustering (analyzed-APK relationship graph) - #
        # Standalone (does NOT feed fusion). Records this APK's campaign signals
        # (cert / domains / package) and returns the cluster it belongs to — a
        # group of >=2 analyzed APKs linked by structural cosine, DEX byte-clone,
        # shared signing cert, or shared C2 domain. Family labels are NOT used
        # here (that's the DNA component). Never raises.
        job.stage = "campaign_clustering"
        emit({"stage": "campaign_clustering"})
        campaign_result = campaign_store.analyze_campaign(
            apk_hash, package_name, static_json)
        emit({"stage": "campaign_clustering",
              "is_campaign": campaign_result.is_campaign,
              "campaign_size": campaign_result.size})

        # --- Stage 4: reverse engineering (Code-Behaviour Score, LLM) ----- #
        # Degrades gracefully (jadx/Ollama missing) to code_score=None; never raises.
        job.stage = "reverse_engineering"
        emit({"stage": "reverse_engineering"})
        re_result = reverse_engineer.reverse_engineer(apk_path, static_json,
                                                      report_dir=REPORTS_DIR)
        emit({"stage": "reverse_engineering", "code_band": re_result.code_band,
              "behaviours": len(re_result.behaviour_catalog)})

        # --- Stage 4.5: social engineering detection (LLM, parallel to RE) - #
        # Standalone signal over the app's UI strings; does NOT feed fusion.
        # Reuses the jadx resources RE persisted (re_result.resources_dir), with
        # the MobSF static strings as the fallback when jadx/resources are absent.
        job.stage = "social_engineering"
        emit({"stage": "social_engineering"})
        se_result = social_engineer.detect_social_engineering(
            static_json,
            re_result.resources_dir,
        )
        emit({"stage": "social_engineering",
              "se_band": se_result.se_band,
              "se_findings": len(se_result.findings)})

        # --- Stage 5: analysis of scores (deterministic fusion) ----------- #
        job.stage = "analysis_of_scores"
        emit({"stage": "analysis_of_scores"})
        fusion_result = fusion.analyse_scores(fs_result, re_result)
        emit({"stage": "analysis_of_scores",
              "quadrant": fusion_result.quadrant,
              "recommended_action": fusion_result.recommended_action})

        # --- Persist the result (plain dict, asdict-able dataclasses) ----- #
        result = {
            "apk_hash": apk_hash,
            "apk_filename": fv.apk_filename,
            "package_name": package_name,
            "analyzed_at": fv.analysis_timestamp,
            # two scores + fused verdict
            "fs_score": fs_result.score,
            "fs_band": fs_result.risk_band,
            "code_score": re_result.code_score,
            "code_band": re_result.code_band,
            "quadrant": fusion_result.quadrant,
            "recommended_action": fusion_result.recommended_action,
            "reasoning": fusion_result.reasoning,
            "re_unavailable": fusion_result.re_unavailable,
            "capability_gap": fusion_result.capability_gap,
            # MITRE + behaviour evidence (code-confirmed)
            "mitre_map": re_result.mitre_map,
            "behaviour_catalog": re_result.behaviour_catalog,
            "capability_constellation": re_result.capability_constellation,
            "re_findings": [dataclasses.asdict(f) for f in re_result.findings],
            "re_summary": re_result.summary,
            "re_verdict": re_result.verdict,
            "re_coverage": re_result.re_coverage,
            # social engineering detection (standalone, does not affect fusion scores)
            "se_verdict": se_result.verdict,
            "se_score": se_result.se_score,
            "se_band": se_result.se_band,
            "se_confidence": se_result.confidence,
            "se_findings": [dataclasses.asdict(f) for f in se_result.findings],
            "se_summary": se_result.summary,
            "se_strings_analysed": se_result.strings_analysed,
            "se_sources_used": se_result.sources_used,
            "se_error": se_result.se_error,
            # intent spoofing (standalone signal — does not affect fusion scores yet)
            "impersonation": {
                "is_impersonation": spoof_result.is_impersonation,
                "confidence": spoof_result.confidence,
                "target_bank": spoof_result.target_bank,
                "target_app": spoof_result.target_app,
                "genuine_package": spoof_result.genuine_package,
                "actual_package": spoof_result.actual_package,
                "signals": [dataclasses.asdict(s) for s in spoof_result.signals],
                "verdict": spoof_result.verdict,
                "error": spoof_result.error,
            },
            # APK DNA fingerprinting (standalone — structural malware-family match)
            "dna": {
                "fingerprinted": dna_result.fingerprinted,
                "top_family": dna_result.top_family,
                "top_similarity": dna_result.top_similarity,
                "band": dna_result.band,
                "per_family": [dataclasses.asdict(f) for f in dna_result.per_family],
                "tlsh_nearest_family": dna_result.tlsh_nearest_family,
                "tlsh_distance": dna_result.tlsh_distance,
                "tlsh_clone": dna_result.tlsh_clone,
                "reference_size": dna_result.reference_size,
                "error": dna_result.error,
            },
            # Fraud-campaign clustering (standalone — analyzed-APK relationship graph)
            "campaign": {
                "is_campaign": campaign_result.is_campaign,
                "campaign_id": campaign_result.campaign_id,
                "size": campaign_result.size,
                "members": campaign_result.members,
                "links": [dataclasses.asdict(e) for e in campaign_result.links],
                "total_analyzed": campaign_result.total_analyzed,
                "error": campaign_result.error,
            },
            # ML classifier (real-dataset-trained — experimental, not in fusion)
            "ml_classification": ml_result,
            # feature-store evidence
            "fired_rules": [dataclasses.asdict(r) for r in fs_result.fired_rules],
            "declared_capabilities": fs_result.capabilities,
            "anti_vm_detected": fs_result.anti_vm_detected,
            "sandbox_evasion_suspected": fs_result.sandbox_evasion_suspected,
            "dynamic_ran": fs_result.dynamic_ran,
            "llm_error": re_result.llm_error,
        }

        # --- Stage 6: final GenAI report (synthesises ALL of the above) ----- #
        # Generated last so it can see every component's output in `result`.
        # Standalone narrative; degrades to {markdown: None, error: ...} if Ollama
        # is down — the deterministic scores and panels are unaffected.
        job.stage = "report_generation"
        emit({"stage": "report_generation"})
        result["report"] = report_generator.generate_report(result)
        emit({"stage": "report_generation",
              "report_ready": bool(result["report"].get("markdown"))})

        result_path = os.path.join(REPORTS_DIR, f"{apk_hash}.result.json")
        with open(result_path, "w") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False, default=str)

        # --- Done --------------------------------------------------------- #
        job.stage = "done"
        job.status = "done"
        emit({"stage": "done", "apk_hash": apk_hash})

    except Exception as exc:  # noqa: BLE001 - any failure becomes an SSE error event
        LOG.exception("Job %s failed", job.job_id)
        job.stage = "error"
        job.status = "error"
        job.detail = str(exc)
        emit({"stage": "error", "detail": str(exc)})


def _read_json(path: str) -> Dict[str, Any]:
    """Load a JSON file, returning {} if it is missing or malformed."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return {}


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


@app.post("/analyze")
async def analyze(apk: UploadFile = File(...)) -> Dict[str, str]:
    """Accept an APK upload, kick off background analysis, return a job_id.

    Validates the upload is an .apk (422 otherwise), saves it under a temp name in
    samples/, registers a JobState, launches run_job off the event loop, and
    returns immediately. Progress is consumed via GET /progress/{job_id}.
    """
    filename = apk.filename or ""
    if not filename.lower().endswith(".apk"):
        raise HTTPException(status_code=422, detail="Upload must be an .apk file.")

    job_id = uuid.uuid4().hex
    dest = os.path.join(SAMPLES_DIR, f"upload_{job_id}.apk")
    data = await apk.read()
    if not data:
        raise HTTPException(status_code=422, detail="Uploaded APK is empty.")
    with open(dest, "wb") as fh:
        fh.write(data)

    job = JobState(job_id=job_id)
    JOBS[job_id] = job

    # Capture the running loop so the worker thread can push events thread-safely.
    loop = asyncio.get_running_loop()

    def emit(event: dict) -> None:
        loop.call_soon_threadsafe(job.queue.put_nowait, event)

    asyncio.create_task(asyncio.to_thread(run_job, dest, job, emit))
    return {"job_id": job_id}


@app.get("/progress/{job_id}")
async def progress(job_id: str) -> StreamingResponse:
    """Stream SSE stage events for a job until it reaches done/error.

    404 if the job_id is unknown. Each event is ``data: {json}\\n\\n``; the stream
    ends after a ``done`` (carrying apk_hash) or ``error`` (carrying detail) event.
    """
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job_id.")

    async def event_stream():
        # The queue buffers every event from job start, so draining it in FIFO
        # order works whether the client subscribes early or late. No speculative
        # replay (which risked emitting a bare "done" without apk_hash).
        while True:
            try:
                event = await asyncio.wait_for(job.queue.get(), timeout=15.0)
            except asyncio.TimeoutError:
                if job.status in ("done", "error"):
                    # Queue already drained but the job is finished (e.g. an SSE
                    # reconnect): synthesize the terminal event so the client still
                    # learns the outcome instead of hanging.
                    term = {"stage": job.stage}
                    if job.apk_hash:
                        term["apk_hash"] = job.apk_hash
                    if job.detail:
                        term["detail"] = job.detail
                    yield f"data: {json.dumps(term)}\n\n"
                    break
                # Heartbeat keeps proxies from closing an idle SSE connection.
                yield ": keep-alive\n\n"
                continue
            # Enrich with a friendly label for the UI.
            if "label" not in event and event.get("stage") in STAGE_LABELS:
                event["label"] = STAGE_LABELS[event["stage"]]
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("stage") in ("done", "error"):
                break

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/analyses")
async def list_analyses() -> JSONResponse:
    """List analyzed APKs by scanning the persisted result JSONs (History view).

    The campaign store is out of scope now, so History is sourced directly from
    the ``reports/<hash>.result.json`` files this pipeline writes.
    """
    import glob
    rows = []
    for path in glob.glob(os.path.join(REPORTS_DIR, "*.result.json")):
        data = _read_json(path)
        if not data:
            continue
        rows.append({
            "apk_hash": data.get("apk_hash", os.path.basename(path).split(".")[0]),
            "apk_filename": data.get("apk_filename", ""),
            "package_name": data.get("package_name", ""),
            "fs_score": data.get("fs_score"),
            "fs_band": data.get("fs_band"),
            "code_band": data.get("code_band"),
            "recommended_action": data.get("recommended_action"),
            "quadrant": data.get("quadrant"),
            "analyzed_at": data.get("analyzed_at", ""),
        })
    rows.sort(key=lambda r: r.get("analyzed_at", ""), reverse=True)
    return JSONResponse(rows)


@app.get("/analyses/{apk_hash}")
async def get_analysis(apk_hash: str) -> JSONResponse:
    """Return the full persisted AnalysisResult for an APK hash (404 if absent)."""
    result_path = os.path.join(REPORTS_DIR, f"{apk_hash}.result.json")
    if not os.path.exists(result_path):
        raise HTTPException(status_code=404, detail="No analysis found for that hash.")
    return JSONResponse(_read_json(result_path))


# Mount the static frontend LAST so the API routes above take precedence over the
# catch-all "/" mount. (Served same-origin, so the frontend's API base is :8001.)
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
else:
    LOG.warning("Frontend directory not found at %s — UI will not be served.", FRONTEND_DIR)


if __name__ == "__main__":
    import uvicorn
    # Single worker is REQUIRED: the JOBS registry lives in process memory.
    uvicorn.run("main:app", host="0.0.0.0", port=8001, workers=1)
