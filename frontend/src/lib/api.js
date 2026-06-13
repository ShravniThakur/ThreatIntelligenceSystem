// Central API client. In dev, VITE_API_BASE is unset -> default to the FastAPI
// backend on :8001 (CORS is open there). In a same-origin production build,
// set VITE_API_BASE="" so calls are relative and work under the static mount.
export const API_BASE =
  import.meta.env.VITE_API_BASE !== undefined
    ? import.meta.env.VITE_API_BASE
    : "http://localhost:8001";

const url = (path) => `${API_BASE}${path}`;

/** POST an APK file -> { job_id }. Throws Error(detail) on failure. */
export async function analyze(file) {
  const fd = new FormData();
  fd.append("apk", file);
  const r = await fetch(url("/analyze"), { method: "POST", body: fd });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.detail || `Upload failed (${r.status})`);
  }
  return r.json();
}

/**
 * Subscribe to SSE progress for a job. Calls onStage(data) for every event.
 * `data.stage === "done"` carries apk_hash; `"error"` carries detail.
 * Returns the EventSource so the caller can close it.
 */
export function streamProgress(jobId, onStage) {
  const es = new EventSource(url(`/progress/${jobId}`));
  es.onmessage = (ev) => {
    let data;
    try {
      data = JSON.parse(ev.data);
    } catch {
      return;
    }
    onStage(data);
    if (data.stage === "done" || data.stage === "error") es.close();
  };
  es.onerror = () => {
    /* connection blip — SSE auto-reconnects until done/error */
  };
  return es;
}

/** GET the history rows (newest first). */
export async function listAnalyses() {
  const r = await fetch(url("/analyses"));
  if (!r.ok) throw new Error(`Could not load history (${r.status})`);
  return r.json();
}

/** GET the full AnalysisResult for a hash. */
export async function getAnalysis(hash) {
  const r = await fetch(url(`/analyses/${hash}`));
  if (!r.ok) throw new Error(`Result not found (${r.status})`);
  return r.json();
}
