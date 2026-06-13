import { useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { UploadCloud, Check, Loader2, AlertTriangle, ShieldCheck } from "lucide-react";
import { analyze, streamProgress, API_BASE } from "../lib/api.js";
import PageTransition from "../components/ui/PageTransition.jsx";

// Ordered pipeline stages -> labels (drives the stepper + progress bar).
const STAGES = [
  ["mobsf_static", "Static analysis"],
  ["mobsf_dynamic", "Dynamic analysis"],
  ["intent_spoofing", "Intent spoofing check"],
  ["feature_score", "Feature-store score"],
  ["ml_classification", "ML threat classification"],
  ["dna_fingerprinting", "DNA fingerprinting"],
  ["campaign_clustering", "Campaign clustering"],
  ["reverse_engineering", "Reverse engineering"],
  ["analysis_of_scores", "Score analysis"],
  ["report_generation", "Final report"],
  ["done", "Done"],
];

export default function Analyze() {
  const navigate = useNavigate();
  const [hot, setHot] = useState(false);
  const [running, setRunning] = useState(false);
  const [stageIdx, setStageIdx] = useState(-1);
  const [doneStages, setDoneStages] = useState({});
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState(null);
  const inputRef = useRef();

  const start = useCallback(
    async (file) => {
      if (!file) return;
      if (!file.name.toLowerCase().endsWith(".apk")) {
        setError("Please select an .apk file.");
        return;
      }
      setError(null);
      setFileName(file.name);
      setRunning(true);
      setStageIdx(0);
      setDoneStages({});
      try {
        const { job_id } = await analyze(file);
        streamProgress(job_id, (data) => {
          if (data.stage === "error") {
            setError(data.detail || "Analysis failed.");
            setRunning(false);
            return;
          }
          const idx = STAGES.findIndex((s) => s[0] === data.stage);
          if (idx >= 0) {
            setStageIdx(idx);
            setDoneStages((prev) => {
              const next = { ...prev };
              for (let i = 0; i < idx; i++) next[STAGES[i][0]] = true;
              return next;
            });
          }
          if (data.stage === "done") navigate("/result/" + data.apk_hash);
        });
      } catch (e) {
        setError(e.message);
        setRunning(false);
      }
    },
    [navigate]
  );

  const visibleStages = STAGES.filter((s) => s[0] !== "done");
  const pct =
    stageIdx < 0 ? 0 : Math.round(((stageIdx + (doneStages.done ? 1 : 0)) / (STAGES.length - 1)) * 100);

  return (
    <PageTransition>
      <div className="max-w-3xl mx-auto">
        {!running && (
          <motion.div
            onClick={() => inputRef.current.click()}
            onDragOver={(e) => {
              e.preventDefault();
              setHot(true);
            }}
            onDragLeave={() => setHot(false)}
            onDrop={(e) => {
              e.preventDefault();
              setHot(false);
              start(e.dataTransfer.files[0]);
            }}
            whileHover={{ scale: 1.005 }}
            className={
              "cursor-pointer rounded-xl2 border-2 border-dashed bg-surface-card text-center px-6 py-16 transition-colors " +
              (hot ? "border-boi-blue bg-boi-sky" : "border-slate-300 hover:border-boi-blue")
            }
          >
            <div className="mx-auto h-16 w-16 rounded-2xl bg-boi-sky text-boi-blue flex items-center justify-center mb-4">
              <UploadCloud size={32} />
            </div>
            <h2 className="text-xl font-700 text-slate-900" style={{ fontWeight: 700 }}>
              Drop an APK here to analyze
            </h2>
            <p className="text-slate-600 mt-1.5">
              or click to browse — static + dynamic + GenAI threat intelligence
            </p>
            <input
              ref={inputRef}
              type="file"
              accept=".apk"
              className="hidden"
              onChange={(e) => start(e.target.files[0])}
            />
          </motion.div>
        )}

        {running && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-xl2 border border-slate-200 bg-surface-card shadow-card p-7"
          >
            <div className="flex items-center gap-2 text-slate-900">
              <Loader2 className="animate-spin text-boi-blue" size={20} />
              <h2 className="text-lg font-700" style={{ fontWeight: 700 }}>
                Analyzing {fileName}…
              </h2>
            </div>

            <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden my-5">
              <motion.div
                className="h-full bg-gradient-to-r from-boi-blue to-boi-navy"
                animate={{ width: pct + "%" }}
                transition={{ duration: 0.4, ease: "easeOut" }}
              />
            </div>

            <ol className="space-y-2.5">
              {visibleStages.map((s, i) => {
                const done = doneStages[s[0]];
                const active = i === stageIdx;
                return (
                  <li key={s[0]} className="flex items-center gap-3">
                    <span
                      className={
                        "h-6 w-6 rounded-full flex items-center justify-center flex-none ring-1 ring-inset " +
                        (done
                          ? "bg-emerald-50 text-emerald-600 ring-emerald-200"
                          : active
                          ? "bg-boi-sky text-boi-blue ring-boi-blue/40"
                          : "bg-slate-50 text-slate-300 ring-slate-200")
                      }
                    >
                      {done ? (
                        <Check size={14} />
                      ) : active ? (
                        <Loader2 size={13} className="animate-spin" />
                      ) : (
                        <span className="h-1.5 w-1.5 rounded-full bg-current" />
                      )}
                    </span>
                    <span
                      className={
                        "text-sm " +
                        (done
                          ? "text-slate-600"
                          : active
                          ? "text-slate-900 font-600"
                          : "text-slate-500")
                      }
                      style={active ? { fontWeight: 600 } : undefined}
                    >
                      {s[1]}
                    </span>
                  </li>
                );
              })}
            </ol>

            <p className="text-slate-500 text-xs mt-5">
              Dynamic analysis runs the app on an emulator and can take a few minutes.
            </p>
          </motion.div>
        )}

        {error && (
          <div className="mt-5 flex items-start gap-2 rounded-xl2 border border-red-200 bg-red-50 text-red-700 px-4 py-3">
            <AlertTriangle size={18} className="flex-none mt-0.5" />
            <span>
              <b>Error:</b> {error}
            </span>
          </div>
        )}

        {!running && (
          <div className="mt-5 flex items-center justify-center gap-2 text-xs text-slate-500">
            <ShieldCheck size={14} className="text-boi-saffron" />
            Backend: {API_BASE || "same-origin"} · MobSF expected on :8000 · uvicorn --workers 1
          </div>
        )}
      </div>
    </PageTransition>
  );
}
