import Gauge from "../components/ui/Gauge.jsx";
import { bandColor } from "../lib/theme.js";

/** Two scores side by side: deterministic Feature-Store vs AI Code-Behaviour. */
export default function ScoreCards({ result }) {
  const fsScore = result.fs_score != null ? result.fs_score : result.rule_score || 0;
  const fsBand = result.fs_band || result.risk_band || "Low";
  const codeBand = result.code_band || null;
  const codeScore = result.code_score;
  const reUnavailable = result.re_unavailable || codeBand == null;
  const catalog = result.behaviour_catalog || [];
  const declared = (result.declared_capabilities || []).length;

  return (
    <div className="grid gap-4 sm:grid-cols-2 mt-4">
      {/* Feature-Store Score */}
      <div className="bg-surface-card border border-slate-200 rounded-xl2 shadow-card p-5 flex items-center gap-5">
        <Gauge score={fsScore} band={fsBand} size={108} />
        <div>
          <h4 className="text-xs uppercase tracking-wide text-slate-500 font-600" style={{ fontWeight: 600 }}>
            Feature-Store Score
          </h4>
          <div className="text-sm mt-1 text-slate-700">
            Deterministic · what the app <b>declares</b>
          </div>
          <div className="text-[12.5px] text-slate-500 mt-1.5">
            {declared} declared capabilities · same input → same score
          </div>
        </div>
      </div>

      {/* Code-Behaviour Score */}
      <div className="bg-surface-card border border-slate-200 rounded-xl2 shadow-card p-5 flex items-center gap-5">
        <div
          className="flex-none rounded-xl2 px-6 py-4 text-2xl font-800"
          style={
            reUnavailable
              ? { fontWeight: 700, fontSize: 16, color: "#64748b", background: "#f1f5f9" }
              : {
                  fontWeight: 800,
                  background: bandColor(codeBand),
                  color: codeBand === "Medium" ? "#0f172a" : "#ffffff",
                }
          }
        >
          {reUnavailable ? "N/A" : codeBand}
        </div>
        <div>
          <h4 className="text-xs uppercase tracking-wide text-slate-500 font-600 flex items-center gap-2" style={{ fontWeight: 600 }}>
            Code-Behaviour Score
            <span className="text-[11.5px] normal-case rounded-full px-2 py-0.5 ring-1 ring-boi-blue/40 text-boi-blue">
              AI-derived · indicative
            </span>
          </h4>
          <div className="text-sm mt-1 text-slate-700">
            Reverse-engineered · what the code <b>does</b>
          </div>
          <div className="text-[12.5px] text-slate-500 mt-1.5">
            {reUnavailable
              ? "Reverse engineering did not run — verdict from the Feature-Store Score alone."
              : `band shown (raw ${codeScore}) · ${catalog.length} behaviours confirmed in code`}
          </div>
        </div>
      </div>
    </div>
  );
}
