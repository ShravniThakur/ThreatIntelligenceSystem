import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Inbox } from "lucide-react";
import { listAnalyses } from "../lib/api.js";
import PageTransition from "../components/ui/PageTransition.jsx";
import { MotionCard } from "../components/ui/Card.jsx";
import { BandPill, ActionPill } from "../components/ui/Pill.jsx";
import { bandColor } from "../lib/theme.js";

export default function History() {
  const navigate = useNavigate();
  const [rows, setRows] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    listAnalyses().then(setRows).catch((e) => setErr(e.message));
  }, []);

  if (err)
    return (
      <PageTransition>
        <div className="rounded-xl2 border border-red-200 bg-red-50 text-red-700 p-4">
          Could not load history: {err}
        </div>
      </PageTransition>
    );

  if (rows === null)
    return (
      <PageTransition>
        <div className="text-center text-slate-500 py-20">Loading history…</div>
      </PageTransition>
    );

  if (rows.length === 0)
    return (
      <PageTransition>
        <div className="text-center text-slate-500 py-20">
          <Inbox size={32} className="mx-auto mb-3" />
          No analyses yet. Upload an APK to get started.
        </div>
      </PageTransition>
    );

  return (
    <PageTransition>
      <MotionCard className="overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-50 text-slate-600 text-[12.5px] uppercase tracking-wide">
              <th className="text-left font-600 px-5 py-3" style={{ fontWeight: 600 }}>Filename</th>
              <th className="text-left font-600 px-3 py-3" style={{ fontWeight: 600 }}>FS Score</th>
              <th className="text-left font-600 px-3 py-3" style={{ fontWeight: 600 }}>FS Band</th>
              <th className="text-left font-600 px-3 py-3" style={{ fontWeight: 600 }}>Code Band</th>
              <th className="text-left font-600 px-3 py-3" style={{ fontWeight: 600 }}>Action</th>
              <th className="text-left font-600 px-5 py-3" style={{ fontWeight: 600 }}>Analyzed</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.map((r) => {
              const fsScore = r.fs_score != null ? r.fs_score : r.risk_score;
              const fsBand = r.fs_band || r.risk_band;
              return (
                <tr
                  key={r.apk_hash}
                  onClick={() => navigate("/result/" + r.apk_hash)}
                  className="cursor-pointer hover:bg-boi-sky/50 transition-colors"
                >
                  <td className="px-5 py-3.5 text-slate-800 max-w-[280px] truncate">
                    {r.apk_filename || r.package_name || (r.apk_hash || "").slice(0, 12)}
                  </td>
                  <td className="px-3 py-3.5 font-700" style={{ fontWeight: 700, color: bandColor(fsBand) }}>
                    {fsScore != null ? fsScore : "—"}
                  </td>
                  <td className="px-3 py-3.5">
                    <BandPill band={fsBand} />
                  </td>
                  <td className="px-3 py-3.5" style={{ color: bandColor(r.code_band) }}>
                    {r.code_band || "—"}
                  </td>
                  <td className="px-3 py-3.5">
                    {r.recommended_action ? <ActionPill action={r.recommended_action} /> : "—"}
                  </td>
                  <td className="px-5 py-3.5 text-slate-500 text-xs">
                    {(r.analyzed_at || "").replace("T", " ").slice(0, 19)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </MotionCard>
    </PageTransition>
  );
}
