import { ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";

/**
 * Detected -> prominent red banner. Otherwise a compact always-visible status
 * (clean / detector-degraded) so the check is never invisible. No-ops only for
 * older result JSONs that predate the impersonation block.
 */
export default function ImpersonationAlert({ result }) {
  const imp = result.impersonation;
  if (!imp) return null;

  if (imp.is_impersonation) {
    return (
      <div className="mt-4 rounded-xl2 border-2 border-boi-red bg-gradient-to-b from-red-50 to-white p-5 animate-impPulse">
        <div className="flex items-center gap-2 text-boi-red font-800 text-lg" style={{ fontWeight: 800 }}>
          <ShieldAlert size={22} /> IMPERSONATION DETECTED
        </div>
        <div className="mt-1.5 text-[17px] text-slate-800">
          This APK is impersonating <b>{imp.target_app}</b>
          {imp.target_bank ? ` (${imp.target_bank})` : ""}
        </div>
        <div className="mt-3 grid gap-1.5 text-[14.5px] leading-relaxed">
          <div>
            <span className="text-slate-600 inline-block min-w-[150px]">Genuine package:</span>
            <span className="font-mono">{imp.genuine_package || "—"}</span>
          </div>
          <div>
            <span className="text-slate-600 inline-block min-w-[150px]">This package:</span>
            <span className="font-mono">{imp.actual_package || "—"}</span>
          </div>
          <div>
            <span className="text-slate-600 inline-block min-w-[150px]">Certificate:</span>
            <span className="text-boi-red font-700" style={{ fontWeight: 700 }}>
              MISMATCH — not signed by {imp.target_bank || "the genuine bank"}
            </span>
          </div>
          <div>
            <span className="text-slate-600 inline-block min-w-[150px]">Confidence:</span>
            Definitive
          </div>
        </div>
      </div>
    );
  }

  if (imp.error) {
    return (
      <div className="mt-4 flex items-center gap-2 rounded-xl2 border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-card">
        <ShieldQuestion size={18} /> Intent-spoofing check unavailable — {imp.error}
      </div>
    );
  }

  return (
    <div className="mt-4 flex flex-wrap items-center gap-3 rounded-xl2 border border-emerald-200 bg-emerald-50 p-4 text-sm shadow-card">
      <span className="flex items-center gap-2 text-emerald-700 font-700" style={{ fontWeight: 700 }}>
        <ShieldCheck size={18} /> Identity verified · no impersonation
      </span>
      <span className="text-slate-600">
        {imp.verdict || "Not impersonating any known bank app."}
      </span>
    </div>
  );
}
