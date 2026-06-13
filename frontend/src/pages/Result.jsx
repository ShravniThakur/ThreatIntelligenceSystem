import { useEffect, useState, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, AlertTriangle, FileSearch, ChevronRight, LayoutList } from "lucide-react";
import { motion } from "framer-motion";
import { getAnalysis } from "../lib/api.js";
import PageTransition from "../components/ui/PageTransition.jsx";
import Gauge from "../components/ui/Gauge.jsx";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import { BandPill, ActionPill } from "../components/ui/Pill.jsx";
import { prettify, actionColor } from "../lib/theme.js";

import ImpersonationAlert from "../panels/ImpersonationAlert.jsx";
import ScoreCards from "../panels/ScoreCards.jsx";
import ReportPanel from "../panels/ReportPanel.jsx";
import { SECTIONS } from "../panels/sections.jsx";

export default function Result() {
  const { hash } = useParams();
  const navigate = useNavigate();
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const menuRef = useRef(null);
  const [menuHeight, setMenuHeight] = useState(null);

  useEffect(() => {
    let live = true;
    setResult(null);
    setError(null);
    getAnalysis(hash)
      .then((d) => live && setResult(d))
      .catch((e) => live && setError(e.message));
    window.scrollTo(0, 0);
    return () => {
      live = false;
    };
  }, [hash]);

  // Match the report column's height to the component menu (lg+ only) so both
  // columns end at the same level; the report then scrolls inside its card.
  useEffect(() => {
    if (!result) return;
    const measure = () => {
      if (window.innerWidth >= 1024 && menuRef.current) setMenuHeight(menuRef.current.offsetHeight);
      else setMenuHeight(null);
    };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [result]);

  if (error)
    return (
      <PageTransition>
        <div className="flex items-center gap-2 rounded-xl2 border border-red-200 bg-red-50 text-red-700 p-4">
          <AlertTriangle size={18} /> {error}
        </div>
      </PageTransition>
    );

  if (!result)
    return (
      <PageTransition>
        <div className="text-center text-slate-500 py-20">
          <FileSearch className="mx-auto mb-3 animate-pulse" size={32} />
          Loading analysis…
        </div>
      </PageTransition>
    );

  const fsScore = result.fs_score != null ? result.fs_score : result.rule_score || 0;
  const fsBand = result.fs_band || result.risk_band || "Low";
  const action =
    result.recommended_action ||
    (result.classification_detail && result.classification_detail.recommended_action) ||
    "escalate_manual_review";
  const reasoning =
    result.reasoning ||
    (result.classification_detail && result.classification_detail.reasoning) ||
    "";

  const sections = SECTIONS; // every component is listed, detected or not

  return (
    <PageTransition>
      <button
        onClick={() => navigate("/analyze")}
        className="inline-flex items-center gap-1.5 text-sm text-boi-blue font-600 hover:underline mb-4"
        style={{ fontWeight: 600 }}
      >
        <ArrowLeft size={16} /> Analyze Another APK
      </button>

      <ImpersonationAlert result={result} />

      {/* Header: identity + verdict */}
      <div className="mt-4 flex flex-wrap items-center gap-6 bg-surface-card border border-slate-200 rounded-xl2 shadow-card p-6">
        <Gauge score={fsScore} band={fsBand} />
        <div className="flex-1 min-w-[260px]">
          <div className="text-lg font-700 text-slate-900 break-all" style={{ fontWeight: 700 }}>
            {result.apk_filename || result.package_name || result.apk_hash}
          </div>
          <div className="text-[12.5px] text-slate-500 break-all mt-1 font-mono">
            SHA256: {result.apk_hash}
          </div>
          <div className="mt-3.5 flex flex-wrap gap-2.5">
            <BandPill band={fsBand} />
            {result.quadrant && (
              <span className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-700 bg-boi-blue text-white" style={{ fontWeight: 700 }}>
                {prettify(result.quadrant)}
              </span>
            )}
            <ActionPill action={action} />
          </div>
        </div>
      </div>

      <ScoreCards result={result} />

      {(reasoning || result.quadrant) && (
        <div
          className="mt-4 rounded-xl2 p-5 shadow-card"
          style={{
            background: actionColor(action),
            color: action === "monitor" ? "#0f172a" : "#ffffff",
          }}
        >
          <div className="text-[14.5px]" style={{ fontWeight: 700 }}>
            <span style={{ fontWeight: 800 }}>SCORE ANALYSIS</span> · quadrant:{" "}
            <b style={{ fontWeight: 800 }}>{prettify(result.quadrant || "—")}</b> · recommended action:{" "}
            <b style={{ fontWeight: 800 }}>{prettify(action)}</b>
          </div>
          {reasoning && (
            <div className="mt-2.5 text-sm leading-relaxed" style={{ opacity: 0.95, fontWeight: 700 }}>
              {reasoning}
            </div>
          )}
        </div>
      )}

      {result.llm_error && (
        <div className="mt-4 flex items-start gap-2 rounded-xl2 border border-amber-200 bg-amber-50 text-amber-800 text-[14.5px] px-4 py-3">
          <AlertTriangle size={16} className="flex-none mt-0.5" />
          Code-behaviour (LLM/jadx) layer degraded ({result.llm_error}). The deterministic
          Feature-Store Score and its fired rules are unaffected.
        </div>
      )}

      {/* Hub: component menu (left) + full report (right) */}
      <div className="mt-9 grid gap-5 lg:grid-cols-3 items-start">
        {/* Component menu */}
        <div ref={menuRef} className="lg:sticky lg:top-20">
          <SectionTitle icon={LayoutList}>Analysis Components</SectionTitle>
          <div className="bg-surface-card border border-slate-200 rounded-xl2 shadow-card overflow-hidden divide-y divide-slate-100">
            {sections.map((s, i) => {
              const has = s.available(result);
              return (
                <motion.button
                  key={s.key}
                  whileHover={{ x: 3 }}
                  onClick={() => navigate(`/result/${hash}/section/${s.key}`)}
                  className={
                    "w-full flex items-center gap-3 px-5 py-3.5 text-left group transition-colors hover:bg-boi-sky " +
                    (i % 2 === 0 ? "bg-white" : "bg-slate-200")
                  }
                >
                  <span
                    className={
                      "h-9 w-9 rounded-lg flex items-center justify-center flex-none " +
                      (has ? "bg-boi-sky text-boi-blue" : "bg-slate-100 text-slate-400")
                    }
                  >
                    <s.icon size={18} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm text-slate-900 font-600 leading-tight" style={{ fontWeight: 600 }}>
                      {s.title}
                    </span>
                    <span
                      className={"block text-[12px] truncate " + (has ? "text-slate-500" : "text-slate-400")}
                    >
                      {has ? s.subtitle(result) : "Not detected"}
                    </span>
                  </span>
                  <ChevronRight size={18} className="text-slate-300 group-hover:text-boi-blue transition-colors flex-none" />
                </motion.button>
              );
            })}
          </div>
        </div>

        {/* Full GenAI report — capped to the menu height, scrolls internally */}
        <div
          className="lg:col-span-2 lg:sticky lg:top-20 [&>section]:!mt-0"
          style={menuHeight ? { height: menuHeight } : undefined}
        >
          <ReportPanel result={result} fill />
        </div>
      </div>
    </PageTransition>
  );
}
