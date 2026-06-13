import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, AlertTriangle, FileSearch, ChevronLeft, ChevronRight, Inbox } from "lucide-react";
import { getAnalysis } from "../lib/api.js";
import PageTransition from "../components/ui/PageTransition.jsx";
import { BandPill } from "../components/ui/Pill.jsx";
import { SECTIONS, findSection } from "../panels/sections.jsx";

export default function ResultSection() {
  const { hash, key } = useParams();
  const navigate = useNavigate();
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

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
  }, [hash, key]);

  const backToResult = () => navigate(`/result/${hash}`);

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
          Loading…
        </div>
      </PageTransition>
    );

  const section = findSection(key);
  if (!section)
    return (
      <PageTransition>
        <button
          onClick={backToResult}
          className="inline-flex items-center gap-1.5 text-sm text-boi-blue font-600 hover:underline mb-4"
          style={{ fontWeight: 600 }}
        >
          <ArrowLeft size={16} /> Back to report
        </button>
        <div className="rounded-xl2 border border-slate-200 bg-white p-8 text-center text-slate-500 shadow-card">
          Unknown component.
        </div>
      </PageTransition>
    );

  // prev/next over ALL components (every one is navigable, detected or not).
  const idx = SECTIONS.findIndex((s) => s.key === key);
  const prev = SECTIONS[idx - 1];
  const next = SECTIONS[idx + 1];
  const Panel = section.Panel;
  const hasData = section.available(result);

  return (
    <PageTransition>
      <button
        onClick={backToResult}
        className="inline-flex items-center gap-1.5 text-sm text-boi-blue font-600 hover:underline mb-4"
        style={{ fontWeight: 600 }}
      >
        <ArrowLeft size={16} /> Back to report
      </button>

      {/* APK context header */}
      <div className="flex flex-wrap items-center gap-3 bg-surface-card border border-slate-200 rounded-xl2 shadow-card px-5 py-4 mb-6">
        <span className="h-10 w-10 rounded-lg bg-boi-sky text-boi-blue flex items-center justify-center flex-none">
          <section.icon size={20} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-[12px] uppercase tracking-wide text-slate-500">Component report</div>
          <div className="text-slate-900 font-700 truncate mt-1.5" style={{ fontWeight: 700 }}>
            {result.apk_filename || result.package_name || result.apk_hash}
          </div>
        </div>
        <BandPill band={result.fs_band || result.risk_band} />
      </div>

      {/* The component panel, or a clean empty state when not detected */}
      {hasData ? (
        <Panel result={result} />
      ) : (
        <section>
          <div className="flex items-center gap-2.5 border-b border-slate-200 pb-2 mb-3 text-[19px] font-700 tracking-tight text-boi-navy" style={{ fontWeight: 700 }}>
            <section.icon size={19} className="text-boi-blue" />
            {section.title}
          </div>
          <div className="rounded-xl2 border border-slate-200 bg-white p-10 text-center shadow-card">
            <Inbox className="mx-auto mb-3 text-slate-300" size={34} />
            <div className="text-slate-900 font-700" style={{ fontWeight: 700 }}>
              Not detected for this APK
            </div>
            <div className="text-slate-500 text-sm mt-1.5">
              This component ran but found no relevant signals in this sample.
            </div>
          </div>
        </section>
      )}

      {/* Prev / next component nav */}
      <div className="mt-6 flex items-center justify-between gap-3">
        {prev ? (
          <button
            onClick={() => navigate(`/result/${hash}/section/${prev.key}`)}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2.5 text-sm text-slate-700 font-600 hover:border-boi-blue hover:text-boi-blue transition-colors shadow-card"
            style={{ fontWeight: 600 }}
          >
            <ChevronLeft size={16} /> {prev.title}
          </button>
        ) : (
          <span />
        )}
        {next ? (
          <button
            onClick={() => navigate(`/result/${hash}/section/${next.key}`)}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2.5 text-sm text-slate-700 font-600 hover:border-boi-blue hover:text-boi-blue transition-colors shadow-card text-right"
            style={{ fontWeight: 600 }}
          >
            {next.title} <ChevronRight size={16} />
          </button>
        ) : (
          <span />
        )}
      </div>
    </PageTransition>
  );
}
