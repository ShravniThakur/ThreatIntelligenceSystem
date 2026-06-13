import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Microscope, X, ChevronRight } from "lucide-react";
import SectionTitle from "../components/ui/SectionTitle.jsx";

const VERDICT_BADGE = {
  malicious: "bg-sev-critical text-white",
  suspicious: "bg-sev-high text-white",
  benign: "bg-sev-low text-white",
};
const VERDICT_DOT = {
  malicious: "#c8102e",
  suspicious: "#ef6c00",
  benign: "#2e7d32",
};
const CONF_BADGE = {
  high: "text-red-600 ring-red-200",
  medium: "text-amber-600 ring-amber-200",
  low: "text-slate-600 ring-slate-200",
};

function VerdictPill({ verdict }) {
  return (
    <span
      className={
        "inline-flex items-center rounded-full px-2.5 py-0.5 text-[12.5px] font-700 capitalize " +
        (VERDICT_BADGE[verdict] || VERDICT_BADGE.benign)
      }
      style={{ fontWeight: 700 }}
    >
      {verdict}
    </span>
  );
}

/** Detail modal — blurred, dimmed backdrop; closes on backdrop click / Esc / ×. */
function FindingModal({ finding, onClose }) {
  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const f = finding;
  const shortClass = (f.class_name || "").split(".").pop() || "";

  return createPortal(
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm"
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 12 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.97, y: 8 }}
        transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-xl max-h-[85vh] overflow-auto bg-white rounded-xl2 shadow-cardhover border border-slate-200"
      >
        <div className="flex items-start justify-between gap-3 px-6 pt-5 pb-3 border-b border-slate-100 sticky top-0 bg-white">
          <div className="min-w-0">
            <div className="text-[12.5px] uppercase tracking-wide text-slate-500">{shortClass}</div>
            <div className="font-mono text-[17px] text-slate-900 font-700 break-all" style={{ fontWeight: 700 }}>
              {f.method}
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <VerdictPill verdict={f.verdict} />
              <span
                className={
                  "rounded-full px-2 py-0.5 text-[12.5px] ring-1 ring-inset " +
                  (CONF_BADGE[f.confidence] || CONF_BADGE.low)
                }
              >
                {f.confidence} confidence
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="flex-none h-9 w-9 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-500 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        <div className="px-6 py-4 space-y-3">
          <div className="text-[14.5px] text-slate-700 leading-relaxed">
            <div className="text-slate-500 font-600 mb-0.5" style={{ fontWeight: 600 }}>What it does</div>
            {f.what_it_does}
          </div>
          <div className="text-[14.5px] text-slate-700 leading-relaxed">
            <div className="text-slate-500 font-600 mb-0.5" style={{ fontWeight: 600 }}>Data accessed</div>
            {f.data_accessed}
          </div>
          {f.behaviour_tags && f.behaviour_tags.length > 0 && (
            <div>
              <div className="text-slate-500 font-600 mb-1 text-[14.5px]" style={{ fontWeight: 600 }}>Behaviour tags</div>
              <div className="flex flex-wrap gap-1.5">
                {f.behaviour_tags.map((t, j) => (
                  <span key={j} className="rounded-md bg-boi-blue text-white px-2 py-0.5 text-[12.5px] font-600" style={{ fontWeight: 600 }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
          <div className="text-[13.5px] text-slate-500 pt-1 border-t border-slate-100">
            <div className="mt-2">
              <b className="font-600 text-slate-600" style={{ fontWeight: 600 }}>Location:</b> {f.location}
            </div>
            <div className="mt-1">
              <b className="font-600 text-slate-600" style={{ fontWeight: 600 }}>Flagged:</b> {f.evidence}
            </div>
          </div>
        </div>
      </motion.div>
    </motion.div>,
    document.body
  );
}

/** Compact 2-column grid of findings; click a card -> detail modal. */
export default function ReFindings({ result }) {
  const findings = result.re_findings || [];
  const [open, setOpen] = useState(null);
  if (findings.length === 0) return null;

  return (
    <section className="mt-5">
      <SectionTitle icon={Microscope}>
        Reverse-Engineering Findings — {findings.length} methods
      </SectionTitle>

      <div className="grid gap-3 sm:grid-cols-2">
        {findings.map((f, i) => {
          const shortClass = (f.class_name || "").split(".").pop() || "";
          return (
            <button
              key={i}
              id={`finding-${i}`}
              onClick={() => setOpen(i)}
              className="group text-left bg-surface-card border border-slate-200 rounded-xl2 shadow-card hover:shadow-cardhover transition-shadow p-4 flex items-center gap-3 scroll-mt-20"
            >
              <span className="h-2.5 w-2.5 rounded-full flex-none" style={{ background: VERDICT_DOT[f.verdict] || VERDICT_DOT.benign }} />
              <div className="min-w-0 flex-1">
                <div className="font-mono text-[15px] text-slate-900 font-600 truncate" style={{ fontWeight: 600 }}>
                  {f.method}
                </div>
                <div className="text-[12.5px] text-slate-500 truncate">{shortClass}</div>
              </div>
              <VerdictPill verdict={f.verdict} />
              <ChevronRight size={16} className="text-slate-300 group-hover:text-boi-blue transition-colors flex-none" />
            </button>
          );
        })}
      </div>

      <AnimatePresence>
        {open != null && <FindingModal finding={findings[open]} onClose={() => setOpen(null)} />}
      </AnimatePresence>
    </section>
  );
}
