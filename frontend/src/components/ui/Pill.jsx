import { bandPill, prettify } from "../../lib/theme.js";

/** Generic pill. Solid by default — pass bg/text classes via className. */
export default function Pill({ className = "", children }) {
  return (
    <span
      className={
        "inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-700 " +
        className
      }
      style={{ fontWeight: 700 }}
    >
      {children}
    </span>
  );
}

/** Solid severity band pill (Low/Medium/High/Critical). */
export function BandPill({ band }) {
  if (!band) return <span className="text-slate-500">—</span>;
  return <Pill className={bandPill(band)}>{band}</Pill>;
}

/** Solid recommended-action pill, colored by action. */
export function ActionPill({ action }) {
  const map = {
    block: "bg-sev-critical text-white",
    escalate_manual_review: "bg-sev-high text-white",
    monitor: "bg-sev-medium text-slate-900",
    clear: "bg-sev-low text-white",
  };
  return (
    <Pill className={map[action] || "bg-slate-500 text-white"}>{prettify(action)}</Pill>
  );
}
