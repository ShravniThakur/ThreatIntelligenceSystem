// Single source of truth for severity/action colors, shared by every panel and
// chart. Hex values mirror the `sev`/`boi` tokens in tailwind.config.js (charts
// and inline SVG need raw hex, not Tailwind classes).

export const BAND_COLOR = {
  Low: "#2e7d32",
  Medium: "#f9a825",
  High: "#ef6c00",
  Critical: "#c8102e",
};

export const ACTION_COLOR = {
  block: "#c8102e",
  escalate_manual_review: "#ef6c00",
  monitor: "#f9a825",
  clear: "#2e7d32",
};

export const BOI = {
  navy: "#1a2b5c",
  blue: "#1e5eb8",
  saffron: "#f57c00",
  red: "#c8102e",
};

export const bandColor = (band) => BAND_COLOR[band] || "#94a3b8";
export const actionColor = (action) => ACTION_COLOR[action] || "#94a3b8";

// Solid severity pills (filled bg + white text), matching the inspiration UI.
// Medium uses dark text for contrast on yellow.
export const BAND_PILL = {
  Low: "bg-sev-low text-white",
  Medium: "bg-sev-medium text-slate-900",
  High: "bg-sev-high text-white",
  Critical: "bg-sev-critical text-white",
};
export const bandPill = (band) => BAND_PILL[band] || "bg-slate-500 text-white";

export const prettify = (s) => String(s || "").replace(/_/g, " ");
