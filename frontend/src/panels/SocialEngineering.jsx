import { Megaphone, ShieldCheck, AlertTriangle } from "lucide-react";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import Card from "../components/ui/Card.jsx";
import { BandPill } from "../components/ui/Pill.jsx";
import { prettify } from "../lib/theme.js";

// Solid technique badges (fraud-UI tactics).
const TECH_BADGE = {
  impersonation: "bg-sev-critical text-white",
  fake_otp: "bg-sev-critical text-white",
  phishing_url: "bg-sev-high text-white",
  urgency: "bg-sev-medium text-slate-900",
  authority_claim: "bg-boi-blue text-white",
};

/**
 * Social-engineering (fraud-UI) detection. Standalone signal — does not affect
 * the fusion score. Always renders a state: flagged findings, a clean "nothing
 * detected" confirmation, or a degraded/error note.
 */
export default function SocialEngineering({ result }) {
  const verdict = result.se_verdict;
  const findings = result.se_findings || [];
  const band = result.se_band;

  return (
    <section>
      <SectionTitle icon={Megaphone}>Social Engineering</SectionTitle>

      {result.se_error ? (
        <Card className="p-4 flex items-center gap-2 text-slate-600">
          <AlertTriangle size={18} className="text-amber-500" /> Social-engineering check
          unavailable — {result.se_error}
        </Card>
      ) : findings.length === 0 ? (
        <Card className="p-4 flex items-center gap-2 border-emerald-200 bg-emerald-50">
          <ShieldCheck size={18} className="text-emerald-600 flex-none" />
          <span className="text-emerald-700 font-700" style={{ fontWeight: 700 }}>
            No fraud-UI strings detected
          </span>
          <span className="text-slate-600">
            {result.se_summary ||
              `Scanned ${result.se_strings_analysed ?? 0} UI strings; no impersonation, fake-OTP, or phishing prompts flagged.`}
          </span>
        </Card>
      ) : (
        <Card className="p-5">
          <div className="flex flex-wrap items-center gap-3 mb-3">
            <BandPill band={band} />
            <span className="text-sm text-slate-700">
              {prettify(verdict || "flagged")} · {findings.length} suspicious UI string
              {findings.length === 1 ? "" : "s"}
              {result.se_strings_analysed ? ` of ${result.se_strings_analysed} analysed` : ""}
            </span>
          </div>
          {result.se_summary && (
            <div className="text-[14.5px] text-slate-700 mb-3 leading-relaxed">{result.se_summary}</div>
          )}
          <div className="space-y-3">
            {findings.map((f, i) => (
              <div key={i} className="rounded-xl border border-slate-200 bg-white p-3.5 shadow-card">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={"rounded-full px-2.5 py-0.5 text-[12.5px] font-700 " + (TECH_BADGE[f.technique] || "bg-slate-500 text-white")}
                    style={{ fontWeight: 700 }}
                  >
                    {prettify(f.technique)}
                  </span>
                  <span className="rounded-full px-2 py-0.5 text-[12px] ring-1 ring-inset ring-slate-200 text-slate-600">
                    {f.confidence} confidence
                  </span>
                  <span className="text-[12px] text-slate-500">{f.source}</span>
                </div>
                <div className="mt-2 text-[14.5px] text-slate-900 font-600" style={{ fontWeight: 600 }}>
                  “{f.text}”
                </div>
                <div className="mt-1 text-[13.5px] text-slate-700 leading-relaxed">{f.explanation}</div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </section>
  );
}
