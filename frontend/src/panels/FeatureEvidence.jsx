import { Database } from "lucide-react";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import Card from "../components/ui/Card.jsx";
import { prettify } from "../lib/theme.js";

// Solid weight pill, graduated by the rule's contribution weight.
function weightPill(w) {
  if (w >= 15) return "bg-sev-critical text-white";
  if (w >= 10) return "bg-sev-high text-white";
  if (w >= 6) return "bg-sev-medium text-slate-900";
  return "bg-sev-low text-white";
}

/** Feature-Store evidence (fired capability rules). */
export default function FeatureEvidence({ result }) {
  const fired = result.fired_rules || [];
  return (
    <section className="mt-5">
      <SectionTitle icon={Database}>
        Feature-Store Evidence — {fired.length} declared capabilities
      </SectionTitle>
      {fired.length === 0 && (
        <Card className="p-4 text-slate-600">No capability rules fired from the feature set.</Card>
      )}
      <div className="grid gap-3 sm:grid-cols-2 items-start">
        {fired.map((r, i) => (
          <Card key={i} className="p-4">
            <div className="flex items-center gap-2 font-700 text-[17px] text-slate-900" style={{ fontWeight: 700 }}>
              {prettify(r.capability)}
              <span className={"rounded-full px-2 py-0.5 text-[12.5px] font-700 " + weightPill(r.weight)} style={{ fontWeight: 700 }}>
                weight {r.weight}
              </span>
            </div>
            {r.mitre && (
              <div className="text-[14.5px] text-slate-700 mt-1.5">
                <b className="text-slate-600 font-600" style={{ fontWeight: 600 }}>MITRE:</b> {r.mitre}
              </div>
            )}
            <div className="text-[13.5px] text-slate-500 mt-1.5">
              <b className="font-600" style={{ fontWeight: 600 }}>Evidence:</b> {r.evidence}
            </div>
          </Card>
        ))}
      </div>
    </section>
  );
}
