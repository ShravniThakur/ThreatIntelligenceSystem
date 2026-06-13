import { Flag } from "lucide-react";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import Card from "../components/ui/Card.jsx";
import { prettify } from "../lib/theme.js";

/** Capability gap: found in code but not declared (the interesting case). */
export default function CapabilityGap({ result }) {
  const gap = result.capability_gap || {};
  const reOnly = gap.re_only || [];
  const declaredOnly = gap.declared_only || [];
  if (reOnly.length === 0 && declaredOnly.length === 0) return null;

  return (
    <section>
      <SectionTitle icon={Flag}>Capability Gap</SectionTitle>
      {reOnly.length > 0 && (
        <Card className="p-4 border-orange-300 bg-orange-50/50">
          <div className="font-700 text-orange-700 flex items-center gap-1.5" style={{ fontWeight: 700 }}>
            <Flag size={15} /> Found in code, NOT declared by features
          </div>
          <div className="text-[14.5px] text-slate-600 mt-2 leading-relaxed">
            These behaviours were confirmed by reverse engineering but no MobSF feature flagged
            them — the case the two-score design exists to surface.
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {reOnly.map((c, i) => (
              <span
                key={i}
                className="rounded-md bg-sev-critical text-white px-2.5 py-1 text-xs font-600"
                style={{ fontWeight: 600 }}
              >
                {prettify(c)}
              </span>
            ))}
          </div>
        </Card>
      )}
      {declaredOnly.length > 0 && (
        <Card className="p-4 mt-3">
          <div className="text-slate-600 font-600" style={{ fontWeight: 600 }}>
            Declared by features, not confirmed in code (over-permissioned / latent)
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {declaredOnly.map((c, i) => (
              <span
                key={i}
                className="rounded-md bg-slate-500 text-white px-2.5 py-1 text-xs font-600"
                style={{ fontWeight: 600 }}
              >
                {prettify(c)}
              </span>
            ))}
          </div>
        </Card>
      )}
    </section>
  );
}
