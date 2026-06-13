import { Network } from "lucide-react";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import Card from "../components/ui/Card.jsx";

/**
 * Cluster of related analyzed APKs. Shows only when this APK is linked to >=1
 * other analyzed APK (a campaign of >=2). Singletons / absent / errors render
 * nothing.
 */
export default function CampaignPanel({ result }) {
  const c = result.campaign;
  if (!c || c.error || !c.is_campaign) return null;
  const links = c.links || [];

  return (
    <section>
      <SectionTitle icon={Network}>Fraud Campaign — linked APKs</SectionTitle>
      <Card className="p-5 border-orange-200 bg-orange-50/40">
        <div className="font-700 text-orange-700" style={{ fontWeight: 700 }}>
          Part of <span className="text-slate-900">{c.campaign_id}</span> — {c.size} linked APK
          {c.size === 1 ? "" : "s"}
        </div>
        <div className="mt-3 flex flex-col gap-2">
          {links.map((e, i) => (
            <div
              key={i}
              className="flex flex-wrap items-baseline gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2"
            >
              <code className="text-boi-blue text-[14px] font-mono break-all">
                {e.other_package || (e.other_hash || "").slice(0, 16)}
              </code>
              <span className="text-[13px] text-slate-600">
                {(e.reasons || []).map((r, j) => (
                  <span key={j}>
                    <span className="text-orange-600">{r}</span>
                    {j < e.reasons.length - 1 ? " · " : ""}
                  </span>
                ))}
              </span>
            </div>
          ))}
        </div>
        <div className="text-xs text-slate-600 mt-3">
          {c.size} of {c.total_analyzed} analyzed APKs form this cluster — linked by shared signing
          certificate, shared C2 domain, DEX byte-clone, or structural twin.
        </div>
      </Card>
    </section>
  );
}
