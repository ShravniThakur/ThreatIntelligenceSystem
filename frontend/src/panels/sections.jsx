import { Crosshair, Cpu, Dna, ListChecks, Flag, Share2, Microscope, Database, Network, Megaphone } from "lucide-react";
import MitreCoverage from "./MitreCoverage.jsx";
import MLPanel from "./MLPanel.jsx";
import DNAPanel from "./DNAPanel.jsx";
import CampaignPanel from "./CampaignPanel.jsx";
import SocialEngineering from "./SocialEngineering.jsx";
import NetworkGraph from "./NetworkGraph.jsx";
import BehaviourCatalog from "./BehaviourCatalog.jsx";
import CapabilityGap from "./CapabilityGap.jsx";
import ReFindings from "./ReFindings.jsx";
import FeatureEvidence from "./FeatureEvidence.jsx";

/**
 * Registry of analysis components shown in the Result hub's left-column menu and
 * rendered full-page at /result/:hash/section/:key. Every component is ALWAYS
 * listed in the menu; `available(result)` reports whether it actually has data
 * (drives the "Not detected" styling in the menu and the empty-state vs panel
 * choice on the detail page). `subtitle(result)` is the menu row's data hint.
 */
export const SECTIONS = [
  {
    key: "mitre",
    title: "MITRE ATT&CK Coverage",
    icon: Crosshair,
    Panel: MitreCoverage,
    available: () => true,
    subtitle: (r) => `${Object.keys(r.mitre_map || {}).length} tactics`,
  },
  {
    key: "ml",
    title: "ML Threat Classification",
    icon: Cpu,
    Panel: MLPanel,
    available: (r) => !!(r.ml_classification && r.ml_classification.available),
    subtitle: (r) => `${(r.ml_classification?.predicted || []).length} predicted labels`,
  },
  {
    key: "dna",
    title: "Malware DNA — structural fingerprint",
    icon: Dna,
    Panel: DNAPanel,
    available: (r) => !!(r.dna && r.dna.fingerprinted),
    subtitle: (r) => (r.dna?.top_family ? `closest: ${r.dna.top_family}` : ""),
  },
  {
    key: "campaign",
    title: "Fraud Campaign — linked APKs",
    icon: Network,
    Panel: CampaignPanel,
    available: (r) => !!(r.campaign && !r.campaign.error && r.campaign.is_campaign),
    subtitle: (r) => `${r.campaign?.size || 0} linked APKs`,
  },
  {
    key: "social",
    title: "Social Engineering",
    icon: Megaphone,
    Panel: SocialEngineering,
    // Always meaningful — the panel renders a clean / error state when nothing
    // is flagged, so it's always "available" (never the generic empty page).
    available: () => true,
    subtitle: (r) =>
      (r.se_findings || []).length
        ? `${r.se_findings.length} flagged UI strings`
        : "no fraud UI detected",
  },
  {
    key: "behaviour",
    title: "Behaviour Catalog",
    icon: ListChecks,
    Panel: BehaviourCatalog,
    available: (r) => (r.behaviour_catalog || []).length > 0,
    subtitle: (r) => `${(r.behaviour_catalog || []).length} confirmed in code`,
  },
  {
    key: "gap",
    title: "Capability Gap",
    icon: Flag,
    Panel: CapabilityGap,
    available: (r) => {
      const g = r.capability_gap || {};
      return (g.re_only || []).length > 0 || (g.declared_only || []).length > 0;
    },
    subtitle: (r) => `${(r.capability_gap?.re_only || []).length} undeclared behaviours`,
  },
  {
    key: "network",
    title: "Network & C2 Surface",
    icon: Share2,
    Panel: NetworkGraph,
    available: () => true,
    subtitle: () => "C2 / endpoint graph",
  },
  {
    key: "findings",
    title: "Reverse-Engineering Findings",
    icon: Microscope,
    Panel: ReFindings,
    available: (r) => (r.re_findings || []).length > 0,
    subtitle: (r) => `${(r.re_findings || []).length} methods analyzed`,
  },
  {
    key: "evidence",
    title: "Feature-Store Evidence",
    icon: Database,
    Panel: FeatureEvidence,
    available: () => true,
    subtitle: (r) => `${(r.fired_rules || []).length} fired capabilities`,
  },
];

export const findSection = (key) => SECTIONS.find((s) => s.key === key);
