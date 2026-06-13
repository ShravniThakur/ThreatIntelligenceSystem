import { Crosshair } from "lucide-react";
import { motion } from "framer-motion";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import Card from "../components/ui/Card.jsx";

/** MITRE ATT&CK coverage (code-confirmed only). */
export default function MitreCoverage({ result }) {
  const mitre = result.mitre_map || {};
  const tactics = Object.keys(mitre);
  const reUnavailable = result.re_unavailable || result.code_band == null;

  return (
    <section>
      <SectionTitle icon={Crosshair}>MITRE ATT&amp;CK Coverage</SectionTitle>
      {tactics.length === 0 ? (
        <Card className="p-4 text-slate-600">
          {reUnavailable
            ? "MITRE unavailable — reverse engineering did not complete."
            : "No ATT&CK techniques confirmed in code."}
        </Card>
      ) : (
        <div className="grid gap-3 [grid-template-columns:repeat(auto-fill,minmax(220px,1fr))]">
          {tactics.map((tac, i) => (
            <motion.div
              key={tac}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: i * 0.04 }}
              className="bg-surface-card border border-slate-200 rounded-xl shadow-card p-3.5"
            >
              <div className="text-[12.5px] uppercase tracking-wide text-boi-blue font-700" style={{ fontWeight: 700 }}>
                {tac}
              </div>
              {(mitre[tac] || []).map((t, j) => (
                <div key={j} className="text-[14px] text-slate-700 mt-1.5 leading-relaxed">
                  {t}
                </div>
              ))}
            </motion.div>
          ))}
        </div>
      )}
    </section>
  );
}
