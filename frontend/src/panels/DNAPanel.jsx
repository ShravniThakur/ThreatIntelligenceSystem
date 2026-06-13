import { Dna, AlertTriangle } from "lucide-react";
import { motion } from "framer-motion";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import Card from "../components/ui/Card.jsx";

/**
 * Structural fingerprint similarity to known malware families. No-ops when
 * result.dna is absent or fingerprinting didn't run. Shows a "seed it" hint
 * when the reference DB is empty.
 */
export default function DNAPanel({ result }) {
  const dna = result.dna;
  if (!dna || !dna.fingerprinted) return null;

  const bandColor =
    { strong: "#c8102e", moderate: "#ef6c00", weak: "#f9a825", none: "#94a3b8" }[dna.band] ||
    "#94a3b8";
  const pct = Math.round((dna.top_similarity || 0) * 100);
  const empty = (dna.reference_size || 0) === 0;
  const perFamily = (dna.per_family || []).slice(0, 6);

  return (
    <section>
      <SectionTitle icon={Dna}>Malware DNA — structural fingerprint</SectionTitle>
      {empty ? (
        <Card className="p-4 text-slate-600">
          No reference fingerprints yet — run <code className="font-mono text-boi-blue">seed_malwarebazaar.py</code> to
          populate the malware-family database, then re-analyze.
        </Card>
      ) : (
        <Card className="p-5">
          <div className="flex items-baseline gap-3 flex-wrap">
            <span className="text-4xl font-800" style={{ fontWeight: 800, color: bandColor }}>
              {pct}%
            </span>
            <span className="text-lg font-700" style={{ fontWeight: 700, color: bandColor }}>
              {dna.band === "none" ? "closest: " : "match: "}
              {dna.top_family}
            </span>
          </div>
          <div className="text-xs text-slate-600 mt-1.5">
            {dna.band === "none"
              ? `Low structural similarity to any known family (closest is ${dna.top_family} at ${pct}%).`
              : `Structurally ${dna.band} match to the ${dna.top_family} family.`}{" "}
            Compared against {dna.reference_size} labelled malware samples.
          </div>

          {dna.tlsh_clone && (
            <div className="mt-3 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 text-red-700 text-[14.5px] px-3 py-2.5">
              <AlertTriangle size={16} className="flex-none mt-0.5" />
              <span>
                <b>Byte-level clone</b> of a known <b>{dna.tlsh_nearest_family}</b> sample (DEX TLSH
                distance {dna.tlsh_distance}) — a repackage, not just a look-alike.
              </span>
            </div>
          )}

          {perFamily.length > 0 && (
            <div className="mt-4 flex flex-col gap-2">
              {perFamily.map((f, i) => {
                const p = Math.round((f.similarity || 0) * 100);
                const col = i === 0 ? bandColor : "#cbd5e1";
                return (
                  <div key={f.family} className="flex items-center gap-2.5 text-xs">
                    <span className="w-24 text-slate-600 capitalize">{f.family}</span>
                    <span className="flex-1 h-2.5 bg-slate-100 rounded-full overflow-hidden">
                      <motion.span
                        className="block h-full rounded-full"
                        style={{ background: col }}
                        initial={{ width: 0 }}
                        animate={{ width: p + "%" }}
                        transition={{ duration: 0.7, delay: i * 0.05, ease: "easeOut" }}
                      />
                    </span>
                    <span className="w-10 text-right text-slate-700">{p}%</span>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      )}
    </section>
  );
}
