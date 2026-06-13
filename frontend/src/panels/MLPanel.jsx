import { FlaskConical, Cpu } from "lucide-react";
import { motion } from "framer-motion";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import Card from "../components/ui/Card.jsx";
import { prettify } from "../lib/theme.js";

/**
 * Multi-label ML classifier (7 categories). PROTOTYPE — synthetic-trained,
 * standalone, clearly disclaimed and deliberately excluded from the risk score.
 * Hidden when the model didn't run.
 */
export default function MLPanel({ result }) {
  const ml = result.ml_classification;
  if (!ml || !ml.available) return null;
  const ranked = ml.ranked || [];
  const barColor = (hit, p) => (hit ? (p >= 0.66 ? "#c8102e" : "#ef6c00") : "#cbd5e1");

  return (
    <section>
      <SectionTitle icon={Cpu}>ML Threat Classification</SectionTitle>
      <Card className="p-5">
        <div className="flex items-center gap-2 rounded-lg border border-dashed border-boi-blue/50 bg-boi-sky text-boi-blue text-[13.5px] px-3 py-2 mb-4">
          <FlaskConical size={15} />
          Prototype — trained on <b>synthetic data</b>. Experimental signal, not a production
          verdict; deliberately excluded from the risk score.
        </div>
        <div className="flex flex-col gap-2">
          {ranked.map((r) => {
            const p = Math.round((r.probability || 0) * 100);
            return (
              <div key={r.label} className="flex items-center gap-3 text-xs">
                <span
                  className={"w-40 capitalize " + (r.prediction ? "text-slate-900 font-700" : "text-slate-600")}
                  style={r.prediction ? { fontWeight: 700 } : undefined}
                >
                  {prettify(r.label)}
                  {r.prediction && <span className="text-boi-saffron ml-1">●</span>}
                </span>
                <span className="flex-1 h-2.5 bg-slate-100 rounded-full overflow-hidden">
                  <motion.span
                    className="block h-full rounded-full"
                    style={{ background: barColor(r.prediction, r.probability) }}
                    initial={{ width: 0 }}
                    animate={{ width: p + "%" }}
                    transition={{ duration: 0.7, ease: "easeOut" }}
                  />
                </span>
                <span className="w-11 text-right text-slate-700">{p}%</span>
              </div>
            );
          })}
        </div>
        {(ml.predicted || []).length > 0 && (
          <div className="text-xs text-slate-600 mt-3">
            Predicted label{ml.predicted.length === 1 ? "" : "s"} (above threshold):{" "}
            {ml.predicted.map((l) => prettify(l)).join(", ")}.
          </div>
        )}
      </Card>
    </section>
  );
}
