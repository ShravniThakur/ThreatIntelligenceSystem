import { motion } from "framer-motion";
import CountUp from "./CountUp.jsx";

/**
 * Dashboard metric tile: icon chip + animated number + label, with an optional
 * trend caption and accent color.
 */
export default function StatCard({
  icon: Icon,
  value,
  label,
  accent = "#1e5eb8",
  tint = "#eaf1fb",
  caption,
  delay = 0,
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay, ease: [0.22, 1, 0.36, 1] }}
      className="bg-surface-card border border-slate-200 rounded-xl2 shadow-card p-5 flex items-center gap-4 transition-shadow hover:shadow-cardhover"
    >
      <div
        className="h-12 w-12 rounded-xl flex items-center justify-center flex-none"
        style={{ background: tint, color: accent }}
      >
        {Icon && <Icon size={22} strokeWidth={2.2} />}
      </div>
      <div className="min-w-0">
        <div className="text-2xl font-800 text-slate-900 leading-tight" style={{ fontWeight: 800 }}>
          <CountUp value={value} />
        </div>
        <div className="text-[14.5px] text-slate-600 font-500" style={{ fontWeight: 500 }}>
          {label}
        </div>
        {caption && <div className="text-[12.5px] text-slate-500 mt-0.5">{caption}</div>}
      </div>
    </motion.div>
  );
}
