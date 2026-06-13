import { motion } from "framer-motion";
import CountUp from "./CountUp.jsx";
import { bandColor } from "../../lib/theme.js";

/**
 * Circular risk gauge. `score` 0-100 fills the ring; color from `band` (or an
 * explicit `color`). The ring sweep and the number both animate in.
 */
export default function Gauge({ score = 0, band, color, size = 132, label = "/ 100" }) {
  const stroke = size * 0.09;
  const r = (size - stroke) / 2 - 2;
  const cx = size / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const col = color || bandColor(band);
  const numSize = Math.round(size * 0.26);

  return (
    <div className="relative flex-none" style={{ width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#eef1f6" strokeWidth={stroke} />
        <motion.circle
          cx={cx}
          cy={cx}
          r={r}
          fill="none"
          stroke={col}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: c * (1 - pct) }}
          transition={{ duration: 1, ease: [0.22, 1, 0.36, 1] }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <CountUp
          value={score}
          duration={1000}
          className="leading-none"
          style={{ fontWeight: 800, fontSize: numSize, color: col }}
        />
        <span className="text-[12.5px] text-slate-500 mt-0.5">{label}</span>
      </div>
    </div>
  );
}
