import { motion } from "framer-motion";

/** White surface card with soft shadow. `as` lets callers swap the element. */
export default function Card({ className = "", children, hover = false, ...rest }) {
  return (
    <div
      className={
        "bg-surface-card border border-slate-200 rounded-xl2 shadow-card " +
        (hover ? "transition-shadow hover:shadow-cardhover " : "") +
        className
      }
      {...rest}
    >
      {children}
    </div>
  );
}

/** Animated entrance wrapper (fade + rise), staggered by `delay`. */
export function MotionCard({ delay = 0, className = "", children, ...rest }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay, ease: [0.22, 1, 0.36, 1] }}
      className={
        "bg-surface-card border border-slate-200 rounded-xl2 shadow-card " + className
      }
      {...rest}
    >
      {children}
    </motion.div>
  );
}
