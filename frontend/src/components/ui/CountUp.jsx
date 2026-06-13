import { useEffect, useRef, useState } from "react";

/** Animated count-up number. Eases from 0 to `value` over `duration` ms. */
export default function CountUp({ value = 0, duration = 900, decimals = 0, className, style }) {
  const [display, setDisplay] = useState(0);
  const raf = useRef();
  useEffect(() => {
    const start = performance.now();
    const from = 0;
    const to = Number(value) || 0;
    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      setDisplay(from + (to - from) * eased);
      if (t < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [value, duration]);
  return (
    <span className={className} style={style}>
      {display.toFixed(decimals)}
    </span>
  );
}
