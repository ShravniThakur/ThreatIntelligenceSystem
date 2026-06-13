/** Bank of India saffron star mark + wordmark. SVG only — no external asset. */
export default function Logo({ compact = false }) {
  return (
    <div className="flex items-center gap-2.5">
      <svg width="34" height="34" viewBox="0 0 24 24" className="flex-none drop-shadow-sm">
        <path
          fill="#f57c00"
          d="M12 1.5l2.7 7.0 7.3.1-5.9 4.4 2.2 7.1L12 17.2 5.4 21.2l2.2-7.1L1.7 8.6l7.3-.1z"
        />
        <path
          fill="#c8102e"
          d="M12 5.2l1.6 4.2 4.3.05-3.5 2.6 1.3 4.2L12 13.9l-3.9 2.4 1.3-4.2-3.5-2.6 4.3-.05z"
          opacity="0.55"
        />
      </svg>
      {!compact && (
        <div className="leading-tight">
          <div className="text-white font-800 text-[17px] tracking-wide" style={{ fontWeight: 800 }}>
            BANK OF INDIA
          </div>
          <div className="text-[11.5px] uppercase tracking-[0.18em] text-boi-saffron/90">
            Threat Intelligence
          </div>
        </div>
      )}
    </div>
  );
}
