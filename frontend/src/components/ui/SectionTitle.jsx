/** Uppercase section heading with an accent rule, used above each Result panel. */
export default function SectionTitle({ icon: Icon, children, right }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-200 pb-2 mb-3">
      <h3 className="flex items-center gap-2.5 text-[19px] font-700 tracking-tight text-boi-navy" style={{ fontWeight: 700 }}>
        {Icon && <Icon size={19} className="text-boi-blue" />}
        {children}
      </h3>
      {right}
    </div>
  );
}
