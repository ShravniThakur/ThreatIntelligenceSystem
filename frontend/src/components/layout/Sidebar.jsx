import { NavLink } from "react-router-dom";
import { LayoutDashboard, ScanLine, History, ShieldCheck } from "lucide-react";
import Logo from "./Logo.jsx";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/analyze", label: "Analyze APK", icon: ScanLine },
  { to: "/history", label: "History", icon: History },
];

export default function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 w-64 bg-boi-navy text-slate-200 shadow-sidebar flex flex-col z-30">
      <div className="h-16 flex items-center px-5 border-b border-white/10">
        <Logo />
      </div>

      <nav className="flex-1 px-3 py-5 space-y-1">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              "flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-500 transition-colors " +
              (isActive
                ? "bg-boi-blue text-white shadow-sm"
                : "text-slate-300 hover:bg-white/5 hover:text-white")
            }
            style={{ fontWeight: 500 }}
          >
            <Icon size={18} strokeWidth={2} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="px-5 py-4 border-t border-white/10 text-[12.5px] text-slate-400 flex items-center gap-2">
        <ShieldCheck size={14} className="text-boi-saffron" />
        GenAI Malware Analysis
      </div>
    </aside>
  );
}
