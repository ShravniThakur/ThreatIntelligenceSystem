import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Bell, Settings, ShieldAlert } from "lucide-react";
import { listAnalyses } from "../../lib/api.js";

const TITLES = {
  "/": "Dashboard",
  "/analyze": "Analyze APK",
  "/history": "Analysis History",
};

export default function Topbar() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState(0);

  // Notification badge = count of Critical/High analyses in history.
  useEffect(() => {
    let live = true;
    listAnalyses()
      .then((rows) => {
        if (!live) return;
        setAlerts(rows.filter((r) => ["Critical", "High"].includes(r.fs_band)).length);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [pathname]);

  const title = pathname.startsWith("/result")
    ? "Analysis Report"
    : TITLES[pathname] || "Threat Intelligence";

  return (
    <header className="sticky top-0 z-20 h-16 bg-white/90 backdrop-blur border-b border-slate-200 flex items-center gap-4 px-6">
      <h1 className="text-lg font-700 text-slate-900 flex-none" style={{ fontWeight: 700 }}>
        {title}
      </h1>

      <div className="ml-auto flex items-center gap-2">
        <button
          onClick={() => navigate("/history")}
          className="relative h-10 w-10 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-600 transition-colors"
          title={`${alerts} high-severity analyses`}
        >
          <Bell size={19} />
          {alerts > 0 && (
            <span className="absolute top-1.5 right-1.5 min-w-[16px] h-4 px-1 rounded-full bg-boi-red text-white text-[11.5px] font-700 flex items-center justify-center" style={{ fontWeight: 700 }}>
              {alerts > 99 ? "99+" : alerts}
            </span>
          )}
        </button>
        <button className="h-10 w-10 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-600 transition-colors">
          <Settings size={19} />
        </button>
        <div className="h-9 w-9 rounded-full bg-boi-navy text-white flex items-center justify-center ml-1" title="Security Analyst">
          <ShieldAlert size={18} className="text-boi-saffron" />
        </div>
      </div>
    </header>
  );
}
