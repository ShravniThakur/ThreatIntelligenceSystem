import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from "recharts";
import { motion } from "framer-motion";
import { ScanLine, ShieldBan, ShieldAlert, Activity, Boxes, ChevronRight } from "lucide-react";
import { listAnalyses } from "../lib/api.js";
import PageTransition from "../components/ui/PageTransition.jsx";
import StatCard from "../components/ui/StatCard.jsx";
import Gauge from "../components/ui/Gauge.jsx";
import { MotionCard } from "../components/ui/Card.jsx";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import { BandPill } from "../components/ui/Pill.jsx";
import { BAND_COLOR, ACTION_COLOR, bandColor, prettify } from "../lib/theme.js";

const BANDS = ["Critical", "High", "Medium", "Low"];

export default function Dashboard() {
  const navigate = useNavigate();
  const [rows, setRows] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    listAnalyses().then(setRows).catch((e) => setErr(e.message));
  }, []);

  const stats = useMemo(() => {
    if (!rows) return null;
    const total = rows.length;
    const by = (pred) => rows.filter(pred).length;
    const blocked = by((r) => r.recommended_action === "block");
    const escalated = by((r) => r.recommended_action === "escalate_manual_review");
    const criticalHigh = by((r) => ["Critical", "High"].includes(r.fs_band));
    const scored = rows.filter((r) => typeof r.fs_score === "number");
    const avgRisk = scored.length ? scored.reduce((s, r) => s + r.fs_score, 0) / scored.length : 0;
    const posture = Math.max(0, Math.min(100, Math.round(100 - avgRisk)));

    const bandDist = BANDS.map((b) => ({ name: b, value: by((r) => r.fs_band === b), color: BAND_COLOR[b] }))
      .filter((d) => d.value > 0);
    const actionDist = Object.keys(ACTION_COLOR)
      .map((a) => ({ name: prettify(a), key: a, value: by((r) => r.recommended_action === a), color: ACTION_COLOR[a] }))
      .filter((d) => d.value > 0);

    return { total, blocked, escalated, criticalHigh, posture, bandDist, actionDist };
  }, [rows]);

  if (err)
    return (
      <PageTransition>
        <div className="rounded-xl2 border border-red-200 bg-red-50 text-red-700 p-4">
          Could not load dashboard: {err}
        </div>
      </PageTransition>
    );

  if (!stats)
    return (
      <PageTransition>
        <div className="text-center text-slate-500 py-20">Loading dashboard…</div>
      </PageTransition>
    );

  if (stats.total === 0)
    return (
      <PageTransition>
        <MotionCard className="p-12 text-center max-w-xl mx-auto mt-6">
          <div className="mx-auto h-16 w-16 rounded-2xl bg-boi-sky text-boi-blue flex items-center justify-center mb-4">
            <Boxes size={32} />
          </div>
          <h2 className="text-xl font-700 text-slate-900" style={{ fontWeight: 700 }}>
            No analyses yet
          </h2>
          <p className="text-slate-600 mt-1.5">
            Upload a banking APK to generate your first threat intelligence report.
          </p>
          <button
            onClick={() => navigate("/analyze")}
            className="mt-5 inline-flex items-center gap-2 rounded-lg bg-boi-blue text-white px-5 py-2.5 font-600 hover:bg-boi-navy transition-colors"
            style={{ fontWeight: 600 }}
          >
            <ScanLine size={18} /> Analyze an APK
          </button>
        </MotionCard>
      </PageTransition>
    );

  const recent = rows.slice(0, 6);

  return (
    <PageTransition>
      {/* Stat row */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard icon={Boxes} value={stats.total} label="APKs Analyzed" delay={0} />
        <StatCard icon={ShieldBan} value={stats.blocked} label="Blocked" accent="#c8102e" tint="#fde8eb" delay={0.05} />
        <StatCard icon={ShieldAlert} value={stats.escalated} label="Escalated for Review" accent="#ef6c00" tint="#fdeede" delay={0.1} />
        <StatCard icon={Activity} value={stats.criticalHigh} label="Critical + High Risk" accent="#f9a825" tint="#fef6e0" delay={0.15} />
      </div>

      {/* Posture + distributions */}
      <div className="grid gap-4 mt-4 lg:grid-cols-3">
        <MotionCard delay={0.1} className="p-5 flex flex-col items-center justify-center text-center">
          <SectionTitle>Security Posture</SectionTitle>
          <Gauge score={stats.posture} color="#2e7d32" size={160} label="% SECURE" />
          <p className="text-sm text-slate-600 mt-3">
            Based on {stats.total} analyzed APK{stats.total === 1 ? "" : "s"}.
            <br />
            {stats.criticalHigh > 0
              ? `Review ${stats.criticalHigh} high-severity item${stats.criticalHigh === 1 ? "" : "s"}.`
              : "No high-severity items outstanding."}
          </p>
        </MotionCard>

        <MotionCard delay={0.15} className="p-5">
          <SectionTitle>Risk Band Distribution</SectionTitle>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={stats.bandDist} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2} stroke="none">
                {stats.bandDist.map((d) => (
                  <Cell key={d.name} fill={d.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap justify-center gap-3 -mt-2">
            {stats.bandDist.map((d) => (
              <span key={d.name} className="inline-flex items-center gap-1.5 text-xs text-slate-600">
                <i className="w-2.5 h-2.5 rounded-full" style={{ background: d.color }} />
                {d.name} · {d.value}
              </span>
            ))}
          </div>
        </MotionCard>

        <MotionCard delay={0.2} className="p-5">
          <SectionTitle>Recommended Actions</SectionTitle>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={stats.actionDist} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#64748b" }} interval={0} angle={-12} textAnchor="end" height={42} />
              <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#94a3b8" }} />
              <Tooltip cursor={{ fill: "#f1f5f9" }} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {stats.actionDist.map((d) => (
                  <Cell key={d.key} fill={d.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </MotionCard>
      </div>

      {/* Recent alerts */}
      <MotionCard delay={0.25} className="p-5 mt-4">
        <SectionTitle
          right={
            <button onClick={() => navigate("/history")} className="text-xs text-boi-blue font-600 hover:underline inline-flex items-center gap-1" style={{ fontWeight: 600 }}>
              View all <ChevronRight size={14} />
            </button>
          }
        >
          Recent Alerts
        </SectionTitle>
        <div className="divide-y divide-slate-100">
          {recent.map((r) => (
            <motion.button
              key={r.apk_hash}
              whileHover={{ x: 3 }}
              onClick={() => navigate("/result/" + r.apk_hash)}
              className="w-full flex items-center gap-3 py-3 text-left"
            >
              <span className="h-2.5 w-2.5 rounded-full flex-none" style={{ background: bandColor(r.fs_band) }} />
              <span className="flex-1 min-w-0 truncate text-sm text-slate-800">
                {r.apk_filename || r.package_name || (r.apk_hash || "").slice(0, 16)}
              </span>
              <BandPill band={r.fs_band} />
              <span className="text-xs text-slate-500 w-36 text-right hidden sm:block">
                {(r.analyzed_at || "").replace("T", " ").slice(0, 19)}
              </span>
              <ChevronRight size={16} className="text-slate-300 flex-none" />
            </motion.button>
          ))}
        </div>
      </MotionCard>
    </PageTransition>
  );
}
