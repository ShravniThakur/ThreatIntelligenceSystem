import { useRef } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Copy, Printer, Sparkles } from "lucide-react";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import Card from "../components/ui/Card.jsx";

/**
 * Final GenAI report. The backend ships Markdown, but we present it as a clean,
 * formatted document — copy as plain text, or print / save as PDF (no raw .md).
 */
export default function ReportPanel({ result, fill = false }) {
  const rep = result.report;
  const bodyRef = useRef(null);
  if (!rep) return null; // older JSON, predates the report

  if (!rep.markdown) {
    return (
      <section className="mt-5">
        <SectionTitle icon={Sparkles}>Threat Report</SectionTitle>
        <Card className="p-4 text-slate-600">
          Report not generated{rep.error ? ` — ${rep.error}` : ""}.
        </Card>
      </section>
    );
  }

  const copy = () => {
    try {
      navigator.clipboard.writeText(bodyRef.current?.innerText || "");
    } catch {}
  };

  // Open the rendered report in a clean print window -> "Save as PDF".
  const printPdf = () => {
    const title = result.apk_filename || result.package_name || "Threat Report";
    const html = bodyRef.current?.innerHTML || "";
    const w = window.open("", "_blank", "width=900,height=1000");
    if (!w) return;
    w.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>${title} — Threat Report</title>
      <style>
        @page { margin: 18mm; }
        * { box-sizing: border-box; }
        body { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color:#1e293b; line-height:1.6; font-size:13px; max-width:760px; margin:0 auto; padding:24px; }
        .brand { display:flex; align-items:center; gap:10px; border-bottom:2px solid #1a2b5c; padding-bottom:12px; margin-bottom:20px; }
        .brand .t { font-weight:800; color:#1a2b5c; letter-spacing:.5px; }
        .brand .s { font-size:11px; color:#f57c00; text-transform:uppercase; letter-spacing:.15em; }
        h1,h2,h3 { color:#1a2b5c; line-height:1.3; margin:18px 0 8px; }
        h1{font-size:20px;} h2{font-size:16px;} h3{font-size:13px; text-transform:uppercase; letter-spacing:.05em;}
        p{margin:8px 0;} ul,ol{padding-left:22px;margin:8px 0;} li{margin:4px 0;}
        strong{color:#0f172a;}
        code{background:#f1f5f9;color:#1e5eb8;border-radius:4px;padding:1px 5px;font-size:12px;}
        table{border-collapse:collapse;width:100%;margin:10px 0;} th,td{border:1px solid #e2e8f0;padding:6px 9px;text-align:left;font-size:12px;} th{background:#f8fafc;}
        blockquote{border-left:3px solid #1e5eb8;margin:8px 0;padding:2px 14px;color:#475569;}
      </style></head><body>
      <div class="brand">
        <svg width="28" height="28" viewBox="0 0 24 24"><path fill="#f57c00" d="M12 1.5l2.7 7.0 7.3.1-5.9 4.4 2.2 7.1L12 17.2 5.4 21.2l2.2-7.1L1.7 8.6l7.3-.1z"/></svg>
        <div><div class="t">BANK OF INDIA</div><div class="s">APK Threat Intelligence Report</div></div>
      </div>
      ${html}
      </body></html>`);
    w.document.close();
    w.focus();
    setTimeout(() => w.print(), 350);
  };

  return (
    <section className={"mt-5" + (fill ? " flex flex-col min-h-0 h-full" : "")}>
      <SectionTitle
        icon={Sparkles}
        right={
          <span className="text-[11.5px] rounded-full px-2 py-0.5 ring-1 ring-boi-blue/40 text-boi-blue">
            AI-generated
          </span>
        }
      >
        Threat Report
      </SectionTitle>
      <div className="flex gap-2 mb-3">
        <button
          onClick={copy}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 text-slate-700 px-3 py-1.5 text-sm font-600 hover:bg-slate-50 transition-colors"
          style={{ fontWeight: 600 }}
        >
          <Copy size={15} /> Copy text
        </button>
        <button
          onClick={printPdf}
          className="inline-flex items-center gap-1.5 rounded-lg bg-boi-blue text-white px-3 py-1.5 text-sm font-600 hover:bg-boi-navy transition-colors"
          style={{ fontWeight: 600 }}
        >
          <Printer size={15} /> Print / Save as PDF
        </button>
      </div>
      <Card className={"p-6" + (fill ? " flex-1 min-h-0 overflow-auto" : "")}>
        <div ref={bodyRef} className="report-md">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{rep.markdown}</ReactMarkdown>
        </div>
      </Card>
    </section>
  );
}
