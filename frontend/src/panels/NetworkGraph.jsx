import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import * as d3 from "d3";
import { Share2 } from "lucide-react";
import SectionTitle from "../components/ui/SectionTitle.jsx";

// Light-theme palette (mirrors the severity scale).
const NET_COLORS = {
  apk: "#1e5eb8", // BOI blue
  red: "#c8102e", // critical / C2 / OFAC
  orange: "#ef6c00", // high / cleartext
  darkred: "#8a0f22", // hidden C2
};
const FILL = { apk: "#eaf1fb", node: "#ffffff" };

const NET_CAP_RULES = {
  c2_sanctioned_infra: { kind: "c2", color: NET_COLORS.red, label: "C2 sanctioned infrastructure" },
  hidden_c2: { kind: "hidden", color: NET_COLORS.darkred, label: "Hidden C2 channel" },
  c2_hardcoded: { kind: "c2", color: NET_COLORS.red, label: "Hardcoded C2 endpoint" },
  cleartext_traffic: { kind: "cleartext", color: NET_COLORS.orange, label: "Cleartext HTTP traffic" },
  hidden_network: { kind: "hidden", color: NET_COLORS.darkred, label: "Hidden network activity" },
};
const NET_BEHAVIOUR_TAGS = {
  c2_web: { kind: "c2", color: NET_COLORS.red, label: "C2 over web (code-confirmed)", mitre: "T1437.001" },
  cleartext_http: { kind: "cleartext", color: NET_COLORS.orange, label: "Cleartext HTTP (code-confirmed)", mitre: "T1437" },
};

function parseEvidence(ev) {
  const out = {};
  const re = /([a-zA-Z_][\w]*)\s*=\s*(-?[0-9]*\.?[0-9]+)/g;
  let m;
  while ((m = re.exec(String(ev || ""))) !== null) out[m[1]] = Number(m[2]);
  return out;
}
const evNum = (ev, ...keys) => keys.reduce((s, k) => s + (ev[k] || 0), 0);

/** Build a directed graph: APK -> capability hubs -> inferred endpoints. PURE. */
function buildNetworkGraph(result) {
  const nodes = [];
  const links = [];
  const nodeById = new Map();
  const addNode = (n) => {
    if (!nodeById.has(n.id)) {
      nodeById.set(n.id, n);
      nodes.push(n);
    }
    return nodeById.get(n.id);
  };
  const addLink = (source, target, color, mitre) =>
    links.push({ source, target, color, mitre: mitre || "" });

  const apkLabel = result.package_name || result.apk_filename || "APK";
  addNode({ id: "apk", type: "apk", label: apkLabel, color: NET_COLORS.apk, evidence: result.apk_filename || "", mitre: "" });

  const fired = result.fired_rules || [];
  const catalog = result.behaviour_catalog || [];
  const findings = result.re_findings || [];

  const mitreFromMap = (token) => {
    if (!token) return "";
    const map = result.mitre_map || {};
    for (const techs of Object.values(map)) {
      for (const t of techs || []) if (t.includes(token)) return t;
    }
    return "";
  };

  fired.forEach((fr) => {
    const rawId = fr.capability || fr.rule_id || "";
    const key = String(rawId).toLowerCase();
    const cfg = NET_CAP_RULES[key];
    if (!cfg) return;
    const ev = parseEvidence(fr.evidence);
    const capNodeId = "cap:" + key;
    const mitre = fr.mitre || mitreFromMap(key === "c2_sanctioned_infra" ? "T1437" : "");
    addNode({ id: capNodeId, type: "capability", kind: cfg.kind, color: cfg.color, label: fr.signal || cfg.label, evidence: fr.evidence || "", mitre });
    addLink("apk", capNodeId, cfg.color, mitre ? mitre.split(" ")[0] : "");

    if (cfg.kind === "c2") {
      const ofac = evNum(ev, "static_ofac_domains", "dyn_ofac_domains");
      const bad = evNum(ev, "static_bad_domains", "dyn_bad_domains");
      if (ofac > 0) {
        const id = "ep:ofac";
        addNode({ id, type: "endpoint", color: NET_COLORS.red, dashed: true, label: ofac + " OFAC-listed domain" + (ofac > 1 ? "s" : ""), evidence: fr.evidence || "", mitre });
        addLink(capNodeId, id, NET_COLORS.red);
      }
      if (bad > 0) {
        const id = "ep:bad";
        addNode({ id, type: "endpoint", color: NET_COLORS.red, dashed: true, label: bad + " flagged bad domain" + (bad > 1 ? "s" : ""), evidence: fr.evidence || "", mitre });
        addLink(capNodeId, id, NET_COLORS.red);
      }
      if (ofac === 0 && bad === 0) {
        const id = "ep:c2:" + key;
        addNode({ id, type: "endpoint", color: NET_COLORS.red, label: "C2 server (inferred)", evidence: fr.evidence || "", mitre });
        addLink(capNodeId, id, NET_COLORS.red);
      }
    } else if (cfg.kind === "cleartext") {
      const http = evNum(ev, "static_http_count");
      const id = "ep:cleartext";
      addNode({ id, type: "endpoint", color: NET_COLORS.orange, label: http > 0 ? http + " cleartext HTTP endpoint" + (http > 1 ? "s" : "") : "Cleartext HTTP endpoint", evidence: fr.evidence || "", mitre });
      addLink(capNodeId, id, NET_COLORS.orange);
    } else if (cfg.kind === "hidden") {
      const delta = evNum(ev, "dyn_static_domain_delta");
      const id = "ep:hidden:" + key;
      addNode({ id, type: "endpoint", color: NET_COLORS.darkred, dashed: true, label: delta > 0 ? delta + " hidden runtime domain" + (delta > 1 ? "s" : "") : "Hidden C2 server", evidence: fr.evidence || "", mitre });
      addLink(capNodeId, id, NET_COLORS.darkred);
    }
  });

  catalog.forEach((tag) => {
    const cfg = NET_BEHAVIOUR_TAGS[tag];
    if (!cfg) return;
    const capNodeId = "cap:tag:" + tag;
    addNode({ id: capNodeId, type: "capability", kind: cfg.kind, color: cfg.color, label: cfg.label, evidence: "code-confirmed behaviour tag: " + tag, mitre: cfg.mitre });
    addLink("apk", capNodeId, cfg.color, cfg.mitre);
  });

  const ensureC2WebHub = () => {
    const id = "cap:tag:c2_web";
    if (!nodeById.has(id)) {
      addNode({ id, type: "capability", kind: "c2", color: NET_COLORS.red, label: NET_BEHAVIOUR_TAGS.c2_web.label, evidence: "inferred from reverse-engineering findings", mitre: "T1437.001" });
      addLink("apk", id, NET_COLORS.red, "T1437.001");
    }
    return id;
  };
  findings.forEach((f, i) => {
    const tags = f.behaviour_tags || [];
    if (!tags.includes("c2_web")) return;
    const verdict = (f.verdict || "").toLowerCase();
    if (verdict !== "malicious" && verdict !== "suspicious") return;
    const color = verdict === "malicious" ? NET_COLORS.red : NET_COLORS.orange;
    const hubId = ensureC2WebHub();
    const id = "ep:finding:" + i;
    const shortClass = (f.class_name || "").split(".").pop() || "endpoint";
    addNode({ id, type: "endpoint", color, findingIndex: i, label: "C2 server — " + shortClass + "." + (f.method || ""), evidence: f.what_it_does || "", mitre: f.mitre_technique || "" });
    addLink(hubId, id, color);
  });

  return { nodes, links };
}

export default function NetworkGraph({ result }) {
  const graph = useMemo(() => buildNetworkGraph(result), [result]);
  const hasNetwork = graph.nodes.some((n) => n.type === "capability");

  const svgRef = useRef(null);
  const wrapRef = useRef(null);
  const tipRef = useRef(null);
  const resetRef = useRef(null);
  const zoomResetRef = useRef(null);
  const [collapsed, setCollapsed] = useState(typeof window !== "undefined" && window.innerWidth < 768);
  const [width, setWidth] = useState(900);

  useEffect(() => {
    const measure = () => {
      if (wrapRef.current) setWidth(wrapRef.current.clientWidth || 900);
    };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [collapsed, hasNetwork]);

  const flashFinding = useCallback((idx) => {
    const el = document.getElementById("finding-" + idx);
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.remove("animate-findingFlash");
    void el.offsetWidth;
    el.classList.add("animate-findingFlash");
    setTimeout(() => el.classList.remove("animate-findingFlash"), 1200);
  }, []);

  useEffect(() => {
    if (collapsed || !hasNetwork || !svgRef.current) return;
    const height = 420;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const nodes = graph.nodes.map((d) => ({ ...d }));
    const links = graph.links.map((d) => ({ ...d }));

    const root = svg.append("g");
    const zoom = d3.zoom().scaleExtent([0.4, 3]).on("zoom", (ev) => root.attr("transform", ev.transform));
    svg.call(zoom);
    zoomResetRef.current = () => svg.transition().duration(300).call(zoom.transform, d3.zoomIdentity);

    const apk = nodes.find((n) => n.type === "apk");
    if (apk) {
      apk.fx = width / 2;
      apk.fy = height / 2;
    }

    const sim = d3
      .forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d) => d.id).distance((l) => (l.source.type === "apk" || l.target.type === "apk" ? 120 : 80)).strength(0.6))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collide", d3.forceCollide(34));

    const link = root.append("g").selectAll("line").data(links).join("line").attr("class", "nn-link").attr("stroke", (d) => d.color).attr("stroke-width", 1.6).attr("stroke-opacity", 0.55).attr("stroke-dasharray", (d) => (d.target.dashed ? "5 4" : null));

    const elabel = root.append("g").selectAll("text").data(links.filter((l) => l.mitre)).join("text").attr("class", "nn-elabel").attr("text-anchor", "middle").text((d) => d.mitre);

    const node = root
      .append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .attr("class", "nn-node")
      .call(
        d3
          .drag()
          .on("start", (ev, d) => {
            if (!ev.active) sim.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (ev, d) => {
            d.fx = ev.x;
            d.fy = ev.y;
          })
          .on("end", (ev, d) => {
            if (!ev.active) sim.alphaTarget(0);
            if (d.type !== "apk") {
              d.fx = null;
              d.fy = null;
            }
          })
      );

    node.each(function (d) {
      const g = d3.select(this);
      if (d.type === "apk") {
        const r = 26;
        const pts = d3.range(6).map((i) => {
          const a = Math.PI / 6 + (i * Math.PI) / 3;
          return [Math.cos(a) * r, Math.sin(a) * r].join(",");
        }).join(" ");
        g.append("polygon").attr("points", pts).attr("fill", FILL.apk).attr("stroke", d.color).attr("stroke-width", 2.5);
      } else if (d.type === "capability") {
        g.append("circle").attr("r", 16).attr("fill", FILL.node).attr("stroke", d.color).attr("stroke-width", 2.5);
      } else {
        const s = 13;
        g.append("polygon").attr("points", `0,${-s} ${s},0 0,${s} ${-s},0`).attr("fill", FILL.node).attr("stroke", d.color).attr("stroke-width", 2).attr("stroke-dasharray", d.dashed ? "4 3" : null);
      }
    });

    node.append("text").attr("class", "nn-label").attr("text-anchor", "middle").attr("dy", (d) => (d.type === "apk" ? 40 : 27)).text((d) => (d.label.length > 26 ? d.label.slice(0, 25) + "…" : d.label));

    const tip = d3.select(tipRef.current);
    const showTip = (ev, d) => {
      const rect = wrapRef.current.getBoundingClientRect();
      let html = `<div class="font-700 text-boi-blue mb-1">${d.label}</div>`;
      if (d.evidence) html += `<div class="text-slate-600"><b class="text-slate-700">Evidence:</b> ${d.evidence}</div>`;
      if (d.mitre) html += `<div class="text-slate-600"><b class="text-slate-700">MITRE:</b> ${d.mitre}</div>`;
      if (d.type === "endpoint" && d.findingIndex != null) html += `<div class="text-slate-600">click → jump to finding #${d.findingIndex + 1}</div>`;
      tip.html(html).style("left", ev.clientX - rect.left + 14 + "px").style("top", ev.clientY - rect.top + 14 + "px").style("opacity", 1);
    };
    const hideTip = () => tip.style("opacity", 0);

    const adjacency = new Map();
    links.forEach((l) => {
      const s = l.source.id, t = l.target.id;
      if (!adjacency.has(s)) adjacency.set(s, new Set());
      if (!adjacency.has(t)) adjacency.set(t, new Set());
      adjacency.get(s).add(t);
      adjacency.get(t).add(s);
    });
    const clearHighlight = () => {
      node.classed("dim", false);
      link.classed("dim", false);
      node.selectAll("text").classed("dim", false);
      elabel.classed("dim", false);
    };
    resetRef.current = clearHighlight;
    const highlight = (d) => {
      const keep = new Set([d.id, "apk", ...(adjacency.get(d.id) || [])]);
      node.classed("dim", (n) => !keep.has(n.id));
      node.selectAll("text").classed("dim", function () {
        return !keep.has(d3.select(this.parentNode).datum().id);
      });
      link.classed("dim", (l) => !(keep.has(l.source.id) && keep.has(l.target.id)));
      elabel.classed("dim", (l) => !(keep.has(l.source.id) && keep.has(l.target.id)));
    };

    node.on("mouseover", showTip).on("mousemove", showTip).on("mouseout", hideTip).on("click", (ev, d) => {
      ev.stopPropagation();
      if (d.type === "capability") highlight(d);
      else if (d.type === "endpoint" && d.findingIndex != null) flashFinding(d.findingIndex);
    });
    svg.on("click", clearHighlight);

    sim.on("tick", () => {
      link.attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y).attr("x2", (d) => d.target.x).attr("y2", (d) => d.target.y);
      elabel.attr("x", (d) => (d.source.x + d.target.x) / 2).attr("y", (d) => (d.source.y + d.target.y) / 2 - 3);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    return () => sim.stop();
  }, [graph, collapsed, width, hasNetwork, flashFinding]);

  return (
    <section className="mt-5">
      <SectionTitle
        icon={Share2}
        right={
          hasNetwork && (
            <button
              className="text-xs rounded-lg border border-slate-200 px-3 py-1 text-slate-600 hover:text-boi-blue hover:border-boi-blue transition-colors"
              onClick={() => setCollapsed((c) => !c)}
            >
              {collapsed ? "▸ Show graph" : "▾ Hide graph"}
            </button>
          )
        }
      >
        Network &amp; C2 Surface
      </SectionTitle>

      {!hasNetwork ? (
        <div className="bg-surface-card border border-slate-200 rounded-xl2 shadow-card text-center text-slate-500 py-14">
          No network connections detected.
        </div>
      ) : collapsed ? (
        <div className="text-xs text-slate-600 mt-2">
          Graph hidden. Tap "Show graph" to render the network surface.
        </div>
      ) : (
        <>
          <div ref={wrapRef} className="relative bg-surface-card border border-slate-200 rounded-xl2 overflow-hidden min-h-[400px] shadow-card">
            <div className="absolute top-2.5 right-2.5 flex gap-2 z-10">
              <button onClick={() => resetRef.current && resetRef.current()} className="bg-white/85 border border-slate-200 rounded-md px-2.5 py-1 text-[12.5px] text-slate-600 hover:text-boi-blue hover:border-boi-blue transition-colors">
                Reset highlight
              </button>
              <button onClick={() => zoomResetRef.current && zoomResetRef.current()} className="bg-white/85 border border-slate-200 rounded-md px-2.5 py-1 text-[12.5px] text-slate-600 hover:text-boi-blue hover:border-boi-blue transition-colors">
                Reset zoom
              </button>
            </div>
            <svg ref={svgRef} width="100%" height="420" className="block cursor-grab active:cursor-grabbing" />
            <div className="absolute bottom-2.5 left-3 flex flex-wrap gap-3.5 text-[12px] text-slate-600 z-10 pointer-events-none">
              <span className="inline-flex items-center gap-1.5"><i className="w-2.5 h-2.5 rounded-full" style={{ background: NET_COLORS.apk }} />App</span>
              <span className="inline-flex items-center gap-1.5"><i className="w-2.5 h-2.5 rounded-full" style={{ background: NET_COLORS.red }} />C2 / OFAC</span>
              <span className="inline-flex items-center gap-1.5"><i className="w-2.5 h-2.5 rounded-full" style={{ background: NET_COLORS.darkred }} />Hidden C2</span>
              <span className="inline-flex items-center gap-1.5"><i className="w-2.5 h-2.5 rounded-full" style={{ background: NET_COLORS.orange }} />Cleartext</span>
            </div>
            <div ref={tipRef} className="absolute pointer-events-none z-20 max-w-[280px] bg-white border border-boi-blue rounded-lg px-2.5 py-2 text-[13px] leading-snug shadow-cardhover opacity-0 transition-opacity" />
          </div>
          <div className="text-[12.5px] text-slate-600 mt-2 leading-relaxed">
            Endpoints are <b>semantic</b>, inferred from stored counts &amp; evidence — the raw
            domain/URL list is not in the result payload. Hover a node for evidence; click a
            capability to isolate its subgraph; click a C2 endpoint to jump to its finding.
          </div>
        </>
      )}
    </section>
  );
}
