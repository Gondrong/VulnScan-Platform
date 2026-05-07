import React, { useState, useEffect, useRef, useCallback } from "react";
import { graphApi } from "../api.js";
import { Icons, Sev } from "./icons.jsx";

/* ── Severity colour map ─────────────────────────────────────────── */
const SEV_COLORS = {
  critical: "var(--sev-critical)",
  high:     "var(--sev-high)",
  medium:   "var(--sev-medium)",
  low:      "var(--sev-low)",
  info:     "var(--sev-info, #888)",
};

/* ── Simple force simulation (no external deps) ──────────────────── */
function forceSimulation(nodes, links, width, height) {
  // Initialise positions randomly around center
  for (const n of nodes) {
    n.x = n.x ?? width / 2 + (Math.random() - 0.5) * width * 0.6;
    n.y = n.y ?? height / 2 + (Math.random() - 0.5) * height * 0.6;
    n.vx = 0;
    n.vy = 0;
  }
  const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));

  return function tick() {
    const alpha = 0.3;
    const repulsion = 800;
    const linkDist = 120;
    const linkStrength = 0.04;
    const centerStrength = 0.01;
    const damping = 0.6;

    // Repulsion between all pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        let force = repulsion / (dist * dist);
        let fx = (dx / dist) * force * alpha;
        let fy = (dy / dist) * force * alpha;
        a.vx -= fx; a.vy -= fy;
        b.vx += fx; b.vy += fy;
      }
    }

    // Link attraction
    for (const l of links) {
      const a = nodeMap[l.source];
      const b = nodeMap[l.target];
      if (!a || !b) continue;
      let dx = b.x - a.x, dy = b.y - a.y;
      let dist = Math.sqrt(dx * dx + dy * dy) || 1;
      let force = (dist - linkDist) * linkStrength * alpha;
      let fx = (dx / dist) * force;
      let fy = (dy / dist) * force;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    }

    // Center gravity
    for (const n of nodes) {
      n.vx += (width / 2 - n.x) * centerStrength * alpha;
      n.vy += (height / 2 - n.y) * centerStrength * alpha;
    }

    // Apply velocity with damping + boundary clamping
    for (const n of nodes) {
      n.vx *= damping;
      n.vy *= damping;
      n.x += n.vx;
      n.y += n.vy;
      n.x = Math.max(30, Math.min(width - 30, n.x));
      n.y = Math.max(30, Math.min(height - 30, n.y));
    }
  };
}

/* ── Graph Canvas (SVG) ──────────────────────────────────────────── */
function GraphCanvas({ data, onSelect }) {
  const svgRef = useRef(null);
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: 900, h: 600 });
  const nodesRef = useRef([]);
  const tickRef = useRef(null);
  const dragRef = useRef(null);
  const [, forceRender] = useState(0);

  // Initialise simulation when data changes
  useEffect(() => {
    if (!data || !data.nodes.length) return;
    const w = 900, h = 600;
    const nodes = data.nodes.map(n => ({ ...n, x: undefined, y: undefined }));
    nodesRef.current = nodes;
    const tick = forceSimulation(nodes, data.links, w, h);
    tickRef.current = tick;
    setViewBox({ x: 0, y: 0, w, h });

    let running = true;
    let frame = 0;
    function loop() {
      if (!running) return;
      tick();
      frame++;
      forceRender(f => f + 1);
      if (frame < 300) requestAnimationFrame(loop);
    }
    requestAnimationFrame(loop);
    return () => { running = false; };
  }, [data]);

  const nodes = nodesRef.current;
  const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));
  const links = data?.links || [];

  // Drag handlers
  const onPointerDown = useCallback((e, node) => {
    e.stopPropagation();
    dragRef.current = { node, startX: e.clientX, startY: e.clientY, origX: node.x, origY: node.y };
    e.currentTarget.setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e) => {
    if (!dragRef.current) return;
    const d = dragRef.current;
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const scaleX = viewBox.w / rect.width;
    const scaleY = viewBox.h / rect.height;
    d.node.x = d.origX + (e.clientX - d.startX) * scaleX;
    d.node.y = d.origY + (e.clientY - d.startY) * scaleY;
    d.node.vx = 0;
    d.node.vy = 0;
    forceRender(f => f + 1);
  }, [viewBox]);

  const onPointerUp = useCallback(() => {
    dragRef.current = null;
  }, []);

  // Zoom with wheel
  const onWheel = useCallback((e) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 1.1 : 0.9;
    setViewBox(v => {
      const nw = v.w * factor, nh = v.h * factor;
      return { x: v.x - (nw - v.w) / 2, y: v.y - (nh - v.h) / 2, w: nw, h: nh };
    });
  }, []);

  if (!data || !nodes.length) return null;

  return (
    <svg ref={svgRef}
         viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
         style={{ width: "100%", height: "100%", background: "var(--surface-0)", borderRadius: 10, cursor: "grab" }}
         onPointerMove={onPointerMove} onPointerUp={onPointerUp} onWheel={onWheel}>
      <defs>
        <marker id="arrowhead" viewBox="0 0 10 7" refX="10" refY="3.5"
                markerWidth="8" markerHeight="6" orient="auto-start-reverse">
          <polygon points="0 0, 10 3.5, 0 7" fill="var(--text-4)" />
        </marker>
      </defs>

      {/* Links */}
      {links.map((l, i) => {
        const s = nodeMap[l.source], t = nodeMap[l.target];
        if (!s || !t) return null;
        const isStructural = l.type === "detected" || l.type === "violates" || l.type === "contains";
        const color = isStructural
          ? "var(--text-4)"
          : SEV_COLORS[l.risk >= 9 ? "critical" : l.risk >= 7 ? "high" : l.risk >= 4 ? "medium" : l.risk > 0 ? "low" : "info"];
        return (
          <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                stroke={color} strokeWidth={isStructural ? 0.8 : 1.2} opacity={isStructural ? 0.3 : 0.5}
                strokeDasharray={isStructural ? "4 3" : "none"}
                markerEnd="url(#arrowhead)" />
        );
      })}

      {/* Nodes */}
      {nodes.map(n => {
        const fills = {
          asset: "var(--brand)",
          vuln: SEV_COLORS[n.severity] || "var(--text-3)",
          plugin: "var(--sev-info, #888)",
          compliance: "#f59e0b",
          group: "var(--brand-text, #a78bfa)",
        };
        const r = n.size || 10;
        const fill = fills[n.type] || "var(--text-3)";
        const isRect = n.type === "compliance" || n.type === "group";
        return (
          <g key={n.id} style={{ cursor: "pointer" }}
             onPointerDown={e => onPointerDown(e, n)}
             onClick={() => onSelect && onSelect(n)}>
            {isRect ? (
              <rect x={n.x - r} y={n.y - r * 0.7} width={r * 2} height={r * 1.4}
                    rx={4} fill={fill} opacity={0.85}
                    stroke="var(--surface-0)" strokeWidth={1.5} />
            ) : (
              <circle cx={n.x} cy={n.y} r={r} fill={fill} opacity={0.85}
                      stroke={n.type === "asset" ? "var(--brand-text)" : "var(--surface-0)"}
                      strokeWidth={n.type === "asset" ? 2 : 1.5} />
            )}
            <text x={n.x} y={n.y + r + 12} textAnchor="middle"
                  fill="var(--text-2)" fontSize={n.type === "asset" ? 11 : 9}
                  fontFamily="var(--font-mono)" fontWeight={n.type === "asset" ? 600 : 400}>
              {(n.label || n.id).length > 28 ? (n.label || n.id).slice(0, 26) + "..." : (n.label || n.id)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

/* ── Legend ───────────────────────────────────────────────────────── */
function Legend() {
  const items = [
    { label: "Asset", color: "var(--brand)", size: 12 },
    { label: "Critical", color: SEV_COLORS.critical, size: 8 },
    { label: "High", color: SEV_COLORS.high, size: 8 },
    { label: "Medium", color: SEV_COLORS.medium, size: 8 },
    { label: "Low", color: SEV_COLORS.low, size: 8 },
    { label: "Plugin", color: "var(--sev-info, #888)", size: 6 },
    { label: "Compliance", color: "#f59e0b", size: 6, rect: true },
    { label: "Group", color: "var(--brand-text, #a78bfa)", size: 6, rect: true },
  ];
  return (
    <div style={{ display: "flex", gap: 14, flexWrap: "wrap", fontSize: 11.5, color: "var(--text-2)" }}>
      {items.map(it => (
        <span key={it.label} style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
          <span style={{
            display: "inline-block", width: it.size * 2, height: it.size * 2,
            borderRadius: it.rect ? 3 : "50%", background: it.color, opacity: 0.85,
          }} />
          {it.label}
        </span>
      ))}
    </div>
  );
}

/* ── Detail sidebar ──────────────────────────────────────────────── */
function NodeDetail({ node, links, nodeMap, onClose }) {
  if (!node) return null;
  const isAsset = node.type === "asset";
  const related = links
    .filter(l => l.source === node.id || l.target === node.id)
    .map(l => {
      const otherId = l.source === node.id ? l.target : l.source;
      return { ...l, other: nodeMap[otherId] };
    })
    .filter(l => l.other)
    .sort((a, b) => (b.risk || 0) - (a.risk || 0));

  return (
    <div style={{
      position: "absolute", top: 12, right: 12, width: 320,
      background: "var(--surface-1)", border: "1px solid var(--line-strong)",
      borderRadius: 10, boxShadow: "var(--shadow-3)", zIndex: 10,
      maxHeight: "calc(100% - 24px)", display: "flex", flexDirection: "column",
    }}>
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-0)" }}>
          {isAsset ? "Asset" : "Vulnerability"}
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-3)", padding: 2 }}>
          <Icons.X size={14} />
        </button>
      </div>
      <div style={{ padding: "12px 16px", flex: 1, overflowY: "auto" }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-0)", wordBreak: "break-all" }}>
          {node.label || node.id}
        </div>
        {node.cve && <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4, fontFamily: "var(--font-mono)" }}>{node.cve}</div>}
        {node.severity && (
          <div style={{ marginTop: 6 }}><Sev s={node.severity} /></div>
        )}
        {node.risk != null && (
          <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4 }}>Risk: {node.risk}</div>
        )}
        <div style={{ marginTop: 16, fontSize: 11, fontWeight: 600, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.04em" }}>
          {isAsset ? `Vulnerabilities (${related.length})` : `Affected assets (${related.length})`}
        </div>
        <div style={{ marginTop: 6, display: "flex", flexDirection: "column", gap: 4 }}>
          {related.slice(0, 50).map((r, i) => (
            <div key={i} style={{
              fontSize: 12, padding: "6px 8px", borderRadius: 6,
              background: "var(--surface-2)", color: "var(--text-1)",
              display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <span style={{ fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, marginRight: 8 }}>
                {r.other.label || r.other.id}
              </span>
              {r.risk > 0 && <span style={{ fontSize: 11, color: SEV_COLORS[r.risk >= 9 ? "critical" : r.risk >= 7 ? "high" : r.risk >= 4 ? "medium" : "low"], fontWeight: 600 }}>{r.risk}</span>}
            </div>
          ))}
          {related.length === 0 && <div style={{ fontSize: 12, color: "var(--text-3)" }}>None</div>}
        </div>
      </div>
    </div>
  );
}

/* ── Stats bar ───────────────────────────────────────────────────── */
function StatsBar({ data }) {
  if (!data) return null;
  const assets = data.nodes.filter(n => n.type === "asset").length;
  const vulns = data.nodes.filter(n => n.type === "vuln");
  const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const v of vulns) bySev[v.severity] = (bySev[v.severity] || 0) + 1;
  return (
    <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
      <StatPill label="Assets" value={assets} color="var(--brand)" />
      <StatPill label="Vulns" value={vulns.length} color="var(--text-2)" />
      <StatPill label="Critical" value={bySev.critical} color={SEV_COLORS.critical} />
      <StatPill label="High" value={bySev.high} color={SEV_COLORS.high} />
      <StatPill label="Medium" value={bySev.medium} color={SEV_COLORS.medium} />
      <StatPill label="Low" value={bySev.low} color={SEV_COLORS.low} />
    </div>
  );
}

function StatPill({ label, value, color }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-2)" }}>
      <span style={{ width: 8, height: 8, borderRadius: "50%", background: color }} />
      <span style={{ fontWeight: 600, color }}>{value}</span>
      <span>{label}</span>
    </div>
  );
}

/* ── Main page ───────────────────────────────────────────────────── */
export function AttackGraph() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [selected, setSelected] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await graphApi.attackMap();
      setData(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleSync(full = true) {
    setSyncing(true);
    try {
      await graphApi.sync(full);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setSyncing(false);
    }
  }

  const nodeMap = data ? Object.fromEntries(data.nodes.map(n => [n.id, n])) : {};

  return (
    <>
      <div className="ph">
        <div>
          <h1>Attack Graph</h1>
          <div className="sub">Visual map of assets and their vulnerabilities</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading}>
            <Icons.Refresh size={14} /> Refresh
          </button>
          <button className="btn btn-ghost btn-sm" onClick={() => handleSync(false)} disabled={syncing}>
            <Icons.Database size={14} /> {syncing ? "Syncing..." : "Incremental sync"}
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => handleSync(true)} disabled={syncing}>
            <Icons.Database size={14} /> {syncing ? "Syncing..." : "Full sync"}
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: "10px 16px", margin: "0 0 12px", borderRadius: 8, background: "var(--status-err-bg, rgba(255,80,80,0.1))", color: "var(--status-err)", fontSize: 13 }}>
          {error}
        </div>
      )}

      {!loading && data && (
        <div style={{ marginBottom: 12, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <StatsBar data={data} />
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <Legend />
            {data.source && (
              <span className="tag" style={{ fontSize: 10 }}>source: {data.source}</span>
            )}
          </div>
        </div>
      )}

      <div style={{ position: "relative", flex: 1, minHeight: 500, border: "1px solid var(--line)", borderRadius: 10, overflow: "hidden" }}>
        {loading && (
          <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", background: "var(--surface-0)", zIndex: 5 }}>
            <div style={{ textAlign: "center", color: "var(--text-3)" }}>
              <Icons.Refresh size={20} className="spin" />
              <div style={{ marginTop: 8, fontSize: 13 }}>Loading graph...</div>
            </div>
          </div>
        )}

        {!loading && (!data || data.nodes.length === 0) && (
          <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center" }}>
            <div style={{ textAlign: "center", color: "var(--text-3)" }}>
              <Icons.Graph size={32} />
              <div style={{ marginTop: 8, fontSize: 14, fontWeight: 500 }}>No graph data</div>
              <div style={{ marginTop: 4, fontSize: 12.5 }}>Run a scan first, then click "Sync graph" to populate.</div>
            </div>
          </div>
        )}

        {!loading && data && data.nodes.length > 0 && (
          <GraphCanvas data={data} onSelect={setSelected} />
        )}

        <NodeDetail
          node={selected}
          links={data?.links || []}
          nodeMap={nodeMap}
          onClose={() => setSelected(null)}
        />
      </div>
    </>
  );
}
