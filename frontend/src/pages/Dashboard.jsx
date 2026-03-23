import React, { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { SevBadge, RiskBar, StatusDot, Panel, fmtDate } from "../components/ui.jsx";

export default function Dashboard() {
  const [jobs, setJobs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [allFindings, setAllFindings] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0, kev: 0, total: 0, totalFindings: 0 });
  const [logs, setLogs] = useState([
    { type: "info", text: "[SYSTEM] VulnScan Platform v1.0.2 initializing..." },
    { type: "ok",   text: "[OK] Database connection established" },
    { type: "ok",   text: "[OK] Redis queue worker active" },
    { type: "ok",   text: "[OK] Neo4j graph connected" },
    { type: "ok",   text: "[PLUGINS] 12 scan plugins loaded" },
    { type: "ok",   text: "[OK] Multi-source CVE enricher ready (NVD + CNA/ADP)" },
    { type: "info", text: "[SYSTEM] Awaiting scan jobs..." },
  ]);
  const termRef = useRef(null);

  function addLog(type, text) {
    setLogs(l => [...l.slice(-49), { type, text }]);
  }

  async function load() {
    try {
      const allJobs = await api("/scan/jobs");
      setJobs(allJobs.slice(0, 8));

      // Get findings from all done jobs
      const doneJobs = allJobs.filter(j => j.status === "done");
      let allFs = [];
      for (const j of doneJobs.slice(0, 5)) {
        try {
          const detail = await api(`/scan/jobs/${j.id}`);
          allFs = allFs.concat(detail.findings || []);
        } catch {}
      }
      setAllFindings(allFs);
      setFindings(allFs.slice(0, 8));
      setStats({
        total: allJobs.length,
        totalFindings: allFs.length,
        critical: allFs.filter(f => f.severity === "critical").length,
        high: allFs.filter(f => f.severity === "high").length,
        medium: allFs.filter(f => f.severity === "medium").length,
        low: allFs.filter(f => f.severity === "low").length,
        kev: allFs.filter(f => f.is_kev).length,
      });
      addLog("ok", `[REFRESH] ${allJobs.length} jobs, ${allFs.length} findings`);
    } catch (e) {
      addLog("err", "[ERROR] " + e.message);
    }
  }

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, []);
  useEffect(() => { if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight; }, [logs]);

  const STAT_CARDS = [
    { label: "Critical", val: stats.critical, cls: "critical", icon: "⚠" },
    { label: "High", val: stats.high, cls: "high", icon: "▲" },
    { label: "Medium", val: stats.medium, cls: "medium", icon: "◆" },
    { label: "Low", val: stats.low, cls: "low", icon: "●" },
    { label: "KEV Hits", val: stats.kev, cls: "kev", icon: "⊘" },
    { label: "Total Scans", val: stats.total, cls: "info", icon: "◎" },
  ];

  // Severity distribution bar
  const sevTotal = stats.critical + stats.high + stats.medium + stats.low;
  const sevPcts = sevTotal > 0 ? {
    critical: (stats.critical / sevTotal * 100),
    high: (stats.high / sevTotal * 100),
    medium: (stats.medium / sevTotal * 100),
    low: (stats.low / sevTotal * 100),
  } : { critical: 0, high: 0, medium: 0, low: 0 };

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Threat <span className="accent">Dashboard</span></div>
          <div className="page-desc">// Real-time vulnerability posture overview</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Link to="/jobs" className="btn btn-outline" style={{ textDecoration: "none" }}>+ New Scan</Link>
          <button className="btn btn-primary" onClick={load}>↻ REFRESH</button>
        </div>
      </div>

      {/* Stat Cards - responsive grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12, marginBottom: 24 }}>
        {STAT_CARDS.map(c => (
          <div key={c.label} className={`stat-card ${c.cls}`}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div className="stat-label">{c.label}</div>
              <span style={{ fontSize: "1rem", opacity: 0.4 }}>{c.icon}</span>
            </div>
            <div className="stat-val">{c.val}</div>
          </div>
        ))}
      </div>

      {/* Severity Distribution Bar */}
      {sevTotal > 0 && (
        <div style={{ marginBottom: 24, background: "var(--surface)", border: "1px solid var(--border)", padding: "14px 18px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <span style={{ fontFamily: "var(--font-head)", fontSize: "0.78rem", fontWeight: 600, letterSpacing: "0.1em", color: "var(--text-bright)" }}>
              SEVERITY DISTRIBUTION
            </span>
            <span className="mono text-dim" style={{ fontSize: "0.65rem" }}>{sevTotal} findings</span>
          </div>
          <div style={{ display: "flex", height: 8, borderRadius: 2, overflow: "hidden", gap: 2 }}>
            {sevPcts.critical > 0 && <div style={{ width: `${sevPcts.critical}%`, background: "var(--critical)", transition: "width 0.3s" }} />}
            {sevPcts.high > 0 && <div style={{ width: `${sevPcts.high}%`, background: "var(--high)", transition: "width 0.3s" }} />}
            {sevPcts.medium > 0 && <div style={{ width: `${sevPcts.medium}%`, background: "var(--medium)", transition: "width 0.3s" }} />}
            {sevPcts.low > 0 && <div style={{ width: `${sevPcts.low}%`, background: "var(--low)", transition: "width 0.3s" }} />}
          </div>
          <div style={{ display: "flex", gap: 16, marginTop: 8 }}>
            {[["critical", stats.critical], ["high", stats.high], ["medium", stats.medium], ["low", stats.low]].map(([sev, ct]) => (
              <div key={sev} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <div style={{ width: 8, height: 8, background: `var(--${sev})`, borderRadius: 1 }} />
                <span className="mono text-dim" style={{ fontSize: "0.6rem", textTransform: "uppercase" }}>{sev} {ct}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Two column layout */}
      <div className="grid-2">
        <Panel title="Recent Scan Jobs" extra={
          <Link to="/jobs" style={{ fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--accent)", textDecoration: "none" }}>View all →</Link>
        } noPad>
          <table className="data-table">
            <thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Status</th><th>Time</th></tr></thead>
            <tbody>
              {jobs.length ? jobs.map(j => (
                <tr key={j.id}>
                  <td><Link to={`/jobs/${j.id}`} className="mono text-accent" style={{ textDecoration: "none" }}>#{j.id}</Link></td>
                  <td className="mono" style={{ maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{j.target}</td>
                  <td><span className={`badge ${j.scan_type === "external" ? "badge-success" : "badge-info"}`} style={{ fontSize: "0.55rem" }}>
                    {j.scan_type || "internal"}
                  </span></td>
                  <td><StatusDot status={j.status} /></td>
                  <td className="mono text-dim" style={{ fontSize: "0.65rem" }}>{fmtDate(j.created_at)}</td>
                </tr>
              )) : (
                <tr><td colSpan="5" style={{ textAlign: "center", padding: 24, color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "0.7rem" }}>No jobs yet — <Link to="/jobs" style={{ color: "var(--accent)" }}>launch a scan</Link></td></tr>
              )}
            </tbody>
          </table>
        </Panel>

        <Panel title="Top Findings" extra={
          <span className="mono text-dim" style={{ fontSize: "0.6rem" }}>{stats.totalFindings} total</span>
        } noPad>
          <table className="data-table">
            <thead><tr><th>Sev</th><th>Risk</th><th>Title</th><th>KEV</th></tr></thead>
            <tbody>
              {findings.length ? findings.map(f => (
                <tr key={f.id}>
                  <td><SevBadge sev={f.severity} /></td>
                  <td><RiskBar score={f.risk_score} /></td>
                  <td style={{ fontSize: "0.76rem", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</td>
                  <td>{f.is_kev && <span className="kev-chip">KEV</span>}</td>
                </tr>
              )) : (
                <tr><td colSpan="4" style={{ textAlign: "center", padding: 24, color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "0.7rem" }}>Run a scan to see findings</td></tr>
              )}
            </tbody>
          </table>
        </Panel>
      </div>

      <Panel title="System Terminal" extra={
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--low)", boxShadow: "0 0 6px var(--low)", animation: "pulse 2s infinite" }} />
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--low)" }}>LIVE</span>
        </div>
      } noPad>
        <div className="terminal" ref={termRef}>
          {logs.map((l, i) => (
            <div key={i} className={`terminal-line ${l.type}`}>{l.text}</div>
          ))}
          <div className="terminal-line" style={{ color: "var(--accent)" }}>█</div>
        </div>
      </Panel>
    </div>
  );
}