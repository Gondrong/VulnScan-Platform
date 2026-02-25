import React, { useEffect, useState, useRef } from "react";
import { api } from "../api";
import { SevBadge, RiskBar, StatusDot, Panel, fmtDate } from "../components/ui.jsx";

export default function Dashboard() {
  const [jobs, setJobs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, kev: 0, total: 0 });
  const [logs, setLogs] = useState([
    { type: "info", text: "[SYSTEM] VulnScan Platform v1.0.0 initializing..." },
    { type: "ok",   text: "[OK] Database connection established" },
    { type: "ok",   text: "[OK] Redis queue worker active" },
    { type: "ok",   text: "[OK] Neo4j graph connected" },
    { type: "ok",   text: "[PLUGINS] 12 scan plugins loaded" },
    { type: "info", text: "[SYSTEM] Awaiting scan jobs..." },
  ]);
  const termRef = useRef(null);

  function addLog(type, text) {
    setLogs(l => [...l.slice(-49), { type, text }]);
  }

  async function load() {
    try {
      const allJobs = await api("/scan/jobs");
      setJobs(allJobs.slice(0, 6));
      setStats(s => ({ ...s, total: allJobs.length }));

      const doneJob = allJobs.find(j => j.status === "done");
      if (doneJob) {
        const detail = await api(`/scan/jobs/${doneJob.id}`);
        const fs = detail.findings || [];
        setFindings(fs.slice(0, 6));
        setStats({
          total: allJobs.length,
          critical: fs.filter(f => f.severity === "critical").length,
          high: fs.filter(f => f.severity === "high").length,
          kev: fs.filter(f => f.is_kev).length,
        });
        addLog("ok", `[REFRESH] ${allJobs.length} jobs, ${fs.length} findings loaded`);
      } else {
        addLog("info", `[REFRESH] ${allJobs.length} jobs loaded`);
      }
    } catch (e) {
      addLog("err", "[ERROR] " + e.message);
    }
  }

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, []);
  useEffect(() => { if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight; }, [logs]);

  const STAT_CARDS = [
    { label: "Critical", val: stats.critical, cls: "critical" },
    { label: "High", val: stats.high, cls: "high" },
    { label: "KEV Hits", val: stats.kev, cls: "medium" },
    { label: "Total Scans", val: stats.total, cls: "info" },
  ];

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Threat <span className="accent">Dashboard</span></div>
          <div className="page-desc">// Real-time vulnerability posture overview</div>
        </div>
        <button className="btn btn-primary" onClick={load}>↻ REFRESH</button>
      </div>

      <div className="stats-grid">
        {STAT_CARDS.map(c => (
          <div key={c.label} className={`stat-card ${c.cls}`}>
            <div className="stat-label">{c.label}</div>
            <div className="stat-val">{c.val}</div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-dim)", marginTop: 4 }}>Findings</div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <Panel title="Recent Scan Jobs" extra={
          <button className="btn btn-ghost btn-sm" onClick={load}>↻</button>
        } noPad>
          <table className="data-table">
            <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Time</th></tr></thead>
            <tbody>
              {jobs.length ? jobs.map(j => (
                <tr key={j.id}>
                  <td className="mono text-accent">#{j.id}</td>
                  <td className="mono">{j.target}</td>
                  <td><StatusDot status={j.status} /></td>
                  <td className="mono text-dim" style={{ fontSize: "0.68rem" }}>{fmtDate(j.created_at)}</td>
                </tr>
              )) : (
                <tr><td colSpan="4" style={{ textAlign: "center", padding: 24, color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "0.7rem" }}>No jobs yet</td></tr>
              )}
            </tbody>
          </table>
        </Panel>

        <Panel title="Top Findings" noPad>
          <table className="data-table">
            <thead><tr><th>Sev</th><th>Risk</th><th>Title</th><th>KEV</th></tr></thead>
            <tbody>
              {findings.length ? findings.map(f => (
                <tr key={f.id}>
                  <td><SevBadge sev={f.severity} /></td>
                  <td><RiskBar score={f.risk_score} /></td>
                  <td style={{ fontSize: "0.78rem", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</td>
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
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--accent)" }}>LIVE</span>
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
