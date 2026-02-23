import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { StatusDot, Panel, Alert, fmtDate } from "../components/ui.jsx";

export default function Jobs() {
  const [jobs, setJobs] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [target, setTarget] = useState("127.0.0.1");
  const [profileId, setProfileId] = useState("");
  const [msg, setMsg] = useState({ type: "", text: "" });
  const [loading, setLoading] = useState(false);

  async function load() {
    const [j, p] = await Promise.all([api("/scan/jobs"), api("/scan/profiles")]);
    setJobs(j); setProfiles(p);
    if (!profileId && p[0]) setProfileId(String(p[0].id));
  }

  useEffect(() => { load(); const t = setInterval(load, 4000); return () => clearInterval(t); }, []);

  async function submit() {
    if (!target.trim()) return;
    setLoading(true); setMsg({ type: "", text: "" });
    try {
      const r = await api("/scan/jobs", { method: "POST", body: { target: target.trim(), profile_id: Number(profileId) } });
      setMsg({ type: "success", text: `✓ Scan job #${r.id} launched for ${target}` });
      await load();
    } catch (e) {
      setMsg({ type: "danger", text: e.message });
    } finally { setLoading(false); }
  }

  const QUICK_TARGETS = ["127.0.0.1", "192.168.1.1", "10.0.0.1", "10.0.0.100"];

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Scan <span className="accent">Jobs</span></div>
          <div className="page-desc">// Execute and monitor vulnerability scans</div>
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: 20 }}>
        <Panel title="Launch Scan">
          {msg.text && <Alert type={msg.type} onClose={() => setMsg({ type: "", text: "" })}>{msg.text}</Alert>}
          <div className="form-group">
            <label className="form-label">Target IP / Hostname</label>
            <input
              className="form-control"
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="10.0.0.1 or host.internal.local"
              onKeyDown={e => e.key === "Enter" && submit()}
            />
          </div>
          <div className="form-group">
            <label className="form-label">Scan Profile</label>
            <select className="form-control" value={profileId} onChange={e => setProfileId(e.target.value)}>
              {profiles.map(p => <option key={p.id} value={p.id}>{p.name} (#{p.id})</option>)}
            </select>
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <button
              className="btn btn-primary btn-lg"
              style={{ flex: 1, gap: 8 }}
              onClick={submit}
              disabled={loading}
            >
              {loading && <div className="spinner" />}
              ⚡ LAUNCH SCAN
            </button>
            <button className="btn btn-ghost" onClick={load} title="Refresh">↻</button>
          </div>
        </Panel>

        <Panel title="Quick Targets">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 16 }}>
            {QUICK_TARGETS.map(t => (
              <button key={t} className="btn btn-ghost btn-sm" onClick={() => setTarget(t)}>
                {t}
              </button>
            ))}
          </div>
          <div style={{
            padding: 12,
            background: "var(--surface2)",
            border: "1px solid var(--border)",
            fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--text-dim)",
          }}>
            <div style={{ color: "var(--accent)", marginBottom: 8, letterSpacing: "0.15em" }}>ALLOWLIST</div>
            {["10.0.0.0/8", "192.168.0.0/16", ".internal.local", ".example.com"].map(a => (
              <div key={a} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 0" }}>
                <span style={{ color: "var(--accent4)" }}>▸</span>
                <span style={{ color: "var(--text)" }}>{a}</span>
              </div>
            ))}
          </div>
          <div style={{
            marginTop: 12, padding: 10,
            background: "var(--surface2)", border: "1px solid var(--border)",
          }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.62rem", color: "var(--text-dim)", marginBottom: 8, letterSpacing: "0.15em" }}>SLA POLICY</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4, fontFamily: "var(--font-mono)", fontSize: "0.65rem" }}>
              <span><span style={{ color: "var(--critical)" }}>CRITICAL</span> → 7d</span>
              <span><span style={{ color: "var(--high)" }}>HIGH</span> → 14d</span>
              <span><span style={{ color: "var(--medium)" }}>MEDIUM</span> → 30d</span>
              <span><span style={{ color: "var(--low)" }}>LOW</span> → 60d</span>
            </div>
          </div>
        </Panel>
      </div>

      <Panel title="Job History" extra={
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--text-dim)" }}>
          {jobs.length} jobs
        </span>
      } noPad>
        <table className="data-table">
          <thead>
            <tr>
              <th>Job ID</th><th>Target</th><th>Profile</th><th>Status</th><th>Created</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {jobs.length ? jobs.map(j => {
              const prof = profiles.find(p => p.id === j.profile_id);
              return (
                <tr key={j.id}>
                  <td className="mono text-accent">#{j.id}</td>
                  <td className="mono">{j.target}</td>
                  <td className="mono text-dim">{prof?.name || j.profile_id}</td>
                  <td><StatusDot status={j.status} /></td>
                  <td className="mono text-dim" style={{ fontSize: "0.68rem" }}>{fmtDate(j.created_at)}</td>
                  <td>
                    <Link to={`/jobs/${j.id}`} className="btn btn-ghost btn-sm" style={{ textDecoration: "none" }}>
                      ▸ Findings
                    </Link>
                  </td>
                </tr>
              );
            }) : (
              <tr><td colSpan="6">
                <div className="empty-state"><div className="empty-icon">◎</div>No scan jobs yet. Launch your first scan above.</div>
              </td></tr>
            )}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
