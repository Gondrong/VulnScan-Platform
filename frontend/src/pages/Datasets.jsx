import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Panel, Alert } from "../components/ui.jsx";

const KINDS = [
  ["osv", "OSV package vulnerability database"],
  ["nvd_cpe_cve", "NVD CPE→CVE match table"],
  ["cisa_kev", "CISA Known Exploited Vulnerabilities"],
  ["favicon_hash_map", "Favicon hash fingerprint map"],
  ["cms_cve_map", "CMS-specific CVE mapping"],
  ["compliance_map", "ISO/NIST/PCI-DSS compliance map"],
];

const SCAN_FLOW = [
  "Port Discovery", "Banner Grab", "Web Tech Detect",
  "CPE Build", "CVE Match", "KEV Prioritize",
  "CVSS Score", "SLA Assign", "Compliance Map", "Graph Push"
];

export default function Datasets() {
  const [datasets, setDatasets] = useState([]);
  const [kind, setKind] = useState("nvd_cpe_cve");
  const [name, setName] = useState("nvd-feed-2024");
  const [file, setFile] = useState(null);
  const [msg, setMsg] = useState({ type: "", text: "" });
  const [loading, setLoading] = useState(false);

  async function load() { setDatasets(await api("/datasets")); }
  useEffect(() => { load(); }, []);

  async function upload() {
    if (!file) return setMsg({ type: "danger", text: "Select a JSON file first" });
    setLoading(true); setMsg({ type: "", text: "" });
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(
        `${import.meta.env.VITE_API_URL || "http://localhost:8080"}/datasets/upload?kind=${encodeURIComponent(kind)}&name=${encodeURIComponent(name)}`,
        { method: "POST", headers: { "Authorization": `Bearer ${localStorage.getItem("token")}` }, body: form }
      );
      if (!res.ok) throw new Error(await res.text());
      const r = await res.json();
      setMsg({ type: "success", text: `✓ Dataset uploaded — ID #${r.dataset_id}` });
      setFile(null);
      document.getElementById("ds-file-input").value = "";
      await load();
    } catch (e) { setMsg({ type: "danger", text: e.message }); }
    finally { setLoading(false); }
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">CVE <span className="accent">Datasets</span></div>
          <div className="page-desc">// Upload and manage threat intelligence feeds</div>
        </div>
      </div>

      <div className="grid-2">
        <Panel title="Upload Dataset" extra={<span className="badge badge-info">ADMIN</span>}>
          {msg.text && <Alert type={msg.type} onClose={() => setMsg({ type: "", text: "" })}>{msg.text}</Alert>}
          <div className="form-group">
            <label className="form-label">Dataset Kind</label>
            <select className="form-control" value={kind} onChange={e => setKind(e.target.value)}>
              {KINDS.map(([k, desc]) => <option key={k} value={k}>{k} — {desc}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Dataset Name</label>
            <input className="form-control" value={name} onChange={e => setName(e.target.value)} placeholder="Human-readable name" />
          </div>
          <div className="form-group">
            <label className="form-label">JSON File</label>
            <input
              id="ds-file-input"
              type="file"
              accept=".json"
              className="form-control"
              onChange={e => setFile(e.target.files?.[0] || null)}
            />
          </div>
          <button className="btn btn-primary btn-full" onClick={upload} disabled={loading} style={{ gap: 8 }}>
            {loading && <div className="spinner" />}
            ▦ UPLOAD DATASET
          </button>

          <div style={{ marginTop: 20 }}>
            <div className="form-label">Supported Formats</div>
            <div style={{ display: "grid", gap: 4, marginTop: 8 }}>
              {KINDS.map(([k, desc]) => (
                <div key={k} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "6px 10px",
                  background: kind === k ? "rgba(0,212,255,0.06)" : "var(--surface2)",
                  border: `1px solid ${kind === k ? "rgba(0,212,255,0.3)" : "var(--border)"}`,
                  cursor: "pointer", transition: "all 0.15s",
                }}
                  onClick={() => setKind(k)}
                >
                  <span className="mono text-accent" style={{ fontSize: "0.7rem" }}>{k}</span>
                  <span className="mono text-dim" style={{ fontSize: "0.62rem" }}>{desc}</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>

        <div>
          <Panel title="Active Datasets" extra={
            <button className="btn btn-ghost btn-sm" onClick={load}>↻</button>
          } noPad>
            <table className="data-table">
              <thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Status</th></tr></thead>
              <tbody>
                {datasets.length ? datasets.map(d => (
                  <tr key={d.id}>
                    <td className="mono text-accent">#{d.id}</td>
                    <td className="text-bright">{d.name}</td>
                    <td><span className="badge badge-info">{d.kind}</span></td>
                    <td>{d.enabled
                      ? <span className="badge badge-success">ACTIVE</span>
                      : <span className="badge">DISABLED</span>}
                    </td>
                  </tr>
                )) : (
                  <tr><td colSpan="4"><div className="empty-state" style={{ padding: 28 }}>No datasets uploaded</div></td></tr>
                )}
              </tbody>
            </table>
          </Panel>

          <Panel title="Scan Flow" style={{ marginTop: 16 }}>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 0, alignItems: "center" }}>
              {SCAN_FLOW.map((step, i) => (
                <React.Fragment key={step}>
                  <div style={{
                    padding: "6px 10px",
                    background: "var(--surface2)", border: "1px solid var(--border)",
                    fontFamily: "var(--font-mono)", fontSize: "0.65rem",
                    color: "var(--accent)", letterSpacing: "0.05em",
                    margin: "3px 0",
                  }}>
                    {i + 1}. {step}
                  </div>
                  {i < SCAN_FLOW.length - 1 && (
                    <span style={{ color: "var(--border-bright)", padding: "0 4px", fontSize: "0.8rem" }}>→</span>
                  )}
                </React.Fragment>
              ))}
            </div>

            <div style={{
              marginTop: 16, padding: 12,
              background: "rgba(46,213,115,0.04)",
              border: "1px solid rgba(46,213,115,0.15)",
              fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--text-dim)",
              lineHeight: 1.8,
            }}>
              <div style={{ color: "var(--low)", marginBottom: 6 }}>▸ RISK FORMULA</div>
              <div>Risk = (CVSS × exploit_weight) + KEV_bonus + asset_criticality × confidence</div>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
