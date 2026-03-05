import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Panel, Alert, fmtDate } from "../components/ui.jsx";

const PLUGINS = [
  ["net.port.discovery.v2", "network", true],
  ["fingerprint.http", "fingerprint", true],
  ["fingerprint.banner.multi", "fingerprint", true],
  ["fingerprint.web.tech", "fingerprint", true],
  ["fingerprint.favicon.hash", "fingerprint", true],
  ["cpe.builder", "cpe", true],
  ["cve.match.nvd_cpe", "cve", true],
  ["cve.match.cms", "cve", true],
  ["priority.cisa_kev", "priority", true],
  ["tls.basic.version", "tls", true],
  ["auth.ssh.inventory", "auth", false],
  ["cve.match.packages", "cve", false],
];

const DATASET_KINDS = [
  ["nvd_cpe_cve", "NVD CPE→CVE", true],
  ["cisa_kev", "CISA KEV", true],
  ["cvedetails_cvss", "CNA/ADP CVSS", false],
  ["epss", "EPSS Scores", false],
  ["cms_cve_map", "CMS CVE Map", false],
  ["compliance_map", "Compliance", true],
];

const CAT_COLORS = {
  network: "badge-info", fingerprint: "badge-info", cpe: "badge-medium",
  cve: "badge-warning", priority: "badge-critical", tls: "badge-medium",
  auth: "badge-success",
};

export default function Profiles() {
  const [profiles, setProfiles] = useState([]);
  const [name, setName] = useState("default");
  const [plugins, setPlugins] = useState(() => {
    const p = {};
    PLUGINS.forEach(([id, , def]) => p[id] = def);
    return p;
  });
  const [dsKinds, setDsKinds] = useState(() => {
    const k = {};
    DATASET_KINDS.forEach(([id, , def]) => k[id] = def);
    return k;
  });
  const [sshCredId, setSshCredId] = useState(1);
  const [sshPort, setSshPort] = useState(22);
  const [criticality, setCriticality] = useState(2);
  const [credentials, setCredentials] = useState([]);
  const [msg, setMsg] = useState({ type: "", text: "" });

  async function load() {
    const [p, c] = await Promise.all([
      api("/scan/profiles"),
      api("/credentials").catch(() => []),
    ]);
    setProfiles(p);
    setCredentials(c);
  }
  useEffect(() => { load(); }, []);

  function togglePlugin(id) {
    setPlugins(p => ({ ...p, [id]: !p[id] }));
  }

  function toggleDsKind(id) {
    setDsKinds(k => ({ ...k, [id]: !k[id] }));
  }

  function buildOptionsJson() {
    const kinds = Object.entries(dsKinds).filter(([, v]) => v).map(([k]) => k);
    return JSON.stringify({
      auth: { ssh_credential_id: sshCredId, ssh_port: sshPort },
      cve: { dataset_kinds: kinds },
      asset: { criticality },
    });
  }

  async function create() {
    setMsg({ type: "", text: "" });
    try {
      const pluginsJson = JSON.stringify(plugins);
      const optionsJson = buildOptionsJson();
      await api("/scan/profiles", {
        method: "POST",
        body: { name, plugin_selection_json: pluginsJson, options_json: optionsJson }
      });
      setMsg({ type: "success", text: `✓ Profile created: ${name}` });
      await load();
    } catch (e) { setMsg({ type: "danger", text: e.message }); }
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Scan <span className="accent">Profiles</span></div>
          <div className="page-desc">// Configure plugin selection and scan options</div>
        </div>
      </div>
      <div className="grid-2">
        <div>
          <Panel title="Create Profile">
            {msg.text && <Alert type={msg.type} onClose={() => setMsg({ type: "", text: "" })}>{msg.text}</Alert>}
            <div className="form-group">
              <label className="form-label">Profile Name</label>
              <input className="form-control" value={name} onChange={e => setName(e.target.value)} />
            </div>

            {/* Plugin toggles */}
            <div className="form-group">
              <label className="form-label">Plugins</label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 4 }}>
                {PLUGINS.map(([id, cat]) => (
                  <label key={id} style={{
                    display: "flex", alignItems: "center", gap: 5,
                    padding: "4px 8px", cursor: "pointer",
                    background: plugins[id] ? "rgba(0,212,255,0.08)" : "var(--surface2)",
                    border: `1px solid ${plugins[id] ? "rgba(0,212,255,0.3)" : "var(--border)"}`,
                    fontFamily: "var(--font-mono)", fontSize: "0.65rem",
                    color: plugins[id] ? "var(--accent)" : "var(--text-dim)",
                    transition: "all 0.15s",
                  }}>
                    <input
                      type="checkbox"
                      checked={plugins[id] || false}
                      onChange={() => togglePlugin(id)}
                      style={{ accentColor: "var(--accent)" }}
                    />
                    {id}
                  </label>
                ))}
              </div>
            </div>

            {/* Scan Options */}
            <div className="form-group">
              <label className="form-label">Scan Options</label>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 4 }}>
                <div>
                  <label className="form-label" style={{ fontSize: "0.6rem" }}>SSH Credential</label>
                  <select className="form-control" value={sshCredId} onChange={e => setSshCredId(Number(e.target.value))}>
                    {credentials.length ? credentials.map(c => (
                      <option key={c.id} value={c.id}>#{c.id} — {c.name} ({c.username})</option>
                    )) : <option value={1}>Default (#1)</option>}
                  </select>
                </div>
                <div>
                  <label className="form-label" style={{ fontSize: "0.6rem" }}>SSH Port</label>
                  <input className="form-control" type="number" value={sshPort} onChange={e => setSshPort(Number(e.target.value))} />
                </div>
              </div>
              <div style={{ marginTop: 10 }}>
                <label className="form-label" style={{ fontSize: "0.6rem" }}>Asset Criticality (1–5)</label>
                <input className="form-control" type="number" min={1} max={5} value={criticality} onChange={e => setCriticality(Number(e.target.value))} />
              </div>
            </div>

            {/* Dataset kind checkboxes */}
            <div className="form-group">
              <label className="form-label">CVE Dataset Kinds</label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 6 }}>
                {DATASET_KINDS.map(([id, label]) => (
                  <label key={id} style={{
                    display: "flex", alignItems: "center", gap: 5,
                    padding: "5px 10px", cursor: "pointer",
                    background: dsKinds[id] ? "rgba(0,212,255,0.08)" : "var(--surface2)",
                    border: `1px solid ${dsKinds[id] ? "rgba(0,212,255,0.3)" : "var(--border)"}`,
                    fontFamily: "var(--font-mono)", fontSize: "0.68rem",
                    color: dsKinds[id] ? "var(--accent)" : "var(--text-dim)",
                    transition: "all 0.15s",
                  }}>
                    <input
                      type="checkbox"
                      checked={dsKinds[id] || false}
                      onChange={() => toggleDsKind(id)}
                      style={{ accentColor: "var(--accent)" }}
                    />
                    {label}
                  </label>
                ))}
              </div>
            </div>

            {/* Generated JSON preview */}
            <div className="form-group">
              <label className="form-label" style={{ fontSize: "0.6rem", opacity: 0.6 }}>Generated Options JSON</label>
              <div style={{
                padding: "8px 10px", background: "var(--surface2)",
                border: "1px solid var(--border)",
                fontFamily: "var(--font-mono)", fontSize: "0.6rem",
                color: "var(--text-dim)", wordBreak: "break-all",
              }}>
                {buildOptionsJson()}
              </div>
            </div>

            <button className="btn btn-primary btn-full" onClick={create}>⬡ CREATE PROFILE</button>
          </Panel>
        </div>

        <div>
          <Panel title="Available Plugins" noPad>
            <table className="data-table" style={{ fontSize: "0.78rem" }}>
              <thead><tr><th>Plugin ID</th><th>Category</th><th>Default</th></tr></thead>
              <tbody>
                {PLUGINS.map(([id, cat, def]) => (
                  <tr key={id}>
                    <td className="mono text-accent" style={{ fontSize: "0.72rem" }}>{id}</td>
                    <td><span className={`badge ${CAT_COLORS[cat] || "badge-info"}`}>{cat}</span></td>
                    <td style={{ color: def ? "var(--low)" : "var(--text-dim)" }}>{def ? "✓" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

          <Panel title="Existing Profiles" extra={
            <button className="btn btn-ghost btn-sm" onClick={load}>↻</button>
          } noPad style={{ marginTop: 16 }}>
            <table className="data-table">
              <thead><tr><th>ID</th><th>Name</th><th>Created</th></tr></thead>
              <tbody>
                {profiles.length ? profiles.map(p => (
                  <tr key={p.id}>
                    <td className="mono text-accent">#{p.id}</td>
                    <td className="text-bright">{p.name}</td>
                    <td className="mono text-dim" style={{ fontSize: "0.68rem" }}>{fmtDate(p.created_at)}</td>
                  </tr>
                )) : (
                  <tr><td colSpan="3"><div className="empty-state" style={{ padding: 24 }}>No profiles</div></td></tr>
                )}
              </tbody>
            </table>
          </Panel>
        </div>
      </div>
    </div>
  );
}
