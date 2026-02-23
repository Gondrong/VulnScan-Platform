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

const CAT_COLORS = {
  network: "badge-info", fingerprint: "badge-info", cpe: "badge-medium",
  cve: "badge-warning", priority: "badge-critical", tls: "badge-medium",
  auth: "badge-success",
};

export default function Profiles() {
  const [profiles, setProfiles] = useState([]);
  const [name, setName] = useState("default");
  const [pluginsJson, setPluginsJson] = useState(JSON.stringify({
    "net.port.discovery.v2": true, "fingerprint.http": true,
    "fingerprint.banner.multi": true, "fingerprint.web.tech": true,
    "fingerprint.favicon.hash": true, "cpe.builder": true,
    "cve.match.nvd_cpe": true, "cve.match.cms": true,
    "priority.cisa_kev": true, "tls.basic.version": true,
    "auth.ssh.inventory": false, "cve.match.packages": false,
  }, null, 2));
  const [optionsJson, setOptionsJson] = useState(JSON.stringify({
    "auth": { "ssh_credential_id": 1, "ssh_port": 22 },
    "cve": { "dataset_kinds": ["osv","nvd_cpe_cve","cisa_kev"] },
    "asset": { "criticality": 2 },
  }, null, 2));
  const [msg, setMsg] = useState({ type: "", text: "" });

  async function load() { setProfiles(await api("/scan/profiles")); }
  useEffect(() => { load(); }, []);

  async function create() {
    setMsg({ type: "", text: "" });
    try { JSON.parse(pluginsJson); } catch { return setMsg({ type: "danger", text: "Invalid plugin JSON" }); }
    try { JSON.parse(optionsJson); } catch { return setMsg({ type: "danger", text: "Invalid options JSON" }); }
    try {
      await api("/scan/profiles", { method: "POST", body: { name, plugin_selection_json: pluginsJson, options_json: optionsJson } });
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
        <Panel title="Create Profile">
          {msg.text && <Alert type={msg.type} onClose={() => setMsg({ type: "", text: "" })}>{msg.text}</Alert>}
          <div className="form-group">
            <label className="form-label">Profile Name</label>
            <input className="form-control" value={name} onChange={e => setName(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Plugin Selection (JSON)</label>
            <textarea className="form-control" rows={10} value={pluginsJson} onChange={e => setPluginsJson(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Options (JSON)</label>
            <textarea className="form-control" rows={7} value={optionsJson} onChange={e => setOptionsJson(e.target.value)} />
          </div>
          <button className="btn btn-primary btn-full" onClick={create}>⬡ CREATE PROFILE</button>
        </Panel>

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
