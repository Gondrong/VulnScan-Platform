import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Panel, Alert, fmtDate } from "../components/ui.jsx";

export default function Credentials() {
  const [creds, setCreds] = useState([]);
  const [name, setName] = useState("prod-ssh");
  const [username, setUsername] = useState("ubuntu");
  const [secretType, setSecretType] = useState("ssh_key");
  const [secret, setSecret] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [msg, setMsg] = useState({ type: "", text: "" });

  async function load() { setCreds(await api("/credentials")); }
  useEffect(() => { load(); }, []);

  async function create() {
    setMsg({ type: "", text: "" });
    try {
      await api("/credentials", { method: "POST", body: {
        name, kind: "ssh", username, secret_type: secretType,
        secret, passphrase: passphrase || null,
      }});
      setMsg({ type: "success", text: "✓ Credential stored securely (AES-256 encrypted)" });
      setSecret(""); setPassphrase("");
      await load();
    } catch (e) { setMsg({ type: "danger", text: e.message }); }
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title"><span className="accent">SSH</span> Credentials</div>
          <div className="page-desc">// Manage authenticated scan credentials — AES-256 encrypted at rest</div>
        </div>
      </div>

      <div className="grid-2">
        <Panel title="Add Credential" extra={<span className="badge badge-info">ADMIN</span>}>
          {msg.text && <Alert type={msg.type} onClose={() => setMsg({ type: "", text: "" })}>{msg.text}</Alert>}
          <div className="form-group">
            <label className="form-label">Credential Name</label>
            <input className="form-control" value={name} onChange={e => setName(e.target.value)} placeholder="e.g. prod-ssh-key" />
          </div>
          <div className="form-group">
            <label className="form-label">SSH Username</label>
            <input className="form-control" value={username} onChange={e => setUsername(e.target.value)} placeholder="ubuntu" />
          </div>
          <div className="form-group">
            <label className="form-label">Secret Type</label>
            <select className="form-control" value={secretType} onChange={e => setSecretType(e.target.value)}>
              <option value="ssh_key">SSH Private Key</option>
              <option value="password">Password</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">{secretType === "ssh_key" ? "SSH Private Key (PEM)" : "Password"}</label>
            <textarea
              className="form-control" rows={6} value={secret}
              onChange={e => setSecret(e.target.value)}
              placeholder={secretType === "ssh_key"
                ? "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"
                : "Enter password"}
            />
          </div>
          {secretType === "ssh_key" && (
            <div className="form-group">
              <label className="form-label">Key Passphrase (optional)</label>
              <input className="form-control" type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder="Leave empty if none" />
            </div>
          )}
          <button className="btn btn-primary btn-full" onClick={create}>⊕ STORE CREDENTIAL</button>
          <div style={{
            marginTop: 12, padding: 10,
            background: "rgba(0,212,255,0.04)",
            border: "1px solid rgba(0,212,255,0.12)",
            fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--text-dim)",
            lineHeight: 1.6,
          }}>
            ⚿ Secrets encrypted with AES-256 (Fernet) before storage. Private keys are never returned via API responses.
          </div>
        </Panel>

        <div>
          <Panel title="Stored Credentials" extra={
            <button className="btn btn-ghost btn-sm" onClick={load}>↻</button>
          } noPad>
            <table className="data-table">
              <thead><tr><th>ID</th><th>Name</th><th>Username</th><th>Type</th><th>Created</th></tr></thead>
              <tbody>
                {creds.length ? creds.map(c => (
                  <tr key={c.id}>
                    <td className="mono text-accent">#{c.id}</td>
                    <td className="text-bright">{c.name}</td>
                    <td className="mono">{c.username}</td>
                    <td><span className="badge badge-info">{c.secret_type}</span></td>
                    <td className="mono text-dim" style={{ fontSize: "0.68rem" }}>{fmtDate(c.created_at)}</td>
                  </tr>
                )) : (
                  <tr><td colSpan="5"><div className="empty-state" style={{ padding: 28 }}>No credentials stored</div></td></tr>
                )}
              </tbody>
            </table>
          </Panel>

          <Panel title="Profile Integration" style={{ marginTop: 16 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--text-dim)", marginBottom: 10, letterSpacing: "0.1em" }}>
              Reference credentials in profile options_json:
            </div>
            <div className="terminal" style={{ maxHeight: 140 }}>
              {`{
  "auth": {
    "ssh_credential_id": 1,
    "ssh_port": 22
  }
}`.split("\n").map((line, i) => (
                <div key={i} className="terminal-line">
                  {line.replace(/"([^"]+)":/g, (_, k) => `<span style="color:var(--accent)">"${k}"</span>:`)}
                  {line}
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
