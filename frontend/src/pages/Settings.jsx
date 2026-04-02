import React, { useEffect, useState } from "react";
import { api, API } from "../api";
import { Panel, Alert } from "../components/ui.jsx";

const TABS = ["General", "Users", "Integrations"];

export default function Settings() {
  const [tab, setTab] = useState("General");
  const [msg, setMsg] = useState({ type: "", text: "" });

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Platform <span className="accent">Settings</span></div>
          <div className="page-desc">// System configuration, users, and integrations</div>
        </div>
      </div>

      <div className="settings-tabs" style={{ display: "flex", gap: 0, marginBottom: 20, borderBottom: "1px solid var(--border)", flexWrap: "wrap" }}>
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => {
              setTab(t);
              setMsg({ type: "", text: "" });
            }}
            style={{
              padding: "10px 20px",
              cursor: "pointer",
              background: tab === t ? "rgba(0,212,255,0.06)" : "transparent",
              border: "none",
              borderBottom: tab === t ? "2px solid var(--accent)" : "2px solid transparent",
              color: tab === t ? "var(--accent)" : "var(--text-dim)",
              fontFamily: "var(--font-head)",
              fontSize: "0.85rem",
              fontWeight: 600,
              letterSpacing: "0.08em",
              transition: "all 0.15s",
            }}
          >
            {t}
          </button>
        ))}
      </div>

      {msg.text && <Alert type={msg.type} onClose={() => setMsg({ type: "", text: "" })}>{msg.text}</Alert>}

      {tab === "General" && <GeneralTab setMsg={setMsg} />}
      {tab === "Users" && <UsersTab setMsg={setMsg} />}
      {tab === "Integrations" && <IntegrationsTab setMsg={setMsg} />}
    </div>
  );
}

function GeneralTab({ setMsg }) {
  const [info, setInfo] = useState(null);
  const [stats, setStats] = useState(null);
  const [allowlist, setAllowlist] = useState("");

  async function load() {
    try {
      const [i, s, a] = await Promise.all([
        api("/settings/info"),
        api("/settings/stats"),
        api("/settings/allowlist"),
      ]);
      setInfo(i);
      setStats(s);
      setAllowlist(a.raw || "");
    } catch (e) {
      setMsg({ type: "danger", text: e.message });
    }
  }

  useEffect(() => { load(); }, []);

  async function saveAllowlist() {
    try {
      await api("/settings/allowlist", { method: "PUT", body: { allowlist } });
      setMsg({ type: "success", text: "OK Allowlist updated" });
    } catch (e) {
      setMsg({ type: "danger", text: e.message });
    }
  }

  return (
    <div className="grid-2">
      <Panel title="Allowlist">
        <div className="form-group">
          <label className="form-label">Allowed Targets</label>
          <textarea
            className="form-control"
            rows={4}
            value={allowlist}
            onChange={(e) => setAllowlist(e.target.value)}
            placeholder="*, 10.0.0.0/8, .example.com"
          />
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.6rem", color: "var(--text-dim)", marginTop: 4 }}>
            Comma-separated: CIDR ranges, IPs, domain suffixes, or * for all
          </div>
        </div>
        <button className="btn btn-primary" onClick={saveAllowlist}>Save Allowlist</button>
      </Panel>

      <div>
        <Panel title="Platform Info">
          {info && (
            <div style={{ display: "grid", gap: 8 }}>
              {Object.entries(info).map(([k, v]) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderBottom: "1px solid var(--border)" }}>
                  <span className="mono text-dim" style={{ fontSize: "0.68rem" }}>{k}</span>
                  <span className="mono text-accent" style={{ fontSize: "0.68rem", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {String(v)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Workspace Stats" style={{ marginTop: 16 }}>
          {stats && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              {Object.entries(stats).map(([k, v]) => (
                <div key={k} style={{ padding: "8px 10px", background: "var(--surface2)", border: "1px solid var(--border)" }}>
                  <div className="mono text-dim" style={{ fontSize: "0.58rem", letterSpacing: "0.15em", textTransform: "uppercase" }}>
                    {k.replace(/_/g, " ")}
                  </div>
                  <div style={{ fontFamily: "var(--font-head)", fontSize: "1.4rem", fontWeight: 800, color: "var(--text-bright)", marginTop: 2 }}>
                    {v}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

function UsersTab({ setMsg }) {
  const [users, setUsers] = useState([]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [loading, setLoading] = useState(false);

  async function load() {
    try {
      setUsers(await api("/settings/users"));
    } catch (e) {
      setMsg({ type: "danger", text: e.message });
    }
  }

  useEffect(() => { load(); }, []);

  async function createUser() {
    if (!email || !password) return setMsg({ type: "danger", text: "Email and password required" });
    setLoading(true);
    try {
      await api("/settings/users", { method: "POST", body: { email, password, role } });
      setMsg({ type: "success", text: `OK User ${email} created` });
      setEmail("");
      setPassword("");
      await load();
    } catch (e) {
      setMsg({ type: "danger", text: e.message });
    } finally {
      setLoading(false);
    }
  }

  async function deleteUser(id) {
    if (!window.confirm("Delete this user?")) return;
    try {
      await api(`/settings/users/${id}`, { method: "DELETE" });
      setMsg({ type: "success", text: "OK User deleted" });
      await load();
    } catch (e) {
      setMsg({ type: "danger", text: e.message });
    }
  }

  return (
    <div className="grid-2">
      <Panel title="Add User">
        <div className="form-group">
          <label className="form-label">Email</label>
          <input className="form-control" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="user@company.com" />
        </div>
        <div className="form-group">
          <label className="form-label">Password</label>
          <input className="form-control" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Strong password" />
        </div>
        <div className="form-group">
          <label className="form-label">Role</label>
          <select className="form-control" value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="admin">Admin - Full access</option>
            <option value="analyst">Analyst - Scan & view</option>
            <option value="viewer">Viewer - Read only</option>
          </select>
        </div>
        <button className="btn btn-primary btn-full" onClick={createUser} disabled={loading}>
          {loading && <div className="spinner" />} + CREATE USER
        </button>
      </Panel>

      <Panel title="User Accounts" noPad>
        <table className="data-table">
          <thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Created</th><th></th></tr></thead>
          <tbody>
            {users.length ? users.map((u) => (
              <tr key={u.id}>
                <td className="mono text-accent">#{u.id}</td>
                <td className="text-bright">{u.email}</td>
                <td><span className={`badge ${u.role === "admin" ? "badge-critical" : u.role === "analyst" ? "badge-medium" : "badge-info"}`}>{u.role}</span></td>
                <td className="mono text-dim" style={{ fontSize: "0.68rem" }}>{u.created_at ? new Date(u.created_at).toLocaleDateString() : "-"}</td>
                <td>
                  <button className="btn btn-ghost btn-sm" style={{ color: "var(--critical)", borderColor: "rgba(255,71,87,0.3)" }} onClick={() => deleteUser(u.id)}>
                    x
                  </button>
                </td>
              </tr>
            )) : (
              <tr><td colSpan="5"><div className="empty-state" style={{ padding: 24 }}>No users</div></td></tr>
            )}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}

function IntegrationsTab({ setMsg }) {
  const [integrations, setIntegrations] = useState({
    slack_webhook: "", email_smtp_host: "", email_smtp_port: "587",
    email_from: "", email_to: "", email_password: "",
    webhook_url: "",
  });
  const [loading, setLoading] = useState(false);
  const [testLoading, setTestLoading] = useState("");

  async function load() {
    try {
      const data = await api("/settings/integrations");
      if (data && typeof data === "object") setIntegrations((prev) => ({ ...prev, ...data }));
    } catch {
      // endpoint may not exist yet
    }
  }

  useEffect(() => { load(); }, []);

  function update(key, val) {
    setIntegrations((prev) => ({ ...prev, [key]: val }));
  }

  async function save() {
    setLoading(true);
    try {
      await api("/settings/integrations", { method: "PUT", body: integrations });
      setMsg({ type: "success", text: "OK Integrations saved" });
    } catch (e) {
      setMsg({ type: "danger", text: e.message });
    } finally {
      setLoading(false);
    }
  }

  async function testIntegration(type) {
    setTestLoading(type);
    try {
      await api("/settings/integrations/test", { method: "POST", body: { type, ...integrations } });
      setMsg({ type: "success", text: `OK ${type} test sent successfully` });
    } catch (e) {
      setMsg({ type: "danger", text: `${type} test failed: ${e.message}` });
    } finally {
      setTestLoading("");
    }
  }

  const cardStyle = {
    padding: 16, background: "var(--surface)", border: "1px solid var(--border)", marginBottom: 16,
  };
  const headerStyle = {
    display: "flex", alignItems: "center", gap: 8, marginBottom: 14,
    fontFamily: "var(--font-head)", fontSize: "0.9rem", fontWeight: 600,
    color: "var(--text-bright)", letterSpacing: "0.05em",
  };

  return (
    <div>
      <div className="settings-integrations-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div style={cardStyle}>
          <div style={headerStyle}><span style={{ fontSize: "1.2rem" }}>Slack</span> Slack Webhook</div>
          <div className="form-group">
            <label className="form-label">Webhook URL</label>
            <input className="form-control" value={integrations.slack_webhook} onChange={(e) => update("slack_webhook", e.target.value)} placeholder="https://hooks.slack.com/services/..." />
          </div>
          <div className="settings-inline-actions" style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button className="btn btn-outline btn-sm" onClick={() => testIntegration("slack")} disabled={testLoading === "slack"}>
              {testLoading === "slack" ? <div className="spinner" /> : "Test"}
            </button>
          </div>
        </div>

        <div style={cardStyle}>
          <div style={headerStyle}><span style={{ fontSize: "1.2rem" }}>Email</span> Email (SMTP)</div>
          <div className="settings-email-grid" style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 8 }}>
            <div className="form-group">
              <label className="form-label">SMTP Host</label>
              <input className="form-control" value={integrations.email_smtp_host} onChange={(e) => update("email_smtp_host", e.target.value)} placeholder="smtp.gmail.com" />
            </div>
            <div className="form-group">
              <label className="form-label">Port</label>
              <input className="form-control" value={integrations.email_smtp_port} onChange={(e) => update("email_smtp_port", e.target.value)} placeholder="587" />
            </div>
          </div>
          <div className="form-group">
            <label className="form-label">From Address</label>
            <input className="form-control" value={integrations.email_from} onChange={(e) => update("email_from", e.target.value)} placeholder="alerts@company.com" />
          </div>
          <div className="form-group">
            <label className="form-label">Password / App Token</label>
            <input className="form-control" type="password" value={integrations.email_password} onChange={(e) => update("email_password", e.target.value)} placeholder="App password" />
          </div>
          <div className="form-group">
            <label className="form-label">Send To</label>
            <input className="form-control" value={integrations.email_to} onChange={(e) => update("email_to", e.target.value)} placeholder="team@company.com" />
          </div>
          <button className="btn btn-outline btn-sm" onClick={() => testIntegration("email")} disabled={testLoading === "email"}>
            {testLoading === "email" ? <div className="spinner" /> : "Send Test Email"}
          </button>
        </div>

        <div style={cardStyle}>
          <div style={headerStyle}><span style={{ fontSize: "1.2rem" }}>Webhook</span> Generic Webhook</div>
          <div className="form-group">
            <label className="form-label">Webhook URL</label>
            <input className="form-control" value={integrations.webhook_url} onChange={(e) => update("webhook_url", e.target.value)} placeholder="https://your-service.com/webhook" />
          </div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.6rem", color: "var(--text-dim)", marginTop: 4, marginBottom: 10, lineHeight: 1.6 }}>
            Receives POST with JSON body on scan complete, critical finding, etc.
          </div>
          <button className="btn btn-outline btn-sm" onClick={() => testIntegration("webhook")} disabled={testLoading === "webhook"}>
            {testLoading === "webhook" ? <div className="spinner" /> : "Test Webhook"}
          </button>
        </div>

        <div style={cardStyle}>
          <div style={headerStyle}><span style={{ fontSize: "1.2rem" }}>API</span> API Access</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.68rem", color: "var(--text-dim)", lineHeight: 1.8, marginBottom: 12 }}>
            All endpoints require a Bearer token from <span className="text-accent">/auth/login</span>
          </div>
          <div style={{ padding: 10, background: "#050a0e", border: "1px solid var(--border)", fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--accent)", lineHeight: 1.8 }}>
            <div style={{ color: "var(--text-dim)" }}># Authenticate</div>
            <div>curl -X POST {API}/auth/login \</div>
            <div>  -d '{`{"email":"admin@local","password":"admin123"}`}'</div>
            <div style={{ color: "var(--text-dim)", marginTop: 8 }}># Launch scan</div>
            <div>curl -X POST {API}/scan/jobs \</div>
            <div>  -H "Authorization: Bearer $TOKEN" \</div>
            <div>  -d '{`{"target":"10.0.0.1","profile_id":1}`}'</div>
            <div style={{ color: "var(--text-dim)", marginTop: 8 }}># Get findings</div>
            <div>curl {API}/scan/jobs/1 \</div>
            <div>  -H "Authorization: Bearer $TOKEN"</div>
          </div>
          <div style={{ marginTop: 12, display: "grid", gap: 4 }}>
            {["/auth/login", "/scan/jobs", "/scan/profiles", "/datasets", "/credentials", "/settings/stats"].map((ep) => (
              <div key={ep} style={{ display: "flex", justifyContent: "space-between", padding: "3px 0" }}>
                <span className="mono text-accent" style={{ fontSize: "0.65rem" }}>{ep}</span>
                <span className="mono text-dim" style={{ fontSize: "0.6rem" }}>GET/POST</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <button className="btn btn-primary btn-lg settings-save-btn" onClick={save} disabled={loading} style={{ gap: 8 }}>
        {loading && <div className="spinner" />} SAVE ALL INTEGRATIONS
      </button>
    </div>
  );
}
