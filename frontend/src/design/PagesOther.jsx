import React, { useState, useEffect, useCallback, useRef } from "react";
import { Icons, Status } from "./icons.jsx";
import { scanApi, credentialsApi, datasetsApi, settingsApi, integrationsApi, aiApi, slaApi, threatIntelApi, notificationPrefsApi, canEdit, isAdmin } from "../api.js";

function countPluginSelection(json) {
  try {
    const sel = typeof json === "string" ? JSON.parse(json || "{}") : (json || {});
    if (Array.isArray(sel)) return sel.length;
    return Object.values(sel).filter(v => v === true).length;
  } catch { return 0; }
}

export function Profiles() {
  const [profiles, setProfiles] = useState([]);
  const [plugins, setPlugins] = useState([]);
  const [creds, setCreds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState(null); // null = closed, "new" = create, profile object = edit

  const refresh = useCallback(async () => {
    try {
      const [p, pl, cr] = await Promise.all([
        scanApi.listProfiles(),
        scanApi.listPlugins(),
        credentialsApi.list().catch(() => []),
      ]);
      setProfiles(p || []);
      setPlugins(pl?.plugins || []);
      setCreds(cr || []);
      setError("");
    } catch (e) { setError(e.message); }
    finally     { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const onDelete = async (id) => {
    if (!confirm(`Delete profile #${id}? Jobs that used it will be unlinked.`)) return;
    try { await scanApi.deleteProfile(id); refresh(); }
    catch (e) { alert(e.message); }
  };

  return (
    <>
      <div className="ph">
        <div><h1>Scan profiles</h1><div className="sub">Reusable plugin presets. Each profile defines which scanner plugins run + which credential to authenticate with.</div></div>
        {canEdit() && (
        <div className="actions">
          <button className="btn btn-primary" onClick={() => setEditing("new")} disabled={plugins.length === 0}>
            <Icons.Plus size={14}/> New profile
          </button>
        </div>
        )}
      </div>
      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}
      {loading && profiles.length === 0 ? (
        <div style={{padding: 60, textAlign: "center", color: "var(--text-3)"}}>Loading profiles…</div>
      ) : profiles.length === 0 ? (
        <div className="card" style={{padding: 40, textAlign: "center", color: "var(--text-3)"}}>
          <Icons.Layers size={28}/>
          <div style={{fontSize: 14, color: "var(--text-1)", marginTop: 12, fontWeight: 500}}>No scan profiles yet</div>
          <div style={{fontSize: 13, marginTop: 4}}>Create one to start running scans.</div>
        </div>
      ) : (
        <div style={{display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 14}}>
          {profiles.map(p => {
            const pluginCount = countPluginSelection(p.plugin_selection_json);
            return (
              <div key={p.id} className="card" style={{transition: "border-color 120ms"}}>
                <div style={{padding: "16px 18px"}}>
                  <div style={{display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12}}>
                    <div style={{flex: 1, minWidth: 0}}>
                      <div style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>{p.name}</div>
                      <div style={{fontSize: 12.5, color: "var(--text-3)", marginTop: 4, fontFamily: "var(--font-mono)"}}>#{p.id}</div>
                    </div>
                    <span className="tag brand">{pluginCount} plugins</span>
                  </div>
                  <div style={{display: "flex", gap: 16, marginTop: 16, fontSize: 12, color: "var(--text-3)"}}>
                    <div>created {p.created_at ? new Date(p.created_at).toLocaleDateString() : "—"}</div>
                  </div>
                  {canEdit() && (
                  <div style={{display: "flex", gap: 6, marginTop: 14, paddingTop: 14, borderTop: "1px solid var(--line)"}}>
                    <button className="btn btn-sm" style={{flex: 1}} onClick={() => setEditing(p)}>
                      <Icons.Edit size={12}/> Edit
                    </button>
                    <button className="btn btn-ghost btn-sm" style={{color: "var(--err)"}} onClick={() => onDelete(p.id)}>
                      <Icons.Trash size={12}/>
                    </button>
                  </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
      {editing && <ProfileModal
        plugins={plugins}
        creds={creds}
        editing={editing === "new" ? null : editing}
        close={() => setEditing(null)}
        onSaved={() => { setEditing(null); refresh(); }}
      />}
    </>
  );
}

function ProfileModal({ plugins, creds, editing, close, onSaved }) {
  const isEdit = !!editing;

  // Parse existing profile if editing
  const initialSel = (() => {
    if (!isEdit) return new Set(plugins.filter(p => p.enabled_by_default).map(p => p.plugin_id));
    try {
      const parsed = typeof editing.plugin_selection_json === "string"
        ? JSON.parse(editing.plugin_selection_json || "{}")
        : (editing.plugin_selection_json || {});
      const enabled = Object.entries(parsed)
        .filter(([, v]) => v === true)
        .map(([k]) => k);
      return new Set(enabled);
    } catch { return new Set(); }
  })();
  const initialOptions = (() => {
    if (!isEdit) return {};
    try {
      return typeof editing.options_json === "string"
        ? JSON.parse(editing.options_json || "{}")
        : (editing.options_json || {});
    } catch { return {}; }
  })();

  const [name, setName] = useState(isEdit ? editing.name : "");
  const [selected, setSelected] = useState(initialSel);
  const [credId, setCredId] = useState(initialOptions.auth?.ssh_credential_id || null);
  const [sshPort, setSshPort] = useState(initialOptions.auth?.ssh_port || 22);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const toggle = (id) => {
    const n = new Set(selected);
    n.has(id) ? n.delete(id) : n.add(id);
    setSelected(n);
  };

  const submit = async () => {
    if (!name.trim()) { setError("Name is required"); return; }
    if (selected.size === 0) { setError("Select at least one plugin"); return; }
    setSubmitting(true);
    setError("");
    try {
      const sel = {};
      for (const id of selected) sel[id] = true;

      // Preserve any other profile options (including any pre-existing web_auth
      // configured outside the UI), then merge the SSH credential block.
      // NOTE: Web auth for HTTP login is now configured at scan-launch time on
      // the New Scan dialog (per-target). This modal only owns the scanner
      // profile (plugins + SSH credential).
      const opts = { ...initialOptions };
      if (credId) {
        opts.auth = { ssh_credential_id: parseInt(credId), ssh_port: parseInt(sshPort) || 22 };
      } else if (opts.auth) {
        delete opts.auth;
      }

      const body = {
        name: name.trim(),
        plugin_selection_json: JSON.stringify(sel),
        options_json: JSON.stringify(opts),
      };
      if (isEdit) await scanApi.updateProfile(editing.id, body);
      else        await scanApi.createProfile(body);
      onSaved();
    } catch (e) {
      setError(e.message);
      setSubmitting(false);
    }
  };

  const byCategory = plugins.reduce((acc, p) => {
    (acc[p.category] = acc[p.category] || []).push(p);
    return acc;
  }, {});

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 580, maxHeight: "85vh", display: "flex", flexDirection: "column"}}>
        <div className="drawer-head">
          <Icons.Layers size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>
            {isEdit ? `Edit profile #${editing.id}` : "New scan profile"}
          </span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "20px 24px", overflowY: "auto", flex: 1}}>
          <div style={{marginBottom: 16}}>
            <label className="form-label">Profile name</label>
            <input className="form-input" placeholder="e.g. Web App Deep" value={name} onChange={e => setName(e.target.value)} autoFocus/>
          </div>

          {/* Credential picker */}
          <div style={{marginBottom: 18, padding: "12px 14px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 8}}>
            <label className="form-label" style={{display: "flex", alignItems: "center", gap: 6}}>
              <Icons.Key size={13}/> Authentication credential
            </label>
            {creds.length === 0 ? (
              <div className="form-help">
                No credentials yet. Add one in <strong>Configuration → Credentials</strong> first if you want authenticated scans (SSH-based plugins, package CVE matching, etc.).
              </div>
            ) : (
              <>
                <select className="form-input" value={credId || ""} onChange={e => setCredId(e.target.value ? parseInt(e.target.value) : null)}>
                  <option value="">— No credential (unauthenticated scan) —</option>
                  {creds.map(c => (
                    <option key={c.id} value={c.id}>
                      #{c.id} {c.name} ({c.kind} · {c.username})
                    </option>
                  ))}
                </select>
                {credId && (
                  <div style={{marginTop: 8, display: "flex", alignItems: "center", gap: 8}}>
                    <label className="form-label" style={{margin: 0, fontSize: 11}}>SSH port</label>
                    <input className="form-input mono" type="number" value={sshPort}
                           onChange={e => setSshPort(e.target.value)}
                           style={{width: 80, height: 28, fontSize: 12.5, padding: "4px 8px"}}/>
                  </div>
                )}
                <div className="form-help" style={{marginTop: 6}}>
                  Used by plugins like <span className="mono">auth.ssh.inventory</span>, <span className="mono">cve.match.packages</span>, <span className="mono">local.security.checks</span>.
                </div>
              </>
            )}
          </div>

          {/* Web Authentication is now configured per-scan in the New Scan dialog
              (it's target-specific, not profile-shared). This profile modal owns
              only the scanner config (plugins + SSH credential for OS-level auth). */}

          <div className="eyebrow" style={{marginBottom: 8}}>Plugins ({selected.size} of {plugins.length} selected)</div>
          <div style={{display: "flex", gap: 8, marginBottom: 12}}>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set(plugins.map(p => p.plugin_id)))}>Select all</button>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}>Clear</button>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set(plugins.filter(p => p.enabled_by_default).map(p => p.plugin_id)))}>Defaults</button>
          </div>
          {Object.entries(byCategory).map(([cat, list]) => (
            <div key={cat} style={{marginBottom: 16}}>
              <div style={{fontSize: 11, fontWeight: 600, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 6}}>{cat}</div>
              <div style={{display: "flex", flexDirection: "column", gap: 4}}>
                {list.map(p => (
                  <label key={p.plugin_id} style={{display: "flex", alignItems: "center", gap: 10, padding: "6px 10px", borderRadius: 6, cursor: "pointer", background: selected.has(p.plugin_id) ? "var(--brand-soft)" : "transparent"}}>
                    <input type="checkbox" checked={selected.has(p.plugin_id)} onChange={() => toggle(p.plugin_id)} style={{accentColor: "var(--brand)"}}/>
                    <span style={{fontSize: 13, color: "var(--text-1)", flex: 1}}>{p.name}</span>
                    <span className="mono" style={{fontSize: 11, color: "var(--text-3)"}}>{p.plugin_id}</span>
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
        {error && <div style={{padding: "10px 24px", color: "var(--err)", fontSize: 12.5, background: "var(--sev-critical-bg)", borderTop: "1px solid var(--line)"}}><Icons.AlertTriangle size={12}/> {error}</div>}
        <div style={{padding: "14px 24px", borderTop: "1px solid var(--line)", display: "flex", gap: 8, justifyContent: "flex-end", background: "var(--surface-1)"}}>
          <button className="btn" onClick={close} disabled={submitting}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={submitting}>
            {submitting ? <><Icons.Refresh size={12} className="spin"/> Saving…</> : <><Icons.Check size={12}/> {isEdit ? "Save changes" : "Create profile"}</>}
          </button>
        </div>
      </div>
    </>
  );
}

export function Credentials() {
  const KIND_ICONS = { ssh: Icons.Key, password: Icons.Lock, api: Icons.Code, oauth: Icons.Lock };
  const [creds, setCreds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [editing, setEditing] = useState(null);

  const refresh = useCallback(async () => {
    try { setCreds(await credentialsApi.list()); setError(""); }
    catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const onDelete = async (id, name) => {
    if (!confirm(`Delete credential "${name}"?`)) return;
    try { await credentialsApi.delete(id); refresh(); }
    catch (e) { alert(e.message); }
  };

  return (
    <>
      <div className="ph">
        <div><h1>Credentials</h1><div className="sub">Authenticated scans use these credentials. Secrets are stored encrypted at rest.</div></div>
        {canEdit() && <div className="actions"><button className="btn btn-primary" onClick={() => setShowNew(true)}><Icons.Plus size={14}/> Add credential</button></div>}
      </div>
      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}
      <div className="card">
        <div className="card-body flush">
          {loading && creds.length === 0 ? (
            <div style={{padding: 60, textAlign: "center", color: "var(--text-3)"}}>Loading…</div>
          ) : creds.length === 0 ? (
            <div style={{padding: 60, textAlign: "center", color: "var(--text-3)"}}>
              No credentials yet. Add one to enable authenticated scans.
            </div>
          ) : (
          <table className="tbl">
            <thead><tr><th style={{width: 40}}/><th>Name</th><th>Kind</th><th>Username</th><th>Secret type</th><th style={{width: 90}}/></tr></thead>
            <tbody>
              {creds.map(c => {
                const I = KIND_ICONS[c.kind] || Icons.Key;
                return (
                  <tr key={c.id}>
                    <td><div style={{width: 28, height: 28, background: "var(--surface-2)", borderRadius: 6, display: "grid", placeItems: "center", color: "var(--text-2)"}}><I size={14}/></div></td>
                    <td><span className="mono" style={{color: "var(--text-0)", fontWeight: 500}}>{c.name}</span></td>
                    <td><span className="tag">{c.kind}</span></td>
                    <td><span className="mono" style={{fontSize: 12.5}}>{c.username}</span></td>
                    <td><span className="tag">{c.secret_type}</span></td>
                    {canEdit() && (
                    <td style={{display: "flex", gap: 2}}>
                      <button className="btn btn-icon btn-ghost btn-sm" title="Edit" style={{color: "var(--text-3)"}}
                              onClick={() => setEditing(c)}><Icons.Edit size={13}/></button>
                      <button className="btn btn-icon btn-ghost btn-sm" title="Delete" style={{color: "var(--text-3)"}}
                              onClick={() => onDelete(c.id, c.name)}><Icons.Trash size={13}/></button>
                    </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
          )}
        </div>
      </div>
      {showNew && <NewCredentialModal close={() => setShowNew(false)} onSaved={() => { setShowNew(false); refresh(); }}/>}
      {editing && <NewCredentialModal credential={editing} close={() => setEditing(null)} onSaved={() => { setEditing(null); refresh(); }}/>}
    </>
  );
}

function NewCredentialModal({ credential, close, onSaved }) {
  const isEdit = !!credential;
  const [data, setData] = useState({
    name: credential?.name || "",
    kind: credential?.kind || "ssh",
    username: credential?.username || "",
    secret: "",
    secret_type: credential?.secret_type || "password",
    passphrase: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const update = (k, v) => setData(d => ({ ...d, [k]: v }));

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      if (isEdit) {
        const body = { name: data.name, kind: data.kind, username: data.username, secret_type: data.secret_type };
        if (data.secret) body.secret = data.secret;
        if (data.passphrase) body.passphrase = data.passphrase;
        await credentialsApi.update(credential.id, body);
      } else {
        await credentialsApi.create(data);
      }
      onSaved();
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 460}}>
        <div className="drawer-head">
          <Icons.Key size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>{isEdit ? "Edit credential" : "New credential"}</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <form onSubmit={submit} style={{padding: "20px 24px", display: "flex", flexDirection: "column", gap: 14}}>
          <div>
            <label className="form-label">Name</label>
            <input className="form-input" placeholder="prod-ssh-key" value={data.name} onChange={e => update("name", e.target.value)} required autoFocus/>
          </div>
          <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12}}>
            <div>
              <label className="form-label">Kind</label>
              <select className="form-input" value={data.kind} onChange={e => update("kind", e.target.value)}>
                <option value="ssh">ssh</option>
                <option value="password">password</option>
                <option value="api">api</option>
                <option value="oauth">oauth</option>
              </select>
            </div>
            <div>
              <label className="form-label">Secret type</label>
              <select className="form-input" value={data.secret_type} onChange={e => update("secret_type", e.target.value)}>
                <option value="password">password</option>
                <option value="SSH_KEY">SSH_KEY</option>
              </select>
            </div>
          </div>
          <div>
            <label className="form-label">Username</label>
            <input className="form-input mono" placeholder="root" value={data.username} onChange={e => update("username", e.target.value)}/>
          </div>
          <div>
            <label className="form-label">{data.secret_type === "SSH_KEY" ? "Private key (PEM)" : "Password"}</label>
            <textarea className="form-input mono" rows={data.secret_type === "SSH_KEY" ? 6 : 1}
                      value={data.secret}
                      onChange={e => update("secret", e.target.value)}
                      style={{height: data.secret_type === "SSH_KEY" ? "auto" : 36, padding: "8px 12px"}}
                      placeholder={isEdit ? "(leave blank to keep current)" : (data.secret_type === "SSH_KEY" ? "-----BEGIN OPENSSH PRIVATE KEY-----\n…" : "••••••••")}
                      required={!isEdit}/>
          </div>
          {data.secret_type === "SSH_KEY" && (
            <div>
              <label className="form-label">Key passphrase (optional)</label>
              <input className="form-input" type="password" value={data.passphrase} onChange={e => update("passphrase", e.target.value)}/>
            </div>
          )}
          {error && <div style={{color: "var(--err)", fontSize: 12.5}}><Icons.AlertTriangle size={12}/> {error}</div>}
          <div style={{display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 6}}>
            <button type="button" className="btn" onClick={close} disabled={submitting}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? <><Icons.Refresh size={12} className="spin"/> Saving…</> : <>{isEdit ? "Save changes" : "Save credential"}</>}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

export function Datasets() {
  const [datasets, setDatasets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [refreshStatus, setRefreshStatus] = useState(null);
  const handledFinishRef = useRef(null);

  const refresh = useCallback(async () => {
    try { setDatasets(await datasetsApi.list()); setError(""); }
    catch (e) { setError(e.message); }
    finally   { setLoading(false); }
  }, []);

  const pollStatus = useCallback(async () => {
    try {
      const s = await datasetsApi.refreshStatus();
      setRefreshStatus(s);
      if (s && s.status === "running") {
        setRefreshing(true);
        handledFinishRef.current = null;
      } else if (s && s.status && s.status !== "running" && s.status !== "idle") {
        // Only handle completion once per refresh cycle
        const finishKey = s.finished_at || s.status;
        if (handledFinishRef.current !== finishKey) {
          handledFinishRef.current = finishKey;
          setRefreshing(false);
          refresh(); // reload dataset list after refresh completes
          // Invalidate the web server's threat intel cache so sidebar counts
          // and the Threat Intel page pick up the newly refreshed datasets.
          threatIntelApi.refresh().catch(() => {});
        }
      }
    } catch {}
  }, [refresh]);

  useEffect(() => { refresh(); pollStatus(); }, [refresh, pollStatus]);
  useEffect(() => {
    if (!refreshing) return;
    const t = setInterval(pollStatus, 3000);
    return () => clearInterval(t);
  }, [refreshing, pollStatus]);

  const onRefreshAll = async () => {
    try {
      setRefreshing(true);
      await datasetsApi.refresh({});
      pollStatus();
    } catch (e) { alert(e.message); setRefreshing(false); }
  };

  const onToggle = async (id) => {
    try { await datasetsApi.toggle(id); refresh(); }
    catch (e) { alert(e.message); }
  };

  const onDelete = async (id, name) => {
    if (!confirm(`Delete dataset "${name}"?`)) return;
    try { await datasetsApi.delete(id); refresh(); }
    catch (e) { alert(e.message); }
  };

  return (
    <>
      <div className="ph">
        <div>
          <h1>Threat intelligence datasets</h1>
          <div className="sub">Vulnerability feeds powering CVE matching, KEV prioritization, and risk scoring.</div>
        </div>
        {isAdmin() && (
        <div className="actions">
          <button className="btn" onClick={onRefreshAll} disabled={refreshing}>
            {refreshing ? <><Icons.Refresh size={14} className="spin"/> Refreshing…</> : <><Icons.Refresh size={14}/> Refresh all</>}
          </button>
        </div>
        )}
      </div>
      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}
      {refreshStatus && refreshStatus.status && refreshStatus.status !== "idle" && (() => {
        const isRunning = refreshStatus.status === "running";
        const kinds = refreshStatus.kinds || {};
        const kindNames = {
          nvd_cpe_cve: "NVD CVE/CPE", cisa_kev: "CISA KEV", epss: "EPSS Scores",
          cvedetails_cvss: "CVE.org CVSS", cms_cve_map: "CMS CVE Map", compliance_map: "Compliance Map",
        };
        const statusIcon = (s) =>
          s === "done" ? <Icons.Check size={12} color="var(--ok)"/>
          : s === "failed" ? <Icons.AlertTriangle size={12} color="var(--err)"/>
          : s === "running" ? <Icons.Refresh size={12} className="spin" color="var(--brand-text)"/>
          : <span style={{display: "inline-block", width: 12, height: 12, borderRadius: "50%", border: "1.5px solid var(--text-3)"}}/>;
        const isDone = ["done", "partial", "failed", "cancelled"].includes(refreshStatus.status);
        return (
          <div style={{padding: "14px 16px", background: isRunning ? "var(--brand-soft)" : isDone ? "var(--surface-1)" : "var(--surface-1)",
                       border: `1px solid ${isRunning ? "var(--brand-line)" : "var(--line)"}`, borderRadius: 8, marginBottom: 14}}>
            <div style={{display: "flex", alignItems: "center", gap: 8, marginBottom: 10}}>
              {isRunning ? <Icons.Refresh size={14} className="spin" color="var(--brand-text)"/> : isDone ? <Icons.Check size={14} color="var(--ok)"/> : null}
              <span style={{fontSize: 13, fontWeight: 600, color: "var(--text-0)"}}>
                {isRunning ? "Refreshing datasets…" : refreshStatus.status === "done" ? "Refresh complete" : refreshStatus.status === "partial" ? "Refresh partially complete" : refreshStatus.status === "cancelled" ? "Refresh cancelled" : "Refresh failed"}
              </span>
              {refreshStatus.finished_at && (
                <span style={{fontSize: 11, color: "var(--text-3)", marginLeft: "auto", fontFamily: "var(--font-mono)"}}>
                  {new Date(refreshStatus.finished_at).toLocaleTimeString()}
                </span>
              )}
            </div>
            <div style={{display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 6}}>
              {Object.entries(kinds).map(([kind, info]) => (
                <div key={kind} style={{display: "flex", alignItems: "center", gap: 8, padding: "6px 10px",
                       background: info.status === "running" ? "var(--brand-soft)" : "var(--surface-0)",
                       border: `1px solid ${info.status === "running" ? "var(--brand-line)" : "var(--line)"}`,
                       borderRadius: 6}}>
                  {statusIcon(info.status)}
                  <span style={{fontSize: 12, color: "var(--text-1)", fontWeight: info.status === "running" ? 600 : 400}}>
                    {kindNames[kind] || kind}
                  </span>
                  {info.status === "running" && info.message && (
                    <span style={{fontSize: 10, color: "var(--brand-text)", marginLeft: "auto", fontFamily: "var(--font-mono)"}}>{info.message}</span>
                  )}
                  {info.status === "failed" && info.message && (
                    <span title={info.message} style={{fontSize: 10, color: "var(--err)", marginLeft: "auto", cursor: "help"}}>error</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        );
      })()}
      {loading && datasets.length === 0 ? (
        <div style={{padding: 60, textAlign: "center", color: "var(--text-3)"}}>Loading datasets…</div>
      ) : datasets.length === 0 ? (
        <div className="card" style={{padding: 40, textAlign: "center", color: "var(--text-3)"}}>
          No datasets yet. Refresh to seed from upstream sources.
        </div>
      ) : (
        <div style={{display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 14}}>
          {datasets.map(d => (
            <div key={d.id} className="card">
              <div style={{padding: "16px 18px"}}>
                <div style={{display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8}}>
                  <div style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)", fontFamily: "var(--font-display)"}}>{d.name}</div>
                  <span className={`status ${d.enabled ? "done" : "queued"}`} style={{fontSize: 11}}>{d.enabled ? "enabled" : "disabled"}</span>
                </div>
                <div style={{fontSize: 12.5, color: "var(--text-3)", marginTop: 4, lineHeight: 1.5}}>
                  <span className="tag">{d.kind}</span>
                </div>
                <div style={{fontSize: 11.5, color: "var(--text-3)", marginTop: 10, fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>{d.path}</div>
                {canEdit() && (
                <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 14, paddingTop: 14, borderTop: "1px solid var(--line)", gap: 6}}>
                  <button className="btn btn-ghost btn-sm" onClick={() => onToggle(d.id)}>{d.enabled ? "Disable" : "Enable"}</button>
                  <button className="btn btn-ghost btn-sm" onClick={() => onDelete(d.id, d.name)} style={{color: "var(--err)"}}><Icons.Trash size={12}/></button>
                </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

export function Settings({ initialTab }) {
  const allSections = [
    { id: "general", label: "General", icon: Icons.Settings },
    { id: "sla", label: "SLA policies", icon: Icons.Clock, minRole: "analyst" },
    { id: "ai", label: "AI providers", icon: Icons.Brain, minRole: "admin" },
    { id: "integrations", label: "Integrations", icon: Icons.Layers, minRole: "admin" },
    { id: "notifications", label: "Notifications", icon: Icons.Bell, minRole: "analyst" },
    { id: "users", label: "Users & RBAC", icon: Icons.Lock, minRole: "admin" },
    { id: "system", label: "System", icon: Icons.Server },
  ];
  const sections = allSections.filter(s => {
    if (!s.minRole) return true;
    if (s.minRole === "admin") return isAdmin();
    if (s.minRole === "analyst") return canEdit();
    return true;
  });
  const [active, setActive] = useState(initialTab || "general");

  useEffect(() => {
    if (initialTab) setActive(initialTab);
  }, [initialTab]);

  return (
    <>
      <div className="ph">
        <div><h1>Settings</h1><div className="sub">Workspace configuration, integrations, and AI providers.</div></div>
      </div>
      <div style={{display: "grid", gridTemplateColumns: "200px 1fr", gap: 24}}>
        <nav style={{display: "flex", flexDirection: "column", gap: 2}}>
          {sections.map(s => {
            const I = s.icon;
            return (
              <button key={s.id} onClick={() => setActive(s.id)} style={{
                display: "flex", alignItems: "center", gap: 10,
                padding: "8px 12px", borderRadius: 6, fontSize: 13,
                color: active === s.id ? "var(--text-0)" : "var(--text-2)",
                background: active === s.id ? "var(--surface-1)" : "transparent",
                fontWeight: active === s.id ? 500 : 400, textAlign: "left",
              }}><I size={14}/> {s.label}</button>
            );
          })}
        </nav>
        <div className="card">
          {active === "general" && (
            <>
              <div className="card-head"><div><div className="card-title">General</div><div className="card-sub" style={{marginTop: 0}}>Workspace name, default time zone, and locale.</div></div></div>
              <div className="card-body" style={{display: "flex", flexDirection: "column", gap: 14}}>
                <div><label className="form-label">Workspace name</label><input className="form-input" defaultValue="VulnScan Production"/></div>
                <div><label className="form-label">Default time zone</label><select className="form-input" defaultValue="UTC"><option>UTC</option><option>America/New_York</option><option>Europe/London</option><option>Asia/Singapore</option></select></div>
                <div><label className="form-label">Date format</label><select className="form-input"><option>2026-04-29 (ISO)</option><option>Apr 29, 2026</option><option>29/04/2026</option></select></div>
              </div>
            </>
          )}
          {active === "sla" && <SLAPolicies/>}
          {active === "ai" && <AIProvidersPanel/>}
          {active === "integrations" && <IntegrationsPanel/>}
          {active === "notifications" && <NotificationPrefsPanel/>}
          {active === "users" && <UsersPanel/>}
          {active === "system" && <SystemPanel/>}
        </div>
      </div>
    </>
  );
}

function SystemPanel() {
  const [info, setInfo] = useState(null);
  const [stats, setStats] = useState(null);
  const [updateInfo, setUpdateInfo] = useState(null);
  const [updateLoading, setUpdateLoading] = useState(false);
  const [updateStatus, setUpdateStatus] = useState(null);
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [i, s] = await Promise.all([settingsApi.info(), settingsApi.stats()]);
      setInfo(i);
      setStats(s);
      setError("");
    } catch (e) { setError(e.message); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const checkUpdate = async () => {
    setUpdateLoading(true);
    try { setUpdateInfo(await settingsApi.updateCheck()); }
    catch (e) { alert(e.message); }
    finally { setUpdateLoading(false); }
  };

  const triggerUpdate = async () => {
    if (!window.confirm("This will update the platform and restart all services. Continue?")) return;
    setTriggering(true);
    try {
      const res = await settingsApi.triggerUpdate();
      setUpdateStatus({ status: res.status, message: res.message });
    } catch (e) {
      setUpdateStatus({ status: "failed", message: e.message });
      setTriggering(false);
      return;
    }
  };

  useEffect(() => {
    if (!triggering) return;
    const poll = setInterval(async () => {
      try {
        const s = await settingsApi.updateStatus();
        setUpdateStatus(s);
        if (s.status === "success" || s.status === "failed" || s.status === "idle") {
          setTriggering(false);
          clearInterval(poll);
          if (s.status === "success") setUpdateInfo(null);
        }
      } catch { /* server may be restarting */ }
    }, 3000);
    return () => clearInterval(poll);
  }, [triggering]);

  return (
    <>
      <div className="card-head"><div><div className="card-title">System</div><div className="card-sub" style={{marginTop: 0}}>Workspace stats, environment, and software updates.</div></div></div>
      <div className="card-body" style={{display: "flex", flexDirection: "column", gap: 18}}>
        {error && <div style={{color: "var(--err)", fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}

        {stats && (
          <div className="grid-stat" style={{gridTemplateColumns: "repeat(4, 1fr)"}}>
            <div className="stat brand"><div className="accent-bar"/><div className="label">Total scans</div><div className="value">{stats.jobs_total}</div></div>
            <div className="stat neutral"><div className="accent-bar"/><div className="label">Findings</div><div className="value">{stats.findings}</div></div>
            <div className="stat neutral"><div className="accent-bar"/><div className="label">Profiles</div><div className="value">{stats.profiles}</div></div>
            <div className="stat neutral"><div className="accent-bar"/><div className="label">Credentials</div><div className="value">{stats.credentials}</div></div>
          </div>
        )}

        {updateStatus && updateStatus.status !== "idle" && (
          <div style={{
            padding: "12px 16px", borderRadius: 10, display: "flex", alignItems: "center", gap: 10, fontSize: 13,
            background: updateStatus.status === "failed" ? "var(--err-soft, rgba(239,68,68,.08))" : updateStatus.status === "success" ? "var(--ok-soft, rgba(34,197,94,.08))" : "var(--brand-soft)",
            border: `1px solid ${updateStatus.status === "failed" ? "var(--err-line, rgba(239,68,68,.2))" : updateStatus.status === "success" ? "var(--ok-line, rgba(34,197,94,.2))" : "var(--brand-line)"}`,
            color: updateStatus.status === "failed" ? "var(--err)" : updateStatus.status === "success" ? "var(--ok)" : "var(--text-1)"
          }}>
            {updateStatus.status === "failed"
              ? <Icons.AlertTriangle size={15}/>
              : updateStatus.status === "success"
                ? <Icons.Check size={15}/>
                : <Icons.Refresh size={15} className="spin"/>}
            <div>
              <div style={{fontWeight: 600}}>
                {updateStatus.status === "triggered" && "Update triggered"}
                {updateStatus.status === "updating" && "Updating platform…"}
                {updateStatus.status === "success" && "Update complete"}
                {updateStatus.status === "failed" && "Update failed"}
              </div>
              {updateStatus.message && <div style={{opacity: .8, marginTop: 2, fontSize: 12}}>{updateStatus.message}</div>}
            </div>
          </div>
        )}

        {updateInfo && updateInfo.available && (
          <div style={{padding: "16px 18px", background: "var(--brand-soft)", border: "1px solid var(--brand-line)", borderRadius: 10}}>
            <div style={{display: "flex", alignItems: "flex-start", gap: 14}}>
              <div style={{width: 40, height: 40, borderRadius: 8, background: "var(--brand)", color: "#fff", display: "grid", placeItems: "center", flexShrink: 0}}>
                <Icons.Download size={18}/>
              </div>
              <div style={{flex: 1, minWidth: 0}}>
                <div style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Update available — {updateInfo.latest}</div>
                <div style={{fontSize: 12.5, color: "var(--text-2)", marginTop: 6, lineHeight: 1.5, whiteSpace: "pre-wrap"}}>
                  {updateInfo.release_notes || "—"}
                </div>
                {updateInfo.repo && (
                  <div style={{display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap"}}>
                    <a className="btn" href={`https://github.com/${updateInfo.repo}/releases/tag/${updateInfo.tag}`} target="_blank" rel="noopener noreferrer">
                      <Icons.External size={12}/> View release
                    </a>
                    <button className="btn btn-brand" onClick={triggerUpdate} disabled={triggering}>
                      {triggering ? <><Icons.Refresh size={12} className="spin"/> Updating…</> : <><Icons.Download size={12}/> Update now</>}
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        <div>
          <div style={{display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10}}>
            <div className="eyebrow">Installed version</div>
            <button className="btn btn-ghost btn-sm" onClick={checkUpdate} disabled={updateLoading}>
              {updateLoading ? <><Icons.Refresh size={11} className="spin"/> Checking…</> : <><Icons.Refresh size={11}/> Check for updates</>}
            </button>
          </div>
          {updateInfo && !updateInfo.available && (
            <div style={{fontSize: 12, color: "var(--ok)", marginBottom: 10, display: "flex", gap: 6, alignItems: "center"}}>
              <Icons.Check size={12}/> You're up to date ({updateInfo.current})
            </div>
          )}
        </div>

        {info && (
          <div>
            <div className="eyebrow" style={{marginBottom: 10}}>Environment</div>
            <dl className="dl">
              <dt>Default workspace</dt><dd className="mono">{info.default_workspace}</dd>
              <dt>Scan timeout</dt><dd className="mono">{info.scan_timeout_seconds}s</dd>
              <dt>Reports dir</dt><dd className="mono" style={{fontSize: 12}}>{info.reports_dir}</dd>
              <dt>Database</dt><dd className="mono" style={{fontSize: 12}}>{info.database_url}</dd>
              <dt>Redis</dt><dd className="mono" style={{fontSize: 12}}>{info.redis_url}</dd>
              <dt>Neo4j</dt><dd className="mono" style={{fontSize: 12}}>{info.neo4j_uri}</dd>
              <dt>CORS origins</dt><dd className="mono" style={{fontSize: 12}}>{Array.isArray(info.cors_origins) ? info.cors_origins.join(", ") : info.cors_origins}</dd>
            </dl>
          </div>
        )}
      </div>
    </>
  );
}

// Provider types that can be added manually via the "Add provider" modal (require API key)
const _AI_ADD_TYPES = {
  openai:       { label: "OpenAI",              icon: Icons.Cloud,    models: ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3-mini"] },
  claude_api:   { label: "Claude API",          icon: Icons.Brain,    models: ["claude-opus-4-5", "claude-sonnet-4-5", "claude-haiku-4-5"] },
  gemini:       { label: "Gemini",              icon: Icons.Sparkles, models: ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"] },
  azure_openai: { label: "Azure OpenAI",        icon: Icons.Cloud,    models: [] },
  openai_compat:{ label: "OpenAI-Compatible",   icon: Icons.Server,   models: [] },
  local_llm:    { label: "Local LLM (Ollama, LM Studio, etc.)", icon: Icons.Server, models: ["llama3.1", "mistral", "codellama", "deepseek-r1", "qwen2.5", "gemma2"] },
};

// Full metadata map for display (includes auto-detected CLI providers)
const _AI_TYPE_META = {
  ..._AI_ADD_TYPES,
  // CLI-detected providers (auto-detected, not manually added)
  claude_cli:   { label: "Claude CLI",          icon: Icons.Brain },
  codex_cli:    { label: "Codex CLI",           icon: Icons.Code },
  gemini_cli:   { label: "Gemini CLI",          icon: Icons.Sparkles },
  copilot_cli:  { label: "GitHub Copilot CLI",  icon: Icons.Cloud },
  ollama:       { label: "Ollama",              icon: Icons.Server },
  llamacpp:     { label: "llama.cpp",           icon: Icons.Server },
  lmstudio:     { label: "LM Studio",          icon: Icons.Monitor },
  localai:      { label: "LocalAI",            icon: Icons.Server },
  jan:          { label: "Jan",                 icon: Icons.Monitor },
  aichat:       { label: "aichat",             icon: Icons.Code },
  mods:         { label: "Mods",               icon: Icons.Code },
  fabric:       { label: "Fabric",             icon: Icons.Code },
  llm:          { label: "llm",                icon: Icons.Code },
  qwen_cli:     { label: "Qwen CLI",           icon: Icons.Code },
};

const _SOURCE_BADGE = {
  db:  { label: "API Key",  bg: "var(--brand-soft)", color: "var(--brand-text)" },
  env: { label: "Server",   bg: "var(--surface-2)",  color: "var(--text-2)" },
  cli: { label: "CLI",      bg: "#2d4a3e",           color: "var(--ok)" },
};

function AIProvidersPanel() {
  const [providers, setProviders] = useState(null);
  const [error, setError] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [testing, setTesting] = useState(null);
  const [testMsg, setTestMsg] = useState({});

  const load = useCallback(() => {
    aiApi.providers().then(r => setProviders(r.providers || [])).catch(e => setError(e.message));
  }, []);
  useEffect(() => { load(); }, [load]);

  const onDelete = async (id) => {
    if (!confirm("Delete this AI provider?")) return;
    try { await aiApi.deleteProvider(id); load(); } catch (e) { alert(e.message); }
  };

  const onToggle = async (id, enabled) => {
    try { await aiApi.updateProvider(id, { enabled: !enabled }); load(); } catch (e) { alert(e.message); }
  };

  const onTest = async (id) => {
    setTesting(id);
    setTestMsg(prev => ({ ...prev, [id]: null }));
    try {
      const r = await aiApi.testProvider(id);
      setTestMsg(prev => ({ ...prev, [id]: r.ok ? "OK" : r.error }));
    } catch (e) { setTestMsg(prev => ({ ...prev, [id]: e.message })); }
    finally { setTesting(null); }
  };

  const providerIcon = (p) => {
    const pt = p.provider_type || p.id || "";
    if (pt in _AI_TYPE_META) return _AI_TYPE_META[pt].icon;
    if (pt.includes("claude")) return Icons.Brain;
    if (pt.includes("openai")) return Icons.Cloud;
    if (pt.includes("gemini")) return Icons.Sparkles;
    if (p.source === "cli") return Icons.Code;
    return Icons.Brain;
  };

  return (
    <>
      <div className="card-head">
        <div><div className="card-title">AI Providers</div><div className="card-sub" style={{marginTop: 0}}>LLM backends for finding validation and PoC generation.</div></div>
        {isAdmin() && (
          <div className="actions">
            <button className="btn btn-primary btn-sm" onClick={() => setShowAdd(true)}><Icons.Plus size={12}/> Add provider</button>
          </div>
        )}
      </div>
      <div className="card-body" style={{display: "flex", flexDirection: "column", gap: 10}}>
        {error && <div style={{color: "var(--err)", fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}
        {providers === null ? (
          <div style={{color: "var(--text-3)", fontSize: 13}}>Loading...</div>
        ) : providers.length === 0 ? (
          <div style={{padding: 24, color: "var(--text-3)", fontSize: 13, border: "1px dashed var(--line)", borderRadius: 8}}>
            No AI providers configured. Click "Add provider" to add an API key, or install a CLI tool (Claude CLI, Codex) on the server.
          </div>
        ) : (
          providers.map(p => {
            const I = providerIcon(p);
            const badge = _SOURCE_BADGE[p.source] || _SOURCE_BADGE.env;
            const isDb = p.source === "db";
            const tm = testMsg[p.id];
            return (
              <div key={p.id} style={{display: "flex", alignItems: "center", gap: 14, padding: "12px 16px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 8, opacity: p.enabled === false ? 0.5 : 1}}>
                <div style={{width: 36, height: 36, borderRadius: 8, background: "var(--surface-2)", display: "grid", placeItems: "center", color: "var(--text-1)"}}><I size={16}/></div>
                <div style={{flex: 1, minWidth: 0}}>
                  <div style={{display: "flex", alignItems: "center", gap: 8}}>
                    <span style={{fontSize: 13.5, color: "var(--text-0)", fontWeight: 500}}>{p.name}</span>
                    <span style={{fontSize: 10, padding: "1px 6px", borderRadius: 4, background: badge.bg, color: badge.color, fontWeight: 600}}>{badge.label}</span>
                  </div>
                  <div style={{fontSize: 12, color: "var(--text-3)", fontFamily: "var(--font-mono)"}}>{p.model}{p.endpoint ? ` @ ${p.endpoint}` : ""}</div>
                  {tm && <div style={{fontSize: 11, marginTop: 2, color: tm === "OK" ? "var(--ok)" : "var(--err)"}}>{tm === "OK" ? "Test passed" : tm}</div>}
                </div>
                <div style={{display: "flex", gap: 6, alignItems: "center"}}>
                  {isDb && isAdmin() && (
                    <>
                      <button className="btn btn-ghost btn-sm" onClick={() => onTest(p.id)} disabled={testing === p.id}>
                        {testing === p.id ? <Icons.Refresh size={11} className="spin"/> : <Icons.Check size={11}/>} Test
                      </button>
                      <button className="btn btn-ghost btn-sm" onClick={() => onToggle(p.id, p.enabled)}>
                        {p.enabled ? "Disable" : "Enable"}
                      </button>
                      <button className="btn btn-ghost btn-sm" style={{color: "var(--err)"}} onClick={() => onDelete(p.id)}>
                        <Icons.Trash size={12}/>
                      </button>
                    </>
                  )}
                  {!isDb && <Status s="done"/>}
                </div>
              </div>
            );
          })
        )}
      </div>
      {showAdd && <AddAIProviderModal close={() => setShowAdd(false)} onSaved={() => { setShowAdd(false); load(); }}/>}
    </>
  );
}

function AddAIProviderModal({ close, onSaved }) {
  const [providerType, setProviderType] = useState("openai");
  const [name, setName] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const meta = _AI_ADD_TYPES[providerType] || {};
  const isLocal = providerType === "local_llm";
  const needsEndpoint = providerType === "azure_openai" || providerType === "openai_compat" || isLocal;
  const needsApiKey = !isLocal;

  useEffect(() => {
    setName(meta.label || providerType);
    setModel(meta.models?.[0] || "");
    setEndpoint(isLocal ? "http://localhost:11434/v1" : "");
    setApiKey("");
  }, [providerType]);

  const submit = async () => {
    setError("");
    setSubmitting(true);
    try {
      await aiApi.saveProvider({
        provider_type: isLocal ? "openai_compat" : providerType,
        name,
        model,
        api_key: apiKey || (isLocal ? "local" : ""),
        endpoint: endpoint || undefined,
      });
      onSaved();
    } catch (e) { setError(e.message); }
    finally { setSubmitting(false); }
  };

  const canSubmit = !submitting && name && model && (needsApiKey ? !!apiKey : true) && (needsEndpoint ? !!endpoint : true);

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 500}}>
        <div className="drawer-head">
          <Icons.Brain size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Add AI provider</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "20px 24px", display: "flex", flexDirection: "column", gap: 14}}>
          <div>
            <label className="form-label">Provider type</label>
            <select className="form-input" value={providerType} onChange={e => setProviderType(e.target.value)}>
              {Object.entries(_AI_ADD_TYPES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
          </div>
          <div>
            <label className="form-label">Display name</label>
            <input className="form-input" value={name} onChange={e => setName(e.target.value)} placeholder={isLocal ? "My Local LLM" : "My OpenAI"}/>
          </div>
          <div>
            <label className="form-label">Model</label>
            <input className="form-input" value={model} onChange={e => setModel(e.target.value)} list="ai-model-list" placeholder={isLocal ? "e.g. llama3.1, mistral, deepseek-r1" : needsEndpoint ? "deployment name or model ID" : "e.g. gpt-4o"}/>
            {meta.models?.length > 0 && (
              <datalist id="ai-model-list">
                {meta.models.map(m => <option key={m} value={m}/>)}
              </datalist>
            )}
          </div>
          {needsEndpoint && (
            <div>
              <label className="form-label">Endpoint URL</label>
              <input className="form-input" value={endpoint} onChange={e => setEndpoint(e.target.value)} placeholder={isLocal ? "http://localhost:11434/v1" : providerType === "azure_openai" ? "https://your-resource.openai.azure.com" : "https://api.example.com/v1"}/>
              {isLocal && <div style={{fontSize: 11, color: "var(--text-3)", marginTop: 3}}>Ollama: :11434/v1 &middot; LM Studio: :1234/v1 &middot; LocalAI: :8080/v1 &middot; Jan: :1337/v1</div>}
            </div>
          )}
          <div>
            <label className="form-label">API key {isLocal && <span style={{color: "var(--text-3)", fontWeight: 400}}>(optional — most local LLMs don't need one)</span>}</label>
            <input className="form-input" type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder={isLocal ? "leave empty if not required" : "sk-..."}/>
          </div>
          {error && <div style={{color: "var(--err)", fontSize: 13}}><Icons.AlertTriangle size={12}/> {error}</div>}
          <button className="btn btn-primary" onClick={submit} disabled={!canSubmit}>
            {submitting ? "Adding..." : "Add provider"}
          </button>
        </div>
      </div>
    </>
  );
}

function UsersPanel() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showInvite, setShowInvite] = useState(false);
  const [resetTarget, setResetTarget] = useState(null);
  const [showChangePw, setShowChangePw] = useState(false);

  const refresh = useCallback(async () => {
    try { setUsers(await settingsApi.listUsers()); setError(""); }
    catch (e) { setError(e.message); }
    finally   { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const onDelete = async (id, email) => {
    if (!confirm(`Remove user ${email}?`)) return;
    try { await settingsApi.deleteUser(id); refresh(); }
    catch (e) { alert(e.message); }
  };

  const fmtDate = (iso) => {
    if (!iso) return "—";
    const d = new Date(iso);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
  };

  return (
    <>
      <div className="card-head" style={{display: "flex", justifyContent: "space-between", alignItems: "center"}}>
        <div><div className="card-title">Users & RBAC</div><div className="card-sub" style={{marginTop: 0}}>Workspace members and their permissions.</div></div>
        <div style={{display: "flex", gap: 8}}>
          <button className="btn btn-sm" onClick={() => setShowChangePw(true)}><Icons.Lock size={11}/> Change my password</button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowInvite(true)}><Icons.Plus size={11}/> Add user</button>
        </div>
      </div>
      <div className="card-body flush">
        {error && <div style={{padding: "10px 18px", color: "var(--err)", fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}
        {loading && users.length === 0 ? (
          <div style={{padding: 60, textAlign: "center", color: "var(--text-3)"}}>Loading…</div>
        ) : (
          <table className="tbl">
            <thead><tr><th>User</th><th>Role</th><th>Last login</th><th>Location</th><th>Password changed</th><th>Created</th><th style={{width: 80}}/></tr></thead>
            <tbody>
              {users.map(u => {
                const initials = u.email.split("@")[0].split(".").map(s => s[0]).join("").slice(0, 2).toUpperCase();
                return (
                  <tr key={u.id}>
                    <td><div style={{display: "flex", alignItems: "center", gap: 10}}>
                      <div style={{width: 26, height: 26, borderRadius: "50%", background: "var(--surface-2)", display: "grid", placeItems: "center", fontSize: 11, color: "var(--text-1)", fontWeight: 600}}>{initials}</div>
                      <div>
                        <div style={{color: "var(--text-0)", fontSize: 13, fontWeight: 500}}>{u.email.split("@")[0]}</div>
                        <div className="mono" style={{fontSize: 11, color: "var(--text-3)"}}>{u.email}</div>
                      </div>
                    </div></td>
                    <td><span className="tag">{u.role}</span></td>
                    <td className="muted" style={{fontSize: 12}}>{fmtDate(u.last_login_at)}</td>
                    <td className="muted" style={{fontSize: 12}} title={u.last_login_ip || ""}>{u.last_login_location || u.last_login_ip || "—"}</td>
                    <td className="muted" style={{fontSize: 12}}>{fmtDate(u.updated_at)}</td>
                    <td className="muted" style={{fontSize: 12}}>{fmtDate(u.created_at)}</td>
                    <td>
                      <div style={{display: "flex", gap: 4}}>
                        <button className="btn btn-icon btn-ghost btn-sm" title="Reset password" style={{color: "var(--text-3)"}}
                                onClick={() => setResetTarget(u)}><Icons.Lock size={13}/></button>
                        <button className="btn btn-icon btn-ghost btn-sm" title="Remove" style={{color: "var(--text-3)"}}
                                onClick={() => onDelete(u.id, u.email)}><Icons.Trash size={13}/></button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      {showInvite && <NewUserModal close={() => setShowInvite(false)} onCreated={() => { setShowInvite(false); refresh(); }}/>}
      {resetTarget && <ResetPasswordModal user={resetTarget} close={() => setResetTarget(null)} onDone={() => { setResetTarget(null); refresh(); }}/>}
      {showChangePw && <ChangePasswordModal close={() => setShowChangePw(false)}/>}
    </>
  );
}

function NewUserModal({ close, onCreated }) {
  const [data, setData] = useState({ email: "", password: "", role: "analyst" });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const update = (k, v) => setData(d => ({ ...d, [k]: v }));

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try { await settingsApi.createUser(data); onCreated(); }
    catch (err) { setError(err.message); setSubmitting(false); }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 440}}>
        <div className="drawer-head">
          <Icons.User size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Add user</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <form onSubmit={submit} style={{padding: "20px 24px", display: "flex", flexDirection: "column", gap: 14}}>
          <div>
            <label className="form-label">Email</label>
            <input className="form-input mono" type="email" placeholder="alice@company.com" value={data.email} onChange={e => update("email", e.target.value)} required autoFocus/>
          </div>
          <div>
            <label className="form-label">Initial password</label>
            <input className="form-input" type="password" value={data.password} onChange={e => update("password", e.target.value)} required minLength={6}/>
            <div className="form-help">User can change their password in Settings &rarr; Users & RBAC.</div>
          </div>
          <div>
            <label className="form-label">Role</label>
            <select className="form-input" value={data.role} onChange={e => update("role", e.target.value)}>
              <option value="admin">Admin — full access</option>
              <option value="analyst">Analyst — run scans, manage findings</option>
              <option value="viewer">Viewer — read-only</option>
            </select>
          </div>
          {error && <div style={{color: "var(--err)", fontSize: 12.5}}><Icons.AlertTriangle size={12}/> {error}</div>}
          <div style={{display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 6}}>
            <button type="button" className="btn" onClick={close} disabled={submitting}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? <><Icons.Refresh size={12} className="spin"/> Adding…</> : <>Add user</>}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

function ResetPasswordModal({ user: target, close, onDone }) {
  const [pw, setPw] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await settingsApi.resetPassword(target.id, { new_password: pw });
      onDone();
    } catch (err) { setError(err.message); setSubmitting(false); }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 400}}>
        <div className="drawer-head">
          <Icons.Lock size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Reset password</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <form onSubmit={submit} style={{padding: "20px 24px", display: "flex", flexDirection: "column", gap: 14}}>
          <div style={{fontSize: 13, color: "var(--text-2)"}}>Set a new password for <strong style={{color: "var(--text-0)"}}>{target.email}</strong></div>
          <div>
            <label className="form-label">New password</label>
            <input className="form-input" type="password" value={pw} onChange={e => setPw(e.target.value)} required minLength={6} autoFocus/>
          </div>
          {error && <div style={{color: "var(--err)", fontSize: 12.5}}><Icons.AlertTriangle size={12}/> {error}</div>}
          <div style={{display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 6}}>
            <button type="button" className="btn" onClick={close} disabled={submitting}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? <><Icons.Refresh size={12} className="spin"/> Resetting…</> : <>Reset password</>}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

function ChangePasswordModal({ close }) {
  const [current, setCurrent] = useState("");
  const [newPw, setNewPw] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await settingsApi.changePassword({ current_password: current, new_password: newPw });
      setSuccess(true);
    } catch (err) { setError(err.message); setSubmitting(false); }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 400}}>
        <div className="drawer-head">
          <Icons.Lock size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Change password</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        {success ? (
          <div style={{padding: "30px 24px", textAlign: "center"}}>
            <Icons.Check size={24} color="var(--ok)"/>
            <div style={{fontSize: 14, fontWeight: 500, color: "var(--text-0)", marginTop: 10}}>Password updated</div>
            <button className="btn btn-primary btn-sm" onClick={close} style={{marginTop: 16}}>Done</button>
          </div>
        ) : (
          <form onSubmit={submit} style={{padding: "20px 24px", display: "flex", flexDirection: "column", gap: 14}}>
            <div>
              <label className="form-label">Current password</label>
              <input className="form-input" type="password" value={current} onChange={e => setCurrent(e.target.value)} required autoFocus/>
            </div>
            <div>
              <label className="form-label">New password</label>
              <input className="form-input" type="password" value={newPw} onChange={e => setNewPw(e.target.value)} required minLength={6}/>
            </div>
            {error && <div style={{color: "var(--err)", fontSize: 12.5}}><Icons.AlertTriangle size={12}/> {error}</div>}
            <div style={{display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 6}}>
              <button type="button" className="btn" onClick={close} disabled={submitting}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? <><Icons.Refresh size={12} className="spin"/> Saving…</> : <>Update password</>}
              </button>
            </div>
          </form>
        )}
      </div>
    </>
  );
}

// Backend supports four integration providers — slack, email, webhook, teams
const INTEGRATION_PROVIDERS = [
  { provider: "slack",   name: "Slack",            cat: "Chat",   desc: "Post findings to a Slack webhook", icon: Icons.Slack },
  { provider: "teams",   name: "Microsoft Teams",  cat: "Chat",   desc: "Send adaptive cards via Teams webhook", icon: Icons.Mail },
  { provider: "email",   name: "Email (SMTP)",     cat: "Email",  desc: "Forward findings via SMTP", icon: Icons.Mail },
  { provider: "webhook", name: "Webhook",          cat: "Custom", desc: "POST events to your own HTTP endpoint", icon: Icons.Globe },
];

const NOTIF_EVENTS = [
  { key: "critical_finding",     label: "Critical finding detected" },
  { key: "cisa_kev_match",       label: "CISA KEV match" },
  { key: "scan_completed",       label: "Scan completed" },
  { key: "scan_failed",          label: "Scan failed" },
  { key: "new_asset_discovered", label: "New asset discovered" },
  { key: "weekly_digest",        label: "Weekly digest" },
];
const NOTIF_CHANNELS = ["email", "slack", "webhook"];

function NotificationPrefsPanel() {
  const [prefs, setPrefs] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    notificationPrefsApi.get()
      .then(r => { setPrefs(r); })
      .catch(() => setMsg("Failed to load preferences"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const toggle = (eventKey, channel) => {
    setPrefs(prev => {
      const updated = {
        ...prev,
        [eventKey]: { ...prev[eventKey], [channel]: !prev[eventKey][channel] },
      };
      // Auto-save on every toggle
      setSaving(true);
      setMsg("");
      notificationPrefsApi.save(updated)
        .then(r => { setPrefs(r); setMsg("Saved"); })
        .catch(() => setMsg("Failed to save"))
        .finally(() => setSaving(false));
      return updated;
    });
  };

  const reset = () => {
    setSaving(true);
    setMsg("");
    notificationPrefsApi.reset()
      .then(r => { setPrefs(r); setMsg("Reset to defaults"); })
      .catch(() => setMsg("Failed to reset"))
      .finally(() => setSaving(false));
  };

  return (
    <>
      <div className="card-head">
        <div>
          <div className="card-title">Notifications</div>
          <div className="card-sub" style={{marginTop: 0}}>Choose what triggers an alert and where it goes. Changes save automatically.</div>
        </div>
        <div style={{display: "flex", gap: 8, alignItems: "center"}}>
          {msg && <span style={{fontSize: 12, color: msg.startsWith("Failed") ? "var(--err)" : "var(--ok)"}}>{msg}</span>}
          {saving && <span style={{fontSize: 12, color: "var(--text-3)"}}>Saving...</span>}
          <button className="btn btn-ghost btn-sm" onClick={reset} disabled={saving}>Reset defaults</button>
        </div>
      </div>
      <div className="card-body">
        {loading && <div style={{textAlign: "center", padding: 20, color: "var(--text-3)"}}>Loading...</div>}
        {!loading && prefs && (
          <table className="tbl">
            <thead>
              <tr>
                <th>Event</th>
                {NOTIF_CHANNELS.map(ch => (
                  <th key={ch} style={{width: 80, textTransform: "capitalize"}}>{ch}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {NOTIF_EVENTS.map(({ key, label }) => (
                <tr key={key}>
                  <td style={{color: "var(--text-1)", fontSize: 13}}>{label}</td>
                  {NOTIF_CHANNELS.map(ch => (
                    <td key={ch}>
                      <input
                        type="checkbox"
                        checked={!!(prefs[key] && prefs[key][ch])}
                        onChange={() => toggle(key, ch)}
                        style={{accentColor: "var(--brand)"}}
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

function IntegrationsPanel() {
  const [installed, setInstalled] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [configuring, setConfiguring] = useState(null);

  const refresh = useCallback(async () => {
    try { setInstalled(await integrationsApi.list()); setError(""); }
    catch (e) { setError(e.message); }
    finally   { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const byProvider = installed.reduce((acc, i) => { acc[i.provider] = i; return acc; }, {});
  const apps = INTEGRATION_PROVIDERS.map(p => ({
    ...p,
    installed: byProvider[p.provider],
    status: byProvider[p.provider]?.enabled ? "connected" : "disconnected",
  }));

  return (
    <>
      <div className="card-head" style={{display: "flex", justifyContent: "space-between", alignItems: "center"}}>
        <div><div className="card-title">Integrations</div><div className="card-sub" style={{marginTop: 0}}>Connect VulnScan to chat, email, and custom HTTP endpoints.</div></div>
        <span className="tag brand">{apps.filter(a => a.status === "connected").length} connected</span>
      </div>
      <div className="card-body">
        {error && <div style={{color: "var(--err)", fontSize: 13, marginBottom: 12}}><Icons.AlertTriangle size={13}/> {error}</div>}
        {loading ? (
          <div style={{padding: 24, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>Loading…</div>
        ) : (
        <div style={{display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 10}}>
          {apps.map(p => {
            const I = p.icon;
            return (
              <div key={p.provider} style={{display: "flex", alignItems: "center", gap: 12, padding: "12px 14px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 8}}>
                <div style={{width: 32, height: 32, borderRadius: 7, background: "var(--surface-2)", display: "grid", placeItems: "center", color: "var(--text-1)", flexShrink: 0}}><I size={15}/></div>
                <div style={{flex: 1, minWidth: 0}}>
                  <div style={{display: "flex", alignItems: "center", gap: 6}}>
                    <span style={{fontSize: 13, color: "var(--text-0)", fontWeight: 500}}>{p.name}</span>
                    {p.status === "connected" && <span style={{width: 6, height: 6, borderRadius: "50%", background: "var(--ok)"}}/>}
                  </div>
                  <div style={{fontSize: 11.5, color: "var(--text-3)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>{p.desc}</div>
                </div>
                <button className="btn btn-sm" onClick={() => setConfiguring(p)}>{p.status === "connected" ? "Configure" : "Connect"}</button>
              </div>
            );
          })}
        </div>
        )}
      </div>
      {configuring && <IntegrationConfigModal app={configuring} close={() => setConfiguring(null)} onSaved={() => { setConfiguring(null); refresh(); }}/>}
    </>
  );
}

function IntegrationConfigModal({ app, close, onSaved }) {
  const I = app.icon;
  const [enabled, setEnabled] = useState(app.installed?.enabled ?? true);
  const [config, setConfig] = useState(app.installed?.config || {});
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [error, setError] = useState("");

  const setCfg = (k, v) => setConfig(c => ({ ...c, [k]: v }));

  // Per-provider client-side validation — surfaces a useful error before we
  // round-trip to the backend.
  const validateConfig = () => {
    const c = config || {};
    if (app.provider === "slack" || app.provider === "teams") {
      if (!c.webhook_url || !/^https?:\/\//.test(c.webhook_url)) {
        return "Webhook URL is required and must start with http(s)://";
      }
    }
    if (app.provider === "webhook") {
      if (!c.url || !/^https?:\/\//.test(c.url)) {
        return "Webhook URL is required and must start with http(s)://";
      }
    }
    if (app.provider === "email") {
      if (!c.smtp_host) return "SMTP host is required";
      if (!c.to_email)  return "Recipient (to_email) is required";
    }
    return "";
  };

  const save = async () => {
    setError("");
    setTestResult(null);
    const v = validateConfig();
    if (v) { setError(v); return; }
    setSaving(true);
    try {
      await integrationsApi.save(app.provider, { enabled, config });
      onSaved();
    } catch (e) {
      setError(e.message);
      setSaving(false);
    }
  };

  const test = async () => {
    setError("");
    setTestResult(null);
    const v = validateConfig();
    if (v) { setTestResult({ ok: false, msg: v }); return; }
    setTesting(true);
    try {
      const r = await integrationsApi.test(app.provider, { enabled: true, config });
      setTestResult({ ok: true, msg: r.message || "Test sent" });
    } catch (e) {
      setTestResult({ ok: false, msg: e.message || "Test failed" });
    } finally { setTesting(false); }
  };

  const remove = async () => {
    if (!app.installed) return;
    if (!window.confirm(`Remove the saved ${app.name} integration?`)) return;
    setRemoving(true);
    setError("");
    try {
      await integrationsApi.remove(app.provider);
      onSaved();
    } catch (e) {
      setError(e.message);
      setRemoving(false);
    }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 540, maxHeight: "85vh"}}>
        <div className="drawer-head">
          <div style={{width: 32, height: 32, borderRadius: 7, background: "var(--surface-2)", display: "grid", placeItems: "center", color: "var(--text-1)"}}><I size={15}/></div>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>{app.name} · Configure</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "20px 24px", overflowY: "auto", flex: 1, display: "flex", flexDirection: "column", gap: 14}}>
          <div style={{fontSize: 12.5, color: "var(--text-2)", lineHeight: 1.55}}>{app.desc}</div>

          <label style={{display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 8, cursor: "pointer"}}>
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} style={{accentColor: "var(--brand)"}}/>
            <span style={{fontSize: 13, color: "var(--text-0)"}}>Enabled</span>
            <span style={{marginLeft: "auto", fontSize: 11.5, color: enabled ? "var(--ok)" : "var(--text-3)"}}>{enabled ? "Active" : "Disabled"}</span>
          </label>

          {(app.provider === "slack" || app.provider === "teams") && (
            <div>
              <label className="form-label">Webhook URL</label>
              <input className="form-input mono"
                     placeholder={app.provider === "slack" ? "https://hooks.slack.com/services/…" : "https://outlook.office.com/webhook/…"}
                     value={config.webhook_url || ""} onChange={e => setCfg("webhook_url", e.target.value)}/>
              <div style={{fontSize: 11, color: "var(--text-3)", marginTop: 4}}>
                Incoming-webhook URL for the {app.name} channel.
              </div>
            </div>
          )}

          {app.provider === "webhook" && (
            <>
              <div>
                <label className="form-label">Endpoint URL</label>
                <input className="form-input mono" placeholder="https://your-service.com/webhook"
                       value={config.url || ""} onChange={e => setCfg("url", e.target.value)}/>
              </div>
              <div>
                <label className="form-label">Bearer secret (optional)</label>
                <input className="form-input mono" placeholder="Sent as 'Authorization: Bearer …'"
                       value={config.secret || ""} onChange={e => setCfg("secret", e.target.value)}/>
              </div>
            </>
          )}

          {app.provider === "email" && (
            <>
              <div style={{display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10}}>
                <div>
                  <label className="form-label">SMTP host</label>
                  <input className="form-input mono" placeholder="smtp.example.com" value={config.smtp_host || ""} onChange={e => setCfg("smtp_host", e.target.value)}/>
                </div>
                <div>
                  <label className="form-label">Port</label>
                  <input className="form-input mono" type="number" placeholder="587" value={config.smtp_port || ""} onChange={e => setCfg("smtp_port", parseInt(e.target.value) || 0)}/>
                </div>
              </div>
              <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10}}>
                <div>
                  <label className="form-label">Username</label>
                  <input className="form-input mono" value={config.smtp_user || ""} onChange={e => setCfg("smtp_user", e.target.value)}/>
                </div>
                <div>
                  <label className="form-label">Password / App token</label>
                  <input className="form-input" type="password" value={config.smtp_pass || ""} onChange={e => setCfg("smtp_pass", e.target.value)}/>
                </div>
              </div>
              <div>
                <label className="form-label">From address</label>
                <input className="form-input mono" placeholder="alerts@company.com" value={config.from_email || ""} onChange={e => setCfg("from_email", e.target.value)}/>
              </div>
              <div>
                <label className="form-label">Recipient</label>
                <input className="form-input mono" placeholder="security@company.com"
                       value={config.to_email || ""} onChange={e => setCfg("to_email", e.target.value)}/>
                <div style={{fontSize: 11, color: "var(--text-3)", marginTop: 4}}>
                  Single address — multi-recipient delivery requires a list at the SMTP relay.
                </div>
              </div>
            </>
          )}

          <div>
            <label className="form-label">Trigger on severity</label>
            <div style={{display: "flex", gap: 6, flexWrap: "wrap"}}>
              {["critical", "high", "medium", "low"].map(s => {
                const sevList = config.severities || ["critical", "high"];
                const active = sevList.includes(s);
                return (
                  <button key={s} type="button" className={`btn btn-sm ${active ? "btn-primary" : "btn-ghost"}`}
                          style={{textTransform: "capitalize"}}
                          onClick={() => {
                            const next = active ? sevList.filter(x => x !== s) : [...sevList, s];
                            setCfg("severities", next);
                          }}>
                    {active && <Icons.Check size={11}/>} {s}
                  </button>
                );
              })}
            </div>
          </div>

          {testResult && (
            <div style={{padding: "10px 12px", background: testResult.ok ? "rgba(95,184,122,0.1)" : "var(--sev-critical-bg)", border: `1px solid ${testResult.ok ? "var(--sev-low-line)" : "var(--sev-critical-line)"}`, borderRadius: 6, fontSize: 12.5, color: testResult.ok ? "var(--ok)" : "var(--err)", display: "flex", alignItems: "center", gap: 8}}>
              {testResult.ok ? <Icons.Check size={13}/> : <Icons.AlertTriangle size={13}/>} {testResult.msg}
            </div>
          )}
          {error && <div style={{color: "var(--err)", fontSize: 12.5}}><Icons.AlertTriangle size={12}/> {error}</div>}
        </div>
        <div style={{padding: "14px 24px", borderTop: "1px solid var(--line)", display: "flex", gap: 8, justifyContent: "space-between", background: "var(--surface-1)"}}>
          <div style={{display: "flex", gap: 8}}>
            <button className="btn" onClick={test} disabled={testing || saving || removing}>
              {testing ? <><Icons.Refresh size={12} className="spin"/> Testing…</> : <>Send test</>}
            </button>
            {app.installed && (
              <button className="btn"
                      style={{color: "var(--err)", borderColor: "var(--sev-critical-line)"}}
                      onClick={remove} disabled={removing || saving || testing}>
                {removing ? <><Icons.Refresh size={12} className="spin"/> Removing…</> : <>Remove</>}
              </button>
            )}
          </div>
          <div style={{display: "flex", gap: 8}}>
            <button className="btn" onClick={close} disabled={saving}>Cancel</button>
            <button className="btn btn-primary" onClick={save} disabled={saving || removing}>
              {saving ? <><Icons.Refresh size={12} className="spin"/> Saving…</> : <><Icons.Check size={12}/> Save</>}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

const NOTIFY_CHANNEL_OPTIONS = [
  "@security-leads", "@asset-owner", "@soc-team", "@devops",
  "#security-alerts", "#incidents", "email:security@company.com", "webhook",
];

function SLAPolicies() {
  const [policies, setPolicies] = useState([]);
  const [breachAction, setBreachAction] = useState("notify");
  const [businessHoursOnly, setBusinessHoursOnly] = useState(false);
  const [compliancePreset, setCompliancePreset] = useState("custom");
  const [pauseStates, setPauseStates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [savedAt, setSavedAt] = useState(null);
  const [addNotifyFor, setAddNotifyFor] = useState(null);
  const [customChannel, setCustomChannel] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await slaApi.get();
      setPolicies(r.policies || []);
      setBreachAction(r.breach_action || "notify");
      setBusinessHoursOnly(!!r.business_hours_only);
      setCompliancePreset(r.compliance_preset || "custom");
      setPauseStates(r.pause_states || []);
      setError("");
    } catch (e) { setError(e.message); }
    finally     { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!addNotifyFor) return;
    const close = () => setAddNotifyFor(null);
    const timer = setTimeout(() => document.addEventListener("click", close), 0);
    return () => { clearTimeout(timer); document.removeEventListener("click", close); };
  }, [addNotifyFor]);

  const update = (sev, key, value) => {
    setPolicies(p => p.map(x => x.sev === sev ? { ...x, [key]: value } : x));
  };

  const addNotifyChannel = (sev, channel) => {
    if (!channel) return;
    setPolicies(p => p.map(x => {
      if (x.sev !== sev) return x;
      if (x.notify.includes(channel)) return x;
      return { ...x, notify: [...x.notify, channel] };
    }));
    setAddNotifyFor(null);
    setCustomChannel("");
  };

  const removeNotifyChannel = (sev, channel) => {
    setPolicies(p => p.map(x => {
      if (x.sev !== sev) return x;
      return { ...x, notify: x.notify.filter(n => n !== channel) };
    }));
  };

  const save = async () => {
    setSaving(true);
    setError("");
    try {
      await slaApi.update({
        policies,
        breach_action: breachAction,
        business_hours_only: businessHoursOnly,
        compliance_preset: compliancePreset,
        pause_states: pauseStates,
      });
      setSavedAt(new Date());
    } catch (e) { setError(e.message); }
    finally     { setSaving(false); }
  };

  const reset = async () => {
    if (!confirm("Reset SLA policies to defaults?")) return;
    setSaving(true);
    try {
      const r = await slaApi.reset();
      setPolicies(r.policies);
      setBreachAction(r.breach_action);
      setBusinessHoursOnly(!!r.business_hours_only);
      setCompliancePreset(r.compliance_preset);
      setPauseStates(r.pause_states || []);
      setSavedAt(new Date());
    } catch (e) { setError(e.message); }
    finally     { setSaving(false); }
  };

  const sevColors = {
    critical: "var(--sev-critical)", high: "var(--sev-high)",
    medium: "var(--sev-medium)", low: "var(--sev-low)", info: "var(--sev-info)",
  };

  return (
    <>
      <div className="card-head" style={{display: "flex", justifyContent: "space-between", alignItems: "flex-start"}}>
        <div>
          <div className="card-title">SLA Policies</div>
          <div className="card-sub" style={{marginTop: 0}}>
            Define remediation deadlines per severity. Findings are flagged as <span style={{color: "var(--err)"}}>overdue</span> when the SLA expires without resolution.
          </div>
        </div>
        <button className="btn btn-sm"><Icons.Download size={12}/> Export policy</button>
      </div>

      <div className="card-body">
        <table className="tbl" style={{marginBottom: 24}}>
          <thead>
            <tr>
              <th style={{width: 110}}>Severity</th>
              <th style={{width: 130}}>Initial response</th>
              <th style={{width: 140}}>Time to remediate</th>
              <th style={{width: 110}}>Escalate</th>
              <th>Notify on breach</th>
            </tr>
          </thead>
          <tbody>
            {policies.map(p => (
              <tr key={p.sev}>
                <td><span className={`sev sev-${p.sev}`}>{p.sev}</span></td>
                <td>
                  <div style={{display: "flex", alignItems: "center", gap: 6}}>
                    <input className="form-input mono" type="number" value={p.hours}
                           onChange={e => update(p.sev, "hours", parseInt(e.target.value || 0))}
                           style={{width: 64, height: 30, padding: "4px 8px", fontSize: 12.5, textAlign: "right"}}/>
                    <span style={{color: "var(--text-3)", fontSize: 12}}>hours</span>
                  </div>
                </td>
                <td>
                  <div style={{display: "flex", alignItems: "center", gap: 6}}>
                    <input className="form-input mono" type="number" value={p.days}
                           onChange={e => update(p.sev, "days", parseInt(e.target.value || 0))}
                           style={{width: 64, height: 30, padding: "4px 8px", fontSize: 12.5, textAlign: "right",
                                   borderColor: p.sev === "critical" && p.days > 7 ? "var(--sev-medium-line)" : "var(--line-strong)"}}/>
                    <span style={{color: "var(--text-3)", fontSize: 12}}>days</span>
                  </div>
                </td>
                <td>
                  <label style={{display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer"}}>
                    <input type="checkbox" checked={p.escalate}
                           onChange={e => update(p.sev, "escalate", e.target.checked)}
                           style={{accentColor: sevColors[p.sev]}}/>
                    <span style={{fontSize: 12.5, color: p.escalate ? "var(--text-1)" : "var(--text-3)"}}>{p.escalate ? "Auto" : "Off"}</span>
                  </label>
                </td>
                <td>
                  <div style={{display: "flex", flexWrap: "wrap", gap: 4, alignItems: "center", position: "relative"}}>
                    {p.notify.map(n => (
                      <span key={n} className="tag" style={{fontSize: 11, display: "inline-flex", alignItems: "center", gap: 4}}>
                        {n}
                        <span onClick={() => removeNotifyChannel(p.sev, n)}
                              style={{cursor: "pointer", opacity: 0.5, fontSize: 13, lineHeight: 1}}
                              title="Remove">&times;</span>
                      </span>
                    ))}
                    <button className="btn btn-ghost btn-sm"
                            onClick={() => setAddNotifyFor(addNotifyFor === p.sev ? null : p.sev)}
                            style={{height: 22, padding: "0 8px", fontSize: 11, color: "var(--text-3)"}}>+ Add</button>
                    {addNotifyFor === p.sev && (
                      <div onClick={e => e.stopPropagation()} style={{
                        position: "absolute", top: "100%", left: 0, zIndex: 50, marginTop: 4,
                        background: "var(--surface-0)", border: "1px solid var(--line-strong)",
                        borderRadius: 8, boxShadow: "var(--shadow-3)", padding: 6, minWidth: 220,
                      }}>
                        <div style={{padding: "4px 8px", fontSize: 11, fontWeight: 600, color: "var(--text-3)", textTransform: "uppercase"}}>Add channel</div>
                        {NOTIFY_CHANNEL_OPTIONS.filter(c => !p.notify.includes(c)).map(ch => (
                          <button key={ch} onClick={() => addNotifyChannel(p.sev, ch)} style={{
                            display: "block", width: "100%", textAlign: "left",
                            padding: "6px 10px", fontSize: 12.5, color: "var(--text-1)",
                            background: "transparent", border: "none", borderRadius: 4, cursor: "pointer",
                          }}
                          onMouseEnter={e => e.currentTarget.style.background = "var(--surface-1)"}
                          onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                            {ch}
                          </button>
                        ))}
                        <div style={{borderTop: "1px solid var(--line)", marginTop: 4, paddingTop: 6, display: "flex", gap: 4}}>
                          <input className="form-input" placeholder="Custom channel..."
                                 value={customChannel} onChange={e => setCustomChannel(e.target.value)}
                                 onKeyDown={e => { if (e.key === "Enter") { addNotifyChannel(p.sev, customChannel.trim()); } }}
                                 style={{flex: 1, height: 28, fontSize: 12, padding: "0 8px"}}/>
                          <button className="btn btn-sm btn-primary" style={{height: 28, padding: "0 10px", fontSize: 11}}
                                  onClick={() => addNotifyChannel(p.sev, customChannel.trim())}
                                  disabled={!customChannel.trim()}>Add</button>
                        </div>
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20}}>
          <div>
            <div className="eyebrow" style={{marginBottom: 10}}>On SLA breach</div>
            <div style={{display: "flex", flexDirection: "column", gap: 8}}>
              {[
                { id: "notify",   label: "Notify only",       sub: "Send alerts to channels above" },
                { id: "ticket",   label: "Auto-create ticket", sub: "Open Jira issue with severity P1/P2" },
                { id: "page",     label: "Page on-call",       sub: "Trigger PagerDuty incident" },
                { id: "block",    label: "Block deploy",       sub: "Fail CI/CD if linked asset has overdue findings" },
              ].map(opt => (
                <label key={opt.id} style={{display: "flex", alignItems: "flex-start", gap: 10, padding: "10px 12px",
                  border: `1px solid ${breachAction === opt.id ? "var(--brand-line)" : "var(--line)"}`, borderRadius: 6,
                  background: breachAction === opt.id ? "var(--brand-soft)" : "var(--surface-1)", cursor: "pointer"}}>
                  <input type="radio" name="breach" checked={breachAction === opt.id}
                         onChange={() => setBreachAction(opt.id)}
                         style={{accentColor: "var(--brand)", marginTop: 2}}/>
                  <span>
                    <span style={{fontSize: 13, color: "var(--text-0)", fontWeight: 500}}>{opt.label}</span>
                    <span style={{display: "block", fontSize: 12, color: "var(--text-3)", marginTop: 2}}>{opt.sub}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          <div>
            <div className="eyebrow" style={{marginBottom: 10}}>Clock rules</div>
            <div style={{display: "flex", flexDirection: "column", gap: 12, padding: "16px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 8}}>
              <label style={{display: "flex", alignItems: "flex-start", gap: 10, cursor: "pointer"}}>
                <input type="checkbox" checked={businessHoursOnly}
                       onChange={e => setBusinessHoursOnly(e.target.checked)}
                       style={{accentColor: "var(--brand)", marginTop: 2}}/>
                <span>
                  <span style={{fontSize: 13, color: "var(--text-0)", fontWeight: 500}}>Count business hours only</span>
                  <span style={{display: "block", fontSize: 12, color: "var(--text-3)", marginTop: 2}}>Pause SLA timer outside Mon–Fri 09:00–18:00 in workspace timezone.</span>
                </span>
              </label>

              <div>
                <label className="form-label">Pause SLA when finding is</label>
                <div style={{display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6}}>
                  {["accepted-risk", "false-positive", "awaiting-vendor", "in-progress"].map(s => (
                    <span key={s} className="tag" style={{fontSize: 11}}>{s}</span>
                  ))}
                </div>
              </div>

              <div>
                <label className="form-label">Compliance preset</label>
                <select className="form-input" value={compliancePreset} onChange={e => setCompliancePreset(e.target.value)} style={{height: 32, fontSize: 12.5}}>
                  <option value="custom">Custom (current)</option>
                  <option value="pci">PCI DSS 4.0 (Critical: 1d, High: 7d)</option>
                  <option value="hipaa">HIPAA Security Rule</option>
                  <option value="soc2">SOC 2 Type II</option>
                  <option value="iso">ISO 27001</option>
                  <option value="cisa">CISA KEV (BOD 22-01)</option>
                </select>
              </div>

              <div style={{padding: "10px 12px", background: "var(--surface-2)", borderRadius: 6, fontSize: 12, color: "var(--text-2)", lineHeight: 1.5}}>
                <Icons.Sparkles size={11} style={{verticalAlign: "middle", marginRight: 4, color: "var(--brand-text)"}}/>
                Asset folders can override these workspace defaults — see <span style={{color: "var(--brand-text)"}}>Assets → [folder] → Settings</span>.
              </div>
            </div>
          </div>
        </div>

        <div style={{marginTop: 24, paddingTop: 16, borderTop: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center"}}>
          <div style={{fontSize: 12, color: error ? "var(--err)" : "var(--text-3)"}}>
            {error
              ? <><Icons.AlertTriangle size={12}/> {error}</>
              : savedAt
                ? <><Icons.Check size={12}/> Saved {savedAt.toLocaleTimeString()}</>
                : loading
                  ? "Loading…"
                  : "Changes apply to new findings only — existing SLA timers continue from their current deadline."}
          </div>
          <div style={{display: "flex", gap: 8}}>
            <button className="btn btn-sm" onClick={reset} disabled={saving || loading}>Reset to defaults</button>
            <button className="btn btn-sm btn-primary" onClick={save} disabled={saving || loading}>
              {saving ? <><Icons.Refresh size={12} className="spin"/> Saving…</> : <><Icons.Check size={12}/> Save policies</>}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
