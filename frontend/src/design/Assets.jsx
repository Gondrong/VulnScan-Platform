import React, { useState, useEffect, useCallback } from "react";
import { Icons, Pip, Risk, Status } from "./icons.jsx";
import { scanApi, assetsApi, reportsApi, apiScannerApi, credentialsApi, webAuthApi } from "../api.js";

export function Assets({ openAsset }) {
  const [view, setView] = useState("grid");
  const [q, setQ] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [showFolder, setShowFolder] = useState(false);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try { setAssets(await assetsApi.list()); setError(""); }
    catch (e) { setError(e.message); }
    finally   { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const roots = assets.filter(a => !a.parent_id);
  const children = (id) => assets.filter(a => a.parent_id === id);
  const filtered = assets.filter(a => !q || a.name.toLowerCase().includes(q.toLowerCase()));

  return (
    <>
      <div className="ph">
        <div>
          <h1>Assets</h1>
          <div className="sub">Group related scan targets into folders. New scans inherit the asset's tags, owners, and SLA defaults.</div>
        </div>
        <div className="actions">
          <div style={{display: "flex", gap: 2, padding: 2, background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 7}}>
            <button className={`btn btn-sm ${view === "grid" ? "" : "btn-ghost"}`} style={{border: "none", background: view === "grid" ? "var(--surface-2)" : "transparent"}} onClick={() => setView("grid")}><Icons.Dashboard size={12}/> Grid</button>
            <button className={`btn btn-sm ${view === "tree" ? "" : "btn-ghost"}`} style={{border: "none", background: view === "tree" ? "var(--surface-2)" : "transparent"}} onClick={() => setView("tree")}><Icons.Layers size={12}/> Tree</button>
          </div>
          <button className="btn" onClick={() => setShowFolder(true)}><Icons.FolderOpen size={14}/> New folder</button>
          <button className="btn btn-primary" onClick={() => setShowCreate(true)}><Icons.Plus size={14}/> New scan</button>
        </div>
      </div>

      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}

      {(() => {
        const totalTargets = assets.reduce((s, a) => s + (a.targets || 0), 0);
        const highest = assets.reduce((m, a) => (a.risk || 0) > (m.risk || 0) ? a : m, {});
        const totalCritical = assets.reduce((s, a) => s + (a.critical || 0), 0);
        return (
          <div className="grid-stat" style={{gridTemplateColumns: "repeat(4, 1fr)", marginBottom: 20}}>
            <div className="stat brand"><div className="accent-bar"/><div className="label"><Icons.Folder size={12}/> Folders</div><div className="value">{roots.length}</div><div className="delta flat">{assets.length - roots.length} sub-folders</div></div>
            <div className="stat neutral"><div className="accent-bar"/><div className="label"><Icons.Target size={12}/> Targets</div><div className="value">{totalTargets}</div><div className="delta flat">across all assets</div></div>
            <div className="stat critical"><div className="accent-bar"/><div className="label">Highest risk</div><div className="value">{highest.risk || 0}</div><div className="delta up">{highest.name || "—"}</div></div>
            <div className="stat high"><div className="accent-bar"/><div className="label">Critical findings</div><div className="value">{totalCritical}</div><div className="delta flat">across folders</div></div>
          </div>
        );
      })()}

      {loading && assets.length === 0 ? (
        <div style={{padding: 60, textAlign: "center", color: "var(--text-3)"}}>Loading assets…</div>
      ) : assets.length === 0 ? (
        <div className="card" style={{padding: 40, textAlign: "center", color: "var(--text-3)"}}>
          <Icons.Folder size={28}/>
          <div style={{fontSize: 14, color: "var(--text-1)", marginTop: 12, fontWeight: 500}}>No asset folders yet</div>
          <div style={{fontSize: 13, marginTop: 4}}>Group related scan targets into folders for shared owners, schedules, and SLA defaults.</div>
          <button className="btn btn-primary" style={{marginTop: 16}} onClick={() => setShowFolder(true)}>
            <Icons.FolderOpen size={14}/> Create first folder
          </button>
        </div>
      ) : view === "grid" ? (
        <>
          <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12}}>
            <div className="eyebrow" style={{margin: 0}}>Top-level folders</div>
            <div className="field" style={{maxWidth: 280}}>
              <Icons.Search size={14} className="icon"/>
              <input placeholder="Search assets…" value={q} onChange={e => setQ(e.target.value)}/>
            </div>
          </div>
          <div style={{display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 14}}>
            {roots.map(a => {
              const subs = children(a.id);
              const total = (a.critical || 0) + (a.high || 0) + (a.medium || 0) + (a.low || 0);
              return (
                <div key={a.id} className="card" style={{cursor: "pointer", transition: "all 120ms"}}
                     onClick={() => openAsset(a)}
                     onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--brand-line)"; }}
                     onMouseLeave={e => { e.currentTarget.style.borderColor = ""; }}>
                  <div style={{padding: "16px 18px"}}>
                    <div style={{display: "flex", alignItems: "flex-start", gap: 12}}>
                      <div style={{width: 38, height: 38, borderRadius: 8, background: "var(--brand-soft)", color: "var(--brand)", display: "grid", placeItems: "center", flexShrink: 0}}>
                        <Icons.Folder size={18}/>
                      </div>
                      <div style={{flex: 1, minWidth: 0}}>
                        <div style={{fontSize: 14.5, fontWeight: 600, color: "var(--text-0)", fontFamily: "var(--font-display)", letterSpacing: "-0.005em"}}>{a.name}</div>
                        <div style={{fontSize: 12, color: "var(--text-3)", marginTop: 3, lineHeight: 1.5}}>{a.desc}</div>
                      </div>
                      <Risk score={a.risk}/>
                    </div>

                    <div style={{display: "flex", gap: 14, marginTop: 14, fontSize: 12, color: "var(--text-3)"}}>
                      <span><Icons.Target size={11} style={{marginRight: 4, verticalAlign: "-1px"}}/><span className="mono" style={{color: "var(--text-1)", fontWeight: 600}}>{a.targets || 0}</span> targets</span>
                      {subs.length > 0 && <span><Icons.Folder size={11} style={{marginRight: 4, verticalAlign: "-1px"}}/><span className="mono" style={{color: "var(--text-1)", fontWeight: 600}}>{subs.length}</span> sub</span>}
                      <span style={{marginLeft: "auto"}}><Icons.Clock size={11} style={{marginRight: 4, verticalAlign: "-1px"}}/>{a.last_scan_at ? new Date(a.last_scan_at).toLocaleDateString() : "never"}</span>
                    </div>

                    {total > 0 && (
                      <>
                        <div style={{display: "flex", height: 4, borderRadius: 2, overflow: "hidden", background: "var(--surface-2)", marginTop: 12}}>
                          {a.critical > 0 && <div style={{flex: a.critical, background: "var(--sev-critical)"}}/>}
                          {a.high > 0     && <div style={{flex: a.high,     background: "var(--sev-high)"}}/>}
                          {a.medium > 0   && <div style={{flex: a.medium,   background: "var(--sev-medium)"}}/>}
                          {a.low > 0      && <div style={{flex: a.low,      background: "var(--sev-low)"}}/>}
                        </div>
                        <div style={{display: "flex", gap: 12, marginTop: 8, fontSize: 11, color: "var(--text-3)", fontFamily: "var(--font-mono)"}}>
                          {a.critical > 0 && <span><Pip s="critical"/> {a.critical}</span>}
                          {a.high > 0 && <span><Pip s="high"/> {a.high}</span>}
                          {a.medium > 0 && <span><Pip s="medium"/> {a.medium}</span>}
                          {a.low > 0 && <span><Pip s="low"/> {a.low}</span>}
                        </div>
                      </>
                    )}

                    {subs.length > 0 && (
                      <div style={{marginTop: 14, paddingTop: 12, borderTop: "1px dashed var(--line)", display: "flex", flexDirection: "column", gap: 4}}>
                        {subs.map(s => (
                          <div key={s.id} style={{display: "flex", alignItems: "center", gap: 8, fontSize: 12, padding: "4px 6px", borderRadius: 4, color: "var(--text-2)"}}>
                            <Icons.Folder size={11} color="var(--text-3)"/>
                            <span style={{flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>{s.name}</span>
                            <span className="mono muted" style={{fontSize: 11}}>{s.targets || 0}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
            <div className="card" onClick={() => setShowFolder(true)}
                 style={{borderStyle: "dashed", display: "flex", alignItems: "center", justifyContent: "center", minHeight: 180, cursor: "pointer", color: "var(--text-3)"}}
                 onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--brand-line)"; e.currentTarget.style.color = "var(--brand-text)"; }}
                 onMouseLeave={e => { e.currentTarget.style.borderColor = ""; e.currentTarget.style.color = "var(--text-3)"; }}>
              <div style={{textAlign: "center"}}>
                <Icons.FolderOpen size={28}/>
                <div style={{fontSize: 13, marginTop: 8, fontWeight: 500}}>New folder</div>
                <div style={{fontSize: 11.5, marginTop: 2}}>Group related targets</div>
              </div>
            </div>
          </div>
        </>
      ) : (
        <div className="card">
          <div className="card-body flush">
            <table className="tbl">
              <thead><tr><th>Asset</th><th>Owner</th><th style={{width: 80}}>Targets</th><th style={{width: 200}}>Severity</th><th style={{width: 90}}>Risk</th><th style={{width: 110}}>Last scan</th></tr></thead>
              <tbody>
                {filtered.map(a => {
                  const isChild = !!a.parent_id;
                  return (
                    <tr key={a.id} className="clickable" onClick={() => openAsset(a)}>
                      <td>
                        <div style={{display: "flex", alignItems: "center", gap: 10, paddingLeft: isChild ? 24 : 0}}>
                          {isChild && <span style={{color: "var(--text-3)", fontSize: 11, fontFamily: "var(--font-mono)"}}>└─</span>}
                          <Icons.Folder size={14} color={isChild ? "var(--text-3)" : "var(--brand)"}/>
                          <span style={{color: "var(--text-0)", fontWeight: isChild ? 400 : 500}}>{a.name}</span>
                        </div>
                      </td>
                      <td><span style={{fontSize: 12.5, color: "var(--text-2)"}}>{a.owner || "—"}</span></td>
                      <td className="num">{a.targets || 0}</td>
                      <td>
                        <div style={{display: "flex", height: 4, borderRadius: 2, overflow: "hidden", background: "var(--surface-2)"}}>
                          {a.critical > 0 && <div style={{flex: a.critical, background: "var(--sev-critical)"}}/>}
                          {a.high > 0     && <div style={{flex: a.high,     background: "var(--sev-high)"}}/>}
                          {a.medium > 0   && <div style={{flex: a.medium,   background: "var(--sev-medium)"}}/>}
                          {a.low > 0      && <div style={{flex: a.low,      background: "var(--sev-low)"}}/>}
                        </div>
                      </td>
                      <td><Risk score={a.risk}/></td>
                      <td className="muted" style={{fontSize: 12}}>{a.last_scan_at ? new Date(a.last_scan_at).toLocaleDateString() : "never"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {showCreate && <NewScanModal close={() => setShowCreate(false)} onCreated={() => { setShowCreate(false); refresh(); }}/>}
      {showFolder && <NewFolderModal assets={assets} close={() => setShowFolder(false)} onCreated={() => { setShowFolder(false); refresh(); }}/>}
    </>
  );
}

export function AssetDetail({ asset: initialAsset, back }) {
  const [tab, setTab] = useState("targets");
  const [showCreate, setShowCreate] = useState(false);
  const [asset, setAsset] = useState(initialAsset);
  const [targets, setTargets] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [subs, setSubs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [a, t, j, all] = await Promise.all([
        assetsApi.get(initialAsset.id),
        assetsApi.targets(initialAsset.id),
        assetsApi.jobs(initialAsset.id),
        assetsApi.list(),
      ]);
      setAsset(a);
      setTargets(t);
      setJobs(j);
      setSubs(all.filter(x => x.parent_id === initialAsset.id));
      setError("");
    } catch (e) { setError(e.message); }
    finally     { setLoading(false); }
  }, [initialAsset.id]);

  useEffect(() => { refresh(); }, [refresh]);

  return (
    <>
      <div className="ph">
        <div>
          <div style={{display: "flex", alignItems: "center", gap: 10, marginBottom: 6}}>
            <button className="btn btn-ghost btn-sm" onClick={back}><Icons.ChevronRight size={12} style={{transform: "rotate(180deg)"}}/> All assets</button>
            <span className="tag"><Icons.Folder size={11}/> Folder</span>
            <span className="tag">{asset.owner}</span>
          </div>
          <h1>{asset.name}</h1>
          <div className="sub">{asset.desc}</div>
        </div>
        <div className="actions">
          <button className="btn"><Icons.Edit size={14}/> Edit</button>
          <button className="btn"><Icons.Download size={14}/> Export report</button>
          <button className="btn btn-primary" onClick={() => setShowCreate(true)}><Icons.Plus size={14}/> Add target & scan</button>
        </div>
      </div>

      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}

      <div className="grid-stat" style={{gridTemplateColumns: "repeat(5, 1fr)", marginBottom: 20}}>
        <div className="stat critical"><div className="accent-bar"/><div className="label">Critical</div><div className="value">{asset.critical || 0}</div></div>
        <div className="stat high"><div className="accent-bar"/><div className="label">High</div><div className="value">{asset.high || 0}</div></div>
        <div className="stat medium"><div className="accent-bar"/><div className="label">Medium</div><div className="value">{asset.medium || 0}</div></div>
        <div className="stat low"><div className="accent-bar"/><div className="label">Low</div><div className="value">{asset.low || 0}</div></div>
        <div className="stat brand"><div className="accent-bar"/><div className="label">Aggregate risk</div><div className="value">{asset.risk || 0}</div></div>
      </div>

      <div className="card">
        <div className="toolbar">
          <div className="left">
            <div className="tabs">
              <button className={`tab ${tab === "targets" ? "active" : ""}`} onClick={() => setTab("targets")}>Targets <span className="badge">{targets.length}</span></button>
              {subs.length > 0 && <button className={`tab ${tab === "subs" ? "active" : ""}`} onClick={() => setTab("subs")}>Sub-folders <span className="badge">{subs.length}</span></button>}
              <button className={`tab ${tab === "scans" ? "active" : ""}`} onClick={() => setTab("scans")}>Scan history</button>
              <button className={`tab ${tab === "settings" ? "active" : ""}`} onClick={() => setTab("settings")}>Settings</button>
            </div>
          </div>
        </div>
        <div className="card-body flush">
          {tab === "targets" && (
            targets.length === 0 ? (
              <div style={{padding: 40, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>
                No scans have been tagged to this folder yet. Click "Add target & scan" above.
              </div>
            ) : (
              <table className="tbl">
                <thead><tr><th>Target</th><th style={{width: 100}}>Findings</th><th style={{width: 100}}>Scans</th><th style={{width: 160}}>Last scan</th></tr></thead>
                <tbody>
                  {targets.map(t => (
                    <tr key={t.target} className="clickable">
                      <td><div style={{display: "flex", gap: 10, alignItems: "center"}}><Icons.Server size={14} color="var(--text-3)"/><span className="mono" style={{color: "var(--text-0)"}}>{t.target}</span></div></td>
                      <td className="num"><span style={{color: "var(--text-0)", fontWeight: 600}}>{t.findings}</span></td>
                      <td className="num">{t.scans}</td>
                      <td className="muted" style={{fontSize: 12}}>{t.last_scan_at ? new Date(t.last_scan_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"}) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}
          {tab === "subs" && (
            <table className="tbl">
              <thead><tr><th>Sub-folder</th><th style={{width: 100}}>Targets</th><th style={{width: 100}}>Risk</th></tr></thead>
              <tbody>
                {subs.map(s => (
                  <tr key={s.id} className="clickable">
                    <td><div style={{display: "flex", gap: 10, alignItems: "center"}}><Icons.Folder size={14} color="var(--brand)"/><span style={{fontWeight: 500, color: "var(--text-0)"}}>{s.name}</span></div></td>
                    <td className="num">{s.targets || 0}</td>
                    <td><Risk score={s.risk}/></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {tab === "scans" && (
            jobs.length === 0 ? (
              <div style={{padding: 40, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>No scan jobs yet for this folder.</div>
            ) : (
              <table className="tbl">
                <thead><tr><th>Job</th><th>Target</th><th>Profile</th><th>Status</th><th style={{width: 130}}>Started</th></tr></thead>
                <tbody>
                  {jobs.map(j => (
                    <tr key={j.id} className="clickable">
                      <td><span className="mono" style={{color: "var(--brand-text)"}}>#{j.id}</span></td>
                      <td><span className="mono">{j.target}</span></td>
                      <td><span style={{color: "var(--text-2)", fontSize: 12.5}} className="mono">#{j.profile_id ?? "—"}</span></td>
                      <td><Status s={j.status}/></td>
                      <td className="muted" style={{fontSize: 12}}>{j.created_at ? new Date(j.created_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"}) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}
          {tab === "settings" && (
            <div style={{padding: "24px 28px"}}>
              <div className="eyebrow">Defaults inherited by new scans</div>
              <dl className="dl">
                <dt>Owner</dt><dd>{asset.owner || "—"}</dd>
                <dt>Description</dt><dd>{asset.description || "—"}</dd>
                <dt>Default profile</dt><dd className="mono">{asset.default_profile_id ? `#${asset.default_profile_id}` : "—"}</dd>
                <dt>Default credential</dt><dd className="mono">{asset.default_credential_id ? `#${asset.default_credential_id}` : "—"}</dd>
                <dt>Tags</dt><dd>{asset.tags && asset.tags.length > 0 ? asset.tags.map(t => <span key={t} className="tag" style={{marginRight: 4}}>{t}</span>) : "—"}</dd>
              </dl>
              <div style={{marginTop: 16, display: "flex", gap: 8}}>
                <button className="btn" style={{color: "var(--err)"}} onClick={async () => {
                  if (!confirm(`Delete folder "${asset.name}"? Scans tagged to it will be unlinked but kept.`)) return;
                  try { await assetsApi.delete(asset.id); back(); }
                  catch (e) { alert(e.message); }
                }}><Icons.Trash size={12}/> Delete folder</button>
              </div>
            </div>
          )}
        </div>
      </div>

      {showCreate && <NewScanModal close={() => setShowCreate(false)} preselectedAsset={asset} onCreated={() => { setShowCreate(false); refresh(); }}/>}
    </>
  );
}

function NewFolderModal({ assets, close, onCreated }) {
  const [data, setData] = useState({ name: "", description: "", parent_id: null, owner: "", tags: [] });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const update = (k, v) => setData(d => ({ ...d, [k]: v }));

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try { await assetsApi.create(data); onCreated(); }
    catch (err) { setError(err.message); setSubmitting(false); }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 460}}>
        <div className="drawer-head">
          <Icons.FolderOpen size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>New asset folder</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <form onSubmit={submit} style={{padding: "20px 24px", display: "flex", flexDirection: "column", gap: 14}}>
          <div>
            <label className="form-label">Name</label>
            <input className="form-input" placeholder="e.g. Production · API" value={data.name} onChange={e => update("name", e.target.value)} required autoFocus/>
          </div>
          <div>
            <label className="form-label">Description (optional)</label>
            <textarea className="form-input" rows={2} value={data.description} onChange={e => update("description", e.target.value)} style={{height: "auto", padding: "8px 12px"}} placeholder="What lives in this folder?"/>
          </div>
          <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12}}>
            <div>
              <label className="form-label">Parent folder</label>
              <select className="form-input" value={data.parent_id || ""} onChange={e => update("parent_id", e.target.value ? parseInt(e.target.value) : null)}>
                <option value="">No parent (top-level)</option>
                {assets.filter(a => !a.parent_id).map(a => (
                  <option key={a.id} value={a.id}>Inside: {a.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="form-label">Owner (optional)</label>
              <input className="form-input" placeholder="API Team" value={data.owner} onChange={e => update("owner", e.target.value)}/>
            </div>
          </div>
          {error && <div style={{color: "var(--err)", fontSize: 12.5}}><Icons.AlertTriangle size={12}/> {error}</div>}
          <div style={{display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 6}}>
            <button type="button" className="btn" onClick={close} disabled={submitting}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? <><Icons.Refresh size={12} className="spin"/> Creating…</> : <><Icons.Check size={12}/> Create folder</>}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

export function NewScanModal({ close, preselectedAsset, onCreated }) {
  const [scanKind, setScanKind] = useState("network");
  const [target, setTarget] = useState("");
  const [profiles, setProfiles] = useState([]);
  const [profileId, setProfileId] = useState(null);
  const [assets, setAssets] = useState([]);
  const [assetId, setAssetId] = useState(preselectedAsset?.id || null);
  const [createNew, setCreateNew] = useState(false);
  const [newAssetName, setNewAssetName] = useState("");
  const [newAssetParent, setNewAssetParent] = useState(null);
  const [apiSource, setApiSource] = useState("upload");
  const [apiFile, setApiFile]     = useState(null);
  const [apiUrl, setApiUrl]       = useState("");
  const [apiBaseUrl, setApiBaseUrl] = useState("");
  const [apiChecks, setApiChecks] = useState([]);
  const [selectedApiChecks, setSelectedApiChecks] = useState(new Set());
  const [scheduleMode, setScheduleMode] = useState("now");
  const [scheduleConfig, setScheduleConfig] = useState({
    interval_hours: 24,
    custom_datetime: "",
    repeat: true,
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  // ── Web Authentication state (only used when scanKind === "web") ─────
  const [creds, setCreds] = useState([]);
  const [waType, setWaType]                     = useState("none");
  const [waCredId, setWaCredId]                 = useState("");
  const [waLoginUrl, setWaLoginUrl]             = useState("");
  const [waActionUrl, setWaActionUrl]           = useState("");
  const [waUsername, setWaUsername]             = useState("");
  const [waPassword, setWaPassword]             = useState("");
  const [waUserField, setWaUserField]           = useState("username");
  const [waPassField, setWaPassField]           = useState("password");
  const [waSuccessIndicator, setWaSuccessInd]   = useState("");
  const [waFailureIndicator, setWaFailureInd]   = useState("");
  const [waToken, setWaToken]                   = useState("");
  const [waCookiesText, setWaCookiesText]       = useState("");
  const [waHeadersText, setWaHeadersText]       = useState("");

  const [inspectResult, setInspectResult]       = useState(null);
  const [inspectLoading, setInspectLoading]     = useState(false);
  const [inspectError, setInspectError]         = useState("");
  const [selectedFormIdx, setSelectedFormIdx]   = useState(0);

  // Save-as-credential / ephemeral
  const [waSaveAsCred, setWaSaveAsCred]         = useState(false);
  const [waSaveCredName, setWaSaveCredName]     = useState("");
  const [waEphemeral, setWaEphemeral]           = useState(false);

  // Test login state
  const [testLoading, setTestLoading]           = useState(false);
  const [testResult, setTestResult]             = useState(null); // {success, evidence, error, cookie_names, header_names}

  useEffect(() => {
    Promise.all([
      scanApi.listProfiles(),
      assetsApi.list(),
      apiScannerApi.checks().catch(() => ({ checks: [] })),
      credentialsApi.list().catch(() => []),
    ])
      .then(([list, ass, chk, cs]) => {
        setProfiles(list || []);
        if (list && list.length > 0) setProfileId(list[0].id);
        setAssets(ass || []);
        const checks = chk.checks || [];
        setApiChecks(checks);
        setSelectedApiChecks(new Set(checks.map(c => c.id)));
        setCreds(cs || []);
      })
      .catch(e => setError(e.message || "Failed to load form data"));
  }, []);

  // Auto-prefill the login URL field from the target when the user types it
  useEffect(() => {
    if (scanKind === "web" && waType === "form" && !waLoginUrl && target.startsWith("http")) {
      // Best-effort default — user can override
      setWaLoginUrl(target.replace(/\/$/, "") + "/login");
    }
  }, [target, scanKind, waType]);  // eslint-disable-line react-hooks/exhaustive-deps

  // Parse "key=value" / "Name: value" lines into a dict
  const parseKv = (text, sep) => {
    const out = {};
    for (const raw of (text || "").split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const idx = line.indexOf(sep);
      if (idx < 1) continue;
      const k = line.slice(0, idx).trim();
      const v = line.slice(idx + sep.length).trim();
      if (k) out[k] = v;
    }
    return out;
  };

  // Build the web_auth block that goes into the scan job. Returns null if type=none.
  const buildWebAuth = () => {
    if (scanKind !== "web" || waType === "none") return null;
    const wa = { type: waType };
    if (waType === "form") {
      if (!waLoginUrl.trim()) throw new Error("Web auth: login URL is required for form login");
      wa.login_url = waLoginUrl.trim();
      if (waActionUrl && waActionUrl !== waLoginUrl.trim()) wa.action_url = waActionUrl;
      wa.username_field = waUserField || "username";
      wa.password_field = waPassField || "password";
      if (waSuccessIndicator) wa.success_indicator = waSuccessIndicator;
      if (waFailureIndicator) wa.failure_indicator = waFailureIndicator;
      if (waCredId) wa.credential_id = parseInt(waCredId);
      else {
        if (!waUsername) throw new Error("Web auth: pick a credential or enter a username");
        wa.username = waUsername;
        wa.password = waPassword;
      }
    } else if (waType === "basic") {
      if (waCredId) wa.credential_id = parseInt(waCredId);
      else {
        if (!waUsername) throw new Error("Web auth: pick a credential or enter a username");
        wa.username = waUsername;
        wa.password = waPassword;
      }
    } else if (waType === "bearer") {
      if (waCredId) wa.credential_id = parseInt(waCredId);
      else {
        if (!waToken.trim()) throw new Error("Web auth: token is required for bearer auth");
        wa.token = waToken.trim();
      }
    } else if (waType === "cookie") {
      const cookies = parseKv(waCookiesText, "=");
      if (Object.keys(cookies).length === 0) throw new Error("Web auth: at least one cookie (name=value) is required");
      wa.cookies = cookies;
    } else if (waType === "header") {
      const headers = parseKv(waHeadersText, ":");
      if (Object.keys(headers).length === 0) throw new Error("Web auth: at least one header (Name: value) is required");
      wa.headers = headers;
    }
    return wa;
  };

  // Inspector helpers
  const applyForm = (form) => {
    if (!form) return;
    setWaActionUrl(form.action || "");
    if (form.username_candidates?.[0]) setWaUserField(form.username_candidates[0]);
    if (form.password_candidates?.[0]) setWaPassField(form.password_candidates[0]);
  };
  const runInspect = async () => {
    if (!waLoginUrl.trim()) { setInspectError("Enter a login URL first"); return; }
    setInspectError(""); setInspectLoading(true);
    try {
      const result = await webAuthApi.inspect(waLoginUrl.trim());
      setInspectResult(result);
      setSelectedFormIdx(0);
      if (result.error) setInspectError(result.error);
      else if (!result.forms?.length) setInspectError("No <form> elements found — login is likely JS-rendered. Fill field names manually.");
      else applyForm(result.forms[0]);
    } catch (e) { setInspectError(e.message || "Inspect failed"); }
    finally     { setInspectLoading(false); }
  };
  const pickForm = (idx) => {
    setSelectedFormIdx(idx);
    if (inspectResult?.forms?.[idx]) applyForm(inspectResult.forms[idx]);
  };
  const clearInspect = () => { setInspectResult(null); setInspectError(""); setSelectedFormIdx(0); };

  const inspectedForm    = inspectResult?.forms?.[selectedFormIdx] || null;
  const userFieldOptions = inspectedForm
    ? inspectedForm.fields.filter(f => f.type !== "password" && !f.is_csrf && !["submit","button","hidden"].includes(f.type)).map(f => f.name)
    : [];
  const passFieldOptions = inspectedForm
    ? inspectedForm.fields.filter(f => f.type === "password").map(f => f.name)
    : [];

  // Detect whether the inspected username field is an email field — used to
  // rank credentials whose username looks like an email.
  const userFieldIsEmail = (() => {
    if (!inspectedForm || !waUserField) return false;
    const f = inspectedForm.fields.find(x => x.name === waUserField);
    if (!f) return false;
    return f.type === "email" || /email|e[-_]?mail/i.test(f.name || "");
  })();

  // Sort credentials: matching ones first (when userFieldIsEmail, prefer creds
  // whose username contains "@"), then by id desc. Returns annotated list.
  const webCreds = (() => {
    const list = creds
      .filter(c => c.secret_type !== "SSH_KEY")
      .map(c => ({
        ...c,
        _matchesEmail: userFieldIsEmail && (c.username || "").includes("@"),
      }));
    list.sort((a, b) => {
      if (a._matchesEmail !== b._matchesEmail) return a._matchesEmail ? -1 : 1;
      return (b.id || 0) - (a.id || 0);
    });
    return list;
  })();

  // Test login — runs the same auth flow once and reports back
  const runTestLogin = async () => {
    setTestResult(null);
    let wa;
    try { wa = buildWebAuth(); }
    catch (e) { setTestResult({success: false, error: e.message}); return; }
    if (!wa) { setTestResult({success: false, error: "No auth configured"}); return; }

    // Resolve base_url — target field, else login_url's origin
    let baseUrl = (target || "").trim();
    if (!baseUrl && wa.login_url) {
      try { baseUrl = new URL(wa.login_url).origin; } catch {}
    }
    if (!baseUrl) {
      setTestResult({success: false, error: "Set the target URL above first"});
      return;
    }
    if (!/^https?:\/\//.test(baseUrl)) {
      setTestResult({success: false, error: "Target must be a full URL (https://…)"});
      return;
    }

    setTestLoading(true);
    try {
      const r = await webAuthApi.testLogin(wa, baseUrl);
      setTestResult(r);
    } catch (e) {
      setTestResult({success: false, error: e.message || "Test login failed"});
    } finally {
      setTestLoading(false);
    }
  };

  // Whether enough fields are filled for Test login to make sense
  const canTestLogin = (() => {
    if (waType === "none") return false;
    if (waType === "form") {
      if (!waLoginUrl.trim()) return false;
      if (waCredId) return true;
      return !!waUsername;
    }
    if (waType === "basic")  return waCredId || !!waUsername;
    if (waType === "bearer") return waCredId || !!waToken.trim();
    if (waType === "cookie") return !!waCookiesText.trim();
    if (waType === "header") return !!waHeadersText.trim();
    return false;
  })();

  const SCAN_KINDS = [
    { id: "network", label: "Network", icon: Icons.Server, desc: "Hosts, ports, services" },
    { id: "web",     label: "Web App", icon: Icons.Globe,  desc: "OWASP Top 10, auth flows" },
    { id: "api",     label: "API",     icon: Icons.Code,   desc: "OpenAPI / Swagger / Postman" },
    { id: "iot",     label: "IoT",     icon: Icons.Chip,   desc: "MQTT, CoAP, gateways" },
    { id: "cloud",   label: "Cloud",   icon: Icons.Cloud,  desc: "AWS / Azure / GCP misconfigs" },
  ];
  const activeKind = SCAN_KINDS.find(k => k.id === scanKind) || SCAN_KINDS[0];

  // Map design scan-kind to backend scan_type ("internal" | "external")
  const scanTypeFor = (k) => (k === "web" || k === "api" || k === "cloud") ? "external" : "internal";

  const submit = async () => {
    setError("");

    // ── API scan → dedicated endpoint ─────────────────────────────
    if (scanKind === "api") {
      const base = apiBaseUrl.trim();
      if (!base) { setError("Base URL is required"); return; }
      if (selectedApiChecks.size === 0) { setError("Select at least one security check"); return; }
      setSubmitting(true);
      try {
        const config = { base_url: base, checks: [...selectedApiChecks] };
        if (apiSource === "url" && apiUrl.trim()) config.spec_url = apiUrl.trim();
        const fd = new FormData();
        fd.append("config_json", JSON.stringify(config));
        if (apiSource === "upload" && apiFile) fd.append("spec_file", apiFile);
        await apiScannerApi.createJob(fd);
        onCreated ? onCreated() : close();
      } catch (e) { setError(e.message || "Failed to create API scan"); setSubmitting(false); }
      return;
    }

    // ── Other scan types ──────────────────────────────────────────
    let finalTarget = target.trim();
    if (!finalTarget) { setError("Target is required"); return; }
    if (!profileId)   { setError("Pick a scan profile"); return; }

    // Build per-job web_auth (only for Web App + Run now)
    let webAuth = null;
    try { webAuth = buildWebAuth(); }
    catch (e) { setError(e.message); return; }
    if (webAuth && scheduleMode !== "now") {
      setError(
        "Per-scan authentication is only applied to immediate ('Run now') scans. " +
        "For scheduled authenticated scans, save the auth in a Profile (Profile → Web Authentication)."
      );
      return;
    }

    // Validation for save-as-credential
    if (webAuth && waSaveAsCred && !waCredId) {
      if (!waSaveCredName.trim()) {
        setError("Pick a name for the credential to save it (e.g., 'webapp-tester')");
        return;
      }
    }
    // Ephemeral only makes sense when paired with save-as-credential (or an existing cred)
    if (webAuth && waEphemeral && !waCredId && !waSaveAsCred) {
      setError("Auto-delete after scan only applies when you Save the credential or pick an existing one");
      return;
    }

    setSubmitting(true);
    try {
      let finalAssetId = assetId;
      if (createNew && newAssetName.trim()) {
        const created = await assetsApi.create({
          name: newAssetName.trim(),
          parent_id: newAssetParent,
        });
        finalAssetId = created.id;
      }

      // ── Save-as-credential: create the credential first, then reference its ID ──
      if (webAuth && waSaveAsCred && !waCredId) {
        const isBearer = webAuth.type === "bearer";
        const credBody = {
          name: waSaveCredName.trim(),
          kind: isBearer ? "api" : "password",
          username: isBearer ? "" : (webAuth.username || ""),
          secret: isBearer ? (webAuth.token || "") : (webAuth.password || ""),
          secret_type: "password",
        };
        const created = await credentialsApi.create(credBody);
        // Replace inline values with credential reference
        webAuth = { ...webAuth };
        webAuth.credential_id = parseInt(created.id);
        delete webAuth.username;
        delete webAuth.password;
        delete webAuth.token;
      }

      const scanType = scanTypeFor(scanKind);

      if (scheduleMode === "now") {
        const jobBody = {
          target: finalTarget,
          profile_id: profileId,
          scan_type: scanType,
          asset_id: finalAssetId || null,
        };
        if (webAuth) jobBody.web_auth = webAuth;
        // Ephemeral cleanup: backend deletes the linked credential when the scan ends
        if (webAuth && waEphemeral && webAuth.credential_id) {
          jobBody.web_auth_credential_ephemeral = true;
        }
        await scanApi.createJob(jobBody);
      } else {
        const schedulePayload = {
          name: `Scheduled: ${finalTarget}`,
          target: finalTarget,
          profile_id: profileId,
          scan_type: scanType,
          enabled: true,
        };
        if (scheduleMode === "once") {
          if (!scheduleConfig.custom_datetime) throw new Error("Pick a date/time for the scheduled run");
          schedulePayload.schedule_type = "custom";
          schedulePayload.custom_datetime = new Date(scheduleConfig.custom_datetime).toISOString();
          schedulePayload.repeat = false;
        } else {
          schedulePayload.schedule_type = "interval";
          const intervalMap = { hourly: 1, daily: 24, weekly: 168, monthly: 720, custom: scheduleConfig.interval_hours };
          schedulePayload.interval_hours = intervalMap[scheduleMode] ?? 24;
          schedulePayload.repeat = true;
        }
        await scanApi.createSchedule(schedulePayload);
      }

      onCreated ? onCreated() : close();
    } catch (e) {
      setError(e.message || "Failed to create scan");
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 600, maxHeight: "90vh", display: "flex", flexDirection: "column"}}>
        <div className="drawer-head">
          <div style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>New scan</div>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "20px 24px", display: "flex", flexDirection: "column", gap: 18, overflowY: "auto", flex: 1}}>

          <div>
            <label className="form-label">Scan type</label>
            <div style={{display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 6}}>
              {SCAN_KINDS.map(k => {
                const I = k.icon; const active = scanKind === k.id;
                return (
                  <button key={k.id} onClick={() => setScanKind(k.id)}
                          className={`btn ${active ? "btn-primary" : ""}`}
                          style={{flexDirection: "column", height: "auto", padding: "10px 4px", gap: 4, alignItems: "center", justifyContent: "center"}}>
                    {I && <I size={16}/>}
                    <div style={{fontSize: 12, fontWeight: 600}}>{k.label}</div>
                  </button>
                );
              })}
            </div>
            <div className="form-help">{activeKind.desc}</div>
          </div>

          {scanKind === "api" ? (
            <div style={{display: "flex", flexDirection: "column", gap: 14}}>
              {/* Base URL */}
              <div>
                <label className="form-label">Base URL *</label>
                <input className="form-input mono" placeholder="https://api.example.com"
                       value={apiBaseUrl} onChange={e => setApiBaseUrl(e.target.value)} autoFocus/>
                <div className="form-help">Root URL of the API. All endpoints will be relative to this.</div>
              </div>

              {/* Spec source */}
              <div>
                <label className="form-label">API specification (optional)</label>
                <div style={{display: "flex", gap: 4, padding: 2, background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 7, marginBottom: 10}}>
                  {[
                    { id: "none",   label: "None (discover)" },
                    { id: "upload", label: "Upload file" },
                    { id: "url",    label: "From URL" },
                  ].map(t => (
                    <button key={t.id}
                            className="btn btn-sm"
                            style={{
                              border: "none",
                              background: apiSource === t.id ? "var(--surface-2)" : "transparent",
                              color: apiSource === t.id ? "var(--text-0)" : "var(--text-2)",
                              flex: 1, justifyContent: "center", fontWeight: apiSource === t.id ? 600 : 500,
                            }}
                            onClick={() => setApiSource(t.id)}>{t.label}</button>
                  ))}
                </div>

                {apiSource === "upload" && (
                  <>
                    <label htmlFor="api-file"
                           style={{display: "block", padding: "18px 16px", border: "1.5px dashed var(--line-strong)", borderRadius: 8, textAlign: "center", cursor: "pointer", background: "var(--surface-1)"}}>
                      <Icons.FilePlus size={20} color="var(--text-3)"/>
                      <div style={{fontSize: 13, color: "var(--text-1)", marginTop: 6, fontWeight: 500}}>
                        {apiFile ? apiFile.name : "Drop OpenAPI / Swagger / Postman file"}
                      </div>
                      <div style={{fontSize: 11.5, color: "var(--text-3)", marginTop: 3}}>
                        .json · .yaml · .yml — up to 5 MB
                      </div>
                      <input id="api-file" type="file" accept=".json,.yaml,.yml" style={{display: "none"}}
                             onChange={e => setApiFile(e.target.files[0] || null)}/>
                    </label>
                    {apiFile && (
                      <div style={{marginTop: 8, padding: "8px 12px", background: "var(--brand-soft)", border: "1px solid var(--brand-line)", borderRadius: 6, fontSize: 12, display: "flex", gap: 8, alignItems: "center"}}>
                        <Icons.Check size={12} color="var(--ok)"/>
                        <span className="mono" style={{flex: 1, color: "var(--text-1)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>{apiFile.name}</span>
                        <span style={{color: "var(--text-3)", fontSize: 11}}>{(apiFile.size / 1024).toFixed(1)} KB</span>
                        <button className="btn btn-ghost btn-icon btn-sm" onClick={() => setApiFile(null)}><Icons.X size={11}/></button>
                      </div>
                    )}
                  </>
                )}

                {apiSource === "url" && (
                  <>
                    <input className="form-input mono" placeholder="https://api.example.com/openapi.yaml"
                           value={apiUrl} onChange={e => setApiUrl(e.target.value)}/>
                    <div className="form-help">URL to a JSON or YAML OpenAPI / Swagger spec.</div>
                  </>
                )}

                {apiSource === "none" && (
                  <div className="form-help">No spec — VulnScan will discover endpoints by crawling and fuzzing common paths.</div>
                )}
              </div>

              {/* Authentication */}
              <div>
                <label className="form-label">Authentication</label>
                <select className="form-input">
                  <option>None</option>
                  <option>Bearer token (credential)</option>
                  <option>Basic auth</option>
                  <option>API key (header)</option>
                  <option>OAuth 2.0</option>
                </select>
              </div>

              {/* Security checks (replaces static Test depth) */}
              <div>
                <label className="form-label" style={{display: "flex", justifyContent: "space-between", alignItems: "center"}}>
                  <span>Security checks</span>
                  <span style={{fontSize: 11, color: "var(--text-3)", fontWeight: 400}}>{selectedApiChecks.size}/{apiChecks.length}</span>
                </label>
                <div style={{display: "flex", gap: 6, marginBottom: 8}}>
                  <button type="button" className="btn btn-ghost btn-sm" style={{fontSize: 11}} onClick={() => setSelectedApiChecks(new Set(apiChecks.map(c => c.id)))}>All</button>
                  <button type="button" className="btn btn-ghost btn-sm" style={{fontSize: 11}} onClick={() => setSelectedApiChecks(new Set())}>None</button>
                </div>
                <div style={{display: "flex", flexWrap: "wrap", gap: 5}}>
                  {apiChecks.map(c => {
                    const on = selectedApiChecks.has(c.id);
                    return (
                      <button key={c.id} type="button"
                              className={`btn btn-sm ${on ? "btn-primary" : ""}`}
                              title={c.description}
                              style={{fontSize: 11.5, padding: "3px 9px"}}
                              onClick={() => setSelectedApiChecks(prev => {
                                const next = new Set(prev);
                                next.has(c.id) ? next.delete(c.id) : next.add(c.id);
                                return next;
                              })}>
                        {on && <Icons.Check size={10}/>} {c.name}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          ) : (
            <div>
              <label className="form-label">Target</label>
              <input className="form-input mono"
                     placeholder={
                       scanKind === "network" ? "10.0.0.0/24, 192.168.1.1, host.internal" :
                       scanKind === "web"     ? "https://app.example.com" :
                       scanKind === "iot"     ? "mqtt://broker.local:1883, coap://gateway" :
                       scanKind === "cloud"   ? "aws:account/123456789, azure:sub/<id>" :
                       "example.com or 10.0.0.0/24"
                     }
                     value={target} onChange={e => setTarget(e.target.value)} autoFocus/>
              <div className="form-help">
                {scanKind === "network" && "Hostname, IP, CIDR range, or comma-separated list"}
                {scanKind === "web"     && "Full URL including scheme. Login flow can be configured under Authentication"}
                {scanKind === "iot"     && "Broker URI or gateway address. Supports MQTT, CoAP, AMQP"}
                {scanKind === "cloud"   && "Cloud account identifier — credential needed to enumerate resources"}
              </div>
            </div>
          )}

          {scanKind !== "api" && (
          <div>
            <label className="form-label">Scan profile</label>
            {profiles.length === 0 ? (
              <div className="form-help" style={{color: "var(--err)"}}>
                No scan profiles available — create one in the Profiles menu first.
              </div>
            ) : (
              <select className="form-input" value={profileId || ""} onChange={e => setProfileId(parseInt(e.target.value))}>
                {profiles.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            )}
          </div>
          )}

          {/* ── Web Authentication (only for Web App scan type) ────────── */}
          {scanKind === "web" && (
          <div style={{padding: "12px 14px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 8}}>
            <label className="form-label" style={{display: "flex", alignItems: "center", gap: 6}}>
              <Icons.Lock size={13}/> Authentication
              <span className="tag" style={{marginLeft: 8, fontSize: 10}}>OWASP scanner + injection plugins</span>
            </label>

            <select className="form-input" value={waType} onChange={e => setWaType(e.target.value)}>
              <option value="none">— None (unauthenticated web scan) —</option>
              <option value="form">Form login</option>
              <option value="bearer">Bearer token</option>
              <option value="basic">HTTP Basic auth</option>
              <option value="cookie">Static cookie(s)</option>
              <option value="header">Static header(s)</option>
            </select>

            {waType !== "none" && (
            <div style={{marginTop: 10, display: "flex", flexDirection: "column", gap: 10}}>
              {waType === "form" && (
                <>
                  <div>
                    <label className="form-label">Login URL</label>
                    <div style={{display: "flex", gap: 8}}>
                      <input className="form-input mono" placeholder="https://target.com/login or /login"
                             value={waLoginUrl}
                             onChange={e => { setWaLoginUrl(e.target.value); if (inspectResult) clearInspect(); }}
                             style={{flex: 1}}/>
                      <button type="button" className="btn btn-sm" onClick={runInspect}
                              disabled={inspectLoading || !waLoginUrl.trim()}>
                        {inspectLoading
                          ? <><Icons.Refresh size={12} className="spin"/> Inspecting…</>
                          : <><Icons.Search size={12}/> {inspectResult ? "Re-inspect" : "Inspect"}</>}
                      </button>
                    </div>
                    {inspectError && (
                      <div style={{color: "var(--err)", fontSize: 12, marginTop: 6}}>
                        <Icons.AlertTriangle size={11}/> {inspectError}
                      </div>
                    )}
                    <div className="form-help" style={{marginTop: 4}}>
                      Click <strong>Inspect</strong> to fetch the page and pre-fill field names from the actual login form.
                    </div>
                  </div>

                  {inspectResult && !inspectResult.error && inspectResult.forms?.length > 0 && (
                    <div style={{padding: "10px 12px", background: "var(--surface-2)", border: "1px solid var(--line)", borderRadius: 6}}>
                      <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8}}>
                        <span style={{fontSize: 12.5, fontWeight: 600, color: "var(--text-1)"}}>
                          <Icons.Check size={12} color="var(--ok)"/>{" "}
                          Inspected {inspectResult.forms.length} form{inspectResult.forms.length !== 1 ? "s" : ""}
                          {" "}(HTTP {inspectResult.fetched_status})
                        </span>
                        <button type="button" className="btn btn-ghost btn-sm" onClick={clearInspect}>
                          <Icons.X size={11}/> Clear
                        </button>
                      </div>

                      {inspectResult.forms.length > 1 && (
                        <div style={{marginBottom: 8}}>
                          <div style={{fontSize: 11, color: "var(--text-3)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em"}}>
                            Pick the login form
                          </div>
                          {inspectResult.forms.map((f, i) => {
                            const passes = f.password_candidates?.length || 0;
                            return (
                              <label key={i} style={{display: "flex", alignItems: "center", gap: 8, padding: "4px 6px", cursor: "pointer", borderRadius: 4, background: selectedFormIdx === i ? "var(--brand-soft, var(--surface-1))" : "transparent"}}>
                                <input type="radio" name="newscan-wa-form-pick"
                                       checked={selectedFormIdx === i}
                                       onChange={() => pickForm(i)}/>
                                <span className="mono" style={{fontSize: 11.5, color: "var(--text-1)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>
                                  #{i + 1} {f.method} {f.action}
                                </span>
                                <span style={{fontSize: 10.5, color: "var(--text-3)"}}>
                                  {f.fields.length} input{f.fields.length !== 1 ? "s" : ""}
                                  {passes > 0 && <span style={{color: "var(--ok)", marginLeft: 6}}>· has password</span>}
                                </span>
                              </label>
                            );
                          })}
                        </div>
                      )}

                      {inspectedForm && (
                        <div style={{fontSize: 11.5, color: "var(--text-2)", marginBottom: 4}}>
                          Form action: <span className="mono" style={{color: "var(--text-1)"}}>{inspectedForm.method} {inspectedForm.action}</span>
                          {inspectedForm.csrf_candidates?.length > 0 && (
                            <span style={{marginLeft: 10}}>
                              · CSRF: <span className="mono" style={{color: "var(--ok)"}}>{inspectedForm.csrf_candidates.join(", ")}</span>
                            </span>
                          )}
                        </div>
                      )}

                      {(inspectResult.warnings || []).map((w, i) => (
                        <div key={i} style={{fontSize: 11.5, color: "#e8a03c", marginTop: 4}}>
                          <Icons.AlertTriangle size={11}/> {w}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* ── Step 1: Form field mapping (auto-detected by Inspect) ── */}
                  <div style={{padding: "10px 12px", background: "var(--surface-2)", border: "1px solid var(--line)", borderRadius: 6}}>
                    <div style={{display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, color: "var(--text-0)", marginBottom: 4}}>
                      <Icons.Code size={12}/> 1. Form field mapping
                      {inspectedForm && <span style={{fontSize: 10, color: "var(--ok)", fontWeight: 500, marginLeft: 4}}>· auto-detected</span>}
                    </div>
                    <div style={{fontSize: 11, color: "var(--text-3)", marginBottom: 8, lineHeight: 1.5}}>
                      Which form fields receive the credentials.
                      {!inspectedForm && " Run Inspect above to auto-detect, or type field names manually."}
                    </div>
                    <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10}}>
                      <div>
                        <label className="form-label">Username goes in form field</label>
                        {userFieldOptions.length > 0 ? (
                          <select className="form-input mono" value={waUserField} onChange={e => setWaUserField(e.target.value)}>
                            {!userFieldOptions.includes(waUserField) && <option value={waUserField}>{waUserField} (manual)</option>}
                            {userFieldOptions.map(n => <option key={n} value={n}>{n}</option>)}
                          </select>
                        ) : (
                          <input className="form-input mono" value={waUserField}
                                 onChange={e => setWaUserField(e.target.value)} placeholder="username"/>
                        )}
                      </div>
                      <div>
                        <label className="form-label">Password goes in form field</label>
                        {passFieldOptions.length > 0 ? (
                          <select className="form-input mono" value={waPassField} onChange={e => setWaPassField(e.target.value)}>
                            {!passFieldOptions.includes(waPassField) && <option value={waPassField}>{waPassField} (manual)</option>}
                            {passFieldOptions.map(n => <option key={n} value={n}>{n}</option>)}
                          </select>
                        ) : (
                          <input className="form-input mono" value={waPassField}
                                 onChange={e => setWaPassField(e.target.value)} placeholder="password"/>
                        )}
                      </div>
                    </div>
                    {inspectedForm?.csrf_candidates?.length > 0 && (
                      <div style={{fontSize: 11, color: "var(--text-2)", marginTop: 8, display: "flex", alignItems: "center", gap: 6}}>
                        <Icons.Check size={11} color="var(--ok)"/>
                        <span>CSRF token <span className="mono" style={{color: "var(--text-1)"}}>{inspectedForm.csrf_candidates.join(", ")}</span> auto-harvested at scan time</span>
                      </div>
                    )}
                  </div>

                  {/* ── Step 2: Login credentials (saved or inline, with save-as-credential) ── */}
                  <CredsCard
                    label="2. Login credentials"
                    isBearer={false}
                    webCreds={webCreds}
                    waCredId={waCredId} setWaCredId={setWaCredId}
                    waUsername={waUsername} setWaUsername={setWaUsername}
                    waPassword={waPassword} setWaPassword={setWaPassword}
                    waToken={waToken} setWaToken={setWaToken}
                    waSaveAsCred={waSaveAsCred} setWaSaveAsCred={setWaSaveAsCred}
                    waSaveCredName={waSaveCredName} setWaSaveCredName={setWaSaveCredName}
                    waEphemeral={waEphemeral} setWaEphemeral={setWaEphemeral}
                    userFieldIsEmail={userFieldIsEmail}
                  />

                  {/* ── Step 3: Success / Failure indicators ─────────────── */}
                  <div style={{padding: "10px 12px", background: "var(--surface-2)", border: "1px solid var(--line)", borderRadius: 6}}>
                    <div style={{display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, color: "var(--text-0)", marginBottom: 4}}>
                      <Icons.Check size={12}/> 3. Success / failure detection
                      <span style={{fontSize: 10, color: "var(--text-3)", fontWeight: 400, marginLeft: 4}}>· optional</span>
                    </div>
                    <div style={{fontSize: 11, color: "var(--text-3)", marginBottom: 8, lineHeight: 1.5}}>
                      Text the scanner expects in the response after a good (or bad) login. If blank, the scanner assumes success when at least one cookie is set.
                    </div>
                    <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10}}>
                      <div>
                        <label className="form-label">Success contains</label>
                        <input className="form-input mono" placeholder="e.g. Logout"
                               value={waSuccessIndicator} onChange={e => setWaSuccessInd(e.target.value)}/>
                      </div>
                      <div>
                        <label className="form-label">Failure contains</label>
                        <input className="form-input mono" placeholder="e.g. Invalid credentials"
                               value={waFailureIndicator} onChange={e => setWaFailureInd(e.target.value)}/>
                      </div>
                    </div>
                  </div>
                </>
              )}

              {waType === "basic" && (
                <CredsCard
                  label="Login credentials"
                  isBearer={false}
                  webCreds={webCreds}
                  waCredId={waCredId} setWaCredId={setWaCredId}
                  waUsername={waUsername} setWaUsername={setWaUsername}
                  waPassword={waPassword} setWaPassword={setWaPassword}
                  waToken={waToken} setWaToken={setWaToken}
                  waSaveAsCred={waSaveAsCred} setWaSaveAsCred={setWaSaveAsCred}
                  waSaveCredName={waSaveCredName} setWaSaveCredName={setWaSaveCredName}
                  waEphemeral={waEphemeral} setWaEphemeral={setWaEphemeral}
                  userFieldIsEmail={false}
                />
              )}

              {waType === "bearer" && (
                <CredsCard
                  label="Bearer token"
                  isBearer={true}
                  webCreds={webCreds}
                  waCredId={waCredId} setWaCredId={setWaCredId}
                  waUsername={waUsername} setWaUsername={setWaUsername}
                  waPassword={waPassword} setWaPassword={setWaPassword}
                  waToken={waToken} setWaToken={setWaToken}
                  waSaveAsCred={waSaveAsCred} setWaSaveAsCred={setWaSaveAsCred}
                  waSaveCredName={waSaveCredName} setWaSaveCredName={setWaSaveCredName}
                  waEphemeral={waEphemeral} setWaEphemeral={setWaEphemeral}
                  userFieldIsEmail={false}
                />
              )}

              {waType === "cookie" && (
                <div>
                  <label className="form-label">Cookies (one per line, name=value)</label>
                  <textarea className="form-input mono" rows={4}
                            placeholder={"sessionid=abc123\ncsrftoken=xyz789"}
                            value={waCookiesText} onChange={e => setWaCookiesText(e.target.value)}
                            style={{padding: "8px 12px"}} autoComplete="off"/>
                </div>
              )}

              {waType === "header" && (
                <div>
                  <label className="form-label">Headers (one per line, Name: value)</label>
                  <textarea className="form-input mono" rows={4}
                            placeholder={"X-API-Key: abc123\nX-Tenant: acme"}
                            value={waHeadersText} onChange={e => setWaHeadersText(e.target.value)}
                            style={{padding: "8px 12px"}} autoComplete="off"/>
                </div>
              )}

              {/* ── Test login button ─────────────────────────────────── */}
              {canTestLogin && (
                <div style={{padding: "10px 12px", background: "var(--surface-2)", border: "1px solid var(--line)", borderRadius: 6}}>
                  <div style={{display: "flex", alignItems: "center", gap: 8}}>
                    <button type="button" className="btn btn-sm" onClick={runTestLogin} disabled={testLoading}>
                      {testLoading
                        ? <><Icons.Refresh size={12} className="spin"/> Testing login…</>
                        : <><Icons.Play size={12}/> Test login now</>}
                    </button>
                    <span style={{fontSize: 11, color: "var(--text-3)"}}>
                      One-shot pre-flight check before launching the full scan.
                    </span>
                  </div>
                  {testResult && (
                    <div style={{
                      marginTop: 10, padding: "8px 12px", borderRadius: 6, fontSize: 12.5,
                      background: testResult.success ? "rgba(95,184,122,0.10)" : "var(--sev-critical-bg)",
                      border: `1px solid ${testResult.success ? "var(--sev-low-line, var(--ok))" : "var(--sev-critical-line, var(--err))"}`,
                      color: testResult.success ? "var(--ok)" : "var(--err)",
                    }}>
                      <div style={{display: "flex", alignItems: "center", gap: 6, fontWeight: 600}}>
                        {testResult.success
                          ? <><Icons.Check size={12}/> Login succeeded</>
                          : <><Icons.AlertTriangle size={12}/> Login failed</>}
                      </div>
                      {testResult.success && (
                        <div style={{fontSize: 11.5, color: "var(--text-2)", marginTop: 4, fontFamily: "var(--font-mono)"}}>
                          {testResult.cookies_count} cookie(s){testResult.cookie_names?.length > 0 && ` (${testResult.cookie_names.join(", ")})`} · {testResult.headers_count} header(s)
                          {testResult.evidence && <div style={{marginTop: 4, color: "var(--text-3)"}}>{testResult.evidence}</div>}
                        </div>
                      )}
                      {!testResult.success && testResult.error && (
                        <div style={{fontSize: 11.5, color: "var(--text-2)", marginTop: 4}}>
                          {testResult.error}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              <div className="form-help" style={{color: "var(--text-3)"}}>
                Per-scan auth applies to <strong>Run now</strong> only. The <span className="mono">web.auth</span>{" "}
                plugin is enabled automatically when a scan launches with auth set.
              </div>
            </div>
            )}
          </div>
          )}

          <div style={{padding: "14px 16px", background: "var(--brand-soft)", border: "1px solid var(--brand-line)", borderRadius: 8}}>
            <label className="form-label" style={{display: "flex", alignItems: "center", gap: 6, color: "var(--brand-text)"}}>
              <Icons.Folder size={13}/> Add to asset folder (optional)
            </label>
            {!createNew ? (
              <>
                <select className="form-input" value={assetId || ""} onChange={e => setAssetId(e.target.value ? parseInt(e.target.value) : null)} style={{marginTop: 4}}>
                  <option value="">— No folder —</option>
                  {assets.length > 0 && (
                    <optgroup label="Existing folders">
                      {assets.map(a => <option key={a.id} value={a.id}>{a.name} ({a.targets || 0} targets)</option>)}
                    </optgroup>
                  )}
                </select>
                <button type="button" className="btn btn-ghost btn-sm" style={{marginTop: 8, padding: 0, color: "var(--brand-text)"}} onClick={() => setCreateNew(true)}>
                  <Icons.Plus size={12}/> Create new folder instead
                </button>
              </>
            ) : (
              <>
                <input className="form-input" placeholder="e.g. Production · Mobile API" value={newAssetName} onChange={e => setNewAssetName(e.target.value)} style={{marginTop: 4}}/>
                <div style={{display: "flex", gap: 8, marginTop: 8, alignItems: "center"}}>
                  <select className="form-input" style={{flex: 1, fontSize: 12.5}} value={newAssetParent || ""} onChange={e => setNewAssetParent(e.target.value ? parseInt(e.target.value) : null)}>
                    <option value="">No parent (top-level)</option>
                    {assets.filter(a => !a.parent_id).map(a => <option key={a.id} value={a.id}>Inside: {a.name}</option>)}
                  </select>
                  <button type="button" className="btn btn-ghost btn-sm" onClick={() => setCreateNew(false)}>Cancel</button>
                </div>
              </>
            )}
            <div className="form-help" style={{marginTop: 8, color: "var(--text-2)"}}>Tagging a scan to a folder lets it appear in the folder's scan history and rollups.</div>
          </div>

          <div>
            <label className="form-label">Schedule</label>
            <div style={{display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginBottom: 10}}>
              {[
                { id: "now",     label: "Run now",      desc: "Dispatch immediately" },
                { id: "once",    label: "Run once at…", desc: "Specific date & time" },
                { id: "hourly",  label: "Hourly",       desc: "Every hour" },
                { id: "daily",   label: "Daily",        desc: "Every 24 hours" },
                { id: "weekly",  label: "Weekly",       desc: "Every 7 days" },
                { id: "monthly", label: "Monthly",      desc: "Every 30 days" },
              ].map(o => {
                const active = scheduleMode === o.id;
                return (
                  <button key={o.id} type="button" onClick={() => setScheduleMode(o.id)}
                          className={`btn ${active ? "btn-primary" : "btn-ghost"}`}
                          style={{flexDirection: "column", alignItems: "flex-start", height: "auto", padding: "10px 12px", gap: 2, textAlign: "left"}}>
                    <div style={{fontSize: 13, fontWeight: 600}}>{o.label}</div>
                    <div style={{fontSize: 11, opacity: active ? 0.85 : 0.6, fontWeight: 400}}>{o.desc}</div>
                  </button>
                );
              })}
            </div>

            {scheduleMode === "once" && (
              <div style={{padding: "10px 12px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 6, marginBottom: 8}}>
                <label className="form-label">Run at (your local time zone)</label>
                <input className="form-input mono" type="datetime-local"
                       value={scheduleConfig.custom_datetime}
                       onChange={e => setScheduleConfig(c => ({...c, custom_datetime: e.target.value}))}/>
              </div>
            )}

            <div className="form-help">
              {scheduleMode === "now"
                ? "Scan will be queued immediately — pick \"+ New scan\"'s default."
                : scheduleMode === "once"
                  ? "One-time future run. After it completes, the schedule auto-disables."
                  : `Recurring scan. The platform's scheduler dispatches a new job ${scheduleMode === "hourly" ? "every hour" : scheduleMode === "daily" ? "every 24 hours" : scheduleMode === "weekly" ? "every 7 days" : "every 30 days"}. Manage from the Scan Jobs → Schedule button.`}
            </div>
          </div>
        </div>
        {error && (
          <div style={{padding: "10px 24px", borderTop: "1px solid var(--line)", color: "var(--err)", fontSize: 12.5, display: "flex", alignItems: "center", gap: 8, background: "var(--sev-critical-bg)"}}>
            <Icons.AlertTriangle size={13}/> {error}
          </div>
        )}
        <div style={{padding: "14px 24px", borderTop: "1px solid var(--line)", display: "flex", gap: 8, justifyContent: "flex-end", background: "var(--surface-1)"}}>
          <button className="btn" onClick={close} disabled={submitting}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={submitting || (scanKind !== "api" && profiles.length === 0)}>
            {submitting
              ? <><Icons.Refresh size={12} className="spin"/> {scanKind === "api" ? "Launching…" : scheduleMode === "now" ? "Creating…" : "Scheduling…"}</>
              : scanKind === "api"
                ? <><Icons.Play size={12}/> Launch API scan</>
                : scheduleMode === "now"
                  ? <><Icons.Play size={12}/> Run scan</>
                  : <><Icons.Clock size={12}/> Create schedule</>}
          </button>
        </div>
      </div>
    </>
  );
}

// ─── CredsCard ───────────────────────────────────────────────────────────────
// Used by the New Scan dialog's Web Auth panel. Bundles:
//   • saved-credential picker with smart suggestions (email-shape match)
//   • inline username/password (or token) inputs as fallback
//   • "Save as credential" toggle with optional auto-delete-after-scan
//   • empty-state CTA when no credentials exist
function CredsCard({
  label, isBearer, webCreds,
  waCredId, setWaCredId,
  waUsername, setWaUsername, waPassword, setWaPassword, waToken, setWaToken,
  waSaveAsCred, setWaSaveAsCred,
  waSaveCredName, setWaSaveCredName,
  waEphemeral, setWaEphemeral,
  userFieldIsEmail,
}) {
  const hasInlineValues = isBearer ? !!waToken.trim() : (!!waUsername || !!waPassword);

  return (
    <div style={{padding: "10px 12px", background: "var(--surface-2)", border: "1px solid var(--line)", borderRadius: 6}}>
      <div style={{display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, color: "var(--text-0)", marginBottom: 4}}>
        <Icons.Key size={12}/> {label}
      </div>

      {/* Saved credential picker (or empty-state CTA) */}
      {webCreds.length > 0 ? (
        <>
          <label className="form-label" style={{marginTop: 6}}>Saved credential</label>
          <select className="form-input" value={waCredId} onChange={e => setWaCredId(e.target.value)}>
            <option value="">— Type credentials below instead —</option>
            {webCreds.map(c => (
              <option key={c.id} value={c.id}>
                #{c.id} {c.name} ({c.kind} · {c.username || "—"})
                {c._matchesEmail ? "  ✓ matches email field" : ""}
              </option>
            ))}
          </select>
          {userFieldIsEmail && webCreds.some(c => c._matchesEmail) && (
            <div className="form-help" style={{marginTop: 4, color: "var(--ok)"}}>
              Login form expects an email — credentials with @ in the username are highlighted above.
            </div>
          )}
        </>
      ) : (
        <div style={{padding: "8px 10px", background: "var(--surface-1)", border: "1px dashed var(--line)", borderRadius: 4, fontSize: 11.5, color: "var(--text-3)", marginTop: 6, marginBottom: 8}}>
          No saved credentials yet. You can <strong>type credentials below</strong> and optionally save them, or
          {" "}<a href="#" onClick={(e) => { e.preventDefault(); window.location.hash = "credentials"; }}
                  style={{color: "var(--brand)", textDecoration: "none"}}>add a credential in Configuration → Credentials</a>.
        </div>
      )}

      {/* Inline credential inputs — only when no saved cred is picked */}
      {!waCredId && (
        <>
          {webCreds.length > 0 && (
            <div style={{margin: "10px 0 6px", display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "var(--text-3)"}}>
              <span style={{flex: 1, height: 1, background: "var(--line)"}}/>
              <span>or type credentials below</span>
              <span style={{flex: 1, height: 1, background: "var(--line)"}}/>
            </div>
          )}

          {isBearer ? (
            <div>
              <label className="form-label">Token</label>
              <textarea className="form-input mono" rows={3}
                        placeholder="eyJhbGciOiJSUzI1NiIs…"
                        value={waToken} onChange={e => setWaToken(e.target.value)}
                        style={{padding: "8px 12px"}} autoComplete="off"/>
              <div className="form-help" style={{marginTop: 4}}>
                Sent as <span className="mono">Authorization: Bearer …</span> on every scanner request.
              </div>
            </div>
          ) : (
            <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10}}>
              <div>
                <label className="form-label">Username or email</label>
                <input className="form-input mono" value={waUsername}
                       placeholder="alice@company.com"
                       onChange={e => setWaUsername(e.target.value)} autoComplete="off"/>
              </div>
              <div>
                <label className="form-label">Password</label>
                <input className="form-input" type="password" value={waPassword}
                       placeholder="••••••••"
                       onChange={e => setWaPassword(e.target.value)} autoComplete="off"/>
              </div>
            </div>
          )}

          {/* Save-as-credential — only meaningful when typing inline */}
          {hasInlineValues && (
            <div style={{marginTop: 10, padding: "8px 10px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 4}}>
              <label style={{display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-1)", cursor: "pointer"}}>
                <input type="checkbox" checked={waSaveAsCred}
                       onChange={e => { setWaSaveAsCred(e.target.checked); if (!e.target.checked) setWaEphemeral(false); }}/>
                <Icons.Plus size={11}/> Save as credential for next time
              </label>
              {waSaveAsCred && (
                <div style={{marginLeft: 22, marginTop: 8, display: "flex", flexDirection: "column", gap: 8}}>
                  <input className="form-input mono"
                         placeholder="Credential name (e.g., webapp-tester)"
                         value={waSaveCredName} onChange={e => setWaSaveCredName(e.target.value)}/>
                  <label style={{display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-1)", cursor: "pointer"}}>
                    <input type="checkbox" checked={waEphemeral}
                           onChange={e => setWaEphemeral(e.target.checked)}/>
                    <span>Auto-delete this credential when the scan completes</span>
                  </label>
                  {waEphemeral && (
                    <div style={{fontSize: 11, color: "#e8a03c", lineHeight: 1.5, marginLeft: 22}}>
                      One-time use: the credential is created now, used for this scan, and deleted when the scan finishes (any status).
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export function Reports() {
  const [q, setQ] = useState("");
  const [showGen, setShowGen] = useState(null);
  const [showTemplates, setShowTemplates] = useState(false);
  const [reports, setReports] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [downloadingId, setDownloadingId] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [r, t] = await Promise.all([
        reportsApi.list(),
        reportsApi.listTemplates().catch(() => []),
      ]);
      setReports(r);
      setTemplates(t);
      setError("");
    } catch (e) { setError(e.message); }
    finally     { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const filtered = reports.filter(r => !q || r.target.toLowerCase().includes(q.toLowerCase()) || r.id.toLowerCase().includes(q.toLowerCase()));

  const download = async (jobId, fmt, templateId = null) => {
    setDownloadingId(`${jobId}-${fmt}`);
    try { await reportsApi.download(jobId, fmt, templateId); }
    catch (e) { alert(e.message); }
    finally { setDownloadingId(null); }
  };

  return (
    <>
      <div className="ph">
        <div>
          <h1>Reports</h1>
          <div className="sub">Generated from completed scans. Download as PDF / DOCX for stakeholders, XLSX for triage, JSON / SARIF for tooling pipelines.</div>
        </div>
        <div className="actions">
          <button className="btn" onClick={() => setShowTemplates(true)}>
            <Icons.FileText size={14}/> Templates <span className="tag" style={{marginLeft: 4}}>{templates.length}</span>
          </button>
        </div>
      </div>

      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}

      <div className="card">
        <div className="toolbar">
          <div className="left"><div className="tabs"><button className="tab active">All <span className="badge">{reports.length}</span></button></div></div>
          <div className="right">
            <div className="field"><Icons.Search size={14} className="icon"/><input placeholder="Search target or report id…" value={q} onChange={e => setQ(e.target.value)}/></div>
          </div>
        </div>
        <div className="card-body flush">
          {loading && reports.length === 0 ? (
            <div style={{padding: 60, textAlign: "center", color: "var(--text-3)"}}>Loading reports…</div>
          ) : reports.length === 0 ? (
            <div style={{padding: 60, textAlign: "center", color: "var(--text-3)"}}>
              No reports yet. Reports become available after a scan completes successfully.
            </div>
          ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th style={{width: 110}}>Report</th>
                <th>Target</th>
                <th>Asset</th>
                <th style={{width: 80}}>Findings</th>
                <th style={{width: 130}}>Generated</th>
                <th style={{width: 380}}>Download</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(r => (
                <tr key={r.id}>
                  <td><span className="mono" style={{color: "var(--brand-text)"}}>{r.id}</span></td>
                  <td><span className="mono" style={{fontSize: 12.5}}>{r.target}</span></td>
                  <td>{r.asset_name ? <span className="tag"><Icons.Folder size={11}/> {r.asset_name}</span> : <span className="muted">—</span>}</td>
                  <td className="num">{r.findings}</td>
                  <td className="muted" style={{fontSize: 12}}>{r.generated_at ? new Date(r.generated_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"}) : "—"}</td>
                  <td>
                    <div style={{display: "flex", gap: 3, flexWrap: "wrap"}}>
                      <button className="btn btn-sm btn-primary"
                              disabled={downloadingId === `${r.job_id}-pdf`}
                              onClick={() => download(r.job_id, "pdf")}>
                        {downloadingId === `${r.job_id}-pdf` ? <Icons.Refresh size={11} className="spin"/> : <Icons.Download size={11}/>}
                        PDF
                      </button>
                      {["docx", "xlsx", "csv", "json", "sarif", "md"].map(fmt => (
                        <button key={fmt} className="btn btn-ghost btn-sm"
                                disabled={downloadingId === `${r.job_id}-${fmt}`}
                                onClick={() => download(r.job_id, fmt)}
                                title={`Download ${fmt.toUpperCase()}`}>
                          {downloadingId === `${r.job_id}-${fmt}` ? <Icons.Refresh size={11} className="spin"/> : null}
                          {fmt.toUpperCase()}
                        </button>
                      ))}
                      <button className="btn btn-ghost btn-icon btn-sm" onClick={() => setShowGen(r)} title="Pick template + format"><Icons.More size={14}/></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          )}
        </div>
      </div>

      {showGen && <ReportPreviewModal report={showGen} templates={templates} close={() => setShowGen(null)} onDownload={download}/>}
      {showTemplates && <TemplatesModal close={() => setShowTemplates(false)} onChanged={refresh}/>}
    </>
  );
}


export function ReportPreviewModal({ report, templates: tplProp, close, onDownload }) {
  const [format, setFormat] = useState("pdf");
  const [templates, setTemplates] = useState(tplProp || []);
  const [templateId, setTemplateId] = useState(null);
  const [busy, setBusy] = useState(false);
  const jobId = report.job_id || report.id?.replace(/^R-/, "");

  useEffect(() => {
    if (tplProp && tplProp.length > 0) return;
    reportsApi.listTemplates().then(setTemplates).catch(() => {});
  }, [tplProp]);

  // Default to the first built-in template ("Executive + Technical")
  useEffect(() => {
    if (templateId == null && templates.length > 0) {
      setTemplateId(templates[0].id);
    }
  }, [templates, templateId]);

  const doDownload = async () => {
    setBusy(true);
    try {
      if (onDownload) {
        await onDownload(jobId, format, templateId);
      } else {
        await reportsApi.download(jobId, format, templateId);
      }
      close();
    } catch (e) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 580}}>
        <div className="drawer-head">
          <Icons.FileText size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Download report — {report.id}</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "20px 24px"}}>
          <dl className="dl" style={{marginBottom: 18}}>
            <dt>Target</dt><dd className="mono">{report.target}</dd>
            {report.asset_name && <><dt>Asset</dt><dd>{report.asset_name}</dd></>}
            <dt>Findings</dt><dd>{report.findings}</dd>
          </dl>

          <div className="eyebrow">Template</div>
          {templates.length === 0 ? (
            <div className="form-help" style={{marginBottom: 16}}>No templates available yet — using default.</div>
          ) : (
            <select className="form-input" value={templateId || ""} onChange={e => setTemplateId(e.target.value ? parseInt(e.target.value) : null)} style={{marginBottom: 16}}>
              {templates.map(t => (
                <option key={t.id} value={t.id}>
                  {t.name}{t.builtin ? " · built-in" : ""} — {t.sections.length} section{t.sections.length === 1 ? "" : "s"}, {t.severities.length}/5 severities
                </option>
              ))}
            </select>
          )}

          <div className="eyebrow">Format</div>
          <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8}}>
            {[
              { id: "pdf",   name: "PDF",      desc: "Branded report for stakeholders" },
              { id: "docx",  name: "DOCX",     desc: "Editable Word document" },
              { id: "xlsx",  name: "XLSX",     desc: "Excel — sheet per severity" },
              { id: "csv",   name: "CSV",      desc: "Findings table" },
              { id: "json",  name: "JSON",     desc: "Machine-readable export" },
              { id: "sarif", name: "SARIF",    desc: "SIEM / GitHub code scanning" },
              { id: "md",    name: "Markdown", desc: "Human-readable" },
            ].map(f => (
              <button key={f.id} onClick={() => setFormat(f.id)}
                      className={`btn ${format === f.id ? "btn-primary" : ""}`}
                      style={{flexDirection: "column", alignItems: "flex-start", height: "auto", padding: "10px 14px", gap: 2, textAlign: "left"}}>
                <div style={{fontSize: 13, fontWeight: 600}}>{f.name}</div>
                <div style={{fontSize: 11, opacity: format === f.id ? 0.85 : 0.6, fontWeight: 400}}>{f.desc}</div>
              </button>
            ))}
          </div>
        </div>
        <div style={{padding: "14px 24px", borderTop: "1px solid var(--line)", display: "flex", gap: 8, justifyContent: "flex-end", background: "var(--surface-1)"}}>
          <button className="btn" onClick={close} disabled={busy}>Cancel</button>
          <button className="btn btn-primary" onClick={doDownload} disabled={busy}>
            {busy ? <><Icons.Refresh size={12} className="spin"/> Downloading…</> : <><Icons.Download size={12}/> Download {format.toUpperCase()}</>}
          </button>
        </div>
      </div>
    </>
  );
}

// ── Template manager ──────────────────────────────────────────────────────
function TemplatesModal({ close, onChanged }) {
  const [templates, setTemplates] = useState([]);
  const [sections, setSections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState(null); // null | "new" | template object

  const refresh = useCallback(async () => {
    try {
      const [t, s] = await Promise.all([
        reportsApi.listTemplates(),
        reportsApi.listSections().catch(() => []),
      ]);
      setTemplates(t);
      setSections(s);
      setError("");
    } catch (e) { setError(e.message); }
    finally     { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const onClone = async (id) => {
    try { await reportsApi.cloneTemplate(id); refresh(); onChanged && onChanged(); }
    catch (e) { alert(e.message); }
  };
  const onDelete = async (t) => {
    if (!confirm(`Delete template "${t.name}"?`)) return;
    try { await reportsApi.deleteTemplate(t.id); refresh(); onChanged && onChanged(); }
    catch (e) { alert(e.message); }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 720, maxHeight: "85vh"}}>
        <div className="drawer-head">
          <Icons.FileText size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Report templates</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "20px 24px", overflowY: "auto", flex: 1}}>
          <div style={{fontSize: 12.5, color: "var(--text-2)", lineHeight: 1.55, marginBottom: 16}}>
            Templates control which sections appear in a generated report (executive summary, severity overview, evidence, remediation, compliance) and which severities are included. Built-in templates can't be edited — clone them to customize.
          </div>

          {error && <div style={{color: "var(--err)", fontSize: 13, marginBottom: 12}}><Icons.AlertTriangle size={13}/> {error}</div>}

          <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12}}>
            <div className="eyebrow" style={{margin: 0}}>{templates.length} template{templates.length === 1 ? "" : "s"}</div>
            <button className="btn btn-primary btn-sm" onClick={() => setEditing("new")}>
              <Icons.Plus size={11}/> New template
            </button>
          </div>

          {loading && templates.length === 0 ? (
            <div style={{padding: 30, textAlign: "center", color: "var(--text-3)"}}>Loading…</div>
          ) : (
            <div style={{display: "flex", flexDirection: "column", gap: 8}}>
              {templates.map(t => (
                <div key={t.id} style={{padding: "12px 14px", border: "1px solid var(--line)", borderRadius: 8, background: "var(--surface-1)", display: "flex", alignItems: "center", gap: 14}}>
                  <div style={{width: 32, height: 32, borderRadius: 6, background: "var(--brand-soft)", color: "var(--brand)", display: "grid", placeItems: "center"}}>
                    <Icons.FileText size={14}/>
                  </div>
                  <div style={{flex: 1, minWidth: 0}}>
                    <div style={{display: "flex", alignItems: "center", gap: 8}}>
                      <span style={{fontSize: 13.5, color: "var(--text-0)", fontWeight: 500}}>{t.name}</span>
                      {t.builtin && <span className="tag" style={{fontSize: 10}}>BUILT-IN</span>}
                    </div>
                    <div style={{fontSize: 12, color: "var(--text-3)", marginTop: 2}}>{t.description || "—"}</div>
                    <div style={{fontSize: 11, color: "var(--text-3)", marginTop: 4, fontFamily: "var(--font-mono)"}}>
                      {t.sections.length} section{t.sections.length === 1 ? "" : "s"} · severities: {t.severities.join(", ")}
                    </div>
                  </div>
                  <div style={{display: "flex", gap: 4}}>
                    <button className="btn btn-ghost btn-sm" title="Clone" onClick={() => onClone(t.id)}><Icons.Copy size={12}/></button>
                    {!t.builtin && (
                      <>
                        <button className="btn btn-ghost btn-sm" title="Edit" onClick={() => setEditing(t)}><Icons.Edit size={12}/></button>
                        <button className="btn btn-ghost btn-sm" title="Delete" style={{color: "var(--err)"}} onClick={() => onDelete(t)}><Icons.Trash size={12}/></button>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {editing && <TemplateEditModal
        sections={sections}
        editing={editing === "new" ? null : editing}
        close={() => setEditing(null)}
        onSaved={() => { setEditing(null); refresh(); onChanged && onChanged(); }}
      />}
    </>
  );
}

function TemplateEditModal({ sections, editing, close, onSaved }) {
  const isEdit = !!editing;
  const [name, setName] = useState(editing?.name || "");
  const [description, setDescription] = useState(editing?.description || "");
  const [selectedSections, setSelectedSections] = useState(() =>
    new Set(editing?.sections || ["summary", "severity", "findings", "remediation"]));
  const [selectedSevs, setSelectedSevs] = useState(() =>
    new Set(editing?.severities || ["critical", "high", "medium", "low", "info"]));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const toggleSection = (id) => {
    const n = new Set(selectedSections);
    n.has(id) ? n.delete(id) : n.add(id);
    setSelectedSections(n);
  };
  const toggleSev = (id) => {
    const n = new Set(selectedSevs);
    n.has(id) ? n.delete(id) : n.add(id);
    setSelectedSevs(n);
  };

  const submit = async () => {
    if (!name.trim()) { setError("Name is required"); return; }
    if (selectedSections.size === 0) { setError("Pick at least one section"); return; }
    setSubmitting(true);
    setError("");
    try {
      const body = {
        name: name.trim(),
        description: description.trim(),
        sections: Array.from(selectedSections),
        severities: Array.from(selectedSevs),
      };
      if (isEdit) await reportsApi.updateTemplate(editing.id, body);
      else        await reportsApi.createTemplate(body);
      onSaved();
    } catch (e) {
      setError(e.message);
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 540, maxHeight: "85vh", display: "flex", flexDirection: "column", zIndex: 1000}}>
        <div className="drawer-head">
          <Icons.FileText size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>
            {isEdit ? `Edit ${editing.name}` : "New report template"}
          </span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "20px 24px", overflowY: "auto", flex: 1, display: "flex", flexDirection: "column", gap: 14}}>
          <div>
            <label className="form-label">Name</label>
            <input className="form-input" value={name} onChange={e => setName(e.target.value)} autoFocus
                   placeholder="e.g. PCI Quarterly Audit"/>
          </div>
          <div>
            <label className="form-label">Description (optional)</label>
            <textarea className="form-input" rows={2} value={description}
                      onChange={e => setDescription(e.target.value)}
                      placeholder="Who is this for? When should you use it?"
                      style={{height: "auto", padding: "8px 12px"}}/>
          </div>

          <div>
            <label className="form-label">Sections to include ({selectedSections.size} selected)</label>
            <div style={{display: "flex", flexDirection: "column", gap: 6}}>
              {sections.map(s => (
                <label key={s.id} style={{display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", borderRadius: 6, cursor: "pointer", background: selectedSections.has(s.id) ? "var(--brand-soft)" : "var(--surface-1)", border: "1px solid var(--line)"}}>
                  <input type="checkbox" checked={selectedSections.has(s.id)} onChange={() => toggleSection(s.id)} style={{accentColor: "var(--brand)"}}/>
                  <div style={{flex: 1}}>
                    <div style={{fontSize: 13, color: "var(--text-1)"}}>{s.name}</div>
                    <div style={{fontSize: 11, color: "var(--text-3)", fontFamily: "var(--font-mono)"}}>{s.id}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="form-label">Severity filter ({selectedSevs.size} of 5 included)</label>
            <div style={{display: "flex", gap: 6, flexWrap: "wrap"}}>
              {["critical", "high", "medium", "low", "info"].map(s => {
                const on = selectedSevs.has(s);
                return (
                  <button key={s} type="button" onClick={() => toggleSev(s)}
                          className={`btn btn-sm ${on ? "btn-primary" : "btn-ghost"}`}
                          style={{textTransform: "capitalize"}}>
                    {on && <Icons.Check size={11}/>} {s}
                  </button>
                );
              })}
            </div>
            <div className="form-help">Findings outside the selected severities are omitted from this template's reports.</div>
          </div>
        </div>
        {error && <div style={{padding: "10px 24px", color: "var(--err)", fontSize: 12.5, background: "var(--sev-critical-bg)", borderTop: "1px solid var(--line)"}}><Icons.AlertTriangle size={12}/> {error}</div>}
        <div style={{padding: "14px 24px", borderTop: "1px solid var(--line)", display: "flex", gap: 8, justifyContent: "flex-end", background: "var(--surface-1)"}}>
          <button className="btn" onClick={close} disabled={submitting}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={submitting}>
            {submitting ? <><Icons.Refresh size={12} className="spin"/> Saving…</> : <><Icons.Check size={12}/> {isEdit ? "Save changes" : "Create template"}</>}
          </button>
        </div>
      </div>
    </>
  );
}

