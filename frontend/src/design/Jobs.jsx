import React, { useState, useMemo, useEffect, useCallback } from "react";
import { Icons, Status, Empty } from "./icons.jsx";
import { scanApi, canEdit } from "../api.js";
import { NewScanModal } from "./Assets.jsx";

function durationOf(j) {
  if (!j.created_at) return "—";
  const start = new Date(j.created_at);
  const end = j.finished_at ? new Date(j.finished_at) : new Date();
  const ms = end - start;
  if (ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const ss = s % 60;
  return m > 0 ? `${m}m ${String(ss).padStart(2,"0")}s` : `${ss}s`;
}

export function parseProgress(metaJson) {
  if (!metaJson) return null;
  try {
    const p = (typeof metaJson === "string" ? JSON.parse(metaJson) : metaJson).progress;
    if (!p) return null;
    return p;
  } catch { return null; }
}

export function Jobs({ openJob }) {
  const [tab, setTab] = useState("all");
  const [q, setQ] = useState("");
  const [cancelTarget, setCancelTarget] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [showNewScan, setShowNewScan] = useState(false);
  const [showSchedules, setShowSchedules] = useState(false);
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const list = await scanApi.listJobs();
      setJobs(list);
      setError("");
    } catch (e) {
      setError(e.message || "Failed to load jobs");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Auto-refresh every 2s if any job is running/queued; do one final refresh
  // shortly after the last active job completes so the UI catches the transition.
  useEffect(() => {
    const hasActive = jobs.some(j => j.status === "running" || j.status === "queued");
    if (!hasActive) {
      const t = setTimeout(refresh, 1500); // catch-up refresh after activity ends
      return () => clearTimeout(t);
    }
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [jobs, refresh]);

  const filtered = useMemo(() => {
    return jobs.filter(j => {
      if (tab !== "all" && j.status !== tab) return false;
      if (q && !j.target.toLowerCase().includes(q.toLowerCase()) && !String(j.id).includes(q)) return false;
      return true;
    });
  }, [jobs, tab, q]);

  const counts = {
    all: jobs.length,
    running: jobs.filter(j => j.status === "running").length,
    done: jobs.filter(j => j.status === "done").length,
    failed: jobs.filter(j => j.status === "failed").length,
    queued: jobs.filter(j => j.status === "queued").length,
  };

  return (
    <>
      <div className="ph">
        <div>
          <h1>Scan jobs</h1>
          <div className="sub">All vulnerability scans across your environments. Click any job to inspect findings.</div>
        </div>
        <div className="actions">
          {canEdit() && <button className="btn" onClick={() => setShowSchedules(true)}><Icons.Clock size={14}/> Schedule</button>}
          {canEdit() && <button className="btn btn-primary" onClick={() => setShowNewScan(true)}><Icons.Plus size={14}/> New scan</button>}
        </div>
      </div>

      <div className="card">
        <div className="toolbar">
          <div className="left">
            <div className="tabs">
              {[
                ["all", "All"],
                ["running", "Running"],
                ["done", "Done"],
                ["failed", "Failed"],
                ["queued", "Queued"],
              ].map(([k, l]) => (
                <button key={k} className={`tab ${tab === k ? "active" : ""}`} onClick={() => setTab(k)}>
                  {l} <span className="badge">{counts[k]}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="right">
            <div className="field">
              <Icons.Search size={14} className="icon"/>
              <input placeholder="Search target or job id…" value={q} onChange={e => setQ(e.target.value)}/>
            </div>
            <button className="btn btn-ghost btn-sm"><Icons.Filter size={14}/> Filter</button>
          </div>
        </div>
        <div className="card-body flush">
          {error && (
            <div style={{padding: "12px 18px", color: "var(--err)", fontSize: 13}}>
              <Icons.AlertTriangle size={13}/> {error}
            </div>
          )}
          {loading && jobs.length === 0 ? (
            <div style={{padding: "60px 18px", textAlign: "center", color: "var(--text-3)"}}>Loading scans…</div>
          ) : filtered.length === 0 ? (
            <Empty icon={Icons.Search} title="No scans match" body={jobs.length === 0 ? "No scans yet. Click \"New scan\" to start." : "Try clearing your filters or broadening the search."}/>
          ) : (
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{width: 80}}>Job</th>
                  <th>Target</th>
                  <th style={{width: 100}}>Profile</th>
                  <th style={{width: 130}}>Status</th>
                  <th style={{width: 90}}>Duration</th>
                  <th style={{width: 100}}>Started by</th>
                  <th style={{width: 140}}>Started</th>
                  <th style={{width: 80}}/>
                </tr>
              </thead>
              <tbody>
                {filtered.map(j => (
                  <tr key={j.id} className="clickable" onClick={() => openJob(j)}>
                    <td><span className="mono" style={{color: "var(--brand-text)"}}>#{j.id}</span></td>
                    <td>
                      <div style={{display: "flex", alignItems: "center", gap: 8}}>
                        {j.scan_type === "external" ? <Icons.Globe size={14} color="var(--text-3)"/> : <Icons.Server size={14} color="var(--text-3)"/>}
                        <span className="mono">{j.target}</span>
                      </div>
                    </td>
                    <td><span style={{color: "var(--text-2)", fontSize: 12.5}} className="mono">#{j.profile_id ?? "—"}</span></td>
                    <td>
                      {j.status === "running" ? (() => {
                        const p = parseProgress(j.meta_json);
                        return (
                          <div>
                            <Status s="running"/>
                            <div style={{display: "flex", alignItems: "center", gap: 6, marginTop: 6}}>
                              <div style={{flex: 1, height: 3, background: "var(--surface-2)", borderRadius: 2, overflow: "hidden", maxWidth: 100}}>
                                <div style={{width: `${p?.pct || 0}%`, height: "100%", background: "var(--brand)", transition: "width 0.4s"}}/>
                              </div>
                              <span className="mono muted" style={{fontSize: 11}}>{p?.pct || 0}%</span>
                            </div>
                            {p?.current_name && (
                              <div className="mono" style={{fontSize: 10.5, color: "var(--text-3)", marginTop: 3, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}} title={p.current_plugin}>
                                {p.step}/{p.total} · {p.current_name}
                              </div>
                            )}
                          </div>
                        );
                      })() : j.status === "failed" && j.error_info ? (
                        <div>
                          <Status s="failed"/>
                          <div style={{fontSize: 11, color: "var(--text-3)", marginTop: 2, fontStyle: "italic", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}} title={j.error_info.error}>
                            {j.error_info.error}
                          </div>
                        </div>
                      ) : <Status s={j.status}/>}
                    </td>
                    <td className="num muted">{durationOf(j)}</td>
                    <td className="muted" style={{fontSize: 12}}>{j.created_by || "—"}</td>
                    <td className="muted" style={{fontSize: 12}}>
                      {j.created_at ? new Date(j.created_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"}) : "—"}
                    </td>
                    <td>
                      {canEdit() && (j.status === "running" || j.status === "queued") ? (
                        <button className="btn btn-icon btn-sm" title="Cancel scan"
                                onClick={e => { e.stopPropagation(); setCancelTarget(j); }}
                                style={{color: "var(--err)", borderColor: "var(--line)"}}>
                          <Icons.Stop size={12}/>
                        </button>
                      ) : canEdit() ? (
                        <div style={{display: "flex", gap: 4}}>
                          <button className="btn btn-icon btn-ghost btn-sm" title="Re-scan"
                                  onClick={async e => {
                                    e.stopPropagation();
                                    try { await scanApi.rescanJob(j.id); refresh(); } catch (err) { alert(err.message); }
                                  }}
                                  style={{color: "var(--text-3)"}}>
                            <Icons.Refresh size={12}/>
                          </button>
                          <button className="btn btn-icon btn-ghost btn-sm" title="Delete scan"
                                  onClick={e => { e.stopPropagation(); setDeleteTarget(j); }}
                                  style={{color: "var(--text-3)"}}>
                            <Icons.Trash size={13}/>
                          </button>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {cancelTarget && <CancelScanModal job={cancelTarget}
        close={() => setCancelTarget(null)}
        onConfirm={async () => {
          try { await scanApi.cancelJob(cancelTarget.id); setCancelTarget(null); refresh(); }
          catch (e) { alert(e.message); }
        }}/>}
      {deleteTarget && <DeleteScanModal job={deleteTarget}
        close={() => setDeleteTarget(null)}
        onConfirm={async () => {
          try { await scanApi.deleteJob(deleteTarget.id); setDeleteTarget(null); refresh(); }
          catch (e) { alert(e.message); }
        }}/>}
      {showNewScan && <NewScanModal close={() => setShowNewScan(false)} onCreated={() => { setShowNewScan(false); refresh(); }}/>}
      {showSchedules && <SchedulesModal close={() => setShowSchedules(false)}/>}
    </>
  );
}

function CancelScanModal({ job, close, onConfirm }) {
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 460}}>
        <div className="drawer-head" style={{borderBottom: "1px solid var(--line)"}}>
          <div style={{width: 28, height: 28, borderRadius: 6, background: "rgba(220,80,80,0.1)", color: "var(--err)", display: "grid", placeItems: "center"}}>
            <Icons.AlertTriangle size={15}/>
          </div>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Cancel running scan?</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "20px 24px"}}>
          <div style={{fontSize: 13.5, lineHeight: 1.6, color: "var(--text-1)"}}>
            Scan <span className="mono" style={{color: "var(--brand-text)"}}>#{job.id}</span> on <span className="mono" style={{color: "var(--text-0)"}}>{job.target}</span> is currently <span style={{color: "var(--brand-text)"}}>{job.status}</span>. Cancelling will stop the active plugins and discard in-progress findings.
          </div>

          <label className="form-label" style={{marginTop: 16}}>Reason (optional)</label>
          <textarea className="form-input" rows={3} placeholder="e.g. Wrong target selected, will rerun against staging"
                    value={reason} onChange={e => setReason(e.target.value)}
                    style={{height: "auto", padding: "10px 12px"}}/>
        </div>
        <div style={{padding: "14px 24px", borderTop: "1px solid var(--line)", display: "flex", gap: 8, justifyContent: "flex-end", background: "var(--surface-1)"}}>
          <button className="btn" onClick={close} disabled={submitting}>Keep running</button>
          <button className="btn" disabled={submitting}
                  onClick={async () => { setSubmitting(true); await onConfirm(); setSubmitting(false); }}
                  style={{background: "var(--err)", borderColor: "var(--err)", color: "#fff"}}>
            {submitting ? <><Icons.Refresh size={11} className="spin"/> Cancelling…</> : <><Icons.Stop size={11}/> Cancel scan</>}
          </button>
        </div>
      </div>
    </>
  );
}

function DeleteScanModal({ job, close, onConfirm }) {
  const [confirmText, setConfirmText] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const canDelete = confirmText === `${job.id}`;

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 480}}>
        <div className="drawer-head" style={{borderBottom: "1px solid var(--line)"}}>
          <div style={{width: 28, height: 28, borderRadius: 6, background: "rgba(220,80,80,0.1)", color: "var(--err)", display: "grid", placeItems: "center"}}>
            <Icons.Trash size={14}/>
          </div>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Delete scan #{job.id}?</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>

        <div style={{padding: "20px 24px"}}>
          <div style={{fontSize: 13.5, lineHeight: 1.6, color: "var(--text-1)"}}>
            Permanently remove scan <span className="mono" style={{color: "var(--brand-text)"}}>#{job.id}</span> on <span className="mono" style={{color: "var(--text-0)"}}>{job.target}</span>. All findings and AI analyses linked to this job will also be deleted. This cannot be undone.
          </div>

          <div style={{marginTop: 16, padding: "10px 12px", background: "rgba(220,80,80,0.06)", border: "1px solid rgba(220,80,80,0.25)", borderRadius: 6, display: "flex", gap: 10, alignItems: "flex-start"}}>
            <Icons.AlertTriangle size={14} style={{color: "var(--err)", marginTop: 2, flexShrink: 0}}/>
            <div style={{fontSize: 12.5, color: "var(--text-1)", lineHeight: 1.5}}>
              Type the scan ID <span className="mono" style={{color: "var(--err)", fontWeight: 600}}>{job.id}</span> to confirm.
            </div>
          </div>

          <input className="form-input mono" value={confirmText} onChange={e => setConfirmText(e.target.value)}
                 placeholder={`Type ${job.id} to confirm`} style={{marginTop: 10}} autoFocus/>
        </div>

        <div style={{padding: "14px 24px", borderTop: "1px solid var(--line)", display: "flex", gap: 8, justifyContent: "flex-end", background: "var(--surface-1)"}}>
          <button className="btn" onClick={close} disabled={submitting}>Keep</button>
          <button className="btn" disabled={!canDelete || submitting}
                  onClick={async () => { setSubmitting(true); await onConfirm(); setSubmitting(false); }}
                  style={{background: canDelete ? "var(--err)" : "var(--surface-2)", borderColor: canDelete ? "var(--err)" : "var(--line)", color: canDelete ? "#fff" : "var(--text-3)", cursor: canDelete && !submitting ? "pointer" : "not-allowed"}}>
            {submitting ? <><Icons.Refresh size={11} className="spin"/> Deleting…</> : <><Icons.Trash size={11}/> Delete permanently</>}
          </button>
        </div>
      </div>
    </>
  );
}

// ── Schedules manager ──────────────────────────────────────────────────────
function SchedulesModal({ close }) {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try { setSchedules(await scanApi.listSchedules()); setError(""); }
    catch (e) { setError(e.message); }
    finally   { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const onToggle = async (id) => {
    try { await scanApi.toggleSchedule(id); refresh(); }
    catch (e) { alert(e.message); }
  };
  const onDelete = async (id, name) => {
    if (!confirm(`Delete schedule "${name}"? Future runs will stop.`)) return;
    try { await scanApi.deleteSchedule(id); refresh(); }
    catch (e) { alert(e.message); }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 700, maxHeight: "85vh"}}>
        <div className="drawer-head">
          <Icons.Clock size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Scan schedules</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "20px 24px", overflowY: "auto", flex: 1}}>
          <div style={{fontSize: 12.5, color: "var(--text-2)", lineHeight: 1.55, marginBottom: 14}}>
            Recurring or one-time scans. To create a new schedule, use the <strong>"+ New scan"</strong> button and pick anything other than "Run now" in the Schedule section.
          </div>
          {error && <div style={{color: "var(--err)", fontSize: 13, marginBottom: 12}}><Icons.AlertTriangle size={13}/> {error}</div>}
          {loading && schedules.length === 0 ? (
            <div style={{padding: 30, textAlign: "center", color: "var(--text-3)"}}>Loading…</div>
          ) : schedules.length === 0 ? (
            <div style={{padding: 30, textAlign: "center", color: "var(--text-3)", border: "1px dashed var(--line)", borderRadius: 8}}>
              <Icons.Clock size={24}/>
              <div style={{marginTop: 8, fontSize: 13}}>No schedules yet.</div>
            </div>
          ) : (
            <table className="tbl">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Target</th>
                  <th style={{width: 130}}>Frequency</th>
                  <th style={{width: 140}}>Next run</th>
                  <th style={{width: 80}}>Status</th>
                  <th style={{width: 90}}/>
                </tr>
              </thead>
              <tbody>
                {schedules.map(s => {
                  const freq = s.schedule_type === "interval"
                    ? `Every ${s.interval_hours}h`
                    : s.schedule_type === "custom"
                      ? (s.repeat ? "Custom · repeating" : "Once")
                      : s.schedule_type;
                  return (
                    <tr key={s.id}>
                      <td><span style={{color: "var(--text-0)", fontWeight: 500}}>{s.name}</span></td>
                      <td><span className="mono" style={{fontSize: 12.5}}>{s.target}</span></td>
                      <td><span className="tag">{freq}</span></td>
                      <td className="muted" style={{fontSize: 12}}>{s.next_run_at ? new Date(s.next_run_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"}) : "—"}</td>
                      <td>
                        {canEdit() ? (
                          <button onClick={() => onToggle(s.id)} className="btn btn-sm" style={{background: s.enabled ? "var(--brand-soft)" : "var(--surface-1)", color: s.enabled ? "var(--brand-text)" : "var(--text-3)", borderColor: s.enabled ? "var(--brand-line)" : "var(--line)"}}>
                            {s.enabled ? "On" : "Off"}
                          </button>
                        ) : <span className="tag">{s.enabled ? "On" : "Off"}</span>}
                      </td>
                      {canEdit() && (
                      <td>
                        <button className="btn btn-icon btn-ghost btn-sm" title="Delete schedule"
                                onClick={() => onDelete(s.id, s.name)} style={{color: "var(--text-3)"}}>
                          <Icons.Trash size={13}/>
                        </button>
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
    </>
  );
}

