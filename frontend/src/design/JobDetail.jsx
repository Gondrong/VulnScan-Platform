import React, { useState, useEffect, useCallback } from "react";
import { Icons, Sev, Risk, Status } from "./icons.jsx";
import { scanApi, aiApi, canEdit } from "../api.js";
import { parseProgress } from "./Jobs.jsx";
import { ReportPreviewModal } from "./Assets.jsx";

function adaptFinding(f, target) {
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    host: target,
    plugin: f.plugin_id,
    risk: f.risk_score,
    cvss: f.cvss_base,
    confidence: f.confidence,
    sla: f.sla_days,
    kev: !!f.is_kev,
    cve: extractCve(f.references_json),
    desc: f.description,
    remediation: f.remediation,
    evidence: f.evidence,
    compliance: parseJsonArr(f.compliance_json),
    fingerprint: f.fingerprint,
  };
}
function parseJsonArr(s) { try { return s ? JSON.parse(s) : []; } catch { return []; } }
function extractCve(refsJson) {
  try {
    const refs = refsJson ? JSON.parse(refsJson) : [];
    const m = (refs.find(r => /CVE-\d+-\d+/.test(r)) || "").match(/CVE-\d+-\d+/);
    return m ? m[0] : null;
  } catch { return null; }
}

export function JobDetail({ job: jobProp, back, openDrawer }) {
  const [sev, setSev] = useState("");
  const [q, setQ] = useState("");
  const [showReport, setShowReport] = useState(false);
  const [job, setJob] = useState(jobProp);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const r = await scanApi.getJob(jobProp.id);
      setJob(r.job);
      setFindings((r.findings || []).map(f => adaptFinding(f, r.job.target)));
      setError("");
    } catch (e) {
      setError(e.message || "Failed to load scan");
    } finally {
      setLoading(false);
    }
  }, [jobProp.id]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    if (job.status !== "running" && job.status !== "queued") return;
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [job.status, refresh]);

  const visible = findings.filter(f =>
    (!sev || f.severity === sev) &&
    (!q || (f.title || "").toLowerCase().includes(q.toLowerCase()) || (f.host || "").toLowerCase().includes(q.toLowerCase()))
  );
  const counts = findings.reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {});
  const kevCount = findings.filter(f => f.kev).length;

  return (
    <>
      <div className="ph">
        <div>
          <div style={{display: "flex", alignItems: "center", gap: 10, marginBottom: 6}}>
            <button className="btn btn-ghost btn-sm" onClick={back}><Icons.ChevronRight size={12} style={{transform: "rotate(180deg)"}}/> Back to jobs</button>
            <span className="tag">#{job.id}</span>
            <Status s={job.status}/>
          </div>
          <h1>{job.target}</h1>
          <div className="sub">
            {job.scan_type} scan
            {job.created_by && <> · by {job.created_by}</>}
            {job.created_at && <> · started {new Date(job.created_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"})}</>}
            {job.finished_at && <> · finished {new Date(job.finished_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"})}</>}
          </div>
          {error && <div style={{color: "var(--err)", fontSize: 12, marginTop: 6}}><Icons.AlertTriangle size={12}/> {error}</div>}
        </div>
        <div className="actions">
          <button className="btn" onClick={() => setShowReport(true)} disabled={findings.length === 0}><Icons.Download size={14}/> Download report</button>
          {canEdit() && <button className="btn" onClick={async () => {
            try { const r = await scanApi.rescanJob(job.id); alert(`Re-scan queued as #${r.id}`); }
            catch (e) { alert(e.message); }
          }}><Icons.Refresh size={14}/> Re-scan</button>}
        </div>
      </div>
      {showReport && <ReportPreviewModal report={{
        id: `R-${job.id}`, job_id: job.id, target: job.target, profile: `#${job.profile_id}`,
        asset: "—", findings: findings.length,
        size_pdf: "—", template: "Executive + Technical"
      }} close={() => setShowReport(false)}/>}

      <div className="grid-stat" style={{gridTemplateColumns: "repeat(6, 1fr)", marginBottom: 20}}>
        <div className="stat critical"><div className="accent-bar"/><div className="label">Critical</div><div className="value">{counts.critical || 0}</div></div>
        <div className="stat high"><div className="accent-bar"/><div className="label">High</div><div className="value">{counts.high || 0}</div></div>
        <div className="stat medium"><div className="accent-bar"/><div className="label">Medium</div><div className="value">{counts.medium || 0}</div></div>
        <div className="stat low"><div className="accent-bar"/><div className="label">Low</div><div className="value">{counts.low || 0}</div></div>
        <div className="stat brand"><div className="accent-bar"/><div className="label">KEV</div><div className="value">{kevCount}</div></div>
        <div className="stat neutral"><div className="accent-bar"/><div className="label">Total</div><div className="value">{findings.length}</div></div>
      </div>

      {(job.status === "running" || job.status === "queued") && <ScanProgressCard job={job}/>}

      <AIAnalysisBanner job={job}/>

      <div className="card">
        <div className="toolbar">
          <div className="left">
            <div className="tabs">
              {[["", "All", findings.length], ["critical", "Critical", counts.critical || 0], ["high", "High", counts.high || 0], ["medium", "Medium", counts.medium || 0], ["low", "Low", counts.low || 0], ["info", "Info", counts.info || 0]].map(([k, l, c]) => (
                <button key={k} className={`tab ${sev === k ? "active" : ""}`} onClick={() => setSev(k)}>
                  {l} <span className="badge">{c}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="right">
            <div className="field"><Icons.Search size={14} className="icon"/><input placeholder="Search findings…" value={q} onChange={e => setQ(e.target.value)}/></div>
            <button className="btn btn-ghost btn-sm"><Icons.Filter size={14}/> Filters</button>
          </div>
        </div>
        <div className="card-body flush">
          {loading && findings.length === 0 ? (
            <div style={{padding: "60px 18px", textAlign: "center", color: "var(--text-3)"}}>Loading findings…</div>
          ) : visible.length === 0 ? (
            <div style={{padding: "60px 18px", textAlign: "center", color: "var(--text-3)"}}>
              {findings.length === 0
                ? (job.status === "running" || job.status === "queued"
                    ? "Scan in progress — findings will appear here as plugins complete."
                    : "No findings recorded for this scan.")
                : "No findings match the current filters."}
            </div>
          ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th style={{width: 90}}>Severity</th>
                <th>Finding</th>
                <th style={{width: 200}}>Host</th>
                <th style={{width: 130}}>Plugin</th>
                <th style={{width: 100}}>Risk</th>
                <th style={{width: 90}}>SLA</th>
              </tr>
            </thead>
            <tbody>
              {visible.map(f => (
                <tr key={f.id} className="clickable" onClick={() => openDrawer({ ...f, _jobId: job.id })}>
                  <td><div style={{display: "flex", gap: 6, alignItems: "center"}}><Sev s={f.severity}/>{f.kev && <span className="kev">KEV</span>}</div></td>
                  <td>
                    <div style={{color: "var(--text-0)", fontWeight: 500, fontSize: 13.5}}>{f.title}</div>
                    {f.cve && <div className="mono" style={{fontSize: 11.5, color: "var(--text-3)", marginTop: 2}}>{f.cve}</div>}
                  </td>
                  <td><span className="mono" style={{fontSize: 12}}>{f.host}</span></td>
                  <td><span className="tag">{f.plugin}</span></td>
                  <td><Risk score={f.risk}/></td>
                  <td className="mono muted" style={{fontSize: 12}}>{f.sla ? `${f.sla}d` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          )}
        </div>
      </div>
    </>
  );
}

function ScanProgressCard({ job }) {
  const p = parseProgress(job.meta_json);
  const pct = p?.pct ?? (job.status === "queued" ? 0 : 0);
  const elapsed = p?.elapsed ?? 0;
  const elapsedStr = elapsed < 60 ? `${Math.round(elapsed)}s` : `${Math.floor(elapsed/60)}m ${Math.round(elapsed%60)}s`;

  return (
    <div className="card" style={{marginBottom: 16, borderColor: "var(--brand-line)"}}>
      <div style={{padding: "16px 20px"}}>
        <div style={{display: "flex", alignItems: "center", gap: 14, marginBottom: 14}}>
          <div style={{width: 36, height: 36, borderRadius: 8, background: "var(--brand-soft)", color: "var(--brand)", display: "grid", placeItems: "center"}}>
            <Icons.Refresh size={16} className="spin"/>
          </div>
          <div style={{flex: 1, minWidth: 0}}>
            <div style={{fontSize: 13, fontWeight: 600, color: "var(--text-0)"}}>
              {job.status === "queued" ? "Queued — waiting for a worker" : `Scanning · ${pct}% complete`}
            </div>
            <div style={{fontSize: 12, color: "var(--text-2)", marginTop: 2, fontFamily: "var(--font-mono)"}}>
              {p?.current_name ? <>plugin {p.step}/{p.total}: <span style={{color: "var(--text-0)"}}>{p.current_name}</span></> : "Initialising plugins…"}
              {" · "}
              elapsed {elapsedStr}
            </div>
          </div>
        </div>

        {/* Progress bar */}
        <div style={{height: 6, background: "var(--surface-2)", borderRadius: 3, overflow: "hidden"}}>
          <div style={{
            width: `${pct}%`, height: "100%",
            background: "linear-gradient(90deg, var(--brand) 0%, #7aa3f5 100%)",
            transition: "width 0.6s ease",
          }}/>
        </div>

        {/* Recent plugin log */}
        {p?.plugins && p.plugins.length > 0 && (
          <div style={{marginTop: 14, maxHeight: 180, overflowY: "auto", borderTop: "1px solid var(--line)", paddingTop: 10}}>
            <div className="eyebrow" style={{marginBottom: 6}}>Plugin activity</div>
            <div style={{display: "flex", flexDirection: "column", gap: 4, fontFamily: "var(--font-mono)", fontSize: 11.5}}>
              {p.plugins.slice().reverse().map((pl, i) => (
                <div key={`${pl.plugin_id}-${i}`} style={{display: "flex", alignItems: "center", gap: 8, padding: "2px 4px"}}>
                  <span style={{
                    width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
                    background: pl.status === "running" ? "var(--brand)" :
                                pl.status === "done"    ? "var(--ok)" :
                                pl.status === "failed"  ? "var(--err)" :
                                pl.status === "skipped" ? "var(--text-4)" : "var(--text-3)",
                    animation: pl.status === "running" ? "pulse 1.4s ease-in-out infinite" : undefined,
                  }}/>
                  <span style={{color: "var(--text-1)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>
                    {pl.plugin_id} <span style={{color: "var(--text-3)"}}>· {pl.name}</span>
                  </span>
                  <span style={{color: "var(--text-3)", fontSize: 10.5}}>{pl.status}</span>
                  <span style={{color: "var(--text-4)", fontSize: 10.5, width: 50, textAlign: "right"}}>{pl.t}s</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function AIAnalysisBanner({ job }) {
  const [providers, setProviders] = useState([]);
  const [provider, setProvider] = useState("");
  const [history, setHistory] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [activeId, setActiveId] = useState(null);
  const [viewing, setViewing] = useState(null);

  const refreshHistory = useCallback(async () => {
    try {
      const r = await aiApi.jobResults(job.id);
      setHistory(r.analyses || r || []);
    } catch {}
  }, [job.id]);

  useEffect(() => {
    aiApi.providers()
      .then(r => {
        const list = r.providers || [];
        setProviders(list);
        if (list.length > 0) setProvider(list[0].id);
      })
      .catch(e => setError(e.message));
    refreshHistory();
  }, [refreshHistory]);

  // Poll active analysis
  useEffect(() => {
    if (!activeId) return;
    const t = setInterval(async () => {
      try {
        const s = await aiApi.status(activeId);
        if (s.status === "done" || s.status === "failed") {
          setActiveId(null);
          setBusy(false);
          refreshHistory();
        }
      } catch {}
    }, 2000);
    return () => clearInterval(t);
  }, [activeId, refreshHistory]);

  const startAnalysis = async (mode) => {
    if (!provider) { setError("No AI provider configured"); return; }
    if (job.status !== "done") { setError("Job must be complete to run AI analysis"); return; }
    setBusy(true);
    setError("");
    try {
      const r = await aiApi.analyze({ job_id: job.id, provider, mode });
      setActiveId(r.id || r.analysis_id);
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  };

  const latestDone = history.find(a => a.status === "done");
  const running = history.find(a => a.status === "running" || a.status === "queued");
  const showRunning = busy || running;

  return (
    <div className="card" style={{marginBottom: 16, background: "linear-gradient(180deg, rgba(91,141,239,0.06) 0%, transparent 100%)", borderColor: "var(--brand-line)"}}>
      <div style={{padding: "16px 20px", display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap"}}>
        <div style={{width: 36, height: 36, borderRadius: 8, background: "var(--brand-soft)", display: "grid", placeItems: "center", color: "var(--brand)"}}>
          <Icons.Brain size={18}/>
        </div>
        <div style={{flex: 1, minWidth: 200}}>
          <div style={{fontSize: 13, fontWeight: 600, color: "var(--text-0)"}}>
            AI analysis {showRunning && "— running"}
            {!showRunning && latestDone && ` — last run ${new Date(latestDone.finished_at || latestDone.created_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"})}`}
          </div>
          <div style={{fontSize: 12.5, color: "var(--text-2)"}}>
            {showRunning
              ? "Validating findings and generating PoC scripts in the background…"
              : providers.length === 0
                ? "No AI providers configured (set API keys in backend .env)"
                : "Validate findings, identify attack chains, and generate proof-of-concept scripts."}
          </div>
          {error && <div style={{fontSize: 12, color: "var(--err)", marginTop: 4}}><Icons.AlertTriangle size={11}/> {error}</div>}
        </div>
        {providers.length > 0 && (
          <select className="form-input" style={{height: 28, fontSize: 12, maxWidth: 180}} value={provider} onChange={e => setProvider(e.target.value)} disabled={busy}>
            {providers.map(p => <option key={p.id} value={p.id}>{p.name || p.id}</option>)}
          </select>
        )}
        <button className="btn btn-sm" disabled={busy || providers.length === 0 || job.status !== "done"} onClick={() => startAnalysis("validate")}>
          {showRunning ? <><Icons.Refresh size={11} className="spin"/> Running…</> : "Validate"}
        </button>
        <button className="btn btn-primary btn-sm" disabled={busy || providers.length === 0 || job.status !== "done"} onClick={() => startAnalysis("full_exploit")}>
          Full + PoC
        </button>
      </div>
      {history.length > 0 && (
        <div style={{padding: "10px 20px 12px", borderTop: "1px solid var(--line)", display: "flex", flexDirection: "column", gap: 4}}>
          {history.slice(0, 5).map(a => {
            const clickable = a.status === "done" || a.status === "failed";
            return (
              <div key={a.id}
                   onClick={clickable ? () => setViewing(a) : undefined}
                   style={{
                     display: "flex", alignItems: "center", gap: 10, fontSize: 12,
                     padding: "6px 8px", borderRadius: 6,
                     cursor: clickable ? "pointer" : "default",
                     transition: "background 120ms",
                   }}
                   onMouseEnter={e => { if (clickable) e.currentTarget.style.background = "var(--surface-1)"; }}
                   onMouseLeave={e => { e.currentTarget.style.background = ""; }}>
                <Status s={a.status === "done" ? "done" : a.status === "failed" ? "failed" : a.status === "running" ? "running" : "queued"}/>
                <span className="mono" style={{color: "var(--text-2)"}}>#{a.id}</span>
                <span className="tag">{a.mode}</span>
                <span style={{color: "var(--text-3)"}}>{a.provider}</span>
                <span style={{color: "var(--text-3)", marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11}}>
                  {a.finished_at ? new Date(a.finished_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"}) : "—"}
                  {a.duration_seconds ? ` · ${a.duration_seconds.toFixed(1)}s` : ""}
                </span>
                {clickable && <Icons.ChevronRight size={11} color="var(--text-3)"/>}
              </div>
            );
          })}
        </div>
      )}

      {viewing && <AIResultModal analysisId={viewing.id} close={() => setViewing(null)}/>}
    </div>
  );
}

function AIResultModal({ analysisId, close }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("summary");

  useEffect(() => {
    aiApi.status(analysisId)
      .then(setData)
      .catch(e => setError(e.message));
  }, [analysisId]);

  const result = data?.result || {};
  const summary = result.summary || result.executive_summary || "";
  const attackChains = result.attack_chains || result.chains || [];
  const recommendations = result.recommendations || result.next_steps || result.remediation_priority || [];

  // finding_validations is a dict keyed by finding_id → convert to array
  const findingValidations = result.finding_validations || {};
  const findings = result.findings || result.findings_validated ||
    Object.entries(findingValidations).map(([id, v]) => ({ finding_id: id, ...v }));

  // poc_results is a dict keyed by finding_id → each has { code, language, description, disclaimer }
  const pocResults = result.poc_results || {};

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 720, maxHeight: "85vh", display: "flex", flexDirection: "column"}}>
        <div className="drawer-head">
          <Icons.Brain size={16} color="var(--brand)"/>
          <div style={{display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap"}}>
            <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>AI Analysis #{analysisId}</span>
            {data && <Status s={data.status === "done" ? "done" : data.status === "failed" ? "failed" : data.status}/>}
            {data && <span className="tag">{data.mode}</span>}
            {data && <span style={{fontSize: 11, color: "var(--text-3)", fontFamily: "var(--font-mono)"}}>{data.provider}</span>}
          </div>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>

        <div style={{padding: "0 24px", borderBottom: "1px solid var(--line)", display: "flex", gap: 0}}>
          {[
            ["summary", "Summary"],
            ["findings", `Findings (${findings.length})`],
            ["chains", `Attack chains (${attackChains.length})`],
            ["poc", `PoC (${Object.keys(pocResults).length})`],
            ["raw", "Raw"],
          ].map(([k, l]) => (
            <button key={k} onClick={() => setTab(k)} style={{
              padding: "10px 14px", fontSize: 13, fontWeight: 500,
              color: tab === k ? "var(--text-0)" : "var(--text-3)",
              borderBottom: tab === k ? "2px solid var(--brand)" : "2px solid transparent",
              marginBottom: -1,
            }}>{l}</button>
          ))}
        </div>

        <div style={{padding: "20px 24px", overflowY: "auto", flex: 1}}>
          {error && <div style={{color: "var(--err)", fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}
          {!data && !error && <div style={{color: "var(--text-3)", fontSize: 13}}>Loading…</div>}

          {data && data.status === "failed" && (() => {
            const err = data.error || "Unknown error";
            const isCpuSegfault = data.provider === "claude_cli" && (
              err.includes("Segmentation fault") ||
              err.includes("rc=-4") ||
              err.includes("CPU lacks AVX")
            );
            return (
              <div>
                <div style={{padding: 14, background: "var(--sev-critical-bg)", border: "1px solid var(--sev-critical-line)", borderRadius: 8, color: "var(--err)", fontSize: 13, marginBottom: 12}}>
                  <div style={{fontWeight: 600, marginBottom: 6}}><Icons.AlertTriangle size={13}/> Analysis failed</div>
                  <pre style={{fontFamily: "var(--font-mono)", fontSize: 11.5, whiteSpace: "pre-wrap", margin: 0, color: "var(--text-1)", maxHeight: 280, overflowY: "auto"}}>{err}</pre>
                </div>

                {isCpuSegfault && (
                  <div style={{padding: "14px 16px", background: "var(--brand-soft)", border: "1px solid var(--brand-line)", borderRadius: 8, fontSize: 13, color: "var(--text-1)", lineHeight: 1.6}}>
                    <div style={{fontWeight: 600, marginBottom: 8, color: "var(--text-0)"}}>
                      <Icons.Info size={13}/> Why this happens
                    </div>
                    <p style={{margin: "0 0 10px"}}>
                      The <span className="mono">claude</span> CLI is built with Bun, and Bun requires a CPU with AVX/AVX2
                      support. This server's CPU lacks AVX — running <span className="mono">claude --print</span> always
                      segfaults here. The CLI <span className="mono">--version</span> command works because it never
                      starts the JS runtime.
                    </p>
                    <p style={{margin: "0 0 10px", fontWeight: 500, color: "var(--text-0)"}}>How to fix:</p>
                    <ul style={{margin: 0, paddingLeft: 18, fontSize: 12.5}}>
                      <li style={{marginBottom: 6}}>
                        <strong>Use Claude (API) instead</strong> — same Claude models via the official Anthropic API,
                        which doesn't depend on your CPU. Set <span className="mono">ANTHROPIC_API_KEY=sk-ant-…</span> in
                        the backend <span className="mono">.env</span>, then restart with{" "}
                        <span className="mono">docker compose restart backend worker</span>. A new <strong>Claude (API)</strong>{" "}
                        provider will appear in the dropdown above.
                      </li>
                      <li style={{marginBottom: 6}}>
                        <strong>Or use Azure OpenAI / Gemini</strong> — already configured for you. Just pick another provider
                        from the dropdown and re-run.
                      </li>
                      <li>
                        <strong>Or move the worker container to a host with AVX2</strong> (any cloud VM since ~2014).
                      </li>
                    </ul>
                  </div>
                )}
              </div>
            );
          })()}

          {data && data.status === "done" && (
            <>
              {tab === "summary" && (
                <div>
                  {summary ? (
                    <div style={{fontSize: 14, lineHeight: 1.7, color: "var(--text-1)", whiteSpace: "pre-wrap"}}>{summary}</div>
                  ) : (
                    <div style={{color: "var(--text-3)", fontSize: 13}}>No summary in this analysis. Try the Raw tab.</div>
                  )}
                  {recommendations.length > 0 && (
                    <div style={{marginTop: 20}}>
                      <div className="eyebrow">Remediation priority</div>
                      <div style={{display: "flex", flexDirection: "column", gap: 8}}>
                        {recommendations.map((r, i) => (
                          <div key={i} style={{padding: "10px 14px", border: "1px solid var(--line)", borderRadius: 8, background: "var(--surface-1)"}}>
                            <div style={{display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap"}}>
                              {r.rank != null && <span style={{fontSize: 12, fontWeight: 700, color: "var(--text-0)", minWidth: 20}}>#{r.rank}</span>}
                              <span style={{fontSize: 13, color: "var(--text-0)", fontWeight: 500, flex: 1}}>{typeof r === "string" ? r : r.action || r.text || JSON.stringify(r)}</span>
                              {r.timeframe && <span className="tag">{r.timeframe}</span>}
                              {r.effort && <span className="tag">effort: {r.effort}</span>}
                              {r.impact && <span className="tag">impact: {r.impact}</span>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {data.token_usage != null && (
                    <div style={{marginTop: 20, fontSize: 11.5, color: "var(--text-3)", fontFamily: "var(--font-mono)"}}>
                      Tokens used: {data.token_usage} · Duration: {data.duration_seconds?.toFixed(1)}s
                    </div>
                  )}
                </div>
              )}

              {tab === "findings" && (
                findings.length === 0 ? (
                  <div style={{color: "var(--text-3)", fontSize: 13}}>No per-finding validation in this analysis.</div>
                ) : (
                  <div style={{display: "flex", flexDirection: "column", gap: 10}}>
                    {findings.map((f, i) => (
                      <div key={i} style={{padding: "12px 14px", border: "1px solid var(--line)", borderRadius: 8, background: "var(--surface-1)"}}>
                        <div style={{display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap"}}>
                          {f.verdict && <span className={`sev sev-${f.verdict === "true_positive" || f.verdict === "exploitable" ? "critical" : f.verdict === "false_positive" ? "low" : "medium"}`}>
                            {String(f.verdict).replace(/_/g, " ")}
                          </span>}
                          {f.confidence != null && <span className="tag">{Math.round(f.confidence * 100)}% confidence</span>}
                          {f.finding_id != null && <span className="mono" style={{fontSize: 11, color: "var(--text-3)"}}>finding #{f.finding_id}</span>}
                          {f.title && <span style={{fontSize: 13, color: "var(--text-0)", fontWeight: 500}}>{f.title}</span>}
                        </div>
                        {f.reasoning && <div style={{fontSize: 13, color: "var(--text-1)", lineHeight: 1.6, whiteSpace: "pre-wrap"}}>{f.reasoning}</div>}
                        {f.recommendation && (
                          <div style={{marginTop: 8, padding: 10, background: "rgba(95,184,122,0.06)", border: "1px solid rgba(95,184,122,0.2)", borderRadius: 6, fontSize: 12.5, color: "var(--text-1)"}}>
                            <strong>Recommendation:</strong> {f.recommendation}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )
              )}

              {tab === "chains" && (
                attackChains.length === 0 ? (
                  <div style={{color: "var(--text-3)", fontSize: 13}}>No attack chains identified in this analysis.</div>
                ) : (
                  <div style={{display: "flex", flexDirection: "column", gap: 12}}>
                    {attackChains.map((c, i) => (
                      <div key={i} style={{padding: "14px 16px", border: "1px solid var(--brand-line)", borderRadius: 8, background: "var(--brand-soft)"}}>
                        <div style={{fontSize: 13.5, color: "var(--text-0)", fontWeight: 600, marginBottom: 6}}>{c.name || c.title || `Chain ${i+1}`}</div>
                        {c.description && <div style={{fontSize: 13, color: "var(--text-1)", lineHeight: 1.6, marginBottom: 8}}>{c.description}</div>}
                        {(c.steps || c.path) && (
                          <ol style={{paddingLeft: 18, fontSize: 12.5, color: "var(--text-1)", lineHeight: 1.7, fontFamily: "var(--font-mono)"}}>
                            {(c.steps || c.path).map((s, j) => (
                              <li key={j}>{typeof s === "string" ? s : s.text || JSON.stringify(s)}</li>
                            ))}
                          </ol>
                        )}
                        {c.impact && <div style={{marginTop: 8, fontSize: 12, color: "var(--text-2)"}}><strong>Impact:</strong> {c.impact}</div>}
                      </div>
                    ))}
                  </div>
                )
              )}

              {tab === "poc" && (
                Object.keys(pocResults).length > 0 ? (
                  <div style={{display: "flex", flexDirection: "column", gap: 14}}>
                    {Object.entries(pocResults).map(([fid, p]) => (
                      <div key={fid} style={{border: "1px solid var(--line)", borderRadius: 8, overflow: "hidden"}}>
                        <div style={{padding: "10px 14px", background: "var(--surface-1)", borderBottom: "1px solid var(--line)", display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap"}}>
                          <span className="mono" style={{fontSize: 12, color: "var(--text-2)"}}>Finding #{fid}</span>
                          {p.language && <span className="tag">{p.language}</span>}
                          {p.description && <span style={{fontSize: 12, color: "var(--text-1)", flex: 1}}>{p.description}</span>}
                        </div>
                        {p.disclaimer && (
                          <div style={{padding: "6px 14px", background: "var(--sev-medium-bg)", fontSize: 11.5, color: "var(--text-2)"}}>
                            {p.disclaimer}
                          </div>
                        )}
                        <div style={{padding: 14}}>
                          <pre className="code" style={{whiteSpace: "pre-wrap", lineHeight: 1.6, fontSize: 11.5, margin: 0}}>{p.code || JSON.stringify(p, null, 2)}</pre>
                          <div style={{display: "flex", gap: 8, marginTop: 10}}>
                            <button className="btn btn-sm" onClick={() => navigator.clipboard?.writeText(p.code || JSON.stringify(p, null, 2))}>
                              <Icons.Copy size={12}/> Copy
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{color: "var(--text-3)", fontSize: 13}}>
                    No PoC in this analysis. Run with mode <span className="mono">full_exploit</span> (the "Full + PoC" button) to generate exploit code for each finding.
                  </div>
                )
              )}

              {tab === "raw" && (
                <div>
                  <div className="eyebrow">Raw response</div>
                  <pre className="code" style={{whiteSpace: "pre-wrap", fontSize: 11.5, lineHeight: 1.55, maxHeight: 500, overflowY: "auto"}}>
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>

        <div style={{padding: "12px 24px", borderTop: "1px solid var(--line)", display: "flex", justifyContent: "flex-end", background: "var(--surface-1)"}}>
          <button className="btn" onClick={close}>Close</button>
        </div>
      </div>
    </>
  );
}

export function FindingDrawer({ finding, close }) {
  const [tab, setTab] = useState("overview");
  const [aiMatch, setAiMatch] = useState(null); // {entry, analysis} or null
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState("");

  if (!finding) return null;
  const f = finding;
  const jobId = f._jobId;

  // Fetch the latest done analysis when the AI tab is opened, then look for an
  // entry matching THIS finding (by id, fingerprint, or title).
  useEffect(() => {
    if (tab !== "ai" || !jobId || aiMatch || aiLoading) return;
    (async () => {
      setAiLoading(true);
      setAiError("");
      try {
        const r = await aiApi.jobResults(jobId);
        const list = r.analyses || r || [];
        // Walk newest→oldest (backend already returns desc by created_at)
        for (const a of list) {
          if (a.status !== "done") continue;
          // Pull full result (jobResults endpoint may already include parsed_result;
          // fall back to /ai/status to be safe)
          let result = a.parsed_result || a.result || null;
          if (!result) {
            try { result = (await aiApi.status(a.id)).result; } catch {}
          }
          if (!result) continue;

          // Backend returns finding_validations as dict keyed by finding_id
          const validations = result.finding_validations || {};
          const pocMap = result.poc_results || {};
          const fid = String(f.id);

          // Direct lookup by finding ID in the dict
          if (validations[fid]) {
            const entry = { finding_id: fid, ...validations[fid] };
            if (pocMap[fid]) entry.poc_code = pocMap[fid];
            setAiMatch({ entry, analysis: a });
            return;
          }

          // Fallback: try array format (if a provider returns that)
          const entries = result.findings || result.findings_validated || [];
          const match = entries.find(e =>
            (e.finding_id != null && Number(e.finding_id) === Number(f.id)) ||
            (e.fingerprint && f.fingerprint && e.fingerprint === f.fingerprint) ||
            (e.title && f.title && e.title === f.title)
          );
          if (match) {
            if (pocMap[fid]) match.poc_code = pocMap[fid];
            setAiMatch({ entry: match, analysis: a });
            return;
          }
        }
        setAiMatch({ entry: null, analysis: list.find(a => a.status === "done") || null });
      } catch (e) {
        setAiError(e.message);
      } finally {
        setAiLoading(false);
      }
    })();
  }, [tab, jobId, aiMatch, aiLoading, f.id, f.fingerprint, f.title]);

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="drawer">
        <div className="drawer-head">
          <Sev s={f.severity}/>
          {f.kev && <span className="kev">KEV</span>}
          <span className="tag">#{f.id}</span>
          <div style={{marginLeft: "auto", display: "flex", gap: 4}}>
            <button className="btn btn-ghost btn-icon btn-sm" onClick={close}><Icons.X size={14}/></button>
          </div>
        </div>
        <div style={{padding: "20px 24px 0"}}>
          <h2 style={{fontFamily: "var(--font-display)", fontSize: 19, fontWeight: 600, color: "var(--text-0)", letterSpacing: "-0.01em", lineHeight: 1.3}}>{f.title}</h2>
          <div style={{display: "flex", gap: 16, marginTop: 12, flexWrap: "wrap"}}>
            <div><div style={{fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em"}}>Risk</div><div style={{marginTop: 4}}><Risk score={f.risk}/></div></div>
            <div><div style={{fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em"}}>CVSS</div><div className="mono" style={{marginTop: 4, fontSize: 14, color: "var(--text-0)", fontWeight: 600}}>{f.cvss != null ? f.cvss : "—"}</div></div>
            <div><div style={{fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em"}}>Confidence</div><div className="mono" style={{marginTop: 4, fontSize: 14, color: "var(--text-0)", fontWeight: 600}}>{f.confidence != null ? `${(f.confidence * 100).toFixed(0)}%` : "—"}</div></div>
            <div><div style={{fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em"}}>SLA</div><div className="mono" style={{marginTop: 4, fontSize: 14, color: "var(--text-0)", fontWeight: 600}}>{f.sla != null ? `${f.sla} days` : "—"}</div></div>
          </div>

          <div style={{display: "flex", gap: 0, marginTop: 20, borderBottom: "1px solid var(--line)"}}>
            {[["overview", "Overview"], ["evidence", "Evidence"], ["remediation", "Remediation"], ["ai", "AI analysis"]].map(([k, l]) => (
              <button key={k} onClick={() => setTab(k)} style={{
                padding: "10px 14px", fontSize: 13, fontWeight: 500,
                color: tab === k ? "var(--text-0)" : "var(--text-3)",
                borderBottom: tab === k ? "2px solid var(--brand)" : "2px solid transparent",
                marginBottom: -1,
              }}>{l}</button>
            ))}
          </div>
        </div>

        <div className="drawer-body">
          {tab === "overview" && (
            <div>
              <div style={{fontSize: 14, lineHeight: 1.7, color: "var(--text-1)"}}>{f.desc || "No description available."}</div>
              <div style={{marginTop: 24}}>
                <div className="eyebrow">Details</div>
                <dl className="dl">
                  <dt>Host</dt><dd className="mono">{f.host}{f.port ? `:${f.port}` : ""}</dd>
                  <dt>Plugin</dt><dd className="mono">{f.plugin}</dd>
                  {f.cve && <><dt>CVE</dt><dd className="mono"><a style={{color: "var(--brand-text)"}}>{f.cve}</a></dd></>}
                  <dt>Fingerprint</dt><dd className="mono" style={{fontSize: 11, wordBreak: "break-all"}}>{f.fingerprint || "—"}</dd>
                </dl>
              </div>
              {f.compliance && f.compliance.length > 0 && (
                <div style={{marginTop: 24}}>
                  <div className="eyebrow">Compliance mapping</div>
                  <div style={{display: "flex", gap: 6, flexWrap: "wrap"}}>
                    {f.compliance.map(c => <span key={c} className="tag">{c}</span>)}
                  </div>
                </div>
              )}
            </div>
          )}
          {tab === "evidence" && (
            <div>
              <div className="eyebrow">Raw response evidence</div>
              <div className="code">{f.evidence || "No evidence captured."}</div>
            </div>
          )}
          {tab === "remediation" && (
            <div>
              <div style={{padding: "14px 16px", background: "rgba(95,184,122,0.06)", border: "1px solid rgba(95,184,122,0.2)", borderRadius: 8, borderLeft: "3px solid var(--ok)"}}>
                <div style={{display: "flex", alignItems: "center", gap: 8, marginBottom: 8}}>
                  <Icons.Shield size={14} color="var(--ok)"/>
                  <span style={{fontSize: 12, fontWeight: 600, color: "var(--ok)", textTransform: "uppercase", letterSpacing: "0.05em"}}>Recommended action</span>
                </div>
                <div style={{fontSize: 14, lineHeight: 1.7, color: "var(--text-1)"}}>{f.remediation || "Consult vendor advisory and apply the latest patch."}</div>
              </div>
            </div>
          )}
          {tab === "ai" && (
            <FindingAITab
              loading={aiLoading}
              error={aiError}
              match={aiMatch}
              finding={f}
            />
          )}
        </div>
      </div>
    </>
  );
}

function FindingAITab({ loading, error, match, finding }) {
  if (loading) {
    return <div style={{padding: 24, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>
      <Icons.Refresh size={16} className="spin"/>
      <div style={{marginTop: 8}}>Loading AI analysis…</div>
    </div>;
  }
  if (error) {
    return <div style={{padding: 14, background: "var(--sev-critical-bg)", border: "1px solid var(--sev-critical-line)", borderRadius: 8, color: "var(--err)", fontSize: 13}}>
      <Icons.AlertTriangle size={13}/> {error}
    </div>;
  }
  if (!match || !match.analysis) {
    return (
      <div style={{padding: "20px 16px", textAlign: "center", color: "var(--text-3)", fontSize: 13, border: "1px dashed var(--line)", borderRadius: 8}}>
        <Icons.Brain size={28}/>
        <div style={{marginTop: 10, fontSize: 13.5, color: "var(--text-1)", fontWeight: 500}}>No AI analysis run for this scan yet</div>
        <div style={{marginTop: 6, fontSize: 12.5}}>
          Click <strong>Validate</strong> or <strong>Full + PoC</strong> in the AI Analysis banner above the findings table to run one. Per-finding verdicts will appear here once it completes.
        </div>
      </div>
    );
  }
  if (!match.entry) {
    return (
      <div>
        <div style={{padding: "14px 16px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 8, marginBottom: 14, fontSize: 13, color: "var(--text-2)"}}>
          AI analysis #{match.analysis.id} ran on {new Date(match.analysis.finished_at).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"})} but didn't include this specific finding (#{finding.id}). The model may have prioritized higher-severity items.
        </div>
        <div className="form-help">Re-run the analysis with mode <span className="mono">full_exploit</span> to get coverage for all findings.</div>
      </div>
    );
  }

  const e = match.entry;
  const verdict = e.verdict || e.assessment || "\u2014";
  const isPositive = /(true_positive|exploitable|confirmed)/i.test(verdict);
  const isNegative = /(false_positive)/i.test(verdict);
  const conf = e.confidence != null ? Math.round(e.confidence * 100) : null;
  const reasoning = e.reasoning || e.explanation || e.notes || "";
  const recommendation = e.recommendation || e.next_step || "";
  const refs = e.references || e.public_pocs || [];

  // poc_code is an object { code, language, description, disclaimer } from poc_results
  const pocObj = e.poc_code || null;
  const pocText = pocObj ? (pocObj.code || JSON.stringify(pocObj, null, 2))
    : (e.exploit_code || e.poc || e.proof_of_concept || e.payload || "");

  return (
    <div>
      <div style={{
        padding: "14px 16px",
        background: isPositive ? "var(--sev-critical-bg)" : isNegative ? "rgba(95,184,122,0.06)" : "var(--brand-soft)",
        border: `1px solid ${isPositive ? "var(--sev-critical-line)" : isNegative ? "rgba(95,184,122,0.2)" : "var(--brand-line)"}`,
        borderRadius: 8,
        marginBottom: 16,
      }}>
        <div style={{display: "flex", alignItems: "center", gap: 8, marginBottom: 8}}>
          <Icons.Brain size={14} color={isPositive ? "var(--err)" : isNegative ? "var(--ok)" : "var(--brand)"}/>
          <span style={{
            fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em",
            color: isPositive ? "var(--err)" : isNegative ? "var(--ok)" : "var(--brand-text)",
          }}>
            Verdict — {String(verdict).replace(/_/g, " ")}{conf != null ? ` · ${conf}%` : ""}
          </span>
        </div>
        {reasoning && (
          <div style={{fontSize: 13.5, lineHeight: 1.7, color: "var(--text-1)", whiteSpace: "pre-wrap"}}>{reasoning}</div>
        )}
      </div>

      {recommendation && (
        <div style={{padding: "12px 14px", background: "rgba(95,184,122,0.06)", border: "1px solid rgba(95,184,122,0.2)", borderRadius: 8, marginBottom: 16}}>
          <div style={{fontSize: 11, fontWeight: 600, color: "var(--ok)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6}}>
            <Icons.Shield size={11}/> Recommendation
          </div>
          <div style={{fontSize: 13, lineHeight: 1.6, color: "var(--text-1)"}}>{recommendation}</div>
        </div>
      )}

      {refs.length > 0 && (
        <div style={{marginBottom: 16}}>
          <div className="eyebrow">References</div>
          <ul style={{paddingLeft: 18, fontSize: 12.5, color: "var(--text-1)", lineHeight: 1.7}}>
            {refs.map((r, i) => (
              <li key={i}>{typeof r === "string" ? r : r.url || r.title || JSON.stringify(r)}</li>
            ))}
          </ul>
        </div>
      )}

      {pocText ? (
        <div>
          <div className="eyebrow" style={{display: "flex", alignItems: "center", gap: 8}}>
            Generated proof-of-concept
            {pocObj?.language && <span className="tag">{pocObj.language}</span>}
          </div>
          {pocObj?.description && (
            <div style={{fontSize: 12.5, color: "var(--text-2)", marginBottom: 8, lineHeight: 1.6}}>{pocObj.description}</div>
          )}
          {pocObj?.disclaimer && (
            <div style={{padding: "6px 10px", background: "var(--sev-medium-bg)", borderRadius: 6, fontSize: 11.5, color: "var(--text-2)", marginBottom: 8}}>
              {pocObj.disclaimer}
            </div>
          )}
          <div className="code" style={{fontSize: 11.5, lineHeight: 1.7, whiteSpace: "pre-wrap"}}>{pocText}</div>
          <div style={{display: "flex", gap: 8, marginTop: 12}}>
            <button className="btn btn-sm" onClick={() => navigator.clipboard?.writeText(pocText)}>
              <Icons.Copy size={12}/> Copy
            </button>
          </div>
        </div>
      ) : (
        <div className="form-help">
          No PoC for this finding. Run the analysis with <strong>Full + PoC</strong> mode to generate exploit code.
        </div>
      )}

      <div style={{marginTop: 18, paddingTop: 14, borderTop: "1px solid var(--line)", fontSize: 11, color: "var(--text-3)", fontFamily: "var(--font-mono)"}}>
        From AI analysis #{match.analysis.id} · {match.analysis.provider} · {match.analysis.mode}
        {match.analysis.finished_at && ` · ${new Date(match.analysis.finished_at).toLocaleString()}`}
      </div>
    </div>
  );
}
