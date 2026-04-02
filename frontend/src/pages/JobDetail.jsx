import React, { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api";
import { SevBadge, RiskBar, StatusDot, Panel, fmtDate } from "../components/ui.jsx";

/* ─── AI Deep Analysis Panel ─────────────────────────────────────────── */

const MODE_OPTIONS = [
  { value: "validate",     label: "Validate",        desc: "Classify findings as true/false positive" },
  { value: "full",         label: "Full Analysis",   desc: "Executive summary, attack chains, remediation" },
  { value: "full_exploit", label: "Full + PoC",      desc: "Full analysis + proof-of-concept exploit scripts" },
];

function AiPanel({ jobId, jobStatus }) {
  const [providers, setProviders] = useState([]);
  const [provider, setProvider] = useState("");
  const [mode, setMode] = useState("full");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [analysisId, setAnalysisId] = useState(null);
  const [status, setStatus] = useState(null);   // polling response
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [expandedResult, setExpandedResult] = useState(null);
  const [pocLoading, setPocLoading] = useState({});

  // Load available providers
  useEffect(() => {
    api("/ai/providers").then(d => {
      setProviders(d.providers || []);
      if (d.providers?.length) setProvider(d.providers[0].id);
    }).catch(() => {});
  }, []);

  // Load history
  const loadHistory = useCallback(() => {
    api(`/ai/results/${jobId}`).then(d => setHistory(d.analyses || [])).catch(() => {});
  }, [jobId]);
  useEffect(() => { loadHistory(); }, [loadHistory]);

  // Poll active analysis
  useEffect(() => {
    if (!analysisId) return;
    const poll = setInterval(async () => {
      try {
        const s = await api(`/ai/status/${analysisId}`);
        setStatus(s);
        if (s.status === "done" || s.status === "failed") {
          clearInterval(poll);
          setBusy(false);
          loadHistory();
          if (s.status === "done") setExpandedResult(s);
        }
      } catch { /* ignore */ }
    }, 2000);
    return () => clearInterval(poll);
  }, [analysisId, loadHistory]);

  async function startAnalysis() {
    setError("");
    setBusy(true);
    setStatus(null);
    setExpandedResult(null);
    try {
      const r = await api("/ai/analyze", {
        method: "POST",
        body: { job_id: jobId, provider, mode },
      });
      setAnalysisId(r.analysis_id);
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  }

  async function requestPoc(analysisId, findingId) {
    setPocLoading(prev => ({ ...prev, [findingId]: true }));
    try {
      await api("/ai/poc", {
        method: "POST",
        body: { analysis_id: analysisId, finding_id: findingId },
      });
      // Poll until PoC appears
      const poll = setInterval(async () => {
        try {
          const s = await api(`/ai/status/${analysisId}`);
          const poc = s.result?.poc_results?.[String(findingId)];
          if (poc) {
            clearInterval(poll);
            setPocLoading(prev => ({ ...prev, [findingId]: false }));
            setExpandedResult(prev => prev ? { ...prev, result: s.result } : prev);
            loadHistory();
          }
        } catch { /* ignore */ }
      }, 3000);
      setTimeout(() => clearInterval(poll), 120000);
    } catch (e) {
      setPocLoading(prev => ({ ...prev, [findingId]: false }));
      setError(e.message);
    }
  }

  function viewResult(analysis) {
    const full = { ...analysis, result: analysis.result };
    setExpandedResult(prev => prev?.id === analysis.id ? null : full);
  }

  const disabled = jobStatus !== "done" || !provider || busy;
  const progress = status?.progress || {};

  return (
    <div style={{
      marginBottom: 24, border: "1px solid var(--border)",
      background: "var(--surface2)",
    }}>
      {/* Header */}
      <div style={{
        padding: "14px 18px",
        borderBottom: "1px solid var(--border)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: "1rem" }}>🤖</span>
          <span style={{
            fontFamily: "var(--font-mono)", fontSize: "0.78rem",
            fontWeight: 700, color: "var(--accent)",
          }}>AI DEEP ANALYSIS</span>
        </div>
        {history.length > 0 && (
          <button className="btn btn-ghost btn-sm" onClick={() => setShowHistory(h => !h)}>
            {showHistory ? "Hide" : "History"} ({history.length})
          </button>
        )}
      </div>

      {/* Controls */}
      <div style={{ padding: "14px 18px", display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
        {/* Provider */}
        <div>
          <div className="form-label" style={{ marginBottom: 4 }}>Provider</div>
          <select
            value={provider}
            onChange={e => setProvider(e.target.value)}
            disabled={busy}
            style={{
              background: "var(--surface3)", color: "var(--text-bright)",
              border: "1px solid var(--border)", padding: "6px 10px",
              fontFamily: "var(--font-mono)", fontSize: "0.75rem",
            }}
          >
            {providers.length === 0 && <option value="">No providers configured</option>}
            {providers.map(p => (
              <option key={p.id} value={p.id}>{p.name || p.id}</option>
            ))}
          </select>
        </div>

        {/* Mode */}
        <div>
          <div className="form-label" style={{ marginBottom: 4 }}>Mode</div>
          <div style={{ display: "flex", gap: 0 }}>
            {MODE_OPTIONS.map(m => (
              <button
                key={m.value}
                disabled={busy}
                onClick={() => setMode(m.value)}
                title={m.desc}
                style={{
                  padding: "6px 12px",
                  fontFamily: "var(--font-mono)", fontSize: "0.7rem",
                  background: mode === m.value ? "var(--accent)" : "var(--surface3)",
                  color: mode === m.value ? "#000" : "var(--text)",
                  border: "1px solid var(--border)",
                  borderRight: "none",
                  cursor: busy ? "not-allowed" : "pointer",
                  fontWeight: mode === m.value ? 700 : 400,
                  opacity: busy ? 0.5 : 1,
                }}
              >
                {m.label}
              </button>
            ))}
            <div style={{ borderRight: "1px solid var(--border)" }} />
          </div>
        </div>

        {/* Run button */}
        <button
          className="btn"
          disabled={disabled}
          onClick={startAnalysis}
          style={{
            background: disabled ? "var(--surface3)" : "var(--accent)",
            color: disabled ? "var(--text-dim)" : "#000",
            fontWeight: 700, fontSize: "0.75rem",
            padding: "6px 20px",
          }}
        >
          {busy ? "Analyzing..." : "▶ Run Analysis"}
        </button>
      </div>

      {/* Progress bar */}
      {busy && status && (
        <div style={{ padding: "0 18px 14px" }}>
          <div style={{
            background: "var(--surface3)", height: 6,
            border: "1px solid var(--border)", overflow: "hidden",
          }}>
            <div style={{
              width: `${progress.pct || 0}%`, height: "100%",
              background: "var(--accent)",
              transition: "width 0.5s ease",
            }} />
          </div>
          <div style={{
            fontFamily: "var(--font-mono)", fontSize: "0.65rem",
            color: "var(--text-dim)", marginTop: 4,
          }}>
            {progress.step || "Processing..."} — {progress.pct || 0}%
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{
          margin: "0 18px 14px", padding: "8px 12px",
          background: "rgba(255,71,87,0.08)", border: "1px solid rgba(255,71,87,0.2)",
          fontFamily: "var(--font-mono)", fontSize: "0.72rem", color: "var(--critical)",
        }}>
          ⚠ {error}
        </div>
      )}

      {/* History */}
      {showHistory && history.length > 0 && (
        <div style={{ padding: "0 18px 14px" }}>
          <table style={{ width: "100%", fontSize: "0.72rem", fontFamily: "var(--font-mono)" }}>
            <thead>
              <tr style={{ color: "var(--text-dim)", textAlign: "left" }}>
                <th style={{ padding: "4px 8px" }}>#</th>
                <th style={{ padding: "4px 8px" }}>Provider</th>
                <th style={{ padding: "4px 8px" }}>Mode</th>
                <th style={{ padding: "4px 8px" }}>Status</th>
                <th style={{ padding: "4px 8px" }}>Tokens</th>
                <th style={{ padding: "4px 8px" }}>Duration</th>
                <th style={{ padding: "4px 8px" }}>Date</th>
                <th style={{ padding: "4px 8px" }}></th>
              </tr>
            </thead>
            <tbody>
              {history.map(a => (
                <tr key={a.id} style={{ borderTop: "1px solid var(--border)" }}>
                  <td style={{ padding: "4px 8px", color: "var(--accent)" }}>{a.id}</td>
                  <td style={{ padding: "4px 8px" }}>{a.provider}</td>
                  <td style={{ padding: "4px 8px" }}>{a.mode}</td>
                  <td style={{ padding: "4px 8px" }}><StatusDot status={a.status} /></td>
                  <td style={{ padding: "4px 8px" }}>{a.token_usage ?? "—"}</td>
                  <td style={{ padding: "4px 8px" }}>{a.duration_seconds ? a.duration_seconds + "s" : "—"}</td>
                  <td style={{ padding: "4px 8px" }}>{fmtDate(a.created_at)}</td>
                  <td style={{ padding: "4px 8px" }}>
                    {a.status === "done" && a.result && (
                      <button className="btn btn-ghost btn-sm" onClick={() => viewResult(a)}>
                        {expandedResult?.id === a.id ? "Hide" : "View"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Result display */}
      {expandedResult?.result && (
        <AiResultView result={expandedResult.result} mode={expandedResult.mode}
          analysisId={expandedResult.id} pocLoading={pocLoading} onRequestPoc={requestPoc} />
      )}
    </div>
  );
}


/* ─── AI Result Rendering ─────────────────────────────────────────────── */

function AiResultView({ result, mode, analysisId, pocLoading, onRequestPoc }) {
  const [tab, setTab] = useState("summary");

  const tabs = [
    result.executive_summary && { key: "summary", label: "Summary" },
    result.attack_chains?.length && { key: "chains", label: `Attack Chains (${result.attack_chains.length})` },
    result.finding_validations && { key: "validations", label: "Validations" },
    result.remediation_priority?.length && { key: "remediation", label: "Remediation" },
    result.poc_results && Object.keys(result.poc_results).length > 0 && { key: "poc", label: "PoC Scripts" },
  ].filter(Boolean);

  return (
    <div style={{ borderTop: "1px solid var(--border)" }}>
      {/* Tab bar */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--border)", padding: "0 18px" }}>
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              padding: "8px 14px",
              fontFamily: "var(--font-mono)", fontSize: "0.68rem",
              background: "none", border: "none",
              color: tab === t.key ? "var(--accent)" : "var(--text-dim)",
              borderBottom: tab === t.key ? "2px solid var(--accent)" : "2px solid transparent",
              cursor: "pointer", fontWeight: tab === t.key ? 700 : 400,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ padding: "14px 18px", maxHeight: 500, overflowY: "auto" }}>
        {tab === "summary" && result.executive_summary && (
          <div style={{
            fontSize: "0.85rem", color: "var(--text)", lineHeight: 1.7,
            whiteSpace: "pre-wrap",
          }}>
            {result.executive_summary}
          </div>
        )}

        {tab === "chains" && result.attack_chains?.map((chain, i) => (
          <div key={i} style={{
            marginBottom: 12, padding: "12px 14px",
            background: "var(--surface3)", border: "1px solid var(--border)",
          }}>
            <div style={{
              fontWeight: 700, color: "var(--text-bright)",
              fontSize: "0.82rem", marginBottom: 6,
            }}>
              {chain.name || `Chain ${i + 1}`}
            </div>
            {chain.description && (
              <div style={{ fontSize: "0.8rem", color: "var(--text)", marginBottom: 8, lineHeight: 1.6 }}>
                {chain.description}
              </div>
            )}
            {chain.steps && (
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem" }}>
                {chain.steps.map((step, j) => (
                  <div key={j} style={{ display: "flex", gap: 8, marginBottom: 2, color: "var(--text)" }}>
                    <span style={{ color: "var(--accent)" }}>{j + 1}.</span>
                    <span>{typeof step === "string" ? step : step.description || JSON.stringify(step)}</span>
                  </div>
                ))}
              </div>
            )}
            {chain.impact && (
              <div style={{
                marginTop: 8, fontSize: "0.72rem",
                color: "var(--high)", fontFamily: "var(--font-mono)",
              }}>
                Impact: {chain.impact}
              </div>
            )}
          </div>
        ))}

        {tab === "validations" && result.finding_validations && (
          <div>
            {Object.entries(result.finding_validations).map(([fid, v]) => (
              <div key={fid} style={{
                display: "flex", gap: 12, alignItems: "center",
                padding: "8px 12px", borderBottom: "1px solid var(--border)",
                fontSize: "0.75rem", fontFamily: "var(--font-mono)",
              }}>
                <span style={{
                  padding: "2px 8px", fontSize: "0.65rem", fontWeight: 700,
                  background: v.verdict === "true_positive" ? "rgba(255,71,87,0.12)"
                    : v.verdict === "false_positive" ? "rgba(46,213,115,0.12)"
                    : "rgba(255,165,2,0.12)",
                  color: v.verdict === "true_positive" ? "var(--critical)"
                    : v.verdict === "false_positive" ? "var(--low)"
                    : "var(--medium)",
                  border: "1px solid currentColor",
                }}>
                  {v.verdict?.replace("_", " ").toUpperCase()}
                </span>
                <span style={{ color: "var(--text-dim)" }}>#{fid}</span>
                <span style={{ flex: 1, color: "var(--text)" }}>{v.reasoning}</span>
                {v.confidence != null && (
                  <span style={{ color: "var(--accent)" }}>{(v.confidence * 100).toFixed(0)}%</span>
                )}
                {/* PoC button for true positives in non-exploit mode */}
                {v.verdict === "true_positive" && mode !== "full_exploit" && (
                  <button
                    className="btn btn-ghost btn-sm"
                    disabled={pocLoading[fid]}
                    onClick={() => onRequestPoc(analysisId, parseInt(fid))}
                    style={{ fontSize: "0.6rem" }}
                  >
                    {pocLoading[fid] ? "..." : "Gen PoC"}
                  </button>
                )}
              </div>
            ))}
          </div>
        )}

        {tab === "remediation" && result.remediation_priority?.map((item, i) => (
          <div key={i} style={{
            display: "flex", gap: 12, padding: "8px 12px",
            borderBottom: "1px solid var(--border)", alignItems: "flex-start",
          }}>
            <span style={{
              fontFamily: "var(--font-mono)", fontWeight: 700,
              color: "var(--accent)", fontSize: "0.8rem", minWidth: 20,
            }}>{i + 1}</span>
            <div style={{ flex: 1 }}>
              <div style={{
                fontWeight: 600, fontSize: "0.8rem",
                color: "var(--text-bright)", marginBottom: 2,
              }}>
                {item.title || item.finding || `Item ${i + 1}`}
              </div>
              {item.action && (
                <div style={{ fontSize: "0.75rem", color: "var(--text)", lineHeight: 1.5 }}>
                  {item.action}
                </div>
              )}
              {item.effort && (
                <span style={{
                  fontFamily: "var(--font-mono)", fontSize: "0.6rem",
                  color: "var(--text-dim)",
                }}>
                  Effort: {item.effort}
                </span>
              )}
            </div>
          </div>
        ))}

        {tab === "poc" && result.poc_results && (
          <div>
            {Object.entries(result.poc_results).map(([fid, poc]) => (
              <div key={fid} style={{ marginBottom: 16 }}>
                <div style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  marginBottom: 6,
                }}>
                  <span style={{
                    fontFamily: "var(--font-mono)", fontSize: "0.72rem",
                    fontWeight: 700, color: "var(--text-bright)",
                  }}>
                    Finding #{fid} — {poc.language || "python"}
                  </span>
                  <button className="btn btn-ghost btn-sm" onClick={() => {
                    navigator.clipboard.writeText(poc.code);
                  }} style={{ fontSize: "0.6rem" }}>
                    Copy
                  </button>
                </div>
                {poc.description && (
                  <div style={{
                    fontSize: "0.72rem", color: "var(--text-dim)",
                    marginBottom: 6, fontStyle: "italic",
                  }}>
                    {poc.description}
                  </div>
                )}
                <div className="terminal" style={{ maxHeight: 300, overflow: "auto" }}>
                  <pre style={{
                    margin: 0, fontFamily: "var(--font-mono)",
                    fontSize: "0.7rem", whiteSpace: "pre-wrap",
                    color: "var(--text)",
                  }}>
                    {poc.code}
                  </pre>
                </div>
                {poc.disclaimer && (
                  <div style={{
                    fontSize: "0.6rem", color: "var(--medium)",
                    fontFamily: "var(--font-mono)", marginTop: 4,
                  }}>
                    ⚠ {poc.disclaimer}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}


/* ─── Main JobDetail Component ────────────────────────────────────────── */

export default function JobDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [sevFilter, setSevFilter] = useState("");
  const [expanded, setExpanded] = useState(new Set());
  // Per-finding PoC state
  const [findingPoc, setFindingPoc] = useState({});       // { findingId: { status, poc, error } }
  const [findingProviders, setFindingProviders] = useState([]);
  const [findingProvider, setFindingProvider] = useState("");

  async function load() {
    const d = await api(`/scan/jobs/${id}`);
    setData(d);
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [id]);

  // Load providers for per-finding analysis
  useEffect(() => {
    api("/ai/providers").then(d => {
      setFindingProviders(d.providers || []);
      if (d.providers?.length) setFindingProvider(d.providers[0].id);
    }).catch(() => {});
  }, []);

  // Generate PoC for a single finding: run a validate analysis then request PoC
  async function generateFindingPoc(findingId) {
    setFindingPoc(prev => ({ ...prev, [findingId]: { status: "running", poc: null, error: null } }));
    try {
      // Fetch provider on-demand if not yet loaded
      let prov = findingProvider;
      if (!prov) {
        const d = await api("/ai/providers");
        const provs = d.providers || [];
        if (!provs.length) throw new Error("No AI providers configured. Set API keys in .env");
        setFindingProviders(provs);
        prov = provs[0].id;
        setFindingProvider(prov);
      }

      // Check if there's already a done analysis for this job
      const histRes = await api(`/ai/results/${id}`);
      const doneAnalysis = (histRes.analyses || []).find(a => a.status === "done");

      let analysisId;
      if (doneAnalysis) {
        analysisId = doneAnalysis.id;
      } else {
        // Run a quick validate analysis first
        const r = await api("/ai/analyze", {
          method: "POST",
          body: { job_id: parseInt(id), provider: prov, mode: "validate" },
        });
        analysisId = r.analysis_id;
        // Wait for it to finish
        let tries = 0;
        while (tries < 120) {
          await new Promise(ok => setTimeout(ok, 3000));
          const s = await api(`/ai/status/${analysisId}`);
          if (s.status === "done") break;
          if (s.status === "failed") throw new Error(s.error || "Analysis failed");
          tries++;
        }
      }

      // Now request PoC for this specific finding
      await api("/ai/poc", {
        method: "POST",
        body: { analysis_id: analysisId, finding_id: findingId },
      });

      // Poll until PoC appears
      let tries = 0;
      while (tries < 40) {
        await new Promise(ok => setTimeout(ok, 3000));
        const s = await api(`/ai/status/${analysisId}`);
        const poc = s.result?.poc_results?.[String(findingId)];
        if (poc) {
          setFindingPoc(prev => ({ ...prev, [findingId]: { status: "done", poc, error: null } }));
          return;
        }
        tries++;
      }
      setFindingPoc(prev => ({ ...prev, [findingId]: { status: "done", poc: null, error: "Timed out waiting for PoC" } }));
    } catch (e) {
      setFindingPoc(prev => ({ ...prev, [findingId]: { status: "error", poc: null, error: e.message } }));
    }
  }

  if (!data) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 300 }}>
      <div className="spinner" style={{ width: 24, height: 24 }} />
    </div>
  );

  const job = data.job;
  const findings = (data.findings || []).filter(f => !sevFilter || f.severity === sevFilter);

  const counts = (data.findings || []).reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  function toggleRow(id) {
    setExpanded(s => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  }

  async function suppress(fp) {
    const reason = prompt("Suppression reason:");
    if (reason === null) return;
    try {
      await api("/scan/suppress", { method: "POST", body: { fingerprint: fp, reason } });
      await load();
    } catch (e) { alert(e.message); }
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Job <span className="accent">#{job.id}</span></div>
          <div className="page-desc">// {job.target} — {job.scan_type || "internal"} scan results</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <StatusDot status={job.status} />
          <span className="badge badge-info" style={{ fontSize: "0.6rem" }}>
            {job.scan_type === "external" ? "🌐 EXTERNAL" : "🏠 INTERNAL"}
          </span>
          <Link to="/jobs" className="btn btn-ghost">← Back</Link>
          <button className="btn btn-ghost" onClick={load}>↻ Refresh</button>
        </div>
      </div>

      {/* Error info for failed jobs */}
      {job.status === "failed" && job.error_info && (
        <div style={{
          padding: "16px 20px", marginBottom: 20,
          background: "rgba(255,71,87,0.06)", border: "1px solid rgba(255,71,87,0.2)",
        }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--critical)", marginBottom: 6 }}>
            ⚠ SCAN FAILED: {job.error_info.error_type || "unknown"}
          </div>
          <div style={{ fontSize: "0.85rem", color: "var(--text)", lineHeight: 1.6 }}>
            {job.error_info.error_detail || job.error_info.error}
          </div>
        </div>
      )}

      {/* Summary pills */}
      <div style={{ display: "flex", gap: 10, marginBottom: 24, flexWrap: "wrap" }}>
        {["critical","high","medium","low","info"].map(sev => (
          counts[sev] ? (
            <button
              key={sev}
              className={`btn btn-ghost btn-sm`}
              style={sevFilter === sev ? { borderColor: "var(--accent)", color: "var(--accent)" } : {}}
              onClick={() => setSevFilter(s => s === sev ? "" : sev)}
            >
              <SevBadge sev={sev} /> {counts[sev]}
            </button>
          ) : null
        ))}
        {sevFilter && (
          <button className="btn btn-ghost btn-sm" onClick={() => setSevFilter("")}>✕ Clear</button>
        )}
        <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: "0.68rem", color: "var(--text-dim)", alignSelf: "center" }}>
          {findings.length} / {(data.findings || []).length} findings
        </span>
      </div>

      {/* AI Deep Analysis panel — shown when job is done */}
      {job.status === "done" && (data.findings || []).length > 0 && (
        <AiPanel jobId={job.id} jobStatus={job.status} />
      )}

      {findings.length === 0 && (
        <div className="empty-state"><div className="empty-icon">◎</div>
          {job.status === "running" ? "Scan in progress..." : "No findings match the filter"}
        </div>
      )}

      {findings.map(f => {
        const isExp = expanded.has(f.id);
        let compliance = null;
        if (f.compliance_json) {
          try { compliance = JSON.parse(f.compliance_json); } catch {}
        }
        return (
          <div key={f.id} className="finding-row" style={{ overflow: "hidden" }}>
            <div
              style={{
                display: "flex", alignItems: "center", gap: 12,
                padding: "12px 16px", cursor: "pointer",
              }}
              onClick={() => toggleRow(f.id)}
            >
              <SevBadge sev={f.severity} />
              {f.is_kev && <span className="kev-chip">KEV</span>}
              <span style={{ flex: 1, fontWeight: 600, color: "var(--text-bright)", fontSize: "0.9rem" }}>{f.title}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.62rem", color: "var(--text-dim)", marginRight: 8 }}>{f.plugin_id}</span>
              <RiskBar score={f.risk_score} />
              <span style={{ color: "var(--text-dim)", marginLeft: 8 }}>{isExp ? "▴" : "▾"}</span>
            </div>

            {isExp && (
              <div style={{
                padding: "12px 16px 16px",
                borderTop: "1px solid var(--border)",
                animation: "fadeIn 0.15s ease both",
              }}>
                {/* Metrics row */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
                  {[
                    ["Risk Score", f.risk_score?.toFixed(2) ?? "—"],
                    ["CVSS Base", f.cvss_base ?? "—"],
                    ["Confidence", f.confidence ? (f.confidence * 100).toFixed(0) + "%" : "—"],
                    ["SLA", f.sla_days ? f.sla_days + " days" : "—"],
                  ].map(([label, val]) => (
                    <div key={label} style={{ padding: 10, background: "var(--surface3)", border: "1px solid var(--border)" }}>
                      <div className="form-label">{label}</div>
                      <div className="mono text-bright" style={{ fontSize: "1.1rem" }}>{val}</div>
                    </div>
                  ))}
                </div>

                {/* Description */}
                {f.description && (
                  <div style={{ marginBottom: 14 }}>
                    <div className="form-label" style={{ marginBottom: 6 }}>Description</div>
                    <div style={{
                      fontSize: "0.85rem", color: "var(--text)", lineHeight: 1.7,
                      whiteSpace: "pre-line",
                      padding: "12px 14px",
                      background: "var(--surface3)",
                      border: "1px solid var(--border)",
                    }}>
                      {f.description}
                    </div>
                  </div>
                )}

                {/* Remediation — prominent display */}
                {f.remediation && (
                  <div style={{ marginBottom: 14 }}>
                    <div className="form-label" style={{
                      marginBottom: 6,
                      color: "var(--low)",
                      display: "flex", alignItems: "center", gap: 6,
                    }}>
                      <span>🛡</span> Remediation Steps
                    </div>
                    <div style={{
                      fontSize: "0.85rem", color: "var(--text)", lineHeight: 1.7,
                      whiteSpace: "pre-line",
                      padding: "14px 16px",
                      background: "rgba(46,213,115,0.04)",
                      border: "1px solid rgba(46,213,115,0.15)",
                      borderLeft: "3px solid var(--low)",
                    }}>
                      {f.remediation}
                    </div>
                  </div>
                )}

                {/* Evidence */}
                {f.evidence && (
                  <div style={{ marginBottom: 14 }}>
                    <div className="form-label" style={{ marginBottom: 6 }}>Evidence</div>
                    <div className="terminal" style={{ maxHeight: 100 }}>
                      <div className="terminal-line">{f.evidence}</div>
                    </div>
                  </div>
                )}

                {/* Compliance mapping */}
                {compliance && compliance.length > 0 && (
                  <div style={{ marginBottom: 14 }}>
                    <div className="form-label" style={{ marginBottom: 6 }}>Compliance Mapping</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {(Array.isArray(compliance) ? compliance : Object.entries(compliance).map(([k,v]) => `${k}: ${v}`)).map((c, i) => (
                        <span key={i} className="badge badge-info">{typeof c === 'string' ? c : JSON.stringify(c)}</span>
                      ))}
                    </div>
                  </div>
                )}

                <div style={{ display: "flex", gap: 8, marginTop: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <button className="btn btn-ghost btn-sm" onClick={() => suppress(f.fingerprint)}>
                    ⊗ Suppress
                  </button>
                  {/* Per-finding AI PoC generation — always visible when job is done */}
                  {job.status === "done" && (
                    <>
                      <div style={{ width: 1, height: 20, background: "var(--border)", margin: "0 4px" }} />
                      {findingProviders.length > 1 && (
                        <select
                          value={findingProvider}
                          onChange={e => setFindingProvider(e.target.value)}
                          disabled={findingPoc[f.id]?.status === "running"}
                          style={{
                            background: "var(--surface3)", color: "var(--text)",
                            border: "1px solid var(--border)", padding: "3px 6px",
                            fontFamily: "var(--font-mono)", fontSize: "0.62rem",
                          }}
                        >
                          {findingProviders.map(p => (
                            <option key={p.id} value={p.id}>{p.name || p.id}</option>
                          ))}
                        </select>
                      )}
                      <button
                        className="btn btn-ghost btn-sm"
                        disabled={findingPoc[f.id]?.status === "running"}
                        onClick={() => generateFindingPoc(f.id)}
                        style={{
                          fontSize: "0.65rem",
                          color: findingPoc[f.id]?.status === "running" ? "var(--text-dim)" : "var(--accent)",
                        }}
                      >
                        {findingPoc[f.id]?.status === "running" ? "⏳ Generating..." : "🤖 Generate PoC"}
                      </button>
                    </>
                  )}
                </div>

                {/* Per-finding PoC error */}
                {findingPoc[f.id]?.error && (
                  <div style={{
                    marginTop: 8, padding: "6px 10px",
                    background: "rgba(255,71,87,0.08)", border: "1px solid rgba(255,71,87,0.2)",
                    fontFamily: "var(--font-mono)", fontSize: "0.68rem", color: "var(--critical)",
                  }}>
                    ⚠ {findingPoc[f.id].error}
                  </div>
                )}

                {/* Per-finding PoC result */}
                {findingPoc[f.id]?.poc && (
                  <div style={{ marginTop: 12 }}>
                    <div style={{
                      display: "flex", justifyContent: "space-between", alignItems: "center",
                      marginBottom: 6,
                    }}>
                      <div className="form-label" style={{
                        color: "var(--accent)", display: "flex", alignItems: "center", gap: 6,
                      }}>
                        <span>🤖</span> AI-Generated PoC — {findingPoc[f.id].poc.language || "python"}
                      </div>
                      <button className="btn btn-ghost btn-sm" onClick={() => {
                        navigator.clipboard.writeText(findingPoc[f.id].poc.code);
                      }} style={{ fontSize: "0.6rem" }}>
                        Copy
                      </button>
                    </div>
                    {findingPoc[f.id].poc.description && (
                      <div style={{
                        fontSize: "0.72rem", color: "var(--text-dim)",
                        marginBottom: 6, fontStyle: "italic",
                      }}>
                        {findingPoc[f.id].poc.description}
                      </div>
                    )}
                    <div className="terminal" style={{ maxHeight: 300, overflow: "auto" }}>
                      <pre style={{
                        margin: 0, fontFamily: "var(--font-mono)",
                        fontSize: "0.7rem", whiteSpace: "pre-wrap",
                        color: "var(--text)",
                      }}>
                        {findingPoc[f.id].poc.code}
                      </pre>
                    </div>
                    {findingPoc[f.id].poc.disclaimer && (
                      <div style={{
                        fontSize: "0.6rem", color: "var(--medium)",
                        fontFamily: "var(--font-mono)", marginTop: 4,
                      }}>
                        ⚠ {findingPoc[f.id].poc.disclaimer}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

