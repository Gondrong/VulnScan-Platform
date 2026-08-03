import React, { useState, useEffect, useCallback } from "react";
import { Icons } from "./icons.jsx";
import { analyticsApi, scanApi } from "../api.js";
import { SevBadge, Spinner, EmptyState, Panel } from "../components/ui.jsx";

// ── Helpers ────────────────────────────────────────────────────────────
const SEV_COLORS = {
  critical: "var(--sev-critical, #e74c3c)",
  high:     "var(--sev-high, #e67e22)",
  medium:   "var(--sev-medium, #f1c40f)",
  low:      "var(--sev-low, #2ecc71)",
  info:     "var(--sev-info, #3498db)",
};

function fmtDate(dt) {
  if (!dt) return "\u2014";
  try { return new Date(dt).toISOString().replace("T", " ").slice(0, 16); }
  catch { return String(dt); }
}

// ── Tab wrapper ────────────────────────────────────────────────────────
function Tabs({ tabs, active, onChange }) {
  return (
    <div style={{ display: "flex", gap: 2, borderBottom: "1px solid var(--line)", marginBottom: 20, flexWrap: "wrap" }}>
      {tabs.map(t => (
        <button key={t.id}
          className={active === t.id ? "btn btn-primary" : "btn"}
          style={{ borderRadius: "6px 6px 0 0", fontSize: 13 }}
          onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ── Collapsible section ────────────────────────────────────────────────
function Collapsible({ title, color, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ border: `1px solid ${color}`, borderRadius: 8, marginBottom: 12, overflow: "hidden" }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          padding: "10px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 8,
          background: color + "18", fontWeight: 600, fontSize: 13, color: "var(--text-0)",
        }}>
        {open ? <Icons.ChevronDown size={14}/> : <Icons.ChevronRight size={14}/>}
        {title}
      </div>
      {open && <div style={{ padding: 14 }}>{children}</div>}
    </div>
  );
}

// ── Stat card ──────────────────────────────────────────────────────────
function StatCard({ label, value, sub }) {
  return (
    <div className="card" style={{ flex: "1 1 180px", minWidth: 160 }}>
      <div className="card-body" style={{ padding: "16px 20px" }}>
        <div style={{ fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>{label}</div>
        <div style={{ fontSize: 28, fontWeight: 700, color: "var(--text-0)", fontFamily: "var(--font-display)" }}>{value ?? "\u2014"}</div>
        {sub && <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 4 }}>{sub}</div>}
      </div>
    </div>
  );
}

// ======================================================================
// Tab 1: Executive Dashboard
// ======================================================================
function ExecutiveTab() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    analyticsApi.executive()
      .then(r => { if (!cancelled) setData(r); })
      .catch(e => { if (!cancelled) setError(e.message || "Failed to load executive data"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <Spinner/>;
  if (error) return <div className="alert alert-error">{error}</div>;
  if (!data) return <EmptyState text="No executive data available"/>;

  const rp = data.risk_posture || {};
  const sla = data.sla_compliance || {};
  const topVulns = data.top_10_vulns || [];
  const categories = data.findings_by_category || {};
  const scans = data.scan_activity || {};

  const critHigh = (rp.critical || 0) + (rp.high || 0);
  const totalFindings = rp.total_findings || 0;
  const riskAvg = rp.risk_score_avg != null ? Number(rp.risk_score_avg).toFixed(1) : "\u2014";
  const slaBreached = sla.breached || 0;

  return (
    <>
      {/* Stat cards */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 20 }}>
        <StatCard label="Total Findings" value={totalFindings}/>
        <StatCard label="Critical + High" value={critHigh}/>
        <StatCard label="Risk Score Avg" value={riskAvg}/>
        <StatCard label="SLA Breached" value={slaBreached}/>
      </div>

      {/* Top 10 Vulnerabilities */}
      <Panel title="Top 10 Vulnerabilities">
        {topVulns.length === 0
          ? <EmptyState text="No vulnerabilities found"/>
          : (
            <div style={{ overflowX: "auto" }}>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Target</th>
                  </tr>
                </thead>
                <tbody>
                  {topVulns.slice(0, 10).map((v, i) => (
                    <tr key={i}>
                      <td>{v.title || v.name || "\u2014"}</td>
                      <td><SevBadge sev={v.severity}/></td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>{v.risk_score != null ? Number(v.risk_score).toFixed(1) : "\u2014"}</td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{v.target || "\u2014"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </Panel>

      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 16 }}>
        {/* Findings by Category */}
        <div style={{ flex: "1 1 300px" }}>
          <Panel title="Findings by Category">
            {Object.keys(categories).length === 0
              ? <EmptyState text="No category data"/>
              : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {Object.entries(categories).map(([cat, count]) => {
                    const maxCount = Math.max(...Object.values(categories), 1);
                    const pct = Math.round((count / maxCount) * 100);
                    return (
                      <div key={cat} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <span style={{ width: 60, fontSize: 12, fontWeight: 600, color: "var(--text-2)", textTransform: "uppercase" }}>{cat}</span>
                        <div style={{ flex: 1, height: 20, background: "var(--surface-2)", borderRadius: 4, overflow: "hidden" }}>
                          <div style={{ width: `${pct}%`, height: "100%", background: "var(--brand)", borderRadius: 4, transition: "width 0.3s" }}/>
                        </div>
                        <span style={{ width: 40, textAlign: "right", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-1)" }}>{count}</span>
                      </div>
                    );
                  })}
                </div>
              )
            }
          </Panel>
        </div>

        {/* Scan Activity */}
        <div style={{ flex: "1 1 260px" }}>
          <Panel title="Scan Activity">
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text-3)" }}>Total scans</span>
                <span style={{ fontWeight: 600, color: "var(--text-0)" }}>{scans.total_scans ?? "\u2014"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text-3)" }}>Completed</span>
                <span style={{ fontWeight: 600, color: "var(--low, #2ecc71)" }}>{scans.completed ?? "\u2014"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text-3)" }}>Failed</span>
                <span style={{ fontWeight: 600, color: "var(--critical, #e74c3c)" }}>{scans.failed ?? "\u2014"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text-3)" }}>Last scan</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-2)" }}>{fmtDate(scans.last_scan_date)}</span>
              </div>
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

// ======================================================================
// Tab 2: Vulnerability Trending
// ======================================================================
function TrendingTab() {
  const [days, setDays] = useState(30);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async (d) => {
    setLoading(true);
    setError("");
    try {
      const interval = d <= 7 ? "daily" : d <= 30 ? "daily" : "weekly";
      const r = await analyticsApi.trending(d, interval);
      setData(r);
    } catch (e) {
      setError(e.message || "Failed to load trending data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(days); }, [days, load]);

  const DAY_OPTIONS = [
    { label: "7d", value: 7 },
    { label: "30d", value: 30 },
    { label: "90d", value: 90 },
  ];

  return (
    <>
      <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
        {DAY_OPTIONS.map(opt => (
          <button key={opt.value}
            className={days === opt.value ? "btn btn-primary" : "btn"}
            onClick={() => setDays(opt.value)}>
            {opt.label}
          </button>
        ))}
      </div>

      {loading && <Spinner/>}
      {error && <div className="alert alert-error">{error}</div>}

      {!loading && !error && data && (() => {
        const buckets = data.series || data.buckets || data.data || [];
        const mttr = data.mean_time_to_remediate_days ?? data.mttr;

        if (buckets.length === 0) return <EmptyState text="No trending data for this period"/>;

        const maxCount = Math.max(...buckets.map(b => b.total || b.count || 0), 1);

        return (
          <>
            {mttr != null && (
              <div style={{ marginBottom: 16 }}>
                <StatCard label="Mean Time to Remediate" value={typeof mttr === "number" ? `${mttr.toFixed(1)}d` : mttr}/>
              </div>
            )}

            <Panel title="Findings Over Time">
              <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 200, padding: "0 4px", overflowX: "auto" }}>
                {buckets.map((b, i) => {
                  const count = b.total || b.count || 0;
                  const barH = Math.max(4, (count / maxCount) * 180);
                  // Severity counts are directly on the bucket object
                  const segments = ["critical", "high", "medium", "low", "info"]
                    .filter(s => b[s])
                    .map(s => ({ sev: s, val: b[s] }));
                  if (segments.length === 0) segments.push({ sev: "info", val: count });
                  const segTotal = segments.reduce((a, s) => a + s.val, 0) || 1;

                  const tooltipLines = segments.map(s => `${s.sev}: ${s.val}`).join(", ");
                  const tooltipText = `${b.date || b.period || ""}\nTotal: ${count}\n${tooltipLines}`;

                  return (
                    <div key={i} style={{ display: "flex", flexDirection: "column", alignItems: "center", flex: "1 1 0", minWidth: 32 }}>
                      {/* Total count above bar */}
                      <div style={{ fontSize: 10, fontWeight: 600, color: "var(--text-2)", marginBottom: 3, fontFamily: "var(--font-mono)" }}>
                        {count}
                      </div>
                      <div style={{ width: "100%", maxWidth: 44, height: barH, display: "flex", flexDirection: "column", borderRadius: "3px 3px 0 0", overflow: "hidden", cursor: "default" }}
                           title={tooltipText}>
                        {segments.map((seg, si) => (
                          <div key={si} style={{
                            flex: `${seg.val / segTotal}`,
                            background: SEV_COLORS[seg.sev] || "var(--brand)",
                            position: "relative",
                            display: "flex", alignItems: "center", justifyContent: "center",
                            minHeight: seg.val / segTotal > 0.15 ? 16 : 0,
                          }}>
                            {/* Show count inside segment if tall enough */}
                            {(seg.val / segTotal > 0.15 && seg.val > 0) && (
                              <span style={{ fontSize: 9, fontWeight: 700, color: "#fff", textShadow: "0 0 2px rgba(0,0,0,0.5)" }}>
                                {seg.val}
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                      <div style={{ fontSize: 9, color: "var(--text-3)", marginTop: 4, textAlign: "center", width: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {(b.date || b.period || "").slice(-5)}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Legend with totals */}
              {(() => {
                const totals = {};
                buckets.forEach(b => {
                  ["critical","high","medium","low","info"].forEach(s => { totals[s] = (totals[s]||0) + (b[s]||0); });
                });
                return (
                  <div style={{ display: "flex", gap: 16, marginTop: 14, flexWrap: "wrap" }}>
                    {["critical", "high", "medium", "low", "info"].map(s => (
                      <div key={s} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 12 }}>
                        <span style={{ width: 10, height: 10, borderRadius: 2, background: SEV_COLORS[s], display: "inline-block" }}/>
                        <span style={{ color: "var(--text-2)", textTransform: "capitalize" }}>{s}</span>
                        <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "var(--text-1)" }}>{totals[s] || 0}</span>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </Panel>
          </>
        );
      })()}
    </>
  );
}

// ======================================================================
// Tab 3: Scan Comparison
// ======================================================================
function CompareTab() {
  const [jobs, setJobs] = useState([]);
  const [jobA, setJobA] = useState("");
  const [jobB, setJobB] = useState("");
  const [loading, setLoading] = useState(false);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  useEffect(() => {
    let cancelled = false;
    scanApi.listJobs()
      .then(r => { if (!cancelled) setJobs(Array.isArray(r) ? r : []); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setJobsLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const runCompare = async () => {
    if (!jobA || !jobB) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const [diff, compare] = await Promise.all([
        analyticsApi.diff(jobA, jobB),
        analyticsApi.compare(jobA, jobB),
      ]);
      setResult({ diff, compare });
    } catch (e) {
      setError(e.message || "Comparison failed");
    } finally {
      setLoading(false);
    }
  };

  const completedJobs = jobs.filter(j => j.status === "done" || j.status === "completed");

  return (
    <>
      <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 20 }}>
        <div style={{ flex: "1 1 200px" }}>
          <label className="form-label">Job A (baseline)</label>
          {jobsLoading ? <Spinner/> : (
            <select className="form-input" value={jobA} onChange={e => setJobA(e.target.value)}>
              <option value="">Select a job...</option>
              {completedJobs.map(j => (
                <option key={j.id} value={j.id}>#{j.id} - {j.target || j.targets?.join(", ") || "unknown"}</option>
              ))}
            </select>
          )}
        </div>
        <div style={{ flex: "1 1 200px" }}>
          <label className="form-label">Job B (current)</label>
          {jobsLoading ? <Spinner/> : (
            <select className="form-input" value={jobB} onChange={e => setJobB(e.target.value)}>
              <option value="">Select a job...</option>
              {completedJobs.map(j => (
                <option key={j.id} value={j.id}>#{j.id} - {j.target || j.targets?.join(", ") || "unknown"}</option>
              ))}
            </select>
          )}
        </div>
        <button className="btn btn-primary" onClick={runCompare} disabled={!jobA || !jobB || loading}>
          {loading ? "Comparing..." : "Compare"}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {result && (() => {
        const diff = result.diff || {};
        const compare = result.compare || {};
        const summary = compare.summary || diff.summary || {};
        const newFindings = diff.new || compare.new || [];
        const fixedFindings = diff.fixed || compare.fixed || [];
        const changedFindings = diff.changed_severity || diff.changed || [];

        return (
          <>
            {/* Summary cards */}
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 20 }}>
              <StatCard label="Improvement" value={summary.improvement_pct != null ? `${Number(summary.improvement_pct).toFixed(1)}%` : "\u2014"}/>
              <StatCard label="New Findings" value={newFindings.length}/>
              <StatCard label="Fixed Findings" value={fixedFindings.length}/>
            </div>

            {/* New findings */}
            <Collapsible title={`New Findings (${newFindings.length})`} color="var(--critical, #e74c3c)" defaultOpen={newFindings.length > 0}>
              {newFindings.length === 0
                ? <span style={{ fontSize: 13, color: "var(--text-3)" }}>No new findings</span>
                : newFindings.map((f, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
                      <SevBadge sev={f.severity}/>
                      <span style={{ flex: 1, fontSize: 13, color: "var(--text-1)" }}>{f.title || f.name || "\u2014"}</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-3)" }}>{f.fingerprint || ""}</span>
                    </div>
                  ))
              }
            </Collapsible>

            {/* Fixed findings */}
            <Collapsible title={`Fixed Findings (${fixedFindings.length})`} color="var(--low, #2ecc71)" defaultOpen={fixedFindings.length > 0}>
              {fixedFindings.length === 0
                ? <span style={{ fontSize: 13, color: "var(--text-3)" }}>No fixed findings</span>
                : fixedFindings.map((f, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
                      <SevBadge sev={f.severity}/>
                      <span style={{ flex: 1, fontSize: 13, color: "var(--text-1)" }}>{f.title || f.name || "\u2014"}</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-3)" }}>{f.fingerprint || ""}</span>
                    </div>
                  ))
              }
            </Collapsible>

            {/* Changed severity */}
            <Collapsible title={`Changed Severity (${changedFindings.length})`} color="var(--medium, #f1c40f)">
              {changedFindings.length === 0
                ? <span style={{ fontSize: 13, color: "var(--text-3)" }}>No severity changes</span>
                : changedFindings.map((f, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
                      <SevBadge sev={f.severity || f.new_severity}/>
                      <span style={{ flex: 1, fontSize: 13, color: "var(--text-1)" }}>{f.title || f.name || "\u2014"}</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-3)" }}>{f.fingerprint || ""}</span>
                    </div>
                  ))
              }
            </Collapsible>
          </>
        );
      })()}
    </>
  );
}

// ======================================================================
// Tab 4: Asset Discovery
// ======================================================================
function DiscoverTab() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [results, setResults] = useState(null);

  const run = async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError("");
    setResults(null);
    try {
      // Detect if input is CIDR (contains /) or domain
      const val = input.trim();
      const body = val.includes("/") ? { network_range: val } : { domain: val };
      const r = await analyticsApi.discover(body);
      setResults(r);
    } catch (e) {
      setError(e.message || "Discovery failed");
    } finally {
      setLoading(false);
    }
  };

  // Domain response has 'discovered' array, CIDR response has network metadata
  const targets = results?.discovered || results?.targets || results?.hosts || [];
  const isCidr = results?.type === "network";

  return (
    <>
      <div style={{ display: "flex", gap: 10, alignItems: "flex-end", marginBottom: 20, flexWrap: "wrap" }}>
        <div style={{ flex: "1 1 300px" }}>
          <label className="form-label">Domain or CIDR range</label>
          <input className="form-input"
            placeholder="e.g. example.com or 192.168.1.0/24"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter") run(); }}
          />
        </div>
        <button className="btn btn-primary" onClick={run} disabled={!input.trim() || loading}>
          {loading ? "Discovering..." : "Discover"}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {loading && <Spinner/>}

      {!loading && results && (
        <Panel title={isCidr ? `Network: ${results.network_range}` : `Discovered Targets (${targets.length})`}>
          {isCidr ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 13, color: "var(--text-1)" }}>
              <div>Range: <strong>{results.network_range}</strong></div>
              <div>Addresses: <strong>{results.num_addresses}</strong></div>
              <div>First IP: <code>{results.first_ip}</code></div>
              <div>Last IP: <code>{results.last_ip}</code></div>
              <div>Prefix: /{results.prefix_len}</div>
            </div>
          ) : targets.length === 0
            ? <EmptyState text="No targets discovered"/>
            : (
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {targets.map((t, i) => {
                  const label = typeof t === "string" ? t
                    : t.hostname ? `${t.hostname}${t.ips?.length ? " → " + t.ips.join(", ") : ""}`
                    : (t.host || t.ip || t.target || JSON.stringify(t));
                  return (
                    <div key={i} style={{
                      padding: "8px 12px", background: "var(--surface-1)", borderRadius: 6,
                      fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-1)",
                    }}>
                      {label}
                    </div>
                  );
                })}
              </div>
            )
          }
        </Panel>
      )}
    </>
  );
}

// ======================================================================
// Tab 5: Re-verification
// ======================================================================
function ReverifyTab() {
  const [jobs, setJobs] = useState([]);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [selectedJob, setSelectedJob] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [newJobId, setNewJobId] = useState(null);

  useEffect(() => {
    let cancelled = false;
    scanApi.listJobs()
      .then(r => { if (!cancelled) setJobs(Array.isArray(r) ? r : []); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setJobsLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const run = async () => {
    if (!selectedJob) return;
    setLoading(true);
    setError("");
    setNewJobId(null);
    try {
      const r = await analyticsApi.reverify(selectedJob);
      setNewJobId(r.job_id || r.id || r.new_job_id || JSON.stringify(r));
    } catch (e) {
      setError(e.message || "Re-verification failed");
    } finally {
      setLoading(false);
    }
  };

  const completedJobs = jobs.filter(j => j.status === "done" || j.status === "completed");

  return (
    <>
      <div style={{ display: "flex", gap: 10, alignItems: "flex-end", marginBottom: 20, flexWrap: "wrap" }}>
        <div style={{ flex: "1 1 300px" }}>
          <label className="form-label">Completed scan job</label>
          {jobsLoading ? <Spinner/> : (
            <select className="form-input" value={selectedJob} onChange={e => setSelectedJob(e.target.value)}>
              <option value="">Select a completed job...</option>
              {completedJobs.map(j => (
                <option key={j.id} value={j.id}>#{j.id} - {j.target || j.targets?.join(", ") || "unknown"}</option>
              ))}
            </select>
          )}
        </div>
        <button className="btn btn-primary" onClick={run} disabled={!selectedJob || loading}>
          {loading ? "Re-verifying..." : "Re-verify Findings"}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {newJobId && (
        <div className="alert alert-success" style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Icons.Check size={16}/>
          Re-verification job created: <strong style={{ fontFamily: "var(--font-mono)" }}>#{newJobId}</strong>
        </div>
      )}
    </>
  );
}

// ======================================================================
// Main Analytics component
// ======================================================================
const TABS = [
  { id: "executive",  label: "Executive Dashboard" },
  { id: "trending",   label: "Vulnerability Trending" },
  { id: "compare",    label: "Scan Comparison" },
  { id: "discover",   label: "Asset Discovery" },
  { id: "reverify",   label: "Re-verification" },
];

export function Analytics() {
  const [activeTab, setActiveTab] = useState("executive");

  return (
    <div>
      <Tabs tabs={TABS} active={activeTab} onChange={setActiveTab}/>

      {activeTab === "executive" && <ExecutiveTab/>}
      {activeTab === "trending"  && <TrendingTab/>}
      {activeTab === "compare"   && <CompareTab/>}
      {activeTab === "discover"  && <DiscoverTab/>}
      {activeTab === "reverify"  && <ReverifyTab/>}
    </div>
  );
}
