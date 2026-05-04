import React, { useState, useEffect, useCallback, useRef } from "react";
import { Icons } from "./icons.jsx";
import { threatIntelApi } from "../api.js";

const SORT_OPTIONS = [
  { id: "threat_score", label: "Threat score"  },
  { id: "cvss",         label: "CVSS"          },
  { id: "epss",         label: "EPSS"          },
  { id: "kev_due",      label: "KEV due date"  },
  { id: "kev_added",    label: "KEV added date"},
];

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low"];

export function ThreatIntel() {
  const [stats, setStats] = useState(null);
  const [loadingStats, setLoadingStats] = useState(true);

  const [filters, setFilters] = useState({
    q: "",
    severity: new Set(["critical", "high"]),
    kev_only: false,
    ransomware_only: false,
    min_epss: 0,
    sort: "threat_score",
    order: "desc",
    page: 1,
    per_page: 50,
  });

  const [results, setResults] = useState({ cves: [], total: 0, page: 1, total_pages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);
  const debounceRef = useRef(null);

  // Normalize whatever the /threat-intel/cves endpoint returns so the rest
  // of the component never has to defend against missing fields. Guards
  // against: 200 with empty body, partial responses, reverse-proxy injected
  // HTML, accidentally-stringified payloads, etc.
  const normalizeListResponse = (r) => ({
    cves:        Array.isArray(r?.cves)              ? r.cves        : [],
    total:       Number.isFinite(r?.total)           ? r.total       : 0,
    page:        Number.isFinite(r?.page)            ? r.page        : 1,
    total_pages: Number.isFinite(r?.total_pages)     ? r.total_pages : 1,
  });

  // Load stats once
  const loadStats = useCallback(async () => {
    setLoadingStats(true);
    try { setStats(await threatIntelApi.stats()); }
    catch (e) { /* stats failures aren't fatal */ }
    finally { setLoadingStats(false); }
  }, []);

  useEffect(() => { loadStats(); }, [loadStats]);

  // Build the API params from current filters
  const buildParams = useCallback((f) => {
    const sev = [...f.severity].join(",");
    return {
      q: f.q,
      severity: sev || undefined,
      kev_only: f.kev_only || undefined,
      ransomware_only: f.ransomware_only || undefined,
      min_epss: f.min_epss > 0 ? f.min_epss : undefined,
      sort: f.sort,
      order: f.order,
      page: f.page,
      per_page: f.per_page,
    };
  }, []);

  const loadResults = useCallback(async (f) => {
    setLoading(true);
    setError("");
    try {
      const r = await threatIntelApi.list(buildParams(f));
      setResults(normalizeListResponse(r));
    } catch (e) {
      setError(e.message || "Failed to load CVEs");
      setResults(normalizeListResponse(null));
    } finally {
      setLoading(false);
    }
  }, [buildParams]);

  // Debounced re-fetch when filters change
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => loadResults(filters), 250);
    return () => clearTimeout(debounceRef.current);
  }, [filters, loadResults]);

  const updateFilter = (patch) => setFilters(f => ({ ...f, ...patch, page: patch.page ?? 1 }));
  const toggleSeverity = (s) => setFilters(f => {
    const n = new Set(f.severity);
    n.has(s) ? n.delete(s) : n.add(s);
    return { ...f, severity: n, page: 1 };
  });

  const refreshCache = async () => {
    setLoading(true);
    try {
      await threatIntelApi.refresh();
      await Promise.all([loadStats(), loadResults(filters)]);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <>
      <div className="ph">
        <div>
          <h1>Threat <span style={{color: "var(--brand)"}}>Intel</span></h1>
          <div className="sub">
            CVEs fused from NVD + EPSS + CISA KEV. Sort by composite threat score to focus on what's most likely to hurt you.
          </div>
        </div>
        <div className="actions">
          <button className="btn" onClick={refreshCache} disabled={loading}>
            <Icons.Refresh size={13} className={loading ? "spin" : ""}/> Refresh cache
          </button>
        </div>
      </div>

      {/* ── Stat tiles ─────────────────────────────────────────────── */}
      <StatsRow stats={stats} loading={loadingStats}/>

      {/* ── Filter bar ─────────────────────────────────────────────── */}
      <div style={{
        background: "var(--surface-0)", border: "1px solid var(--line)",
        borderRadius: 10, padding: 14, marginTop: 14,
      }}>
        <div style={{display: "grid", gridTemplateColumns: "1fr auto auto auto", gap: 10, alignItems: "end"}}>
          <div>
            <label className="form-label">Search</label>
            <input className="form-input" placeholder="CVE-ID, vendor, product, summary…"
                   value={filters.q} onChange={e => updateFilter({q: e.target.value})}/>
          </div>
          <div>
            <label className="form-label">Sort by</label>
            <select className="form-input" value={filters.sort} onChange={e => updateFilter({sort: e.target.value})} style={{minWidth: 160}}>
              {SORT_OPTIONS.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
            </select>
          </div>
          <div>
            <label className="form-label">Order</label>
            <select className="form-input" value={filters.order} onChange={e => updateFilter({order: e.target.value})} style={{minWidth: 110}}>
              <option value="desc">Highest first</option>
              <option value="asc">Lowest first</option>
            </select>
          </div>
          <div>
            <label className="form-label">Per page</label>
            <select className="form-input" value={filters.per_page}
                    onChange={e => updateFilter({per_page: parseInt(e.target.value)})}
                    style={{minWidth: 90}}>
              <option>25</option><option>50</option><option>100</option><option>200</option>
            </select>
          </div>
        </div>

        <div style={{display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12, alignItems: "center"}}>
          <span style={{fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.04em"}}>
            Severity:
          </span>
          {SEVERITY_OPTIONS.map(s => {
            const on = filters.severity.has(s);
            return (
              <button key={s} className={`btn btn-sm ${on ? "btn-primary" : ""}`}
                      onClick={() => toggleSeverity(s)} style={{textTransform: "capitalize", fontSize: 11.5, padding: "3px 10px"}}>
                {on && <Icons.Check size={10}/>} {s}
              </button>
            );
          })}

          <span style={{width: 1, height: 20, background: "var(--line)", margin: "0 4px"}}/>

          <button className={`btn btn-sm ${filters.kev_only ? "btn-primary" : ""}`}
                  onClick={() => updateFilter({kev_only: !filters.kev_only})}
                  style={{fontSize: 11.5, padding: "3px 10px"}}>
            {filters.kev_only && <Icons.Check size={10}/>} CISA KEV only
          </button>
          <button className={`btn btn-sm ${filters.ransomware_only ? "btn-primary" : ""}`}
                  onClick={() => updateFilter({ransomware_only: !filters.ransomware_only})}
                  style={{fontSize: 11.5, padding: "3px 10px"}}>
            {filters.ransomware_only && <Icons.Check size={10}/>} Ransomware-known
          </button>

          <span style={{width: 1, height: 20, background: "var(--line)", margin: "0 4px"}}/>

          <span style={{fontSize: 11.5, color: "var(--text-2)"}}>EPSS ≥</span>
          <select className="form-input" value={filters.min_epss}
                  onChange={e => updateFilter({min_epss: parseFloat(e.target.value)})}
                  style={{padding: "3px 8px", height: 26, fontSize: 11.5, width: 80}}>
            <option value={0}>0%</option>
            <option value={0.1}>10%</option>
            <option value={0.25}>25%</option>
            <option value={0.5}>50%</option>
            <option value={0.75}>75%</option>
            <option value={0.9}>90%</option>
          </select>

          <span style={{flex: 1}}/>
          <span style={{fontSize: 12, color: "var(--text-3)"}}>
            {(results?.total ?? 0).toLocaleString()} CVEs match
          </span>
        </div>
      </div>

      {/* ── Results table ──────────────────────────────────────────── */}
      <div style={{
        background: "var(--surface-0)", border: "1px solid var(--line)",
        borderRadius: 10, marginTop: 14, overflow: "hidden",
      }}>
        {error && (
          <div style={{padding: "12px 16px", color: "var(--err)", fontSize: 13, borderBottom: "1px solid var(--line)"}}>
            <Icons.AlertTriangle size={13}/> {error}
          </div>
        )}
        <CVETable rows={results.cves} loading={loading} onSelect={setSelected}/>
        <Pagination
          page={results.page} totalPages={results.total_pages}
          onPage={(p) => updateFilter({page: p})}
        />
      </div>

      {selected && <CVEDrawer cveId={selected} close={() => setSelected(null)}/>}
    </>
  );
}

// ─── Stats tiles ────────────────────────────────────────────────────────────

function StatsRow({ stats, loading }) {
  if (loading || !stats) {
    return (
      <div style={{display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginTop: 14}}>
        {[1,2,3,4].map(i => (
          <div key={i} style={{background: "var(--surface-0)", border: "1px solid var(--line)", borderRadius: 10, padding: 16, height: 88}}>
            <div style={{height: 12, width: "60%", background: "var(--surface-2)", borderRadius: 3, opacity: 0.6}}/>
            <div style={{height: 24, width: "40%", marginTop: 8, background: "var(--surface-2)", borderRadius: 3, opacity: 0.6}}/>
          </div>
        ))}
      </div>
    );
  }

  const tiles = [
    { label: "CVEs in catalog",       value: stats.total_cves,         hint: `${(stats.datasets_loaded||[]).join(" + ") || "no datasets"} loaded` },
    { label: "CISA KEV listed",       value: stats.kev_count,          hint: `${stats.new_kev_7d || 0} added in last 7 days`, accent: "var(--brand)" },
    { label: "KEV due within 7 days", value: stats.kev_due_within_7d,  hint: "Federal SLA approaching",                       accent: "#e8a03c" },
    { label: "Ransomware-known",      value: stats.ransomware_count,   hint: "Patch first — confirmed in ransomware ops",      accent: "var(--err)" },
  ];

  return (
    <div style={{display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginTop: 14}}>
      {tiles.map(t => (
        <div key={t.label} style={{
          background: "var(--surface-0)", border: "1px solid var(--line)",
          borderRadius: 10, padding: 16,
        }}>
          <div style={{fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600}}>
            {t.label}
          </div>
          <div style={{fontSize: 28, fontWeight: 700, marginTop: 6, color: t.accent || "var(--text-0)", lineHeight: 1}}>
            {(t.value ?? 0).toLocaleString()}
          </div>
          <div style={{fontSize: 11.5, color: "var(--text-3)", marginTop: 6}}>
            {t.hint}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Results table ──────────────────────────────────────────────────────────

function CVETable({ rows, loading, onSelect }) {
  if (loading) {
    return <div style={{padding: 30, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>
      <Icons.Refresh size={14} className="spin"/> Loading CVEs…
    </div>;
  }
  if (rows.length === 0) {
    return <div style={{padding: 40, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>
      No CVEs match the current filters.
    </div>;
  }

  return (
    <div style={{overflowX: "auto"}}>
      <table style={{width: "100%", borderCollapse: "collapse", fontSize: 12.5}}>
        <thead>
          <tr style={{background: "var(--surface-1)", textAlign: "left"}}>
            <th style={cellHead}>CVE</th>
            <th style={{...cellHead, width: 70}}>CVSS</th>
            <th style={{...cellHead, width: 70}}>EPSS</th>
            <th style={{...cellHead, width: 50, textAlign: "center"}}>KEV</th>
            <th style={{...cellHead, width: 80, textAlign: "center"}}>Ransom.</th>
            <th style={cellHead}>Vendor / product</th>
            <th style={{...cellHead, width: 100, textAlign: "right"}}>Threat score</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(r => (
            <tr key={r.cve} onClick={() => onSelect(r.cve)}
                style={{cursor: "pointer", borderTop: "1px solid var(--line)"}}
                onMouseEnter={e => e.currentTarget.style.background = "var(--surface-1)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
              <td style={{...cell, fontFamily: "var(--font-mono)", fontWeight: 600, color: "var(--text-0)"}}>
                {r.cve}
              </td>
              <td style={cell}>
                {typeof r.cvss === "number" ? (
                  <span style={{display: "inline-flex", alignItems: "center", gap: 6}}>
                    <span style={{width: 8, height: 8, borderRadius: "50%", background: severityColor(r.severity)}}/>
                    <span className="mono">{r.cvss.toFixed(1)}</span>
                  </span>
                ) : <span style={{color: "var(--text-3)"}}>—</span>}
              </td>
              <td style={{...cell, fontFamily: "var(--font-mono)"}}>
                {typeof r.epss === "number" ? `${(r.epss * 100).toFixed(1)}%` : <span style={{color: "var(--text-3)"}}>—</span>}
              </td>
              <td style={{...cell, textAlign: "center"}}>
                {r.kev ? <span style={{color: "var(--brand)", fontWeight: 600}}>✓</span> : <span style={{color: "var(--text-3)"}}>—</span>}
              </td>
              <td style={{...cell, textAlign: "center"}}>
                {r.ransomware ? <span style={{color: "var(--err)", fontWeight: 600}}>YES</span> : <span style={{color: "var(--text-3)"}}>—</span>}
              </td>
              <td style={{...cell, color: "var(--text-1)"}}>
                {r.vendor || r.product
                  ? <span><span style={{color: "var(--text-1)"}}>{r.vendor || "—"}</span>{" "}<span style={{color: "var(--text-3)"}}>· {r.product || "—"}</span></span>
                  : <span style={{color: "var(--text-3)"}}>—</span>}
              </td>
              <td style={{...cell, textAlign: "right", fontFamily: "var(--font-mono)", fontWeight: 600, color: scoreColor(r.threat_score)}}>
                {(r.threat_score ?? 0).toFixed(1)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Pagination({ page, totalPages, onPage }) {
  if (totalPages <= 1) return null;
  return (
    <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 16px", borderTop: "1px solid var(--line)"}}>
      <div style={{fontSize: 12, color: "var(--text-3)"}}>Page {page} of {totalPages}</div>
      <div style={{display: "flex", gap: 6}}>
        <button className="btn btn-sm" disabled={page <= 1} onClick={() => onPage(1)}>« First</button>
        <button className="btn btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹ Prev</button>
        <button className="btn btn-sm" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>Next ›</button>
        <button className="btn btn-sm" disabled={page >= totalPages} onClick={() => onPage(totalPages)}>Last »</button>
      </div>
    </div>
  );
}

// ─── Detail drawer ──────────────────────────────────────────────────────────

function CVEDrawer({ cveId, close }) {
  const [rec, setRec] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    threatIntelApi.detail(cveId)
      .then(r => { if (!cancelled) setRec(r); })
      .catch(e => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [cveId]);

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 720, maxHeight: "90vh", display: "flex", flexDirection: "column"}}>
        <div className="drawer-head">
          <Icons.Target size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)", fontFamily: "var(--font-mono)"}}>{cveId}</span>
          {rec?.severity && (
            <span className="tag" style={{
              background: severityColor(rec.severity), color: "#0a0a0a",
              textTransform: "uppercase", fontSize: 10, fontWeight: 700,
            }}>{rec.severity}</span>
          )}
          {rec?.kev && <span className="tag brand">CISA KEV</span>}
          {rec?.ransomware && <span className="tag" style={{background: "var(--err)", color: "#fff"}}>RANSOMWARE-KNOWN</span>}
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>

        <div style={{padding: "20px 24px", overflowY: "auto", flex: 1}}>
          {loading && <div style={{textAlign: "center", padding: 30, color: "var(--text-3)"}}>
            <Icons.Refresh size={14} className="spin"/> Loading…
          </div>}
          {error && <div style={{color: "var(--err)", fontSize: 13}}><Icons.AlertTriangle size={12}/> {error}</div>}
          {rec && !loading && (
            <>
              {/* Score grid */}
              <div style={{display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12, marginBottom: 18}}>
                <ScoreCard
                  title="Severity"
                  rows={[
                    ["CVSS", typeof rec.cvss === "number" ? rec.cvss.toFixed(1) : "—"],
                    ["Severity", (rec.severity || "—").toUpperCase()],
                    ["Threat score", `${(rec.threat_score ?? 0).toFixed(1)} / 100`],
                  ]}
                />
                <ScoreCard
                  title="Exploitation"
                  rows={[
                    ["EPSS", typeof rec.epss === "number" ? `${(rec.epss * 100).toFixed(2)}%` : "—"],
                    ["EPSS percentile", typeof rec.epss_percentile === "number" ? `${(rec.epss_percentile * 100).toFixed(1)}%` : "—"],
                    ["CISA KEV", rec.kev ? "Yes" : "No"],
                    ...(rec.kev ? [
                      ["KEV added", rec.kev_added || "—"],
                      ["KEV due", rec.kev_due || "—"],
                      ["Ransomware-known", rec.ransomware ? "Yes" : "No"],
                    ] : []),
                  ]}
                />
              </div>

              {/* Description */}
              {rec.summary && (
                <Section title="Description">
                  <div style={{fontSize: 13, color: "var(--text-1)", lineHeight: 1.6}}>{rec.summary}</div>
                </Section>
              )}

              {/* KEV notes */}
              {rec.kev && rec.kev_notes && (
                <Section title="CISA KEV notes">
                  <div style={{fontSize: 13, color: "var(--text-1)", lineHeight: 1.6}}>{rec.kev_notes}</div>
                </Section>
              )}

              {/* Vendor/product */}
              {(rec.vendor || rec.product) && (
                <Section title="Vendor / product">
                  <div style={{fontSize: 13, color: "var(--text-1)"}}>
                    {rec.vendor || "—"} · {rec.product || "—"}
                  </div>
                </Section>
              )}

              {/* Affected CPEs */}
              {Array.isArray(rec.matches) && rec.matches.length > 0 && (
                <Section title={`Affected CPEs (${rec.matches.length})`}>
                  <div style={{display: "flex", flexDirection: "column", gap: 4, maxHeight: 200, overflowY: "auto"}}>
                    {rec.matches.slice(0, 50).map((m, i) => (
                      <div key={i} className="mono" style={{fontSize: 11, color: "var(--text-2)", padding: "3px 6px", background: "var(--surface-1)", borderRadius: 4}}>
                        {m.cpe23}
                        {(m.versionStartIncluding || m.versionEndIncluding) && (
                          <span style={{color: "var(--text-3)", marginLeft: 8}}>
                            {m.versionStartIncluding && `≥ ${m.versionStartIncluding}`}
                            {m.versionStartIncluding && m.versionEndIncluding && " "}
                            {m.versionEndIncluding && `≤ ${m.versionEndIncluding}`}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </Section>
              )}

              {/* References */}
              {Array.isArray(rec.refs) && rec.refs.length > 0 && (
                <Section title={`References (${rec.refs.length})`}>
                  <div style={{display: "flex", flexDirection: "column", gap: 4}}>
                    {rec.refs.slice(0, 20).map((r, i) => (
                      <a key={i} href={r} target="_blank" rel="noopener noreferrer"
                         className="mono" style={{fontSize: 11.5, color: "var(--brand)", textDecoration: "none", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>
                        {r}
                      </a>
                    ))}
                  </div>
                </Section>
              )}

              <div style={{marginTop: 20, padding: "12px 14px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 6, fontSize: 12, color: "var(--text-3)"}}>
                <Icons.AlertTriangle size={11}/> "Find affected assets in workspace" cross-reference is coming in Phase 2 — for now, search the Findings page for this CVE-ID directly.
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}

function Section({ title, children }) {
  return (
    <div style={{marginBottom: 16}}>
      <div style={{fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600, marginBottom: 6}}>
        {title}
      </div>
      {children}
    </div>
  );
}

function ScoreCard({ title, rows }) {
  return (
    <div style={{padding: "12px 14px", background: "var(--surface-1)", border: "1px solid var(--line)", borderRadius: 6}}>
      <div style={{fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600, marginBottom: 8}}>
        {title}
      </div>
      <div style={{display: "flex", flexDirection: "column", gap: 4}}>
        {rows.map(([k, v], i) => (
          <div key={i} style={{display: "flex", justifyContent: "space-between", fontSize: 12.5}}>
            <span style={{color: "var(--text-3)"}}>{k}</span>
            <span style={{color: "var(--text-1)", fontFamily: "var(--font-mono)", fontWeight: 600}}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Helpers ────────────────────────────────────────────────────────────────

const cellHead = {
  padding: "10px 12px", fontSize: 11, color: "var(--text-3)",
  textTransform: "uppercase", letterSpacing: "0.04em", fontWeight: 600,
  borderBottom: "1px solid var(--line)",
};
const cell = { padding: "9px 12px", color: "var(--text-1)" };

function severityColor(sev) {
  switch ((sev || "").toLowerCase()) {
    case "critical": return "var(--err, #ff4757)";
    case "high":     return "#e8a03c";
    case "medium":   return "#f5d142";
    case "low":      return "var(--ok, #5fb87a)";
    default:         return "var(--text-3)";
  }
}

function scoreColor(s) {
  if (typeof s !== "number") return "var(--text-3)";
  if (s >= 80) return "var(--err)";
  if (s >= 60) return "#e8a03c";
  if (s >= 40) return "#f5d142";
  return "var(--text-1)";
}
