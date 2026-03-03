import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api";
import { SevBadge, RiskBar, StatusDot, Panel, fmtDate } from "../components/ui.jsx";

export default function JobDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [sevFilter, setSevFilter] = useState("");
  const [expanded, setExpanded] = useState(new Set());

  async function load() {
    const d = await api(`/scan/jobs/${id}`);
    setData(d);
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [id]);

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

                <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                  <button className="btn btn-ghost btn-sm" onClick={() => suppress(f.fingerprint)}>
                    ⊗ Suppress
                  </button>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
