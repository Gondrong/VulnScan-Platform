import React from "react";

export function SevBadge({ sev }) {
  const cls = {
    critical: "badge-critical", high: "badge-high",
    medium: "badge-medium", low: "badge-low", info: "badge-info",
  }[sev] || "badge-info";
  return <span className={`badge ${cls}`}>{sev || "info"}</span>;
}

export function RiskBar({ score }) {
  if (score == null) return <span className="mono text-dim" style={{ fontSize: "0.7rem" }}>—</span>;
  const pct = Math.min(100, Math.round(score * 10));
  const color = score >= 9 ? "var(--critical)" : score >= 7 ? "var(--high)" : score >= 4 ? "var(--medium)" : "var(--low)";
  return (
    <div className="risk-bar-wrap">
      <div className="risk-bar-track">
        <div className="risk-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <div className="risk-val" style={{ color }}>{score.toFixed(1)}</div>
    </div>
  );
}

export function StatusDot({ status }) {
  const dotCls = {
    running: "dot-running", done: "dot-done",
    failed: "dot-failed", queued: "dot-queued",
    analyzing: "dot-running",
  }[status] || "dot-queued";
  const color = {
    running: "var(--accent)", done: "var(--low)",
    failed: "var(--critical)", queued: "var(--text-dim)",
    analyzing: "var(--medium, #d4a838)",
  }[status] || "var(--text-dim)";
  const label = status === "analyzing" ? "AI analyzing" : status;
  return (
    <div className="status-dot">
      <div className={`dot ${dotCls}`} />
      <span style={{ color, fontFamily: "var(--font-mono)", fontSize: "0.7rem" }}>{label}</span>
    </div>
  );
}

export function Alert({ type, children, onClose }) {
  if (!children) return null;
  return (
    <div className={`alert alert-${type}`} style={{ position: "relative" }}>
      {children}
      {onClose && (
        <button onClick={onClose} style={{
          position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)",
          background: "none", border: "none", cursor: "pointer",
          color: "inherit", fontSize: "1rem", lineHeight: 1,
        }}>✕</button>
      )}
    </div>
  );
}

export function Spinner() {
  return <div className="spinner" />;
}

export function EmptyState({ icon = "◎", text = "No data" }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">{icon}</div>
      {text}
    </div>
  );
}

export function Panel({ title, extra, children, noPad }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-title">{title}</div>
        {extra && <div>{extra}</div>}
      </div>
      {noPad ? children : <div className="panel-body">{children}</div>}
    </div>
  );
}

export function fmtDate(dt) {
  if (!dt) return "—";
  try { return new Date(dt).toISOString().replace("T", " ").slice(0, 16); }
  catch { return dt; }
}
