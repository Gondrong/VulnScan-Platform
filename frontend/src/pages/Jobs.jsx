import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { StatusDot, Panel, Alert, fmtDate } from "../components/ui.jsx";

const INTERNAL_CHIPS = ["127.0.0.1", "192.168.1.1", "10.0.0.1", "10.0.0.100"];
const EXTERNAL_CHIPS = [
  "https://example.com",
  "https://httpbin.org",
  "scanme.nmap.org",
  "https://testphp.vulnweb.com",
];

function validateTarget(target, scanType) {
  if (!target.trim()) return "Target is required";

  if (scanType === "external") {
    // Accept full URLs or plain domain names
    const isUrl = /^https?:\/\//i.test(target);
    const isDomain =
      /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(
        target
      );
    if (!isUrl && !isDomain) {
      return "Enter a domain (e.g. example.com) or URL (https://example.com)";
    }
    if (isUrl) {
      try {
        new URL(target);
      } catch {
        return "Invalid URL format";
      }
    }
  } else {
    // Internal: must be IP or hostname — no http://
    if (/^https?:\/\//i.test(target)) {
      return "For internal scans, enter an IP or hostname only (no http://)";
    }
    const isIp =
      /^(\d{1,3}\.){3}\d{1,3}$/.test(target) &&
      target.split(".").every((n) => parseInt(n) <= 255);
    const isHostname =
      /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9-]+)*$/.test(
        target
      );
    if (!isIp && !isHostname) {
      return "Enter a valid IP address or hostname";
    }
  }
  return null;
}

export default function Jobs() {
  const [jobs, setJobs] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [target, setTarget] = useState("127.0.0.1");
  const [profileId, setProfileId] = useState("");
  const [scanType, setScanType] = useState("internal");
  const [msg, setMsg] = useState({ type: "", text: "" });
  const [loading, setLoading] = useState(false);
  const [targetErr, setTargetErr] = useState("");
  const [deletingIds, setDeletingIds] = useState(new Set());

  async function load() {
    try {
      const [j, p] = await Promise.all([
        api("/scan/jobs"),
        api("/scan/profiles"),
      ]);
      setJobs(j);
      setProfiles(p);
      if (!profileId && p[0]) setProfileId(String(p[0].id));
    } catch (e) {
      console.error("load error", e);
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, []);

  function handleScanTypeChange(type) {
    setScanType(type);
    setTargetErr("");
    setTarget(type === "external" ? "https://example.com" : "127.0.0.1");
  }

  function handleTargetChange(val) {
    setTarget(val);
    if (targetErr) setTargetErr("");
  }

  async function submit() {
    const err = validateTarget(target, scanType);
    if (err) {
      setTargetErr(err);
      return;
    }
    setLoading(true);
    setMsg({ type: "", text: "" });
    try {
      const r = await api("/scan/jobs", {
        method: "POST",
        body: {
          target: target.trim(),
          profile_id: Number(profileId),
          scan_type: scanType,
        },
      });
      setMsg({
        type: "success",
        text: `✓ Scan job #${r.id} launched — ${target} [${scanType}]`,
      });
      await load();
    } catch (e) {
      setMsg({ type: "danger", text: `Failed to launch scan: ${e.message}` });
    } finally {
      setLoading(false);
    }
  }

  async function deleteJob(jobId) {
    if (!window.confirm(`Delete job #${jobId} and all its findings?`)) return;

    // Optimistic removal
    setDeletingIds((s) => new Set([...s, jobId]));
    setJobs((prev) => prev.filter((j) => j.id !== jobId));

    try {
      await api(`/scan/jobs/${jobId}`, { method: "DELETE" });
      setMsg({ type: "success", text: `✓ Job #${jobId} deleted` });
    } catch (e) {
      // Rollback on error
      setDeletingIds((s) => {
        const n = new Set(s);
        n.delete(jobId);
        return n;
      });
      await load();
      if (e.message.includes("404")) {
        setMsg({ type: "info", text: `Job #${jobId} was already removed` });
      } else {
        setMsg({ type: "danger", text: `Could not delete job: ${e.message}` });
      }
    }
  }

  const chips = scanType === "external" ? EXTERNAL_CHIPS : INTERNAL_CHIPS;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">
            Scan <span className="accent">Jobs</span>
          </div>
          <div className="page-desc">
            // Execute internal LAN scans and external web scans
          </div>
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: 20 }}>
        <Panel title="Launch Scan">
          {msg.text && (
            <Alert
              type={msg.type}
              onClose={() => setMsg({ type: "", text: "" })}
            >
              {msg.text}
            </Alert>
          )}

          {/* Scan type toggle */}
          <div className="form-group">
            <label className="form-label">Scan Type</label>
            <div style={{ display: "flex", gap: 0 }}>
              {["internal", "external"].map((type) => (
                <button
                  key={type}
                  className="btn btn-ghost"
                  style={{
                    flex: 1,
                    borderRadius: 0,
                    borderColor:
                      scanType === type ? "var(--accent)" : "var(--border)",
                    color:
                      scanType === type ? "var(--accent)" : "var(--text-dim)",
                    background:
                      scanType === type
                        ? "rgba(0,212,255,0.08)"
                        : "var(--surface2)",
                  }}
                  onClick={() => handleScanTypeChange(type)}
                >
                  {type === "internal" ? "🏠 Internal / LAN" : "🌐 External / Web"}
                </button>
              ))}
            </div>
          </div>

          {scanType === "external" && (
            <div
              style={{
                padding: "8px 12px",
                marginBottom: 12,
                background: "rgba(255,165,2,0.06)",
                border: "1px solid rgba(255,165,2,0.2)",
                fontFamily: "var(--font-mono)",
                fontSize: "0.65rem",
                color: "var(--medium)",
                lineHeight: 1.6,
              }}
            >
              ⚠ Only scan targets you own or have written permission to test.
            </div>
          )}

          <div className="form-group">
            <label className="form-label">
              {scanType === "external"
                ? "Domain or URL"
                : "IP Address or Hostname"}
            </label>
            <input
              className="form-control"
              value={target}
              onChange={(e) => handleTargetChange(e.target.value)}
              placeholder={
                scanType === "external"
                  ? "https://example.com or example.com"
                  : "10.0.0.1 or host.internal.local"
              }
              onKeyDown={(e) => e.key === "Enter" && submit()}
              style={
                targetErr ? { borderColor: "var(--critical)" } : undefined
              }
            />
            {targetErr && (
              <div
                style={{
                  color: "var(--critical)",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.65rem",
                  marginTop: 4,
                }}
              >
                {targetErr}
              </div>
            )}
            {/* Quick target chips */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 8 }}>
              {chips.map((c) => (
                <button
                  key={c}
                  className="btn btn-ghost btn-sm"
                  style={{ fontSize: "0.65rem", padding: "3px 8px" }}
                  onClick={() => handleTargetChange(c)}
                >
                  {c}
                </button>
              ))}
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Scan Profile</label>
            <select
              className="form-control"
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
            >
              {profiles.length ? (
                profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} (#{p.id})
                  </option>
                ))
              ) : (
                <option value="">No profiles — create one first</option>
              )}
            </select>
          </div>

          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <button
              className="btn btn-primary btn-lg"
              style={{ flex: 1, gap: 8 }}
              onClick={submit}
              disabled={loading || !profileId}
            >
              {loading && <div className="spinner" />}
              ⚡ LAUNCH SCAN
            </button>
            <button className="btn btn-ghost" onClick={load} title="Refresh">
              ↻
            </button>
          </div>
        </Panel>

        <Panel title="Scan Info">
          <div
            style={{
              display: "grid",
              gap: 12,
            }}
          >
            <div>
              <div
                style={{
                  fontWeight: 600,
                  color: "var(--text-bright)",
                  marginBottom: 4,
                }}
              >
                🏠 Internal / LAN
              </div>
              <div
                style={{
                  fontSize: "0.83rem",
                  color: "var(--text-dim)",
                  lineHeight: 1.6,
                }}
              >
                Port scan, banner grab, SSH inventory, NVD CVE match, TLS check
              </div>
            </div>
            <div>
              <div
                style={{
                  fontWeight: 600,
                  color: "var(--text-bright)",
                  marginBottom: 4,
                }}
              >
                🌐 External / Web
              </div>
              <div
                style={{
                  fontSize: "0.83rem",
                  color: "var(--text-dim)",
                  lineHeight: 1.6,
                }}
              >
                HTTP fingerprint, web tech detect, favicon hash, CMS CVE map,
                CISA KEV correlation
              </div>
            </div>
          </div>

          <div
            style={{
              marginTop: 14,
              padding: "10px 12px",
              background: "var(--surface2)",
              border: "1px solid var(--border)",
            }}
          >
            <div
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "0.6rem",
                color: "var(--text-dim)",
                letterSpacing: "0.14em",
                marginBottom: 7,
              }}
            >
              REMEDIATION SLA
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: 5,
                fontFamily: "var(--font-mono)",
                fontSize: "0.72rem",
              }}
            >
              <span>
                <span style={{ color: "var(--critical)" }}>CRITICAL</span> → 7d
              </span>
              <span>
                <span style={{ color: "var(--high)" }}>HIGH</span> → 14d
              </span>
              <span>
                <span style={{ color: "var(--medium)" }}>MEDIUM</span> → 30d
              </span>
              <span>
                <span style={{ color: "var(--low)" }}>LOW</span> → 60d
              </span>
            </div>
          </div>
        </Panel>
      </div>

      {/* Job History */}
      <Panel
        title="Job History"
        extra={
          <span
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "0.65rem",
              color: "var(--text-dim)",
            }}
          >
            {jobs.length} jobs
          </span>
        }
        noPad
      >
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Target</th>
              <th>Type</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Started</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {jobs.length ? (
              jobs.map((j) => {
                const prof = profiles.find((p) => p.id === j.profile_id);
                return (
                  <tr key={j.id}>
                    <td className="mono text-accent">#{j.id}</td>
                    <td
                      className="mono"
                      style={{
                        maxWidth: 200,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {j.target}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          j.scan_type === "external"
                            ? "badge-success"
                            : "badge-info"
                        }`}
                      >
                        {j.scan_type === "external" ? "🌐" : "🏠"}{" "}
                        {j.scan_type || "internal"}
                      </span>
                    </td>
                    <td className="mono text-dim">
                      {prof?.name || `#${j.profile_id}`}
                    </td>
                    <td>
                      <StatusDot status={j.status} />
                    </td>
                    <td
                      className="mono text-dim"
                      style={{ fontSize: "0.68rem" }}
                    >
                      {fmtDate(j.created_at)}
                    </td>
                    <td>
                      <div
                        style={{
                          display: "flex",
                          gap: 6,
                          justifyContent: "flex-end",
                        }}
                      >
                        <Link
                          to={`/jobs/${j.id}`}
                          className="btn btn-ghost btn-sm"
                          style={{ textDecoration: "none" }}
                        >
                          ▸ Results
                        </Link>
                        <button
                          className="btn btn-ghost btn-sm"
                          style={{
                            color: "var(--critical)",
                            borderColor: "rgba(255,71,87,0.3)",
                          }}
                          onClick={() => deleteJob(j.id)}
                          disabled={deletingIds.has(j.id)}
                          title="Delete job"
                        >
                          🗑
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan="7">
                  <div className="empty-state">
                    <div className="empty-icon">◎</div>
                    No scan jobs yet. Launch your first scan above.
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
