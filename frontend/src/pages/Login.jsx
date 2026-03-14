import React, { useState } from "react";
import { api, setToken } from "../api";

export default function Login() {
  const [email, setEmail] = useState("admin@local");
  const [password, setPassword] = useState("admin123");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit() {
    setErr(""); setLoading(true);
    try {
      const r = await api("/auth/login", { method: "POST", body: { email, password } });
      setToken(r.token);
      localStorage.setItem("vs_email", email);
      location.href = "/";
    } catch (e) {
      setErr(e.message || "Authentication failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{
      position: "fixed", inset: 0,
      display: "flex", alignItems: "center", justifyContent: "center",
      background: "var(--bg)",
    }}>
      {/* Animated grid bg */}
      <div style={{
        position: "absolute", inset: 0,
        backgroundImage: "linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px)",
        backgroundSize: "40px 40px",
      }} />

      <div style={{
        width: "min(400px, calc(100vw - 28px))", position: "relative",
        background: "var(--surface)",
        border: "1px solid var(--border)",
        animation: "fadeIn 0.3s ease both",
      }}>
        {/* Top accent bar */}
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, height: 3,
          background: "linear-gradient(90deg, var(--accent), #0066ff, var(--accent))",
          boxShadow: "0 0 20px rgba(0,212,255,0.5)",
        }} />

        <div style={{ padding: "32px 32px 24px", borderBottom: "1px solid var(--border)" }}>
          <div style={{
            fontFamily: "var(--font-head)", fontSize: "2rem", fontWeight: 800,
            color: "var(--accent)", letterSpacing: "0.15em",
            textShadow: "var(--accent-glow)",
          }}>
            VULNSCAN
          </div>
          <div style={{
            fontFamily: "var(--font-mono)", fontSize: "0.62rem",
            color: "var(--text-dim)", letterSpacing: "0.2em", marginTop: 6,
          }}>
            // ENTERPRISE VULNERABILITY MANAGEMENT
          </div>
        </div>

        <div style={{ padding: "28px 32px 32px" }}>
          {err && (
            <div style={{
              padding: "10px 14px", marginBottom: 16,
              background: "rgba(255,71,87,0.1)",
              border: "1px solid rgba(255,71,87,0.3)",
              color: "#ff7686",
              fontFamily: "var(--font-mono)", fontSize: "0.72rem",
              borderRadius: 2,
            }}>
              ! {err}
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              className="form-control"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="user@domain.com"
              onKeyDown={e => e.key === "Enter" && submit()}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              className="form-control"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="********"
              onKeyDown={e => e.key === "Enter" && submit()}
            />
          </div>

          <button
            className="btn btn-primary btn-lg btn-full"
            onClick={submit}
            disabled={loading}
            style={{ marginTop: 8, gap: 10 }}
          >
            {loading && <div className="spinner" />}
            AUTHENTICATE
          </button>

          <div style={{
            marginTop: 16, fontFamily: "var(--font-mono)", fontSize: "0.6rem",
            color: "var(--text-dim)", textAlign: "center", letterSpacing: "0.1em",
          }}>
            DEFAULT: admin@local / admin123
          </div>
        </div>

        {/* Corner decoration */}
        <div style={{
          position: "absolute", bottom: 0, right: 0,
          width: 60, height: 60,
          borderTop: "1px solid var(--border-bright)",
          borderLeft: "1px solid var(--border-bright)",
          opacity: 0.4,
        }} />
      </div>
    </div>
  );
}