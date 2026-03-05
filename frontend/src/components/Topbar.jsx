import React, { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";

const TITLES = {
  "/dashboard": ["DASHBOARD", "Overview"],
  "/jobs": ["SCAN JOBS", "Execute & Monitor"],
  "/findings": ["FINDINGS", "Vulnerability Details"],
  "/profiles": ["PROFILES", "Plugin Configuration"],
  "/credentials": ["CREDENTIALS", "SSH Keys & Passwords"],
  "/datasets": ["DATASETS", "Threat Intelligence Feeds"],
  "/settings": ["SETTINGS", "Platform Configuration"],
};

export default function Topbar() {
  const [now, setNow] = useState(new Date());
  const location = useLocation();
  const email = localStorage.getItem("vs_email") || "admin@local";
  const [section, sub] = TITLES[location.pathname] || ["VULNSCAN", ""];

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <div style={{
      height: 56, background: "var(--surface)",
      borderBottom: "1px solid var(--border)",
      display: "flex", alignItems: "center",
      justifyContent: "space-between",
      padding: "0 28px",
      position: "sticky", top: 0, zIndex: 50,
    }}>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.72rem", color: "var(--text-dim)" }}>
        <span style={{ color: "var(--accent)" }}>{section}</span>
        {sub && <> <span style={{ margin: "0 6px", color: "var(--border-bright)" }}>/</span> {sub}</>}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--text-dim)" }}>
          {now.toISOString().replace("T", " ").slice(0, 19)} UTC
        </div>
        <div style={{
          display: "flex", alignItems: "center", gap: 8,
          background: "var(--surface2)", border: "1px solid var(--border)",
          borderRadius: 4, padding: "5px 12px",
          fontFamily: "var(--font-mono)", fontSize: "0.68rem", color: "var(--text-dim)",
        }}>
          <div style={{
            width: 20, height: 20, borderRadius: 2,
            background: "linear-gradient(135deg, var(--accent), #0066ff)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: "0.6rem", fontWeight: 700, color: "white",
          }}>
            {email[0].toUpperCase()}
          </div>
          {email}
        </div>
      </div>
    </div>
  );
}
