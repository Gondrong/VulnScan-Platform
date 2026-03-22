import React from "react";
import { NavLink } from "react-router-dom";

const NAV = [
  { to: "/dashboard", icon: "D", label: "Dashboard", group: "Monitoring" },
  { to: "/jobs", icon: "J", label: "Scan Jobs", group: "Scanning" },
  { to: "/profiles", icon: "P", label: "Profiles", group: "Configuration" },
  { to: "/credentials", icon: "C", label: "Credentials" },
  { to: "/datasets", icon: "T", label: "Datasets" },
  { to: "/settings", icon: "S", label: "Settings" },
];

const styles = {
  sidebar: {
    position: "fixed", left: 0, top: 0, bottom: 0,
    width: "var(--sidebar-w)",
    background: "var(--surface)",
    borderRight: "1px solid var(--border)",
    display: "flex", flexDirection: "column",
    zIndex: 100,
  },
  topBar: {
    position: "absolute", top: 0, left: 0, right: 0,
    height: "2px",
    background: "linear-gradient(90deg, var(--accent), transparent)",
  },
  logo: {
    padding: "24px 20px 20px",
    borderBottom: "1px solid var(--border)",
  },
  logoText: {
    fontFamily: "var(--font-head)",
    fontSize: "1.6rem", fontWeight: 800,
    color: "var(--accent)",
    letterSpacing: "0.1em",
    textShadow: "var(--accent-glow)",
  },
  logoSub: {
    fontFamily: "var(--font-mono)", fontSize: "0.6rem",
    color: "var(--text-dim)", letterSpacing: "0.18em",
    marginTop: 4,
  },
  logoBadge: {
    display: "inline-block",
    background: "var(--accent-dim)",
    border: "1px solid rgba(0,212,255,0.3)",
    color: "var(--accent)",
    fontFamily: "var(--font-mono)", fontSize: "0.55rem",
    padding: "2px 6px", borderRadius: 2,
    marginTop: 8, letterSpacing: "0.15em",
  },
  navArea: { flex: 1, overflowY: "auto", padding: "8px 0" },
  navLabel: {
    fontFamily: "var(--font-mono)", fontSize: "0.6rem",
    color: "var(--text-dim)", letterSpacing: "0.25em",
    textTransform: "uppercase", padding: "10px 20px 4px",
  },
  footer: {
    padding: "14px 20px",
    borderTop: "1px solid var(--border)",
    fontFamily: "var(--font-mono)", fontSize: "0.6rem",
    color: "var(--text-dim)",
  },
};

export default function Sidebar({ onLogout }) {
  let lastGroup = null;

  return (
    <nav className="sidebar" style={styles.sidebar}>
      <div style={styles.topBar} />
      <div className="sidebar-logo" style={styles.logo}>
        <div className="sidebar-logo-text" style={styles.logoText}>VULNSCAN</div>
        <div className="sidebar-logo-sub" style={styles.logoSub}>// THREAT INTELLIGENCE</div>
        <div className="sidebar-logo-badge" style={styles.logoBadge}>v2.1.0 ENTERPRISE</div>
      </div>

      <div style={styles.navArea}>
        {NAV.map((item) => {
          const showLabel = item.group && item.group !== lastGroup;
          if (item.group) lastGroup = item.group;
          return (
            <React.Fragment key={item.to}>
              {showLabel && <div className="sidebar-nav-label" style={styles.navLabel}>{item.group}</div>}
              <NavLink
                to={item.to}
                className="sidebar-nav-link"
                style={({ isActive }) => ({
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "9px 20px",
                  cursor: "pointer",
                  fontFamily: "var(--font-body)",
                  fontSize: "0.95rem", fontWeight: 500,
                  letterSpacing: "0.05em",
                  textDecoration: "none",
                  color: isActive ? "var(--accent)" : "var(--text-dim)",
                  background: isActive ? "var(--accent-dim)" : "transparent",
                  position: "relative",
                  transition: "all 0.15s",
                  borderLeft: isActive ? "2px solid var(--accent)" : "2px solid transparent",
                })}
              >
                <span className="sidebar-nav-icon" style={{ width: 16, textAlign: "center" }}>{item.icon}</span>
                <span className="sidebar-nav-text">{item.label}</span>
              </NavLink>
            </React.Fragment>
          );
        })}
      </div>

      <div className="sidebar-footer" style={styles.footer}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
          <div style={{
            width: 6, height: 6, borderRadius: "50%",
            background: "var(--accent4)",
            boxShadow: "0 0 8px var(--accent4)",
            animation: "pulse 2s infinite",
          }} />
          <span className="sidebar-system-text">SYSTEM ONLINE</span>
        </div>
        <button
          className="sidebar-logout"
          onClick={onLogout}
          style={{
            marginTop: 10, width: "100%",
            background: "transparent",
            border: "1px solid var(--border)",
            color: "var(--text-dim)",
            fontFamily: "var(--font-mono)", fontSize: "0.65rem",
            padding: "5px", cursor: "pointer",
            letterSpacing: "0.1em", transition: "all 0.15s",
          }}
          onMouseOver={(e) => { e.target.style.borderColor = "var(--accent2)"; e.target.style.color = "var(--accent2)"; }}
          onMouseOut={(e) => { e.target.style.borderColor = "var(--border)"; e.target.style.color = "var(--text-dim)"; }}
        >
          LOGOUT
        </button>
      </div>
    </nav>
  );
}
