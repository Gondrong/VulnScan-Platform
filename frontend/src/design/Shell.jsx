import React, { useState, useEffect, Fragment } from "react";
import { Icons } from "./icons.jsx";
import { eventsApi, getUser } from "../api.js";

export function Nav({ page, setPage, onSignOut, counts = {}, version = "" }) {
  const NAV_ITEMS = [
    { section: "Overview", items: [
      { id: "dashboard", label: "Dashboard", icon: Icons.Dashboard },
    ]},
    { section: "Scanning", items: [
      { id: "assets", label: "Assets", icon: Icons.Folder, count: counts.assets },
      { id: "jobs", label: "Scan Jobs", icon: Icons.Scan, count: counts.jobs },
      { id: "profiles", label: "Profiles", icon: Icons.Layers, count: counts.profiles },
      { id: "reports", label: "Reports", icon: Icons.FileText, count: counts.reports },
    ]},
    { section: "Intelligence", items: [
      { id: "threat-intel", label: "Threat Intel", icon: Icons.Target, count: counts.threat_kev },
      { id: "attack-graph", label: "Attack Graph", icon: Icons.Graph },
      { id: "analytics", label: "Analytics", icon: Icons.Activity },
    ]},
    { section: "Configuration", items: [
      { id: "credentials", label: "Credentials", icon: Icons.Key, count: counts.credentials },
      { id: "datasets", label: "Datasets", icon: Icons.Database, count: counts.datasets },
      { id: "settings", label: "Settings", icon: Icons.Settings },
    ]},
  ];

  return (
    <aside className="nav">
      <div className="nav-brand">
        <div className="nav-logo">V</div>
        <div className="nav-name">VulnScan<span className="ver">{version ? `v${version}` : ""}</span></div>
      </div>
      <div className="nav-search">
        <span className="icon"><Icons.Search size={14}/></span>
        <input placeholder="Jump to…" />
        <span className="kbd">⌘K</span>
      </div>
      <div className="nav-scroll">
        {NAV_ITEMS.map(g => (
          <div key={g.section}>
            <div className="nav-section">{g.section}</div>
            {g.items.map(i => {
              const I = i.icon;
              const active = page === i.id;
              return (
                <div key={i.id} className={`nav-item ${active ? "active" : ""}`} onClick={() => setPage(i.id)}>
                  <I size={16} className="nav-icon" />
                  <span className="nav-label">{i.label}</span>
                  {i.count != null && <span className="nav-count">{i.count}</span>}
                </div>
              );
            })}
          </div>
        ))}
      </div>
      <div className="nav-foot">
        <NavUser onSignOut={onSignOut} setPage={setPage}/>
        <div style={{padding: "10px 16px 14px", fontSize: 11, color: "var(--text-4)", textAlign: "center", lineHeight: 1.5}}>
          Powered by <span style={{fontWeight: 600, color: "var(--text-3)"}}>Gondrong</span>
        </div>
      </div>
    </aside>
  );
}

function NavUser({ onSignOut, setPage }) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, [open]);

  const u = getUser() || {};
  const email = u.email || "—";
  const initials = email.split("@")[0].split(".").map(s => s[0]).join("").slice(0, 2).toUpperCase() || "VS";

  return (
    <div style={{position: "relative"}} onClick={e => e.stopPropagation()}>
      <div className="nav-user" onClick={() => setOpen(o => !o)} style={{cursor: "pointer"}}>
        <div className="nav-avatar">{initials}</div>
        <div className="nav-user-meta">
          <div className="nav-user-name">{email.split("@")[0]}</div>
          <div className="nav-user-org">{u.role || "user"}</div>
        </div>
      </div>
      {open && (
        <div className="nav-user-menu">
          <div className="nav-user-menu-head">
            <div className="nav-user-name">{email.split("@")[0]}</div>
            <div style={{fontSize: 11.5, color: "var(--text-3)", marginTop: 2}}>{email}</div>
          </div>
          <button className="nav-user-menu-item" onClick={() => { setOpen(false); setPage && setPage("settings", "users"); }}>
            <Icons.User size={13}/> My profile
          </button>
          <button className="nav-user-menu-item" onClick={() => { setOpen(false); setPage && setPage("settings", "general"); }}>
            <Icons.Settings size={13}/> Settings
          </button>
          <div className="nav-user-menu-sep"/>
          <button className="nav-user-menu-item danger" onClick={() => onSignOut && onSignOut()}>
            <Icons.LogOut size={13}/> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

const THEMES = [
  { id: "dark",  label: "Dark",   sub: "Default — near-black surfaces", icon: Icons.Moon },
  { id: "light", label: "Light",  sub: "Daylight — for bright rooms",   icon: Icons.Sun },
  { id: "dim",   label: "Dim",    sub: "Slate — easier on long shifts", icon: Icons.Monitor },
];

export function Topbar({ crumbs, setPage }) {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem("vs-theme") || "dark"; } catch { return "dark"; }
  });
  const [openTheme, setOpenTheme] = useState(false);
  const [openBell, setOpenBell] = useState(false);
  const [events, setEvents] = useState([]);
  const [unread, setUnread] = useState(0);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try { localStorage.setItem("vs-theme", theme); } catch {}
  }, [theme]);

  useEffect(() => {
    if (!openTheme && !openBell) return;
    const close = () => { setOpenTheme(false); setOpenBell(false); };
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [openTheme, openBell]);

  // Poll events every 15s; track unread = events newer than last-seen-at
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await eventsApi.recent(10);
        if (cancelled) return;
        const items = r.events || [];
        setEvents(items);
        const lastSeen = parseInt(localStorage.getItem("vs-bell-seen") || "0");
        const newest = items[0]?.at ? new Date(items[0].at).getTime() : 0;
        const unreadCount = items.filter(e => e.at && new Date(e.at).getTime() > lastSeen && e.sev !== "info").length;
        setUnread(unreadCount);
      } catch {}
    };
    tick();
    const t = setInterval(tick, 15000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  const markSeen = () => {
    if (events[0]?.at) localStorage.setItem("vs-bell-seen", String(new Date(events[0].at).getTime()));
    setUnread(0);
  };

  const active = THEMES.find(t => t.id === theme) || THEMES[0];
  const ActiveIcon = active.icon;

  return (
    <div className="topbar">
      <div className="crumbs">
        {crumbs.map((c, i) => (
          <Fragment key={i}>
            {i > 0 && <span className="sep">/</span>}
            <span className={i === crumbs.length - 1 ? "leaf" : ""}>{c}</span>
          </Fragment>
        ))}
      </div>
      <div className="right">
        {/* Theme switcher */}
        <div style={{position: "relative"}} onClick={e => e.stopPropagation()}>
          <button className="topbar-btn" onClick={() => { setOpenTheme(o => !o); setOpenBell(false); }} title={`Theme: ${active.label}`}>
            <ActiveIcon size={16}/>
          </button>
          {openTheme && (
            <div style={{
              position: "absolute", top: "calc(100% + 6px)", right: 0, zIndex: 100,
              minWidth: 240, background: "var(--surface-0)", border: "1px solid var(--line-strong)",
              borderRadius: 10, boxShadow: "var(--shadow-3)", padding: 6,
            }}>
              <div style={{padding: "8px 12px 4px", fontSize: 11, fontWeight: 600, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.04em"}}>Theme</div>
              {THEMES.map(t => {
                const I = t.icon; const sel = t.id === theme;
                return (
                  <button key={t.id} onClick={() => { setTheme(t.id); setOpenTheme(false); }}
                          style={{
                            display: "flex", alignItems: "center", gap: 10, width: "100%",
                            padding: "8px 10px", border: "none", borderRadius: 6, cursor: "pointer",
                            background: sel ? "var(--brand-soft)" : "transparent",
                            color: sel ? "var(--brand-text)" : "var(--text-1)",
                            textAlign: "left",
                          }}
                          onMouseEnter={e => { if (!sel) e.currentTarget.style.background = "var(--surface-1)"; }}
                          onMouseLeave={e => { if (!sel) e.currentTarget.style.background = "transparent"; }}>
                    <div style={{width: 28, height: 28, borderRadius: 6, background: "var(--surface-2)", display: "grid", placeItems: "center", flexShrink: 0}}>
                      <I size={14}/>
                    </div>
                    <div style={{flex: 1, minWidth: 0}}>
                      <div style={{fontSize: 13, fontWeight: 500}}>{t.label}</div>
                      <div style={{fontSize: 11.5, color: "var(--text-3)", marginTop: 1}}>{t.sub}</div>
                    </div>
                    {sel && <Icons.Check size={13}/>}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Notification bell */}
        <div style={{position: "relative"}} onClick={e => e.stopPropagation()}>
          <button className="topbar-btn"
                  onClick={() => { setOpenBell(o => !o); setOpenTheme(false); if (!openBell) markSeen(); }}
                  title="Recent activity">
            <Icons.Bell size={16}/>
            {unread > 0 && <span className="dot"/>}
          </button>
          {openBell && (
            <div style={{
              position: "absolute", top: "calc(100% + 6px)", right: 0, zIndex: 100,
              width: 380, background: "var(--surface-0)", border: "1px solid var(--line-strong)",
              borderRadius: 10, boxShadow: "var(--shadow-3)",
              maxHeight: 480, display: "flex", flexDirection: "column",
            }}>
              <div style={{padding: "10px 14px", borderBottom: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center"}}>
                <div style={{fontSize: 13, fontWeight: 600, color: "var(--text-0)"}}>Recent activity</div>
                <span className="tag">{events.length}</span>
              </div>
              <div style={{flex: 1, overflowY: "auto"}}>
                {events.length === 0 ? (
                  <div style={{padding: 30, textAlign: "center", fontSize: 12.5, color: "var(--text-3)"}}>No recent events.</div>
                ) : events.map((e, i) => (
                  <div key={`${e.kind}-${e.id}-${i}`} style={{
                    padding: "10px 14px", borderBottom: "1px solid var(--line)",
                    display: "flex", gap: 10, alignItems: "flex-start",
                  }}>
                    <span className={`ambient-sev-dot ${e.sev}`} style={{marginTop: 6, flexShrink: 0}}/>
                    <div style={{flex: 1, minWidth: 0}}>
                      <div style={{fontSize: 13, color: "var(--text-1)", lineHeight: 1.4}}>{e.text}</div>
                      <div style={{fontSize: 11, color: "var(--text-3)", marginTop: 2, fontFamily: "var(--font-mono)"}}>
                        {e.who} {e.target ? `· ${e.target}` : ""} · {e.ago}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              <div style={{padding: "8px 14px", borderTop: "1px solid var(--line)"}}>
                <button className="link-btn" onClick={() => { setOpenBell(false); setPage && setPage("dashboard"); }} style={{fontSize: 12}}>
                  Open Dashboard for live feed →
                </button>
              </div>
            </div>
          )}
        </div>

        <button className="topbar-btn" title="Help" onClick={() => window.open("https://github.com/Gondrong/VulnScan-Platform", "_blank")}>
          <Icons.Help size={16}/>
        </button>
      </div>
    </div>
  );
}
