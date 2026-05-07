import React, { useState, useEffect } from "react";
import { Icons } from "./icons.jsx";
import { login as apiLogin, eventsApi } from "../api.js";

export function LoginPage({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [remember, setRemember] = useState(true);
  const [view, setView] = useState("login");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e) => {
    e?.preventDefault?.();
    setLoading(true);
    setError("");
    try {
      const r = await apiLogin(email, password);
      onLogin && onLogin({ email, role: r.role, workspace_id: r.workspace_id });
    } catch (err) {
      setError(err.message || "Sign-in failed");
      setLoading(false);
    }
  };

  return (
    <div className="login-shell-centered">
      <div className="login-bg-grid"/>

      <div className="login-card">
        <div className="login-brand">
          <div className="nav-logo" style={{width: 36, height: 36, fontSize: 15}}>V</div>
          <div>
            <div style={{fontSize: 16, fontWeight: 600, color: "var(--text-0)", letterSpacing: "-0.01em"}}>
              VulnScan <span style={{color: "var(--text-3)", fontWeight: 400, fontSize: 12, marginLeft: 4}}>v3.0.1</span>
            </div>
            <div style={{fontSize: 12, color: "var(--text-3)", marginTop: 1}}>Risk Based Vulnerability Management — Security operations console</div>
          </div>
        </div>

        {view === "login" && (
          <>
            <div className="login-head">
              <h1>Sign in</h1>
              <div className="login-sub">Welcome back. Use your work email or SSO provider.</div>
            </div>

            <div className="sso-grid">
              {[
                { name: "Google",     icon: GoogleSSO },
                { name: "Microsoft",  icon: MsSSO },
                { name: "Okta",       icon: OktaSSO },
              ].map(p => {
                const I = p.icon;
                return (
                  <button key={p.name} type="button" className="sso-btn" onClick={() => setView("sso")}>
                    <I/>
                    <span>{p.name}</span>
                  </button>
                );
              })}
            </div>

            <div className="login-divider"><span>or with email</span></div>

            <form onSubmit={submit} className="login-form">
              <div>
                <label className="form-label">Work email</label>
                <div className="login-field">
                  <Icons.Mail size={14}/>
                  <input type="email" autoFocus required placeholder="alex.chen@company.com"
                         value={email} onChange={e => setEmail(e.target.value)}/>
                </div>
              </div>

              <div>
                <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6}}>
                  <label className="form-label" style={{margin: 0}}>Password</label>
                  <button type="button" className="link-btn" onClick={() => setView("forgot")}>Forgot?</button>
                </div>
                <div className="login-field">
                  <Icons.Lock size={14}/>
                  <input type={showPwd ? "text" : "password"} required placeholder="••••••••••••"
                         value={password} onChange={e => setPassword(e.target.value)}/>
                  <button type="button" className="login-eye" onClick={() => setShowPwd(s => !s)} aria-label="Show password">
                    {showPwd ? <Icons.EyeOff size={14}/> : <Icons.Eye size={14}/>}
                  </button>
                </div>
              </div>

              <label className="login-check">
                <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)}/>
                <span>Keep me signed in for 30 days</span>
              </label>

              {error && (
                <div style={{padding: "10px 12px", background: "var(--sev-critical-bg)", border: "1px solid var(--sev-critical-line)", borderRadius: 6, fontSize: 12.5, color: "var(--sev-critical)", display: "flex", gap: 8, alignItems: "center"}}>
                  <Icons.AlertTriangle size={13}/> {error}
                </div>
              )}

              <button type="submit" className="btn btn-primary login-submit" disabled={loading || !email || !password}>
                {loading ? <><Icons.Refresh size={13} className="spin"/> Signing in…</> : <>Sign in <Icons.ArrowRight size={13}/></>}
              </button>
            </form>

            <div className="login-foot-cta">
              Don't have an account? <button className="link-btn" onClick={() => setView("request")}>Request access</button>
            </div>
          </>
        )}

        {view === "forgot" && (
          <>
            <div className="login-head">
              <button className="link-btn back-btn" onClick={() => setView("login")}>
                <Icons.ChevronLeft size={12}/> Back to sign in
              </button>
              <h1>Reset password</h1>
              <div className="login-sub">We'll send a magic link to your work email. The link expires in 15 minutes.</div>
            </div>

            <form onSubmit={(e) => { e.preventDefault(); setView("login"); }} className="login-form">
              <div>
                <label className="form-label">Work email</label>
                <div className="login-field">
                  <Icons.Mail size={14}/>
                  <input type="email" autoFocus required placeholder="alex.chen@company.com"
                         value={email} onChange={e => setEmail(e.target.value)}/>
                </div>
              </div>
              <button type="submit" className="btn btn-primary login-submit">
                Send reset link <Icons.ArrowRight size={13}/>
              </button>
            </form>
          </>
        )}

        {view === "sso" && (
          <>
            <div className="login-head">
              <h1>SSO not configured</h1>
              <div className="login-sub">
                Single sign-on requires backend identity-provider setup (OAuth / SAML).
                Sign in with your work email and password instead.
              </div>
            </div>
            <button className="btn login-submit" onClick={() => setView("login")} style={{width: "100%"}}>
              <Icons.ChevronLeft size={13}/> Back to sign in
            </button>
          </>
        )}

        {view === "request" && (
          <RequestAccessForm onBack={() => setView("login")} onSubmit={() => setView("request-sent")}/>
        )}

        {view === "request-sent" && (
          <>
            <div className="login-head" style={{textAlign: "center"}}>
              <div className="success-circle">
                <Icons.Check size={28}/>
              </div>
              <h1>Request submitted</h1>
              <div className="login-sub">
                Thanks. Your workspace admin has been notified and will review your request within 1 business day.
                You'll receive an email at <span className="mono" style={{color: "var(--text-1)"}}>{email || "your address"}</span> once approved.
              </div>
            </div>
            <button className="btn login-submit" onClick={() => setView("login")} style={{width: "100%"}}>
              Back to sign in
            </button>
          </>
        )}

        <div className="login-foot">
          <div className="login-foot-meta">
            © 2026 VulnScan Platform by Gondrong
          </div>
        </div>
      </div>
    </div>
  );
}

function RequestAccessForm({ onBack, onSubmit }) {
  const [data, setData] = useState({
    name: "", email: "", company: "", role: "Security engineer", teamSize: "1-10", useCase: ""
  });
  const [submitting, setSubmitting] = useState(false);
  const update = (k, v) => setData(d => ({ ...d, [k]: v }));
  const submit = (e) => {
    e.preventDefault();
    setSubmitting(true);
    setTimeout(() => { setSubmitting(false); onSubmit(); }, 800);
  };
  const valid = data.name && data.email && data.company && data.useCase;

  return (
    <>
      <div className="login-head">
        <button className="link-btn back-btn" onClick={onBack}>
          <Icons.ChevronLeft size={12}/> Back to sign in
        </button>
        <h1>Request access</h1>
        <div className="login-sub">
          VulnScan is invite-only for security teams. Tell us about yourself and we'll route your request to the right admin.
        </div>
      </div>

      <form onSubmit={submit} className="login-form">
        <div className="ra-grid-2">
          <div>
            <label className="form-label">Full name</label>
            <div className="login-field">
              <Icons.User size={14}/>
              <input type="text" required placeholder="Alex Chen" value={data.name} onChange={e => update("name", e.target.value)}/>
            </div>
          </div>
          <div>
            <label className="form-label">Work email</label>
            <div className="login-field">
              <Icons.Mail size={14}/>
              <input type="email" required placeholder="alex@company.com" value={data.email} onChange={e => update("email", e.target.value)}/>
            </div>
          </div>
        </div>

        <div>
          <label className="form-label">Company</label>
          <div className="login-field">
            <Icons.Server size={14}/>
            <input type="text" required placeholder="Acme Corp" value={data.company} onChange={e => update("company", e.target.value)}/>
          </div>
        </div>

        <div className="ra-grid-2">
          <div>
            <label className="form-label">Your role</label>
            <div className="login-field">
              <Icons.User size={14}/>
              <select className="ra-select" value={data.role} onChange={e => update("role", e.target.value)}>
                <option>Security engineer</option>
                <option>Security analyst</option>
                <option>VP / Director Security</option>
                <option>CISO</option>
                <option>DevOps / SRE</option>
                <option>Compliance</option>
                <option>Other</option>
              </select>
            </div>
          </div>
          <div>
            <label className="form-label">Team size</label>
            <div className="login-field">
              <Icons.Users size={14}/>
              <select className="ra-select" value={data.teamSize} onChange={e => update("teamSize", e.target.value)}>
                <option>1-10</option>
                <option>11-50</option>
                <option>51-200</option>
                <option>201-1000</option>
                <option>1000+</option>
              </select>
            </div>
          </div>
        </div>

        <div>
          <label className="form-label">What would you like to use VulnScan for?</label>
          <textarea className="ra-textarea" required rows={3}
                    placeholder="Briefly: what are you trying to scan, current pain points, timeline…"
                    value={data.useCase}
                    onChange={e => update("useCase", e.target.value)}/>
        </div>

        <div className="ra-notice">
          <Icons.Lock size={12}/>
          <span>Your request will be reviewed by your workspace admin. We don't share your details.</span>
        </div>

        <button type="submit" className="btn btn-primary login-submit" disabled={!valid || submitting}>
          {submitting ? <><Icons.Refresh size={13} className="spin"/> Submitting…</> : <>Submit request <Icons.ArrowRight size={13}/></>}
        </button>
      </form>
    </>
  );
}

function GoogleSSO() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24">
      <path fill="#4285F4" d="M22.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h5.9c-.3 1.4-1 2.5-2.2 3.3v2.7h3.5c2.1-1.9 3.3-4.7 3.3-8.2z"/>
      <path fill="#34A853" d="M12 23c2.9 0 5.4-1 7.2-2.6l-3.5-2.7c-1 .7-2.2 1.1-3.7 1.1-2.9 0-5.3-1.9-6.2-4.5H2.2v2.8C4 20.5 7.7 23 12 23z"/>
      <path fill="#FBBC05" d="M5.8 14.3c-.2-.7-.4-1.4-.4-2.3s.1-1.6.4-2.3V6.9H2.2C1.4 8.4 1 10.1 1 12s.4 3.6 1.2 5.1l3.6-2.8z"/>
      <path fill="#EA4335" d="M12 5.4c1.6 0 3.1.6 4.2 1.6l3.1-3.1C17.4 2 14.9 1 12 1 7.7 1 4 3.5 2.2 6.9l3.6 2.8C6.7 7.1 9.1 5.4 12 5.4z"/>
    </svg>
  );
}
function MsSSO() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24">
      <rect x="2" y="2" width="9.5" height="9.5" fill="#F25022"/>
      <rect x="12.5" y="2" width="9.5" height="9.5" fill="#7FBA00"/>
      <rect x="2" y="12.5" width="9.5" height="9.5" fill="#00A4EF"/>
      <rect x="12.5" y="12.5" width="9.5" height="9.5" fill="#FFB900"/>
    </svg>
  );
}
function OktaSSO() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="3.5"/>
    </svg>
  );
}

export function LiveActivityFeed() {
  const [events, setEvents] = useState([]);
  const [paused, setPaused] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = async () => {
    try {
      const r = await eventsApi.recent(15);
      setEvents(r.events || []);
      setError("");
    } catch (e) { setError(e.message); }
    finally     { setLoading(false); }
  };

  useEffect(() => { refresh(); }, []);
  useEffect(() => {
    if (paused) return;
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [paused]);

  return (
    <div className="card">
      <div className="card-head">
        <div>
          <div className="card-title" style={{display: "flex", alignItems: "center", gap: 8}}>
            Live activity
            <span className={`live-pulse ${paused ? "paused" : ""}`}/>
          </div>
          <div className="card-sub">Recent scanner findings & job events</div>
        </div>
        <div style={{display: "flex", gap: 4}}>
          <button className="btn btn-ghost btn-sm" onClick={() => setPaused(p => !p)} title={paused ? "Resume" : "Pause"}>
            {paused ? <Icons.Play size={11}/> : <Icons.Stop size={11}/>}
            {paused ? "Resume" : "Pause"}
          </button>
        </div>
      </div>
      <div className="card-body flush">
        <div className="live-feed">
          {loading && events.length === 0 ? (
            <div style={{padding: 24, textAlign: "center", color: "var(--text-3)", fontSize: 12.5}}>Loading…</div>
          ) : error ? (
            <div style={{padding: 24, textAlign: "center", color: "var(--err)", fontSize: 12}}><Icons.AlertTriangle size={12}/> {error}</div>
          ) : events.length === 0 ? (
            <div style={{padding: 24, textAlign: "center", color: "var(--text-3)", fontSize: 12.5}}>
              No recent events. Run a scan to see live activity.
            </div>
          ) : (
            events.slice(0, 8).map((e, i) => (
              <div key={`${e.kind}-${e.id}-${i}`} className="live-feed-row" style={{
                opacity: 1 - i * 0.04,
              }}>
                <span className={`ambient-sev-dot ${e.sev}`} style={{flexShrink: 0}}/>
                <div style={{flex: 1, minWidth: 0}}>
                  <div style={{fontSize: 13, color: "var(--text-1)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>
                    {e.is_kev && <span className="kev" style={{marginRight: 6}}>KEV</span>}
                    {e.text}
                  </div>
                  <div style={{fontSize: 11, color: "var(--text-3)", marginTop: 2, fontFamily: "var(--font-mono)"}}>
                    {e.who} · {e.target ? `${e.target} · ` : ""}{e.ago}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
