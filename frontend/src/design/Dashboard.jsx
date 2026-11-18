import React, { useMemo, useState, useEffect } from "react";
import { Icons, Sev, Pip, Risk, Status, Donut, Sparkline } from "./icons.jsx";
import { scanApi, settingsApi, threatIntelApi } from "../api.js";
import { LiveActivityFeed } from "./Login.jsx";

function useCountUp(target, duration = 900, delay = 0) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    if (target == null || typeof target !== "number") return;
    if (target === 0) { setDisplay(0); return; }
    let raf, timeout;
    timeout = setTimeout(() => {
      const start = performance.now();
      function tick(now) {
        const t = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - t, 3);
        setDisplay(Math.round(ease * target));
        if (t < 1) raf = requestAnimationFrame(tick);
      }
      raf = requestAnimationFrame(tick);
    }, delay);
    return () => { clearTimeout(timeout); if (raf) cancelAnimationFrame(raf); };
  }, [target, duration, delay]);
  return target != null && typeof target === "number" ? display : target;
}

function TiMiniTile({ label, value, accent, hint, onClick, animDelay = 0 }) {
  const display = useCountUp(value, value > 1000 ? 1400 : 900, animDelay + 300);
  return (
    <div onClick={onClick}
         className="dash-slide-right"
         style={{
           padding: "10px 12px", background: "var(--surface-1)", border: "1px solid var(--line)",
           borderRadius: 6, cursor: onClick ? "pointer" : "default",
           transition: "border-color 0.15s, background 0.15s",
           animationDelay: `${animDelay}ms`,
         }}
         onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--line-strong, var(--brand))"; }}
         onMouseLeave={e => { e.currentTarget.style.borderColor = "var(--line)"; }}>
      <div style={{fontSize: 10.5, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600}}>
        {label}
      </div>
      <div style={{fontSize: 22, fontWeight: 700, color: accent || "var(--text-0)", lineHeight: 1.1, marginTop: 4, fontVariantNumeric: "tabular-nums"}}>
        {(display ?? 0).toLocaleString()}
      </div>
      {hint && <div style={{fontSize: 11, color: "var(--text-3)", marginTop: 4}}>{hint}</div>}
    </div>
  );
}

function StatTile({ label, value, delta, deltaDir, accent, icon, sparkData, onClick, hint, animDelay = 0 }) {
  const I = icon;
  const clickable = typeof onClick === "function";
  const numValue = typeof value === "number" ? value : null;
  const display = useCountUp(numValue, numValue > 100 ? 1200 : 900, animDelay + 200);
  return (
    <div className={`stat ${accent} dash-enter`}
         onClick={clickable ? onClick : undefined}
         style={{ cursor: clickable ? "pointer" : undefined, animationDelay: `${animDelay}ms` }}
         title={hint}>
      <div className="accent-bar" />
      <div className="label">{I && <I size={12}/>} {label}</div>
      <div className="value" style={{fontVariantNumeric: "tabular-nums"}}>{numValue != null ? display : value}</div>
      {delta && <div className={`delta ${deltaDir}`}>{deltaDir === "up" ? "↑" : deltaDir === "down" ? "↓" : "→"} {delta}</div>}
      {hint && !delta && <div style={{fontSize: 10.5, color: "var(--text-3)", marginTop: 6, fontWeight: 400}}>{hint}</div>}
      {sparkData && <div style={{marginTop: 8}}><Sparkline data={sparkData} w={180} h={28} color={accent === "critical" ? "var(--sev-critical)" : "var(--brand)"}/></div>}
    </div>
  );
}

export function Dashboard({ openDrawer, setPage }) {
  const [jobs, setJobs] = useState([]);
  const [stats, setStats] = useState(null);
  const [recentFindings, setRecentFindings] = useState([]);
  const [tiStats, setTiStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [allJobs, s, ti] = await Promise.all([
          scanApi.listJobs(),
          settingsApi.stats().catch(() => null),
          threatIntelApi.stats().catch(() => null),
        ]);
        if (cancelled) return;
        setJobs(allJobs || []);
        setStats(s);
        setTiStats(ti);

        const lastDone = (allJobs || []).find(j => j.status === "done");
        if (lastDone) {
          try {
            const detail = await scanApi.getJob(lastDone.id);
            if (!cancelled) {
              const all = (detail.findings || []).map(f => ({ ...f, _target: detail.job.target }));
              all.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
              setRecentFindings(all.slice(0, 5));
            }
          } catch {}
        }
      } catch (e) {
        if (!cancelled) setError(e.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0, kev: 0 };
    for (const f of recentFindings) {
      c[f.severity] = (c[f.severity] || 0) + 1;
      if (f.is_kev) c.kev++;
    }
    return c;
  }, [recentFindings]);

  const segments = [
    { value: sevCounts.critical, color: "var(--sev-critical)", label: "Critical" },
    { value: sevCounts.high,     color: "var(--sev-high)",     label: "High" },
    { value: sevCounts.medium,   color: "var(--sev-medium)",   label: "Medium" },
    { value: sevCounts.low,      color: "var(--sev-low)",      label: "Low" },
  ];

  const topTargets = useMemo(() => {
    const byTarget = {};
    for (const j of jobs) {
      if (!byTarget[j.target]) byTarget[j.target] = { target: j.target, total: 0, done: 0, failed: 0, last: null };
      byTarget[j.target].total++;
      if (j.status === "done")   byTarget[j.target].done++;
      if (j.status === "failed") byTarget[j.target].failed++;
      const t = j.created_at ? new Date(j.created_at).getTime() : 0;
      if (t > (byTarget[j.target].last || 0)) byTarget[j.target].last = t;
    }
    return Object.values(byTarget).sort((a, b) => b.total - a.total).slice(0, 5);
  }, [jobs]);

  const lastScanAt = jobs[0]?.created_at;

  return (
    <>
      <div className="ph">
        <div>
          <h1>Posture overview</h1>
          <div className="sub">
            {stats?.profiles ?? "—"} scan profiles · {jobs.length} total jobs
            {lastScanAt && <> · last scan {new Date(lastScanAt).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"})}</>}
          </div>
        </div>
        <div className="actions">
          <button className="btn-ghost btn" onClick={() => window.location.reload()}><Icons.Refresh size={14}/> Refresh</button>
          <button className="btn btn-primary" onClick={() => setPage && setPage("jobs")}><Icons.Plus size={14}/> New scan</button>
        </div>
      </div>

      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}

      {/* Animation 1: Staggered card entrance + Animation 2: Count-up numbers */}
      <div className="grid-stat">
        {loading && !stats ? (
          <>
            {[0,1,2,3,4].map(i => <div key={i} className="skel skel-stat dash-enter" style={{animationDelay: `${i * 80}ms`}}/>)}
          </>
        ) : (
          <>
            <StatTile label="Total scans"     value={stats?.jobs_total ?? "—"}  accent="brand"    icon={Icons.Scan}          animDelay={0}/>
            <StatTile label="Done"            value={stats?.jobs_done  ?? "—"}  accent="low"      icon={Icons.Check}         animDelay={80}/>
            <StatTile label="Failed"          value={stats?.jobs_failed ?? "—"} accent="critical"  icon={Icons.AlertTriangle} animDelay={160}/>
            <StatTile label="Findings"        value={stats?.findings   ?? "—"}  accent="high"     icon={Icons.Activity}      animDelay={240}/>
            <StatTile label="KEV (last scan)" value={sevCounts.kev}                  accent="critical"  icon={Icons.Target}        animDelay={320}/>
          </>
        )}
      </div>

      {/* Animation 5: Threat Intel tiles slide-in from right */}
      {tiStats && tiStats.total_cves > 0 && (
        <div className="dash-enter" style={{
          background: "var(--surface-0)", border: "1px solid var(--line)",
          borderRadius: 10, padding: "14px 16px", marginTop: 14,
          animationDelay: "400ms",
        }}>
          <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12}}>
            <div style={{display: "flex", alignItems: "center", gap: 8}}>
              <Icons.Target size={14} color="var(--brand)"/>
              <span style={{fontSize: 13, fontWeight: 600, color: "var(--text-0)"}}>Threat Intel</span>
              <span style={{fontSize: 11.5, color: "var(--text-3)"}}>
                · {tiStats.total_cves.toLocaleString()} CVEs in catalog
                {tiStats.datasets_loaded?.length > 0 && ` · ${tiStats.datasets_loaded.join(" + ")}`}
              </span>
            </div>
            <button className="btn btn-sm btn-ghost"
                    onClick={() => setPage && setPage("threat-intel")}>
              Open Threat Intel →
            </button>
          </div>
          <div style={{display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10}}>
            <TiMiniTile
              label="New KEV (7d)"
              value={tiStats.new_kev_7d}
              accent="var(--brand)"
              hint={tiStats.new_kev_7d > 0 ? "Recently exploited — review now" : "No new KEV this week"}
              onClick={() => setPage && setPage("threat-intel")}
              animDelay={500}
            />
            <TiMiniTile
              label="KEV due in 7 days"
              value={tiStats.kev_due_within_7d}
              accent="#e8a03c"
              hint="Federal SLA approaching"
              onClick={() => setPage && setPage("threat-intel")}
              animDelay={600}
            />
            <TiMiniTile
              label="Ransomware-known"
              value={tiStats.ransomware_count}
              accent="var(--err)"
              hint="Patch first — confirmed in ransomware ops"
              onClick={() => setPage && setPage("threat-intel")}
              animDelay={700}
            />
            <TiMiniTile
              label="High EPSS (≥50%)"
              value={tiStats.high_epss_count}
              accent="var(--text-1)"
              hint="High exploit probability"
              onClick={() => setPage && setPage("threat-intel")}
              animDelay={800}
            />
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Animation 1: Staggered entrance on cards */}
        <div className="card dash-enter" style={{animationDelay: "450ms"}}>
          <div className="card-head">
            <div>
              <div className="card-title">Top targets by activity</div>
              <div className="card-sub">Most-scanned targets across all jobs</div>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={() => setPage && setPage("jobs")}>View jobs <Icons.ChevronRight size={12}/></button>
          </div>
          <div className="card-body flush">
            {topTargets.length === 0 ? (
              loading ? (
                <div style={{padding: 8}}>
                  {[0,1,2,3].map(i => <div key={i} className="skel-row"><div className="skel skel-circle"/><div style={{flex:1,display:'flex',flexDirection:'column',gap:6}}><div className="skel skel-line w80"/><div className="skel skel-line w40"/></div><div className="skel skel-line" style={{width:50}}/></div>)}
                </div>
              ) : (
                <div style={{padding: 40, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>No scans yet.</div>
              )
            ) : (
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th style={{width: 80}}>Scans</th>
                    <th style={{width: 80}}>Done</th>
                    <th style={{width: 80}}>Failed</th>
                    <th style={{width: 130}}>Last scan</th>
                  </tr>
                </thead>
                <tbody>
                  {topTargets.map(t => (
                    <tr key={t.target} className="clickable" onClick={() => setPage && setPage("jobs")}>
                      <td>
                        <div style={{display: "flex", alignItems: "center", gap: 10}}>
                          <Icons.Server size={14} color="var(--text-3)"/>
                          <span className="mono" style={{color: "var(--text-0)", fontWeight: 500}}>{t.target}</span>
                        </div>
                      </td>
                      <td className="num">{t.total}</td>
                      <td className="num" style={{color: t.done > 0 ? "var(--ok)" : "var(--text-3)"}}>{t.done}</td>
                      <td className="num" style={{color: t.failed > 0 ? "var(--err)" : "var(--text-3)"}}>{t.failed}</td>
                      <td className="muted" style={{fontSize: 12}}>
                        {t.last ? new Date(t.last).toLocaleString("en-US", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"}) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Animation 3: Donut chart stroke draw */}
        <div className="card dash-enter" style={{animationDelay: "550ms"}}>
          <div className="card-head">
            <div>
              <div className="card-title">Last scan distribution</div>
              <div className="card-sub">Severity breakdown of the most recent completed scan</div>
            </div>
          </div>
          <div className="card-body">
            {recentFindings.length === 0 ? (
              loading ? (
                <div style={{display:'flex',alignItems:'center',gap:24,padding:12}}>
                  <div className="skel" style={{width:130,height:130,borderRadius:'50%'}}/>
                  <div style={{flex:1,display:'flex',flexDirection:'column',gap:10}}>
                    {[0,1,2,3].map(i => <div key={i} style={{display:'flex',alignItems:'center',gap:8}}><div className="skel" style={{width:8,height:8,borderRadius:2}}/><div className="skel skel-line w60"/></div>)}
                  </div>
                </div>
              ) : (
                <div style={{padding: 24, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>No completed scans yet.</div>
              )
            ) : (
              <div className="donut-wrap">
                <Donut size={130} thickness={18} segments={segments} animate/>
                <div className="donut-legend">
                  {segments.map(s => (
                    <div key={s.label} className="donut-row">
                      <span className="pip" style={{background: s.color, width: 8, height: 8}}/>
                      <span className="name">{s.label}</span>
                      <span className="val">{s.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{height: 16}}/>

      <div className="grid-3">
        <div className="card dash-enter" style={{animationDelay: "600ms"}}>
          <div className="card-head">
            <div className="card-title">Recent scans</div>
            <button className="btn btn-ghost btn-sm" onClick={() => setPage && setPage("jobs")}>View jobs <Icons.ChevronRight size={12}/></button>
          </div>
          <div className="card-body flush">
            {jobs.length === 0 ? (
              loading ? (
                <div style={{padding: 8}}>
                  {[0,1,2].map(i => <div key={i} className="skel-row"><div className="skel skel-line w30"/><div className="skel skel-line" style={{flex:1}}/><div className="skel skel-line" style={{width:60}}/></div>)}
                </div>
              ) : (
                <div style={{padding: 40, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>No scans yet.</div>
              )
            ) : (
              <table className="tbl">
                <thead><tr><th>Job</th><th>Target</th><th>Status</th></tr></thead>
                <tbody>
                  {jobs.slice(0, 6).map(j => (
                    <tr key={j.id} className="clickable" onClick={() => setPage && setPage("jobs")}>
                      <td><span className="mono" style={{color: "var(--brand-text)"}}>#{j.id}</span></td>
                      <td><span className="mono" style={{fontSize: 12.5}}>{j.target}</span></td>
                      <td><Status s={j.status}/></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Animation 4: KEV badge pulse glow */}
        <div className="card dash-enter" style={{animationDelay: "700ms"}}>
          <div className="card-head">
            <div className="card-title">Top findings (last scan)</div>
          </div>
          <div className="card-body flush">
            {recentFindings.length === 0 ? (
              loading ? (
                <div>
                  {[0,1,2].map(i => <div key={i} style={{padding: "12px 18px", borderBottom: "1px solid var(--line)", display: "flex", alignItems: "center", gap: 12}}>
                    <div className="skel" style={{width:60,height:22,borderRadius:4}}/><div style={{flex:1,display:"flex",flexDirection:"column",gap:6}}><div className="skel skel-line w80"/><div className="skel skel-line w40"/></div><div className="skel" style={{width:50,height:14}}/>
                  </div>)}
                </div>
              ) : (
                <div style={{padding: 40, textAlign: "center", color: "var(--text-3)", fontSize: 13}}>No findings to show.</div>
              )
            ) : (
              <div style={{display: "flex", flexDirection: "column"}}>
                {recentFindings.map(f => (
                  <div key={f.id} onClick={() => openDrawer({
                    id: f.id, title: f.title, severity: f.severity,
                    host: f._target, plugin: f.plugin_id,
                    risk: f.risk_score, cvss: f.cvss_base, confidence: f.confidence,
                    sla: f.sla_days, kev: !!f.is_kev,
                    desc: f.description, remediation: f.remediation, evidence: f.evidence,
                  })}
                       style={{padding: "12px 18px", borderBottom: "1px solid var(--line)", cursor: "pointer", display: "flex", alignItems: "center", gap: 12}}
                       onMouseEnter={e => e.currentTarget.style.background = "var(--surface-1)"}
                       onMouseLeave={e => e.currentTarget.style.background = ""}>
                    <Sev s={f.severity}/>
                    {f.is_kev && <span className="kev kev-glow">KEV</span>}
                    <div style={{flex: 1, minWidth: 0}}>
                      <div style={{color: "var(--text-0)", fontSize: 13, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>{f.title}</div>
                      <div style={{fontSize: 11.5, color: "var(--text-3)", marginTop: 2, fontFamily: "var(--font-mono)"}}>{f._target}</div>
                    </div>
                    <Risk score={f.risk_score}/>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="dash-enter" style={{animationDelay: "800ms"}}>
          <LiveActivityFeed/>
        </div>
      </div>
    </>
  );
}
