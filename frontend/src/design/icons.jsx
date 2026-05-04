import React from "react";

const ICON = (path, fill = false) => ({ size = 16, color = "currentColor", ...rest } = {}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={fill ? color : "none"} stroke={fill ? "none" : color}
       strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" {...rest}>
    {path}
  </svg>
);

export const Icons = {
  Dashboard:  ICON(<><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></>),
  Scan:       ICON(<><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M7 12h10"/></>),
  Profile:    ICON(<><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></>),
  Key:        ICON(<><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></>),
  Database:   ICON(<><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/></>),
  Settings:   ICON(<><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></>),
  Search:     ICON(<><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></>),
  Plus:       ICON(<><path d="M12 5v14M5 12h14"/></>),
  Refresh:    ICON(<><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></>),
  Bell:       ICON(<><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></>),
  Help:       ICON(<><circle cx="12" cy="12" r="9"/><path d="M9.1 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></>),
  Sun:        ICON(<><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></>),
  Moon:       ICON(<><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></>),
  Monitor:    ICON(<><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></>),
  Filter:     ICON(<><path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/></>),
  ChevronDown:ICON(<><path d="m6 9 6 6 6-6"/></>),
  ChevronRight:ICON(<><path d="m9 18 6-6-6-6"/></>),
  Download:   ICON(<><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></>),
  External:   ICON(<><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></>),
  Sparkles:   ICON(<><path d="M12 3l1.9 4.6L18.5 9.5l-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/><path d="M19 14l.95 2.3L22 17.5l-2.05.95L19 21l-.95-2.55L16 17.5l2.05-1.2L19 14z"/></>),
  Shield:     ICON(<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></>),
  Activity:   ICON(<><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></>),
  Globe:      ICON(<><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z"/></>),
  Server:     ICON(<><rect x="2" y="3" width="20" height="7" rx="1.5"/><rect x="2" y="14" width="20" height="7" rx="1.5"/><path d="M6 6.5h.01M6 17.5h.01"/></>),
  Lock:       ICON(<><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></>),
  Code:       ICON(<><path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/></>),
  Cloud:      ICON(<><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></>),
  Layers:     ICON(<><path d="m12 2 10 5-10 5L2 7l10-5z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/></>),
  Clock:      ICON(<><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>),
  Check:      ICON(<><path d="M20 6 9 17l-5-5"/></>),
  X:          ICON(<><path d="M18 6 6 18M6 6l12 12"/></>),
  AlertTriangle: ICON(<><path d="M10.3 3.7 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.7a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></>),
  Info:       ICON(<><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></>),
  Play:       ICON(<><polygon points="5 3 19 12 5 21 5 3" fill="currentColor"/></>, true),
  Stop:       ICON(<><rect x="6" y="6" width="12" height="12" rx="1.5" fill="currentColor"/></>, true),
  Copy:       ICON(<><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></>),
  Eye:        ICON(<><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></>),
  EyeOff:     ICON(<><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.7 5.08A10.4 10.4 0 0 1 12 5c6 0 10 7 10 7a13.2 13.2 0 0 1-1.67 2.45"/><path d="M6.61 6.61A13.5 13.5 0 0 0 2 12s4 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><path d="M2 2l20 20"/></>),
  ArrowRight: ICON(<><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></>),
  ChevronLeft:ICON(<><path d="m15 18-6-6 6-6"/></>),
  User:       ICON(<><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/></>),
  LogOut:     ICON(<><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/></>),
  More:       ICON(<><circle cx="5" cy="12" r="1.4" fill="currentColor"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/><circle cx="19" cy="12" r="1.4" fill="currentColor"/></>),
  Target:     ICON(<><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/></>),
  Trash:      ICON(<><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></>),
  Edit:       ICON(<><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></>),
  Mail:       ICON(<><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 7L2 7"/></>),
  Slack:      ICON(<><rect x="13" y="2" width="3" height="8" rx="1.5"/><rect x="8" y="14" width="3" height="8" rx="1.5"/><rect x="14" y="13" width="8" height="3" rx="1.5"/><rect x="2" y="8" width="8" height="3" rx="1.5"/></>),
  Chip:       ICON(<><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9z"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></>),
  Brain:      ICON(<><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2a2.5 2.5 0 0 0-2.5 2.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></>),
  Folder:     ICON(<><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></>),
  FolderOpen: ICON(<><path d="M6 14l1.45-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.55 6a2 2 0 0 1-1.94 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.93a2 2 0 0 1 1.66.9l.82 1.2a2 2 0 0 0 1.66.9H18a2 2 0 0 1 2 2v2"/></>),
  FilePlus:   ICON(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 18v-6M9 15h6"/></>),
  FileText:   ICON(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8M16 17H8M10 9H8"/></>),
  Tag:        ICON(<><path d="M20.59 13.41 13.42 20.58a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><path d="M7 7h.01"/></>),
  Users:      ICON(<><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></>),
};

export function Sev({ s }) {
  return <span className={`sev sev-${s}`}>{s}</span>;
}

export function Pip({ s }) {
  return <span className={`pip pip-${s}`} />;
}

export function Risk({ score }) {
  if (score == null) return <span className="muted mono">—</span>;
  const pct = Math.min(100, Math.round(score * 10));
  const color = score >= 9 ? "var(--sev-critical)" : score >= 7 ? "var(--sev-high)" : score >= 4 ? "var(--sev-medium)" : "var(--sev-low)";
  return (
    <div className="risk">
      <div className="risk-track"><div className="risk-fill" style={{ width: `${pct}%`, background: color }} /></div>
      <span className="risk-num" style={{ color }}>{score.toFixed(1)}</span>
    </div>
  );
}

export function Status({ s }) {
  return <span className={`status ${s}`}>{s}</span>;
}

export function Donut({ size = 120, thickness = 16, segments }) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let acc = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="var(--surface-2)" strokeWidth={thickness} />
      {segments.map((s, i) => {
        const len = (s.value / total) * c;
        const rot = (acc / total) * 360 - 90;
        acc += s.value;
        return (
          <circle key={i} cx={size/2} cy={size/2} r={r} fill="none"
                  stroke={s.color} strokeWidth={thickness}
                  strokeDasharray={`${len} ${c}`} strokeDashoffset={0}
                  transform={`rotate(${rot} ${size/2} ${size/2})`}
                  strokeLinecap="butt" />
        );
      })}
      <text x="50%" y="48%" textAnchor="middle" fill="var(--text-0)"
            fontFamily="var(--font-display)" fontSize="22" fontWeight="600">
        {total}
      </text>
      <text x="50%" y="62%" textAnchor="middle" fill="var(--text-3)"
            fontFamily="var(--font-sans)" fontSize="10" letterSpacing="0.1em">
        FINDINGS
      </text>
    </svg>
  );
}

export function Sparkline({ data, w = 120, h = 32, color = "var(--brand)" }) {
  if (!data || data.length === 0) return null;
  const max = Math.max(...data, 1);
  const step = w / (data.length - 1 || 1);
  const pts = data.map((v, i) => [i * step, h - (v / max) * (h - 4) - 2]);
  const line = pts.map((p, i) => (i === 0 ? "M" : "L") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const area = line + ` L ${w} ${h} L 0 ${h} Z`;
  const gradId = `sparkfade-${Math.random().toString(36).slice(2, 8)}`;
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.2"/>
          <stop offset="100%" stopColor={color} stopOpacity="0"/>
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gradId})`} />
      <path d={line} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

export function Empty({ icon, title, body, action }) {
  const I = icon || Icons.Search;
  return (
    <div className="empty">
      <div className="empty-icon"><I size={20}/></div>
      <div className="empty-title">{title}</div>
      <div className="empty-body">{body}</div>
      {action}
    </div>
  );
}
