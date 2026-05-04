// API client — wraps fetch with bearer-token auth + JSON handling.
//
// VITE_API_URL behavior:
//   - empty / unset       → same-origin relative URLs (use a reverse proxy in prod,
//                           Vite's built-in proxy in dev — see vite.config.js)
//   - "http://host:port"  → absolute URL (must match the page's protocol or be
//                           reachable from the browser; CORS must be open on the backend)
const RAW_API = import.meta.env.VITE_API_URL?.trim()?.replace(/\/$/, "") ?? "";
const API = RAW_API; // empty string = relative paths

export { API };

export function setToken(t) { localStorage.setItem("vs_token", t); }
export function getToken()  { return localStorage.getItem("vs_token"); }
export function clearToken() {
  localStorage.removeItem("vs_token");
  localStorage.removeItem("vs_user");
}
export function setUser(u)  { localStorage.setItem("vs_user", JSON.stringify(u)); }
export function getUser() {
  try { return JSON.parse(localStorage.getItem("vs_user") || "null"); } catch { return null; }
}

export async function api(path, opts = {}) {
  const token = getToken();
  const isForm = opts.body instanceof FormData;
  const headers = { ...(opts.headers || {}) };

  if (!isForm && opts.body !== undefined) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers,
    body: isForm ? opts.body : opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  if (res.status === 401) {
    clearToken();
    throw new Error("Session expired — please sign in again");
  }

  if (!res.ok) {
    let msg = res.statusText;
    try {
      const txt = await res.text();
      if (txt) {
        try {
          const parsed = JSON.parse(txt);
          const detail = parsed.detail;
          if (Array.isArray(detail)) {
            // FastAPI 422 validation errors — flatten to "loc: msg" lines
            msg = detail
              .map((d) => {
                const loc = Array.isArray(d?.loc) ? d.loc.filter((x) => x !== "body").join(".") : "";
                const m = d?.msg || "";
                return loc ? `${loc}: ${m}` : m;
              })
              .filter(Boolean)
              .join("; ") || txt;
          } else if (typeof detail === "string") {
            msg = detail;
          } else if (detail) {
            msg = JSON.stringify(detail);
          } else {
            msg = txt;
          }
        } catch { msg = txt; }
      }
    } catch {}
    throw new Error(msg);
  }

  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

// ── Auth ─────────────────────────────────────────────────────────────
export async function login(email, password) {
  const r = await api("/auth/login", { method: "POST", body: { email, password } });
  setToken(r.token);
  setUser({ email, role: r.role, workspace_id: r.workspace_id });
  return r;
}

export async function me() { return api("/auth/me"); }

export function logout() { clearToken(); }

// ── Credentials ──────────────────────────────────────────────────────
export const credentialsApi = {
  list:   ()         => api("/credentials"),
  create: (body)     => api("/credentials", { method: "POST", body }),
  delete: (id)       => api(`/credentials/${id}`, { method: "DELETE" }),
};

// ── Datasets ─────────────────────────────────────────────────────────
export const datasetsApi = {
  list:    ()        => api("/datasets"),
  create:  (body)    => api("/datasets", { method: "POST", body }),
  update:  (id, body)=> api(`/datasets/${id}`, { method: "PATCH", body }),
  toggle:  (id)      => api(`/datasets/${id}/toggle`, { method: "PATCH" }),
  delete:  (id)      => api(`/datasets/${id}`, { method: "DELETE" }),
  refresh: (body)    => api("/datasets/refresh", { method: "POST", body }),
  refreshStatus: ()  => api("/datasets/refresh/status"),
};

// ── Settings ─────────────────────────────────────────────────────────
export const settingsApi = {
  info:        ()      => api("/settings/info"),
  stats:       ()      => api("/settings/stats"),
  listUsers:   ()      => api("/settings/users"),
  createUser:  (body)  => api("/settings/users", { method: "POST", body }),
  deleteUser:  (id)    => api(`/settings/users/${id}`, { method: "DELETE" }),
  changePassword: (body) => api("/settings/users/me/password", { method: "PUT", body }),
  resetPassword: (id, body) => api(`/settings/users/${id}/password`, { method: "PUT", body }),
  allowlist:   ()      => api("/settings/allowlist"),
  updateAllowlist: (body) => api("/settings/allowlist", { method: "PUT", body }),
  updateCheck: ()      => api("/settings/update/check"),
  updateStatus:()      => api("/settings/update/status"),
  triggerUpdate: ()    => api("/settings/update/trigger", { method: "POST" }),
};

// ── Integrations ─────────────────────────────────────────────────────
export const integrationsApi = {
  list:    ()                  => api("/integrations"),
  save:    (provider, body)    => api(`/integrations/${provider}`,        { method: "POST",   body }),
  // body is optional — if supplied, backend tests with the in-flight config;
  // if omitted, backend falls back to the last saved config for the provider.
  test:    (provider, body)    => api(`/integrations/${provider}/test`,   { method: "POST",   body }),
  remove:  (provider)          => api(`/integrations/${provider}`,        { method: "DELETE" }),
};

// ── AI ───────────────────────────────────────────────────────────────
export const aiApi = {
  providers:   ()      => api("/ai/providers"),
  analyze:     (body)  => api("/ai/analyze", { method: "POST", body }),
  status:      (id)    => api(`/ai/status/${id}`),
  jobResults:  (jobId) => api(`/ai/results/${jobId}`),
};

// ── Assets ───────────────────────────────────────────────────────────
export const assetsApi = {
  list:    ()           => api("/assets"),
  get:     (id)         => api(`/assets/${id}`),
  create:  (body)       => api("/assets", { method: "POST", body }),
  update:  (id, body)   => api(`/assets/${id}`, { method: "PATCH", body }),
  delete:  (id)         => api(`/assets/${id}`, { method: "DELETE" }),
  jobs:    (id)         => api(`/assets/${id}/jobs`),
  targets: (id)         => api(`/assets/${id}/targets`),
};

// ── Reports ──────────────────────────────────────────────────────────
export const reportsApi = {
  list:        ()                  => api("/reports"),
  download:    async (jobId, fmt, templateId = null) => {
    const token = getToken();
    const params = new URLSearchParams({ format: fmt });
    if (templateId) params.set("template_id", String(templateId));
    const res = await fetch(`${API}/reports/${jobId}/download?${params}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      let msg = res.statusText;
      try { const txt = await res.text(); if (txt) msg = txt; } catch {}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const cd = res.headers.get("Content-Disposition") || "";
    const m = cd.match(/filename="([^"]+)"/);
    const filename = m ? m[1] : `report-${jobId}.${fmt}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    a.remove(); URL.revokeObjectURL(url);
  },

  // Templates
  listTemplates:   ()         => api("/reports/templates"),
  listSections:    ()         => api("/reports/templates/sections"),
  createTemplate:  (body)     => api("/reports/templates", { method: "POST", body }),
  updateTemplate:  (id, body) => api(`/reports/templates/${id}`, { method: "PATCH", body }),
  cloneTemplate:   (id)       => api(`/reports/templates/${id}/clone`, { method: "POST" }),
  deleteTemplate:  (id)       => api(`/reports/templates/${id}`, { method: "DELETE" }),
};

// ── SLA (extends settingsApi) ───────────────────────────────────────
export const slaApi = {
  get:     ()     => api("/settings/sla"),
  update:  (body) => api("/settings/sla", { method: "PUT", body }),
  reset:   ()     => api("/settings/sla/reset", { method: "POST" }),
};

// ── Events (live activity) ───────────────────────────────────────────
export const eventsApi = {
  recent:  (limit = 20) => api(`/events/recent?limit=${limit}`),
};

// ── Web Auth helper (login form inspector + test login) ─────────────
export const webAuthApi = {
  inspect:   (login_url)               => api("/scan/web-auth/inspect",    { method: "POST", body: { login_url } }),
  testLogin: (web_auth, base_url)      => api("/scan/web-auth/test-login", { method: "POST", body: { web_auth, base_url } }),
};

// ── Threat Intel (fused NVD + EPSS + CISA KEV) ──────────────────────
export const threatIntelApi = {
  stats:    ()                  => api("/threat-intel/stats"),
  list:     (params = {})       => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v === undefined || v === null || v === "" || v === false) return;
      qs.set(k, String(v));
    });
    const s = qs.toString();
    return api(`/threat-intel/cves${s ? "?" + s : ""}`);
  },
  detail:   (cveId)             => api(`/threat-intel/cves/${encodeURIComponent(cveId)}`),
  refresh:  ()                  => api("/threat-intel/refresh", { method: "POST" }),
};

// ── API Scanner ─────────────────────────────────────────────────────
export const apiScannerApi = {
  checks:    ()                    => api("/scan/api-scanner/checks"),
  parse:     (formData)            => api("/scan/api-scanner/parse", { method: "POST", body: formData }),
  createJob: (formData)            => api("/scan/api-scanner/jobs",  { method: "POST", body: formData }),
};

// ── Scan ─────────────────────────────────────────────────────────────
export const scanApi = {
  listJobs:   ()       => api("/scan/jobs"),
  getJob:     (id)     => api(`/scan/jobs/${id}`),
  createJob:  (body)   => api("/scan/jobs", { method: "POST", body }),
  cancelJob:  (id)     => api(`/scan/jobs/${id}/cancel`, { method: "POST" }),
  deleteJob:  (id)     => api(`/scan/jobs/${id}`, { method: "DELETE" }),
  rescanJob:  (id)     => api(`/scan/jobs/${id}/rescan`, { method: "POST" }),

  listProfiles:   ()           => api("/scan/profiles"),
  createProfile:  (body)       => api("/scan/profiles", { method: "POST", body }),
  updateProfile:  (id, body)   => api(`/scan/profiles/${id}`, { method: "PUT", body }),
  deleteProfile:  (id)         => api(`/scan/profiles/${id}`, { method: "DELETE" }),

  listPlugins:    () => api("/scan/plugins"),
  history:        (target) => api(`/scan/history/${encodeURIComponent(target)}`),

  listSchedules:    ()           => api("/scan/schedules"),
  createSchedule:   (body)       => api("/scan/schedules", { method: "POST", body }),
  toggleSchedule:   (id)         => api(`/scan/schedules/${id}/toggle`, { method: "PUT" }),
  deleteSchedule:   (id)         => api(`/scan/schedules/${id}`, { method: "DELETE" }),
};
