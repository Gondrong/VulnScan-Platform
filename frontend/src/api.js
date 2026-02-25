// API base URL — set VITE_API_URL in .env or docker-compose environment.
// Falls back to same origin (works when frontend and backend are on the same host).
const API =
  import.meta.env.VITE_API_URL?.replace(/\/$/, "") ||
  `${window.location.protocol}//${window.location.hostname}:8080`;

export { API };

export function setToken(t) {
  localStorage.setItem("token", t);
}
export function getToken() {
  return localStorage.getItem("token");
}
export function clearToken() {
  localStorage.removeItem("token");
  localStorage.removeItem("vs_email");
}

/**
 * Core API helper — wraps fetch with auth header + JSON handling.
 * @param {string} path  - e.g. "/scan/jobs"
 * @param {RequestInit & {body?: any}} opts
 */
export async function api(path, opts = {}) {
  const token = getToken();
  const isForm = opts.body instanceof FormData;
  const headers = { ...(opts.headers || {}) };

  if (!isForm) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers,
    body:
      isForm
        ? opts.body
        : opts.body !== undefined
        ? JSON.stringify(opts.body)
        : undefined,
  });

  if (res.status === 401) {
    // Token expired or invalid — clear and force re-login
    clearToken();
    window.location.reload();
    throw new Error("Session expired — please log in again");
  }

  if (!res.ok) {
    let msg = res.statusText;
    try {
      const txt = await res.text();
      if (txt) msg = txt;
    } catch {}
    throw new Error(msg);
  }

  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}
