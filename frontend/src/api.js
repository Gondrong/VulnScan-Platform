const API = import.meta.env.VITE_API_URL || "http://localhost:8080";

export function setToken(t){ localStorage.setItem("token", t); }
export function getToken(){ return localStorage.getItem("token"); }
export function clearToken(){ localStorage.removeItem("token"); }

export async function api(path, opts={}){
  const token = getToken();
  const headers = opts.headers || {};

  const isForm = (opts.body && typeof FormData !== "undefined" && opts.body instanceof FormData);

  if (!isForm) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers,
    body: isForm ? opts.body : (opts.body ? JSON.stringify(opts.body) : undefined),
  });

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(txt || res.statusText);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}
