const runtime = window.__SAFEOPS__ || {};
const API_BASE = runtime.API_BASE || import.meta.env.VITE_API_BASE || "http://127.0.0.1:3010";
const REPORT_BASE = runtime.REPORT_BASE || import.meta.env.VITE_REPORT_BASE || "http://127.0.0.1:3006";

async function safeJson(r) {
  try { return await r.json(); } catch { return null; }
}

export async function apiGet(path) {
  const r = await fetch(`${API_BASE}${path}`);
  if (!r.ok) {
    const j = await safeJson(r);
    throw new Error(j?.error || j?.detail || `HTTP ${r.status}`);
  }
  return r.json();
}

export async function apiPost(path, body) {
  const r = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : "{}",
  });
  if (!r.ok) {
    const j = await safeJson(r);
    throw new Error(j?.error || j?.detail || `HTTP ${r.status}`);
  }
  return r.json();
}

export function getApiBase() { return API_BASE; }
export function getReportBase() { return REPORT_BASE; }
