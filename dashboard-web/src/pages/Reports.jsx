import React, { useEffect, useState } from "react";
import Card from "../components/Card";
import Button from "../components/Button";
import Badge from "../components/Badge";
import { apiGet, getReportBase } from "../api/client";

export default function Reports() {
  const [pipelines, setPipelines] = useState([]);
  const [pipeline, setPipeline] = useState("ci-demo");
  const [links, setLinks] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  async function load() {
    setLoading(true); setErr("");
    try {
      const p = await apiGet("/pipelines");
      const items = Array.isArray(p.items) ? p.items : [];
      setPipelines(items);
      const picked = items.includes(pipeline) ? pipeline : (items[0] || "ci-demo");
      setPipeline(picked);

      const r = await apiGet(`/dashboard/reports?pipeline=${encodeURIComponent(picked)}`);
      setLinks(r);
    } catch (e) {
      setErr(String(e?.message || e));
    } finally { setLoading(false); }
  }

  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  return (
    <div className="space-y-4">
      <div className="text-2xl font-semibold text-white">Reports</div>

      {err && (
        <div className="rounded-2xl border border-rose-200/20 bg-rose-950/30 p-4 text-rose-200">
          <div className="font-semibold">Erreur</div>
          <div className="text-sm">{err}</div>
        </div>
      )}

      <Card
        title="Générer & ouvrir les rapports"
        subtitle={`MS6 (report-generator) — base: ${getReportBase()}`}
        right={<Badge tone="blue">{loading ? "Loading…" : "Ready"}</Badge>}
      >
        <div className="flex flex-wrap items-center gap-2">
          <select
            className="rounded-xl bg-slate-900 border border-slate-200/10 px-3 py-2 text-sm text-white"
            value={pipeline}
            onChange={(e) => setPipeline(e.target.value)}
          >
            {pipelines.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>

          <Button onClick={load} disabled={loading}>{loading ? "Refresh…" : "Refresh"}</Button>

          {links?.generate && (
            <a href={links.generate} target="_blank" rel="noreferrer">
              <Button>Generate Report</Button>
            </a>
          )}
        </div>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          {["html","pdf","sarif","zip"].map((k) => (
            <div key={k} className="rounded-2xl border border-slate-200/10 bg-slate-950/30 p-4">
              <div className="text-sm font-semibold text-white">{k.toUpperCase()}</div>
              <div className="text-xs text-slate-400 mt-1 break-all">{links?.[k] || "—"}</div>
              <div className="mt-3">
                {links?.[k] ? (
                  <a href={links[k]} target="_blank" rel="noreferrer">
                    <Button variant="soft">Open</Button>
                  </a>
                ) : (
                  <Button variant="outline" disabled>Open</Button>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
