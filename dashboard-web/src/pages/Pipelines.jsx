import React, { useEffect, useMemo, useState } from "react";
import Card from "../components/Card";
import Button from "../components/Button";
import Badge from "../components/Badge";
import { apiGet } from "../api/client";

export default function Pipelines() {
  const [items, setItems] = useState([]);
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  async function load() {
    setLoading(true); setErr("");
    try {
      const j = await apiGet("/pipelines");
      // ton API renvoie parfois strings, parfois objets => normalise
      const raw = Array.isArray(j.items) ? j.items : [];
      const normalized = raw.map((x) =>
        typeof x === "string" ? ({ pipeline_id: x, runs: null }) : x
      );
      setItems(normalized);
    } catch (e) {
      setErr(String(e?.message || e));
    } finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return items;
    return items.filter((x) => String(x.pipeline_id || x.pipeline || "").toLowerCase().includes(s));
  }, [items, q]);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="text-2xl font-semibold">Pipelines</div>
          <div className="text-sm text-slate-400">Liste + recherche</div>
        </div>
        <div className="flex gap-2">
          <input
            className="rounded-xl bg-slate-900 border border-slate-200/10 px-3 py-2 text-sm text-white"
            placeholder="Search pipeline…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <Button onClick={load} disabled={loading}>{loading ? "…" : "Refresh"}</Button>
        </div>
      </div>

      {err && <div className="rounded-2xl border border-rose-200/20 bg-rose-950/30 p-4 text-rose-200">{err}</div>}

      <Card
        title="Pipelines"
        subtitle={`${filtered.length} pipelines`}
        right={<Badge tone={loading ? "yellow" : "green"}>{loading ? "Loading" : "Ready"}</Badge>}
      >
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((p) => (
            <div key={p.pipeline_id || p.pipeline} className="rounded-2xl border border-slate-200/10 bg-slate-950/30 p-4">
              <div className="font-semibold">{p.pipeline_id || p.pipeline}</div>
              <div className="text-xs text-slate-400 mt-1">runs: {p.runs ?? "—"}</div>
              <div className="mt-3 flex gap-2">
                <a href={`/runs?pipeline=${encodeURIComponent(p.pipeline_id || p.pipeline)}`}>
                  <Button variant="soft">View runs</Button>
                </a>
                <a href={`/findings?pipeline=${encodeURIComponent(p.pipeline_id || p.pipeline)}`}>
                  <Button variant="outline">Findings</Button>
                </a>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
