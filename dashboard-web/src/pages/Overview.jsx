import React, { useEffect, useMemo, useState } from "react";
import Card from "../components/Card";
import Badge from "../components/Badge";
import Button from "../components/Button";
import { apiGet, getApiBase, getReportBase } from "../api/client";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend,
} from "chart.js";
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);
ChartJS.defaults.animation = false;

export default function Overview() {
  const [health, setHealth] = useState({ api: "…", db: "…" });
  const [pipelines, setPipelines] = useState([]);
  const [pipeline, setPipeline] = useState("ci-demo");
  const [summary, setSummary] = useState(null);
  const [trend, setTrend] = useState([]);
  const [scores, setScores] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  async function load() {
    setLoading(true);
    setErr("");
    try {
      const h = await apiGet("/health");
      setHealth({ api: "OK", db: h?.postgres ? "OK" : "KO" });

      const p = await apiGet("/pipelines");
      const items = Array.isArray(p.items) ? p.items : [];
      setPipelines(items);
      const picked = items.includes(pipeline) ? pipeline : (items[0] || "ci-demo");
      setPipeline(picked);

      const [sc, sum, tr] = await Promise.all([
        apiGet(`/dashboard/scores?limit=30`),
        apiGet(`/dashboard/summary?pipeline=${encodeURIComponent(picked)}&limit=50`),
        apiGet(`/dashboard/trend?pipeline=${encodeURIComponent(picked)}&limit=20`),
      ]);

      setScores(sc?.items || []);
      setSummary(sum);
      setTrend(tr?.points || []);
    } catch (e) {
      setErr(String(e?.message || e));
      setHealth({ api: "KO", db: "KO" });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  const tone = useMemo(() => {
    const s = summary?.score;
    if (typeof s !== "number") return "gray";
    if (s <= 40) return "red";
    if (s <= 60) return "orange";
    if (s <= 80) return "yellow";
    return "green";
  }, [summary]);

  const chart = useMemo(() => {
    const labels = trend.map((p) => new Date(p.t).toLocaleTimeString());
    const data = trend.map((p) => p.score);
    return { labels, datasets: [{ label: "Score", data, tension: 0.35 }] };
  }, [trend]);

  const opts = useMemo(() => ({
    responsive: true,
    plugins: { legend: { display: false } },
    scales: { y: { min: 0, max: 100 } },
  }), []);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="text-2xl font-semibold text-white">Overview</div>
          <div className="text-sm text-slate-400">Vue globale: score, tendances, pipelines</div>
          <div className="mt-2 flex flex-wrap gap-2">
            <Badge tone={health.api === "OK" ? "green" : "red"}>API: {health.api}</Badge>
            <Badge tone={health.db === "OK" ? "green" : "red"}>DB: {health.db}</Badge>
            <Badge tone="blue">API_BASE: {getApiBase()}</Badge>
            <Badge tone="purple">REPORT_BASE: {getReportBase()}</Badge>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            className="rounded-xl bg-slate-900 border border-slate-200/10 px-3 py-2 text-sm text-white"
            value={pipeline}
            onChange={(e) => setPipeline(e.target.value)}
            disabled={loading}
          >
            {pipelines.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <Button onClick={load} disabled={loading}>{loading ? "Refresh…" : "Refresh"}</Button>
        </div>
      </div>

      {err && (
        <div className="rounded-2xl border border-rose-200/20 bg-rose-950/30 p-4 text-rose-200">
          <div className="font-semibold">Erreur</div>
          <div className="text-sm">{err}</div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card
          title="Security Score"
          subtitle={`Pipeline: ${pipeline}`}
          right={<Badge tone={tone}>{summary?.score ?? "--"}/100</Badge>}
        >
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-2xl bg-slate-950/40 border border-slate-200/10 p-3">
              <div className="text-xs text-slate-400">Findings</div>
              <div className="text-xl font-semibold text-white">{summary?.findings ?? 0}</div>
            </div>
            <div className="rounded-2xl bg-slate-950/40 border border-slate-200/10 p-3">
              <div className="text-xs text-slate-400">Anomalies</div>
              <div className="text-xl font-semibold text-white">{summary?.anomalies ?? 0}</div>
            </div>
            <div className="rounded-2xl bg-slate-950/40 border border-slate-200/10 p-3">
              <div className="text-xs text-slate-400">Risk</div>
              <div className="text-xl font-semibold text-white">{summary?.risk ?? 0}</div>
            </div>
          </div>

          <div className="mt-4 text-xs text-slate-400">
            Last run: {summary?.lastRun?.ts ? new Date(summary.lastRun.ts).toLocaleString() : "—"} • {summary?.lastRun?.status || "—"}
          </div>
        </Card>

        <Card title="Trend (Score)" subtitle="20 derniers points">
          {trend.length === 0 ? (
            <div className="text-sm text-slate-400">Aucune donnée.</div>
          ) : (
            <Line data={chart} options={opts} />
          )}
        </Card>

        <Card title="Pipelines" subtitle="Score moyen par pipeline">
          <div className="space-y-2">
            {(scores || []).map((x) => (
              <button
                key={x.pipeline_id}
                onClick={() => setPipeline(x.pipeline_id)}
                className="w-full text-left rounded-2xl border border-slate-200/10 bg-slate-950/30 hover:bg-slate-950/50 p-3"
              >
                <div className="flex items-center justify-between">
                  <div className="font-semibold text-white">{x.pipeline_id}</div>
                  <div className="text-slate-200">{Math.round(Number(x.score))}/100</div>
                </div>
                <div className="text-xs text-slate-400">runs: {x.runs}</div>
              </button>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
