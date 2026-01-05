import React, { useEffect, useMemo, useState } from "react";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from "chart.js";
import { Line } from "react-chartjs-2";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);
ChartJS.defaults.animation = false;

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:3010";

function cn(...xs) {
  return xs.filter(Boolean).join(" ");
}

function fmt(n, fallback = "—") {
  if (n === null || n === undefined) return fallback;
  if (Number.isNaN(Number(n))) return fallback;
  return String(n);
}

function scoreTone(score) {
  if (typeof score !== "number") return { label: "No data", cls: "bg-slate-800 text-slate-200 border-slate-700" };
  if (score <= 40) return { label: "Critical", cls: "bg-rose-900/30 text-rose-200 border-rose-700/50" };
  if (score <= 60) return { label: "High", cls: "bg-orange-900/30 text-orange-200 border-orange-700/50" };
  if (score <= 80) return { label: "Medium", cls: "bg-amber-900/30 text-amber-200 border-amber-700/50" };
  return { label: "Good", cls: "bg-emerald-900/25 text-emerald-200 border-emerald-700/50" };
}

function Badge({ children, className = "" }) {
  return (
    <span className={cn("inline-flex items-center rounded-full border px-3 py-1 text-xs", className)}>
      {children}
    </span>
  );
}

function Button({ children, onClick, href, target, rel, variant = "secondary", disabled, title }) {
  const base =
    "inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-medium transition border";
  const styles = {
    primary: "bg-emerald-600 border-emerald-500 text-white hover:bg-emerald-700",
    secondary: "bg-slate-900 border-slate-800 text-slate-100 hover:bg-slate-800",
    ghost: "bg-transparent border-slate-800 text-slate-100 hover:bg-slate-900",
    danger: "bg-rose-600 border-rose-500 text-white hover:bg-rose-700",
  };

  if (href) {
    return (
      <a
        className={cn(base, styles[variant], disabled && "opacity-60 pointer-events-none")}
        href={href}
        target={target}
        rel={rel}
        title={title}
      >
        {children}
      </a>
    );
  }

  return (
    <button
      className={cn(base, styles[variant], disabled && "opacity-60 cursor-not-allowed")}
      onClick={onClick}
      disabled={disabled}
      title={title}
    >
      {children}
    </button>
  );
}

async function apiGet(path) {
  const r = await fetch(`${API_BASE}${path}`);
  const txt = await r.text();
  let data = null;
  try { data = txt ? JSON.parse(txt) : null; } catch { /* ignore */ }
  if (!r.ok) {
    const msg = data?.error || data?.detail || `HTTP ${r.status}`;
    throw new Error(msg);
  }
  return data ?? {};
}

export default function App() {
  const [pipelines, setPipelines] = useState([]);
  const [q, setQ] = useState("");
  const [pipeline, setPipeline] = useState("");
  const [limit, setLimit] = useState(30);

  const [health, setHealth] = useState({ api: "…", db: "…" });
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const [summary, setSummary] = useState(null);
  const [scores, setScores] = useState([]);
  const [trend, setTrend] = useState([]);
  const [reports, setReports] = useState(null);

  const filteredPipelines = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return pipelines;
    return pipelines.filter((p) => String(p.pipeline_id || p).toLowerCase().includes(s));
  }, [pipelines, q]);

  async function refreshHealth() {
    try {
      const h = await apiGet("/health");
      setHealth({ api: "OK", db: h?.postgres ? "OK" : "KO" });
    } catch {
      setHealth({ api: "KO", db: "KO" });
    }
  }

  async function refreshPipelines() {
    // dashboard-api (ton endpoint) renvoie maintenant: {"items":[{"pipeline_id":"ci-demo","runs":14},...]}
    const j = await apiGet("/pipelines");
    const items = Array.isArray(j.items) ? j.items : [];
    setPipelines(items);

    if (!pipeline && items.length) {
      const first = items[0]?.pipeline_id || items[0];
      setPipeline(first);
    }
  }

  async function refreshAll() {
    if (!pipeline) return;
    setLoading(true);
    setErr("");

    try {
      await refreshHealth();

      const lim = Math.min(200, Math.max(1, Number(limit) || 30));
      const [sum, tr, sc, rep] = await Promise.all([
        apiGet(`/dashboard/summary?pipeline=${encodeURIComponent(pipeline)}&limit=${lim}`),
        apiGet(`/dashboard/trend?pipeline=${encodeURIComponent(pipeline)}&limit=20`),
        apiGet(`/dashboard/scores?limit=${lim}`),
        apiGet(`/dashboard/reports?pipeline=${encodeURIComponent(pipeline)}`),
      ]);

      setSummary(sum);
      setTrend(tr?.points || []);
      setScores(sc?.items || []);
      setReports(rep || null);
    } catch (e) {
      setErr(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  }

  // initial
  useEffect(() => {
    refreshPipelines().catch((e) => setErr(String(e?.message || e)));
    refreshHealth().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // when pipeline changes
  useEffect(() => {
    if (pipeline) refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pipeline]);

  // chart
const trendChart = useMemo(() => {
  const labels = trend.map((p) => {
    const d = new Date(p.t);
    return Number.isNaN(d.getTime()) ? String(p.t) : d.toLocaleTimeString();
  });

  const data = trend.map((p) => Number(p.score));

  return {
    labels,
    datasets: [
      {
        label: "Score",
        data,
        tension: 0.35,

        // ✅ visibilité en dark mode
        borderColor: "rgba(16, 185, 129, 1)",      // emerald
        backgroundColor: "rgba(16, 185, 129, 0.15)",
        borderWidth: 3,
        pointRadius: 3,
        pointHoverRadius: 6,
        pointBackgroundColor: "rgba(16, 185, 129, 1)",
        fill: true,
      },
    ],
  };
}, [trend]);

const trendOptions = useMemo(
  () => ({
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        enabled: true,
        callbacks: {
          label: (ctx) => `Score: ${ctx.parsed.y}/100`,
        },
      },
    },
    scales: {
      x: {
        ticks: { color: "rgba(226, 232, 240, 0.7)", maxRotation: 0, autoSkip: true },
        grid: { color: "rgba(148, 163, 184, 0.12)" },
      },
      y: {
        min: 0,
        max: 100,
        ticks: { color: "rgba(226, 232, 240, 0.7)", stepSize: 10 },
        grid: { color: "rgba(148, 163, 184, 0.12)" },
      },
    },
  }),
  []
);

  const tone = scoreTone(summary?.score);

  return (
    <div className="min-h-screen bg-[#070A12] text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Header */}
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div className="flex items-start gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-2xl bg-white/10 border border-white/10 font-bold">
              S
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl font-semibold">SafeOps-LogMiner</h1>
                <Badge className={cn("border-slate-700", tone.cls)}>{tone.label}</Badge>
                <Badge className="border-slate-700 bg-slate-900 text-slate-200">
                  API: {API_BASE}
                </Badge>
                <Badge className={cn("border-slate-700", health.api === "OK" ? "bg-emerald-900/25 text-emerald-200" : "bg-rose-900/25 text-rose-200")}>
                  API Health: {health.api}
                </Badge>
                <Badge className={cn("border-slate-700", health.db === "OK" ? "bg-emerald-900/25 text-emerald-200" : "bg-rose-900/25 text-rose-200")}>
                  DB: {health.db}
                </Badge>
              </div>
              <p className="mt-1 text-sm text-slate-400">
                Dashboard DevSecOps — pipelines • tendance • score • rapports (HTML/PDF/SARIF/ZIP)
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="ghost" onClick={() => refreshPipelines()} disabled={loading}>
              Refresh pipelines
            </Button>
            <Button variant="secondary" onClick={() => refreshAll()} disabled={loading || !pipeline}>
              {loading ? "Refresh…" : "Refresh"}
            </Button>
            {reports?.generate && (
              <Button variant="primary" href={reports.generate} target="_blank" rel="noreferrer">
                Générer report (MS6)
              </Button>
            )}
          </div>
        </div>

        {/* Filters */}
        <div className="mt-6 rounded-3xl border border-white/10 bg-white/5 p-4">
          <div className="grid gap-4 md:grid-cols-12">
            <div className="md:col-span-4">
              <label className="text-xs font-medium text-slate-300">Search pipeline</label>
              <input
                className="mt-2 w-full rounded-2xl border border-white/10 bg-black/20 px-3 py-2 text-sm outline-none focus:border-emerald-500/50"
                placeholder="ex: ci-demo"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>

            <div className="md:col-span-5">
              <label className="text-xs font-medium text-slate-300">Pipeline</label>
              <select
                className="mt-2 w-full rounded-2xl border border-white/10 bg-black/20 px-3 py-2 text-sm outline-none focus:border-emerald-500/50"
                value={pipeline}
                onChange={(e) => setPipeline(e.target.value)}
              >
                {!filteredPipelines.length && <option value="">(No pipeline)</option>}
                {filteredPipelines.map((p) => {
                  const id = p.pipeline_id || p;
                  const runs = p.runs;
                  return (
                    <option key={id} value={id}>
                      {id}{typeof runs === "number" ? ` (${runs} runs)` : ""}
                    </option>
                  );
                })}
              </select>
              <div className="mt-2 text-xs text-slate-400">
                Conseil démo: crée plusieurs pipelines (demo-clean / demo-secrets / demo-bypass / demo-errors).
              </div>
            </div>

            <div className="md:col-span-3">
              <label className="text-xs font-medium text-slate-300">Limit (runs)</label>
              <input
                className="mt-2 w-full rounded-2xl border border-white/10 bg-black/20 px-3 py-2 text-sm outline-none focus:border-emerald-500/50"
                type="number"
                min={1}
                max={200}
                value={limit}
                onChange={(e) => setLimit(e.target.value)}
              />
              <div className="mt-2 text-xs text-slate-400">Nombre de runs pris en compte.</div>
            </div>
          </div>
        </div>

        {/* Error */}
        {err && (
          <div className="mt-4 rounded-3xl border border-rose-500/30 bg-rose-900/20 p-4 text-rose-200">
            <div className="font-semibold">Erreur</div>
            <div className="text-sm opacity-90">{err}</div>
          </div>
        )}

        {/* Grid */}
        <div className="mt-6 grid gap-4 lg:grid-cols-3">
          {/* Summary */}
          <div className="rounded-3xl border border-white/10 bg-white/5 p-5 lg:col-span-1">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-xs text-slate-400">Pipeline</div>
                <div className="text-lg font-semibold">{pipeline || "—"}</div>
              </div>
              <Badge className={cn("border-white/10", tone.cls)}>{tone.label}</Badge>
            </div>

            <div className="mt-4 h-[320px] rounded-2xl border border-white/10 bg-black/20 p-4">
              <div className="text-xs text-slate-400">Security score</div>
              <div className="mt-1 text-3xl font-bold">
                {typeof summary?.score === "number" ? `${Math.round(summary.score)}/100` : "—"}
              </div>
              <div className="mt-2 text-xs text-slate-400">
                (Score calculé via dashboard-api à partir de pipeline_runs)
              </div>
            </div>

            <div className="mt-4 grid grid-cols-3 gap-3">
              <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
                <div className="text-xs text-slate-400">Findings</div>
                <div className="text-lg font-semibold">{fmt(summary?.findings, "0")}</div>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
                <div className="text-xs text-slate-400">Anomalies</div>
                <div className="text-lg font-semibold">{fmt(summary?.anomalies, "0")}</div>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
                <div className="text-xs text-slate-400">Risk</div>
                <div className="text-lg font-semibold">{fmt(summary?.risk, "0")}</div>
              </div>
            </div>

            <div className="mt-4 text-xs text-slate-400">
              Last run:{" "}
              {summary?.lastRun?.created_at
                ? `${new Date(summary.lastRun.created_at).toLocaleString()} — ${summary?.lastRun?.status || "?"}`
                : "—"}
            </div>
          </div>

          {/* Trend */}
          <div className="rounded-3xl border border-white/10 bg-white/5 p-5 lg:col-span-2">
            <div className="flex items-center justify-between gap-2">
              <div>
                <div className="text-sm font-semibold">Trend</div>
                <div className="text-xs text-slate-400">Score dans le temps (pipeline_runs)</div>
              </div>
              <Button
                variant="ghost"
                onClick={() => refreshAll()}
                disabled={loading || !pipeline}
                title="Reload data"
              >
                Reload
              </Button>
            </div>

            <div className="mt-4 rounded-2xl border border-white/10 bg-black/20 p-4">
              {trend.length === 0 ? (
                <div className="text-sm text-slate-400">No data.</div>
              ) : (
                <Line data={trendChart} options={trendOptions} />
              )}
            </div>
          </div>

          {/* Scores list */}
          <div className="rounded-3xl border border-white/10 bg-white/5 p-5 lg:col-span-2">
            <div className="text-sm font-semibold">Scores par pipeline</div>
            <div className="text-xs text-slate-400">Moyenne des derniers runs</div>

            <div className="mt-4 grid gap-2 sm:grid-cols-2">
              {(scores || []).map((x) => {
                const t = scoreTone(typeof x.score === "number" ? x.score : null);
                return (
                  <button
                    key={x.pipeline_id}
                    onClick={() => setPipeline(x.pipeline_id)}
                    className={cn(
                      "rounded-2xl border bg-black/20 p-4 text-left transition hover:bg-black/30",
                      pipeline === x.pipeline_id ? "border-emerald-500/40" : "border-white/10"
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-semibold">{x.pipeline_id}</div>
                      <Badge className={cn("border-white/10", t.cls)}>
                        {typeof x.score === "number" ? `${Math.round(x.score)}/100` : "—"}
                      </Badge>
                    </div>
                    <div className="mt-2 text-xs text-slate-400">Runs: {fmt(x.runs, "0")}</div>
                  </button>
                );
              })}
              {!scores?.length && <div className="text-sm text-slate-400">No pipelines scores.</div>}
            </div>
          </div>

          {/* Reports */}
          <div className="rounded-3xl border border-white/10 bg-white/5 p-5 lg:col-span-1">
            <div className="text-sm font-semibold">Reports (MS6)</div>
            <div className="text-xs text-slate-400">HTML • PDF • SARIF • ZIP</div>

            <div className="mt-4 grid gap-2">
              <Button
                variant="primary"
                href={reports?.generate || "#"}
                target="_blank"
                rel="noreferrer"
                disabled={!reports?.generate}
              >
                Generate
              </Button>

              <div className="grid grid-cols-2 gap-2">
                <Button variant="ghost" href={reports?.html || "#"} target="_blank" rel="noreferrer" disabled={!reports?.html}>
                  HTML
                </Button>
                <Button variant="ghost" href={reports?.pdf || "#"} target="_blank" rel="noreferrer" disabled={!reports?.pdf}>
                  PDF
                </Button>
                <Button variant="ghost" href={reports?.sarif || "#"} target="_blank" rel="noreferrer" disabled={!reports?.sarif}>
                  SARIF
                </Button>
                <Button variant="ghost" href={reports?.zip || "#"} target="_blank" rel="noreferrer" disabled={!reports?.zip}>
                  ZIP
                </Button>
              </div>

              <div className="mt-2 text-xs text-slate-400">
                Si les boutons HTML/PDF renvoient 404 → clique d’abord sur <b>Generate</b>.
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-6 rounded-3xl border border-white/10 bg-white/5 p-5 text-sm text-slate-200">
          <div className="font-semibold">Checklist soutenance</div>
          <ul className="mt-2 list-disc pl-5 text-slate-300">
            <li>Montre la chaîne: <b>collector → parser → detector → anomaly → fix → report</b>.</li>
            <li>Choisis <b>ci-demo</b>, clique <b>Generate</b>, ouvre <b>HTML</b> puis <b>PDF</b>.</li>
            <li>Explique comment le score est calculé (riskPoints → score 0–100).</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
