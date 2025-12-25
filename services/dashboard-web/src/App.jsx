import { useEffect, useMemo, useRef, useState } from "react";
import { Bar, Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, BarElement, PointElement, LineElement, Tooltip, Legend, Filler);

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:3010";
const REPORT_BASE = import.meta.env.VITE_REPORT_BASE || "http://localhost:3006";

const tones = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high: "bg-orange-50 text-orange-700 border-orange-200",
  medium: "bg-yellow-50 text-yellow-800 border-yellow-200",
  low: "bg-emerald-50 text-emerald-700 border-emerald-200",
  na: "bg-slate-50 text-slate-700 border-slate-200",
};

function Pill({ children, tone = "na", className = "" }) {
  return (
    <span className={`text-xs px-2.5 py-1 rounded-full border ${tones[tone] || tones.na} ${className}`}>
      {children}
    </span>
  );
}

function Button({ variant = "solid", className = "", ...props }) {
  const base =
    "px-4 py-2 rounded-xl text-sm font-medium transition inline-flex items-center justify-center gap-2 select-none disabled:opacity-50 disabled:cursor-not-allowed";
  const styles =
    variant === "solid"
      ? "bg-slate-900 text-white hover:opacity-90 active:opacity-80"
      : variant === "success"
      ? "bg-emerald-600 text-white hover:opacity-90 active:opacity-80"
      : variant === "danger"
      ? "bg-red-600 text-white hover:opacity-90 active:opacity-80"
      : "bg-white border border-slate-200 hover:bg-slate-50 text-slate-800";
  return <button className={`${base} ${styles} ${className}`} {...props} />;
}

function KPI({ title, value, hint, icon }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs text-slate-500">{title}</p>
          <p className="mt-2 text-2xl font-semibold text-slate-900">{value}</p>
          {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
        </div>
        <div className="w-10 h-10 rounded-xl bg-slate-100 flex items-center justify-center text-slate-700">
          {icon}
        </div>
      </div>
    </div>
  );
}

function Panel({ title, subtitle, right, children }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-100 flex items-start justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
          {subtitle ? <p className="mt-1 text-xs text-slate-500">{subtitle}</p> : null}
        </div>
        {right}
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function fmtDate(x) {
  try {
    return new Date(x).toLocaleString();
  } catch {
    return String(x || "");
  }
}

function Empty({ title, desc }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6 text-center">
      <div className="text-sm font-semibold text-slate-900">{title}</div>
      {desc ? <div className="mt-1 text-sm text-slate-600">{desc}</div> : null}
    </div>
  );
}

function Modal({ open, title, onClose, children }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/30" onClick={onClose} />
      <div className="absolute left-1/2 top-1/2 w-[95vw] max-w-3xl -translate-x-1/2 -translate-y-1/2 rounded-2xl bg-white shadow-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
          <div className="font-semibold text-slate-900">{title}</div>
          <Button variant="outline" onClick={onClose} className="px-3 py-1.5">
            Fermer
          </Button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

function scoreTheme(score) {
  if (score == null) return { pill: "bg-slate-50 text-slate-700 border-slate-200", bar: "bg-slate-400", ring: "ring-slate-200" };
  if (score >= 80) return { pill: "bg-emerald-50 text-emerald-700 border-emerald-200", bar: "bg-emerald-500", ring: "ring-emerald-200" };
  if (score >= 50) return { pill: "bg-amber-50 text-amber-800 border-amber-200", bar: "bg-amber-500", ring: "ring-amber-200" };
  return { pill: "bg-red-50 text-red-700 border-red-200", bar: "bg-red-500", ring: "ring-red-200" };
}

export default function App() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  // Draft filters
  const [pipelineDraft, setPipelineDraft] = useState("all");
  const [severityDraft, setSeverityDraft] = useState("all");
  const [qDraft, setQDraft] = useState("");
  const [limitDraft, setLimitDraft] = useState(20);

  // Applied filters
  const [pipeline, setPipeline] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [q, setQ] = useState("");
  const [limit, setLimit] = useState(20);

  const [tab, setTab] = useState("overview"); // overview | alerts | reports
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Live refresh
  const [live, setLive] = useState(false);
  const [liveEvery, setLiveEvery] = useState(10); // seconds
  const liveTimer = useRef(null);

  const scoreValue = data?.score?.value ?? null;
  const scoreDetails = data?.score?.details ?? {};
  const alerts = data?.alerts || [];
  const vulns = data?.vulns || [];
  const fixes = data?.fixes || [];
  const anomalies = data?.anomalies || [];
  const timeline = data?.timeline || [];
  const reportLinks = data?.reportLinks || null;

  const pipelines = useMemo(() => {
    const list = data?.pipelines || [];
    return ["all", ...Array.from(new Set(list))];
  }, [data]);

  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) {
      const s = String(a.severity || "").toLowerCase();
      if (c[s] != null) c[s] += 1;
    }
    return c;
  }, [alerts]);

  const load = async (opts = {}) => {
    const p = opts.pipeline ?? pipeline;
    const s = opts.severity ?? severity;
    const qq = opts.q ?? q;
    const lim = opts.limit ?? limit;

    setLoading(true);
    setErr("");
    try {
      const params = new URLSearchParams();
      if (p !== "all") params.set("pipeline", p);
      if (s !== "all") params.set("severity", s);
      if (qq.trim()) params.set("q", qq.trim());
      params.set("limit", String(clamp(Number(lim || 20), 1, 200)));

      const url = `${API_BASE}/dashboard?${params.toString()}`;
      const r = await fetch(url);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j?.error || j?.detail || "Erreur Dashboard API");
      setData(j);
    } catch (e) {
      setErr(e?.message || "Impossible de charger les données.");
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (liveTimer.current) {
      clearInterval(liveTimer.current);
      liveTimer.current = null;
    }
    if (!live) return;

    const intervalMs = clamp(Number(liveEvery || 10), 3, 60) * 1000;
    liveTimer.current = setInterval(() => load(), intervalMs);

    return () => {
      if (liveTimer.current) clearInterval(liveTimer.current);
      liveTimer.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, liveEvery, pipeline, severity, q, limit]);

  const applyFilters = () => {
    setPipeline(pipelineDraft);
    setSeverity(severityDraft);
    setQ(qDraft);
    setLimit(limitDraft);
    load({ pipeline: pipelineDraft, severity: severityDraft, q: qDraft, limit: limitDraft });
  };

  const resetFilters = () => {
    setPipelineDraft("all");
    setSeverityDraft("all");
    setQDraft("");
    setLimitDraft(20);
    setPipeline("all");
    setSeverity("all");
    setQ("");
    setLimit(20);
    load({ pipeline: "all", severity: "all", q: "", limit: 20 });
  };

  const barData = useMemo(() => {
    const labels = (data?.pipelineScores || []).map((p) => p.pipeline_id);
    const values = (data?.pipelineScores || []).map((p) => p.score);
    return {
      labels,
      datasets: [{ label: "Score sécurité (0–100)", data: values, borderRadius: 10, barThickness: 18 }],
    };
  }, [data]);

  const chartOptionsBase = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: true, labels: { boxWidth: 10, boxHeight: 10 } },
        tooltip: { mode: "index", intersect: false },
      },
      scales: {
        x: { grid: { display: false } },
        y: { min: 0, max: 100 },
      },
    }),
    []
  );

  const lineData = useMemo(() => {
    const t = (timeline || []).slice(-30);
    const labels = t.map((x) => new Date(x.time).toLocaleTimeString());
    const values = t.map((x) => 100 - Number(x.severity_score || 0));
    return { labels, datasets: [{ label: "Tendance du score (0–100)", data: values, tension: 0.35, fill: true }] };
  }, [timeline]);

  const canReport = pipeline !== "all" && pipeline !== "" && pipeline != null;

  const getReportUrl = (type) => {
    if (reportLinks?.[`${type}_public`]) return reportLinks[`${type}_public`];
    if (type === "generate") return `${REPORT_BASE}/report/${pipeline}`;
    if (type === "zip") return `${REPORT_BASE}/report/${pipeline}/zip?mode=latest`;
    return `${REPORT_BASE}/report/${pipeline}/${type}`;
  };

  const generateReport = async () => {
    if (!canReport) return alert("Choisis un pipeline pour générer le rapport.");
    try {
      const r = await fetch(getReportUrl("generate"));
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j?.error || j?.detail || "Échec génération report");
      alert("Rapport généré ✅");
    } catch (e) {
      alert(e?.message || "Erreur génération report");
    }
  };

  const openInNew = (url) => window.open(url, "_blank");

  const theme = scoreTheme(scoreValue);

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="sticky top-0 z-10 border-b border-slate-200 bg-white/80 backdrop-blur">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-col gap-3">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-2xl bg-slate-900 text-white flex items-center justify-center font-bold">
                S
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-tight text-slate-900">SafeOps — Security Dashboard</h1>
                <p className="text-sm text-slate-600">Vulnérabilités • Anomalies • Fixes • Rapports</p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button onClick={() => load()} variant="outline">
                {loading ? "Actualisation..." : "Refresh"}
              </Button>

              <Button onClick={() => setLive((v) => !v)} variant={live ? "danger" : "outline"} className="px-3">
                {live ? "Live: ON" : "Live: OFF"}
              </Button>

              <div className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2">
                <span className="text-xs text-slate-500">Chaque</span>
                <input
                  type="number"
                  min={3}
                  max={60}
                  className="w-16 text-sm outline-none"
                  value={liveEvery}
                  onChange={(e) => setLiveEvery(clamp(Number(e.target.value || 10), 3, 60))}
                  disabled={!live}
                />
                <span className="text-xs text-slate-500">s</span>
              </div>

              <Button onClick={generateReport} variant="success" disabled={!canReport}>
                Générer report (MS6)
              </Button>
              <Button onClick={() => canReport && openInNew(getReportUrl("html"))} variant="outline" className="px-3" disabled={!canReport}>
                HTML
              </Button>
              <Button onClick={() => canReport && openInNew(getReportUrl("pdf"))} variant="outline" className="px-3" disabled={!canReport}>
                PDF
              </Button>
              <Button onClick={() => canReport && openInNew(getReportUrl("sarif"))} variant="outline" className="px-3" disabled={!canReport}>
                SARIF
              </Button>
              <Button onClick={() => canReport && openInNew(getReportUrl("zip"))} variant="outline" className="px-3" disabled={!canReport}>
                ZIP
              </Button>
            </div>
          </div>

          <div className="flex flex-col lg:flex-row lg:items-end gap-3">
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 flex-1">
              <div>
                <label className="text-xs text-slate-500">Pipeline</label>
                <select
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-slate-200 bg-white text-sm"
                  value={pipelineDraft}
                  onChange={(e) => setPipelineDraft(e.target.value)}
                >
                  {pipelines.map((p) => (
                    <option key={p} value={p}>
                      {p === "all" ? "Tous les pipelines" : p}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-500">Sévérité</label>
                <select
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-slate-200 bg-white text-sm"
                  value={severityDraft}
                  onChange={(e) => setSeverityDraft(e.target.value)}
                >
                  <option value="all">Toutes</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-500">Recherche</label>
                <input
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-slate-200 bg-white text-sm"
                  placeholder="R001, token, ERROR, title..."
                  value={qDraft}
                  onChange={(e) => setQDraft(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && applyFilters()}
                />
              </div>

              <div>
                <label className="text-xs text-slate-500">Limit</label>
                <input
                  type="number"
                  min={1}
                  max={200}
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-slate-200 bg-white text-sm"
                  value={limitDraft}
                  onChange={(e) => setLimitDraft(clamp(Number(e.target.value || 20), 1, 200))}
                />
              </div>
            </div>

            <div className="flex gap-2">
              <Button onClick={applyFilters}>Appliquer</Button>
              <Button onClick={resetFilters} variant="outline">
                Reset
              </Button>
            </div>
          </div>

          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="flex gap-2">
              {["overview", "alerts", "reports"].map((k) => (
                <button
                  key={k}
                  onClick={() => setTab(k)}
                  className={`px-3 py-1.5 rounded-xl text-sm border ${
                    tab === k ? "bg-slate-900 text-white border-slate-900" : "bg-white border-slate-200 text-slate-700 hover:bg-slate-50"
                  }`}
                >
                  {k === "overview" ? "Overview" : k === "alerts" ? `Alerts (${alerts.length})` : "Reports"}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Pill tone="critical">Critical: {sevCounts.critical}</Pill>
              <Pill tone="high">High: {sevCounts.high}</Pill>
              <Pill tone="medium">Medium: {sevCounts.medium}</Pill>
              <Pill tone="low">Low: {sevCounts.low}</Pill>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto p-6 space-y-6">
        {err ? (
          <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-red-700">
            <div className="font-semibold">Erreur</div>
            <div className="text-sm mt-1">{err}</div>
          </div>
        ) : null}

        {/* Score card colored + progress */}
        <div className={`rounded-2xl border border-slate-200 bg-white p-5 shadow-sm ring-4 ${theme.ring}`}>
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
              <div className="text-xs text-slate-500">Score sécurité global</div>
              <div className="text-4xl font-bold text-slate-900">{scoreValue == null ? "--" : `${scoreValue}/100`}</div>
              <div className="text-sm text-slate-600 mt-1">
                Findings: {scoreDetails.totalFindings ?? 0} • Anomalies: {scoreDetails.anomalyCount ?? 0} • Risk: {scoreDetails.totalRisk ?? 0}
              </div>
            </div>

            <div className="flex flex-wrap gap-2 justify-start lg:justify-end">
              <span className={`text-xs px-3 py-1 rounded-full border ${theme.pill}`}>API: {API_BASE}</span>
              <span className={`text-xs px-3 py-1 rounded-full border ${theme.pill}`}>Reports: {REPORT_BASE}</span>
              <span className={`text-xs px-3 py-1 rounded-full border ${theme.pill}`}>Pipeline: {pipeline === "all" ? "all" : pipeline}</span>
              <span className={`text-xs px-3 py-1 rounded-full border ${theme.pill}`}>Live: {live ? "ON" : "OFF"}</span>
            </div>
          </div>

          <div className="mt-4 h-2.5 w-full rounded-full bg-slate-100 overflow-hidden border border-slate-200">
            <div className={`h-full ${theme.bar}`} style={{ width: `${clamp(Number(scoreValue ?? 0), 0, 100)}%` }} />
          </div>
        </div>

        {loading && !data ? <Empty title="Chargement..." desc="Récupération des données depuis Dashboard API." /> : null}
        {!loading && !data ? <Empty title="Aucune donnée" desc="Vérifie dashboard-api (3010) et Postgres." /> : null}

        {data ? (
          <>
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <KPI title="Pipelines" value={data?.pipelines?.length || 0} hint="Pipelines détectés" icon="⛓️" />
              <KPI title="Vuln reports" value={vulns.length} hint="VulnDetector (MS3)" icon="🛡️" />
              <KPI title="Fixes" value={fixes.length} hint="FixSuggester (MS4)" icon="🧩" />
              <KPI title="Timeline points" value={timeline.length} hint="pipeline_runs" icon="📈" />
            </div>

            {tab === "overview" ? (
              <div className="grid lg:grid-cols-2 gap-6">
                <Panel title="Score sécurité par pipeline" subtitle="Plus élevé = mieux (0–100)" right={<Pill tone="na">Bar</Pill>}>
                  <div className="h-[320px]">
                    <Bar data={barData} options={chartOptionsBase} />
                  </div>
                </Panel>

                <Panel title="Tendance du score" subtitle="Basée sur pipeline_runs (severity_score)" right={<Pill tone="na">Line</Pill>}>
                  <div className="h-[320px]">
                    <Line data={lineData} options={chartOptionsBase} />
                  </div>
                  <div className="mt-2 text-xs text-slate-500">score_point = 100 - severity_score</div>
                </Panel>
              </div>
            ) : null}

            {tab === "alerts" ? (
              <Panel title="Vulnérabilités (Alerts)" subtitle="Clique une ligne pour voir les détails" right={<Pill tone="na">{alerts.length} items</Pill>}>
                <div className="overflow-auto">
                  <table className="w-full text-sm">
                    <thead className="text-xs text-slate-500">
                      <tr className="border-b border-slate-200">
                        <th className="text-left py-2 pr-2">Pipeline</th>
                        <th className="text-left py-2 pr-2">Rule</th>
                        <th className="text-left py-2 pr-2">Titre</th>
                        <th className="text-left py-2 pr-2">Sévérité</th>
                        <th className="text-left py-2 pr-2">Evidence</th>
                        <th className="text-left py-2 pr-2">Date</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.map((a, i) => (
                        <tr
                          key={i}
                          className="border-b border-slate-100 hover:bg-slate-50 cursor-pointer"
                          onClick={() => setSelectedAlert(a)}
                        >
                          <td className="py-2 pr-2 font-medium text-slate-900">{a.pipeline}</td>
                          <td className="py-2 pr-2">
                            <Pill tone="na">{a.rule_id || "-"}</Pill>
                          </td>
                          <td className="py-2 pr-2">
                            <div className="font-medium text-slate-900">{a.title || "-"}</div>
                            {a.recommendation ? <div className="text-xs text-slate-500 truncate max-w-[620px]">{a.recommendation}</div> : null}
                          </td>
                          <td className="py-2 pr-2">
                            <Pill tone={a.severity}>{a.severity}</Pill>
                          </td>
                          <td className="py-2 pr-2 text-slate-600 max-w-[260px] truncate" title={a.evidence}>
                            {a.evidence || "-"}
                          </td>
                          <td className="py-2 pr-2 text-slate-500">{fmtDate(a.created_at)}</td>
                        </tr>
                      ))}
                      {alerts.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="py-4 text-slate-600">
                            Aucun résultat pour ces filtres.
                          </td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </Panel>
            ) : null}

            {tab === "reports" ? (
              <div className="grid lg:grid-cols-2 gap-6">
                <Panel
                  title="Rapports (MS6)"
                  subtitle="Générer et télécharger les rapports du pipeline sélectionné"
                  right={canReport ? <Pill tone="low">Ready</Pill> : <Pill tone="na">Select pipeline</Pill>}
                >
                  <div className="space-y-3">
                    <div className="text-sm text-slate-700">
                      Pipeline sélectionné : <span className="font-semibold">{pipeline === "all" ? "Aucun (all)" : pipeline}</span>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <Button onClick={generateReport} variant="success" disabled={!canReport}>
                        Générer report
                      </Button>
                      <Button onClick={() => canReport && openInNew(getReportUrl("html"))} variant="outline" disabled={!canReport}>
                        Ouvrir HTML
                      </Button>
                      <Button onClick={() => canReport && openInNew(getReportUrl("pdf"))} variant="outline" disabled={!canReport}>
                        Télécharger PDF
                      </Button>
                      <Button onClick={() => canReport && openInNew(getReportUrl("sarif"))} variant="outline" disabled={!canReport}>
                        Télécharger SARIF
                      </Button>
                      <Button onClick={() => canReport && openInNew(getReportUrl("zip"))} variant="outline" disabled={!canReport}>
                        Télécharger ZIP
                      </Button>
                    </div>

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700">
                      <div className="font-semibold mb-1">Endpoints utilisés</div>
                      <div>Generate: {getReportUrl("generate")}</div>
                      <div>HTML: {getReportUrl("html")}</div>
                      <div>PDF: {getReportUrl("pdf")}</div>
                      <div>SARIF: {getReportUrl("sarif")}</div>
                      <div>ZIP: {getReportUrl("zip")}</div>
                    </div>
                  </div>
                </Panel>

                <Panel title="Fix suggestions" subtitle="Dernières corrections (MS4)" right={<Pill tone="na">{fixes.length}</Pill>}>
                  <div className="space-y-2">
                    {fixes.slice(0, 12).map((f) => (
                      <div key={f.id} className="rounded-xl border border-slate-200 p-3">
                        <div className="flex items-center justify-between gap-3">
                          <div className="font-semibold text-slate-900">{f.title}</div>
                          <Pill tone="na">{f.rule_id}</Pill>
                        </div>
                        <div className="text-xs text-slate-500 mt-1">{fmtDate(f.created_at)}</div>
                      </div>
                    ))}
                    {fixes.length === 0 ? <div className="text-sm text-slate-600">Aucune suggestion disponible.</div> : null}
                  </div>
                </Panel>
              </div>
            ) : null}

            <Modal
              open={!!selectedAlert}
              title={`Détails — ${selectedAlert?.rule_id || ""} ${selectedAlert?.title || ""}`}
              onClose={() => setSelectedAlert(null)}
            >
              {selectedAlert ? (
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-2">
                    <Pill tone="na">Pipeline: {selectedAlert.pipeline}</Pill>
                    <Pill tone="na">Run: {selectedAlert.run_id || "-"}</Pill>
                    <Pill tone={selectedAlert.severity}>{selectedAlert.severity}</Pill>
                    <Pill tone="na">{fmtDate(selectedAlert.created_at)}</Pill>
                  </div>

                  <div className="rounded-xl border border-slate-200 p-4">
                    <div className="text-xs text-slate-500">Description</div>
                    <div className="mt-1 text-sm text-slate-900">{selectedAlert.description || "-"}</div>

                    <div className="mt-3 text-xs text-slate-500">Recommendation</div>
                    <div className="mt-1 text-sm text-slate-900">{selectedAlert.recommendation || "-"}</div>

                    <div className="mt-3 text-xs text-slate-500">Evidence</div>
                    <div className="mt-1 text-sm text-slate-900 break-words">{selectedAlert.evidence || "-"}</div>
                  </div>

                  <div className="rounded-xl border border-slate-200 p-4">
                    <div className="text-xs text-slate-500">Mapping</div>
                    <div className="mt-2 flex flex-col gap-2 text-sm">
                      <div>
                        <span className="font-semibold">OWASP:</span>{" "}
                        <span className="text-slate-800">{selectedAlert?.mapping?.owasp || "-"}</span>
                      </div>
                      <div>
                        <span className="font-semibold">SLSA:</span>{" "}
                        <span className="text-slate-800">{selectedAlert?.mapping?.slsa || "-"}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}
            </Modal>
          </>
        ) : null}
      </main>
    </div>
  );
}
