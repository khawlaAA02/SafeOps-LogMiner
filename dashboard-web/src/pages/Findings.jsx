import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import Card from "../components/Card";
import Button from "../components/Button";
import Badge from "../components/Badge";
import DataTable from "../components/DataTable";
import Modal from "../components/Modal";
import CodeBlock from "../components/CodeBlock";
import { apiGet } from "../api/client";

const TABS = [
  { key: "vulns", label: "Vulnerabilities" },
  { key: "anomalies", label: "Anomalies" },
  { key: "fixes", label: "Fixes" },
  { key: "patches", label: "Patches" },
];

export default function Findings() {
  const [sp] = useSearchParams();
  const [pipeline, setPipeline] = useState(sp.get("pipeline") || "ci-demo");
  const [tab, setTab] = useState("vulns");

  const [page, setPage] = useState(0);
  const pageSize = 20;

  const [data, setData] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [selected, setSelected] = useState(null);

  function endpoint() {
    if (tab === "vulns") return "/dashboard/vulns";
    if (tab === "anomalies") return "/dashboard/anomalies";
    if (tab === "fixes") return "/dashboard/fixes";
    return "/dashboard/patches";
  }

  async function load() {
    setLoading(true); setErr("");
    try {
      const j = await apiGet(`${endpoint()}?pipeline=${encodeURIComponent(pipeline)}&limit=${pageSize}&offset=${page*pageSize}`);
      setData({ items: j.items || [], total: j.total || 0 });
    } catch (e) {
      setErr(String(e?.message || e));
    } finally { setLoading(false); }
  }

  useEffect(() => { setPage(0); }, [tab, pipeline]);
  useEffect(() => { load(); }, [tab, pipeline, page]);

  const cols = useMemo(() => {
    if (tab === "vulns") {
      return [
        { key: "detected_at", header: "Time", render: (r) => r.detected_at ? new Date(r.detected_at).toLocaleString() : "—" },
        { key: "severity", header: "Severity" },
        { key: "rule_id", header: "Rule" },
        { key: "title", header: "Title" },
        { key: "run_id", header: "Run" },
      ];
    }
    if (tab === "anomalies") {
      return [
        { key: "ts", header: "Time", render: (r) => r.ts ? new Date(r.ts).toLocaleString() : "—" },
        { key: "model_used", header: "Model" },
        { key: "anomaly_score", header: "Score" },
        { key: "is_anomaly", header: "Anomaly" },
        { key: "run_id", header: "Run" },
      ];
    }
    if (tab === "fixes") {
      return [
        { key: "created_at", header: "Time", render: (r) => r.created_at ? new Date(r.created_at).toLocaleString() : "—" },
        { key: "safe", header: "Safe" },
        { key: "rule_id", header: "Rule" },
        { key: "title", header: "Title" },
        { key: "run_id", header: "Run" },
      ];
    }
    return [
      { key: "created_at", header: "Time", render: (r) => r.created_at ? new Date(r.created_at).toLocaleString() : "—" },
      { key: "status", header: "Status" },
      { key: "rule_id", header: "Rule" },
      { key: "run_id", header: "Run" },
    ];
  }, [tab]);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="text-2xl font-semibold">Findings</div>
          <div className="text-sm text-slate-400">Tout ce qui sort de MS3/MS5/MS6</div>
        </div>
        <div className="flex gap-2">
          <input
            className="rounded-xl bg-slate-900 border border-slate-200/10 px-3 py-2 text-sm text-white"
            value={pipeline}
            onChange={(e) => setPipeline(e.target.value)}
            placeholder="pipeline id…"
          />
          <Button onClick={load} disabled={loading}>{loading ? "…" : "Refresh"}</Button>
          <Badge tone={err ? "red" : "green"}>{err ? "Error" : "OK"}</Badge>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`rounded-xl px-4 py-2 text-sm border border-slate-200/10 ${
              tab === t.key ? "bg-white text-slate-900" : "bg-slate-900 text-white hover:bg-slate-800"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {err && <div className="rounded-2xl border border-rose-200/20 bg-rose-950/30 p-4 text-rose-200">{err}</div>}

      <Card title={`${TABS.find(x => x.key===tab)?.label} — ${pipeline}`} subtitle={`Total: ${data.total}`}>
        <DataTable
          columns={cols}
          rows={data.items}
          loading={loading}
          page={page}
          pageSize={pageSize}
          total={data.total}
          onPrev={() => setPage((p) => Math.max(0, p - 1))}
          onNext={() => setPage((p) => p + 1)}
          onRowClick={(r) => setSelected(r)}
        />
      </Card>

      <Modal open={!!selected} title="Details" onClose={() => setSelected(null)}>
        <CodeBlock code={selected} label="Row JSON" />
        {tab === "fixes" && (
          <div className="mt-4 grid gap-3">
            <CodeBlock code={selected?.original_yaml || ""} label="original_yaml" />
            <CodeBlock code={selected?.yaml_patch || ""} label="yaml_patch" />
            <CodeBlock code={selected?.patched_yaml_preview || ""} label="patched_yaml_preview" />
          </div>
        )}
      </Modal>
    </div>
  );
}
