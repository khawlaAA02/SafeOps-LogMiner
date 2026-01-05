import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import Card from "../components/Card";
import Button from "../components/Button";
import Badge from "../components/Badge";
import DataTable from "../components/DataTable";
import Modal from "../components/Modal";
import CodeBlock from "../components/CodeBlock";
import { apiGet } from "../api/client";

export default function Runs() {
  const [sp] = useSearchParams();
  const [pipeline, setPipeline] = useState(sp.get("pipeline") || "ci-demo");

  const [page, setPage] = useState(0);
  const pageSize = 20;

  const [data, setData] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const [selected, setSelected] = useState(null);

  async function load() {
    setLoading(true); setErr("");
    try {
      const j = await apiGet(`/dashboard/runs?pipeline=${encodeURIComponent(pipeline)}&limit=${pageSize}&offset=${page*pageSize}`);
      setData({ items: j.items || [], total: j.total || 0 });
    } catch (e) {
      setErr(String(e?.message || e));
    } finally { setLoading(false); }
  }

  useEffect(() => { load(); }, [pipeline, page]);

  const cols = useMemo(() => ([
    { key: "created_at", header: "Time", render: (r) => r.created_at ? new Date(r.created_at).toLocaleString() : "—" },
    { key: "status", header: "Status" },
    { key: "source", header: "Source" },
    { key: "run_id", header: "Run ID", render: (r) => String(r.run_id || "").slice(0, 8) + "…" },
    { key: "error_count", header: "Errors" },
    { key: "secrets_count", header: "Secrets" },
    { key: "bypass_count", header: "Bypass" },
    { key: "severity_score", header: "Severity" },
  ]), []);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="text-2xl font-semibold">Runs</div>
          <div className="text-sm text-slate-400">pipeline_runs (Postgres)</div>
        </div>
        <div className="flex gap-2">
          <input
            className="rounded-xl bg-slate-900 border border-slate-200/10 px-3 py-2 text-sm text-white"
            value={pipeline}
            onChange={(e) => { setPipeline(e.target.value); setPage(0); }}
            placeholder="pipeline id…"
          />
          <Button onClick={load} disabled={loading}>{loading ? "…" : "Refresh"}</Button>
          <Badge tone={err ? "red" : "green"}>{err ? "Error" : "OK"}</Badge>
        </div>
      </div>

      {err && <div className="rounded-2xl border border-rose-200/20 bg-rose-950/30 p-4 text-rose-200">{err}</div>}

      <Card title={`Runs — ${pipeline}`} subtitle={`Total: ${data.total}`}>
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

      <Modal open={!!selected} title="Run details" onClose={() => setSelected(null)}>
        <CodeBlock code={selected} label="pipeline_runs row" />
      </Modal>
    </div>
  );
}
