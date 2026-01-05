import React from "react";
import Button from "./Button";

export default function DataTable({
  columns,
  rows,
  loading,
  emptyText="Aucune donnée.",
  page,
  pageSize,
  total,
  onPrev,
  onNext,
  onRowClick,
}) {
  const canPrev = page > 0;
  const canNext = (page + 1) * pageSize < total;

  return (
    <div className="rounded-2xl border border-slate-200/10 overflow-hidden">
      <div className="overflow-auto">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 dark:bg-slate-800/50">
            <tr>
              {columns.map((c) => (
                <th key={c.key} className="text-left px-4 py-3 text-xs font-semibold text-slate-600 dark:text-slate-300">
                  {c.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={columns.length} className="px-4 py-6 text-slate-500">Chargement…</td></tr>
            ) : rows.length === 0 ? (
              <tr><td colSpan={columns.length} className="px-4 py-6 text-slate-500">{emptyText}</td></tr>
            ) : (
              rows.map((r, idx) => (
                <tr
                  key={r.id ?? r.run_id ?? idx}
                  className={`border-t border-slate-200/10 hover:bg-slate-50 dark:hover:bg-slate-800/40 ${onRowClick ? "cursor-pointer" : ""}`}
                  onClick={() => onRowClick?.(r)}
                >
                  {columns.map((c) => (
                    <td key={c.key} className="px-4 py-3 align-top text-slate-900 dark:text-slate-100">
                      {c.render ? c.render(r) : String(r[c.key] ?? "")}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between p-3 bg-white dark:bg-slate-900 border-t border-slate-200/10">
        <div className="text-xs text-slate-500">
          Total: {total} • Page {page + 1}
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={onPrev} disabled={!canPrev}>Précédent</Button>
          <Button variant="outline" onClick={onNext} disabled={!canNext}>Suivant</Button>
        </div>
      </div>
    </div>
  );
}
