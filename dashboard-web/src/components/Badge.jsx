import React from "react";

export default function Badge({ tone="gray", children }) {
  const map = {
    gray: "bg-slate-100 text-slate-700 border-slate-200/40 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700",
    green: "bg-emerald-50 text-emerald-700 border-emerald-200/60 dark:bg-emerald-950/40 dark:text-emerald-200 dark:border-emerald-900/60",
    yellow: "bg-amber-50 text-amber-700 border-amber-200/60 dark:bg-amber-950/40 dark:text-amber-200 dark:border-amber-900/60",
    orange: "bg-orange-50 text-orange-700 border-orange-200/60 dark:bg-orange-950/40 dark:text-orange-200 dark:border-orange-900/60",
    red: "bg-rose-50 text-rose-700 border-rose-200/60 dark:bg-rose-950/40 dark:text-rose-200 dark:border-rose-900/60",
    blue: "bg-sky-50 text-sky-700 border-sky-200/60 dark:bg-sky-950/40 dark:text-sky-200 dark:border-sky-900/60",
    purple: "bg-violet-50 text-violet-700 border-violet-200/60 dark:bg-violet-950/40 dark:text-violet-200 dark:border-violet-900/60",
  };
  return (
    <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs ${map[tone] || map.gray}`}>
      {children}
    </span>
  );
}
