import React from "react";

export default function Card({ title, subtitle, right, children, className = "" }) {
  return (
    <div className={`rounded-2xl border border-slate-200/10 bg-white/70 dark:bg-slate-900/60 backdrop-blur shadow-sm ${className}`}>
      {(title || subtitle || right) && (
        <div className="flex items-start justify-between gap-3 p-5 border-b border-slate-200/10">
          <div>
            {title && <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</div>}
            {subtitle && <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">{subtitle}</div>}
          </div>
          {right}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}
