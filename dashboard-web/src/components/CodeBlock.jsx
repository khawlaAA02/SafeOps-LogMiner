import React from "react";
import Button from "./Button";

export default function CodeBlock({ code, label="Détails" }) {
  const text = typeof code === "string" ? code : JSON.stringify(code, null, 2);
  return (
    <div className="rounded-2xl border border-slate-200/10 overflow-hidden">
      <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200/10">
        <div className="text-xs text-slate-600 dark:text-slate-300">{label}</div>
        <Button
          variant="soft"
          onClick={() => navigator.clipboard.writeText(text)}
          className="px-3 py-1 text-xs"
        >
          Copier
        </Button>
      </div>
      <pre className="p-3 text-xs overflow-auto bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100">
{text}
      </pre>
    </div>
  );
}
