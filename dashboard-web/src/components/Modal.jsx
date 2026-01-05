import React, { useEffect } from "react";
import Button from "./Button";

export default function Modal({ open, title, children, onClose, right }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose?.(); };
    if (open) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="absolute inset-0 p-4 grid place-items-center">
        <div className="w-full max-w-4xl rounded-2xl border border-slate-200/10 bg-white dark:bg-slate-900 shadow-xl overflow-hidden">
          <div className="flex items-center justify-between gap-2 p-4 border-b border-slate-200/10">
            <div className="font-semibold text-slate-900 dark:text-slate-100">{title}</div>
            <div className="flex items-center gap-2">
              {right}
              <Button variant="outline" onClick={onClose}>Fermer</Button>
            </div>
          </div>
          <div className="p-4 max-h-[70vh] overflow-auto">{children}</div>
        </div>
      </div>
    </div>
  );
}
