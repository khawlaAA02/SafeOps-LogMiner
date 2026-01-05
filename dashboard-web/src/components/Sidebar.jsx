import React from "react";
import { NavLink } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";

function Item({ to, children }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `flex items-center gap-2 rounded-xl px-3 py-2 text-sm transition ${
          isActive
            ? "bg-white text-slate-900 dark:bg-slate-800 dark:text-slate-100"
            : "text-slate-300 hover:bg-white/10 hover:text-white"
        }`
      }
    >
      {children}
    </NavLink>
  );
}

export default function Sidebar() {
  return (
    <aside className="w-[270px] hidden md:flex flex-col p-4 bg-slate-950 border-r border-slate-200/10">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="h-9 w-9 grid place-items-center rounded-xl bg-white text-slate-900 font-black">S</div>
          <div>
            <div className="text-sm font-semibold text-white">SafeOps</div>
            <div className="text-xs text-slate-400">LogMiner Platform</div>
          </div>
        </div>
        <ThemeToggle />
      </div>

      <div className="mt-6 space-y-2">
        <Item to="/overview">📊 Overview</Item>
        <Item to="/pipelines">🧩 Pipelines</Item>
        <Item to="/runs">🧾 Runs</Item>
        <Item to="/findings">🛡️ Findings</Item>
        <Item to="/reports">📄 Reports</Item>
        <Item to="/settings">⚙️ Settings</Item>
      </div>

      <div className="mt-auto pt-4 text-xs text-slate-400">
        <div className="rounded-2xl border border-slate-200/10 p-3">
          <div className="font-semibold text-slate-200">Tip soutenance</div>
          <div className="mt-1">
            Montre: pipeline <b>ci-demo</b> + generate report + ouvrir PDF.
          </div>
        </div>
      </div>
    </aside>
  );
}
