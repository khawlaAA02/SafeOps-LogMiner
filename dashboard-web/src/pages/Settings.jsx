import React from "react";
import Card from "../components/Card";
import Badge from "../components/Badge";
import { getApiBase, getReportBase } from "../api/client";

export default function Settings() {
  return (
    <div className="space-y-4">
      <div className="text-2xl font-semibold text-white">Settings</div>

      <Card title="Environment" subtitle="Variables VITE_* (build-time)">
        <div className="flex flex-wrap gap-2">
          <Badge tone="blue">VITE_API_BASE: {getApiBase()}</Badge>
          <Badge tone="purple">VITE_REPORT_BASE: {getReportBase()}</Badge>
        </div>

        <div className="mt-4 text-sm text-slate-300">
          Si tu changes ces valeurs, tu dois rebuild le container dashboard-web (Vite injecte au build).
        </div>
      </Card>
    </div>
  );
}
