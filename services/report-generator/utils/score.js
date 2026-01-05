"use strict";

function parseFindings(row) {
  if (!row) return [];
  const f = row.findings;
  if (!f) return [];
  if (Array.isArray(f)) return f;
  try {
    if (typeof f === "string") return JSON.parse(f);
  } catch (_) {}
  return [];
}

function severityWeight(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return 10;
  if (s === "high") return 7;
  if (s === "medium") return 4;
  if (s === "low") return 1;
  return 1;
}

function computeScore(vulnRows, anomaliesCount) {
  let totalRisk = 0;
  let totalFindings = 0;

  for (const r of vulnRows || []) {
    const findings = parseFindings(r);
    totalFindings += findings.length;
    for (const f of findings) totalRisk += severityWeight(f.severity);
  }

  const anomalyPenalty = Math.min(30, Number(anomaliesCount || 0) * 2);
  const vulnPenalty = Math.min(80, totalRisk * 2);

  const raw = 100 - vulnPenalty - anomalyPenalty;
  const score = Math.max(0, Math.min(100, Math.round(raw)));

  return {
    score,
    stats: {
      totalFindings,
      totalRisk,
      anomaliesCount: Number(anomaliesCount || 0),
    },
    penalty: { vulnPenalty, anomalyPenalty },
  };
}

module.exports = { computeScore, parseFindings };
