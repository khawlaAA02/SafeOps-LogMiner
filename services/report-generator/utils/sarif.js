"use strict";

const { parseFindings } = require("./score");

function dedupeSarifByRule(results) {
  const seen = new Set();
  const out = [];
  for (const r of results) {
    const ruleId = String(r.ruleId || "").trim();
    if (!ruleId) continue;
    if (seen.has(ruleId)) continue;
    seen.add(ruleId);
    out.push(r);
  }
  return out;
}

function toSarif(pipelineId, vulnRows) {
  const results = [];

  for (const r of vulnRows || []) {
    const findings = parseFindings(r);
    for (const f of findings) {
      const sev = (f.severity || "low").toLowerCase();
      const level =
        sev === "critical" || sev === "high"
          ? "error"
          : sev === "medium"
          ? "warning"
          : "note";

      const msg = `${f.title || "Finding"} - ${f.description || ""}`.trim();

      results.push({
        ruleId: f.rule_id || "SAFEOPS_RULE",
        level,
        message: { text: msg },
        properties: {
          pipeline: pipelineId,
          mapping: f.mapping || {},
          recommendation: f.recommendation || "",
          evidence: f.evidence || null,
        },
      });
    }
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SafeOps-LogMiner",
            informationUri: "https://example.local/safeops",
          },
        },
        results: dedupeSarifByRule(results),
      },
    ],
  };
}

module.exports = { toSarif };
