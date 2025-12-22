const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
app.use(express.json({ limit: "1mb" }));

// ---------------------------
// Env
// ---------------------------
const PORT = Number(process.env.PORT || 3010);
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5173";

// Important:
// - REPORT_BASE_DOCKER: pour les liens utilisés entre conteneurs (report-generator)
// - REPORT_BASE_PUBLIC: pour les liens cliquables depuis le navigateur (localhost)
const REPORT_BASE_DOCKER = process.env.REPORT_BASE || "http://report-generator:3006";
const REPORT_BASE_PUBLIC = process.env.REPORT_BASE_PUBLIC || "http://localhost:3006";

// ---------------------------
// CORS
// ---------------------------
app.use(
  cors({
    origin: CORS_ORIGIN,
    credentials: true,
  })
);

// ---------------------------
// DB
// ---------------------------
const pool = new Pool({
  host: process.env.POSTGRES_HOST || "postgres",
  port: Number(process.env.POSTGRES_PORT || 5432),
  user: process.env.POSTGRES_USER || "safeops",
  password: process.env.POSTGRES_PASSWORD || "safeops",
  database: process.env.POSTGRES_DB || "safeops_security",
});

// ---------------------------
// Helpers
// ---------------------------
function parseJsonMaybe(v) {
  if (!v) return null;
  if (typeof v === "object") return v;
  try {
    return JSON.parse(v);
  } catch {
    return null;
  }
}

function normSeverity(s) {
  const x = String(s || "").toLowerCase().trim();
  if (["critical", "high", "medium", "low"].includes(x)) return x;
  return null;
}

// 0..100 conversion simple
function severityWeight(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return 10;
  if (s === "high") return 7;
  if (s === "medium") return 4;
  return 1;
}

// build WHERE safely (no "AND" bug)
function buildWhere(conditions) {
  const cleaned = conditions.filter(Boolean);
  return cleaned.length ? `WHERE ${cleaned.join(" AND ")}` : "";
}

function computeScoreFromAlerts(alerts, anomalyCount) {
  let totalRisk = 0;
  for (const a of alerts) totalRisk += severityWeight(a.severity);

  const vulnPenalty = Math.min(80, totalRisk * 2);
  const anomalyPenalty = Math.min(30, Number(anomalyCount || 0) * 2);

  const raw = 100 - vulnPenalty - anomalyPenalty;
  const value = Math.max(0, Math.min(100, raw));

  return {
    value,
    details: {
      totalFindings: alerts.length,
      totalRisk,
      anomalyCount: Number(anomalyCount || 0),
      vulnPenalty,
      anomalyPenalty,
    },
  };
}

// Extract findings from vuln_reports rows to a flat alerts array
function vulnRowsToAlerts(vulnRows) {
  const alerts = [];
  for (const r of vulnRows) {
    const findings = Array.isArray(r.findings) ? r.findings : parseJsonMaybe(r.findings) || [];
    for (const f of findings) {
      alerts.push({
        pipeline: r.pipeline,
        run_id: r.run_id,
        rule_id: f.rule_id || "SAFEOPS_RULE",
        title: f.title || f.rule_id || "Finding",
        severity: String(f.severity || "low").toLowerCase(),
        recommendation: f.recommendation || "",
        evidence: Array.isArray(f.evidence) ? f.evidence.join(" | ") : (f.evidence || ""),
        created_at: r.created_at,
      });
    }
  }
  // newest first
  alerts.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  return alerts;
}

// ---------------------------
// Routes
// ---------------------------
app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok" });
  } catch (e) {
    res.status(500).json({ status: "degraded", error: String(e.message || e) });
  }
});

/**
 * GET /dashboard
 * Query:
 *  - pipeline=all|p1|...
 *  - severity=all|critical|high|medium|low
 *  - q=search text
 *  - limit=20
 */
app.get("/dashboard", async (req, res) => {
  const pipeline = req.query.pipeline && req.query.pipeline !== "all" ? String(req.query.pipeline) : null;
  const severity = req.query.severity && req.query.severity !== "all" ? normSeverity(req.query.severity) : null;
  const q = String(req.query.q || "").trim();
  const limit = Math.min(Math.max(Number(req.query.limit || 20), 1), 200);

  try {
    // 1) pipelines list (for dropdown)
    const pipelines = (await pool.query(
      `SELECT DISTINCT pipeline_id FROM pipeline_runs ORDER BY pipeline_id`
    )).rows.map(r => r.pipeline_id);

    // 2) pipelineScores (score per pipeline) from latest run in pipeline_runs
    // we compute "score" as (100 - severity_score) if severity_score is 0..100 risk
    // If your severity_score already represents security score, just map directly.
    const ps = (await pool.query(`
      SELECT DISTINCT ON (pipeline_id)
        pipeline_id,
        ts,
        severity_score
      FROM pipeline_runs
      ORDER BY pipeline_id, ts DESC
    `)).rows.map(r => {
      const risk = Number(r.severity_score || 0);
      // assume risk 0..100 => score 100-risk
      const score = Math.max(0, Math.min(100, 100 - risk));
      return { pipeline_id: r.pipeline_id, score, ts: r.ts };
    });

    // 3) timeline for selected pipeline (line chart)
    // if pipeline not selected => last 25 points overall
    const conds = [];
    const params = [];
    let i = 1;

    if (pipeline) {
      conds.push(`pipeline_id = $${i++}`);
      params.push(pipeline);
    }
    const whereRuns = buildWhere(conds);

    const timelineRows = (await pool.query(
      `
      SELECT ts, pipeline_id, run_id, severity_score
      FROM pipeline_runs
      ${whereRuns}
      ORDER BY ts DESC
      LIMIT $${i}
      `,
      [...params, 25]
    )).rows;

    const timeline = timelineRows
      .slice()
      .reverse()
      .map(r => ({
        time: r.ts,
        pipeline_id: r.pipeline_id,
        run_id: r.run_id,
        severity_score: Number(r.severity_score || 0),
      }));

    // 4) vulns: filter from vuln_reports
    // NOTE: vuln_reports uses column "pipeline" (not pipeline_id)
    const vulnConds = [];
    const vulnParams = [];
    let j = 1;

    if (pipeline) {
      vulnConds.push(`pipeline = $${j++}`);
      vulnParams.push(pipeline);
    }

    // q filter: search inside findings jsonb as text + pipeline/run_id/status
    if (q) {
      vulnConds.push(`(pipeline ILIKE $${j} OR run_id ILIKE $${j} OR status ILIKE $${j} OR findings::text ILIKE $${j})`);
      vulnParams.push(`%${q}%`);
      j++;
    }

    const whereVuln = buildWhere(vulnConds);

    const vulnRows = (await pool.query(
      `
      SELECT id, pipeline, run_id, source, status, findings, created_at
      FROM vuln_reports
      ${whereVuln}
      ORDER BY created_at DESC
      LIMIT $${j}
      `,
      [...vulnParams, limit]
    )).rows;

    const alertsAll = vulnRowsToAlerts(vulnRows);

    // severity filter at alert level
    const alerts = severity ? alertsAll.filter(a => a.severity === severity) : alertsAll;

    // 5) anomalies count (anomaly_reports has pipeline_id)
    let anomalyCount = 0;
    if (pipeline) {
      anomalyCount = Number((await pool.query(
        `SELECT COUNT(*)::int AS c FROM anomaly_reports WHERE pipeline_id=$1 AND is_anomaly=true`,
        [pipeline]
      )).rows[0]?.c || 0);
    }

    // 6) fixes (latest for selected pipeline if column exists)
    // fix_reports now has pipeline_id (you created it)
    const fixConds = [];
    const fixParams = [];
    let k = 1;

    if (pipeline) {
      fixConds.push(`pipeline_id = $${k++}`);
      fixParams.push(pipeline);
    }
    const whereFix = buildWhere(fixConds);

    const fixes = (await pool.query(
      `
      SELECT id, rule_id, title, created_at
      FROM fix_reports
      ${whereFix}
      ORDER BY created_at DESC
      LIMIT 20
      `,
      fixParams
    )).rows;

    // 7) global score
    const score = computeScoreFromAlerts(alerts, anomalyCount);

    // 8) report links
    // - For Docker internal usage: REPORT_BASE_DOCKER
    // - For browser: REPORT_BASE_PUBLIC
    const reportLinks = pipeline
      ? {
          generate: `${REPORT_BASE_DOCKER}/report/${pipeline}`,
          pdf: `${REPORT_BASE_DOCKER}/report/${pipeline}/pdf`,
          html: `${REPORT_BASE_DOCKER}/report/${pipeline}/html`,
          sarif: `${REPORT_BASE_DOCKER}/report/${pipeline}/sarif`,

          // Helpful for frontend:
          generate_public: `${REPORT_BASE_PUBLIC}/report/${pipeline}`,
          pdf_public: `${REPORT_BASE_PUBLIC}/report/${pipeline}/pdf`,
          html_public: `${REPORT_BASE_PUBLIC}/report/${pipeline}/html`,
          sarif_public: `${REPORT_BASE_PUBLIC}/report/${pipeline}/sarif`,
        }
      : null;

    res.json({
      meta: { pipeline, severity, q, limit },
      score,
      pipelines,           // ✅ dropdown
      pipelineScores: ps,  // ✅ bar chart
      timeline,            // ✅ line chart
      vulns: vulnRows.map(v => ({
        id: v.id,
        pipeline: v.pipeline,
        run_id: v.run_id,
        source: v.source,
        status: v.status,
        created_at: v.created_at,
        findings: Array.isArray(v.findings) ? v.findings : (parseJsonMaybe(v.findings) || []),
      })),
      fixes,
      anomalies: pipeline ? [{ pipeline_id: pipeline, count: anomalyCount }] : [],
      alerts,
      reportLinks,
    });
  } catch (e) {
    console.error("dashboard error:", e);
    res.status(500).json({ error: "Dashboard API error", detail: String(e.message || e) });
  }
});

// ---------------------------
// Start
// ---------------------------
app.listen(PORT, () => console.log(`Dashboard API running on ${PORT}`));
