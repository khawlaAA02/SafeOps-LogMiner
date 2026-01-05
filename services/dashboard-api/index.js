const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

const corsOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((s) => s.trim()).filter(Boolean)
  : null;

app.use(
  cors({
    origin: corsOrigins && corsOrigins.length ? corsOrigins : true,
    credentials: true,
  })
);

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: Number(process.env.RATE_LIMIT_PER_MIN || 120),
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// -------------------------
// PostgreSQL
// -------------------------
const pgPool = new Pool({
  host: process.env.DB_HOST || "postgres",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "safeops",
  password: process.env.DB_PASSWORD || "safeops",
  database: process.env.DB_NAME || "safeops_security",
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

async function checkPostgres() {
  const r = await pgPool.query("SELECT 1 as ok");
  return r?.rows?.[0]?.ok === 1;
}

function computeScore(row) {
  const secrets = Number(row.secrets_count || 0);
  const bypass = Number(row.bypass_count || 0);
  const errors = Number(row.error_count || 0);
  const urls = Number(row.urls_count || 0);
  const sev = Number(row.severity_score || 0);

  const riskPoints =
    secrets * 12 + bypass * 8 + errors * 2 + urls * 1 + Math.floor(sev / 5);

  const score = Math.max(0, Math.min(100, 100 - riskPoints));

  return {
    score,
    riskPoints,
    breakdown: { secrets, bypass, errors, urls, severity_score: sev },
  };
}

function bucketFromScore(score) {
  if (score <= 40) return "critical";
  if (score <= 60) return "high";
  if (score <= 80) return "medium";
  return "low";
}

// -------------------------
// Routes
// -------------------------
app.get("/", (_req, res) => res.json({ name: "dashboard-api", ok: true }));
app.get("/ping", (_req, res) => res.json({ ok: true }));

app.get("/health", async (_req, res) => {
  let pgOk = false;
  try {
    pgOk = await checkPostgres();
  } catch {
    pgOk = false;
  }
  res.status(pgOk ? 200 : 503).json({ status: pgOk ? "ok" : "degraded", postgres: pgOk });
});

/**
 * ✅ /dashboard/reports?pipeline=xxx
 */
app.get("/dashboard/reports", (req, res) => {
  const pipeline = String(req.query.pipeline || "").trim();
  if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

  const basePublic = process.env.REPORT_BASE_PUBLIC || "http://127.0.0.1:3006";

  res.json({
    pipeline,
    generate: `${basePublic}/report/${encodeURIComponent(pipeline)}?mode=all`,
    html: `${basePublic}/report/${encodeURIComponent(pipeline)}/html`,
    pdf: `${basePublic}/report/${encodeURIComponent(pipeline)}/pdf`,
    sarif: `${basePublic}/report/${encodeURIComponent(pipeline)}/sarif`,
    zip: `${basePublic}/report/${encodeURIComponent(pipeline)}/zip?mode=all`,
  });
});

/**
 * ✅ /pipelines : pipeline_id + runs
 */
app.get("/pipelines", async (_req, res, next) => {
  try {
    const r = await pgPool.query(
      `SELECT pipeline_id, COUNT(*)::int AS runs
       FROM pipeline_runs
       GROUP BY pipeline_id
       ORDER BY runs DESC`
    );
    res.json({ items: r.rows });
  } catch (e) {
    next(e);
  }
});

/**
 * ✅ /dashboard/summary (tri ts)
 */
app.get("/dashboard/summary", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    const limit = Math.min(Number(req.query.limit || 30), 200);

    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const r = await pgPool.query(
      `SELECT
         ts, pipeline_id, source, status, duration_sec,
         error_count, secrets_count, urls_count, bypass_count,
         steps_count, severity_score
       FROM pipeline_runs
       WHERE pipeline_id = $1
       ORDER BY ts DESC
       LIMIT $2`,
      [pipeline, limit]
    );

    const rows = r.rows;
    if (!rows.length) {
      return res.json({
        pipeline,
        score: null,
        findings: 0,
        anomalies: 0,
        risk: 0,
        buckets: { critical: 0, high: 0, medium: 0, low: 0 },
        lastRun: null,
      });
    }

    let sumScore = 0;
    let count = 0;
    let findings = 0;
    let anomalies = 0; // démo: bypass_count
    let risk = 0;

    const buckets = { critical: 0, high: 0, medium: 0, low: 0 };

    for (const row of rows) {
      const { score, riskPoints } = computeScore(row);
      sumScore += score;
      count += 1;

      const f =
        Number(row.error_count || 0) +
        Number(row.secrets_count || 0) +
        Number(row.urls_count || 0) +
        Number(row.bypass_count || 0);

      findings += f;
      anomalies += Number(row.bypass_count || 0);
      risk += riskPoints;

      buckets[bucketFromScore(score)] += 1;
    }

    const avgScore = Math.round(sumScore / count);
    const lastRun = rows[0];

    res.json({
      pipeline,
      score: avgScore,
      findings,
      anomalies,
      risk,
      buckets,
      lastRun: {
        ts: lastRun.ts,
        status: lastRun.status,
        source: lastRun.source,
        duration_sec: lastRun.duration_sec,
        severity_score: lastRun.severity_score,
      },
    });
  } catch (e) {
    next(e);
  }
});

/**
 * ✅ /dashboard/scores (CTE tri ts)
 * limit = nb de runs retenus par pipeline (max 50)
 */
app.get("/dashboard/scores", async (req, res, next) => {
  try {
    const perPipeline = Math.min(Number(req.query.limit || 30), 50);

    const r = await pgPool.query(
      `
      WITH ranked AS (
        SELECT
          pipeline_id,
          error_count, secrets_count, urls_count, bypass_count, severity_score,
          ts,
          ROW_NUMBER() OVER (PARTITION BY pipeline_id ORDER BY ts DESC) AS rn
        FROM pipeline_runs
      ),
      lastn AS (
        SELECT * FROM ranked WHERE rn <= $1
      )
      SELECT
        pipeline_id,
        COUNT(*)::int AS runs,
        AVG(COALESCE(error_count,0)) AS avg_errors,
        AVG(COALESCE(secrets_count,0)) AS avg_secrets,
        AVG(COALESCE(bypass_count,0)) AS avg_bypass,
        AVG(COALESCE(urls_count,0)) AS avg_urls,
        AVG(COALESCE(severity_score,0)) AS avg_severity
      FROM lastn
      GROUP BY pipeline_id
      ORDER BY pipeline_id ASC
      `,
      [perPipeline]
    );

    const items = r.rows.map((x) => {
      const rowForScore = {
        error_count: Number(x.avg_errors),
        secrets_count: Number(x.avg_secrets),
        bypass_count: Number(x.avg_bypass),
        urls_count: Number(x.avg_urls),
        severity_score: Number(x.avg_severity),
      };
      const { score } = computeScore(rowForScore);
      return { pipeline_id: x.pipeline_id, score, runs: Number(x.runs) };
    });

    res.json({ per_pipeline: perPipeline, items });
  } catch (e) {
    next(e);
  }
});

/**
 * ✅ /dashboard/trend (tri ts)
 */
app.get("/dashboard/trend", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    const limit = Math.min(Number(req.query.limit || 20), 200);

    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const r = await pgPool.query(
      `SELECT
         ts,
         error_count, secrets_count, urls_count, bypass_count, severity_score
       FROM pipeline_runs
       WHERE pipeline_id = $1
       ORDER BY ts DESC
       LIMIT $2`,
      [pipeline, limit]
    );

    const points = r.rows
      .reverse()
      .map((row) => ({ t: row.ts, score: computeScore(row).score }));

    res.json({ pipeline, points });
  } catch (e) {
    next(e);
  }
});

// -------------------------
// Error handler
// -------------------------
app.use((err, _req, res, _next) => {
  console.error("❌ dashboard-api error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// -------------------------
// Start
// -------------------------
const port = Number(process.env.PORT || 3010);
app.listen(port, () => console.log(`🚀 dashboard-api running on port ${port}`));
// -------------------------
// Helpers pagination
// -------------------------
function clampInt(v, def, min, max) {
  const n = Number(v);
  if (Number.isNaN(n)) return def;
  return Math.max(min, Math.min(max, n));
}

// =========================
// Runs
// =========================
app.get("/dashboard/runs", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const limit = clampInt(req.query.limit, 50, 1, 200);
    const offset = clampInt(req.query.offset, 0, 0, 100000);
    const status = String(req.query.status || "").trim(); // optional

    const where = ["pipeline_id = $1"];
    const params = [pipeline];
    let idx = 2;

    if (status) {
      where.push(`status = $${idx++}`);
      params.push(status);
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const totalQ = `SELECT COUNT(*)::int AS c FROM pipeline_runs ${whereSql}`;
    const listQ = `
      SELECT
        run_id::text AS run_id,
        pipeline_id,
        source,
        status,
        duration_sec,
        error_count, secrets_count, urls_count, bypass_count,
        steps_count, severity_score,
        created_at, ts
      FROM pipeline_runs
      ${whereSql}
      ORDER BY created_at DESC
      LIMIT $${idx++} OFFSET $${idx++}
    `;

    const total = Number((await pgPool.query(totalQ, params)).rows[0]?.c || 0);
    const items = (await pgPool.query(listQ, [...params, limit, offset])).rows;

    res.json({ pipeline, total, limit, offset, items });
  } catch (e) {
    next(e);
  }
});

// =========================
// Vulnerabilities
// =========================
app.get("/dashboard/vulns", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const limit = clampInt(req.query.limit, 50, 1, 200);
    const offset = clampInt(req.query.offset, 0, 0, 100000);
    const severity = String(req.query.severity || "").trim().toLowerCase(); // optional

    const where = [`pr.pipeline_id = $1`];
    const params = [pipeline];
    let idx = 2;

    if (severity) {
      where.push(`LOWER(COALESCE(v.severity,'low')) = $${idx++}`);
      params.push(severity);
    }

    const whereSql = `WHERE ${where.join(" AND ")}`;

    const totalQ = `
      SELECT COUNT(*)::int AS c
      FROM vulnerabilities v
      JOIN pipeline_runs pr ON pr.run_id::text = v.run_id::text
      ${whereSql}
    `;

    const listQ = `
      SELECT
        v.run_id::text AS run_id,
        v.rule_id,
        v.title,
        v.severity,
        v.confidence,
        v.evidence,
        v.detected_at
      FROM vulnerabilities v
      JOIN pipeline_runs pr ON pr.run_id::text = v.run_id::text
      ${whereSql}
      ORDER BY v.detected_at DESC
      LIMIT $${idx++} OFFSET $${idx++}
    `;

    const total = Number((await pgPool.query(totalQ, params)).rows[0]?.c || 0);
    const items = (await pgPool.query(listQ, [...params, limit, offset])).rows;

    res.json({ pipeline, total, limit, offset, items });
  } catch (e) {
    next(e);
  }
});

// =========================
// Anomalies
// =========================
app.get("/dashboard/anomalies", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const limit = clampInt(req.query.limit, 50, 1, 200);
    const offset = clampInt(req.query.offset, 0, 0, 100000);

    const totalQ = `
      SELECT COUNT(*)::int AS c
      FROM anomaly_reports
      WHERE pipeline_id = $1
    `;
    const listQ = `
      SELECT
        id,
        ts,
        pipeline_id,
        run_id,
        job_id,
        model_used,
        anomaly_score,
        is_anomaly,
        details
      FROM anomaly_reports
      WHERE pipeline_id = $1
      ORDER BY ts DESC
      LIMIT $2 OFFSET $3
    `;

    const total = Number((await pgPool.query(totalQ, [pipeline])).rows[0]?.c || 0);
    const items = (await pgPool.query(listQ, [pipeline, limit, offset])).rows;

    res.json({ pipeline, total, limit, offset, items });
  } catch (e) {
    next(e);
  }
});

// =========================
// Fixes
// =========================
app.get("/dashboard/fixes", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const limit = clampInt(req.query.limit, 50, 1, 200);
    const offset = clampInt(req.query.offset, 0, 0, 100000);

    const totalQ = `SELECT COUNT(*)::int AS c FROM fix_reports WHERE pipeline_id=$1`;
    const listQ = `
      SELECT
        id,
        pipeline_id,
        run_id::text AS run_id,
        rule_id,
        title,
        safe,
        created_at,
        yaml_patch,
        patched_yaml_preview,
        original_yaml
      FROM fix_reports
      WHERE pipeline_id=$1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
    `;

    const total = Number((await pgPool.query(totalQ, [pipeline])).rows[0]?.c || 0);
    const items = (await pgPool.query(listQ, [pipeline, limit, offset])).rows;

    res.json({ pipeline, total, limit, offset, items });
  } catch (e) {
    next(e);
  }
});

// =========================
// Patches
// =========================
app.get("/dashboard/patches", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const limit = clampInt(req.query.limit, 50, 1, 200);
    const offset = clampInt(req.query.offset, 0, 0, 100000);

    const totalQ = `SELECT COUNT(*)::int AS c FROM patch_applies WHERE pipeline_id=$1`;
    const listQ = `
      SELECT
        id,
        pipeline_id,
        run_id::text AS run_id,
        rule_id,
        status,
        created_at
      FROM patch_applies
      WHERE pipeline_id=$1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
    `;

    const total = Number((await pgPool.query(totalQ, [pipeline])).rows[0]?.c || 0);
    const items = (await pgPool.query(listQ, [pipeline, limit, offset])).rows;

    res.json({ pipeline, total, limit, offset, items });
  } catch (e) {
    next(e);
  }
});
