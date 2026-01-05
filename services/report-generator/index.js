const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");
const Handlebars = require("handlebars");
const archiver = require("archiver");
require("dotenv").config();

const app = express();
app.use(express.json({ limit: "2mb" }));

// ---------------------------
// Crash safety
// ---------------------------
process.on("uncaughtException", (err) => console.error("🔥 uncaughtException:", err));
process.on("unhandledRejection", (reason) => console.error("🔥 unhandledRejection:", reason));

app.use((req, _res, next) => {
  console.log(`--> ${req.method} ${req.url}`);
  next();
});

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------------------------
// CORS
// ---------------------------
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5173";
const EXTRA_ORIGINS = (process.env.CORS_EXTRA_ORIGINS || "")
  .split(",").map((s) => s.trim()).filter(Boolean);
const allowedOrigins = Array.from(new Set([CORS_ORIGIN, ...EXTRA_ORIGINS]));

app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error("CORS blocked: " + origin), false);
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// ---------------------------
// Paths
// ---------------------------
const REPORTS_DIR = process.env.REPORTS_DIR || path.join(__dirname, "reports");
const TPL_PATH = process.env.TEMPLATE_PATH || path.join(__dirname, "templates", "report.hbs");

function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }
ensureDir(REPORTS_DIR);

function safePipelineId(input) {
  const v = String(input || "").trim();
  if (!/^[a-zA-Z0-9._-]{2,80}$/.test(v)) return null;
  return v;
}

function filePathFor(pipelineId, ext) {
  return path.join(REPORTS_DIR, `${pipelineId}.${ext}`);
}

// ---------------------------
// DB
// ---------------------------
const pool = new Pool({
  host: process.env.POSTGRES_HOST || "postgres",
  port: Number(process.env.POSTGRES_PORT || 5432),
  user: process.env.POSTGRES_USER || "safeops",
  password: process.env.POSTGRES_PASSWORD || "safeops",
  database: process.env.POSTGRES_DB || "safeops_security",
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT || 30000),
  connectionTimeoutMillis: Number(process.env.PG_CONN_TIMEOUT || 5000),
});

pool.on("error", (err) => console.error("PG Pool error:", err));




// =========================
// Extra endpoints (plateforme)
// =========================

// GET /dashboard/runs?pipeline=ci-demo&limit=20&offset=0
app.get("/dashboard/runs", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    const limit = Math.min(Number(req.query.limit || 20), 200);
    const offset = Math.max(Number(req.query.offset || 0), 0);

    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const r = await pgPool.query(
      `
      SELECT
        created_at, ts, pipeline_id, run_id, job_id, source, status,
        duration_sec, error_count, secrets_count, urls_count, bypass_count,
        steps_count, severity_score
      FROM pipeline_runs
      WHERE pipeline_id = $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
      `,
      [pipeline, limit, offset]
    );

    const c = await pgPool.query(
      `SELECT COUNT(*)::int AS n FROM pipeline_runs WHERE pipeline_id=$1`,
      [pipeline]
    );

    res.json({ pipeline, limit, offset, total: c.rows[0].n, items: r.rows });
  } catch (e) {
    next(e);
  }
});

// GET /dashboard/vulns?pipeline=ci-demo&limit=50&offset=0
app.get("/dashboard/vulns", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    const limit = Math.min(Number(req.query.limit || 50), 200);
    const offset = Math.max(Number(req.query.offset || 0), 0);

    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const r = await pgPool.query(
      `
      SELECT
        v.id,
        v.run_id::text AS run_id,
        v.rule_id,
        v.title,
        v.severity,
        v.confidence,
        v.evidence,
        v.detected_at
      FROM vulnerabilities v
      WHERE v.run_id::text IN (
        SELECT pr.run_id
        FROM pipeline_runs pr
        WHERE pr.pipeline_id = $1
      )
      ORDER BY v.detected_at DESC
      LIMIT $2 OFFSET $3
      `,
      [pipeline, limit, offset]
    );

    const c = await pgPool.query(
      `
      SELECT COUNT(*)::int AS n
      FROM vulnerabilities v
      WHERE v.run_id::text IN (
        SELECT pr.run_id
        FROM pipeline_runs pr
        WHERE pr.pipeline_id = $1
      )
      `,
      [pipeline]
    );

    res.json({ pipeline, limit, offset, total: c.rows[0].n, items: r.rows });
  } catch (e) {
    next(e);
  }
});

// GET /dashboard/anomalies?pipeline=ci-demo&limit=50&offset=0
app.get("/dashboard/anomalies", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    const limit = Math.min(Number(req.query.limit || 50), 200);
    const offset = Math.max(Number(req.query.offset || 0), 0);

    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const r = await pgPool.query(
      `
      SELECT
        id, ts, pipeline_id, run_id, job_id,
        model_used, anomaly_score, is_anomaly, details
      FROM anomaly_reports
      WHERE pipeline_id = $1
      ORDER BY ts DESC
      LIMIT $2 OFFSET $3
      `,
      [pipeline, limit, offset]
    );

    const c = await pgPool.query(
      `SELECT COUNT(*)::int AS n FROM anomaly_reports WHERE pipeline_id=$1`,
      [pipeline]
    );

    res.json({ pipeline, limit, offset, total: c.rows[0].n, items: r.rows });
  } catch (e) {
    next(e);
  }
});

// GET /dashboard/fixes?pipeline=ci-demo&limit=50&offset=0
app.get("/dashboard/fixes", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    const limit = Math.min(Number(req.query.limit || 50), 200);
    const offset = Math.max(Number(req.query.offset || 0), 0);

    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const r = await pgPool.query(
      `
      SELECT
        id, pipeline_id, run_id::text AS run_id,
        rule_id, title, safe, created_at,
        yaml_patch, patched_yaml_preview, original_yaml
      FROM fix_reports
      WHERE pipeline_id = $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
      `,
      [pipeline, limit, offset]
    );

    const c = await pgPool.query(
      `SELECT COUNT(*)::int AS n FROM fix_reports WHERE pipeline_id=$1`,
      [pipeline]
    );

    res.json({ pipeline, limit, offset, total: c.rows[0].n, items: r.rows });
  } catch (e) {
    next(e);
  }
});

// GET /dashboard/patches?pipeline=ci-demo&limit=50&offset=0
app.get("/dashboard/patches", async (req, res, next) => {
  try {
    const pipeline = String(req.query.pipeline || "").trim();
    const limit = Math.min(Number(req.query.limit || 50), 200);
    const offset = Math.max(Number(req.query.offset || 0), 0);

    if (!pipeline) return res.status(400).json({ error: "pipeline is required" });

    const r = await pgPool.query(
      `
      SELECT
        id, pipeline_id, run_id::text AS run_id,
        rule_id, status, created_at
      FROM patch_applies
      WHERE pipeline_id = $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
      `,
      [pipeline, limit, offset]
    );

    const c = await pgPool.query(
      `SELECT COUNT(*)::int AS n FROM patch_applies WHERE pipeline_id=$1`,
      [pipeline]
    );

    res.json({ pipeline, limit, offset, total: c.rows[0].n, items: r.rows });
  } catch (e) {
    next(e);
  }
});


// ---------------------------
// Handlebars helpers (IMPORTANT)
// ---------------------------
Handlebars.registerHelper("gte", (a, b) => Number(a) >= Number(b));
Handlebars.registerHelper("lte", (a, b) => Number(a) <= Number(b));
Handlebars.registerHelper("eq", (a, b) => String(a) === String(b));
Handlebars.registerHelper("json", (obj) => JSON.stringify(obj, null, 2));
Handlebars.registerHelper("upper", (v) => String(v ?? "").toUpperCase());
Handlebars.registerHelper("lower", (v) => String(v ?? "").toLowerCase());
Handlebars.registerHelper("default", (v, def) => (v === null || v === undefined || v === "") ? def : v);
Handlebars.registerHelper("upper", (s) => String(s ?? "").toUpperCase());


// ---------------------------
// Utils
// ---------------------------
function severityWeight(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return 10;
  if (s === "high") return 7;
  if (s === "medium") return 4;
  if (s === "low") return 1;
  return 1;
}

function computeScore(vulns, anomalyCount) {
  let totalRisk = 0;
  for (const v of vulns) totalRisk += severityWeight(v.severity);

  const vulnsCount = vulns.length;
  const anomalyPenalty = Math.min(30, Number(anomalyCount || 0) * 2);
  const vulnPenalty = Math.min(80, totalRisk * 2);

  const raw = 100 - vulnPenalty - anomalyPenalty;
  const score = Math.max(0, Math.min(100, Math.round(raw)));

  return {
    score,
    stats: { vulnsCount, totalRisk, anomalyCount: Number(anomalyCount || 0) },
    penalty: { vulnPenalty, anomalyPenalty },
  };
}

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

function toSarif(pipelineId, vulns) {
  const results = vulns.map((v) => {
    const sev = (v.severity || "low").toLowerCase();
    const level = (sev === "critical" || sev === "high") ? "error" : (sev === "medium") ? "warning" : "note";
    return {
      ruleId: v.rule_id || "SAFEOPS_RULE",
      level,
      message: { text: `${v.title || v.rule_id || "Finding"}` },
      properties: {
        pipeline: pipelineId,
        run_id: v.run_id,
        evidence: v.evidence || null,
        confidence: v.confidence ?? null,
      },
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "SafeOps-LogMiner", informationUri: "https://example.local/safeops" } },
      results: dedupeSarifByRule(results),
    }],
  };
}

// ✅ PDF robuste: écoute aussi doc.on("error")
function renderPdf({ pipelineId, scoreObj, vulns, fixes, anomalyCount, patches }, outPath) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    const stream = fs.createWriteStream(outPath);

    doc.on("error", reject);
    stream.on("error", reject);
    stream.on("finish", resolve);

    doc.pipe(stream);

    doc.fontSize(18).text("SafeOps-LogMiner — DevSecOps Security Report");
    doc.moveDown(0.5);
    doc.fontSize(12).text(`Pipeline: ${pipelineId}`);
    doc.text(`Generated: ${new Date().toISOString()}`);
    doc.moveDown();

    doc.fontSize(16).text(`Security Score: ${scoreObj.score}/100`);
    doc.fontSize(10).text(
      `Vulns: ${scoreObj.stats.vulnsCount} | Risk: ${scoreObj.stats.totalRisk} | Anomalies: ${anomalyCount}`
    );
    doc.moveDown();

    doc.fontSize(14).text("Vulnerabilities", { underline: true });
    doc.moveDown(0.3);
    if (!vulns.length) {
      doc.fontSize(11).text("Aucune vulnérabilité trouvée pour ce pipeline.");
    } else {
      for (const v of vulns.slice(0, 15)) {
        doc.fontSize(11).text(`- [${String(v.severity || "medium").toUpperCase()}] ${v.title || v.rule_id}`);
        doc.fontSize(9).text(`  rule_id=${v.rule_id} | run_id=${v.run_id} | ${v.detected_at}`);
      }
    }

    doc.addPage();
    doc.fontSize(14).text("Fix Suggestions", { underline: true });
    doc.moveDown(0.3);
    if (!fixes.length) {
      doc.fontSize(11).text("Aucun fix trouvé.");
    } else {
      for (const f of fixes.slice(0, 10)) {
        doc.fontSize(11).text(`- ${f.rule_id || "FIX"} | run_id=${f.run_id} | safe=${f.safe} | ${f.created_at}`);
      }
    }

    doc.moveDown();
    doc.fontSize(14).text("Patches", { underline: true });
    doc.moveDown(0.3);
    if (!patches.length) doc.fontSize(11).text("Aucun patch appliqué.");
    else {
      for (const p of patches.slice(0, 10)) {
        doc.fontSize(11).text(`- ${p.rule_id || "PATCH"} | run_id=${p.run_id} | status=${p.status} | ${p.created_at}`);
      }
    }

    doc.moveDown();
    doc.fontSize(14).text("Behavioral Anomalies", { underline: true });
    doc.moveDown(0.3);
    doc.fontSize(11).text(`Nombre d'anomalies (is_anomaly=true): ${anomalyCount}`);

    doc.end();
  });
}

// ---------------------------
// Template cache
// ---------------------------
let compiledTemplate = null;
function getTemplate() {
  if (compiledTemplate) return compiledTemplate;
  const tplText = fs.readFileSync(TPL_PATH, "utf8");
  compiledTemplate = Handlebars.compile(tplText);
  return compiledTemplate;
}

// ---------------------------
// Queries adaptées à TES tables
// ---------------------------

const UUID_REGEX_SQL = "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";

async function fetchPipelines() {
  const q = `
    SELECT pipeline_id AS pipeline, COUNT(*)::int AS runs
    FROM pipeline_runs
    GROUP BY pipeline_id
    ORDER BY runs DESC
    LIMIT 200;
  `;
  return (await pool.query(q)).rows;
}

async function fetchVulnerabilitiesForPipeline(pipelineId, limit = 200) {
  // ✅ On ne cast jamais text -> uuid
  // ✅ On relie via run_id UUID seulement
  const q = `
    SELECT
      v.run_id::text AS run_id,
      v.rule_id,
      v.title,
      v.severity,
      v.confidence,
      v.evidence,
      v.detected_at
    FROM vulnerabilities v
    WHERE v.run_id::text IN (
      SELECT pr.run_id
      FROM pipeline_runs pr
      WHERE pr.pipeline_id = $1
        AND pr.run_id ~* '${UUID_REGEX_SQL}'
    )
    ORDER BY v.detected_at DESC
    LIMIT $2;
  `;
  return (await pool.query(q, [pipelineId, limit])).rows;
}

async function fetchFixesForPipeline(pipelineId, limit = 50) {
  // Ton fix_reports contient au moins: id, pipeline_id, run_id, safe, created_at
  // Certaines versions contiennent aussi rule_id/title => on met COALESCE si présent
  const q = `
    SELECT
      id,
      pipeline_id,
      run_id,
      COALESCE(rule_id, 'FIX') AS rule_id,
      COALESCE(title, '') AS title,
      safe,
      created_at
    FROM fix_reports
    WHERE pipeline_id = $1
    ORDER BY created_at DESC
    LIMIT $2;
  `;
  return (await pool.query(q, [pipelineId, limit])).rows;
}

async function fetchPatchesForPipeline(pipelineId, limit = 50) {
  const q = `
    SELECT id, run_id::text AS run_id, rule_id, status, created_at
    FROM patch_applies
    WHERE pipeline_id = $1
    ORDER BY created_at DESC
    LIMIT $2;
  `;
  return (await pool.query(q, [pipelineId, limit])).rows;
}

async function fetchAnomalyCount(pipelineId) {
  const q = `
    SELECT COUNT(*)::int AS c
    FROM anomaly_reports
    WHERE pipeline_id = $1 AND is_anomaly = true;
  `;
  return Number((await pool.query(q, [pipelineId])).rows[0]?.c || 0);
}

// ---------------------------
// Génération report
// ---------------------------
async function generateReport(pipelineId, mode = "all") {
  const template = getTemplate();

  const vulns = await fetchVulnerabilitiesForPipeline(pipelineId, 200);
  const fixes = await fetchFixesForPipeline(pipelineId, 50);
  const patches = await fetchPatchesForPipeline(pipelineId, 50);
  const anomalyCount = await fetchAnomalyCount(pipelineId);

  const scoreObj = computeScore(vulns, anomalyCount);

  const html = template({
    pipeline: pipelineId,
    date: new Date().toISOString(),
    score: scoreObj.score,
    stats: scoreObj.stats,
    penalties: scoreObj.penalty,
    vulns,
    fixes,
    patches,
    anomalies: anomalyCount,
    mode,
  });

  const pdfPath = filePathFor(pipelineId, "pdf");
  const htmlPath = filePathFor(pipelineId, "html");
  const sarifPath = filePathFor(pipelineId, "sarif");

  fs.writeFileSync(htmlPath, html, "utf8");
  await renderPdf({ pipelineId, scoreObj, vulns, fixes, patches, anomalyCount }, pdfPath);

  const sarif = toSarif(pipelineId, vulns);
  fs.writeFileSync(sarifPath, JSON.stringify(sarif, null, 2), "utf8");

  return { scoreObj, pdfPath, htmlPath, sarifPath };
}

// ---------------------------
// Routes
// ---------------------------
app.get("/ping", (_req, res) => res.json({ pong: true }));

app.get("/health", asyncHandler(async (_req, res) => {
  await pool.query("SELECT 1");
  res.json({ status: "ok", db: "ok" });
}));

app.get("/pipelines", asyncHandler(async (_req, res) => {
  const rows = await fetchPipelines();
  res.json(rows);
}));

app.get("/report/:pipelineId", asyncHandler(async (req, res) => {
  const pipelineId = safePipelineId(req.params.pipelineId);
  if (!pipelineId) return res.status(400).json({ error: "Invalid pipelineId" });

  const mode = String(req.query.mode || "all").toLowerCase();
  const { scoreObj } = await generateReport(pipelineId, mode);

  res.json({
    message: "Report generated",
    pipelineId,
    mode,
    score: scoreObj.score,
    stats: scoreObj.stats,
    files: {
      pdf: `/report/${pipelineId}/pdf`,
      html: `/report/${pipelineId}/html`,
      sarif: `/report/${pipelineId}/sarif`,
      zip: `/report/${pipelineId}/zip?mode=${encodeURIComponent(mode)}`,
    },
  });
}));

app.get("/report/:pipelineId/zip", asyncHandler(async (req, res) => {
  const pipelineId = safePipelineId(req.params.pipelineId);
  if (!pipelineId) return res.status(400).json({ error: "Invalid pipelineId" });

  const mode = String(req.query.mode || "all").toLowerCase();
  const { pdfPath, htmlPath, sarifPath } = await generateReport(pipelineId, mode);

  res.status(200);
  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Disposition", `attachment; filename="${pipelineId}-${mode}.zip"`);

  const archive = archiver("zip", { zlib: { level: 9 } });
  res.on("close", () => { try { archive.abort(); } catch (_) {} });

  archive.on("warning", (err) => console.warn("ZIP warning:", err));
  archive.on("error", (err) => {
    console.error("ZIP error:", err);
    if (!res.headersSent) res.status(500);
    res.end();
  });

  archive.pipe(res);
  archive.file(htmlPath, { name: `${pipelineId}.html` });
  archive.file(pdfPath, { name: `${pipelineId}.pdf` });
  archive.file(sarifPath, { name: `${pipelineId}.sarif` });
  archive.finalize();
}));

app.get("/report/:pipelineId/pdf", (req, res) => {
  const pipelineId = safePipelineId(req.params.pipelineId);
  if (!pipelineId) return res.status(400).json({ error: "Invalid pipelineId" });

  const p = filePathFor(pipelineId, "pdf");
  if (!fs.existsSync(p)) return res.status(404).json({ error: "PDF not found. Generate /report/:pipelineId first." });
  res.sendFile(p);
});

app.get("/report/:pipelineId/html", (req, res) => {
  const pipelineId = safePipelineId(req.params.pipelineId);
  if (!pipelineId) return res.status(400).json({ error: "Invalid pipelineId" });

  const p = filePathFor(pipelineId, "html");
  if (!fs.existsSync(p)) return res.status(404).json({ error: "HTML not found. Generate /report/:pipelineId first." });
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(fs.readFileSync(p, "utf8"));
});

app.get("/report/:pipelineId/sarif", (req, res) => {
  const pipelineId = safePipelineId(req.params.pipelineId);
  if (!pipelineId) return res.status(400).json({ error: "Invalid pipelineId" });

  const p = filePathFor(pipelineId, "sarif");
  if (!fs.existsSync(p)) return res.status(404).json({ error: "SARIF not found. Generate /report/:pipelineId first." });
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.send(fs.readFileSync(p, "utf8"));
});

// Global error handler
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal error", detail: String(err.message || err) });
});

const port = Number(process.env.PORT || 3006);
app.listen(port, () => console.log(`ReportGenerator running on ${port}`));
