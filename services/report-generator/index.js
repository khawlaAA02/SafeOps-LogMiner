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
// Logs + crash safety
// ---------------------------
process.on("uncaughtException", (err) => {
  console.error("🔥 uncaughtException:", err);
});
process.on("unhandledRejection", (reason) => {
  console.error("🔥 unhandledRejection:", reason);
});

app.use((req, _res, next) => {
  console.log(`--> ${req.method} ${req.url}`);
  next();
});

// Wrapper Express v4 pour routes async
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ---------------------------
// CORS
// ---------------------------
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5173";
const EXTRA_ORIGINS = (process.env.CORS_EXTRA_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const allowedOrigins = Array.from(new Set([CORS_ORIGIN, ...EXTRA_ORIGINS]));

app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true); // curl/postman
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked: " + origin), false);
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ---------------------------
// Paths / Files
// ---------------------------
const REPORTS_DIR = process.env.REPORTS_DIR || path.join(__dirname, "reports");
const TPL_PATH =
  process.env.TEMPLATE_PATH || path.join(__dirname, "templates", "report.hbs");

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}
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
// PostgreSQL pool
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

pool.on("error", (err) => {
  console.error("PG Pool error:", err);
});

// ---------------------------
// Utils
// ---------------------------
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

function computeScore(vulnRows, anomalyCount) {
  let totalRisk = 0;
  let totalFindings = 0;

  for (const r of vulnRows) {
    const findings = parseFindings(r);
    totalFindings += findings.length;
    for (const f of findings) totalRisk += severityWeight(f.severity);
  }

  const anomalyPenalty = Math.min(30, Number(anomalyCount || 0) * 2);
  const vulnPenalty = Math.min(80, totalRisk * 2);

  const raw = 100 - vulnPenalty - anomalyPenalty;
  const score = Math.max(0, Math.min(100, Math.round(raw)));

  return {
    score,
    stats: { totalFindings, totalRisk, anomalyCount: Number(anomalyCount || 0) },
    penalty: { vulnPenalty, anomalyPenalty },
  };
}

// ✅ Dédup SARIF par ruleId
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

  for (const r of vulnRows) {
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

function renderPdf({ pipelineId, scoreObj, vulns, fixes, anomalyCount }, outPath) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    const stream = fs.createWriteStream(outPath);
    doc.pipe(stream);

    doc.fontSize(18).text("SafeOps-LogMiner — DevSecOps Security Report");
    doc.moveDown(0.5);
    doc.fontSize(12).text(`Pipeline: ${pipelineId}`);
    doc.text(`Generated: ${new Date().toISOString()}`);
    doc.moveDown();

    doc.fontSize(16).text(`Security Score: ${scoreObj.score}/100`);
    doc.fontSize(10).text(
      `Findings: ${scoreObj.stats.totalFindings} | TotalRisk: ${scoreObj.stats.totalRisk} | Anomalies: ${anomalyCount}`
    );
    doc.moveDown();

    doc.fontSize(14).text("Vulnerabilities (VulnDetector)", { underline: true });
    doc.moveDown(0.3);

    if (!vulns.length) {
      doc.fontSize(11).text("No vulnerability reports found for this pipeline.");
    } else {
      const maxReports = Math.min(10, vulns.length);
      for (let i = 0; i < maxReports; i++) {
        const vr = vulns[i];
        doc.fontSize(11).text(
          `Report #${vr.id} — status=${vr.status || "unknown"} — ${vr.created_at}`
        );

        const findings = parseFindings(vr);
        if (!findings.length) {
          doc.text("  - No findings in this report.");
        } else {
          for (const f of findings) {
            doc.text(
              `  - [${(f.severity || "low").toUpperCase()}] ${f.title || f.rule_id || "Finding"}`
            );
            if (f.description) doc.text(`      desc: ${f.description}`);
            if (f.recommendation) doc.text(`      fix: ${f.recommendation}`);
          }
        }
        doc.moveDown(0.5);
      }
    }

    doc.addPage();
    doc.fontSize(14).text("Fix Suggestions (FixSuggester)", { underline: true });
    doc.moveDown(0.3);

    if (!fixes.length) {
      doc.fontSize(11).text("No fixes found (yet).");
    } else {
      const max = Math.min(10, fixes.length);
      doc.fontSize(11).text(`Showing latest ${max} fixes.`);
      doc.moveDown(0.3);
      for (let i = 0; i < max; i++) {
        const fr = fixes[i];
        doc.text(`- ${fr.rule_id || "FIX"} — ${fr.title || ""} — ${fr.created_at}`);
      }
    }

    doc.moveDown();
    doc.fontSize(14).text("Behavioral Anomalies (AnomalyDetector)", { underline: true });
    doc.moveDown(0.3);
    doc.fontSize(11).text(`Anomalies detected for pipeline "${pipelineId}": ${anomalyCount}`);

    doc.end();
    stream.on("finish", resolve);
    stream.on("error", reject);
  });
}

// ---------------------------
// Template cache (évite relire le fichier à chaque call)
// ---------------------------
let compiledTemplate = null;
function getTemplate() {
  if (compiledTemplate) return compiledTemplate;
  const tplText = fs.readFileSync(TPL_PATH, "utf8");
  compiledTemplate = Handlebars.compile(tplText);
  return compiledTemplate;
}

// ---------------------------
// Génération report (factorisée)
// ---------------------------
async function generateReport(pipelineId, mode = "all") {
  const limit = mode === "latest" ? 1 : 50;

  const vulnRows = (
    await pool.query(
      `SELECT id, pipeline, run_id, source, status, findings, created_at
       FROM vuln_reports
       WHERE pipeline=$1
       ORDER BY created_at DESC
       LIMIT $2`,
      [pipelineId, limit]
    )
  ).rows;

  const fixRows = (
    await pool.query(
      `SELECT id, rule_id, title, yaml_patch, created_at
       FROM fix_reports
       ORDER BY created_at DESC
       LIMIT 50`
    )
  ).rows;

  const anomalyCount = Number(
    (
      await pool.query(
        `SELECT COUNT(*)::int AS c
         FROM anomaly_reports
         WHERE pipeline_id=$1 AND is_anomaly=true`,
        [pipelineId]
      )
    ).rows[0]?.c || 0
  );

  const scoreObj = computeScore(vulnRows, anomalyCount);

  const template = getTemplate();
  const html = template({
    pipeline: pipelineId,
    date: new Date().toISOString(),
    score: scoreObj.score,
    stats: scoreObj.stats,
    penalties: scoreObj.penalty,
    vulns: vulnRows.map((v) => ({ ...v, findings: parseFindings(v) })),
    fixes: fixRows,
    anomalies: anomalyCount,
    mode,
  });

  const pdfPath = filePathFor(pipelineId, "pdf");
  const htmlPath = filePathFor(pipelineId, "html");
  const sarifPath = filePathFor(pipelineId, "sarif");

  fs.writeFileSync(htmlPath, html, "utf8");
  await renderPdf({ pipelineId, scoreObj, vulns: vulnRows, fixes: fixRows, anomalyCount }, pdfPath);

  const sarif = toSarif(pipelineId, vulnRows);
  fs.writeFileSync(sarifPath, JSON.stringify(sarif, null, 2), "utf8");

  return { scoreObj, pdfPath, htmlPath, sarifPath, anomalyCount };
}

// ---------------------------
// Routes
// ---------------------------
app.get("/health", asyncHandler(async (_req, res) => {
  await pool.query("SELECT 1");
  res.json({ status: "ok" });
}));

app.get("/pipelines", asyncHandler(async (_req, res) => {
  const rows = (
    await pool.query(
      `SELECT pipeline, COUNT(*)::int as reports
       FROM vuln_reports
       GROUP BY pipeline
       ORDER BY reports DESC
       LIMIT 200`
    )
  ).rows;
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

// ✅ ZIP robuste (évite "Empty reply")
app.get("/report/:pipelineId/zip", asyncHandler(async (req, res) => {
  const pipelineId = safePipelineId(req.params.pipelineId);
  if (!pipelineId) return res.status(400).json({ error: "Invalid pipelineId" });

  const mode = String(req.query.mode || "all").toLowerCase();
  const { pdfPath, htmlPath, sarifPath } = await generateReport(pipelineId, mode);

  res.status(200);
  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Disposition", `attachment; filename="${pipelineId}-${mode}.zip"`);

  const archive = archiver("zip", { zlib: { level: 9 } });

  // Si le client coupe la connexion => stop archiver
  res.on("close", () => {
    try { archive.abort(); } catch (_) {}
  });

  archive.on("warning", (err) => {
    // warning non bloquant
    console.warn("ZIP warning:", err);
  });

  archive.on("error", (err) => {
    console.error("ZIP error:", err);
    if (!res.headersSent) res.status(500);
    res.end();
  });

  archive.pipe(res);

  archive.file(htmlPath, { name: `${pipelineId}.html` });
  archive.file(pdfPath, { name: `${pipelineId}.pdf` });
  archive.file(sarifPath, { name: `${pipelineId}.sarif` });

  archive.finalize(); // pas de await
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

// Handler global (doit être tout en bas)
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal error", detail: String(err.message || err) });
});

// Start
const port = Number(process.env.PORT || 3006);
app.listen(port, () => console.log(`ReportGenerator running on ${port}`));
