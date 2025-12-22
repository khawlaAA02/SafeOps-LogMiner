const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");
const Handlebars = require("handlebars");
require("dotenv").config();

const app = express();

// ✅ CORS pour le front Vite (5173)
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5173";
app.use(
  cors({
    origin: [CORS_ORIGIN],
    methods: ["GET", "POST", "OPTIONS"],
  })
);

// si tu veux aussi pouvoir télécharger directement dans le navigateur
app.use(express.json());

const REPORTS_DIR = process.env.REPORTS_DIR || path.join(__dirname, "reports");
const TPL_PATH = process.env.TEMPLATE_PATH || path.join(__dirname, "templates", "report.hbs");

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}
ensureDir(REPORTS_DIR);

const pool = new Pool({
  host: process.env.POSTGRES_HOST || "postgres",
  port: Number(process.env.POSTGRES_PORT || 5432),
  user: process.env.POSTGRES_USER || "safeops",
  password: process.env.POSTGRES_PASSWORD || "safeops",
  database: process.env.POSTGRES_DB || "safeops_security",
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

function toSarif(pipelineId, vulnRows) {
  const results = [];

  for (const r of vulnRows) {
    const findings = parseFindings(r);
    for (const f of findings) {
      const sev = (f.severity || "low").toLowerCase();
      const level = sev === "critical" || sev === "high" ? "error" : sev === "medium" ? "warning" : "note";

      results.push({
        ruleId: f.rule_id || "SAFEOPS_RULE",
        level,
        message: { text: `${f.title || "Finding"} - ${f.description || ""}`.trim() },
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
          driver: { name: "SafeOps-LogMiner", informationUri: "https://example.local/safeops" },
        },
        results,
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
      for (const vr of vulns) {
        doc.fontSize(11).text(`Report #${vr.id} — status=${vr.status || "unknown"} — ${vr.created_at}`);
        const findings = parseFindings(vr);
        if (!findings.length) {
          doc.text("  - No findings in this report.");
        } else {
          for (const f of findings) {
            doc.text(`  - [${(f.severity || "low").toUpperCase()}] ${f.title || f.rule_id || "Finding"}`);
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
      doc.fontSize(11).text(`Showing latest ${max} fixes (global history).`);
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
// Routes
// ---------------------------
app.get("/health", async (_, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok" });
  } catch (e) {
    res.status(500).json({ status: "degraded", error: String(e.message || e) });
  }
});

// Génère tout (HTML + PDF + SARIF)
app.get("/report/:pipelineId", async (req, res) => {
  const { pipelineId } = req.params;

  try {
    const vulnRows = (await pool.query(
      "SELECT id, pipeline, run_id, source, status, findings, created_at FROM vuln_reports WHERE pipeline=$1 ORDER BY created_at DESC LIMIT 50",
      [pipelineId]
    )).rows;

    const fixRows = (await pool.query(
      "SELECT id, rule_id, title, yaml_patch, created_at FROM fix_reports ORDER BY created_at DESC LIMIT 50"
    )).rows;

    const anomalyCount = Number((await pool.query(
      "SELECT COUNT(*)::int AS c FROM anomaly_reports WHERE pipeline_id=$1 AND is_anomaly=true",
      [pipelineId]
    )).rows[0]?.c || 0);

    const scoreObj = computeScore(vulnRows, anomalyCount);

    const tplText = fs.readFileSync(TPL_PATH, "utf8");
    const template = Handlebars.compile(tplText);

    const html = template({
      pipeline: pipelineId,
      date: new Date().toISOString(),
      score: scoreObj.score,
      stats: scoreObj.stats,
      penalties: scoreObj.penalty,
      vulns: vulnRows.map(v => ({ ...v, findings: parseFindings(v) })),
      fixes: fixRows,
      anomalies: anomalyCount,
    });

    const pdfPath = path.join(REPORTS_DIR, `${pipelineId}.pdf`);
    const htmlPath = path.join(REPORTS_DIR, `${pipelineId}.html`);
    const sarifPath = path.join(REPORTS_DIR, `${pipelineId}.sarif`);

    fs.writeFileSync(htmlPath, html, "utf8");
    await renderPdf({ pipelineId, scoreObj, vulns: vulnRows, fixes: fixRows, anomalyCount }, pdfPath);

    const sarif = toSarif(pipelineId, vulnRows);
    fs.writeFileSync(sarifPath, JSON.stringify(sarif, null, 2), "utf8");

    res.json({
      message: "Report generated",
      pipelineId,
      score: scoreObj.score,
      stats: scoreObj.stats,
      files: {
        pdf: `/report/${pipelineId}/pdf`,
        html: `/report/${pipelineId}/html`,
        sarif: `/report/${pipelineId}/sarif`,
      },
    });
  } catch (e) {
    console.error("Report generation failed:", e);
    res.status(500).json({ error: "Report generation failed", detail: String(e.message || e) });
  }
});

// Download endpoints
app.get("/report/:pipelineId/pdf", (req, res) => {
  const p = path.join(REPORTS_DIR, `${req.params.pipelineId}.pdf`);
  if (!fs.existsSync(p)) return res.status(404).json({ error: "PDF not found. Generate /report/:pipelineId first." });
  res.sendFile(p);
});

app.get("/report/:pipelineId/html", (req, res) => {
  const p = path.join(REPORTS_DIR, `${req.params.pipelineId}.html`);
  if (!fs.existsSync(p)) return res.status(404).json({ error: "HTML not found. Generate /report/:pipelineId first." });
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(fs.readFileSync(p, "utf8"));
});

app.get("/report/:pipelineId/sarif", (req, res) => {
  const p = path.join(REPORTS_DIR, `${req.params.pipelineId}.sarif`);
  if (!fs.existsSync(p)) return res.status(404).json({ error: "SARIF not found. Generate /report/:pipelineId first." });
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.send(fs.readFileSync(p, "utf8"));
});

const port = Number(process.env.PORT || 3006);
app.listen(port, () => console.log(`ReportGenerator running on ${port}`));
