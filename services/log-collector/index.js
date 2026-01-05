/**
 * LogCollector - SafeOps-LogMiner (PRO + REAL CI/CD)
 * - GitHub Actions: webhook (workflow_run) + optional fetch logs (providers/github.js)
 * - GitLab CI: fetch job trace via API
 * - Jenkins: fetch consoleText via API
 *
 * Storage:
 * - MongoDB: raw_logs (brut)
 * - Postgres:
 *   - pipeline_runs (run_id TEXT, external_run_id, metrics...; meta jsonb)
 *   - raw_logs (run_id TEXT/UUID selon ton schema; raw jsonb)
 */

const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const helmet = require("helmet");
const cors = require("cors");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { z } = require("zod");
const { Pool } = require("pg");

const { verifyGitHubSignature, buildDocFromGithubWebhook } = require("./providers/github");
const { buildDocFromGitlabFetch } = require("./providers/gitlab");
const { buildDocFromJenkinsFetch } = require("./providers/jenkins");

dotenv.config();
const app = express();

// -------------------------
// Security & Middleware
// -------------------------
app.disable("x-powered-by");
app.use(helmet());

const corsOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((s) => s.trim()).filter(Boolean)
  : null;

app.use(cors({ origin: corsOrigins && corsOrigins.length ? corsOrigins : true }));

// IMPORTANT: raw body only for GitHub webhook (signature)
app.use("/webhook/github", express.raw({ type: "*/*", limit: process.env.JSON_LIMIT || "5mb" }));

// All other routes use JSON
app.use(express.json({ limit: process.env.JSON_LIMIT || "5mb" }));

app.use(morgan("combined"));

// request id
app.use((req, _res, next) => {
  req.requestId = crypto.randomBytes(6).toString("hex");
  next();
});

// Rate limit
const ingestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_PER_MIN || 60),
  standardHeaders: true,
  legacyHeaders: false,
});

// -------------------------
// Postgres pool
// -------------------------
const pgPool = new Pool({
  host: process.env.DB_HOST || "postgres",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "safeops",
  password: process.env.DB_PASSWORD || "safeops",
  database: process.env.DB_NAME || "safeops_security",
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

async function checkPostgres() {
  const r = await pgPool.query("SELECT 1 as ok");
  return r?.rows?.[0]?.ok === 1;
}

// -------------------------
// MongoDB
// -------------------------
async function connectMongo() {
  const uri = process.env.MONGO_URI || process.env.MONGO_URL;
  if (!uri) throw new Error("MONGO_URI missing");
  await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 5000,
    socketTimeoutMS: 15000,
  });
}

const RawLogSchema = new mongoose.Schema(
  {
    source: { type: String, default: "unknown", index: true },
    pipelineId: { type: String, default: null, index: true },
    runId: { type: String, default: null, index: true }, // external
    repo: { type: String, default: null, index: true },
    branch: { type: String, default: null },
    status: { type: String, default: null },
    raw: { type: String, required: true },
    meta: { type: Object, default: {} },
    ingestType: { type: String, default: "upload", index: true },
  },
  { timestamps: true }
);

RawLogSchema.index({ source: 1, pipelineId: 1, runId: 1, createdAt: -1 });
const RawLog = mongoose.model("RawLog", RawLogSchema, "raw_logs");

// -------------------------
// API key security
// -------------------------
function safeEqual(a, b) {
  const aBuf = Buffer.from(String(a || ""));
  const bBuf = Buffer.from(String(b || ""));
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function requireApiKey(req, res, next) {
  const apiKey = req.header("x-api-key");
  const expected = process.env.INGEST_API_KEY;

  if (!expected) return res.status(500).json({ error: "INGEST_API_KEY missing" });
  if (!apiKey || !safeEqual(apiKey, expected)) {
    return res.status(401).json({ error: "Unauthorized", requestId: req.requestId });
  }
  next();
}

// -------------------------
// Validation
// -------------------------
const UploadSchema = z.object({
  source: z.string().optional(),
  provider: z.string().optional(),
  pipelineId: z.string().optional(),
  pipeline_id: z.string().optional(),
  runId: z.string().optional(),
  run_id: z.string().optional(),
  repo: z.string().optional(),
  repository: z.string().optional(),
  branch: z.string().optional(),
  status: z.string().optional(),
  raw: z.any().optional(),
  log: z.any().optional(),
  meta: z.any().optional(),
  ingestType: z.string().optional(),
  step: z.string().optional(),
  level: z.string().optional(),
});

function normalizeUpload(body) {
  const source = body.source || body.provider || "unknown";
  const pipelineId = body.pipelineId || body.pipeline_id || null;
  const runId = body.runId || body.run_id || null;
  const repo = body.repo || body.repository || null;

  let raw = body.raw || body.log;
  if (raw == null) raw = body;

  // ✅ raw doit être string dans Mongo (brut)
  if (typeof raw !== "string") raw = JSON.stringify(raw, null, 2);

  return {
    source,
    pipelineId,
    runId,
    repo,
    branch: body.branch || null,
    status: body.status || null,
    raw,
    meta: body.meta || {},
    ingestType: body.ingestType || "upload",
    step: body.step || "ingest",
    level: body.level || "info",
  };
}

// -------------------------
// Metrics & severity score
// -------------------------
function analyzeLogText(rawText) {
  const t = String(rawText || "");

  const error_count = (t.match(/\b(ERROR|FATAL|EXCEPTION|FAILED|FAILURE)\b/gi) || []).length;
  const secrets_count =
    (t.match(/\b(AWS_SECRET|AWS_ACCESS_KEY|SECRET|TOKEN|API[_-]?KEY|PRIVATE KEY)\b/gi) || []).length;
  const urls_count = (t.match(/https?:\/\/\S+/gi) || []).length;
  const bypass_count =
    (t.match(/\b(bypass|skip\s+checks|--no-verify|slsa|allow-unauth|disable\s+auth)\b/gi) || []).length;
  const steps_count = (t.match(/^\s*(Step|==>|##\[group\]|Run\s)/gmi) || []).length;

  let severity_score = 0;
  severity_score += Math.min(60, secrets_count * 25);
  severity_score += Math.min(35, error_count * 6);
  severity_score += Math.min(30, bypass_count * 15);
  severity_score += Math.min(10, urls_count * 2);

  severity_score = Math.max(0, Math.min(100, Math.round(severity_score)));

  return { error_count, secrets_count, urls_count, bypass_count, steps_count, severity_score };
}

function internalRunUuid() {
  return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
}

// -------------------------
// Postgres inserts
// -------------------------
async function insertPipelineRun({
  pipelineId,
  internalRunId,
  externalRunId,
  source,
  status,
  meta,
  durationSec,
  jobId,
  metrics,
}) {
  const metaJson = JSON.stringify(meta || {});
  await pgPool.query(
    `INSERT INTO pipeline_runs
      (ts, pipeline_id, run_id, job_id, source, status, duration_sec,
       error_count, secrets_count, urls_count, bypass_count, steps_count,
       severity_score, meta, external_run_id)
     VALUES
      (now(), $1, $2, $3, $4, $5, $6,
       $7, $8, $9, $10, $11,
       $12, $13::jsonb, $14)`,
    [
      pipelineId || "unknown-pipeline",
      String(internalRunId),
      jobId || null,
      source || null,
      status || null,
      Number.isFinite(durationSec) ? durationSec : null,

      metrics?.error_count ?? 0,
      metrics?.secrets_count ?? 0,
      metrics?.urls_count ?? 0,
      metrics?.bypass_count ?? 0,
      metrics?.steps_count ?? 0,

      metrics?.severity_score ?? 0,
      metaJson,
      externalRunId || null,
    ]
  );
}

async function insertRawLog({ run_id, step_name, level, message, raw }) {
  const safeMsg = String(message || "").slice(0, Number(process.env.PG_MAX_MESSAGE || 20000));
  const rawJson = JSON.stringify(raw || {});

  await pgPool.query(
    `INSERT INTO raw_logs (run_id, step_name, level, message, raw)
     VALUES ($1, $2, $3, $4, $5::jsonb)`,
    [run_id, step_name || "ingest", level || "info", safeMsg, rawJson]
  );
}

// -------------------------
// Ingestion (single function)
// -------------------------
async function ingest(doc, requestId) {
  const internalId = internalRunUuid();
  const metrics = analyzeLogText(doc.raw);

  const savedMongo = await RawLog.create({
    source: doc.source,
    pipelineId: doc.pipelineId,
    runId: doc.runId,
    repo: doc.repo,
    branch: doc.branch,
    status: doc.status,
    raw: doc.raw,
    meta: doc.meta,
    ingestType: doc.ingestType,
  });

  await insertPipelineRun({
    pipelineId: doc.pipelineId || "demo",
    internalRunId: internalId,
    externalRunId: doc.runId,
    source: doc.source,
    status: doc.status,
    jobId: doc.meta?.job_id || null,
    durationSec: Number(doc.meta?.duration_sec),
    meta: {
      ...doc.meta,
      repo: doc.repo,
      branch: doc.branch,
      requestId,
      mongo_id: String(savedMongo._id),
    },
    metrics,
  });

  await insertRawLog({
    run_id: internalId,
    step_name: doc.step,
    level: doc.level,
    message: doc.raw,
    raw: {
      mongo_id: String(savedMongo._id),
      ingestType: doc.ingestType,
      pipelineId: doc.pipelineId,
      external_run_id: doc.runId,
      metrics,
      ...doc.meta,
    },
  });

  // ✅ IMPORTANT: return internal UUID string
  return internalId;
}

// -------------------------
// Routes
// -------------------------
app.get("/", (_req, res) => res.json({ message: "LogCollector is running", service: "log-collector" }));

app.get("/routes", (_req, res) => {
  res.json({
    routes: [
      "GET /",
      "GET /health",
      "GET /routes",
      "POST /logs/upload",
      "GET /logs",
      "GET /logs/:id",
      "POST /webhook/github",
      "POST /fetch/gitlab",
      "POST /fetch/jenkins",
    ],
  });
});

app.get("/health", async (_req, res) => {
  const mongoOk = mongoose.connection.readyState === 1;
  let pgOk = false;
  try {
    pgOk = await checkPostgres();
  } catch {
    pgOk = false;
  }
  const ok = mongoOk && pgOk;
  res.status(ok ? 200 : 503).json({ status: ok ? "ok" : "degraded", mongo: mongoOk, postgres: pgOk });
});

/**
 * Manual upload ingestion (PATCHED)
 * ✅ NEVER JSON.parse(req.body) when express.json() is used
 */
app.post("/logs/upload", ingestLimiter, requireApiKey, async (req, res, next) => {
  try {
    // ✅ express.json() gives object; if someone sent a raw JSON string, parse safely
    const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {});

    const parsed = UploadSchema.safeParse(body);
    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid payload",
        requestId: req.requestId,
        details: parsed.error.issues.map((i) => ({ path: i.path, message: i.message })),
      });
    }

    const doc = normalizeUpload(parsed.data);
    const internalId = await ingest(doc, req.requestId);

    res.status(201).json({ message: "Ingested", runId: internalId });
  } catch (err) {
    next(err);
  }
});

/**
 * GitHub webhook (REAL)
 */
app.post("/webhook/github", ingestLimiter, async (req, res, next) => {
  try {
    if (!verifyGitHubSignature(req, safeEqual)) {
      return res.status(401).json({ error: "Invalid GitHub signature" });
    }

    const event = req.header("x-github-event");
    const payload = JSON.parse(req.body.toString("utf8") || "{}");
    const docLike = await buildDocFromGithubWebhook({ event, payload });

    if (!docLike) return res.status(200).json({ message: "ignored" });

    const doc = normalizeUpload(docLike);
    const internalId = await ingest(doc, req.requestId);

    res.status(201).json({ message: "GitHub ingested", runId: internalId });
  } catch (err) {
    next(err);
  }
});

/**
 * GitLab fetch (REAL)
 */
app.post("/fetch/gitlab", ingestLimiter, requireApiKey, async (req, res, next) => {
  try {
    const docLike = await buildDocFromGitlabFetch(req.body || {});
    const doc = normalizeUpload(docLike);
    const internalId = await ingest(doc, req.requestId);
    res.status(201).json({ message: "GitLab ingested", runId: internalId });
  } catch (err) {
    next(err);
  }
});

/**
 * Jenkins fetch (REAL)
 */
app.post("/fetch/jenkins", ingestLimiter, requireApiKey, async (req, res, next) => {
  try {
    const docLike = await buildDocFromJenkinsFetch(req.body || {});
    const doc = normalizeUpload(docLike);
    const internalId = await ingest(doc, req.requestId);
    res.status(201).json({ message: "Jenkins ingested", runId: internalId });
  } catch (err) {
    next(err);
  }
});

/**
 * Read Mongo logs
 */
app.get("/logs", requireApiKey, async (req, res, next) => {
  try {
    const { source, pipelineId, runId, repo, ingestType, limit = "50", page = "1" } = req.query;

    const q = {};
    if (source) q.source = source;
    if (pipelineId) q.pipelineId = pipelineId;
    if (runId) q.runId = runId;
    if (repo) q.repo = repo;
    if (ingestType) q.ingestType = ingestType;

    const lim = Math.min(Number(limit) || 50, 200);
    const pg = Math.max(Number(page) || 1, 1);
    const skip = (pg - 1) * lim;

    const [items, total] = await Promise.all([
      RawLog.find(q).sort({ createdAt: -1 }).skip(skip).limit(lim).lean(),
      RawLog.countDocuments(q),
    ]);

    res.json({ page: pg, limit: lim, total, items });
  } catch (err) {
    next(err);
  }
});

app.get("/logs/:id", requireApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: "Invalid id" });

    const doc = await RawLog.findById(id).lean();
    if (!doc) return res.status(404).json({ error: "Not found" });
    res.json(doc);
  } catch (err) {
    next(err);
  }
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: "Not found", path: req.path, requestId: req.requestId });
});

// Global error handler
app.use((err, req, res, _next) => {
  console.error("❌ Error:", err?.message || err);
  res.status(500).json({ error: "Internal server error", requestId: req.requestId });
});

// Process-level safety
process.on("uncaughtException", (err) => console.error("❌ uncaughtException:", err));
process.on("unhandledRejection", (err) => console.error("❌ unhandledRejection:", err));

// Start
const port = Number(process.env.PORT || 3001);
(async () => {
  try {
    await connectMongo();
    console.log("✅ MongoDB connected");
    await checkPostgres();
    console.log("✅ Postgres connected");
    app.listen(port, () => console.log(`🚀 LogCollector running on port ${port}`));
  } catch (e) {
    console.error("❌ Startup error:", e?.message || e);
    process.exit(1);
  }
})();
