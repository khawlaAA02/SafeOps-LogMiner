/**
 * LogCollector - SafeOps-LogMiner
 * Rôle: collecter des logs CI/CD (webhook/push ou pull) et les stocker en MongoDB.
 *
 * Améliorations:
 * - Sécurité: helmet, CORS, rate limiting, API key propre + timing-safe compare
 * - Qualité API: validation Zod, erreurs centralisées, réponses cohérentes
 * - Mongo: timeouts + options, schéma Mongoose + index, pagination
 * - Observabilité: logs HTTP (morgan), request id simple
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

dotenv.config();

const app = express();

// -------------------------
// Middlewares (base)
// -------------------------
app.disable("x-powered-by"); // petite sécurité
app.use(helmet());
app.use(cors({ origin: true })); // si tu veux limiter: origin: ["http://localhost:3000"]
app.use(express.json({ limit: process.env.JSON_LIMIT || "2mb" }));
app.use(morgan("combined"));

// Ajout d'un request id simple (utile pour debug)
app.use((req, _res, next) => {
  req.requestId = crypto.randomBytes(6).toString("hex");
  next();
});

// Rate limit (protège /logs/upload d'abus)
const ingestLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: Number(process.env.RATE_LIMIT_PER_MIN || 60), // 60 req/min par IP
  standardHeaders: true,
  legacyHeaders: false,
});

// -------------------------
// MongoDB connection
// -------------------------
async function connectMongo() {
  if (!process.env.MONGO_URI) {
    console.error("❌ MONGO_URI missing");
    process.exit(1);
  }

  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000,
      socketTimeoutMS: 15000,
    });
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ Mongo error:", err.message || err);
    process.exit(1);
  }
}

// -------------------------
// Mongoose schema + indexes
// -------------------------
const RawLogSchema = new mongoose.Schema(
  {
    source: { type: String, default: "unknown", index: true },
    pipelineId: { type: String, default: null, index: true },
    runId: { type: String, default: null, index: true },
    repo: { type: String, default: null, index: true },
    branch: { type: String, default: null },
    status: { type: String, default: null },
    raw: { type: String, required: true }, // le contenu brut
    meta: { type: Object, default: {} },
    ingestType: { type: String, default: "upload", index: true },
  },
  { timestamps: true } // createdAt, updatedAt auto
);

// index composé utile pour les recherches fréquentes
RawLogSchema.index({ source: 1, pipelineId: 1, runId: 1, createdAt: -1 });

const RawLog = mongoose.model("RawLog", RawLogSchema, "raw_logs");

// -------------------------
// API Key middleware (timing-safe)
// -------------------------
function safeEqual(a, b) {
  // Evite certains timing attacks, et gère les tailles différentes
  const aBuf = Buffer.from(String(a || ""));
  const bBuf = Buffer.from(String(b || ""));
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function requireApiKey(req, res, next) {
  const apiKey = req.header("x-api-key");
  const expected = process.env.INGEST_API_KEY;

  if (!expected) {
    return res.status(500).json({ error: "INGEST_API_KEY missing" });
  }
  if (!apiKey || !safeEqual(apiKey, expected)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// -------------------------
// Validation schemas (Zod)
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
});

function normalizeUpload(body) {
  const source = body.source || body.provider || "unknown";
  const pipelineId = body.pipelineId || body.pipeline_id || null;
  const runId = body.runId || body.run_id || null;
  const repo = body.repo || body.repository || null;

  // raw peut être string ou objet -> on sécurise le type
  let raw = body.raw || body.log;
  if (raw == null) raw = body;
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
  };
}

// -------------------------
// Routes
// -------------------------

app.get("/", (_req, res) => res.json({ message: "LogCollector is running" }));

app.get("/health", async (_req, res) => {
  // Vérifie Mongo (optionnel mais utile)
  const mongoOk = mongoose.connection.readyState === 1;
  res.status(mongoOk ? 200 : 503).json({ status: mongoOk ? "ok" : "degraded", mongo: mongoOk });
});

/**
 * POST /logs/upload
 * Stocke un log brut (push/webhook)
 */
app.post("/logs/upload", ingestLimiter, requireApiKey, async (req, res, next) => {
  try {
    const parsed = UploadSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid payload",
        details: parsed.error.issues.map((i) => ({ path: i.path, message: i.message })),
      });
    }

    const doc = normalizeUpload(parsed.data);
    const saved = await RawLog.create(doc);

    return res.status(201).json({
      message: "Log saved",
      id: saved._id,
      requestId: req.requestId,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /logs
 * Liste avec filtres + pagination
 * Query:
 * - source, pipelineId, runId, repo, ingestType
 * - limit (max 200), page (>=1)
 */
app.get("/logs", async (req, res, next) => {
  try {
    const {
      source,
      pipelineId,
      runId,
      repo,
      ingestType,
      limit = "50",
      page = "1",
    } = req.query;

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

    res.json({
      page: pg,
      limit: lim,
      total,
      items,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /logs/:id
 */
app.get("/logs/:id", async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: "Invalid id" });
    }

    const doc = await RawLog.findById(id).lean();
    if (!doc) return res.status(404).json({ error: "Not found" });

    res.json(doc);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /logs/pull/:provider
 * Simulation pull
 */
app.get("/logs/pull/:provider", ingestLimiter, requireApiKey, async (req, res, next) => {
  try {
    const { provider } = req.params;

    const pulled = await RawLog.create({
      source: provider,
      pipelineId: "pipeline-pull-001",
      runId: "run-pull-001",
      repo: "demo/repository",
      branch: "main",
      status: "success",
      raw: "CI job started...\nBuild success",
      meta: { simulated: true },
      ingestType: "pull",
    });

    res.json({ message: "Logs pulled successfully", provider, id: pulled._id });
  } catch (err) {
    next(err);
  }
});

// -------------------------
// Global error handler (centralisé)
// -------------------------
app.use((err, req, res, _next) => {
  console.error("❌ Error:", err);
  res.status(500).json({
    error: "Internal server error",
    requestId: req.requestId,
  });
});

// -------------------------
// Start server
// -------------------------
const port = Number(process.env.PORT || 3001);

connectMongo().then(() => {
  app.listen(port, () => console.log(`🚀 LogCollector running on port ${port}`));
});
