const express = require("express");
const mongoose = require("mongoose");
require("dotenv").config();

const app = express();
app.use(express.json({ limit: "2mb" }));

// --- Mongo ---
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("Mongo error:", err));

// --- Simple API key protection (DevSecOps-ish) ---
function requireApiKey(req, res, next) {
  const apiKey = req.header("x-api-key");
  if (!process.env.INGEST_API_KEY) return res.status(500).json({ error: "INGEST_API_KEY missing" });
  if (apiKey !== process.env.INGEST_API_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// Route de test
app.get("/", (req, res) => res.json({ message: "LogCollector is running" }));

// Health check
app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));

// --- Upload logs (webhook / manual) ---
app.post("/logs/upload", requireApiKey, async (req, res) => {
  try {
    const body = req.body || {};

    // Normalisation minimale pour que GET /logs filtre correctement
    const log = {
      source: body.source || body.provider || "unknown",
      pipelineId: body.pipelineId || body.pipeline_id || null,
      runId: body.runId || body.run_id || null,
      repo: body.repo || body.repository || null,
      branch: body.branch || null,
      status: body.status || null,
      raw: body.raw || body.log || JSON.stringify(body, null, 2), // fallback
      meta: body.meta || {},
      ingestType: body.ingestType || "upload",
      createdAt: new Date()
    };

    const result = await mongoose.connection.collection("raw_logs").insertOne(log);
    res.status(201).json({ message: "Log saved", id: result.insertedId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error while saving log" });
  }
});

// --- List logs (for debug + LogParser) ---
app.get("/logs", async (req, res) => {
  try {
    const { source, pipelineId, runId, limit = 50 } = req.query;

    const query = {};
    if (source) query.source = source;
    if (pipelineId) query.pipelineId = pipelineId;
    if (runId) query.runId = runId;

    const logs = await mongoose.connection
      .collection("raw_logs")
      .find(query)
      .sort({ createdAt: -1 })
      .limit(Math.min(Number(limit), 200))
      .toArray();

    res.json(logs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error fetching logs" });
  }
});

// --- Get by id ---
app.get("/logs/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const doc = await mongoose.connection
      .collection("raw_logs")
      .findOne({ _id: new mongoose.Types.ObjectId(id) });

    if (!doc) return res.status(404).json({ error: "Not found" });
    res.json(doc);
  } catch (err) {
    res.status(400).json({ error: "Invalid id" });
  }
});

// --- Pull API (simulation) ---
app.get("/logs/pull/:provider", requireApiKey, async (req, res) => {
  const { provider } = req.params;

  const pulledLog = {
    source: provider,
    pipelineId: "pipeline-pull-001",
    runId: "run-pull-001",
    repo: "demo/repository",
    branch: "main",
    status: "success",
    raw: "CI job started...\nBuild success",
    meta: { simulated: true },
    ingestType: "pull",
    createdAt: new Date()
  };

  await mongoose.connection.collection("raw_logs").insertOne(pulledLog);

  res.json({ message: "Logs pulled successfully", provider });
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`LogCollector running on port ${port}`));
