-- 001_init.sql

-- -------------------------
-- Vuln reports (MS3)
-- -------------------------
CREATE TABLE IF NOT EXISTS vuln_reports (
  id SERIAL PRIMARY KEY,
  pipeline TEXT NOT NULL,
  run_id TEXT,
  source TEXT,
  status TEXT,
  findings JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vuln_reports_pipeline_created
ON vuln_reports(pipeline, created_at DESC);

-- -------------------------
-- Fix reports (MS4)
-- -------------------------
CREATE TABLE IF NOT EXISTS fix_reports (
  id SERIAL PRIMARY KEY,
  pipeline_id TEXT,             -- ✅ important
  run_id TEXT,
  rule_id TEXT,
  title TEXT,
  yaml_patch TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fix_reports_pipeline_id
ON fix_reports(pipeline_id);

CREATE INDEX IF NOT EXISTS idx_fix_reports_created_at
ON fix_reports(created_at DESC);

-- -------------------------
-- Anomaly reports (MS5) - Timescale
-- IMPORTANT: pas de PK unique sans ts
-- -------------------------
CREATE TABLE IF NOT EXISTS anomaly_reports (
  ts TIMESTAMPTZ NOT NULL,
  pipeline_id TEXT NOT NULL,
  run_id TEXT,
  job_id TEXT,
  model_used TEXT,
  anomaly_score DOUBLE PRECISION,
  is_anomaly BOOLEAN DEFAULT FALSE,
  details JSONB,

  -- ✅ PK composite incluant ts
  PRIMARY KEY (pipeline_id, ts, run_id)
);

CREATE INDEX IF NOT EXISTS idx_anomaly_reports_pipeline_ts
ON anomaly_reports(pipeline_id, ts DESC);
