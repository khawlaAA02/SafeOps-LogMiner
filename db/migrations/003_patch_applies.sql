-- 004_patch_applies.sql
CREATE TABLE IF NOT EXISTS patch_applies (
  id SERIAL PRIMARY KEY,
  pipeline_id TEXT NOT NULL,
  run_id TEXT,
  rule_id TEXT,
  original_yaml TEXT NOT NULL,
  yaml_patch TEXT NOT NULL,
  patched_yaml TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'simulated', -- simulated | applied | failed
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_patch_applies_pipeline ON patch_applies(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_patch_applies_created_at ON patch_applies(created_at DESC);
