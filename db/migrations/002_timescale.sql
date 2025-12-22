-- 002_timescale.sql
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- create hypertable (idempotent)
SELECT create_hypertable(
  'anomaly_reports',
  'ts',
  if_not_exists => TRUE
);
