import os
import time
import json
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from uuid import UUID

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query, Path
from dotenv import load_dotenv

load_dotenv()

# =========================
# CONFIG
# =========================
APP_VERSION = "1.2.1"
PORT = int(os.getenv("PORT", "3002"))

PG_HOST = os.getenv("POSTGRES_HOST", os.getenv("PG_HOST", "postgres"))
PG_PORT = int(os.getenv("POSTGRES_PORT", os.getenv("PG_PORT", "5432")))
PG_DB = os.getenv("POSTGRES_DB", os.getenv("PG_DB", "safeops_security"))
PG_USER = os.getenv("POSTGRES_USER", os.getenv("PG_USER", "safeops"))
PG_PASS = os.getenv("POSTGRES_PASSWORD", os.getenv("PG_PASS", "safeops"))

DEFAULT_LIMIT = 500

app = FastAPI(title="SafeOps Log Parser", version=APP_VERSION)

# =========================
# REGEX RULES
# =========================
RE_ERROR = re.compile(r"\b(error|failed|exception|fatal)\b", re.IGNORECASE)
RE_SECRET = re.compile(r"\b(token|secret|api[_-]?key|password)\b", re.IGNORECASE)
RE_URL = re.compile(r"https?://\S+", re.IGNORECASE)
RE_BYPASS = re.compile(r"\b(no-verify|bypass|skip)\b", re.IGNORECASE)


def now_utc():
    return datetime.now(timezone.utc)


def sha256_text(s):
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def db_conn():
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASS,
        connect_timeout=3,
    )


def wait_pg(max_tries=30):
    for _ in range(max_tries):
        try:
            with db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            return
        except:
            time.sleep(1)
    raise RuntimeError("Postgres not ready")


# =========================
# SCHEMA
# =========================
def ensure_schema():
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

            cur.execute("""
            CREATE TABLE IF NOT EXISTS parsed_events (
                id BIGSERIAL PRIMARY KEY,
                run_id UUID NOT NULL,
                ts TIMESTAMPTZ NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                value_hash TEXT NOT NULL,
                payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                line_no INTEGER
            );
            """)

            cur.execute("CREATE INDEX IF NOT EXISTS idx_parsed_events_run ON parsed_events(run_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_parsed_events_line ON parsed_events(run_id, line_no);")

            # Dedup index (NO constraint)
            cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_parsed_events_dedup
            ON parsed_events (run_id, event_type, value_hash, ts);
            """)

        conn.commit()


# =========================
# PARSER
# =========================
def classify_line(line):
    if RE_SECRET.search(line):
        return "secret", "critical"
    if RE_BYPASS.search(line):
        return "bypass", "high"
    if RE_ERROR.search(line):
        return "error", "high"
    if RE_URL.search(line):
        return "url", "low"
    return "info", "low"


def parse_message_to_events(run_id, message, base_ts):
    events = []
    lines = (message or "").splitlines()

    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue

        event_type, severity = classify_line(line)
        value_hash = sha256_text(f"{event_type}|{line}")

        events.append({
            "run_id": str(run_id),
            "ts": base_ts,
            "event_type": event_type,
            "severity": severity,
            "value_hash": value_hash,
            "payload": {
                "line": line,
                "line_no": i,
                "event_type": event_type,
                "severity": severity,
            },
            "line_no": i,
        })

    return events


# =========================
# RAW LOG FETCH
# =========================
def fetch_raw_logs(run_id, limit):
    with db_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ts, message
                FROM raw_logs
                WHERE run_id = %s::uuid
                ORDER BY ts ASC
                LIMIT %s
            """, (str(run_id), limit))
            return cur.fetchall()


# =========================
# INSERT EVENTS (FIXED)
# =========================
def insert_parsed_events(events):
    if not events:
        return 0

    with db_conn() as conn:
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO parsed_events
                  (run_id, ts, event_type, severity, value_hash, payload, line_no)
                VALUES %s
                ON CONFLICT DO NOTHING
                """,
                [
                    (
                        e["run_id"],
                        e["ts"],
                        e["event_type"],
                        e["severity"],
                        e["value_hash"],
                        json.dumps(e["payload"]),
                        e["line_no"],
                    )
                    for e in events
                ],
                page_size=1000,
            )
        conn.commit()

        with conn.cursor() as cur2:
            cur2.execute("SELECT COUNT(*) FROM parsed_events WHERE run_id=%s::uuid", (events[0]["run_id"],))
            return cur2.fetchone()[0]


# =========================
# API
# =========================
@app.on_event("startup")
def startup():
    wait_pg()
    ensure_schema()


@app.get("/health")
def health():
    return {"status": "ok", "service": "log-parser", "version": APP_VERSION}


@app.post("/parse/postgres/run/{run_id}")
def parse_run(run_id: UUID, limit: int = Query(DEFAULT_LIMIT, le=5000)):
    try:
        rows = fetch_raw_logs(run_id, limit)
        if not rows:
            return {"runId": str(run_id), "raw_logs": 0, "parsed": 0, "inserted": 0}

        all_events = []
        for r in rows:
            events = parse_message_to_events(run_id, r["message"], r["ts"])
            all_events.extend(events)

        inserted = insert_parsed_events(all_events)

        return {
            "runId": str(run_id),
            "raw_logs": len(rows),
            "parsed_events_generated": len(all_events),
            "inserted_total_for_run": inserted,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
