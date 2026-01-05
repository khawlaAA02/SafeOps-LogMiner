from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime
import os
import time
import yaml
import json
from typing import Optional, List, Dict, Any

import psycopg2
import psycopg2.extras

# ======================================================
# 1) ENV
# ======================================================
load_dotenv()

PG_HOST = os.getenv("PG_HOST", os.getenv("POSTGRES_HOST", "postgres"))
PG_PORT = int(os.getenv("PG_PORT", os.getenv("POSTGRES_PORT", "5432")))
PG_DB = os.getenv("PG_DB", os.getenv("POSTGRES_DB", "safeops_security"))
PG_USER = os.getenv("PG_USER", os.getenv("POSTGRES_USER", "safeops"))
PG_PASS = os.getenv("PG_PASSWORD") or os.getenv("POSTGRES_PASSWORD", "safeops")


RULES_FILE = os.getenv("RULES_FILE", "rules.yaml")

if not os.path.exists(RULES_FILE):
    raise RuntimeError("rules.yaml is missing (RULES_FILE)")

with open(RULES_FILE, "r", encoding="utf-8") as f:
    RULES_DOC = yaml.safe_load(f) or {}
RULES = RULES_DOC.get("rules", [])

app = FastAPI(title="VulnDetector", version="2.1.0")

_conn = None


# ======================================================
# 2) DB CONNECTION (retry)
# ======================================================
def get_conn():
    global _conn
    if _conn and _conn.closed == 0:
        return _conn

    last_err = None
    for _ in range(30):
        try:
            _conn = psycopg2.connect(
                host=PG_HOST,
                port=PG_PORT,
                dbname=PG_DB,
                user=PG_USER,
                password=PG_PASS,
            )
            _conn.autocommit = False
            return _conn
        except Exception as e:
            last_err = e
            time.sleep(1)

    raise RuntimeError(f"PostgreSQL not ready: {last_err}")


# ======================================================
# 3) RULES TABLE + SYNC
# ======================================================
def init_rules_table():
    """
    Stocker les règles YAML en DB (optionnel mais pro).
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_rules (
        id TEXT PRIMARY KEY,
        title TEXT,
        description TEXT,
        severity TEXT,
        owasp TEXT,
        slsa TEXT,
        match_event_type TEXT,
        match_contains TEXT,
        recommendation TEXT
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_security_rules_sev ON security_rules(severity)")
    conn.commit()


def sync_rules_to_db():
    """
    Charge rules.yaml -> security_rules (UPSERT)
    """
    conn = get_conn()
    cur = conn.cursor()

    for rule in RULES:
        mapping = rule.get("mapping", {}) or {}
        match = rule.get("match", {}) or {}

        cur.execute("""
        INSERT INTO security_rules (
          id, title, description, severity, owasp, slsa,
          match_event_type, match_contains, recommendation
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (id) DO UPDATE SET
          title=EXCLUDED.title,
          description=EXCLUDED.description,
          severity=EXCLUDED.severity,
          owasp=EXCLUDED.owasp,
          slsa=EXCLUDED.slsa,
          match_event_type=EXCLUDED.match_event_type,
          match_contains=EXCLUDED.match_contains,
          recommendation=EXCLUDED.recommendation
        """, (
            rule.get("id"),
            rule.get("title"),
            rule.get("description"),
            rule.get("severity", "medium"),
            mapping.get("owasp"),
            mapping.get("slsa"),
            match.get("event_type"),
            match.get("contains"),
            rule.get("recommendation"),
        ))

    conn.commit()


@app.on_event("startup")
def on_startup():
    init_rules_table()
    sync_rules_to_db()


# ======================================================
# 4) API Schema
# ======================================================
class ScanRequest(BaseModel):
    runId: str
    source: Optional[str] = None
    repo: Optional[str] = None
    branch: Optional[str] = None


# ======================================================
# 5) CORE - Load rules/events
# ======================================================
def load_rules_from_db() -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
      SELECT id, title, description, severity, owasp, slsa,
             match_event_type, match_contains, recommendation
      FROM security_rules
      ORDER BY id
    """)
    return cur.fetchall()


def fetch_parsed_events(run_id: str) -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
      SELECT id, ts, event_type, severity, payload
      FROM parsed_events
      WHERE run_id = %s
      ORDER BY id ASC
    """, (run_id,))
    return cur.fetchall()


def event_to_text(ev: Dict[str, Any]) -> str:
    payload = ev.get("payload") or {}
    parts = [
        str(ev.get("event_type") or ""),
        str(ev.get("severity") or ""),
        str(payload.get("line") or ""),
        str(payload.get("value") or ""),
        str(payload.get("evidence_line") or ""),
    ]
    return " ".join(parts)


def rule_match(rule: Dict[str, Any], ev: Dict[str, Any]) -> bool:
    # Match event_type
    if rule.get("match_event_type"):
        if (ev.get("event_type") or "") != rule["match_event_type"]:
            return False

    # Match contains (optional)
    contains = rule.get("match_contains")
    if contains:
        txt = event_to_text(ev).lower()
        if contains.lower() not in txt:
            return False

    return True


# ======================================================
# 6) Insert vulnerability (anti-dup real + inserted boolean)
# ======================================================
def insert_vulnerability(run_id: str, rule: Dict[str, Any], ev: Dict[str, Any]) -> bool:
    """
    Insère une vulnérabilité si elle n'existe pas déjà
    (index unique: run_id + rule_id + parsed_event_id)
    Retourne True si inserted, False si conflit.
    """
    conn = get_conn()
    cur = conn.cursor()

    payload = ev.get("payload") or {}

    evidence = {
        "rule": {
            "id": rule.get("id"),
            "owasp": rule.get("owasp"),
            "slsa": rule.get("slsa"),
        },
        "event": {
            "parsed_event_id": ev.get("id"),
            "event_type": ev.get("event_type"),
            "event_severity": ev.get("severity"),
            "ts": str(ev.get("ts")),
            "line_no": payload.get("line_no"),
            "line": payload.get("line"),
            "value": payload.get("value"),
        },
        "recommendation": rule.get("recommendation"),
        "description": rule.get("description"),
    }

    base_conf = 0.85
    if ev.get("event_type") == "secret":
        base_conf = 0.95
    elif ev.get("event_type") == "bypass":
        base_conf = 0.90

    cur.execute("""
      INSERT INTO vulnerabilities (run_id, rule_id, title, severity, confidence, evidence, detected_at)
      VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s)
      ON CONFLICT DO NOTHING
      RETURNING id
    """, (
        run_id,
        rule.get("id"),
        rule.get("title"),
        rule.get("severity", "medium"),
        base_conf,
        json.dumps(evidence, ensure_ascii=False),
        datetime.utcnow()
    ))

    row = cur.fetchone()
    conn.commit()
    return row is not None


# ======================================================
# 7) ROUTES
# ======================================================
@app.get("/health")
def health():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "degraded", "error": str(e)}


@app.get("/")
def root():
    return {"message": "VulnDetector is running"}


@app.post("/scan")
def scan(req: ScanRequest):
    """
    POST /scan
    - lit rules (depuis security_rules)
    - lit parsed_events (Postgres)
    - match rules -> insère dans vulnerabilities
    - anti-duplication réelle + compteur correct
    """
    try:
        run_id = req.runId

        rules = load_rules_from_db()
        events = fetch_parsed_events(run_id)

        if not events:
            return {"runId": run_id, "message": "No parsed_events found", "inserted": 0}

        inserted = 0
        findings = []

        for ev in events:
            for rule in rules:
                if rule_match(rule, ev):
                    did_insert = insert_vulnerability(run_id, rule, ev)
                    if did_insert:
                        inserted += 1
                    findings.append({
                        "rule_id": rule.get("id"),
                        "title": rule.get("title"),
                        "severity": rule.get("severity"),
                        "mapping": {"owasp": rule.get("owasp"), "slsa": rule.get("slsa")},
                        "parsed_event_id": ev.get("id"),
                        "event_type": ev.get("event_type"),
                        "inserted": did_insert
                    })

        return {
            "runId": run_id,
            "parsed_events": len(events),
            "rules": len(rules),
            "inserted": inserted,
            "findings": findings[:50],
        }

    except Exception as e:
        print("Scan error:", e)
        raise HTTPException(status_code=500, detail="Error while scanning parsed events")


@app.get("/scan/run/{run_id}")
def get_scan_report(run_id: str):
    """
    GET /scan/run/{run_id}
    Rapport groupé par sévérité (dashboard + report-generator).
    """
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute("""
          SELECT id, rule_id, title, severity, confidence, evidence, detected_at
          FROM vulnerabilities
          WHERE run_id = %s
          ORDER BY
            CASE severity
              WHEN 'critical' THEN 1
              WHEN 'high' THEN 2
              WHEN 'medium' THEN 3
              WHEN 'low' THEN 4
              ELSE 5
            END,
            detected_at DESC
        """, (run_id,))
        items = cur.fetchall()

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
        for it in items:
            sev = (it.get("severity") or "other").lower()
            if sev not in summary:
                sev = "other"
            summary[sev] += 1

        return {"runId": run_id, "total": len(items), "summary": summary, "items": items}

    except Exception as e:
        print("Report error:", e)
        raise HTTPException(status_code=500, detail="Error while building scan report")
