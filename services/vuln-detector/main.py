from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime
import yaml
import os
import time
import psycopg2
import psycopg2.extras
import json
from typing import Optional, List, Dict, Any

load_dotenv()

PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB   = os.getenv("POSTGRES_DB", "safeops_security")
PG_USER = os.getenv("POSTGRES_USER", "safeops")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "safeops")

RULES_FILE = os.getenv("RULES_FILE", "rules.yaml")
if not os.path.exists(RULES_FILE):
    raise RuntimeError("rules.yaml is missing (RULES_FILE)")

with open(RULES_FILE, "r", encoding="utf-8") as f:
    RULES_DOC = yaml.safe_load(f) or {}
RULES = RULES_DOC.get("rules", [])

app = FastAPI(title="VulnDetector", version="1.2.0")

_conn = None

def get_conn():
    global _conn
    if _conn and _conn.closed == 0:
        return _conn

    # Retry (important en Docker)
    last_err = None
    for _ in range(20):
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


def init_db():
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
        field TEXT,
        contains TEXT,
        recommendation TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS vuln_reports (
        id SERIAL PRIMARY KEY,
        pipeline TEXT,
        run_id TEXT,
        source TEXT,
        status TEXT,
        findings JSONB,
        created_at TIMESTAMP
    )
    """)

    # Indexes (bonus sérieux)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vuln_reports_created_at ON vuln_reports(created_at DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vuln_reports_pipeline ON vuln_reports(pipeline)")
    conn.commit()


def sync_rules_to_db():
    conn = get_conn()
    cur = conn.cursor()

    for rule in RULES:
        cur.execute("""
        INSERT INTO security_rules (id, title, description, severity, owasp, slsa, field, contains, recommendation)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (id) DO UPDATE SET
            title=EXCLUDED.title,
            description=EXCLUDED.description,
            severity=EXCLUDED.severity,
            owasp=EXCLUDED.owasp,
            slsa=EXCLUDED.slsa,
            field=EXCLUDED.field,
            contains=EXCLUDED.contains,
            recommendation=EXCLUDED.recommendation
        """, (
            rule.get("id"),
            rule.get("title"),
            rule.get("description"),
            rule.get("severity", "medium"),
            (rule.get("mapping", {}) or {}).get("owasp"),
            (rule.get("mapping", {}) or {}).get("slsa"),
            (rule.get("match", {}) or {}).get("field"),
            (rule.get("match", {}) or {}).get("contains"),
            rule.get("recommendation")
        ))

    conn.commit()


@app.on_event("startup")
def on_startup():
    init_db()
    sync_rules_to_db()


class ParsedLog(BaseModel):
    pipelineId: str
    runId: Optional[str] = None
    source: Optional[str] = None
    status: Optional[str] = None
    message: Optional[str] = None

    # Depuis LogParser
    regex_findings: Optional[dict] = None
    events: Optional[List[Dict[str, Any]]] = None

    severity: Optional[str] = None
    severity_score: Optional[int] = None


@app.get("/health")
def health():
    # ping DB
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        _ = cur.fetchone()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "degraded", "error": str(e)}


@app.get("/")
def root():
    return {"message": "VulnDetector is running"}


def get_by_path(obj: Any, path: str) -> Any:
    """
    Support simple de 'a.b.c' pour dicts.
    """
    if obj is None or not path:
        return None
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def apply_rules(log: ParsedLog) -> List[Dict[str, Any]]:
    """
    Applique des règles déclaratives YAML.
    field peut être:
    - "message"
    - "severity"
    - "regex_findings.secrets"
    - "events" (liste) avec contains sur type/value/line
    """
    findings: List[Dict[str, Any]] = []
    log_dict = log.model_dump()

    for rule in RULES:
        rule_id = rule.get("id")
        title = rule.get("title")
        sev = rule.get("severity", "medium")
        field = (rule.get("match", {}) or {}).get("field")
        contains = (rule.get("match", {}) or {}).get("contains")

        value = None
        if field:
            # champs top-level
            if field in log_dict:
                value = log_dict.get(field)
            # champs nested (regex_findings.xxx, etc)
            else:
                value = get_by_path(log_dict, field)

        hit = False
        evidence = None

        # Match sur string
        if isinstance(value, str):
            if contains and contains.lower() in value.lower():
                hit = True
                evidence = value

        # Match sur list (secrets/errors/events)
        elif isinstance(value, list) and value:
            if contains:
                # si liste d'events dict -> on cherche dans type/value/line
                filtered = []
                for x in value:
                    s = ""
                    if isinstance(x, dict):
                        s = f"{x.get('type','')} {x.get('value','')} {x.get('line','')}"
                    else:
                        s = str(x)
                    if contains.lower() in s.lower():
                        filtered.append(x)
                if filtered:
                    hit = True
                    evidence = filtered
            else:
                hit = True
                evidence = value

        # Match sur dict
        elif isinstance(value, dict) and value:
            if contains:
                s = json.dumps(value, ensure_ascii=False)
                if contains.lower() in s.lower():
                    hit = True
                    evidence = value
            else:
                hit = True
                evidence = value

        if hit:
            findings.append({
                "rule_id": rule_id,
                "title": title,
                "severity": sev,
                "mapping": rule.get("mapping", {}),
                "description": rule.get("description"),
                "recommendation": rule.get("recommendation"),
                "evidence": evidence,
            })

    return findings


@app.post("/scan")
def scan_log(log: ParsedLog):
    try:
        findings = apply_rules(log)

        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO vuln_reports (pipeline, run_id, source, status, findings, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                log.pipelineId,
                log.runId,
                log.source,
                log.status,
                json.dumps(findings),
                datetime.utcnow()
            )
        )
        conn.commit()

        return {"message": "Scan completed", "count": len(findings), "findings": findings}

    except Exception as e:
        print("Scan error:", e)
        raise HTTPException(status_code=500, detail="Error while scanning log")


@app.get("/reports")
def list_reports(limit: int = Query(20, ge=1, le=200)):
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT id, pipeline, run_id, source, status, findings, created_at
            FROM vuln_reports
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        return cur.fetchall()
    except Exception as e:
        print("List reports error:", e)
        raise HTTPException(status_code=500, detail="Error while fetching reports")
