from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from datetime import datetime
from dotenv import load_dotenv
from pymongo import MongoClient
from jsonpath_ng import parse as jsonpath_parse
from bson import ObjectId
import yaml
import re
import os
from typing import Union, Optional, Any, Dict, List


# ======================================================
# 1) CONFIGURATION / ENV
# ======================================================

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
PORT = int(os.getenv("PORT", "3002"))
DB_NAME = os.getenv("DB_NAME", "safeops_logs")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI is not set in .env")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
raw_logs_collection = db["raw_logs"]        # MS1
parsed_logs_collection = db["parsed_logs"]  # MS2

app = FastAPI(title="LogParser", version="1.2.0")


# ======================================================
# 2) REGEX / OUTILS D’EXTRACTION
# ======================================================

REGEX_PATTERNS = {
    "error": re.compile(r"(error|failed|exception|traceback)", re.IGNORECASE),
    "warning": re.compile(r"(warning|warn)", re.IGNORECASE),
    "secret": re.compile(r"(AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36})"),
    "url": re.compile(r"https?://[^\s]+"),
    "bypass": re.compile(r"(skip\s+checks|--no-verify|disable\s+security|bypass)", re.IGNORECASE),
}

STEP_LINE_PATTERNS = [
    re.compile(r"^\s*##\[group\]\s*(.+)$", re.IGNORECASE),
    re.compile(r"^\s*Step\s*\d+\s*:\s*(.+)$", re.IGNORECASE),
    re.compile(r"^\s*Run\s+(.+)$", re.IGNORECASE),
    re.compile(r"^\s*Executing\s+(.+)$", re.IGNORECASE),
    re.compile(r"^\s*Job\s*:\s*(.+)$", re.IGNORECASE),
]


def extract_regex_findings(text: Optional[str]) -> Dict[str, Any]:
    """
    Résumé compact (counts/lists) - utile pour score + dashboard.
    """
    if not text:
        return {"errors": [], "warnings": [], "secrets": [], "urls": [], "bypass": [], "steps": []}

    # steps (on garde juste les matches simples si besoin)
    steps = []
    for p in STEP_LINE_PATTERNS:
        steps.extend(p.findall(text))

    return {
        "errors": REGEX_PATTERNS["error"].findall(text),
        "warnings": REGEX_PATTERNS["warning"].findall(text),
        "secrets": REGEX_PATTERNS["secret"].findall(text),
        "urls": REGEX_PATTERNS["url"].findall(text),
        "bypass": REGEX_PATTERNS["bypass"].findall(text),
        "steps": steps,
    }


def extract_semantic_events(text: str) -> List[Dict[str, Any]]:
    """
    Evénements sémantiques demandés par le prof:
    - jobs/steps
    - erreurs
    - secrets
    - URLs
    - bypass
    Chaque event contient la ligne + line_no => exploitable par VulnDetector.
    """
    if not text:
        return []

    events: List[Dict[str, Any]] = []
    lines = text.splitlines()

    for idx, line in enumerate(lines):
        ln = idx + 1
        stripped = line.strip()
        if not stripped:
            continue

        # job/step
        for p in STEP_LINE_PATTERNS:
            m = p.search(line)
            if m:
                value = m.group(1).strip() if m.groups() else stripped
                events.append({
                    "type": "job_step",
                    "value": value,
                    "line": stripped,
                    "line_no": ln
                })
                break

        # error line
        if REGEX_PATTERNS["error"].search(line):
            events.append({
                "type": "error",
                "value": stripped,
                "line": stripped,
                "line_no": ln
            })

        # bypass
        if REGEX_PATTERNS["bypass"].search(line):
            events.append({
                "type": "bypass",
                "value": stripped,
                "line": stripped,
                "line_no": ln
            })

        # secrets
        for s in REGEX_PATTERNS["secret"].findall(line):
            events.append({
                "type": "secret",
                "value": s,
                "line": stripped,
                "line_no": ln
            })

        # urls
        for u in REGEX_PATTERNS["url"].findall(line):
            events.append({
                "type": "url",
                "value": u,
                "line": stripped,
                "line_no": ln
            })

    return events


def try_parse_yaml(raw_text: Optional[str]) -> Optional[dict]:
    if not raw_text or not isinstance(raw_text, str):
        return None
    try:
        data = yaml.safe_load(raw_text)
        if isinstance(data, (dict, list)):
            return data
        return None
    except Exception:
        return None


def extract_jsonpath(data: Optional[dict], path: str) -> Optional[List[Any]]:
    if not data or not isinstance(data, dict):
        return None
    try:
        expr = jsonpath_parse(path)
        return [m.value for m in expr.find(data)]
    except Exception:
        return None


def compute_severity(findings: Dict[str, Any]) -> Dict[str, Any]:
    secrets = len(findings.get("secrets", []))
    errors = len(findings.get("errors", []))
    bypass = len(findings.get("bypass", []))
    warnings = len(findings.get("warnings", []))
    urls = len(findings.get("urls", []))

    score = 0
    score += secrets * 50
    score += bypass * 25
    score += errors * 15
    score += warnings * 5
    score += min(urls, 5) * 2
    score = min(score, 100)

    if secrets > 0:
        severity = "critical"
    elif bypass > 0 or errors >= 2:
        severity = "high"
    elif errors == 1 or warnings >= 2:
        severity = "medium"
    else:
        severity = "low"

    return {"severity": severity, "score": score}


# ======================================================
# 3) NORMALISATION DES LOGS raw_logs (MS1)
# ======================================================

def normalize_raw_log(doc: dict) -> dict:
    """
    Supporte:
    - format récent: {source,pipelineId,runId,raw,...}
    - format ancien : {data:{...}, createdAt}
    """
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}

    raw_text = doc.get("raw")
    if raw_text is None:
        raw_text = data.get("raw") or data.get("log")

    return {
        "raw_log_id": str(doc.get("_id")),
        "source": doc.get("source") or data.get("source") or "unknown",
        "pipelineId": doc.get("pipelineId") or data.get("pipelineId") or "unknown",
        "runId": doc.get("runId") or data.get("runId") or "unknown",
        "repo": doc.get("repo") or data.get("repo") or data.get("repository"),
        "branch": doc.get("branch") or data.get("branch"),
        "jobId": doc.get("jobId") or data.get("jobId"),
        "status": doc.get("status") or data.get("status"),
        "raw_text": raw_text or "",
        "createdAt_raw": doc.get("createdAt"),
        "pulled": bool(doc.get("pulled", False)),
    }


# ======================================================
# 4) SCHEMAS
# ======================================================

class LogInput(BaseModel):
    pipeline: Optional[str] = None
    status: Optional[str] = None
    message: Optional[str] = None
    raw: Union[dict, str, None] = None


# ======================================================
# 5) ENDPOINTS
# ======================================================

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {"message": "LogParser is running"}


@app.post("/logs/parse")
def parse_log(log: LogInput):
    """
    API demandée: POST /logs/parse
    - regex
    - parsing YAML
    - jsonpath sur json
    - stockage Mongo parsed_logs
    """
    try:
        # déterminer texte brut à analyser
        raw_text = ""
        yaml_data = None
        important_fields = None

        if isinstance(log.raw, str):
            raw_text = log.raw
            yaml_data = try_parse_yaml(raw_text)

        elif isinstance(log.raw, dict):
            # si raw json, on analyse message + on extrait champs via jsonpath
            raw_text = log.message or ""
            important_fields = {
                "pipeline_name": extract_jsonpath(log.raw, "$.pipeline.name"),
                "first_step": extract_jsonpath(log.raw, "$.steps[0].name"),
            }

        else:
            raw_text = log.message or ""

        findings = extract_regex_findings(raw_text)
        events = extract_semantic_events(raw_text)
        sev = compute_severity(findings)

        parsed = {
            "source": "manual",
            "pipelineId": log.pipeline or "unknown",
            "runId": "unknown",
            "status": (log.status or "unknown"),
            "message": log.message,

            "events": events,                 # ✅ jobs/errors/secrets/urls/bypass
            "regex_findings": findings,       # résumé
            "severity": sev["severity"],
            "severity_score": sev["score"],

            "yaml": yaml_data,
            "important_fields": important_fields,

            "createdAt": datetime.utcnow(),
        }

        result = parsed_logs_collection.insert_one(parsed.copy())

        return {
            "message": "Log parsed and saved",
            "id": str(result.inserted_id),
            "parsed": parsed,
        }

    except Exception as e:
        print("Parse error:", e)
        raise HTTPException(status_code=500, detail="Error while parsing log")


@app.post("/logs/parse/from-db")
def parse_from_db(limit: int = Query(20, ge=1, le=200)):
    """
    BONUS utile pour pipeline automatique:
    - lit raw_logs
    - normalise
    - parse + events
    - insère dans parsed_logs
    - anti-duplication par raw_log_id
    """
    try:
        raw_docs = list(raw_logs_collection.find().sort("createdAt", -1).limit(int(limit)))

        inserted = 0
        items = []

        for doc in raw_docs:
            norm = normalize_raw_log(doc)
            raw_text = norm["raw_text"]

            if parsed_logs_collection.find_one({"raw_log_id": norm["raw_log_id"]}):
                continue

            findings = extract_regex_findings(raw_text)
            events = extract_semantic_events(raw_text)
            sev = compute_severity(findings)
            yaml_data = try_parse_yaml(raw_text)

            parsed = {
                "raw_log_id": norm["raw_log_id"],
                "source": norm["source"],
                "pipelineId": norm["pipelineId"],
                "runId": norm["runId"],
                "repo": norm["repo"],
                "branch": norm["branch"],
                "jobId": norm["jobId"],
                "status": norm["status"],
                "pulled": norm["pulled"],

                "events": events,               # ✅ événements sémantiques
                "regex_findings": findings,
                "severity": sev["severity"],
                "severity_score": sev["score"],
                "yaml": yaml_data,

                "createdAt": datetime.utcnow(),
            }

            r = parsed_logs_collection.insert_one(parsed.copy())
            inserted += 1
            items.append({"raw_log_id": norm["raw_log_id"], "parsed_id": str(r.inserted_id)})

        return {
            "message": "Parsed from DB",
            "requested": int(limit),
            "inserted": inserted,
            "items": items,
        }

    except Exception as e:
        print("Parse-from-db error:", e)
        raise HTTPException(status_code=500, detail="Error while parsing from DB")


@app.get("/parsed")
def list_parsed(limit: int = Query(20, ge=1, le=200)):
    try:
        docs = list(parsed_logs_collection.find().sort("createdAt", -1).limit(int(limit)))
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs
    except Exception as e:
        print("List parsed error:", e)
        raise HTTPException(status_code=500, detail="Error while fetching parsed logs")


@app.get("/parsed/{parsed_id}")
def get_parsed_by_id(parsed_id: str):
    try:
        doc = parsed_logs_collection.find_one({"_id": ObjectId(parsed_id)})
        if not doc:
            raise HTTPException(status_code=404, detail="Parsed log not found")
        doc["_id"] = str(doc["_id"])
        return doc
    except HTTPException:
        raise
    except Exception as e:
        print("Get parsed error:", e)
        raise HTTPException(status_code=400, detail="Invalid id format")
