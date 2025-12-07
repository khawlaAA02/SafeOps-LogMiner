from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
from dotenv import load_dotenv
from pymongo import MongoClient
from jsonpath_ng import parse as jsonpath_parse
import yaml
import re
import os
from typing import Union

# Charger .env
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
PORT = int(os.getenv("PORT", "3002"))

if not MONGO_URI:
    raise RuntimeError("MONGO_URI is not set in .env")

# Connexion Mongo
client = MongoClient(MONGO_URI)
db = client["safeops_logs"]
raw_logs_collection = db["raw_logs"]
parsed_logs_collection = db["parsed_logs"]

app = FastAPI(title="LogParser")

# ------------------------
# 🔎 REGEX / YAML / JSONPATH
# ------------------------

REGEX_PATTERNS = {
    "error": re.compile(r"(error|failed|exception)", re.IGNORECASE),
    # exemple secrets : clé AWS ou GitHub token
    "secret": re.compile(r"(AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36})"),
    "url": re.compile(r"https?://[^\s]+"),
}


def extract_regex_patterns(message: str | None):
    """Analyse une string et détecte erreurs / secrets / URLs."""
    if not message:
        return {}

    return {
        "errors": REGEX_PATTERNS["error"].findall(message),
        "secrets": REGEX_PATTERNS["secret"].findall(message),
        "urls": REGEX_PATTERNS["url"].findall(message),
    }


def parse_yaml(raw_text: str | None):
    """Parse du YAML brut si possible."""
    if not raw_text:
        return None
    try:
        return yaml.safe_load(raw_text)
    except Exception:
        return None


def extract_jsonpath(data: dict | None, path: str):
    """Extrait des éléments précis dans un JSON via JSONPath."""
    if not data:
        return None
    try:
        expr = jsonpath_parse(path)
        return [match.value for match in expr.find(data)]
    except Exception:
        return None


# Schéma d'entrée (log JSON)
class LogInput(BaseModel):
    pipeline: str | None = None
    status: str | None = None
    message: str | None = None
    # raw peut être du JSON (dict) ou du texte YAML
    raw: Union[dict, str, None] = None


@app.get("/")
async def root():
    return {"message": "LogParser is running"}


@app.post("/logs/parse")
def parse_log(log: LogInput):
    """
    1) Reçoit un log JSON
    2) Applique un parsing enrichi (regex / YAML / JSONPath)
    3) Sauvegarde dans parsed_logs
    """
    try:
        # Dictionnaire "propre" pour la réponse API (jamais touché par Mongo)
        parsed = {
            "pipeline": log.pipeline or "unknown",
            "status": log.status or "unknown",
            "has_error": (
                log.status is not None
                and log.status.lower() in ["error", "failed", "failure"]
            ),
            "message": log.message,
            "createdAt": datetime.utcnow(),
        }

        # 🔎 1) Analyse REGEX sur le message
        parsed["regex_findings"] = extract_regex_patterns(log.message)

        # 2) Analyse du champ raw
        # - si string → on suppose YAML possible
        # - si dict   → JSON + JSONPath
        if isinstance(log.raw, str):
            parsed["yaml"] = parse_yaml(log.raw)
        elif isinstance(log.raw, dict):
            parsed["important_fields"] = {
                "pipeline_name": extract_jsonpath(log.raw, "$.pipeline.name"),
                "first_step": extract_jsonpath(log.raw, "$.steps[0].name"),
            }

        # Copie pour MongoDB (c'est celle-ci que PyMongo va modifier en ajoutant _id)
        parsed_to_save = parsed.copy()
        result = parsed_logs_collection.insert_one(parsed_to_save)

        return {
            "message": "Log parsed and saved",
            "id": str(result.inserted_id),   # id en string pour l'API
            "parsed": parsed                 # dict sans ObjectId -> JSON OK
        }

    except Exception as e:
        print("Parse error:", e)
        raise HTTPException(status_code=500, detail="Error while parsing log")
