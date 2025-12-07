from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime
import yaml
import os
import psycopg2
import json
# -------------------------------------
# 1. Chargement des variables d'environnement
# -------------------------------------
load_dotenv()

PG_HOST = os.getenv("POSTGRES_HOST", "localhost")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5433"))
PG_DB   = os.getenv("POSTGRES_DB", "safeops_security")
PG_USER = os.getenv("POSTGRES_USER", "safeops")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "safeops")

# Vérification
if not PG_HOST:
    raise RuntimeError("POSTGRES_HOST is missing in .env")
if not PG_DB:
    raise RuntimeError("POSTGRES_DB is missing in .env")

# -------------------------------------
# 2. Connexion PostgreSQL
# -------------------------------------
# Connexion Postgres (safeops-pg)
conn = psycopg2.connect(
    host=PG_HOST,
    port=PG_PORT,
    dbname=PG_DB,
    user=PG_USER,
    password=PG_PASS,
)
cursor = conn.cursor()

# Création table résultats vulnérabilités
cursor.execute("""
CREATE TABLE IF NOT EXISTS vuln_reports (
    id SERIAL PRIMARY KEY,
    pipeline VARCHAR(255),
    status VARCHAR(100),
    vulnerabilities JSON,
    created_at TIMESTAMP
)
""")
conn.commit()

# -------------------------------------
# 3. Chargement des règles YAML
# -------------------------------------
RULES_FILE = "rules.yaml"

if not os.path.exists(RULES_FILE):
    raise RuntimeError("Le fichier rules.yaml est manquant !")

with open(RULES_FILE, "r", encoding="utf-8") as f:
    RULES = yaml.safe_load(f)

# -------------------------------------
# 4. API FastAPI
# -------------------------------------
app = FastAPI(title="VulnDetector")


# Schéma du log d'entrée
class ParsedLog(BaseModel):
    pipeline: str
    status: str
    has_error: bool | None = None
    message: str | None = None
    regex_findings: dict | None = None
    important_fields: dict | None = None


@app.get("/")
def root():
    return {"message": "VulnDetector is running"}


# -------------------------------------
# 5. Détection des vulnérabilités
# -------------------------------------
def apply_rules(log: ParsedLog):
    vulnerabilities = []

    # Vérifier règles simples (exemple)
    for rule in RULES.get("rules", []):
        field = rule.get("field")
        contains = rule.get("contains")
        vuln_msg = rule.get("message")

        # Ex : field=message contains=token → vuln
        value = getattr(log, field, "")

        if value and contains and contains.lower() in str(value).lower():
            vulnerabilities.append(vuln_msg)

    return vulnerabilities


@app.post("/scan")
def scan_log(log: ParsedLog):
    """
    1. Reçoit un log parsé (JSON)
    2. Applique les règles YAML
    3. Sauvegarde le rapport dans PostgreSQL
    4. Retourne les vulnérabilités trouvées
    """
    try:
        vulns = apply_rules(log)

        cursor.execute(
            """
            INSERT INTO vuln_reports (pipeline, status, vulnerabilities, created_at)
            VALUES (%s, %s, %s, %s)
            """,
            (
                log.pipeline,
                log.status,
                json.dumps(vulns),
                datetime.utcnow()
            )
        )
        conn.commit()

        return {
            "message": "Scan completed",
            "vulnerabilities": vulns
        }

    except Exception as e:
        print("Scan error:", e)
        raise HTTPException(status_code=500, detail="Error while scanning log")


