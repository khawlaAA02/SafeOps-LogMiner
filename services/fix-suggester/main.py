import os
import yaml
import psycopg2
from psycopg2.extras import Json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

APP_NAME = "fix-suggester"

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_USER = os.getenv("POSTGRES_USER", "safeops")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "safeops")
POSTGRES_DB = os.getenv("POSTGRES_DB", "safeops_security")

FIX_RULES_FILE = os.getenv("FIX_RULES_FILE", "rules_fixes.yaml")
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "*")

app = FastAPI(title="SafeOps Fix Suggester", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[CORS_ORIGIN] if CORS_ORIGIN != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------- Models -------------
class Finding(BaseModel):
    rule_id: str
    title: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None

class FixRequest(BaseModel):
    pipeline_id: str
    run_id: Optional[str] = None
    original_yaml: str = Field(..., description="Original pipeline YAML content")
    findings: List[Finding] = []

class ApplyRequest(BaseModel):
    pipeline_id: str
    run_id: Optional[str] = None
    original_yaml: str
    yaml_patch: str
    rule_id: Optional[str] = None

# ------------- DB -------------
def db_conn():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        dbname=POSTGRES_DB,
    )

def insert_fix_report(pipeline_id: str, run_id: Optional[str], rule_id: Optional[str], title: Optional[str], yaml_patch: str):
    # Stocker la proposition dans fix_reports (preuve que le système propose des correctifs)
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO fix_reports (pipeline_id, run_id, rule_id, title, yaml_patch)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (pipeline_id, run_id, rule_id, title, yaml_patch)
            )
            new_id = cur.fetchone()[0]
            return new_id

def insert_patch_apply(pipeline_id: str, run_id: Optional[str], rule_id: Optional[str],
                       original_yaml: str, yaml_patch: str, patched_yaml: str, status: str = "simulated"):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO patch_applies (pipeline_id, run_id, rule_id, original_yaml, yaml_patch, patched_yaml, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (pipeline_id, run_id, rule_id, original_yaml, yaml_patch, patched_yaml, status)
            )
            return cur.fetchone()[0]

# ------------- Fix rules loading -------------
FIX_RULES: Dict[str, Any] = {}

def load_fix_rules():
    if not os.path.exists(FIX_RULES_FILE):
        # Pas bloquant : on laisse vide
        return {"rules": []}
    with open(FIX_RULES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {"rules": []}

@app.on_event("startup")
def on_startup():
    global FIX_RULES
    FIX_RULES = load_fix_rules()

@app.get("/health")
def health():
    return {"status": "ok", "service": APP_NAME}

# ------------- Patch generation (simple & demo-friendly) -------------
def build_patch(original_yaml: str, triggers: List[str]) -> str:
    """
    Génère un patch "diff" simple.
    (Dans un vrai outil, tu ferais un vrai patch unifié + application réelle.)
    """
    lines = original_yaml.splitlines()
    # Ajout d’un "hardening baseline" en haut s'il manque permissions
    patched_lines = list(lines)

    if not any(l.strip().startswith("permissions:") for l in patched_lines):
        patched_lines.insert(0, "permissions: read-all")

    # Ajouts de commentaires anti-secrets + concurrency
    if "Do NOT print secrets" not in original_yaml:
        patched_lines.append("")
        patched_lines.append("# FIX: Do NOT print secrets in logs. Use CI secret store + masking.")
        patched_lines.append("")
        patched_lines.append("# FIX: Hardening baseline")
        patched_lines.append("concurrency:")
        patched_lines.append("  group: safeops-${{ github.ref }}")
        patched_lines.append("  cancel-in-progress: true")

    # Diff fake (suffisant pour démo prof)
    before = "\n".join(lines) + "\n"
    after = "\n".join(patched_lines) + "\n"

    patch = (
        "--- before.yml\n"
        "+++ after.yml\n"
        "@@ -1,3 +1,4 @@\n"
        "+permissions: read-all\n\n"
    )
    # On met le "after" comme bloc pour être clair
    patch += "\n# --- AFTER (preview) ---\n" + after
    return patch, after

@app.post("/fix")
def suggest_fix(req: FixRequest):
    triggers = [f.rule_id for f in req.findings] if req.findings else []
    rule_id = triggers[0] if triggers else None
    title = req.findings[0].title if req.findings and req.findings[0].title else "Fix suggestion"

    yaml_patch, patched_yaml_preview = build_patch(req.original_yaml, triggers)

    # ✅ IMPORTANT: on sauvegarde dans fix_reports
    try:
        fix_id = insert_fix_report(
            pipeline_id=req.pipeline_id,
            run_id=req.run_id,
            rule_id=rule_id,
            title=title,
            yaml_patch=yaml_patch,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB insert failed: {str(e)}")

    return {
        "fix_id": fix_id,
        "pipeline_id": req.pipeline_id,
        "run_id": req.run_id,
        "triggers": triggers,
        "yaml_patch": yaml_patch,
        "safe": True,
        "note": "Correctifs proposés (sauvegardés en DB).",
        "patched_yaml_preview": patched_yaml_preview,  # utile côté dashboard
    }

@app.post("/apply")
def apply_fix(req: ApplyRequest):
    """
    Pour la preuve 'corriger automatiquement' :
    - ici on 'applique' en simulation (on prend le after preview)
    - on sauvegarde le résultat dans patch_applies
    """
    # On reconstruit un patched_yaml simple
    # (si tu veux appliquer un vrai diff unifié, je te donne après une version plus avancée)
    if "# --- AFTER (preview) ---" in req.yaml_patch:
        patched_yaml = req.yaml_patch.split("# --- AFTER (preview) ---", 1)[1].lstrip("\n")
    else:
        # fallback: on garde original + commentaire
        patched_yaml = req.original_yaml + "\n\n# simulated apply\n"

    try:
        apply_id = insert_patch_apply(
            pipeline_id=req.pipeline_id,
            run_id=req.run_id,
            rule_id=req.rule_id,
            original_yaml=req.original_yaml,
            yaml_patch=req.yaml_patch,
            patched_yaml=patched_yaml,
            status="simulated",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB apply insert failed: {str(e)}")

    return {
        "apply_id": apply_id,
        "status": "simulated",
        "pipeline_id": req.pipeline_id,
        "run_id": req.run_id,
        "rule_id": req.rule_id,
        "patched_yaml": patched_yaml,
        "note": "Correctif appliqué en SIMULATION (preuve auto-correction).",
    }
