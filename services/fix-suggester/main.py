import os
import time
import yaml
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware

from jinja2 import Environment, BaseLoader
from diff_match_patch import diff_match_patch


# ======================================================
# 1) CONFIG / ENV
# ======================================================
APP_NAME = "fix-suggester"

PORT = int(os.getenv("PORT", "3004"))  # (ton Docker peut override PORT=3007)

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_USER = os.getenv("POSTGRES_USER", "safeops")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "safeops")
POSTGRES_DB = os.getenv("POSTGRES_DB", "safeops_security")

# Fichier des règles de correction
FIX_RULES_FILE = os.getenv("FIX_RULES_FILE", "rules_fixes.yaml")

# CORS (dashboard)
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "*")

app = FastAPI(title="SafeOps Fix Suggester", version="2.0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[CORS_ORIGIN] if CORS_ORIGIN != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ======================================================
# 2) DB HELPERS
# ======================================================
def db_conn():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        dbname=POSTGRES_DB,
    )


def wait_pg():
    """Attendre que Postgres soit prêt (utile en docker-compose)."""
    last = None
    for _ in range(30):
        try:
            with db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1;")
                    cur.fetchone()
            return
        except Exception as e:
            last = e
            time.sleep(1)
    raise RuntimeError(f"Postgres not ready: {last}")


def init_tables():
    """Créer les tables nécessaires à MS4."""
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS fix_reports (
              id BIGSERIAL PRIMARY KEY,
              pipeline_id TEXT NOT NULL,
              run_id UUID NULL,
              rule_id TEXT NULL,
              title TEXT NULL,
              yaml_patch TEXT NOT NULL,
              patched_yaml_preview TEXT NOT NULL,
              original_yaml TEXT NOT NULL,
              safe BOOLEAN NOT NULL DEFAULT true,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS patch_applies (
              id BIGSERIAL PRIMARY KEY,
              pipeline_id TEXT NOT NULL,
              run_id UUID NULL,
              rule_id TEXT NULL,
              original_yaml TEXT NOT NULL,
              yaml_patch TEXT NOT NULL,
              patched_yaml TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'applied',
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """)
        conn.commit()


# ======================================================
# 3) RULES LOADER
# ======================================================
FIX_RULES: Dict[str, Any] = {"rules": []}


def load_fix_rules() -> Dict[str, Any]:
    """Charger rules_fixes.yaml."""
    if not os.path.exists(FIX_RULES_FILE):
        return {"rules": []}
    with open(FIX_RULES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {"rules": []}


def find_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    for r in FIX_RULES.get("rules", []):
        if r.get("rule_id") == rule_id:
            return r
    return None


# ======================================================
# 4) SCHEMAS API
# ======================================================
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
    findings: List[Finding] = Field(default_factory=list)


class ApplyRequest(BaseModel):
    pipeline_id: str
    run_id: Optional[str] = None

    # mode A
    fix_id: Optional[int] = None

    # mode B (manual)
    original_yaml: Optional[str] = None
    patched_yaml: Optional[str] = None

    rule_id: Optional[str] = "AUTO"


# ======================================================
# 5) UTIL: TIME + BASELINE HARDENING
# ======================================================
def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_baseline(original_yaml: str) -> str:
    """
    Ajout de hardening "safe defaults" (démo-friendly).
    Tu peux enrichir :
    - permissions minimales
    - concurrency
    - timeout
    """
    lines = original_yaml.splitlines()

    # permissions (si absent)
    if not any(l.strip().startswith("permissions:") for l in lines):
        lines.insert(0, "permissions: read-all")

    # concurrency (si absent)
    if not any(l.strip().startswith("concurrency:") for l in lines):
        lines.append("")
        lines.append("concurrency:")
        # IMPORTANT: garde le GitHub expression tel quel (ne pas casser ${{ }})
        lines.append("  group: safeops-${{ github.ref }}")
        lines.append("  cancel-in-progress: true")

    return "\n".join(lines).rstrip() + "\n"


# ======================================================
# 6) PATCH GENERATION (Jinja2 + diff-match-patch)
# ======================================================
from jinja2 import Environment, BaseLoader

JINJA_ENV = Environment(
    loader=BaseLoader(),
    autoescape=False,
    variable_start_string="[[",
    variable_end_string="]]",
)

def render_template(template_text: str, ctx: Dict[str, Any]) -> str:
    tpl = JINJA_ENV.from_string(template_text)
    return tpl.render(**ctx)

    tpl = JINJA_ENV.from_string(template_text)
    return tpl.render(**ctx)


def build_patched_yaml(original_yaml: str, findings: List[Finding]) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Construit un YAML final (preview) en ajoutant des blocks de fix
    dans une zone commentée / safe.
    """
    base = ensure_baseline(original_yaml)

    ctx = {"generated_at": iso_now()}
    applied: List[Dict[str, Any]] = []
    blocks: List[str] = []

    # AUTO: si pas de findings, on applique rien (pro)
    for f in findings:
        rule = find_rule(f.rule_id)
        if not rule:
            continue

        sug = rule.get("suggestion") or {}
        template_text = (sug.get("template") or "").strip()
        if not template_text:
            continue

        safe = bool(sug.get("safe", True))

        applied.append(
            {
                "rule_id": rule.get("rule_id"),
                "title": rule.get("title") or f.title,
                "severity": rule.get("severity") or f.severity,
                "safe": safe,
            }
        )

        header = (
            f"# --------------------------------------------------\n"
            f"# SafeOps Auto-Fix: {rule.get('rule_id')} ({rule.get('severity','medium')})\n"
            f"# GeneratedAt: {iso_now()}\n"
            f"# --------------------------------------------------\n"
        )
        blocks.append(header + render_template(template_text, ctx) + "\n")

    patched = base + "\n# ===== SafeOps Auto-Fix Suggestions =====\n\n" + "\n".join(blocks)
    return patched, applied


def make_diff(old_text: str, new_text: str) -> str:
    """
    Génère un diff "patch" lisible pour afficher au user (commenté).
    On stocke :
    - yaml_patch (diff)
    - patched_yaml_preview (YAML complet)
    """
    dmp = diff_match_patch()
    diffs = dmp.diff_main(old_text, new_text)
    dmp.diff_cleanupSemantic(diffs)
    patches = dmp.patch_make(old_text, diffs)
    patch_text = dmp.patch_toText(patches)

    commented = "\n".join([("# " + line) for line in patch_text.splitlines()]) + "\n"
    return commented


# ======================================================
# 7) DB INSERT / GET
# ======================================================
def insert_fix_report(
    pipeline_id: str,
    run_id: Optional[str],
    rule_id: Optional[str],
    title: Optional[str],
    yaml_patch: str,
    patched_yaml_preview: str,
    original_yaml: str,
    safe: bool,
) -> int:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO fix_reports (
                    pipeline_id, run_id, rule_id, title,
                    yaml_patch, patched_yaml_preview, original_yaml, safe
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
                """,
                (
                    pipeline_id,
                    run_id,
                    rule_id,
                    title,
                    yaml_patch,
                    patched_yaml_preview,
                    original_yaml,
                    safe,
                ),
            )
            return cur.fetchone()[0]


def get_fix_by_id(fix_id: int) -> Optional[Dict[str, Any]]:
    with db_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM fix_reports WHERE id=%s", (fix_id,))
            return cur.fetchone()


def insert_patch_apply(
    pipeline_id: str,
    run_id: Optional[str],
    rule_id: str,
    original_yaml: str,
    yaml_patch: str,
    patched_yaml: str,
    status: str = "applied",
) -> int:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO patch_applies (
                    pipeline_id, run_id, rule_id,
                    original_yaml, yaml_patch, patched_yaml, status
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
                """,
                (pipeline_id, run_id, rule_id, original_yaml, yaml_patch, patched_yaml, status),
            )
            return cur.fetchone()[0]


# ======================================================
# 8) FASTAPI STARTUP
# ======================================================
@app.on_event("startup")
def startup():
    wait_pg()
    init_tables()
    global FIX_RULES
    FIX_RULES = load_fix_rules()


# ======================================================
# 9) ROUTES
# ======================================================
@app.get("/health")
def health():
    return {"status": "ok", "service": APP_NAME, "rules": len(FIX_RULES.get("rules", []))}


@app.post("/fix")
def fix(req: FixRequest):
    """
    POST /fix
    Input:
      - original_yaml
      - findings[] (rule_id)
    Output:
      - fix_id
      - yaml_patch (diff commenté)
      - patched_yaml_preview (yaml complet)
    """
    try:
        patched_yaml, applied = build_patched_yaml(req.original_yaml, req.findings)
        yaml_patch = make_diff(req.original_yaml, patched_yaml)

        # info DB (première règle appliquée)
        rule_id = applied[0]["rule_id"] if applied else None
        title = applied[0]["title"] if applied else "Fix suggestion"
        safe = all(a.get("safe", True) for a in applied) if applied else True

        fix_id = insert_fix_report(
            pipeline_id=req.pipeline_id,
            run_id=req.run_id,
            rule_id=rule_id,
            title=title,
            yaml_patch=yaml_patch,
            patched_yaml_preview=patched_yaml,
            original_yaml=req.original_yaml,
            safe=safe,
        )

        return {
            "fix_id": fix_id,
            "pipeline_id": req.pipeline_id,
            "run_id": req.run_id,
            "applied_rules": applied,
            "safe": safe,
            "yaml_patch": yaml_patch,
            "patched_yaml_preview": patched_yaml,
        }

    except Exception as e:
        # ✅ pour voir la vraie erreur dans docker logs
        print("❌ /fix crashed:", repr(e))
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Fix failed: {str(e)}")


@app.post("/apply/fix/{fix_id}")
def apply_fix(fix_id: int):
    """
    Applique un fix stocké en DB:
    - on applique le patched_yaml_preview (YAML complet)
    - on log l'opération dans patch_applies
    """
    fx = get_fix_by_id(fix_id)
    if not fx:
        raise HTTPException(status_code=404, detail="Fix not found")

    patched = fx.get("patched_yaml_preview")
    if not patched:
        raise HTTPException(status_code=400, detail="Fix has no patched_yaml_preview")

    apply_id = insert_patch_apply(
        pipeline_id=fx["pipeline_id"],
        run_id=fx.get("run_id"),
        rule_id=fx.get("rule_id") or "AUTO",
        original_yaml=fx.get("original_yaml") or "",
        yaml_patch=fx.get("yaml_patch") or "",
        patched_yaml=patched,
        status="applied",
    )

    return {"ok": True, "apply_id": apply_id, "fix_id": fix_id, "status": "applied"}


@app.post("/apply")
def apply(req: ApplyRequest):
    """
    Mode A:
      {"pipeline_id":"x","fix_id": 12}
    Mode B:
      {"pipeline_id":"x","original_yaml":"...","patched_yaml":"..."}
    """
    try:
        if req.fix_id is not None:
            fx = get_fix_by_id(req.fix_id)
            if not fx:
                raise HTTPException(status_code=404, detail="Fix not found")

            patched = fx.get("patched_yaml_preview")
            if not patched:
                raise HTTPException(status_code=400, detail="Fix has no preview stored")

            apply_id = insert_patch_apply(
                pipeline_id=fx["pipeline_id"],
                run_id=fx.get("run_id"),
                rule_id=fx.get("rule_id") or req.rule_id or "AUTO",
                original_yaml=fx.get("original_yaml") or "",
                yaml_patch=fx.get("yaml_patch") or "",
                patched_yaml=patched,
                status="applied",
            )
            return {"ok": True, "apply_id": apply_id, "status": "applied", "fix_id": req.fix_id}

        # mode B
        if not req.original_yaml or not req.patched_yaml:
            raise HTTPException(status_code=400, detail="Provide fix_id OR (original_yaml + patched_yaml)")

        apply_id = insert_patch_apply(
            pipeline_id=req.pipeline_id,
            run_id=req.run_id,
            rule_id=req.rule_id or "MANUAL",
            original_yaml=req.original_yaml,
            yaml_patch="(manual)",
            patched_yaml=req.patched_yaml,
            status="applied",
        )
        return {"ok": True, "apply_id": apply_id, "status": "applied"}

    except HTTPException:
        raise
    except Exception as e:
        print("❌ /apply crashed:", repr(e))
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Apply failed: {str(e)}")
