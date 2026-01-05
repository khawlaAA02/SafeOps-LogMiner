"""
SafeOps-LogMiner — MS5 AnomalyDetector (FastAPI)
================================================

🎯 Objectif:
- Lire l'historique des exécutions CI/CD depuis `pipeline_runs` (table owned par LogCollector/migrations)
- Détecter une exécution anormale (Machine Learning + Deep Learning optionnel)
- Enregistrer le résultat dans `anomaly_reports` (table owned par MS5)

✅ Points forts:
- Init DB robuste (TimescaleDB optionnel via SAVEPOINT)
- Pool Postgres (SimpleConnectionPool)
- Cache modèle par pipeline (TTL)
- ML: IsolationForest (non supervisé)
- DL: AutoEncoder (optionnel via TF_ENABLED=true)
- Fallback heuristique si historique insuffisant (MIN_HISTORY)

Run:
  uvicorn main:app --host 0.0.0.0 --port 3005
"""

from __future__ import annotations

# =========================
# 1) IMPORTS
# =========================
import os
import time
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple, List

import numpy as np
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, ConfigDict, AliasChoices

import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# =========================
#    2) TENSORFLOW 
# =========================
# TF_ENABLED active/désactive le modèle Deep Learning.
# Si TF n'est pas installé -> service continue en mode IF only.

TF_ENABLED = os.getenv("TF_ENABLED", "false").lower() in ("1", "true", "yes", "y")
keras = None
try:
    if TF_ENABLED:
        import tensorflow as tf  # noqa: F401
        from tensorflow import keras  # type: ignore
except Exception:
    TF_ENABLED = False
    keras = None


# =========================
# 3) CONFIG / ENV
# =========================
PORT = int(os.getenv("PORT", "3005"))

PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB = os.getenv("POSTGRES_DB", "safeops_security")
PG_USER = os.getenv("POSTGRES_USER", "safeops")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "safeops")

# IsolationForest
ISO_CONTAMINATION = float(os.getenv("ISO_CONTAMINATION", "0.05"))
MIN_HISTORY = int(os.getenv("MIN_HISTORY", "10"))

# AutoEncoder
AE_EPOCHS = int(os.getenv("AE_EPOCHS", "10"))
AE_BATCH = int(os.getenv("AE_BATCH", "16"))

# Cache model
MODEL_CACHE_TTL_SEC = int(os.getenv("MODEL_CACHE_TTL_SEC", "300"))
CACHE_MAX_PIPELINES = int(os.getenv("CACHE_MAX_PIPELINES", "50"))

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("safeops-anomaly")

# FastAPI app
app = FastAPI(title="AnomalyDetector", version="2.0.0")


# =========================
# 4) FEATURES (DATA MINING)
# =========================
# IMPORTANT: ordre fixe = même ordre en train/predict
FEATURES_ORDER = [
    "duration_sec",
    "error_count",
    "secrets_count",
    "urls_count",
    "bypass_count",
    "steps_count",
    "severity_score",
]


# =========================
# 5) GLOBALS (POOL + CACHE)
# =========================
PG_POOL: Optional[SimpleConnectionPool] = None

# Cache: pipeline_id -> (trained_at, iso_model, iso_scaler, ae_model, ae_scaler, iso_stats)
MODEL_CACHE: Dict[str, Tuple[float, Any, Any, Any, Any, Dict[str, float]]] = {}


# =========================
# 6) UTILS
# =========================
def now_utc() -> datetime:
    """Retourne l'heure UTC (cohérente pour DB/logs)."""
    return datetime.now(timezone.utc)

def clamp01(x: float) -> float:
    """Clamp score dans [0..1]"""
    return float(np.clip(x, 0.0, 1.0))


# =========================
# 7) DB : POOL + DECORATOR
# =========================
def init_pool() -> None:
    """
    Initialise un pool Postgres avec retry.
    Utile en docker: postgres peut démarrer après MS5.
    """
    global PG_POOL
    if PG_POOL is not None:
        return

    last_err = None
    for _ in range(30):  # 30 tentatives (1 sec) ~ 30 sec max
        try:
            PG_POOL = SimpleConnectionPool(
                minconn=1,
                maxconn=10,
                host=PG_HOST,
                port=PG_PORT,
                dbname=PG_DB,
                user=PG_USER,
                password=PG_PASS,
                connect_timeout=3,
            )
            logger.info("✅ PostgreSQL pool created")
            return
        except Exception as e:
            last_err = e
            time.sleep(1)

    raise RuntimeError(f"PostgreSQL pool not ready: {last_err}")


def with_conn(fn):
    """
    Décorateur DB pro:
    - prend une connexion du pool
    - exécute la fonction
    - commit/rollback
    - remet la connexion dans le pool
    """
    def wrapper(*args, **kwargs):
        if PG_POOL is None:
            init_pool()

        conn = None
        try:
            conn = PG_POOL.getconn()
            conn.autocommit = False
            result = fn(conn, *args, **kwargs)
            conn.commit()
            return result
        except Exception:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn and PG_POOL:
                PG_POOL.putconn(conn)

    return wrapper


@with_conn
def db_health(conn) -> bool:
    """Healthcheck DB simple."""
    cur = conn.cursor()
    cur.execute("SELECT 1")
    cur.fetchone()
    return True


# =========================
# 8) DB INIT (SAFE)
# =========================
@with_conn
def init_db(conn) -> None:
    """
    Init DB robuste:
    - TimescaleDB optionnel (ne casse pas si absent)
    - Vérifie l'existence de pipeline_runs (doit exister!)
    - Crée anomaly_reports (owned par MS5)
    - Index pour performance
    """
    cur = conn.cursor()

    # --- helper SQL optionnel avec SAVEPOINT ---
    def optional_sql(sql: str, label: str) -> None:
        cur.execute("SAVEPOINT sp_optional;")
        try:
            cur.execute(sql)
            cur.execute("RELEASE SAVEPOINT sp_optional;")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT sp_optional;")
            cur.execute("RELEASE SAVEPOINT sp_optional;")
            logger.warning(f"⚠️ {label} skipped: {e}")

    optional_sql("CREATE EXTENSION IF NOT EXISTS timescaledb;", "Timescale extension")

    # ✅ pipeline_runs doit exister (créé par LogCollector/migrations)
    cur.execute("""
        SELECT 1 FROM information_schema.tables
        WHERE table_schema='public' AND table_name='pipeline_runs'
    """)
    if cur.fetchone() is None:
        raise RuntimeError("pipeline_runs missing. Start LogCollector/migrations first.")

    # ✅ Table outputs ML (MS5)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS anomaly_reports (
            id SERIAL PRIMARY KEY,
            ts TIMESTAMPTZ NOT NULL DEFAULT now(),
            pipeline_id TEXT NOT NULL,
            run_id TEXT NULL,
            job_id TEXT NULL,
            model_used TEXT NULL,
            anomaly_score DOUBLE PRECISION NULL,
            is_anomaly BOOLEAN NOT NULL DEFAULT false,
            details JSONB NOT NULL DEFAULT '{}'::jsonb
        );
    """)

    optional_sql(
        "SELECT create_hypertable('anomaly_reports','ts', if_not_exists=>TRUE);",
        "create_hypertable(anomaly_reports)"
    )

    # Index
    cur.execute("CREATE INDEX IF NOT EXISTS idx_runs_pipeline_ts ON pipeline_runs(pipeline_id, ts DESC);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_anom_pipeline_ts ON anomaly_reports(pipeline_id, ts DESC);")

    logger.info("✅ DB ready: pipeline_runs ok, anomaly_reports ok")


# =========================
# 9) INPUT SCHEMA (API)
# =========================
class AnomalyInput(BaseModel):
    """
    Payload /anomaly
    - accepte pipelineId (frontend) OU pipeline_id (backend)
    - champs features: remplacent le parsing logs -> déjà agrégés
    """
    model_config = ConfigDict(populate_by_name=True)

    pipeline_id: str = Field(..., alias="pipelineId")
    run_id: Optional[str] = Field(default=None, alias="runId")
    job_id: Optional[str] = Field(default=None, alias="jobId")

    duration_sec: Optional[float] = None
    severity_score: Optional[int] = 0

    error_count: int = Field(default=0, validation_alias=AliasChoices("error_count", "errors_count"))
    secrets_count: int = 0
    urls_count: int = 0
    bypass_count: int = 0
    steps_count: int = 0

    meta: Optional[Dict[str, Any]] = None


def to_feature_vector(item: AnomalyInput) -> np.ndarray:
    """
    DATA MINING:
    Convertit JSON -> vecteur numérique (7 features).
    None -> 0 (robuste).
    """
    d = item.model_dump(by_alias=False)
    vec = [float(d.get(k) or 0) for k in FEATURES_ORDER]
    return np.array(vec, dtype=np.float32)


# =========================
# 10) DB CRUD (HISTORY + SAVE)
# =========================
@with_conn
def fetch_history(conn, pipeline_id: str, limit: int = 500) -> np.ndarray:
    """
    Lit l'historique dans pipeline_runs et construit X (N x 7)
    """
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT duration_sec, error_count, secrets_count, urls_count, bypass_count, steps_count, severity_score
        FROM pipeline_runs
        WHERE pipeline_id=%s
        ORDER BY ts DESC
        LIMIT %s
        """,
        (pipeline_id, limit),
    )
    rows = cur.fetchall() or []
    if not rows:
        return np.zeros((0, len(FEATURES_ORDER)), dtype=np.float32)

    X = [[float(r.get(k) or 0) for k in FEATURES_ORDER] for r in rows]
    return np.array(X, dtype=np.float32)


@with_conn
def save_report(conn, item: AnomalyInput, model_used: str, score: float, is_anomaly: bool, details: Dict[str, Any]) -> None:
    """
    Sauvegarde la décision dans anomaly_reports.
    details contient une explication (audit + soutenance).
    """
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO anomaly_reports(ts, pipeline_id, run_id, job_id, model_used, anomaly_score, is_anomaly, details)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        """,
        (
            now_utc(),
            item.pipeline_id,
            item.run_id,
            item.job_id,
            model_used,
            float(score),
            bool(is_anomaly),
            json.dumps(details or {}, ensure_ascii=False),
        ),
    )


@with_conn
def list_reports(conn, pipeline_id: Optional[str], limit: int):
    """Liste les derniers rapports."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if pipeline_id:
        cur.execute("""
            SELECT id, ts, pipeline_id, run_id, job_id, model_used, anomaly_score, is_anomaly, details
            FROM anomaly_reports
            WHERE pipeline_id=%s
            ORDER BY ts DESC
            LIMIT %s
        """, (pipeline_id, limit))
    else:
        cur.execute("""
            SELECT id, ts, pipeline_id, run_id, job_id, model_used, anomaly_score, is_anomaly, details
            FROM anomaly_reports
            ORDER BY ts DESC
            LIMIT %s
        """, (limit,))
    return cur.fetchall()


# =========================
# 11) ML : ISOLATION FOREST
# =========================
def train_isolation_forest(X: np.ndarray):
    """
    MACHINE LEARNING (non supervisé):
    - StandardScaler: normalise les features
    - IsolationForest: apprend la normalité et isole les outliers
    """
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=ISO_CONTAMINATION,
        random_state=42,
    )
    model.fit(Xs)

    # On sauvegarde min/max des decision_function pour normaliser score 0..1
    df = model.decision_function(Xs)  # plus grand = plus normal
    stats = {"min": float(np.min(df)), "max": float(np.max(df))}
    return model, scaler, stats


# =========================
# 12) DL : AUTOENCODER (OPTIONNEL)
# =========================
def build_autoencoder(input_dim: int):
    """AutoEncoder Dense simple (Deep Learning)."""
    inp = keras.Input(shape=(input_dim,))
    x = keras.layers.Dense(16, activation="relu")(inp)
    x = keras.layers.Dense(8, activation="relu")(x)
    x = keras.layers.Dense(16, activation="relu")(x)
    out = keras.layers.Dense(input_dim, activation="linear")(x)
    ae = keras.Model(inp, out)
    ae.compile(optimizer="adam", loss="mse")
    return ae


def train_autoencoder(X: np.ndarray):
    """
    Entraîne l'AutoEncoder sur les runs historiques (supposés normaux).
    """
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    ae = build_autoencoder(Xs.shape[1])
    ae.fit(Xs, Xs, epochs=AE_EPOCHS, batch_size=AE_BATCH, verbose=0)
    return ae, scaler


def ae_errors(ae, scaler, X: np.ndarray) -> np.ndarray:
    """
    Calcule l'erreur de reconstruction MSE par ligne (vectorisé).
    """
    Xs = scaler.transform(X)
    recon = ae.predict(Xs, verbose=0)
    return np.mean((Xs - recon) ** 2, axis=1).astype(np.float64)


# =========================
# 13) CACHE MODELS
# =========================
def cache_gc() -> None:
    """Nettoie le cache: TTL + limite de pipelines."""
    now = time.time()

    # Eviction TTL
    expired = [pid for pid, (t, *_rest) in MODEL_CACHE.items() if (now - t) > MODEL_CACHE_TTL_SEC]
    for pid in expired:
        MODEL_CACHE.pop(pid, None)

    # Limite max pipelines
    if len(MODEL_CACHE) > CACHE_MAX_PIPELINES:
        ordered = sorted(MODEL_CACHE.items(), key=lambda kv: kv[1][0])  # oldest first
        for pid, _ in ordered[: len(MODEL_CACHE) - CACHE_MAX_PIPELINES]:
            MODEL_CACHE.pop(pid, None)


def get_or_train_models(pipeline_id: str, X_hist: np.ndarray):
    """
    Retourne modèles depuis cache si possible.
    Sinon: train IF (+ AE si activé).
    """
    cache_gc()
    now = time.time()

    # Cache hit
    if pipeline_id in MODEL_CACHE:
        trained_at, iso_model, iso_scaler, ae_model, ae_scaler, iso_stats = MODEL_CACHE[pipeline_id]
        if (now - trained_at) <= MODEL_CACHE_TTL_SEC:
            return iso_model, iso_scaler, ae_model, ae_scaler, iso_stats, True

    # Cache miss
    iso_model, iso_scaler, iso_stats = train_isolation_forest(X_hist)

    ae_model, ae_scaler = (None, None)
    if TF_ENABLED and keras is not None:
        ae_model, ae_scaler = train_autoencoder(X_hist)

    MODEL_CACHE[pipeline_id] = (now, iso_model, iso_scaler, ae_model, ae_scaler, iso_stats)
    return iso_model, iso_scaler, ae_model, ae_scaler, iso_stats, False


# =========================
# 14) API STARTUP
# =========================
@app.on_event("startup")
def on_startup():
    """Init pool + DB."""
    init_pool()
    init_db()
    logger.info("✅ AnomalyDetector ready")


# =========================
# 15) API ENDPOINTS
# =========================
@app.get("/")
def root():
    """Info service."""
    return {"message": "AnomalyDetector is running", "version": app.version}


@app.get("/health")
def health():
    """Healthcheck complet."""
    try:
        ok = db_health()
        return {
            "status": "ok" if ok else "degraded",
            "db": "ok" if ok else "down",
            "tf_enabled": TF_ENABLED,
            "cache_size": len(MODEL_CACHE),
            "time_utc": now_utc().isoformat(),
            "version": app.version,
        }
    except Exception as e:
        return {
            "status": "degraded",
            "db": "down",
            "tf_enabled": TF_ENABLED,
            "cache_size": len(MODEL_CACHE),
            "error": str(e),
            "time_utc": now_utc().isoformat(),
            "version": app.version,
        }


@app.post("/reset-cache")
def reset_cache():
    """Vide le cache."""
    MODEL_CACHE.clear()
    return {"message": "cache cleared", "cache_size": 0}


@app.post("/train")
def warmup_train(pipelineId: str):
    """
    Warmup training:
    - charge historique
    - entraîne et met en cache
    """
    X_hist = fetch_history(pipelineId, limit=500)
    if X_hist.shape[0] < MIN_HISTORY:
        return {"message": "Not enough history", "history_points": int(X_hist.shape[0]), "min_history": MIN_HISTORY}

    _iso_model, _iso_scaler, _ae_model, _ae_scaler, _stats, reused = get_or_train_models(pipelineId, X_hist)
    return {
        "message": "Models ready",
        "pipeline_id": pipelineId,
        "history_points": int(X_hist.shape[0]),
        "cache_reused": bool(reused),
        "tf_enabled": TF_ENABLED,
    }


@app.post("/anomaly")
def detect_anomaly(item: AnomalyInput):
    """
    ✅ ENDPOINT PRINCIPAL
    1) récupère historique X_hist
    2) construit le vecteur x (run courant)
    3) si pas assez d'historique -> fallback rules
    4) sinon -> IsolationForest (+ AutoEncoder optionnel)
    5) sauvegarde + retourne une réponse explicable
    """
    try:
        X_hist = fetch_history(item.pipeline_id, limit=500)
        x = to_feature_vector(item)  # shape (7,)

        # ---------------------------------------------------------
        # A) FALLBACK (baseline rules) si historique insuffisant
        # ---------------------------------------------------------
        if X_hist.shape[0] < MIN_HISTORY:
            reasons = []
            if item.secrets_count > 0:
                reasons.append("secrets_count>0")
            if item.bypass_count > 0:
                reasons.append("bypass_count>0")
            if item.error_count >= 3:
                reasons.append("error_count>=3")
            if (item.severity_score or 0) >= 80:
                reasons.append("severity_score>=80")
            if (item.duration_sec or 0) >= 600:
                reasons.append("duration_sec>=600")

            is_anom = len(reasons) > 0
            score = 1.0 if is_anom else 0.0

            details = {
                "mode": "fallback",
                "history_points": int(X_hist.shape[0]),
                "reasons": reasons,
                "features_order": FEATURES_ORDER,
                "x": [float(v) for v in x.tolist()],
            }

            save_report(item, "fallback", score, is_anom, details)
            return {
                "pipeline_id": item.pipeline_id,
                "run_id": item.run_id,
                "job_id": item.job_id,
                "model_used": "fallback",
                "anomaly_score": score,
                "is_anomaly": is_anom,
                "details": details,
            }

        # ---------------------------------------------------------
        # B) ML (IsolationForest) + DL (AutoEncoder optionnel)
        # ---------------------------------------------------------
        iso_model, iso_scaler, ae_model, ae_scaler, iso_stats, reused = get_or_train_models(item.pipeline_id, X_hist)

        # --- IsolationForest ---
        xs = iso_scaler.transform(x.reshape(1, -1))
        iso_df = float(iso_model.decision_function(xs)[0])  # normalité (haut = normal)
        iso_pred = int(iso_model.predict(xs)[0])            # -1 anomalie, +1 normal

        iso_is_anom = (iso_pred == -1)

        # Normaliser df en [0..1] (1=très anormal)
        mn, mx = iso_stats["min"], iso_stats["max"]
        iso_score = 1.0 - ((iso_df - mn) / (mx - mn + 1e-9))
        iso_score = clamp01(iso_score)

        # --- AutoEncoder optionnel ---
        ae_err = None
        ae_score = 0.0
        ae_is_anom = False
        thr = None

        if TF_ENABLED and ae_model is not None and ae_scaler is not None:
            # threshold sur erreurs historiques (p90)
            sample = X_hist[: min(200, X_hist.shape[0])]
            hist_errs = ae_errors(ae_model, ae_scaler, sample)
            thr = float(np.percentile(hist_errs, 90))

            ae_err = float(ae_errors(ae_model, ae_scaler, x.reshape(1, -1))[0])
            ae_is_anom = ae_err > thr
            ae_score = clamp01(ae_err / (thr + 1e-9))

        # --- Fusion score ---
        if TF_ENABLED and ae_err is not None:
            combined_score = clamp01((iso_score * 0.6) + (ae_score * 0.4))
            is_anomaly = bool(iso_is_anom or ae_is_anom or combined_score > 0.7)
            model_used = "IF+AE"
        else:
            combined_score = iso_score
            is_anomaly = bool(iso_is_anom or combined_score > 0.7)
            model_used = "IF"

        details = {
            "mode": "ml",
            "history_points": int(X_hist.shape[0]),
            "cache_reused": bool(reused),
            "features_order": FEATURES_ORDER,
            "x": [float(v) for v in x.tolist()],
            "isolation_forest": {
                "decision_function": iso_df,
                "norm_stats": {"min": mn, "max": mx},
                "anomaly_score": iso_score,
                "is_anomaly": iso_is_anom,
                "rule": "anomaly if (predict=-1) OR (score>0.7)",
            },
            "autoencoder": None if ae_err is None else {
                "reconstruction_error": ae_err,
                "threshold_p90": thr,
                "anomaly_score": ae_score,
                "is_anomaly": ae_is_anom,
                "rule": "anomaly if reconstruction_error > p90(history)",
            },
            "combined": {
                "score": combined_score,
                "decision_rule": "anomaly if IF or AE triggers, or combined_score>0.7",
            },
        }

        save_report(item, model_used, combined_score, is_anomaly, details)

        return {
            "pipeline_id": item.pipeline_id,
            "run_id": item.run_id,
            "job_id": item.job_id,
            "model_used": model_used,
            "anomaly_score": combined_score,
            "is_anomaly": is_anomaly,
            "details": details,
        }

    except Exception as e:
        logger.exception("❌ anomaly detection failed")
        raise HTTPException(status_code=500, detail=f"Error detecting anomaly: {str(e)}")


@app.get("/reports")
def reports(
    pipelineId: Optional[str] = None,
    pipeline_id: Optional[str] = None,
    limit: int = Query(20, ge=1, le=200),
):
    """
    Retourne les derniers reports (pour dashboard / audit).
    """
    try:
        pid = pipelineId or pipeline_id
        return list_reports(pid, limit)
    except Exception as e:
        logger.exception("❌ reports fetch failed")
        raise HTTPException(status_code=500, detail=f"Error fetching reports: {str(e)}")
