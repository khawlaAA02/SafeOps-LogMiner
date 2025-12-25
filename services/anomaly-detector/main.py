from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
import os
import time
import json
import logging

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

# TensorFlow (optionnel)
TF_ENABLED = os.getenv("TF_ENABLED", "true").lower() in ("1", "true", "yes", "y")
try:
    if TF_ENABLED:
        import tensorflow as tf  # noqa
        from tensorflow import keras
    else:
        keras = None
except Exception:
    TF_ENABLED = False
    keras = None

# ======================================================
# 1) CONFIG / ENV
# ======================================================
load_dotenv()

PORT = int(os.getenv("PORT", "3005"))

PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB   = os.getenv("POSTGRES_DB", "safeops_security")
PG_USER = os.getenv("POSTGRES_USER", "safeops")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "safeops")

ISO_CONTAMINATION = float(os.getenv("ISO_CONTAMINATION", "0.05"))
MIN_HISTORY = int(os.getenv("MIN_HISTORY", "10"))   # 10 pour tester, 30+ en soutenance
AE_EPOCHS = int(os.getenv("AE_EPOCHS", "10"))
AE_BATCH = int(os.getenv("AE_BATCH", "16"))

# Cache modèles
MODEL_CACHE_TTL_SEC = int(os.getenv("MODEL_CACHE_TTL_SEC", "300"))  # 5 min
CACHE_MAX_PIPELINES = int(os.getenv("CACHE_MAX_PIPELINES", "50"))

logger = logging.getLogger("safeops-anomaly")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s"
)

app = FastAPI(title="AnomalyDetector", version="1.2.0")

# Pool PostgreSQL
PG_POOL: Optional[SimpleConnectionPool] = None

# Cache des modèles: pipeline_id -> (trained_at_epoch, iso_model, iso_scaler, ae_model, ae_scaler)
MODEL_CACHE: Dict[str, Tuple[float, Any, Any, Any, Any]] = {}


# ======================================================
# 2) DB HELPERS
# ======================================================
def init_pool():
    global PG_POOL
    if PG_POOL is not None:
        return

    last_err = None
    for _ in range(30):
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
            logger.info("PostgreSQL pool created")
            return
        except Exception as e:
            last_err = e
            time.sleep(1)

    raise RuntimeError(f"PostgreSQL pool not ready: {last_err}")


def with_conn(fn):
    """
    Décorateur simple pour gérer getconn/putconn + commit/rollback.
    """
    def wrapper(*args, **kwargs):
        if PG_POOL is None:
            init_pool()
        conn = None
        try:
            conn = PG_POOL.getconn()
            conn.autocommit = False
            res = fn(conn, *args, **kwargs)
            conn.commit()
            return res
        except Exception:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn and PG_POOL:
                PG_POOL.putconn(conn)
    return wrapper


@with_conn
def init_db(conn):
    cur = conn.cursor()

    # Timescale extension (si dispo). Si pas dispo, on continue sans bloquer.
    try:
        cur.execute("CREATE EXTENSION IF NOT EXISTS timescaledb;")
    except Exception as e:
        logger.warning(f"Timescale extension not enabled (continuing): {e}")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pipeline_runs (
        ts TIMESTAMPTZ NOT NULL,
        pipeline_id TEXT NOT NULL,
        run_id TEXT,
        job_id TEXT,
        source TEXT,
        status TEXT,
        duration_sec DOUBLE PRECISION,
        error_count INT,
        secrets_count INT,
        urls_count INT,
        bypass_count INT,
        steps_count INT,
        severity_score INT,
        meta JSONB
    );
    """)

    # Hypertable (si timescale dispo)
    try:
        cur.execute("SELECT create_hypertable('pipeline_runs', 'ts', if_not_exists => TRUE);")
    except Exception:
        # pas grave si pas Timescale
        pass

    cur.execute("""
    CREATE TABLE IF NOT EXISTS anomaly_reports (
        id SERIAL PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL,
        pipeline_id TEXT NOT NULL,
        run_id TEXT,
        job_id TEXT,
        model_used TEXT,
        anomaly_score DOUBLE PRECISION,
        is_anomaly BOOLEAN,
        details JSONB
    );
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_runs_pipeline_ts ON pipeline_runs(pipeline_id, ts DESC);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_anom_pipeline_ts ON anomaly_reports(pipeline_id, ts DESC);")

    logger.info("DB initialized")


@with_conn
def db_health(conn) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT 1")
    cur.fetchone()
    return True


# ======================================================
# 3) INPUT SCHEMA
# ======================================================
class AnomalyInput(BaseModel):
    pipeline_id: str = Field(..., alias="pipelineId")
    run_id: Optional[str] = Field(default=None, alias="runId")
    job_id: Optional[str] = Field(default=None, alias="jobId")

    source: Optional[str] = None
    status: Optional[str] = None

    duration_sec: Optional[float] = None
    severity_score: Optional[int] = 0

    # accepte error_count OU errors_count
    error_count: int = Field(default=0, alias="errors_count")

    secrets_count: int = 0
    urls_count: int = 0
    bypass_count: int = 0
    steps_count: int = 0

    meta: Optional[Dict[str, Any]] = None

    class Config:
        populate_by_name = True  # permet d'envoyer pipeline_id aussi


FEATURES_ORDER = [
    "duration_sec",
    "error_count",
    "secrets_count",
    "urls_count",
    "bypass_count",
    "steps_count",
    "severity_score",
]


def now_utc():
    return datetime.now(timezone.utc)


def to_feature_vector(item: AnomalyInput) -> np.ndarray:
    d = item.model_dump(by_alias=False)
    vec = []
    for k in FEATURES_ORDER:
        v = d.get(k, 0)
        if v is None:
            v = 0
        vec.append(float(v))
    return np.array(vec, dtype=np.float32)


@with_conn
def save_run(conn, item: AnomalyInput):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO pipeline_runs
        (ts, pipeline_id, run_id, job_id, source, status, duration_sec, error_count,
         secrets_count, urls_count, bypass_count, steps_count, severity_score, meta)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        now_utc(),
        item.pipeline_id,
        item.run_id,
        item.job_id,
        item.source,
        item.status,
        item.duration_sec,
        item.error_count,
        item.secrets_count,
        item.urls_count,
        item.bypass_count,
        item.steps_count,
        item.severity_score,
        json.dumps(item.meta or {})
    ))


@with_conn
def save_report(conn, item: AnomalyInput, model_used: str, score: float, is_anomaly: bool, details: Dict[str, Any]):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO anomaly_reports
        (ts, pipeline_id, run_id, job_id, model_used, anomaly_score, is_anomaly, details)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        now_utc(),
        item.pipeline_id,
        item.run_id,
        item.job_id,
        model_used,
        float(score),
        bool(is_anomaly),
        json.dumps(details or {})
    ))


@with_conn
def fetch_history(conn, pipeline_id: str, limit: int = 500) -> np.ndarray:
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT duration_sec, error_count, secrets_count, urls_count, bypass_count, steps_count, severity_score
        FROM pipeline_runs
        WHERE pipeline_id = %s
        ORDER BY ts DESC
        LIMIT %s
    """, (pipeline_id, limit))
    rows = cur.fetchall()

    if not rows:
        return np.zeros((0, len(FEATURES_ORDER)), dtype=np.float32)

    X = []
    for r in rows:
        X.append([float(r.get(k) or 0) for k in FEATURES_ORDER])
    return np.array(X, dtype=np.float32)


@with_conn
def count_stats(conn, pipeline_id: Optional[str] = None) -> Dict[str, int]:
    cur = conn.cursor()
    if pipeline_id:
        cur.execute("SELECT COUNT(*) FROM pipeline_runs WHERE pipeline_id=%s", (pipeline_id,))
        runs = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM anomaly_reports WHERE pipeline_id=%s AND is_anomaly=true", (pipeline_id,))
        anoms = cur.fetchone()[0]
    else:
        cur.execute("SELECT COUNT(*) FROM pipeline_runs")
        runs = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM anomaly_reports WHERE is_anomaly=true")
        anoms = cur.fetchone()[0]
    return {"runs_count": int(runs), "anomalies_count": int(anoms)}


@with_conn
def list_reports(conn, pipeline_id: Optional[str], limit: int):
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


# ======================================================
# 4) ML
# ======================================================
def train_isolation_forest(X: np.ndarray):
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=ISO_CONTAMINATION,
        random_state=42,
    )
    model.fit(Xs)
    return model, scaler


def build_autoencoder(input_dim: int):
    inp = keras.Input(shape=(input_dim,))
    x = keras.layers.Dense(16, activation="relu")(inp)
    x = keras.layers.Dense(8, activation="relu")(x)
    x = keras.layers.Dense(16, activation="relu")(x)
    out = keras.layers.Dense(input_dim, activation="linear")(x)
    ae = keras.Model(inp, out)
    ae.compile(optimizer="adam", loss="mse")
    return ae


def train_autoencoder(X: np.ndarray):
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    ae = build_autoencoder(Xs.shape[1])
    ae.fit(Xs, Xs, epochs=AE_EPOCHS, batch_size=AE_BATCH, verbose=0)
    return ae, scaler


def ae_reconstruction_error(ae, scaler, x: np.ndarray) -> float:
    xs = scaler.transform(x.reshape(1, -1))
    recon = ae.predict(xs, verbose=0)
    return float(np.mean((xs - recon) ** 2))


def cache_gc():
    """
    Nettoie le cache: TTL + limite max pipelines.
    """
    now = time.time()
    # TTL
    to_del = [pid for pid, (t, *_rest) in MODEL_CACHE.items() if (now - t) > MODEL_CACHE_TTL_SEC]
    for pid in to_del:
        MODEL_CACHE.pop(pid, None)

    # limite max
    if len(MODEL_CACHE) > CACHE_MAX_PIPELINES:
        # retire les plus anciens
        ordered = sorted(MODEL_CACHE.items(), key=lambda kv: kv[1][0])  # by trained_at
        for pid, _ in ordered[: max(0, len(MODEL_CACHE) - CACHE_MAX_PIPELINES)]:
            MODEL_CACHE.pop(pid, None)


def get_or_train_models(pipeline_id: str, X_hist: np.ndarray):
    """
    Cache par pipeline. Evite le retrain complet à chaque requête.
    """
    cache_gc()
    now = time.time()

    if pipeline_id in MODEL_CACHE:
        trained_at, iso_model, iso_scaler, ae_model, ae_scaler = MODEL_CACHE[pipeline_id]
        # si encore valide => reuse
        if (now - trained_at) <= MODEL_CACHE_TTL_SEC:
            return iso_model, iso_scaler, ae_model, ae_scaler, True

    iso_model, iso_scaler = train_isolation_forest(X_hist)

    ae_model, ae_scaler = (None, None)
    if TF_ENABLED and keras is not None:
        ae_model, ae_scaler = train_autoencoder(X_hist)

    MODEL_CACHE[pipeline_id] = (now, iso_model, iso_scaler, ae_model, ae_scaler)
    return iso_model, iso_scaler, ae_model, ae_scaler, False


# ======================================================
# 5) API
# ======================================================
@app.on_event("startup")
def on_startup():
    init_pool()
    init_db()


@app.get("/health")
def health():
    try:
        ok = db_health()
        return {
            "status": "ok" if ok else "degraded",
            "tf_enabled": TF_ENABLED,
            "cache_pipelines": len(MODEL_CACHE),
        }
    except Exception as e:
        return {"status": "degraded", "error": str(e), "tf_enabled": TF_ENABLED, "cache_pipelines": len(MODEL_CACHE)}


@app.get("/")
def root():
    return {"message": "AnomalyDetector is running"}


@app.post("/reset-cache")
def reset_cache():
    MODEL_CACHE.clear()
    return {"message": "Model cache cleared"}


@app.get("/stats")
def stats(pipelineId: Optional[str] = None, pipeline_id: Optional[str] = None):
    pid = pipelineId or pipeline_id
    s = count_stats(pid)
    return {
        "pipeline_id": pid,
        **s,
        "min_history": MIN_HISTORY,
        "tf_enabled": TF_ENABLED,
        "cache_pipelines": list(MODEL_CACHE.keys())
    }


@app.post("/anomaly")
def anomaly(item: AnomalyInput):
    try:
        # 1) Sauver le run (historique)
        save_run(item)

        # 2) Fetch history
        X_hist = fetch_history(item.pipeline_id, limit=500)
        x = to_feature_vector(item)

        # 3) Fallback amélioré (si pas assez d'historique)
        if X_hist.shape[0] < MIN_HISTORY:
            # Heuristique plus “pro”
            is_anom = (
                (item.secrets_count > 0) or
                (item.bypass_count > 0) or
                (item.error_count >= 3) or
                ((item.severity_score or 0) >= 80) or
                ((item.duration_sec or 0) >= 600)  # 10 min+
            )
            score = 1.0 if is_anom else 0.0
            details = {
                "mode": "fallback",
                "history_points": int(X_hist.shape[0]),
                "reason": "Not enough history to train models",
                "rule": "anomaly if secrets>0 OR bypass>0 OR errors>=3 OR severity>=80 OR duration>=600"
            }
            save_report(item, "fallback", score, is_anom, details)
            return {
                "pipeline_id": item.pipeline_id,
                "run_id": item.run_id,
                "job_id": item.job_id,
                "model_used": "fallback",
                "anomaly_score": score,
                "is_anomaly": is_anom,
                "details": details
            }

        # 4) Train or reuse models from cache
        iso_model, iso_scaler, ae_model, ae_scaler, reused = get_or_train_models(item.pipeline_id, X_hist)

        # 5) IsolationForest
        xs = iso_scaler.transform(x.reshape(1, -1))
        iso_normality = float(iso_model.decision_function(xs)[0])
        iso_pred = int(iso_model.predict(xs)[0])  # -1 anomaly, 1 normal
        iso_is_anom = (iso_pred == -1)

        # convertir “normality” -> score [0..1]
        iso_score = float(max(0.0, min(1.0, -iso_normality)))

        # 6) AutoEncoder (si TF dispo)
        ae_is_anom = False
        ae_score = 0.0
        ae_err = None
        thr = None

        if TF_ENABLED and ae_model is not None and ae_scaler is not None:
            ae_err = ae_reconstruction_error(ae_model, ae_scaler, x)

            # threshold basé sur percentile des erreurs historiques (on prend 200 max)
            hist_errs = []
            for i in range(min(X_hist.shape[0], 200)):
                hist_errs.append(ae_reconstruction_error(ae_model, ae_scaler, X_hist[i]))
            thr = float(np.percentile(hist_errs, 90))

            ae_is_anom = (ae_err > thr)
            ae_score = float(min(1.0, ae_err / (thr + 1e-9)))

        # 7) Score combiné + décision
        if TF_ENABLED and ae_err is not None:
            combined_score = float(min(1.0, (iso_score * 0.6) + (ae_score * 0.4)))
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
                "normality": iso_normality,
                "anomaly_score": iso_score,
                "is_anomaly": iso_is_anom
            },
            "autoencoder": None if ae_err is None else {
                "reconstruction_error": ae_err,
                "threshold_p90": thr,
                "anomaly_score": ae_score,
                "is_anomaly": ae_is_anom
            },
            "combined": {
                "score": combined_score,
                "decision_rule": "anomaly if (IF anomaly) OR (AE anomaly) OR (combined_score>0.7)"
            }
        }

        save_report(item, model_used, combined_score, is_anomaly, details)

        return {
            "pipeline_id": item.pipeline_id,
            "run_id": item.run_id,
            "job_id": item.job_id,
            "model_used": model_used,
            "anomaly_score": combined_score,
            "is_anomaly": is_anomaly,
            "details": details
        }

    except Exception as e:
        logger.exception("Anomaly error")
        raise HTTPException(status_code=500, detail=f"Error while detecting anomaly: {str(e)}")


@app.get("/reports")
def reports(
    pipelineId: Optional[str] = None,
    pipeline_id: Optional[str] = None,
    limit: int = Query(20, ge=1, le=200)
):
    try:
        pid = pipelineId or pipeline_id
        return list_reports(pid, limit)
    except Exception as e:
        logger.exception("Reports error")
        raise HTTPException(status_code=500, detail=f"Error while fetching reports: {str(e)}")
@app.post("/train")
def train(pipelineId: str):
    X_hist = fetch_history(pipelineId, limit=500)
    if X_hist.shape[0] < MIN_HISTORY:
        return {"message": "Not enough history", "history_points": int(X_hist.shape[0])}

    iso_model, iso_scaler, ae_model, ae_scaler, reused = get_or_train_models(pipelineId, X_hist)
    return {
        "message": "Models ready",
        "pipeline_id": pipelineId,
        "history_points": int(X_hist.shape[0]),
        "cache_reused": reused,
        "tf_enabled": TF_ENABLED
    }
