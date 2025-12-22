from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from datetime import datetime
from typing import Optional, Dict, Any, List
import os
import time
import json

import psycopg2
import psycopg2.extras

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import tensorflow as tf
from tensorflow import keras


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
MIN_HISTORY = int(os.getenv("MIN_HISTORY", "10"))   # mets 10 pour tester vite, 30 pour soutenance
AE_EPOCHS = int(os.getenv("AE_EPOCHS", "10"))
AE_BATCH = int(os.getenv("AE_BATCH", "16"))

app = FastAPI(title="AnomalyDetector", version="1.1.0")

_conn = None


def get_conn():
    global _conn
    if _conn and _conn.closed == 0:
        return _conn

    last_err = None
    for _ in range(25):
        try:
            _conn = psycopg2.connect(
                host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS
            )
            _conn.autocommit = False
            return _conn
        except Exception as e:
            last_err = e
            time.sleep(1)

    raise RuntimeError(f"PostgreSQL/TimescaleDB not ready: {last_err}")


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("CREATE EXTENSION IF NOT EXISTS timescaledb;")

    # Historique runs (Timescale hypertable)
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
    cur.execute("SELECT create_hypertable('pipeline_runs', 'ts', if_not_exists => TRUE);")

    # Rapports anomalies
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

    conn.commit()


@app.on_event("startup")
def on_startup():
    init_db()


# ======================================================
# 2) INPUT SCHEMA (ACCEPTE pipelineId OU pipeline_id)
# ======================================================
class AnomalyInput(BaseModel):
    # aliases: accepte pipelineId/pipeline_id, etc.
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


def to_feature_vector(item: AnomalyInput) -> np.ndarray:
    d = item.model_dump(by_alias=False)
    vec = []
    for k in FEATURES_ORDER:
        v = d.get(k, 0)
        if v is None:
            v = 0
        vec.append(float(v))
    return np.array(vec, dtype=np.float32)


def fetch_history(pipeline_id: str, limit: int = 500) -> np.ndarray:
    conn = get_conn()
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


# ======================================================
# 3) ML
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


# ======================================================
# 4) DB HELPERS
# ======================================================
def save_run(item: AnomalyInput):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO pipeline_runs
        (ts, pipeline_id, run_id, job_id, source, status, duration_sec, error_count, secrets_count, urls_count, bypass_count, steps_count, severity_score, meta)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        datetime.utcnow(),
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
    conn.commit()


def save_report(item: AnomalyInput, model_used: str, score: float, is_anomaly: bool, details: Dict[str, Any]):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO anomaly_reports
        (ts, pipeline_id, run_id, job_id, model_used, anomaly_score, is_anomaly, details)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        datetime.utcnow(),
        item.pipeline_id,
        item.run_id,
        item.job_id,
        model_used,
        float(score),
        bool(is_anomaly),
        json.dumps(details or {})
    ))
    conn.commit()


# ======================================================
# 5) API
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
    return {"message": "AnomalyDetector is running"}


@app.post("/anomaly")
def anomaly(item: AnomalyInput):
    try:
        save_run(item)

        X_hist = fetch_history(item.pipeline_id, limit=500)
        x = to_feature_vector(item)

        # fallback si pas assez d'historique
        if X_hist.shape[0] < MIN_HISTORY:
            is_anom = (item.secrets_count > 0) or (item.bypass_count > 0) or (item.error_count > 3)
            score = 1.0 if is_anom else 0.0
            details = {
                "mode": "fallback",
                "history_points": int(X_hist.shape[0]),
                "reason": "Not enough history to train models"
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

        iso_model, iso_scaler = train_isolation_forest(X_hist)
        ae_model, ae_scaler = train_autoencoder(X_hist)

        xs = iso_scaler.transform(x.reshape(1, -1))
        iso_normality = float(iso_model.decision_function(xs)[0])
        iso_pred = int(iso_model.predict(xs)[0])  # -1 anomaly, 1 normal
        iso_is_anom = (iso_pred == -1)
        iso_score = float(max(0.0, min(1.0, -iso_normality)))

        ae_err = ae_reconstruction_error(ae_model, ae_scaler, x)

        hist_errs = []
        for i in range(min(X_hist.shape[0], 200)):
            hist_errs.append(ae_reconstruction_error(ae_model, ae_scaler, X_hist[i]))
        thr = float(np.percentile(hist_errs, 90))

        ae_is_anom = ae_err > thr
        ae_score = float(min(1.0, ae_err / (thr + 1e-9)))

        combined_score = float(min(1.0, (iso_score * 0.6) + (ae_score * 0.4)))
        is_anomaly = bool(iso_is_anom or ae_is_anom or combined_score > 0.7)

        details = {
            "mode": "ml",
            "history_points": int(X_hist.shape[0]),
            "features_order": FEATURES_ORDER,
            "x": [float(v) for v in x.tolist()],
            "isolation_forest": {
                "normality": iso_normality,
                "anomaly_score": iso_score,
                "is_anomaly": iso_is_anom
            },
            "autoencoder": {
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

        save_report(item, "IF+AE", combined_score, is_anomaly, details)

        return {
            "pipeline_id": item.pipeline_id,
            "run_id": item.run_id,
            "job_id": item.job_id,
            "model_used": "IF+AE",
            "anomaly_score": combined_score,
            "is_anomaly": is_anomaly,
            "details": details
        }

    except Exception as e:
        print("Anomaly error:", e)
        raise HTTPException(status_code=500, detail="Error while detecting anomaly")


@app.get("/reports")
def reports(pipelineId: Optional[str] = None, pipeline_id: Optional[str] = None, limit: int = Query(20, ge=1, le=200)):
    """
    Support query pipelineId OU pipeline_id.
    """
    try:
        pid = pipelineId or pipeline_id

        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        if pid:
            cur.execute("""
                SELECT id, ts, pipeline_id, run_id, job_id, model_used, anomaly_score, is_anomaly, details
                FROM anomaly_reports
                WHERE pipeline_id=%s
                ORDER BY ts DESC
                LIMIT %s
            """, (pid, limit))
        else:
            cur.execute("""
                SELECT id, ts, pipeline_id, run_id, job_id, model_used, anomaly_score, is_anomaly, details
                FROM anomaly_reports
                ORDER BY ts DESC
                LIMIT %s
            """, (limit,))
        return cur.fetchall()

    except Exception as e:
        print("Reports error:", e)
        raise HTTPException(status_code=500, detail="Error while fetching reports")
