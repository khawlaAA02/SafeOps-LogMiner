import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

import psycopg2
import psycopg2.extras

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest


# ======================================================
# CONFIG
# ======================================================
PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB   = os.getenv("POSTGRES_DB", "safeops_security")
PG_USER = os.getenv("POSTGRES_USER", "safeops")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "safeops")

MODEL_DIR = os.getenv("MODEL_DIR", "/app/models")
RISK_MODEL_PATH = os.path.join(MODEL_DIR, "risk_model.joblib")
ANOM_MODEL_PATH = os.path.join(MODEL_DIR, "anomaly_model.joblib")

MODEL_VERSION = os.getenv("MODEL_VERSION", "v1")

app = FastAPI(title="SafeOps ML Service (Risk + Anomaly)", version="1.0.0")


# ======================================================
# DB helpers
# ======================================================
def db_conn():
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS
    )


def wait_pg():
    last = None
    for _ in range(25):
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


# ======================================================
# DATA MINING: build dataset from Postgres
# ======================================================
def load_dataset(limit: int = 10000) -> pd.DataFrame:
    """
    Dataset construit depuis:
    - pipeline_runs (metrics globales)
    - vulnerabilities (agrégées par run)
    Objectif:
    - Classification (risk): y_risk
    - Anomaly detection: uniquement features num (comportement inhabituel)
    """
    with db_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                  ts,
                  pipeline_id,
                  run_id,
                  source,
                  status,
                  duration_sec,
                  error_count,
                  secrets_count,
                  urls_count,
                  bypass_count,
                  steps_count,
                  severity_score
                FROM pipeline_runs
                ORDER BY ts DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
            if not rows:
                return pd.DataFrame()
            df = pd.DataFrame(rows)

            # vuln aggregation by run_id (UUID in vulnerabilities)
            cur.execute(
                """
                SELECT
                  run_id::text AS run_id_text,
                  SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS v_critical,
                  SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END)     AS v_high,
                  SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END)   AS v_medium,
                  SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END)      AS v_low
                FROM vulnerabilities
                GROUP BY run_id::text
                """
            )
            vul = pd.DataFrame(cur.fetchall()) if cur.rowcount else pd.DataFrame()

    if not vul.empty:
        df = df.merge(vul, left_on="run_id", right_on="run_id_text", how="left")
        df.drop(columns=["run_id_text"], inplace=True, errors="ignore")
    else:
        df["v_critical"] = 0
        df["v_high"] = 0
        df["v_medium"] = 0
        df["v_low"] = 0

    for c in ["v_critical", "v_high", "v_medium", "v_low"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)

    # Label "réaliste" (heuristique) : ce n'est pas parfait, mais c'est pratique en PFE
    # - Risqué si secret leak, ou vuln critical, ou severity_score élevé
    df["y_risk"] = (
        (df["v_critical"] > 0)
        | (df["secrets_count"] > 0)
        | (df["severity_score"] >= 70)
    ).astype(int)

    return df


# ======================================================
# FEATURES
# ======================================================
NUM_COLS = [
    "duration_sec", "error_count", "secrets_count", "urls_count",
    "bypass_count", "steps_count", "severity_score",
    "v_critical", "v_high", "v_medium", "v_low"
]
CAT_COLS = ["source", "status", "pipeline_id"]


def prep(df: pd.DataFrame) -> pd.DataFrame:
    for c in NUM_COLS:
        df[c] = pd.to_numeric(df.get(c), errors="coerce").fillna(0)
    for c in CAT_COLS:
        df[c] = df.get(c).fillna("unknown").astype(str)
    return df


# ======================================================
# TRAIN - Risk model (classification)
# ======================================================
def train_risk(df: pd.DataFrame) -> Dict[str, Any]:
    df = prep(df)

    X = df[NUM_COLS + CAT_COLS]
    y = df["y_risk"].astype(int)

    pre = ColumnTransformer(
        transformers=[
            ("num", "passthrough", NUM_COLS),
            ("cat", OneHotEncoder(handle_unknown="ignore"), CAT_COLS),
        ]
    )

    clf = LogisticRegression(max_iter=250)

    pipe = Pipeline(steps=[("pre", pre), ("clf", clf)])

    # si dataset trop petit / 1 classe → pas de stratify
    strat = y if y.nunique() > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=strat
    )

    pipe.fit(X_train, y_train)

    y_pred = pipe.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    auc = None
    if y_test.nunique() > 1:
        try:
            y_proba = pipe.predict_proba(X_test)[:, 1]
            auc = roc_auc_score(y_test, y_proba)
        except Exception:
            auc = None

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({"model": pipe, "num_cols": NUM_COLS, "cat_cols": CAT_COLS}, RISK_MODEL_PATH)

    return {"risk_model_saved_to": RISK_MODEL_PATH, "risk_auc": auc, "risk_report": report}


# ======================================================
# TRAIN - Anomaly model (unsupervised)
# ======================================================
def train_anomaly(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Anomaly detection:
    - IsolationForest sur features numériques uniquement
    - Score = "anomaly_score" (plus grand => plus anormal)
    """
    df = prep(df)

    Xn = df[NUM_COLS].copy()
    # scaler pour stabiliser un peu (même si IsolationForest peut fonctionner sans)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(Xn)

    # contamination: % d'anomalies attendues (tu peux l'ajuster)
    iso = IsolationForest(
        n_estimators=200,
        random_state=42,
        contamination=0.10
    )
    iso.fit(Xs)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({"scaler": scaler, "model": iso, "num_cols": NUM_COLS}, ANOM_MODEL_PATH)

    return {"anomaly_model_saved_to": ANOM_MODEL_PATH, "contamination": 0.10}


def load_risk_model():
    if not os.path.exists(RISK_MODEL_PATH):
        raise FileNotFoundError("Risk model not trained. Call /train first.")
    blob = joblib.load(RISK_MODEL_PATH)
    return blob["model"], blob["num_cols"], blob["cat_cols"]


def load_anom_model():
    if not os.path.exists(ANOM_MODEL_PATH):
        raise FileNotFoundError("Anomaly model not trained. Call /train first.")
    blob = joblib.load(ANOM_MODEL_PATH)
    return blob["scaler"], blob["model"], blob["num_cols"]


# ======================================================
# API models
# ======================================================
class PredictRequest(BaseModel):
    run_id: Optional[str] = None   # si fourni, on peut lire Postgres (mode réel)
    pipeline_id: Optional[str] = "unknown"
    source: str = "unknown"
    status: str = "unknown"
    duration_sec: float = 0
    error_count: int = 0
    secrets_count: int = 0
    urls_count: int = 0
    bypass_count: int = 0
    steps_count: int = 0
    severity_score: int = 0
    v_critical: int = 0
    v_high: int = 0
    v_medium: int = 0
    v_low: int = 0


def fetch_run_features(run_id: str) -> Dict[str, Any]:
    """
    Mode "réel":
    On récupère automatiquement les features depuis Postgres pour un run_id donné.
    """
    with db_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT pipeline_id, source, status, duration_sec, error_count, secrets_count,
                       urls_count, bypass_count, steps_count, severity_score
                FROM pipeline_runs
                WHERE run_id = %s
                ORDER BY ts DESC
                LIMIT 1
                """,
                (run_id,),
            )
            r = cur.fetchone()
            if not r:
                raise ValueError("run_id not found in pipeline_runs")

            # vuln counts
            cur.execute(
                """
                SELECT
                  SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS v_critical,
                  SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END)     AS v_high,
                  SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END)   AS v_medium,
                  SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END)      AS v_low
                FROM vulnerabilities
                WHERE run_id = %s
                """,
                (run_id,),
            )
            v = cur.fetchone() or {}

    return {
        "pipeline_id": r.get("pipeline_id") or "unknown",
        "source": r.get("source") or "unknown",
        "status": r.get("status") or "unknown",
        "duration_sec": float(r.get("duration_sec") or 0),
        "error_count": int(r.get("error_count") or 0),
        "secrets_count": int(r.get("secrets_count") or 0),
        "urls_count": int(r.get("urls_count") or 0),
        "bypass_count": int(r.get("bypass_count") or 0),
        "steps_count": int(r.get("steps_count") or 0),
        "severity_score": int(r.get("severity_score") or 0),
        "v_critical": int(v.get("v_critical") or 0),
        "v_high": int(v.get("v_high") or 0),
        "v_medium": int(v.get("v_medium") or 0),
        "v_low": int(v.get("v_low") or 0),
    }


def upsert_score(run_id: str, pipeline_id: str, risk_proba: float, risk_label: str, anomaly_score: float, anomaly_label: str):
    """
    Stocke le résultat (utile dashboard/report).
    """
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ml_run_scores (run_id, pipeline_id, risk_proba, risk_label, anomaly_score, anomaly_label, model_version)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (run_id) DO UPDATE SET
                  pipeline_id=EXCLUDED.pipeline_id,
                  risk_proba=EXCLUDED.risk_proba,
                  risk_label=EXCLUDED.risk_label,
                  anomaly_score=EXCLUDED.anomaly_score,
                  anomaly_label=EXCLUDED.anomaly_label,
                  model_version=EXCLUDED.model_version,
                  created_at=now()
                """,
                (run_id, pipeline_id, risk_proba, risk_label, anomaly_score, anomaly_label, MODEL_VERSION),
            )
            conn.commit()


# ======================================================
# Routes
# ======================================================
@app.on_event("startup")
def startup():
    wait_pg()


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION}


@app.post("/train")
def train(limit: int = Query(10000, ge=50, le=50000)):
    """
    Entraîne les 2 modèles:
    - Risk classifier (LogisticRegression)
    - Anomaly detector (IsolationForest)
    """
    try:
        df = load_dataset(limit=limit)
        if df.empty:
            raise ValueError("No data in pipeline_runs. Ingest some runs first.")

        res_risk = train_risk(df)
        res_anom = train_anomaly(df)

        return {"ok": True, "rows": len(df), **res_risk, **res_anom}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict")
def predict(req: PredictRequest):
    """
    Prédit:
    - risk_proba / risk_label
    - anomaly_score / anomaly_label

    Deux modes:
    - Mode réel: fournir run_id => on récupère les features depuis Postgres
    - Mode manuel: fournir les champs directement
    """
    try:
        if req.run_id:
            feats = fetch_run_features(req.run_id)
            run_id = req.run_id
        else:
            feats = req.model_dump()
            run_id = None

        # Risk
        risk_model, num_cols, cat_cols = load_risk_model()
        row = {**{c: feats.get(c, 0) for c in num_cols}, **{c: feats.get(c, "unknown") for c in cat_cols}}
        X = pd.DataFrame([row])
        risk_proba = float(risk_model.predict_proba(X)[:, 1][0])
        risk_label = "high" if risk_proba >= 0.5 else "low"

        # Anomaly
        scaler, anom_model, an_num_cols = load_anom_model()
        Xn = pd.DataFrame([{c: float(feats.get(c, 0) or 0) for c in an_num_cols}])
        Xs = scaler.transform(Xn)
        # IsolationForest: score_samples (plus grand => plus normal)
        normal_score = float(anom_model.score_samples(Xs)[0])
        anomaly_score = float(-normal_score)  # plus grand => plus anormal

        # seuil simple (propre pour démo): au-dessus de 0.6 => anomaly
        anomaly_label = "anomaly" if anomaly_score >= 0.6 else "normal"

        # Stockage (si run_id présent)
        if run_id:
            upsert_score(
                run_id=run_id,
                pipeline_id=feats.get("pipeline_id", "unknown"),
                risk_proba=risk_proba,
                risk_label=risk_label,
                anomaly_score=anomaly_score,
                anomaly_label=anomaly_label
            )

        return {
            "run_id": run_id,
            "features": feats,
            "risk_proba": risk_proba,
            "risk_label": risk_label,
            "anomaly_score": anomaly_score,
            "anomaly_label": anomaly_label,
            "model_version": MODEL_VERSION
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scores/{run_id}")
def get_scores(run_id: str):
    """
    Lire les scores stockés (pour dashboard/report).
    """
    with db_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM ml_run_scores WHERE run_id=%s", (run_id,))
            r = cur.fetchone()
            if not r:
                raise HTTPException(status_code=404, detail="No score found for this run_id")
            return r
