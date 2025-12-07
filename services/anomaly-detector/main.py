from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest
import psycopg2
import numpy as np
import os

# Charger .env
load_dotenv()

TS_HOST = os.getenv("TS_HOST", "localhost")
TS_PORT = os.getenv("TS_PORT", "5432")
TS_DB   = os.getenv("TS_DB", "safeops_ts")
TS_USER = os.getenv("TS_USER", "postgres")
TS_PASS = os.getenv("TS_PASS", "postgres")

# FastAPI
app = FastAPI(title="AnomalyDetector")

# Modèle ML
model = IsolationForest(contamination=0.10, random_state=42)

# Connexion TimescaleDB
def get_conn():
    return psycopg2.connect(
        host=TS_HOST,
        port=TS_PORT,
        database=TS_DB,
        user=TS_USER,
        password=TS_PASS
    )

# Input JSON
class LogInput(BaseModel):
    pipeline: str
    status: str
    has_error: bool
    duration: float | None = None
    message: str | None = None


@app.get("/")
def root():
    return {"message": "AnomalyDetector is running"}


@app.post("/anomaly")
def detect_anomaly(payload: LogInput):

    try:
        # convertir données en vecteurs numériques
        X = np.array([
            [
                1 if payload.has_error else 0,
                len(payload.message) if payload.message else 0,
                payload.duration if payload.duration else 0
            ]
        ])

        # récupérer historique pour entraîner modèle
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT has_error, msg_length, duration FROM logs_ts")
        rows = cur.fetchall()

        if len(rows) > 10:
            X_train = np.array(rows)
            model.fit(X_train)

            score = model.decision_function(X)[0]
            label = "anomaly" if score < -0.1 else "normal"
        else:
            score = 0.0
            label = "normal"

        # sauvegarder dans TimescaleDB
        cur.execute(
            """
            INSERT INTO logs_ts (has_error, msg_length, duration)
            VALUES (%s, %s, %s)
            """,
            (
                1 if payload.has_error else 0,
                len(payload.message) if payload.message else 0,
                payload.duration or 0
            )
        )
        conn.commit()
        cur.close()
        conn.close()

        return {
            "pipeline": payload.pipeline,
            "score": score,
            "label": label
        }

    except Exception as e:
        print("Error anomaly:", e)
        raise HTTPException(status_code=500, detail="Error computing anomaly")
