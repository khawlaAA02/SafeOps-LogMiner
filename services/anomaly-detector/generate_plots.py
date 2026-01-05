import os
import json
from datetime import datetime
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

import psycopg2
from psycopg2.extras import RealDictCursor

from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest

# =========================
# 1) CONFIG ENV
# =========================
PG_HOST = os.getenv("POSTGRES_HOST", "localhost")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB   = os.getenv("POSTGRES_DB", "safeops_security")
PG_USER = os.getenv("POSTGRES_USER", "safeops")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "safeops")

PIPELINE_ID = os.getenv("PIPELINE_ID", "demo-pipeline")
LIMIT = int(os.getenv("LIMIT", "300"))

ISO_CONTAMINATION = float(os.getenv("ISO_CONTAMINATION", "0.05"))

TF_ENABLED = os.getenv("TF_ENABLED", "false").lower() in ("1", "true", "yes", "y")

FEATURES_ORDER = [
    "duration_sec",
    "error_count",
    "secrets_count",
    "urls_count",
    "bypass_count",
    "steps_count",
    "severity_score",
]

OUT_DIR = os.getenv("OUT_DIR", "./plots")
os.makedirs(OUT_DIR, exist_ok=True)

# =========================
# 2) OPTIONAL TF (AE)
# =========================
keras = None
if TF_ENABLED:
    try:
        import tensorflow as tf  # noqa
        from tensorflow import keras  # type: ignore
    except Exception:
        TF_ENABLED = False
        keras = None


# =========================
# 3) DB: READ DATA
# =========================
def connect():
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS
    )

def fetch_pipeline_runs(pipeline_id: str, limit: int) -> pd.DataFrame:
    q = f"""
    SELECT ts, pipeline_id, run_id, job_id,
           duration_sec, error_count, secrets_count, urls_count,
           bypass_count, steps_count, severity_score
    FROM pipeline_runs
    WHERE pipeline_id = %s
    ORDER BY ts DESC
    LIMIT %s
    """
    with connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(q, (pipeline_id, limit))
            rows = cur.fetchall()
    df = pd.DataFrame(rows)
    if df.empty:
        raise RuntimeError(f"Aucune donnée trouvée dans pipeline_runs pour pipeline_id={pipeline_id}")
    df["ts"] = pd.to_datetime(df["ts"])
    df = df.sort_values("ts")  # ordre chronologique
    return df

# =========================
# 4) ML: IF + SCORES
# =========================
def train_isolation_forest(X: np.ndarray):
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=250,
        contamination=ISO_CONTAMINATION,
        random_state=42
    )
    model.fit(Xs)

    df = model.decision_function(Xs)  # + grand = + normal
    mn, mx = float(np.min(df)), float(np.max(df))
    return model, scaler, mn, mx

def anomaly_score_from_df(df_value: float, mn: float, mx: float) -> float:
    # score 0..1 (1 = très anormal)
    s = 1.0 - ((df_value - mn) / (mx - mn + 1e-9))
    return float(np.clip(s, 0.0, 1.0))

# =========================
# 5) AE (OPTIONNEL)
# =========================
def build_autoencoder(input_dim: int):
    inp = keras.Input(shape=(input_dim,))
    x = keras.layers.Dense(16, activation="relu")(inp)
    x = keras.layers.Dense(8, activation="relu")(x)
    x = keras.layers.Dense(16, activation="relu")(x)
    out = keras.layers.Dense(input_dim, activation="linear")(x)
    ae = keras.Model(inp, out)
    ae.compile(optimizer="adam", loss="mse")
    return ae

def train_autoencoder(X: np.ndarray, epochs=10, batch=16):
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    ae = build_autoencoder(Xs.shape[1])
    ae.fit(Xs, Xs, epochs=epochs, batch_size=batch, verbose=0)
    return ae, scaler

def recon_errors(ae, scaler, X: np.ndarray) -> np.ndarray:
    Xs = scaler.transform(X)
    recon = ae.predict(Xs, verbose=0)
    return np.mean((Xs - recon) ** 2, axis=1)

# =========================
# 6) PLOTS
# =========================
def plot_matrix_heatmap(df: pd.DataFrame):
    X = df[FEATURES_ORDER].fillna(0).to_numpy(dtype=float)

    plt.figure()
    plt.title(f"Heatmap matrice X (N={len(df)}) — {PIPELINE_ID}")
    plt.imshow(X, aspect="auto")
    plt.xlabel("Features")
    plt.ylabel("Runs (ordre temporel)")
    plt.xticks(range(len(FEATURES_ORDER)), FEATURES_ORDER, rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "1_matrix_heatmap.png"), dpi=200)
    plt.close()

def plot_feature_distributions(df: pd.DataFrame):
    X = df[FEATURES_ORDER].fillna(0)

    for col in FEATURES_ORDER:
        plt.figure()
        plt.title(f"Distribution feature: {col} — {PIPELINE_ID}")
        plt.hist(X[col].values, bins=25)
        plt.xlabel(col)
        plt.ylabel("Count")
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, f"2_hist_{col}.png"), dpi=200)
        plt.close()

def plot_pca_scatter(df: pd.DataFrame, labels_if: np.ndarray):
    X = df[FEATURES_ORDER].fillna(0).to_numpy(dtype=float)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    pca = PCA(n_components=2, random_state=42)
    Z = pca.fit_transform(Xs)  # (N,2)

    plt.figure()
    plt.title(f"PCA 2D — IsolationForest anomalies — {PIPELINE_ID}")
    # labels_if: -1 anomalie, 1 normal
    normal = labels_if == 1
    anom = labels_if == -1

    plt.scatter(Z[normal, 0], Z[normal, 1], label="Normal")
    plt.scatter(Z[anom, 0], Z[anom, 1], label="Anomaly")
    plt.xlabel("PC1")
    plt.ylabel("PC2")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "3_pca_if_scatter.png"), dpi=200)
    plt.close()

def plot_anomaly_score_timeline(df: pd.DataFrame, scores: np.ndarray):
    plt.figure()
    plt.title(f"Anomaly score (IF) dans le temps — {PIPELINE_ID}")
    plt.plot(df["ts"].values, scores)
    plt.xlabel("Time")
    plt.ylabel("Score (0..1)")
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "4_if_score_timeline.png"), dpi=200)
    plt.close()

def plot_autoencoder_errors(df: pd.DataFrame, errs: np.ndarray, thr: float):
    plt.figure()
    plt.title(f"AutoEncoder — Reconstruction error + seuil p90 — {PIPELINE_ID}")
    plt.plot(df["ts"].values, errs, label="reconstruction_error")
    plt.axhline(thr, linestyle="--", label=f"threshold p90 = {thr:.4f}")
    plt.xlabel("Time")
    plt.ylabel("Reconstruction error (MSE)")
    plt.xticks(rotation=25, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "5_ae_recon_error.png"), dpi=200)
    plt.close()

# =========================
# 7) MAIN
# =========================
def main():
    df = fetch_pipeline_runs(PIPELINE_ID, LIMIT)

    # ---- matrice X ----
    plot_matrix_heatmap(df)
    plot_feature_distributions(df)

    # ---- IsolationForest ----
    X = df[FEATURES_ORDER].fillna(0).to_numpy(dtype=float)
    iso, scaler, mn, mx = train_isolation_forest(X)

    Xs = scaler.transform(X)
    df_vals = iso.decision_function(Xs)
    labels = iso.predict(Xs)  # -1 anomaly / 1 normal
    scores = np.array([anomaly_score_from_df(v, mn, mx) for v in df_vals], dtype=float)

    plot_pca_scatter(df, labels)
    plot_anomaly_score_timeline(df, scores)

    # ---- AutoEncoder optionnel ----
    if TF_ENABLED and keras is not None:
        ae, ae_scaler = train_autoencoder(X, epochs=10, batch=16)
        errs = recon_errors(ae, ae_scaler, X).astype(float)
        thr = float(np.percentile(errs, 90))
        plot_autoencoder_errors(df, errs, thr)

    # Save summary JSON
    summary = {
        "pipeline_id": PIPELINE_ID,
        "points": int(len(df)),
        "features_order": FEATURES_ORDER,
        "tf_enabled": bool(TF_ENABLED),
        "iso_contamination": ISO_CONTAMINATION,
        "out_dir": OUT_DIR,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "files": sorted(os.listdir(OUT_DIR)),
    }
    with open(os.path.join(OUT_DIR, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("✅ Plots generated in:", OUT_DIR)
    print("📄 summary:", os.path.join(OUT_DIR, "summary.json"))

if __name__ == "__main__":
    main()
