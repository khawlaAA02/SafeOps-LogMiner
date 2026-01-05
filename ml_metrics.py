import os
import requests
import pandas as pd
import matplotlib.pyplot as plt
import os
print("CWD =", os.getcwd())
os.makedirs("demo_metrics", exist_ok=True)
print("demo_metrics created/exists")


API_ANOM = os.getenv("API_ANOM", "http://127.0.0.1:3005")   # MS5
PG_HOST = os.getenv("PG_HOST", "127.0.0.1")                # si tu veux via API seulement, pas besoin
API_DASH = os.getenv("API_DASH", "http://127.0.0.1:3010")  # pour pipelines
OUT_DIR = os.getenv("OUT_DIR", "./demo_metrics")

os.makedirs(OUT_DIR, exist_ok=True)

def get_json(url: str):
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.json()

def confusion_matrix(y_true, y_pred):
    # y_true/y_pred: list of bool
    tp = sum((t and p) for t, p in zip(y_true, y_pred))
    tn = sum((not t and not p) for t, p in zip(y_true, y_pred))
    fp = sum((not t and p) for t, p in zip(y_true, y_pred))
    fn = sum((t and not p) for t, p in zip(y_true, y_pred))
    return tp, tn, fp, fn

def metrics_from_cm(tp, tn, fp, fn):
    acc = (tp + tn) / max(1, (tp + tn + fp + fn))
    prec = tp / max(1, (tp + fp))
    rec = tp / max(1, (tp + fn))
    f1 = (2 * prec * rec) / max(1e-9, (prec + rec))
    return acc, prec, rec, f1

def plot_cm(tp, tn, fp, fn, out_path):
    # matrix [[TN, FP],[FN, TP]]
    mat = [[tn, fp],[fn, tp]]
    plt.figure()
    plt.imshow(mat)
    plt.title("Confusion Matrix (Anomaly Detection)")
    plt.xticks([0,1], ["Pred Normal", "Pred Anomaly"])
    plt.yticks([0,1], ["True Normal", "True Anomaly"])

    for i in range(2):
        for j in range(2):
            plt.text(j, i, str(mat[i][j]), ha="center", va="center")

    plt.tight_layout()
    plt.savefig(out_path, dpi=180)
    plt.close()

def main():
    # 1) récupérer predictions (anomaly_reports) depuis MS5
    # /reports retourne les lignes (pipeline_id, run_id, is_anomaly, anomaly_score...)
    # On filtre sur une pipeline si tu veux
    pipeline = os.getenv("PIPELINE", "").strip()  # ex: demo-errors
    if pipeline:
        reports = get_json(f"{API_ANOM}/reports?pipelineId={pipeline}&limit=200")
    else:
        reports = get_json(f"{API_ANOM}/reports?limit=200")

    df_pred = pd.DataFrame(reports)
    if df_pred.empty:
        print("No anomaly_reports found. Run /anomaly first.")
        return

    # normaliser colonnes
    df_pred["pipeline_id"] = df_pred["pipeline_id"].astype(str)
    df_pred["run_id"] = df_pred["run_id"].fillna("").astype(str)
    df_pred["is_anomaly"] = df_pred["is_anomaly"].astype(bool)
    df_pred = df_pred[df_pred["run_id"] != ""]  # run_id vide => pas comparable

    # 2) récupérer labels depuis Postgres via endpoint? (tu n'as pas d'API labels)
    # => méthode simple pour démo: lire labels depuis une requête SQL exportée CSV
    labels_csv = os.getenv("LABELS_CSV", "./labels.csv")
    if not os.path.exists(labels_csv):
        print(f"Missing {labels_csv}. Export labels with SQL below.")
        print("SQL: \\copy (SELECT pipeline_id, run_id, y_true FROM anomaly_labels) TO 'labels.csv' CSV HEADER;")
        return

    df_true = pd.read_csv(labels_csv)
    df_true["pipeline_id"] = df_true["pipeline_id"].astype(str)
    df_true["run_id"] = df_true["run_id"].astype(str)
    df_true["y_true"] = df_true["y_true"].astype(bool)

    # 3) join predictions + truth
    df = df_pred.merge(df_true, on=["pipeline_id","run_id"], how="inner")
    if df.empty:
        print("No matches between anomaly_reports and anomaly_labels.")
        print("Make sure run_id values match exactly.")
        return

    y_true = df["y_true"].tolist()
    y_pred = df["is_anomaly"].tolist()

    tp, tn, fp, fn = confusion_matrix(y_true, y_pred)
    acc, prec, rec, f1 = metrics_from_cm(tp, tn, fp, fn)

    # 4) sauver résumé + images
    summary = {
        "rows_used": len(df),
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1
    }
    out_json = os.path.join(OUT_DIR, "metrics_summary.json")
    with open(out_json, "w", encoding="utf-8") as f:
        import json
        json.dump(summary, f, indent=2, ensure_ascii=False)

    out_cm = os.path.join(OUT_DIR, "confusion_matrix.png")
    plot_cm(tp, tn, fp, fn, out_cm)

    # graphe score distribution (optionnel)
    if "anomaly_score" in df.columns:
        plt.figure()
        df["anomaly_score"].astype(float).hist(bins=20)
        plt.title("Distribution anomaly_score (sur runs labellisés)")
        plt.xlabel("anomaly_score")
        plt.ylabel("count")
        plt.tight_layout()
        out_hist = os.path.join(OUT_DIR, "score_distribution.png")
        plt.savefig(out_hist, dpi=180)
        plt.close()
    else:
        out_hist = None

    print("✅ Metrics saved:", out_json)
    print("✅ Confusion matrix image:", out_cm)
    if out_hist:
        print("✅ Score distribution image:", out_hist)

if __name__ == "__main__":
    main()
