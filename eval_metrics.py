import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve,
    classification_report
)

CSV_PATH = "eval.csv"
OUT_DIR = "demo_metrics"

import os
os.makedirs(OUT_DIR, exist_ok=True)

df = pd.read_csv(CSV_PATH)

# Nettoyage: certains rows peuvent ne pas avoir de prédiction si LEFT JOIN n'a rien trouvé
df["y_true"] = df["y_true"].fillna(0).astype(int)
df["y_pred"] = df["y_pred"].fillna(0).astype(int)
df["score"] = df["score"].fillna(0.0).astype(float)
df["model_used"] = df["model_used"].fillna("NA").astype(str)

def compute_and_save(sub: pd.DataFrame, tag: str):
    y_true = sub["y_true"].values
    y_pred = sub["y_pred"].values
    score = sub["score"].values

    # Metrics
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    # AUC seulement si y_true contient 2 classes
    auc = None
    if len(np.unique(y_true)) == 2:
        try:
            auc = roc_auc_score(y_true, score)
        except Exception:
            auc = None

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=[0,1])

    # Save confusion matrix figure
    fig = plt.figure()
    plt.imshow(cm)
    plt.title(f"Confusion Matrix — {tag}")
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.xticks([0,1], ["Normal(0)", "Anomaly(1)"])
    plt.yticks([0,1], ["Normal(0)", "Anomaly(1)"])

    # Annotate values
    for (i, j), v in np.ndenumerate(cm):
        plt.text(j, i, str(v), ha="center", va="center")

    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, f"cm_{tag}.png"), dpi=200)
    plt.close(fig)

    # ROC Curve
    if auc is not None:
        fpr, tpr, _ = roc_curve(y_true, score)
        fig = plt.figure()
        plt.plot(fpr, tpr, label=f"AUC={auc:.3f}")
        plt.plot([0,1], [0,1], linestyle="--")
        plt.title(f"ROC Curve — {tag}")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, f"roc_{tag}.png"), dpi=200)
        plt.close(fig)

    return {
        "tag": tag,
        "n": len(sub),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc if auc is not None else ""
    }

rows = []

# Global
rows.append(compute_and_save(df, "ALL"))

# Par modèle (IF / IF+AE / fallback)
for m in sorted(df["model_used"].unique()):
    sub = df[df["model_used"] == m].copy()
    if len(sub) >= 2:
        rows.append(compute_and_save(sub, f"MODEL_{m.replace('+','_')}"))

metrics_df = pd.DataFrame(rows)
metrics_df.to_csv(os.path.join(OUT_DIR, "metrics.csv"), index=False)

# Bonus: report texte
with open(os.path.join(OUT_DIR, "classification_report.txt"), "w", encoding="utf-8") as f:
    f.write(classification_report(df["y_true"], df["y_pred"], digits=4))

print("✅ Done!")
print(f"- Saved to: {OUT_DIR}/metrics.csv")
print(f"- Confusion matrices: {OUT_DIR}/cm_*.png")
print(f"- ROC curves: {OUT_DIR}/roc_*.png (si possible)")
print(f"- Text report: {OUT_DIR}/classification_report.txt")
