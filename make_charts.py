import os
import json
from datetime import datetime
import requests
import matplotlib.pyplot as plt

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:3010")
OUT_DIR = os.getenv("OUT_DIR", "./demo_charts")
PIPELINES = os.getenv("PIPELINES", "").strip()  # ex: "ci-demo,demo-clean,demo-errors"

os.makedirs(OUT_DIR, exist_ok=True)


def get_json(url: str):
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.json()


def safe_dt(x):
    try:
        return datetime.fromisoformat(x.replace("Z", "+00:00"))
    except Exception:
        return None


def save_json(name, data):
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path


def plot_scores(scores_items):
    # scores_items: [{pipeline_id, score, runs}, ...]
    scores_items = sorted(scores_items, key=lambda x: x.get("score", 0), reverse=True)

    labels = [x["pipeline_id"] for x in scores_items]
    values = [float(x["score"]) for x in scores_items]

    plt.figure()
    plt.bar(labels, values)
    plt.ylim(0, 100)
    plt.title("Score sécurité par pipeline (0-100)")
    plt.ylabel("Score")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()

    out = os.path.join(OUT_DIR, "scores_by_pipeline.png")
    plt.savefig(out, dpi=180)
    plt.close()
    return out


def plot_trend(pipeline_id, points):
    # points: [{t, score}, ...]
    pts = []
    for p in points:
        dt = safe_dt(p.get("t"))
        sc = p.get("score")
        if dt and sc is not None:
            pts.append((dt, float(sc)))

    if not pts:
        return None

    pts.sort(key=lambda x: x[0])
    xs = [x[0] for x in pts]
    ys = [x[1] for x in pts]

    plt.figure()
    plt.plot(xs, ys, marker="o")
    plt.ylim(0, 100)
    plt.title(f"Tendance du score — {pipeline_id}")
    plt.ylabel("Score")
    plt.xlabel("Temps")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()

    out = os.path.join(OUT_DIR, f"trend_{pipeline_id}.png")
    plt.savefig(out, dpi=180)
    plt.close()
    return out


def plot_buckets(pipeline_id, summary):
    # summary.buckets: {critical, high, medium, low}
    b = (summary or {}).get("buckets") or {}
    labels = ["critical", "high", "medium", "low"]
    values = [int(b.get(k, 0) or 0) for k in labels]

    if sum(values) == 0:
        return None

    plt.figure()
    plt.pie(values, labels=labels, autopct="%1.0f%%")
    plt.title(f"Répartition des runs par niveau — {pipeline_id}")
    plt.tight_layout()

    out = os.path.join(OUT_DIR, f"buckets_{pipeline_id}.png")
    plt.savefig(out, dpi=180)
    plt.close()
    return out


def main():
    # 1) Récupérer pipelines
    pipes_resp = get_json(f"{API_BASE}/pipelines")

    # Ton API peut renvoyer: {items:["ci-demo",...]} ou {items:[{pipeline_id,runs}]}
    items = pipes_resp.get("items", []) if isinstance(pipes_resp, dict) else []
    pipelines = []
    if items:
        if isinstance(items[0], dict) and "pipeline_id" in items[0]:
            pipelines = [x["pipeline_id"] for x in items]
        else:
            pipelines = list(items)

    # override si PIPELINES env fourni
    if PIPELINES:
        pipelines = [x.strip() for x in PIPELINES.split(",") if x.strip()]

    if not pipelines:
        print("No pipelines found.")
        return

    print("Pipelines:", pipelines)

    # 2) Scores global -> image bar
    scores = get_json(f"{API_BASE}/dashboard/scores?limit=30")
    save_json("scores.json", scores)
    scores_img = plot_scores(scores.get("items", []))
    print("Saved:", scores_img)

    # 3) Pour chaque pipeline: summary + trend + buckets (images)
    for pid in pipelines:
        summary = get_json(f"{API_BASE}/dashboard/summary?pipeline={pid}&limit=30")
        trend = get_json(f"{API_BASE}/dashboard/trend?pipeline={pid}&limit=30")

        save_json(f"summary_{pid}.json", summary)
        save_json(f"trend_{pid}.json", trend)

        img1 = plot_trend(pid, trend.get("points", []))
        img2 = plot_buckets(pid, summary)

        print(f"{pid} -> trend:", img1)
        print(f"{pid} -> buckets:", img2)

    print(f"\n✅ All outputs in: {os.path.abspath(OUT_DIR)}")


if __name__ == "__main__":
    main()
