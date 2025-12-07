from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from dotenv import load_dotenv
from jinja2 import Template
from diff_match_patch import diff_match_patch
import os
import yaml

# Charger .env (optionnel pour PORT)
load_dotenv()

PORT = int(os.getenv("PORT", "3004"))

app = FastAPI(title="FixSuggester")

# --- Chargement des règles YAML ---
RULES_FILE = "rules_fixes.yaml"


def load_rules():
    if not os.path.exists(RULES_FILE):
        print(f"[WARN] Fichier {RULES_FILE} introuvable.")
        return []

    with open(RULES_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
        return data.get("fixes", [])


RULES = load_rules()


# --- Input Model ---
class VulnInput(BaseModel):
    vulnerabilities: List[str]


# --- Root ---
@app.get("/")
async def root():
    return {"message": "FixSuggester is running"}


# --- Utilitaire : Diff intelligente ---
def generate_diff(before: str, after: str) -> str:
    dmp = diff_match_patch()
    diffs = dmp.diff_main(before, after)
    dmp.diff_cleanupSemantic(diffs)
    return dmp.diff_prettyHtml(diffs)


# --- API principale ---
@app.post("/suggest")
async def suggest_fixes(vuln_input: VulnInput):
    try:
        vulns = vuln_input.vulnerabilities
        suggestions = []

        # Trouver les règles qui matchent
        for rule in RULES:
            trigger = rule.get("trigger")
            suggestion = rule.get("suggestion")

            if trigger in vulns:
                suggestions.append({
                    "vulnerability": trigger,
                    "suggestion": suggestion,
                })

        # Génération du rapport HTML via Jinja2
        template = Template("""
        <h2>Rapport de remédiation</h2>
        <ul>
        {% for s in suggestions %}
            <li><b>{{ s.vulnerability }}</b> → {{ s.suggestion }}</li>
        {% endfor %}
        </ul>
        """)

        html_report = template.render(suggestions=suggestions)

        # Exemple de diff : Avant vs Après rapport
        diff_html = generate_diff("OLD REPORT", html_report)

        return {
            "count": len(suggestions),
            "suggestions": suggestions,
            "html_report": html_report,
            "diff_preview": diff_html
        }

    except Exception as e:
        print("Error in /suggest:", e)
        raise HTTPException(status_code=500, detail="Error while generating suggestions")
