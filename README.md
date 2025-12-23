# 🛡️ SafeOps-LogMiner
**AI-Powered DevSecOps Log Intelligence Platform**

SafeOps-LogMiner est une plateforme DevSecOps basée sur une architecture microservices qui analyse automatiquement les logs CI/CD afin de détecter les vulnérabilités de sécurité, les anomalies comportementales et de proposer des correctifs automatiques pour renforcer les pipelines.

---

## 🚀 Objectifs
- Détecter les fuites de secrets (tokens, clés API…)
- Identifier les erreurs, bypass et comportements suspects
- Appliquer des règles OWASP & SLSA sur les pipelines
- Détecter les anomalies par Machine Learning
- Générer des correctifs YAML
- Produire des rapports PDF, HTML et SARIF
- Offrir un dashboard temps réel

---

## 🧱 Architecture Microservices

| Service | Rôle |
|-------|------|
| Log Collector (3001) | Ingestion des logs CI/CD |
| Parser (3002) | Extraction sémantique (erreurs, secrets, steps…) |
| Vuln Detector (3003) | Détection OWASP / SLSA |
| Fix Suggester (3004) | Génération des correctifs YAML |
| Anomaly Detector (3005) | Détection ML des comportements anormaux |
| Report Generator (3006) | Génération PDF / HTML / SARIF |
| Dashboard API (3010) | Agrégation des données |
| Dashboard Web (5173) | Interface React |

---

## 🧠 Intelligence de Sécurité

SafeOps-LogMiner combine :
- **Regex & NLP** pour extraire les événements
- **Règles OWASP CI/CD Top 10**
- **Mapping SLSA**
- **IsolationForest / ML** pour la détection d’anomalies
- **Scoring de risque (0–100)**

---

## 📊 Dashboard

Fonctionnalités :
- Score de sécurité par pipeline
- Timeline des risques
- Liste des vulnérabilités
- Détection d’anomalies
- Génération de rapports
- Export PDF / HTML / SARIF

---

## 📄 Rapports

Pour chaque pipeline :
- PDF de sécurité
- HTML interactif
- Fichier SARIF compatible GitHub Advanced Security

---

## 🐳 Déploiement

```bash
docker compose up --build
