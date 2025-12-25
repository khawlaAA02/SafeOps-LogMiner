# 🛡️ SafeOps-LogMiner  
**AI-Powered DevSecOps Log Intelligence Platform**

SafeOps-LogMiner est une plateforme **DevSecOps intelligente** basée sur une architecture **microservices** qui analyse automatiquement les **logs CI/CD** (GitHub Actions, GitLab CI, Jenkins, etc.) afin de détecter les vulnérabilités de sécurité, les anomalies comportementales et de proposer des **correctifs automatiques** pour renforcer les pipelines.

---

## 📌 Vision

Les pipelines CI/CD modernes sont hautement automatisés mais exposés à :
- des fuites de secrets (tokens, clés API, credentials),
- des mauvaises configurations,
- des bypass de sécurité,
- des attaques sur la supply-chain logicielle.

SafeOps-LogMiner fournit une **surveillance de sécurité continue basée sur les logs réels d’exécution**, et non uniquement sur l’analyse statique du code.

---

## 🎯 Objectifs

- Détecter les **fuites de secrets**
- Identifier les **erreurs critiques et comportements suspects**
- Appliquer les règles **OWASP CI/CD Top 10**
- Vérifier la conformité **SLSA**
- Détecter les anomalies via **Machine Learning**
- Générer des **correctifs YAML automatiques**
- Produire des rapports **PDF / HTML / SARIF**
- Fournir un **dashboard temps réel**

---

## 🧠 Intelligence de Sécurité

SafeOps-LogMiner combine plusieurs moteurs :

| Mécanisme | Description |
|--------|-------------|
| Regex & NLP | Extraction des erreurs, secrets, étapes CI |
| OWASP CI/CD | Détection des mauvaises pratiques |
| SLSA | Évaluation de la maturité supply-chain |
| Isolation Forest (ML) | Détection d’anomalies |
| Scoring | Score de risque de 0 à 100 |

---

## 🔁 Fonctionnement Global

1. L’utilisateur sélectionne un pipeline CI/CD (GitHub, GitLab, Jenkins…)
2. Les logs sont collectés (API, Webhook ou ZIP)
3. Les logs sont analysés par le Parser
4. VulnDetector applique OWASP & SLSA
5. AnomalyDetector détecte les comportements anormaux
6. FixSuggester génère des correctifs YAML
7. ReportGenerator produit les rapports
8. Les résultats sont stockés et affichés dans le Dashboard

---

## 🧱 Architecture Microservices

| Service | Port | Rôle |
|-------|------|------|
| Log Collector | 3001 | Ingestion des logs CI/CD |
| Log Parser | 3002 | Extraction sémantique |
| Vuln Detector | 3003 | Détection OWASP / SLSA |
| Fix Suggester | 3004 | Génération de correctifs YAML |
| Anomaly Detector | 3005 | Détection ML |
| Report Generator | 3006 | Génération PDF / HTML / SARIF |
| Dashboard API | 3010 | Agrégation des données |
| Dashboard Web | 5173 | Interface React |


<img width="1192" height="411" alt="architecture" src="https://github.com/user-attachments/assets/c44ff3f8-8877-449c-8191-5d37ccdf8525" />

## 🗄️ Stockage des données

| Base de données | Rôle |
|----------------|------|
| MongoDB | Stockage des logs bruts |
| PostgreSQL | Vulnérabilités, scores, rapports |
| TimescaleDB | Métriques temporelles |

---

## 📊 Dashboard Web

Le Dashboard permet de :

- Visualiser le **score de sécurité**
- Voir la **timeline des risques**
- Explorer les **vulnérabilités**
- Détecter les **anomalies ML**
- Télécharger les **rapports**
- Récupérer les **correctifs YAML**

---

## 📄 Rapports

Pour chaque pipeline analysé :

- 📕 **PDF** – Rapport de sécurité
- 🌐 **HTML** – Version interactive
- 🧩 **SARIF** – Compatible GitHub Advanced Security

## 🎥 Vidéo de démonstration


https://github.com/user-attachments/assets/4c1e63f8-45a1-473a-9ed5-e5ac6569b651

## 🏗️ Cas d’usage

- Audit de pipelines CI/CD
- Détection des fuites de clés API
- Vérification de la conformité SLSA
- Surveillance de la sécurité DevSecOps
- Intégration GitHub Advanced Security

## 👨‍💻 Projet

Ce projet est une plateforme DevSecOps & IA combinant :

- Microservices
- Sécurité CI/CD
- Machine Learning
- Observabilité
- Reporting

## 🐳 Déploiement

```bash
docker compose up --build


