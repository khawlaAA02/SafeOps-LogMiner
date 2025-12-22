FROM python:3.11-slim

WORKDIR /app

# Copier dépendances
COPY requirements.txt .

# Installer dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code + rules.yaml
COPY . .

# Port exposé
EXPOSE 3003

# Lancer FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3003"]
