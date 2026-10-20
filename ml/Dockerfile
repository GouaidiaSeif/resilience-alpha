# Image du service « detector ». Contexte de build = racine du dépôt.
#   lancé avec la pile : docker compose up -d --build   (service « detector » de docker-compose.yml)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Versions EXACTES de l'entraînement du modèle publié (le .joblib ne se recharge qu'avec elles).
# Mêmes chemins relatifs que dans le dépôt : ml/requirements-lock.txt inclut ../libs/common/requirements.txt
COPY libs/common/requirements.txt /build/libs/common/requirements.txt
COPY ml/requirements-lock.txt /build/ml/requirements-lock.txt
RUN pip install --no-cache-dir -r /build/ml/requirements-lock.txt

COPY libs/common/resilience_common ./resilience_common
COPY ml/loki.py ml/features.py ml/model_io.py ml/detector.py ./

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001

EXPOSE 8000
CMD ["uvicorn", "detector:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
