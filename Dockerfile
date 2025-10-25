FROM python:3.11-slim

WORKDIR /app

# Systemabhängigkeiten installieren
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Python-Abhängigkeiten kopieren und installieren
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Anwendung kopieren
COPY app.py .
COPY index.html .

# Volume für Datenbank
VOLUME ["/app/data"]

# Umgebungsvariablen
ENV DATABASE_PATH=/app/data/webhooks.db
ENV PORT=5000

# Port exponieren
EXPOSE 5000

# Health Check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/status')" || exit 1

# Als non-root User ausführen
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Anwendung starten
CMD ["python", "app.py"]