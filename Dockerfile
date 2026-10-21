FROM python:3.11-slim

WORKDIR /app

# Python-Abhängigkeiten kopieren und installieren
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Anwendung kopieren
COPY app.py .
COPY index.html .
COPY static ./static

# Non-root User und beschreibbares Datenverzeichnis
RUN useradd -m -u 1000 appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app

# Volume für Datenbank
VOLUME ["/app/data"]

# Umgebungsvariablen
ENV DATABASE_PATH=/app/data/webhooks.db
ENV PORT=5000

# Port exponieren
EXPOSE 5000

# Health Check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '5000'), timeout=3)" || exit 1

USER appuser

# Anwendung mit gunicorn starten. Bewusst 1 Worker mit mehreren Threads:
# das Login-Rate-Limit wird im Prozessspeicher geführt. Der Timeout liegt über der
# längsten möglichen Auslösung (4 Versuche x 60 s + Wartezeiten).
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 8 --timeout 300 app:app"]
