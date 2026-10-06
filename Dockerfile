FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==26.2.0

COPY app.py .
COPY templates templates
COPY static static

# Run as a non-root user; the SQLite file lives in /app, so it must be writable.
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

# SECRET_KEY is required (the app refuses to start without it).
# One worker on purpose: rate-limit counters are in memory, per process.
# init_db() runs here because gunicorn imports app.py instead of running it.
CMD ["sh", "-c", "python -c 'import app; app.init_db()' && exec gunicorn --workers 1 --bind 0.0.0.0:8000 app:app"]
