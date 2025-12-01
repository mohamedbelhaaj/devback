# ---- Image Python officielle ----
FROM python:3.11-slim

# ---- Répertoire de travail ----
WORKDIR /app

# ---- Installer les dépendances ----
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- Copier le projet ----
COPY . .

# ---- Exposer le port Django ----
EXPOSE 8000

# ---- Créer la base SQLite si elle n'existe pas, puis collectstatic et lancer Gunicorn ----
CMD ["sh", "-c", "\
    if [ ! -f db.sqlite3 ]; then \
        echo 'Création de la base SQLite...' && \
        python manage.py migrate; \
    fi && \
    python manage.py collectstatic --noinput && \
    gunicorn virus_analyzer.wsgi:application --bind 0.0.0.0:8000"]
