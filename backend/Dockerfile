# PLEXUS backend — FastAPI NIDS API + detection engine.
#
# Build context is the repo root (see docker-compose.yml):
#   docker build -f backend/Dockerfile .
#
# Live packet capture needs NET_RAW/NET_ADMIN (granted in docker-compose.yml).
# Runs as a non-root user; the SQLite db lives at $PLEXUS_DB_PATH (/data).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# backend/ package + ml/ package (flow aggregator, model loader, artifacts).
COPY backend/ ./backend/
COPY ml/ ./ml/

RUN useradd --create-home --shell /usr/sbin/nologin plexus \
    && mkdir -p /data \
    && chown -R plexus:plexus /app /data

# Raw-socket capture as a non-root user: grant the python binary file
# capabilities (same approach as start_backend.sh's setcap on the venv
# python). cap_add alone is not enough — for non-root processes the caps
# must also be effective, which file capabilities provide.
# NOTE: setcap refuses symlinks, so target the real binary only
# (/usr/local/bin/python3 is a symlink to python3.12).
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/python3.12

USER plexus

ENV PLEXUS_DB_PATH=/data/network_traffic.db

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
