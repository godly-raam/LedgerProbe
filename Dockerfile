# Base digest resolved from python:3.12-slim on 2026-11-06.
FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS builder

WORKDIR /build

COPY pyproject.toml README.md LICENSE ledgerprobe.py ./
COPY pkg ./pkg
COPY schemas ./schemas

RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels . \
    && python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --no-index --find-links=/wheels ledgerprobe \
    && rm -f /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.12

FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54

LABEL org.opencontainers.image.title="LedgerProbe" \
      org.opencontainers.image.description="API authorization and business-logic testing engine" \
      org.opencontainers.image.source="https://github.com/godly-raam/LedgerProbe" \
      org.opencontainers.image.version="1.1.0" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin ledgerprobe

COPY --from=builder /opt/venv /opt/venv

WORKDIR /work
RUN chown ledgerprobe:ledgerprobe /work

RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade apt libapt-pkg7.0 \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
USER ledgerprobe

ENTRYPOINT ["ledgerprobe"]
CMD ["--help"]
