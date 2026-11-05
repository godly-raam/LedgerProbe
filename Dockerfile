# Base digest resolved locally on 2026-11-05.
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 AS builder

WORKDIR /build

COPY pyproject.toml README.md ledgerprobe.py ./
COPY pkg ./pkg

RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels . \
    && python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --no-index --find-links=/wheels ledgerprobe \
    && rm -f /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.12

FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

LABEL org.opencontainers.image.title="LedgerProbe" \
      org.opencontainers.image.description="Specification-driven API security checks" \
      org.opencontainers.image.source="https://github.com/godly-raam/LedgerProbe" \
      org.opencontainers.image.version="1.1.0" \
      org.opencontainers.image.licenses="UNLICENSED"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin ledgerprobe

COPY --from=builder /opt/venv /opt/venv

WORKDIR /work
RUN chown ledgerprobe:ledgerprobe /work

USER ledgerprobe

ENTRYPOINT ["ledgerprobe"]
CMD ["--help"]
