FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ledgerprobe.py ./
COPY pkg ./pkg

RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels . \
    && python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --no-index --find-links=/wheels ledgerprobe \
    && rm -f /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.12

FROM python:3.12-slim

LABEL org.opencontainers.image.title="LedgerProbe" \
      org.opencontainers.image.description="Specification-driven API security checks" \
      org.opencontainers.image.source="https://github.com/godly-raam/LedgerProbe"

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
