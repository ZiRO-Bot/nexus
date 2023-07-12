FROM python:3.10-slim as base

LABEL org.opencontainers.image.source="https://github.com/ZiRO-Bot/nexus"
LABEL org.opencontainers.image.description="FastAPI-based backend"
LABEL org.opencontainers.image.licenses=MPL-2.0

# ---
FROM base as builder

WORKDIR /app

ENV PATH="/root/.local/bin:${PATH}" \
    VIRTUAL_ENV="/venv"

RUN pip install -U pip setuptools wheel
RUN pip install pdm

COPY pyproject.toml pdm.lock ./
COPY nexus/ ./
RUN pdm sync --prod --no-editable

# ---
FROM base as final

WORKDIR /app

ENV PATH="/venv/bin:${PATH}" \
    VIRTUAL_ENV="/venv"

COPY --from=builder /venv /venv
COPY --from=builder /app/nexus/ /app/nexus

CMD ["uvicorn", "nexus.app:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]