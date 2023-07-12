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
RUN python -m venv /venv

COPY pyproject.toml pdm.lock uvicorn.patch ./
ADD nexus/ ./nexus
RUN pdm sync --prod --no-editable
RUN patch /venv/lib/**/sites-packages/uvicorn/main.py < /app/uvicorn.patch

# ---
FROM base as final

WORKDIR /app

ENV PATH="/venv/bin:${PATH}" \
    VIRTUAL_ENV="/venv"

COPY --from=builder /venv /venv
COPY --from=builder /app/nexus/ /app/nexus
COPY assets/ /app/assets

CMD ["uvicorn", "nexus.app:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]