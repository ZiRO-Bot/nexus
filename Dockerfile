# build stage
FROM python:3.10-slim as base

# ---
FROM base as builder

RUN pip install -U pip setuptools wheel
RUN pip install pdm

COPY pyproject.toml pdm.lock README.md /project/
COPY nexus/ /project/nexus

WORKDIR /project
RUN mkdir __pypackages__ && pdm sync --prod --no-editable

# ---
FROM base as final

COPY --from=builder /project/nexus /project/nexus

CMD ["uvicorn", "nexus.app:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]