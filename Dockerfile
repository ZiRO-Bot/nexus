# build stage
FROM python:3.10-slim as base

# ---
FROM base as builder

RUN pip install -U pip setuptools wheel
RUN pip install pdm

COPY pyproject.toml pdm.lock README.md /project/
COPY src/ /project/src

WORKDIR /project
RUN mkdir __pypackages__ && pdm sync --prod --no-editable

# ---
FROM base as final

ENV PYTHONPATH=/project/pkgs
COPY --from=builder /project/__pypackages__/3.10/lib /project/pkgs

CMD ["uvicorn", "nexus.app:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]