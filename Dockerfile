# PathTriage — reproducible environment
#
# Build:  docker build -t pathtriage .
# Test:   docker run --rm pathtriage
# Shell:  docker run --rm -it pathtriage bash
#
# The default command runs the unit test suite, so a successful
# `docker run` is itself evidence that the environment is correctly
# provisioned. No cloud credentials are required for the tests, the
# fixture-mode CLI, or the detection evaluation.

FROM python:3.11-slim

# jq is used by the documented reproduction steps to read the
# evaluation results; git lets a reader inspect provenance in-image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git jq \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency manifests first, so edits to source do not invalidate
# the pip layer on rebuild.
COPY pyproject.toml requirements.txt ./

COPY pathtriage/ ./pathtriage/
COPY attacks/    ./attacks/
COPY tests/      ./tests/
COPY README.md LICENSE ./

# [evaluation] pulls in duckdb, which the detection harness requires.
RUN pip install --no-cache-dir -e ".[evaluation,dev]"

CMD ["pytest", "-v"]
