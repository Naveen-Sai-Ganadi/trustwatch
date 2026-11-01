# TrustWatch images. Most people use compose.yaml (`make up`); each stage can also be built on its own:
#   web      (default) the public website: `docker build -t trustwatch-web . && docker run -p 8080:8080 trustwatch-web`
#   scanner  the CLI and local dashboard, with the docker CLI to read images through the host's Docker
#   test     the test suite: `docker build --target test -t trustwatch-test . && docker run --rm trustwatch-test`
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv build --wheel -o /dist

FROM build AS test
COPY tests ./tests
RUN uv sync --frozen --group dev
CMD ["uv", "run", "--frozen", "pytest", "-q"]

FROM python:3.12-slim AS runtime
COPY --from=build /dist /opt/trustwatch
RUN pip install --no-cache-dir /opt/trustwatch/*.whl && useradd --system --no-create-home trustwatch
# The wheel is offered for download on the website, so visitors can run the same scanner.
ENV TRUSTWATCH_WHEEL=/opt/trustwatch

# Runs as root: it talks to the host's Docker socket, which is root-equivalent anyway. It only reads.
FROM runtime AS scanner
COPY --from=docker:29-cli /usr/local/bin/docker /usr/local/bin/docker
ENTRYPOINT ["trustwatch"]
CMD ["scan", "--no-host", "--help"]

FROM runtime AS web
USER trustwatch
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz')"
CMD ["trustwatch", "serve", "--public"]
