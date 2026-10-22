# Hosted TrustWatch: `docker build -t trustwatch-web . && docker run -p 8080:8080 trustwatch-web`
# Put it behind a TLS-terminating proxy (the browser test and clipboard need https).
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv build --wheel -o /dist

FROM python:3.12-slim
COPY --from=build /dist /opt/trustwatch
RUN pip install --no-cache-dir /opt/trustwatch/*.whl && useradd --system --no-create-home trustwatch
USER trustwatch
ENV PORT=8080 TRUSTWATCH_WHEEL=/opt/trustwatch/trustwatch-0.1.0-py3-none-any.whl
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz')"
CMD ["trustwatch", "serve", "--public"]
