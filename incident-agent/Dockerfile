FROM python:3.12-slim
RUN pip install --no-cache-dir uv==0.8.11
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src/main/python ./src/main/python
RUN uv sync --frozen --no-dev
RUN useradd -r agent && mkdir -p /data && chown -R agent /app /data
USER agent
ENV HOST=0.0.0.0 DATA_DIR=/data
EXPOSE 8080
CMD ["/app/.venv/bin/incident-agent"]
