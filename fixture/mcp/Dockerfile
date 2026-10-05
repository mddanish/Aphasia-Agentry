# INTENTIONALLY VULNERABLE fixture - run only on an isolated network, never expose.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "mcp>=2"
COPY server.py .
USER nobody
EXPOSE 8000
# Must bind 0.0.0.0 inside the container; compose maps it to 127.0.0.1 on the host.
CMD ["python", "-c", "import server; server.mcp.run('streamable-http', host='0.0.0.0', port=8000)"]
