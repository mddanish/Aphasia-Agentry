# INTENTIONALLY VULNERABLE fixture - run only on an isolated network, never expose.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER nobody
EXPOSE 8080
# Inside the container it must bind 0.0.0.0 to be reachable; compose maps it to 127.0.0.1 on the host.
CMD ["python", "-c", "import app; app.app.run(host='0.0.0.0', port=8080)"]
