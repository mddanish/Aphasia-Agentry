# INTENTIONALLY VULNERABLE lab agent - run only on an isolated network, never expose.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER nobody
EXPOSE 8080
# Reaches the proxy on the host; OPENAI_BASE_URL/OPENAI_API_KEY/AGENT_MODEL come from the environment.
CMD ["python", "-c", "import app; app.app.run(host='0.0.0.0', port=8080)"]
