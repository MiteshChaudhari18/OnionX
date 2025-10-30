FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tor ca-certificates curl fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1 \
    PORT=5000 \
    STREAMLIT_SERVER_PORT=5000 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    TOR_PROXY_HOST=127.0.0.1 \
    TOR_PROXY_PORT=9050 \
    TOR_CONTROL_HOST=127.0.0.1 \
    TOR_CONTROL_PORT=9051 \
    TOR_TIMEOUT=45 \
    REQUESTS_VERIFY_SSL=false

COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 5000

CMD ["/app/start.sh"]
