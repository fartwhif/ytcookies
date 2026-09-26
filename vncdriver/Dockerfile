FROM python:3.13-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --break-system-packages websocket-client pyDes pillow

COPY vncdriver/vncdriver.py /app/vncdriver.py
ENTRYPOINT ["python3", "/app/vncdriver.py"]
