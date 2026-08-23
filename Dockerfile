FROM python:3.13-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:99

RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        xvfb x11vnc xauth dbus-x11 \
        websockify novnc \
        wireguard iproute2 iptables iputils-ping procps curl \
        fonts-liberation fonts-noto-core \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --break-system-packages websocket-client

COPY cookie_exporter.py /app/cookie_exporter.py
COPY entrypoint.sh /app/entrypoint.sh
COPY wireguard/wg0.conf.template /etc/wireguard/wg0.conf.template
RUN chmod +x /app/entrypoint.sh

VOLUME /data
EXPOSE 8300

ENTRYPOINT ["/app/entrypoint.sh"]
