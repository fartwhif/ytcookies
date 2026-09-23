#!/bin/bash
set -e

# ── WireGuard tunnel ───────────────────────────────────────────────
if [ -n "$WG_PRIVATE_KEY" ] && [ -n "$WG_PEER_PUBLIC_KEY" ] && [ -n "$WG_PEER_ENDPOINT" ]; then
  echo "Configuring WireGuard tunnel..."

  sed \
    -e "s|__WG_PRIVATE_KEY__|${WG_PRIVATE_KEY}|g" \
    -e "s|__WG_ADDRESS__|${WG_ADDRESS:-10.99.0.240/32}|g" \
    -e "s|__WG_PEER_PUBLIC_KEY__|${WG_PEER_PUBLIC_KEY}|g" \
    -e "s|__WG_PEER_ALLOWEDIPS__|${WG_PEER_ALLOWEDIPS:-10.99.0.0/20}|g" \
    -e "s|__WG_PEER_ENDPOINT__|${WG_PEER_ENDPOINT}|g" \
    -e "s|__WG_PEER_PERSISTENT_KEEPALIVE__|${WG_PEER_PERSISTENT_KEEPALIVE:-25}|g" \
    /etc/wireguard/wg0.conf.template > /etc/wireguard/wg0.conf

  wg-quick up wg0
  # Keep the docker bridge subnet on eth0: full-tunnel WireGuard (table
  # 51820) would otherwise route replies to the bridge gateway
  # (docker-proxy's local end for host-mapped ports) via wg0 and drop them.
  BRIDGE_NET=$(ip -4 route show table main | awk '/scope link/ {print $1; exit}')
  [ -n "$BRIDGE_NET" ] && ip route replace ${BRIDGE_NET} dev eth0 table 51820 2>/dev/null || true

  echo "WireGuard tunnel established"
  wg show
else
  echo "WireGuard: skipping (missing env vars)"
fi

mkdir -p /data/profile

# Clear stale profile locks from a previous container run (same volume,
# new hostname) so Chromium doesn't refuse to start with a lock dialog.
rm -f /data/profile/SingletonLock /data/profile/SingletonSocket /data/profile/SingletonCookie

# Clear stale X display artifacts: Docker restarts reuse the container's
# writable layer, so a leftover /tmp/.X99-lock makes Xvfb abort with
# "Server is already active for display 99" and x11vnc then can't open :99.
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 /tmp/.X99-auth*

# ── VNC password ───────────────────────────────────────────────────
VNC_AUTH=""
if [ -n "$VNC_PASSWORD" ]; then
  VNC_AUTH=/tmp/vncpasswd
  x11vnc -storepasswd "$VNC_PASSWORD" /tmp/vncpasswd >/dev/null
  chmod 600 /tmp/vncpasswd
  echo "noVNC password: configured (from VNC_PASSWORD env)"
else
  echo "WARNING: VNC_PASSWORD not set — noVNC has NO password"
fi

# ── X server + VNC ─────────────────────────────────────────────────
Xvfb :99 -screen 0 1920x1080x24 -nolisten tcp &
sleep 1

X11VNC_ARGS=(-display :99 -forever -shared -rfbport 5900)
if [ -n "$VNC_AUTH" ]; then
  X11VNC_ARGS+=(-rfbauth "$VNC_AUTH")
else
  X11VNC_ARGS+=(-nopw)
fi
x11vnc "${X11VNC_ARGS[@]}" &

NOVNC_WEB=/usr/share/novnc
[ -d "$NOVNC_WEB" ] || NOVNC_WEB=/usr/share/webapps/noVNC
websockify --web "$NOVNC_WEB" 0.0.0.0:8300 localhost:5900 &

# ── Chromium (persistent profile, CDP on localhost) ───────────────
echo "Starting Chromium with persistent profile at /data/profile..."
chromium \
  --no-sandbox \
  --user-data-dir=/data/profile \
  --remote-debugging-port=9222 \
  --remote-debugging-address=127.0.0.1 \
  --remote-allow-origins=* \
  --window-size=1920,1080 \
  --no-first-run \
  --no-default-browser-check \
  --disable-session-crashed-bubble \
  --hide-crash-restore-bubble \
  --disable-features=Translate \
  --lang=en-US \
  "https://www.youtube.com" &

# ── Cookie exporter (main process) ────────────────────────────────
exec python3 /app/cookie_exporter.py
