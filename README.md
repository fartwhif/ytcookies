# ytcookies

Docker container running a real Chromium browser (noVNC viewable in your
browser) for logging into YouTube, with a continuously refreshed,
yt-dlp-compatible Netscape cookies file on a volume mount.

## How it works
- Chromium runs headless (Xvfb) with a **persistent profile** at ./data/profile,
  so the login survives container rebuilds/restarts like a normal browser.
- noVNC (port 8300) lets you log in / re-authenticate from any browser.
- cookie_exporter.py polls the Chrome DevTools endpoint (localhost-only CDP)
  every 30s and atomically rewrites ./data/cookies.txt (Netscape format)
  only when the cookie jar actually changes.

## Access
- https://ytcookies.example.com  -> noVNC, password is VNC_PASSWORD in .env
- Cookie file: /home/user/projects/ytcookies/data/cookies.txt

## Using the cookies with yt-dlp
    yt-dlp --cookies /home/user/projects/ytcookies/data/cookies.txt <url>

For other yt-dlp services on the LAN, mount this container's data dir and
point them at data/cookies.txt.

## Ops
    cd /home/user/projects/ytcookies
    docker compose build && docker compose create --force-recreate && docker start ytcookies
    docker logs -f ytcookies   # "[cookie-exporter] cookies exported: N total"

- WireGuard peer 10.99.0.240 (WG key in .env, peer added on vps wg0).
- Docker network pinned to 172.33.0.0/16 — must not overlap WG 10.99.0.0/20.
- Cert: DNS-01 via <dns-provider>, renews automatically (certbot 5.6.0 on vps).
- The entrypoint clears stale Chromium SingletonLock files on start (safe:
  only one container runs at a time).
