# ytcookies

Docker container running a real Chromium browser (noVNC viewable in your
browser) for logging into YouTube, with a yt-dlp-compatible Netscape cookies
file on a volume mount.

## How it works
- Chromium runs headless (Xvfb) with a **persistent profile** at ./data/profile,
  so the login survives container rebuilds/restarts like a normal browser.
- noVNC (port 8300) lets you log in / re-authenticate from any browser.
- cookie_exporter.py watches the Chrome DevTools endpoint (localhost-only CDP).
  While the cookie file's session is dead it seeds ./data/cookies.txt (Netscape
  format) from the browser jar; a live file is never touched, because it is
  owned by the yt-dlp services' write-backs.

## Session watch
Google periodically kills sessions it deems suspicious (a datacenter IP is a
classic trigger). The cookie file is the source of truth for the yt-dlp
services (they write cookie updates back into it, and that steady state is what
Google tolerates for days/weeks), so the exporter never rewrites a live file —
the headless browser is just a sign-in vault.

Every ~10.5 min the exporter verifies the FILE's session server-side: one
GET https://www.youtube.com/account with the file's cookies. Live -> the
account page; killed -> 30x to accounts.google.com. No browser traffic is
involved. On death it logs `SESSION DEAD`, pushes a notification (if
configured), and pre-stages the sign-in page as far as possible (clicks the
remembered account or prefills the email) so re-auth is just typing the
password. When you sign in via noVNC, the exporter seeds the dead file from
the browser jar within ~30s and confirms liveness -> `SESSION UP` +
notification. If the browser profile ever loses its login while the file is
still live (container restart, profile wipe), the file is imported back into
the browser once so the vault stays warm.
If Google walls the sign-in flow with its CookieMismatch / session-expired
page (lingering killed-session cookies), the exporter does the full
"delete browsing data" clear itself (cookies + cache + site storage) and
restarts the flow — no manual clearing needed.

**User-Agent sync.** Google also correlates the client fingerprint of a
session: the session is created by the real Chromium in the vault, so the
cookie consumers must present the same UA, or the mismatch itself is a kill
signal. On startup the exporter reads the browser's live UA from CDP and
pushes it to DrivePod (`POST /api/config`) and GrabbyTube
(`POST /settings/user-agent`); both persist it in their own databases, so
it applies immediately and survives restarts. When an image rebuild bumps
the browser's version, the next exporter start re-syncs automatically — no
copy-pasting the UA from the noVNC browser. The exporter's own liveness
probe uses the same live UA.

The exporter also writes `session-state.json` next to the cookie file;
DrivePod skips harvest rounds while it says `down` (and is fresh, <30 min) —
a dead-session harvest would only worsen the kill, and its write-backs would
delay the post-sign-in re-seed.

Env vars (all optional):
- `NTFY_TOPIC` — ntfy.sh topic for `session_dead` / `session_restored` pushes
- `NOTIFY_WEBHOOK_URL` — POSTs `{event, detail, time}` JSON to this URL
- `COOKIE_SESSION_PROBE` — liveness probe interval in seconds (default 630; offset from the consumers' ~10-min write-back cadence)
- `GOOGLE_EMAIL` — account shown in the sign-in chooser; the exporter clicks it when the session dies
- `DRIVEPOD_API_URL` — DrivePod backend for UA sync (default `http://drivepod:3000` on the docker `shared` network)
- `GRABBY_API_URL` — GrabbyTube API for UA sync (default `http://grabbytube:8101`)
- `GOOGLE_PASSWORD` — account password; when set the entrypoint starts the auto sign-in daemon (below)
- `AUTO_SIGNIN_DELAY_MIN` / `AUTO_SIGNIN_DELAY_MAX` — fuzzed pre-typing delay window, seconds (default 240–1500)

## Auto sign-in

When `GOOGLE_PASSWORD` is set, the entrypoint starts a second background
daemon (`auto_signin.py`) next to the exporter. While the state file
says `down` it waits a fuzzed 4–25 min (skewed short), then types the
account email and password into the sign-in flow as real VNC keystrokes
(sibling `vncdriver` RFB client; CDP stays read-only) at a human typing
rhythm, and checks the result:

- **session restored** — the tab parks on about:blank and the exporter
  reseeds the cookie file from the fresh browser jar within ~30s →
  `SESSION UP`.
- **anything else** (2FA / verification challenge, captcha, wrong
  password, page-flow change) — the daemon stops, pushes
  `manual re-auth needed` to ntfy, and waits. Sign in via noVNC as
  before; when the session is up again the daemon re-arms for the
  next kill.

The daemon never touches the cookie file — the exporter stays the single
source of truth. All timing (pre-typing delay, keystroke rhythm) is
fuzzed so the re-auth does not look machine-paced.

## Access
- https://ytcookies.example.com  -> noVNC, password is VNC_PASSWORD in .env
- Cookie file: /home/user/projects/ytcookies/data/cookies.txt

## Using the cookies with yt-dlp
    yt-dlp --cookies /home/user/projects/ytcookies/data/cookies.txt <url>

For other yt-dlp services on the LAN, mount this container's data dir and
point them at data/cookies.txt.

## Ops
    cd /home/user/projects/ytcookies
    docker compose build && docker compose up -d
    docker logs -f ytcookies   # "[cookie-exporter] SESSION DEAD/UP, cookies exported: N total"

- WireGuard peer 10.99.0.240 (WG key in .env, peer on vps wg0).
- Docker network pinned to 172.33.0.0/16 — must not overlap WG 10.99.0.0/20.
- Cert: DNS-01 via <dns-provider>, renews automatically (certbot 5.6.0 on vps).
- The entrypoint clears stale Chromium SingletonLock files on start (safe:
  only one container runs at a time).
