# ytcookies

Docker container running a real Chromium browser (noVNC viewable in your
browser) for logging into YouTube, with a yt-dlp-compatible Netscape cookies
file on a volume mount.

## How it works
- Chromium runs headless (Xvfb) with a **persistent profile** at ./data/profile,
  so the login survives container rebuilds/restarts like a normal browser.
- noVNC lets you log in / re-authenticate from any browser (remotely via the
  public URL in `VNC_URL`, see Access; the in-container websockify port is
  bound to the host loopback only).
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
involved.

The vault tab otherwise idles on `about:blank` (owner's invariant): a warm
signed-in page keeps rotating the browser's cookie copy and fights the
consumers' write-backs on the file, so the tab only ever sits in a Google
flow while an auth procedure is actively running. Every park is verified
(location.href read-back, one retry).

On death it logs `SESSION DEAD`, pushes a notification (if configured),
tries a cheap re-seed of the file from the browser jar (covers the
"jar still holds a live session" edge), and if the state is still down
runs the explicit refresh: the sign-in navigation is issued and where it
lands decides the outcome:
- **base session alive** -> the flow bounces to the signed-in destination
  and the exchange mints a fresh SID into the jar; the exporter harvests
  it into the file, confirms liveness server-side, parks the tab ->
  `SESSION UP` with no password involved;
- **base session dead** -> the flow is staged as far as possible (clicks
  the remembered account, prefills the email, dismisses onboarding cards)
  and left at the password step for the auto sign-in daemon or a human via
  noVNC; the tab sitting in the auth flow IS the active procedure.
If the browser profile ever loses its login while the file is still live
(container restart, profile wipe), the file is imported back into the
browser, the tab loads YouTube once so the imported cookies apply, and
parks on `about:blank` again.
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
- `VNC_URL` — public URL of the noVNC backstop door, quoted in those pushes so
  a human knows where to sign in (unset: the messages just say "via noVNC")
- `COOKIE_SESSION_PROBE` — liveness probe interval in seconds (default 630; offset from the consumers' ~10-min write-back cadence)
- `GOOGLE_EMAIL` — account shown in the sign-in chooser; the exporter clicks it when the session dies
- `DRIVEPOD_API_URL` — DrivePod backend for UA sync (default `http://drivepod:3000` on the docker `shared` network)
- `GRABBY_API_URL` — GrabbyTube API for UA sync (default `http://grabbytube:8101`)
- `GOOGLE_PASSWORD` — account password; when set the entrypoint starts the auto sign-in daemon (below)
- `AUTO_SIGNIN_DELAY_MIN` / `AUTO_SIGNIN_DELAY_MAX` — fuzzed pre-typing delay window, seconds (default 240–1500)
- `AUTO_SIGNIN_FLOW_MAX_AGE` — max age (seconds) of the sign-in flow before the daemon re-opens it before typing (default 600); Google v3 flows expire server-side after ~20 min and a stale flow fails with a generic error page
- `AUTO_SIGNIN_MAX_ATTEMPTS` — total attempts per kill before escalating to manual re-auth (default 3); only transient failures are retried

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
- **anything transient** (flow error page, page-flow change, dropped
  keystrokes, VNC hiccup) — the daemon waits another fuzzed window and
  retries, up to `AUTO_SIGNIN_MAX_ATTEMPTS` attempts in total.
- **needs a human** (2FA / verification challenge, captcha, wrong
  password) — the daemon stops, pushes `manual re-auth needed` to ntfy,
  and waits. Sign in via noVNC as before; when the session is up again
  the daemon re-arms for the next kill.

Before typing, the daemon checks the flow's age from the URL's `dsh`
stamp: a Google v3 sign-in flow is a server-side session that dies after
~20 min, and a password submitted to a stale flow fails with the generic
"Something went wrong" page. A flow older than `AUTO_SIGNIN_FLOW_MAX_AGE`
is re-opened (fresh navigation + re-stage) so the password always lands
in a fresh flow.

After a successful password check, Google can hold the (already
authenticated) flow at post-verification onboarding cards
(`gds.google.com`: "Make sure you can always sign in" — add a recovery
phone/email — "Set a home address", ...). The cards are sticky: navigating
away bounces straight back to the card, and they block a sign-in that has
already passed the password check. The daemon therefore clicks each card's
skip/cancel button (real pointer, like everything else) until the flow
reaches the destination — both while staging and while watching the result;
the exporter's pre-staging does the same with CDP clicks. A card without a
recognizable skip button is a transient failure (retried, then escalated
like any other).

The daemon never touches the cookie file — the exporter stays the single
source of truth. All timing (pre-typing delay, keystroke rhythm) is
fuzzed so the re-auth does not look machine-paced.

## Access
- `VNC_URL` in .env names the public URL of the noVNC backstop door (the same
  value the ntfy session messages quote). Behind it: HTTP basic auth on top of
  the VNC password. Basic-auth user `novnc`, password is `NOVNC_HTTP_PASS` in
  .env (nginx htpasswd on the VPS); the VNC password is `VNC_PASSWORD` in .env.
  The vhost is rate-limited (5 r/s, burst 20).
- Cookie file: ./data/cookies.txt (the `./data` volume mount)

## Using the cookies with yt-dlp
    yt-dlp --cookies <repo>/data/cookies.txt <url>

For other yt-dlp services on the LAN, mount this container's data dir and
point them at data/cookies.txt.

## Ops
    cd <repo>   # this project's directory
    docker compose build && docker compose up -d
    docker logs -f ytcookies   # "[cookie-exporter] SESSION DEAD/UP, cookies exported: N total"

- WireGuard peer address from `WG_ADDRESS` in .env (WG key in .env, peer on the
  VPS wg0). `WG_DNS` in .env is the tunnel DNS the compose file hands the container.
- Docker network pinned to 172.33.0.0/16 — must not overlap the WG tunnel subnet.
- Cert: DNS-01 via the DNS provider in .env, renews automatically (certbot on the VPS).
- The entrypoint clears stale Chromium SingletonLock files on start (safe:
  only one container runs at a time).
- Single instance by construction: the exporter takes an exclusive `flock` on
  `./data/exporter.lock` for its whole run, so a stray second copy — e.g. a
  `docker exec ytcookies python3 /app/cookie_exporter.py …` whose client was
  killed, leaving it orphaned as PID 1's sibling — exits at once instead of
  running a second liveness state machine (which pushed every
  `session_dead`/`session_restored` twice, minutes apart, and raced the
  consumers' write-backs on the cookie file).
