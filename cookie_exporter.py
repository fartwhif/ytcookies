#!/usr/bin/env python3
"""Keep a yt-dlp compatible Netscape cookies file usable.

Division of labor (this matters!):

- The cookie FILE is owned by the yt-dlp services. Every yt-dlp run writes
  the cookie updates it observed back into the file, and that steady state
  is what Google tolerates for days/weeks.
- The browser (persistent profile, noVNC-accessible) is a sign-in VAULT.
  The exporter seeds the file from the browser jar only while the file's
  session is dead. Once the file is live, the exporter never touches it —
  a running exporter clobbering the write-back-maintained file is exactly
  what used to kill sessions.
- Session watch does not use the browser at all: every
  SESSION_PROBE_INTERVAL seconds a single GET https://www.youtube.com/account
  with the file's cookies decides whether the session is alive server-side
  (live -> the account page; dead -> 30x to accounts.google.com). One cheap
  request, zero headless-browser traffic.

On death: logs SESSION DEAD, pushes a notification (ntfy/webhook), and
pre-stages the sign-in page (clicks the remembered account / prefills the
email) so re-auth is just typing the password. When the browser jar gains a
login (fresh VNC sign-in) the exporter seeds the dead file and confirms the
file is live again -> SESSION UP. When the browser profile loses its login
while the file is still live (container restart, profile wipe), the file is
imported back into the browser so the vault stays warm.
"""

import json
import os
import time
import urllib.error
import urllib.request

import websocket  # websocket-client

CDP_HOST = os.environ.get("CDP_HOST", "127.0.0.1")
CDP_PORT = int(os.environ.get("CDP_PORT", "9222"))
OUT_PATH = os.environ.get("COOKIES_FILE", "/data/cookies.txt")
# Session liveness file for consumers: DrivePod skips harvest rounds while
# the shared cookie file's session is dead (dead-cookie harvests only
# hammer Google and their write-backs delay our re-seed).
SESSION_STATE_PATH = os.environ.get("COOKIE_SESSION_STATE", "/data/session-state.json")
POLL_SECONDS = int(os.environ.get("COOKIE_POLL_INTERVAL", "30"))
# If the cookies file was written from outside (yt-dlp write-back), don't
# overwrite it for this long.
EXTERNAL_WRITE_COOLDOWN = int(os.environ.get("COOKIE_EXTERNAL_COOLDOWN", "120"))
# How often to verify the FILE's session is alive server-side (one HTTP GET,
# no browser involved). 630s (not 600) so the probe stays out of lockstep
# with the ~10-min consumer write-back cycles that keep the file mtime fresh.
SESSION_PROBE_INTERVAL = int(os.environ.get("COOKIE_SESSION_PROBE", "630"))
# Notification channels for session death/recovery (both optional).
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()
NOTIFY_WEBHOOK_URL = os.environ.get("NOTIFY_WEBHOOK_URL", "").strip()
# Google account email; prefilled/clicked on the sign-in page when the
# session dies.
GOOGLE_EMAIL = os.environ.get("GOOGLE_EMAIL", "").strip()
# The auto re-auth daemon (auto_signin.py) is started by the entrypoint
# when the password is configured; the death notification reflects that.
AUTO_SIGNIN = bool(os.environ.get("GOOGLE_PASSWORD", "").strip())

# The consumer services must present the SAME user agent as the browser that
# created the session (a mismatched UA on the same session is a kill signal).
# The exporter reads the browser's live UA and pushes it to them.
DRIVEPOD_API_URL = os.environ.get("DRIVEPOD_API_URL", "http://drivepod:3000")
GRABBY_API_URL = os.environ.get("GRABBY_API_URL", "http://grabbytube:8101")

# Fallback UA for probes while the browser's UA is not yet known.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
)
PROBE_USER_AGENT = USER_AGENT


def log(msg: str) -> None:
    print(f"[cookie-exporter {time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def http_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.load(resp)


def cdp_call(ws, msg_id: int, method: str, params: dict | None = None) -> dict:
    ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
    while True:
        msg = json.loads(ws.recv())
        if msg.get("id") == msg_id:
            if "error" in msg:
                raise RuntimeError(f"CDP error for {method}: {msg['error']}")
            return msg.get("result", {})


def open_ws() -> "websocket.WebSocket":
    version = http_json(f"http://{CDP_HOST}:{CDP_PORT}/json/version")
    return websocket.create_connection(
        version["webSocketDebuggerUrl"], timeout=15, origin=""
    )


def fetch_cookies() -> list:
    ws = open_ws()
    try:
        result = cdp_call(ws, 1, "Storage.getCookies")
    finally:
        ws.close()
    return result.get("cookies", [])


def cookie_fingerprint(cookies: list) -> str:
    """Stable fingerprint of the cookie set (order-independent)."""
    items = sorted(
        (
            c.get("domain", ""),
            c.get("path", ""),
            c.get("name", ""),
            c.get("value", ""),
            int(c.get("expirationDate") or 0),
            bool(c.get("secure")),
            bool(c.get("hostOnly")),
        )
        for c in cookies
    )
    return json.dumps(items)


def to_netscape(cookies: list) -> str:
    lines = [
        "# Netscape HTTP Cookie File",
        "# https://curl.se/docs/http-cookies.html",
        "# This file was generated by ytcookies. Do not edit.",
        "",
    ]
    for c in cookies:
        domain = c.get("domain", "")
        host_only = bool(c.get("hostOnly"))
        if host_only:
            dom = domain.lstrip(".")
            sub_domains = "FALSE"
        else:
            dom = domain if domain.startswith(".") else "." + domain
            sub_domains = "TRUE"
        expires = c.get("expirationDate") or 0
        exp = int(expires) if expires and expires > 0 else 0  # 0 = session cookie
        name = str(c.get("name", "")).replace("\r", "\\r").replace("\n", "\\n")
        value = str(c.get("value", "")).replace("\r", "\\r").replace("\n", "\\n")
        lines.append(
            "\t".join(
                [
                    dom,
                    sub_domains,
                    c.get("path", "/"),
                    "TRUE" if c.get("secure") else "FALSE",
                    str(exp),
                    name,
                    value,
                ]
            )
        )
    return "\n".join(lines) + "\n"


def atomic_write(path: str, content: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# File session watch: prove the FILE's session is alive server-side with a
# single page load (no browser involved), and notify on state transitions.
# ---------------------------------------------------------------------------

def notify(event: str, detail: str) -> None:
    """Best-effort push of a session event to the configured channels."""
    text = f"ytcookies {event}: {detail}"
    if NTFY_TOPIC:
        try:
            req = urllib.request.Request(
                f"https://ntfy.sh/{NTFY_TOPIC}",
                data=text.encode(),
                headers={
                    "Title": "ytcookies " + event,
                    "Priority": "high" if "dead" in event else "default",
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as exc:
            log(f"ntfy notify failed: {exc}")
    if NOTIFY_WEBHOOK_URL:
        try:
            payload = json.dumps(
                {
                    "event": event,
                    "detail": detail,
                    "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            ).encode()
            req = urllib.request.Request(
                NOTIFY_WEBHOOK_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as exc:
            log(f"webhook notify failed: {exc}")


def file_cookie_header() -> str | None:
    """Cookie header built from the file's youtube.com cookies."""
    pairs = []
    for c in parse_netscape(OUT_PATH):
        dom = (c.get("domain") or "").lstrip(".")
        if dom == "youtube.com" or dom.endswith(".youtube.com"):
            pairs.append(f"{c['name']}={c['value']}")
    return "; ".join(pairs) or None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def probe_file() -> bool | None:
    """Check the FILE's session server-side. Returns True (alive), False
    (dead), None (inconclusive).

    One GET https://www.youtube.com/account with the file's cookies: a live
    session serves the account page (200), a dead one is bounced 30x to
    accounts.google.com.
    """
    header = file_cookie_header()
    if not header:
        return None
    req = urllib.request.Request(
        "https://www.youtube.com/account",
        headers={
            "Cookie": header,
            "User-Agent": PROBE_USER_AGENT,
            "Accept": "text/html",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(req, timeout=20)
        url = resp.geturl()
        resp.read()
        if "accounts.google.com" in url:
            return False
        return "youtube.com" in url
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            loc = e.headers.get("Location", "")
            if loc:
                return "accounts.google.com" not in loc
        return None
    except Exception:
        return None


def write_session_state(state: str) -> None:
    """Persist session liveness next to the cookie file (DrivePod gates its
    harvester on it; tunester reads the browser UA from it). Atomic, so a
    reader never sees a partial file."""
    payload = {"state": state, "ts": int(time.time())}
    if LIVE_UA is not None:
        payload["ua"] = LIVE_UA
    try:
        atomic_write(SESSION_STATE_PATH, json.dumps(payload) + "\n")
    except OSError as exc:
        log(f"session-state write failed: {exc}")


def _export_if_ok(cookies: list, reason: str) -> bool:
    """Atomically write the jar to OUT_PATH. Returns False (and logs) while
    the external-write cooldown is active."""
    mtime = os.path.getmtime(OUT_PATH) if os.path.exists(OUT_PATH) else 0
    if time.time() - mtime < EXTERNAL_WRITE_COOLDOWN:
        log(f"file modified externally {int(time.time()-mtime)}s ago (yt-dlp write-back?) - holding off {EXTERNAL_WRITE_COOLDOWN - int(time.time()-mtime)}s")
        return False
    atomic_write(OUT_PATH, to_netscape(cookies))
    yt = sum(1 for c in cookies if "youtube.com" in (c.get("domain") or ""))
    log(f"cookies exported: {len(cookies)} total ({yt} youtube.com) [{reason}]")
    return True


_STAGE_JS = """
(function(){
  const vis = x => !!(x && (x.offsetWidth || x.offsetHeight || x.getClientRects().length));
  if (/something went wrong/i.test(document.body ? document.body.innerText : '')) {
    const btn = [...document.querySelectorAll('button')].find(b =>
      (b.innerText || '').trim() === 'Restart' && vis(b));
    if (btn) { btn.click(); return 'restart clicked'; }
  }
  // The v3 flow keeps a hidden input[name=hiddenPassword] on the
  // identifier page, so only a VISIBLE password field means the flow
  // has actually reached the password step.
  if ([...document.querySelectorAll('input[type=password]')].some(vis)) return 'password step ready';
  const email = __EMAIL__;
  if (email) {
    const all = [...document.querySelectorAll('*')];
    const leaves = all.filter(
      el => el.children.length === 0 && el.textContent.includes(email)
    );
    let el = leaves[0];
    while (el && el !== document.body) {
      const r = el.getAttribute('role');
      if (r === 'link' || r === 'button' || el.tagName === 'A' || el.tagName === 'BUTTON') break;
      el = el.parentElement;
    }
    if (el && el !== document.body) { el.click(); return 'account selected'; }
  }
  const i = document.querySelector('input[name=identifier]') || document.querySelector('#identifierId');
  if (i && vis(i)) {
    const s = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    ).set;
    s.call(i, email);
    i.dispatchEvent(new Event('input', {bubbles: true}));
    i.focus();
    // Deliberately NOT clicking Next: the submit is the Google-visible
    // step and is paced like a person by the auto sign-in daemon (or a
    // human via noVNC).
    return i.value === email ? 'email prefilled' : 'prefill rejected';
  }
  return 'no target yet';
})()
"""

def _stage_js() -> str:
    return _STAGE_JS.replace("__EMAIL__", json.dumps(GOOGLE_EMAIL))


BLOCKED_SIGNIN_MARKERS = ("CookieMismatch", "info/sessionexpired")


def _stage_poll(ws, expr: str, msg_id: int = 10) -> str:
    """Poll the page for a stageable target; returns the stage result string."""
    for _ in range(12):
        time.sleep(1)
        res = cdp_call(
            ws,
            msg_id,
            "Runtime.evaluate",
            {"expression": expr, "returnByValue": True},
        )
        msg_id += 1
        result = str((res.get("result") or {}).get("value") or "no target yet")
        if result in ("account selected", "restart clicked"):
            time.sleep(4)  # let the password step load
            res = cdp_call(
                ws,
                msg_id,
                "Runtime.evaluate",
                {"expression": expr, "returnByValue": True},
            )
            msg_id += 1
            after = str((res.get("result") or {}).get("value") or "")
            return f"{result} -> {after}"
        if result != "no target yet":
            return result
    return "no target yet"


def _clear_browser_state(ws) -> None:
    """Full vault reset: cookies, cache, and Google/YouTube site storage
    (localStorage/IndexedDB/Cache). Mirrors the 'delete browsing data'
    workaround for the CookieMismatch wall, which a cookies-only clear does
    not get past. The cookie file on disk is never touched."""
    mid = 200
    cdp_call(ws, mid, "Network.enable")
    mid += 1
    cdp_call(ws, mid, "Network.clearBrowserCache")
    mid += 1
    cdp_call(ws, mid, "Storage.clearCookies")
    mid += 1
    for origin in (
        "https://accounts.google.com",
        "https://www.google.com",
        "https://www.youtube.com",
    ):
        cdp_call(
            ws,
            mid,
            "Storage.clearDataForOrigin",
            {
                "origin": origin,
                "storageTypes": "local_storage, indexeddb, cache_storage",
            },
        )
        mid += 1
    log("vault cleared: cookies, cache, and site storage")


def prepare_resignin() -> None:
    """Bring the visible tab as close to the password step as possible so
    manual re-auth is just typing the password. Never disturbs a tab already
    at the password step. Handles the account chooser (clicks the remembered
    account) and the identifier page (prefills the email). If the flow is
    walled off by Google's CookieMismatch / session-expired page, clears the
    vault and retries once."""
    try:
        targets = http_json(f"http://{CDP_HOST}:{CDP_PORT}/json")
        pages = [t for t in targets if t.get("type") == "page"]
        if not pages:
            return
        ws = websocket.create_connection(
            pages[0]["webSocketDebuggerUrl"], timeout=15, origin=""
        )
        try:
            cur = cdp_call(
                ws,
                1,
                "Runtime.evaluate",
                {"expression": "location.href", "returnByValue": True},
            )
            cur = str((cur.get("result") or {}).get("value") or "")
            if "accounts.google.com" not in cur:
                cdp_call(ws, 2, "Page.enable")
                cdp_call(ws, 3, "Page.navigate", {"url": "https://www.youtube.com/signin"})
            expr = _stage_js()
            result = _stage_poll(ws, expr)
            if result == "no target yet":
                now = cdp_call(
                    ws,
                    50,
                    "Runtime.evaluate",
                    {"expression": "location.href", "returnByValue": True},
                )
                now = str((now.get("result") or {}).get("value") or "")
                if any(marker in now for marker in BLOCKED_SIGNIN_MARKERS):
                    log("sign-in blocked by cookie mismatch; clearing vault and retrying")
                    _clear_browser_state(ws)
                    cdp_call(ws, 300, "Page.enable")
                    cdp_call(ws, 301, "Page.navigate", {"url": "https://www.youtube.com/signin"})
                    result = _stage_poll(ws, expr, msg_id=400)
                    log(f"re-sign-in prepared (after vault clear): {result}")
                    return
                log(f"re-sign-in prepared: no target; page at {now or 'unknown URL'}")
                return
            log(f"re-sign-in prepared: {result}")
        finally:
            ws.close()
    except Exception as exc:
        log(f"prepare_resignin failed: {exc}")


# ---------------------------------------------------------------------------
# Vault restoration: the file as source of truth for the browser profile
# ---------------------------------------------------------------------------
# If the browser has no login of its own but the file holds one (profile
# wipe, container restart, killed profile session), import the file's
# cookies into the browser. One attempt per file version; never overwrites
# a live browser login, so Google cookie rotations in the live session are
# never reverted by stale file values.

LOGIN_DOMAIN = "youtube.com"
IMPORT_RETRY_S = int(os.environ.get("COOKIE_IMPORT_RETRY", "60"))
_last_import_attempt = 0.0
_last_imported_fp = None


def parse_netscape(path: str) -> list:
    """Parse a Netscape cookies file into CDP Storage.setCookies dicts."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return out
    now = time.time()
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 7:
            continue
        domain, _sub, cpath, secure, expires_s, name, value = parts
        if not name or name.lower() == "value":
            continue
        # __Host-* cookies must be host-only; the Netscape dot form is
        # rejected by CDP, so drop the leading dot.
        if name.startswith("__Host-") and domain.startswith("."):
            domain = domain[1:]
        try:
            exp = int(float(expires_s))
        except ValueError:
            exp = 0
        if exp and exp <= now:
            continue  # skip expired
        cookie = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": cpath or "/",
            "secure": secure == "TRUE",
            "httpOnly": line.startswith("#HttpOnly_"),
        }
        if exp > 0:
            cookie["expires"] = exp
        out.append(cookie)
    return out


def _cookies_have_login(cookies: list, key="name") -> bool:
    """Heuristic: does this cookie set look like a valid YouTube login?"""
    by_name = {}
    for c in cookies:
        dom = c.get("domain") or ""
        if LOGIN_DOMAIN in dom:
            by_name.setdefault(c.get(key, ""), c.get("value"))
    if by_name.get("login_info"):
        return True
    if by_name.get("SID") and by_name.get("HSID"):
        return True
    # Partitioned session-cookie family: Google now issues
    # __Secure-1PSID/__Secure-3PSID (+TS, +PAPISID) instead of SID/HSID.
    for psid in ("__Secure-1PSID", "__Secure-3PSID"):
        if by_name.get(psid) and by_name.get(psid + "TS"):
            return True
    return False


def navigate_to_youtube() -> None:
    """Reload the first page target at YouTube so imported cookies apply."""
    try:
        targets = http_json(f"http://{CDP_HOST}:{CDP_PORT}/json")
        pages = [t for t in targets if t.get("type") == "page"]
        if not pages:
            log("no page target found for navigate; skipping")
            return
        ws = websocket.create_connection(
            pages[0]["webSocketDebuggerUrl"], timeout=15, origin=""
        )
        try:
            cdp_call(ws, 1, "Page.enable")
            cdp_call(ws, 2, "Page.navigate", {"url": "https://www.youtube.com"})
            log("reloaded YouTube page to activate imported cookies")
        finally:
            ws.close()
    except Exception as exc:
        log(f"navigate failed: {exc}")


def maybe_import(cookies: list) -> bool:
    """Vault restoration. Returns True if the browser was re-seeded."""
    global _last_import_attempt, _last_imported_fp
    if _cookies_have_login(cookies):
        return False  # live session: never overwrite with file values
    if time.time() - _last_import_attempt < IMPORT_RETRY_S:
        return False
    if not os.path.exists(OUT_PATH):
        return False
    try:
        file_fp = os.path.getmtime(OUT_PATH)
    except OSError:
        return False
    if _last_imported_fp == file_fp:
        return False  # already tried importing this exact file version
    _last_import_attempt = time.time()
    _last_imported_fp = file_fp
    file_cookies = parse_netscape(OUT_PATH)
    if not file_cookies:
        log("browser logged out; cookies.txt empty/unreadable")
        return False
    if not _cookies_have_login(file_cookies):
        log("browser logged out; cookies.txt has no valid YouTube login to import")
        return False
    ws = open_ws()
    try:
        cdp_call(ws, 1, "Storage.setCookies", {"cookies": file_cookies})
    finally:
        ws.close()
    log(f"imported {len(file_cookies)} cookies from {OUT_PATH} into browser")
    navigate_to_youtube()
    return True


LIVE_UA: str | None = None  # last UA read from the browser (source of truth)

def browser_user_agent() -> str | None:
    """The browser's real UA from CDP /json/version (None while CDP is down)."""
    global LIVE_UA
    try:
        ua = http_json(f"http://{CDP_HOST}:{CDP_PORT}/json/version").get("User-Agent")
        if ua:
            LIVE_UA = ua
        return ua
    except Exception:
        return None


def _http_post_json(url: str, payload: dict) -> bool:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def sync_user_agent() -> tuple[bool, str]:
    """Push the browser's UA to the cookie consumers (DrivePod, GrabbyTube).
    Returns (ok, summary). Both services persist the value themselves, so a
    single success is permanent until the browser's UA changes (rebuild)."""
    global PROBE_USER_AGENT
    ua = browser_user_agent()
    if not ua:
        return False, "ua sync: browser UA unavailable (CDP down)"
    PROBE_USER_AGENT = ua
    dp = _http_post_json(f"{DRIVEPOD_API_URL}/api/config", {"userAgent": ua})
    gt = _http_post_json(f"{GRABBY_API_URL}/settings/user-agent", {"user_agent": ua})
    try:
        chrome = ua.split("Chrome/", 1)[1].split(" ", 1)[0]
    except IndexError:
        chrome = "?"
    return (dp and gt), (
        f"user-agent synced: Chrome/{chrome} "
        f"drivepod={'ok' if dp else 'fail'} grabbytube={'ok' if gt else 'fail'}"
    )


def main() -> None:
    channels = "+".join(
        [n for n, v in (("ntfy", NTFY_TOPIC), ("webhook", NOTIFY_WEBHOOK_URL)) if v]
    ) or "none"
    log(
        f"starting: cdp={CDP_HOST}:{CDP_PORT} out={OUT_PATH} "
        f"poll={POLL_SECONDS}s probe={SESSION_PROBE_INTERVAL}s notify={channels}"
    )
    write_session_state("unknown")
    last_fp = None
    state = "unknown"  # liveness of the FILE's session: unknown | up | down
    state_since = time.time()
    last_probe = 0.0
    last_confirm = 0.0
    prev_jar_login: bool | None = None  # jar login state at last probe
    ua_synced = False
    ua_last_log = 0.0

    while True:
        try:
            cookies = fetch_cookies()
            fp = cookie_fingerprint(cookies)
            jar_login = _cookies_have_login(cookies)
        except Exception as exc:
            log(f"jar fetch failed (browser/CDP {CDP_HOST}:{CDP_PORT}): {exc}")
            cookies, fp, jar_login = None, None, None

        # ---- user-agent sync (once; retried until both consumers accept) ----
        if not ua_synced:
            try:
                ok, summary = sync_user_agent()
            except Exception as exc:
                ok, summary = False, f"ua sync failed: {exc}"
            if ok:
                ua_synced = True
                log(summary)
                write_session_state(state)
            elif time.time() - ua_last_log >= 300:
                ua_last_log = time.time()
                log(summary)

        # ---- file session liveness (no browser required) ----
        if time.time() - last_probe >= SESSION_PROBE_INTERVAL:
            last_probe = time.time()
            file_alive = probe_file()
            if file_alive is not None:
                if file_alive:
                    if state != "up":
                        log(f"SESSION UP (file live; was '{state}')")
                        if state == "down":
                            notify(
                                "session_restored",
                                "cookie file session is live again",
                            )
                        state, state_since = "up", time.time()
                    # Vault restoration: the browser lost its login (or never
                    # had one after a restart) while the file is still live.
                    if (
                        cookies is not None
                        and not jar_login
                        and prev_jar_login in (None, True)
                    ):
                        maybe_import(cookies)
                else:
                    if state != "down":
                        since = time.strftime("%H:%M:%S", time.gmtime(state_since))
                        log(
                            f"SESSION DEAD (file session killed; "
                            f"was '{state}' since {since} UTC)"
                        )
                        if AUTO_SIGNIN:
                            detail = (
                                "cookie file session killed by Google; auto "
                                "re-auth in progress (manual fallback: noVNC "
                                "ytcookies.example.com)"
                            )
                        else:
                            detail = (
                                "cookie file session killed by Google; re-sign "
                                "in via noVNC (ytcookies.example.com)"
                            )
                        notify("session_dead", detail)
                        state, state_since = "down", time.time()
                    if cookies is not None:
                        if jar_login and _export_if_ok(
                            cookies, "file dead; browser jar has a login"
                        ):
                            last_fp = fp
                            if probe_file():
                                state, state_since = "up", time.time()
                                log("SESSION UP (file re-seeded from browser jar)")
                                notify(
                                    "session_restored",
                                    "file re-seeded from the browser jar",
                                )
                            else:
                                log("seeded jar is also dead server-side")
                        if state == "down":
                            # Re-stage the password step: idempotent (no-op at
                            # the password step) and never touches the file, so
                            # it also covers "jar has no login" and "seed
                            # blocked by an in-flight write-back".
                            prepare_resignin()
            if cookies is not None:
                prev_jar_login = jar_login
            write_session_state(state)

        # ---- fast path: seed a dead file as soon as the jar changes ----
        if cookies is not None and state != "up" and jar_login and fp != last_fp:
            if _export_if_ok(cookies, "jar changed while file not live"):
                last_fp = fp
                if time.time() - last_confirm >= 60:
                    last_confirm = time.time()
                    if probe_file():
                        state, state_since = "up", time.time()
                        write_session_state(state)
                        log("SESSION UP (file re-seeded from browser jar)")
                        notify(
                            "session_restored",
                            "file re-seeded from the browser jar",
                        )
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
