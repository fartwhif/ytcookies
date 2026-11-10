#!/usr/bin/env python3
"""Auto re-auth for the ytcookies sign-in vault.

cookie_exporter.py is the source of truth: it probes the cookie file's
session server-side, flips /data/session-state.json to "down" on death,
and keeps the headless browser staged in the sign-in flow. This daemon
completes what used to be the manual noVNC step: while the state is
"down" it waits a human-like fuzzed delay, then drives the browser
through email -> Next -> password -> Next over CDP and verifies the
outcome.

Design constraints:

- Never touches the cookie file (owned by the exporter + consumers).
- All timing is fuzzed — the pre-typing delay and the typing rhythm —
  so the re-auth does not look machine-paced to the sign-in flow.
- One attempt per kill: if the attempt cannot restore the session
  (2FA, challenge, wrong password, page-flow change) the daemon stops
  and pushes a notification; a human signs in via noVNC and the daemon
  re-arms when the state flips back to "up".
- The daemon never exits: unexpected errors are logged and the loop
  continues.
"""

import fcntl
import json
import os
import re
import random
import time
import urllib.request

import websocket  # websocket-client

CDP_HOST = os.environ.get("CDP_HOST", "127.0.0.1")
CDP_PORT = int(os.environ.get("CDP_PORT", "9222"))
SESSION_STATE_PATH = os.environ.get("COOKIE_SESSION_STATE", "/data/session-state.json")
EMAIL = os.environ.get("GOOGLE_EMAIL", "").strip()
PASSWORD = os.environ.get("GOOGLE_PASSWORD", "").strip()
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()
NOTIFY_WEBHOOK_URL = os.environ.get("NOTIFY_WEBHOOK_URL", "").strip()
# Same backstop-door hint as the exporter: env-supplied, never hardcoded.
VNC_URL = os.environ.get("VNC_URL", "").strip()
VNC_HINT = f"noVNC {VNC_URL}" if VNC_URL else "noVNC"
VNC_DRIVER_URL = os.environ.get("VNC_DRIVER_URL", "http://vncdriver:8123")
POLL_SECONDS = int(os.environ.get("AUTO_SIGNIN_POLL", "30"))
# Fuzzed delay (seconds) between "session down" and actually typing.
DELAY_MIN = int(os.environ.get("AUTO_SIGNIN_DELAY_MIN", "240"))
DELAY_MAX = int(os.environ.get("AUTO_SIGNIN_DELAY_MAX", "1500"))
# Stand-down (seconds) after a successful sign-in: give the exporter
# time to seed the file from the fresh jar and confirm liveness.
SUCCESS_COOLDOWN = 300
# Never run two attempts at once, and never re-attempt within this window:
# a concurrent daemon + manual run interleaves keystrokes and burns strikes,
# and the window also paces the strike count for the account.
REENTRY_GUARD = 1800
# Google's v3 sign-in flow is a server-side session with a ~20-min
# lifetime; submitting a stale flow (staged long before the password is
# typed) returns the generic "Something went wrong" page instead of a
# real verdict. Re-open the flow before typing when its URL dsh stamp is
# older than this.
FLOW_MAX_AGE = int(os.environ.get("AUTO_SIGNIN_FLOW_MAX_AGE", "600"))
# Total attempts per kill. Transient outcomes (RETRYABLE) are retried
# with a fresh fuzzed delay; wrong_password / 2fa / challenge escalate to
# a human immediately (retrying a wrong password just burns strikes).
MAX_ATTEMPTS = int(os.environ.get("AUTO_SIGNIN_MAX_ATTEMPTS", "3"))
RETRYABLE = ("error_page", "staging_failed", "vnc_type_failed", "vnc_unreachable")
_DATA_DIR = os.path.dirname(SESSION_STATE_PATH) or "/"
SIGNIN_LOCK = os.path.join(_DATA_DIR, "signin.lock")
ATTEMPT_MARK = os.path.join(_DATA_DIR, "attempted.json")


def log(msg: str) -> None:
    print(f"[auto-signin {time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def http_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.load(resp)


def vnc_request(path: str, payload: dict | None = None):
    """POST the sibling vncdriver's HTTP API (real X input / screen).
    Returns (ok, body)."""
    url = VNC_DRIVER_URL.rstrip("/") + path
    req = urllib.request.Request(
        url,
        data=json.dumps(payload or {}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return True, json.load(resp)
    except Exception as exc:  # noqa: BLE001
        log(f"vncdriver {path} failed: {exc}")
        return False, {"error": str(exc)}


def _screen_center(rect_raw) -> tuple[int, int] | None:
    """Screen (X/VNC) center of a page-coord rect.

    The browser window sits at (0,0); the page viewport starts below the
    browser chrome, whose height is outerHeight - innerHeight.
    """
    if not rect_raw or rect_raw == "null":
        return None
    try:
        r = json.loads(rect_raw)
    except (TypeError, ValueError):
        return None
    if not r or r.get("width", 0) <= 0 or r.get("height", 0) <= 0:
        return None
    chrome = int(r.get("outerH", 0)) - int(r.get("innerH", 0))
    x = int(r["left"] + r["width"] / 2)
    y = int(chrome + r["top"] + r["height"] / 2)
    return x, y


def cdp_call(ws, msg_id: int, method: str, params: dict | None = None) -> dict:
    ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
    while True:
        msg = json.loads(ws.recv())
        if msg.get("id") == msg_id:
            return msg.get("result", {})


def read_state() -> str | None:
    """Current session liveness from the exporter's state file."""
    try:
        with open(SESSION_STATE_PATH) as f:
            return json.load(f).get("state")
    except Exception:
        return None


def notify(title: str, detail: str) -> None:
    """Best-effort push (same channels as the exporter)."""
    text = f"ytcookies {title}: {detail}"
    if NTFY_TOPIC:
        try:
            req = urllib.request.Request(
                f"https://ntfy.sh/{NTFY_TOPIC}",
                data=text.encode(),
                headers={"Title": "ytcookies " + title, "Priority": "high"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as exc:
            log(f"ntfy notify failed: {exc}")
    if NOTIFY_WEBHOOK_URL:
        try:
            payload = json.dumps(
                {
                    "event": title,
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


def fuzz(a: int, b: int) -> int:
    """Fuzzed delay in [a, b], skewed toward the short end (a person who
    got a push notification usually acts within a few minutes)."""
    return int(a + (b - a) * (random.random() ** 1.6))


def sleep_fuzzed(total: float, stop_pred) -> bool:
    """Sleep ~total seconds in fuzzed slices. Returns False if stop_pred()
    becomes true early (e.g. the session was resolved while waiting)."""
    end = time.time() + total
    while time.time() < end:
        try:
            if stop_pred():
                return False
        except Exception:
            pass
        time.sleep(random.uniform(6, 14))
    return True


# ---------------------------------------------------------------------------
# Page staging / typing. Google's v3 sign-in is a single React document
# that keeps hidden inputs for later steps in the DOM (a hidden
# input[name=hiddenPassword] sits on the identifier page), so every
# selector discriminates on visibility, not mere presence.
# ---------------------------------------------------------------------------

# Idempotent: advances the flow one step per call and settles at the
# password step. Chooser -> click remembered account; identifier ->
# prefill email + click Next; password step -> no-op.
_STAGE_JS = """
(function(){
  const vis = x => !!(x && (x.offsetWidth || x.offsetHeight || x.getClientRects().length));
  if (/something went wrong/i.test(document.body ? document.body.innerText : '')) {
    const btn = [...document.querySelectorAll('button')].find(b =>
      (b.innerText || '').trim() === 'Restart' && vis(b));
    if (btn) { btn.click(); return 'restart clicked'; }
  }
  if ([...document.querySelectorAll('input[type=password]')].some(vis)) return 'password step ready';
  const email = __EMAIL__;
  if (email) {
    const leaves = [...document.querySelectorAll('*')].filter(
      el => el.children.length === 0 && el.textContent.includes(email));
    let el = leaves[0];
    while (el && el !== document.body) {
      const r = el.getAttribute('role');
      if (r === 'link' || r === 'button' || el.tagName === 'A' || el.tagName === 'BUTTON') break;
      el = el.parentElement;
    }
    if (el && el !== document.body) { el.click(); return 'account selected'; }
  }
  const i = document.querySelector('input[name=identifier]') || document.querySelector('#identifierId');
  if (i && vis(i)) return 'email field ready';
  return 'no target yet';
})()
"""


def _stage_js() -> str:
    return _STAGE_JS.replace("__EMAIL__", json.dumps(EMAIL))


# Field-finder expressions (visibility-aware; the v3 flow keeps hidden
# inputs for later steps in the DOM, so the discriminant is visibility).
_EMAIL_FIELD_JS = (
    "(document.querySelector('input[name=identifier]') ||"
    " document.querySelector('#identifierId'))"
)
_PW_FIELD_JS = (
    "([...document.querySelectorAll('input[type=password]')]"
    ".find(x => x.name === 'Passwd' ||"
    " (x.offsetWidth || x.offsetHeight || x.getClientRects().length)))"
)

_PW_RECT_JS = (
    "((el)=>{"
    "if(!el||!(el.offsetWidth||el.offsetHeight||el.getClientRects().length))return null;"
    "const b=el.getBoundingClientRect();"
    "return JSON.stringify({left:b.left,top:b.top,width:b.width,height:b.height,"
    "innerH:window.innerHeight,outerH:window.outerHeight})"
    "})(" + _PW_FIELD_JS + ")"
)

_EMAIL_RECT_JS = (
    "((el)=>{"
    "if(!el||!(el.offsetWidth||el.offsetHeight||el.getClientRects().length))return null;"
    "const b=el.getBoundingClientRect();"
    "return JSON.stringify({left:b.left,top:b.top,width:b.width,height:b.height,"
    "innerH:window.innerHeight,outerH:window.outerHeight})"
    "})(" + _EMAIL_FIELD_JS + ")"
)

# Screen-space rect of the visible "Next" button (for the VNC click that
# submits the password: a real pointer event, not a CDP synthetic click).
_NEXT_RECT_JS = """
(function(){
  const vis = x => !!(x && (x.offsetWidth || x.offsetHeight || x.getClientRects().length));
  const btn = [...document.querySelectorAll('button')].find(b =>
    (b.innerText || '').trim() === 'Next' && vis(b));
  if (!btn) return null;
  const b = btn.getBoundingClientRect();
  return JSON.stringify({left:b.left, top:b.top, width:b.width, height:b.height,
    innerH: window.innerHeight, outerH: window.outerHeight});
})()
"""

# Post-verification onboarding cards. After a successful password check,
# Google can hold the (already authenticated) flow at a run of
# gds.google.com cards — "Make sure you can always sign in" (recovery
# phone/email), "Set a home address", ... — each dismissable via a
# skip/cancel button. The cards are sticky: navigating away (even to
# /signin) bounces straight back to the card, so the button is the only
# way through. The sign-in completes only after the last card is
# dismissed and the flow's continue= target is reached.
GDS_SKIP_WORDS = ("cancel", "skip", "not now", "no thanks", "later")

# Screen-space rect of the visible skip/cancel button on the current
# gds onboarding card (same shape as _NEXT_RECT_JS for _screen_center).
_GDS_SKIP_RECT_JS = """
(function(){
  const vis = x => !!(x && (x.offsetWidth || x.offsetHeight || x.getClientRects().length));
  const words = new Set(%s);
  const btn = [...document.querySelectorAll('button, a')].find(b => {
    if (!vis(b)) return false;
    const t = (b.innerText || '').trim().toLowerCase();
    const a = (b.getAttribute('aria-label') || '').trim().toLowerCase();
    return words.has(t) || words.has(a);
  });
  if (!btn) return null;
  const b = btn.getBoundingClientRect();
  return JSON.stringify({left:b.left, top:b.top, width:b.width, height:b.height,
    innerH: window.innerHeight, outerH: window.outerHeight});
})()
""" % json.dumps(list(GDS_SKIP_WORDS))

_STATE_JS = """
JSON.stringify({
  href: location.href,
  text: (document.body ? document.body.innerText : '').replace(/\\s+/g, ' ').slice(0, 300)
})
"""

# Outcomes that need a human.
CHALLENGE_MARKERS = (
    "2-step verification",
    "enter a code",
    "verification code",
    "type the text you hear",  # captcha
    "confirm it's you",
    "verify it's you",
    "unusual activity",
)


def _is_gds_card(href: str) -> bool:
    """A gds.google.com onboarding card: an interstitial holding a sign-in
    flow (always carries the continue= target of the pending auth)."""
    h = (href or "").lower()
    return "gds.google.com" in h and "continue=" in h


def _dismiss_gds_card(ws, mid: int) -> tuple[str, int]:
    """Click the skip/cancel button of the onboarding card on screen (real
    pointer via vncdriver, like every other button in this flow). Returns
    ('clicked' | 'no_button' | 'vnc_unreachable', mid)."""
    rect_raw = _eval(ws, mid, _GDS_SKIP_RECT_JS)
    mid += 1
    center = _screen_center(rect_raw)
    if not center:
        return "no_button", mid
    ok, _ = vnc_request("/click", {"x": center[0], "y": center[1]})
    return ("clicked" if ok else "vnc_unreachable"), mid


def _youtube_signed_in(ws, mid: int, href: str) -> tuple[bool, int]:
    """A YouTube destination page with no visible 'Sign in' button: the
    session is live in the browser (the flow completed outside this
    attempt's typing — the last card just landed, or a human signed in
    via noVNC while the state file was still 'down')."""
    if not href.startswith(("https://www.youtube.com", "https://m.youtube.com")):
        return False, mid
    js = (
        "(function(){if(document.readyState!=='complete')return false;"
        "const vis=x=>!!(x&&(x.offsetWidth||x.offsetHeight||"
        "x.getClientRects().length));return [...document.querySelectorAll("
        "'button, a')].some(b=>(b.innerText||'').trim().toLowerCase()==="
        "'sign in'&&vis(b));})()"
    )
    return not bool(_eval(ws, mid, js)), mid + 1


def find_page() -> dict | None:
    """The page target to drive: prefer one already in the Google flow."""
    targets = http_json(f"http://{CDP_HOST}:{CDP_PORT}/json")
    pages = [t for t in targets if t.get("type") == "page"]
    if not pages:
        return None
    for t in pages:
        if "accounts.google.com" in (t.get("url") or ""):
            return t
    return pages[0]


def _eval(ws, msg_id: int, expr: str):
    res = cdp_call(
        ws, msg_id, "Runtime.evaluate", {"expression": expr, "returnByValue": True}
    )
    return (res.get("result") or {}).get("value")


def _page_state(ws, msg_id: int) -> dict:
    raw = _eval(ws, msg_id, _STATE_JS)
    try:
        return json.loads(raw) if raw else {}
    except Exception:
        return {}




def classify_page(ws, msg_id: int) -> str:
    """When staging cannot reach the password step, say why (best effort)."""
    info = _page_state(ws, msg_id)
    href = info.get("href") or ""
    text = (info.get("text") or "").lower()
    if "otp" in href or any(m in text for m in CHALLENGE_MARKERS):
        outcome = "2fa"
    elif "challenge" in href and "challenge/pwd" not in href:
        outcome = "challenge"
    else:
        outcome = "staging_failed"
    log(f"classify {outcome} href={href} text={(info.get('text') or '')[:400]!r}")
    return outcome


def verify_result(ws, msg_id: int, pre_href: str, pre_text: str) -> str:
    """Watch the flow settle after the password submit.

    pre_href/pre_text are the page URL and text captured *before* the Next
    click. A verdict is only trustworthy once the page has moved: a
    successful sign-in leaves accounts.google.com, and a fresh failure
    re-renders the page — either under a new URL (new token) or, when
    Google keeps the same URL, with changed content. While the URL and the
    text are both unchanged, any 'Wrong password' text on screen belongs to
    a *previous* attempt and must not be classified as this submission's
    result.
    Post-verification onboarding cards (gds.google.com) can appear between
    the password check and the destination; each is dismissed via its
    skip/cancel button (see _dismiss_gds_card) and the watch continues.
    """
    for _ in range(60):
        time.sleep(2)
        info = _page_state(ws, msg_id)
        msg_id += 1
        href = info.get("href") or ""
        if _is_gds_card(href):
            # The sign-in is authenticated but the flow is held at this
            # onboarding card until it is skipped. Dismiss it and keep
            # watching for the flow to reach the destination.
            res, msg_id = _dismiss_gds_card(ws, msg_id)
            if res == "vnc_unreachable":
                return "vnc_unreachable"
            if res == "no_button":
                log(f"gds card has no dismiss button: {href[:200]}")
                return "staging_failed"
            log(f"dismissed gds onboarding card ({href.split('?')[0]})")
            continue
        if "accounts.google.com" not in href:
            return "success"
        text_raw = info.get("text") or ""
        if href == pre_href and text_raw == pre_text:
            # Still the untouched pre-submit page: Google is processing (or
            # the click is still landing). Any error text visible now is
            # stale. A fresh failure that keeps the same URL still changes
            # the content, so unchanged text is what keeps us waiting.
            continue
        text = text_raw.lower()
        if any(
            m in text
            for m in ("wrong password", "enter a different password", "password is incorrect")
        ):
            outcome = "wrong_password"
        elif "something went wrong" in text:
            outcome = "error_page"
        elif "otp" in href or any(m in text for m in CHALLENGE_MARKERS):
            outcome = "2fa"
        elif ("challenge" in href and "challenge/pwd" not in href) or "confirm it's you" in text:
            outcome = "challenge"
        else:
            continue
        log(f"verdict {outcome} href={href}")
        log(f"verdict page text: {(info.get('text') or '')[:800]!r}")
        return outcome
    return "staging_failed"


def attempt_signin(bypass_reentry: bool = False) -> str:
    """Guarded entry: one live attempt at a time, none within
    REENTRY_GUARD seconds of the last one (prevents a concurrent daemon +
    manual run from interleaving keystrokes and burning strikes).
    bypass_reentry is for the daemon's own scheduled retry of a transient
    failure (no password was verified, so no strikes were burned); the
    file lock still serializes attempts."""
    if not bypass_reentry:
        try:
            with open(ATTEMPT_MARK) as f:
                last = float(json.load(f).get("at", 0))
            if time.time() - last < REENTRY_GUARD:
                log(f"attempt blocked: last attempt was {int(time.time() - last)}s ago")
                return "recent_attempt"
        except (OSError, ValueError, TypeError):
            pass
    lock_fh = open(SIGNIN_LOCK, "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock_fh.close()
        log("attempt blocked: another attempt in progress")
        return "busy"
    try:
        try:
            with open(ATTEMPT_MARK, "w") as f:
                json.dump({"at": time.time()}, f)
        except OSError:
            pass
        return _do_attempt()
    finally:
        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        lock_fh.close()


def _navigate_to_signin() -> bool:
    """Open the sign-in flow like a person: focus the address bar
    (Ctrl+L), type the URL, hit Enter. A real navigation (normal referrer
    chain) instead of a CDP Page.navigate (empty referrer is a bot
    signal)."""
    ok, _ = vnc_request("/combo", {"mod": "ctrl", "key": "l"})
    if not ok:
        return False
    time.sleep(random.uniform(0.5, 1.2))  # let the omnibox take focus
    ok, _ = vnc_request("/type", {"text": "https://www.youtube.com/signin\n"})
    if not ok:
        return False
    time.sleep(random.uniform(3.0, 7.0))  # let the page load; read it
    return True


def _park_tab_blank(ws, mid: int) -> int:
    """Park the tab on about:blank using the same VNC omnibox navigation as
    above (real keystrokes; owner's call): a live YouTube page keeps
    rotating the browser's cookie copy, while the file — owned by the
    yt-dlp services — is the live session. Keep the vault's tab inert.
    Verifies the tab actually landed on about:blank (the keystrokes alone
    are fire-and-forget: a silently failed park leaves the vault tab warm
    and the downstream cheap re-seeds paper over it). One retry on
    mismatch. Returns the next msg id."""
    time.sleep(random.uniform(3.0, 6.0))  # let the post-login settle
    for attempt in (1, 2):
        ok, _ = vnc_request("/combo", {"mod": "ctrl", "key": "l"})
        if ok:
            time.sleep(random.uniform(0.5, 1.2))  # let the omnibox take focus
            ok, _ = vnc_request("/type", {"text": "about:blank\n"})
        time.sleep(2.0)  # let the navigation settle
        href = str(_eval(ws, mid, "location.href") or "")
        mid += 1
        if href == "about:blank":
            log(f"parked tab on about:blank (verified, attempt {attempt})")
            return mid
        log(f"park verify failed (attempt {attempt}): page at {href[:120]}")
        if not ok:
            return mid  # VNC down: a retry cannot help
    return mid


def _at_auth_page(ws, mid: int) -> tuple[bool, int]:
    """True while the tab sits in the Google sign-in flow (chooser,
    identifier, password, 2fa/challenge, or a sticky gds onboarding card):
    that is an active auth procedure, and a failed attempt leaves the
    screen as-is for a human via noVNC. Anything else (a signed-in
    destination, about:blank, ...) is parked. Returns (at_auth_page, mid)."""
    href = str(_eval(ws, mid, "location.href") or "")
    mid += 1
    return ("accounts.google.com" in href or _is_gds_card(href)), mid


def flow_age(ws, mid: int) -> tuple[float | None, int]:
    """Age in seconds of the current v3 sign-in flow, read from the URL's
    dsh=<server>:<usec> stamp (percent-encoded or bare). (None, mid) when
    the stamp is absent or undecodable."""
    href = str(_eval(ws, mid, "location.href") or "")
    mid += 1
    m = re.search(r"dsh=[^&]*?(?:%3A|:)(\d{15,})", href)
    if not m:
        return None, mid
    age = time.time() - int(m.group(1)) / 1e6
    return (age if age >= 0 else None), mid


def _stage_to_password(ws, mid: int) -> tuple[str, int, str]:
    """Drive the flow to the password step, typing as a person would.
    Returns (outcome, mid, last_stage); outcome is 'password',
    'signed in' (the flow completed without this attempt's typing),
    'vnc_unreachable', or 'staging_failed' (loop exhausted / rect missing /
    an onboarding card without a dismiss button)."""
    stage = "no target yet"
    for _ in range(30):
        # Where is the flow right now?
        href = str(_eval(ws, mid, "location.href") or "")
        mid += 1
        if "accounts.google.com" not in href:
            if _is_gds_card(href):
                # The sign-in is authenticated but held at a sticky
                # onboarding card; only its skip/cancel advances it
                # (navigating away bounces straight back to the card).
                res, mid = _dismiss_gds_card(ws, mid)
                if res == "vnc_unreachable":
                    return "vnc_unreachable", mid, stage
                if res == "no_button":
                    log(f"gds card has no dismiss button: {href[:200]}")
                    return "staging_failed", mid, stage
                log(f"dismissed gds onboarding card ({href.split('?')[0]})")
                time.sleep(random.uniform(2.0, 5.0))  # let the flow advance
                continue
            signed_in, mid = _youtube_signed_in(ws, mid, href)
            if signed_in:
                # The flow completed while we were staging (the last card
                # just landed, or a human signed in via noVNC): the session
                # is live in the browser; report it, don't type.
                return "signed in", mid, href
        stage = str(_eval(ws, mid, _stage_js()) or "no target yet")
        mid += 1
        if stage == "password step ready":
            return "password", mid, stage
        if stage == "email field ready":
            cur = str(_eval(ws, mid, _EMAIL_FIELD_JS + ".value") or "")
            mid += 1
            time.sleep(random.uniform(2.0, 5.0))  # read the page
            if cur != EMAIL:
                email_center = _screen_center(_eval(ws, mid, _EMAIL_RECT_JS))
                mid += 1
                if not email_center:
                    log("email field rect not found")
                    return "staging_failed", mid, stage
                ok, _ = vnc_request("/click", {"x": email_center[0], "y": email_center[1]})
                if not ok:
                    return "vnc_unreachable", mid, stage
                if cur:  # stale/prefilled value: genuine select-all + Delete
                    ok, _ = vnc_request("/clear")
                    if not ok:
                        return "vnc_unreachable", mid, stage
                    time.sleep(random.uniform(0.4, 0.9))
                ok, _ = vnc_request("/type", {"text": EMAIL})
                if not ok:
                    return "vnc_unreachable", mid, stage
                time.sleep(random.uniform(1.5, 4.0))  # look at the typed email
            next_center = _screen_center(_eval(ws, mid, _NEXT_RECT_JS))
            mid += 1
            if not next_center:
                log("Next button rect not found")
                return "staging_failed", mid, stage
            ok, _ = vnc_request("/click", {"x": next_center[0], "y": next_center[1]})
            if not ok:
                return "vnc_unreachable", mid, stage
            time.sleep(random.uniform(3.0, 6.0))  # let the flow advance
            continue
        if stage in ("account selected", "restart clicked"):
            time.sleep(random.uniform(2.0, 5.0))  # let the next step load
            continue
        time.sleep(random.uniform(2.0, 4.0))  # no target yet
    return "staging_failed", mid, stage


def _do_attempt() -> str:
    """One full email -> password attempt, paced like a person filling
    out the form. Returns an outcome string."""
    page = find_page()
    if not page:
        return "staging_failed"
    ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=20, origin="")
    try:
        mid = 1
        href = str(_eval(ws, mid, "location.href") or "")
        mid += 1
        if "accounts.google.com" not in href:
            if _is_gds_card(href):
                # The onboarding cards are sticky: navigating away bounces
                # straight back to the card; staging dismisses them.
                pass
            elif not _navigate_to_signin():
                return "vnc_unreachable"
        outcome, mid, stage = _stage_to_password(ws, mid)
        if outcome == "vnc_unreachable":
            return "vnc_unreachable"
        if outcome == "signed in":
            log(f"sign-in already complete (tab at {href[:120]})")
            mid = _park_tab_blank(ws, mid)
            return "success"
        if outcome != "password":
            log(f"staging ended at '{stage}'")
            outcome = classify_page(ws, mid)
            if not _at_auth_page(ws, mid):
                mid = _park_tab_blank(ws, mid)
            return outcome
        # The v3 flow is a server-side session with a ~20-min lifetime;
        # the exporter may have staged this page minutes ago. Submitting
        # into a stale flow returns the generic "Something went wrong"
        # page instead of a real verdict, so re-open the flow right
        # before typing when it is older than FLOW_MAX_AGE.
        age, mid = flow_age(ws, mid)
        if age is not None and age > FLOW_MAX_AGE:
            log(f"flow is {int(age)}s old (> {FLOW_MAX_AGE}s); re-opening before typing")
            if not _navigate_to_signin():
                return "vnc_unreachable"
            outcome, mid, stage = _stage_to_password(ws, mid)
            if outcome == "vnc_unreachable":
                return "vnc_unreachable"
            if outcome == "signed in":
                log(f"sign-in already complete (tab at {href[:120]})")
                mid = _park_tab_blank(ws, mid)
                return "success"
            if outcome != "password":
                log(f"staging after fresh flow ended at '{stage}'")
                outcome = classify_page(ws, mid)
                if not _at_auth_page(ws, mid):
                    mid = _park_tab_blank(ws, mid)
                return outcome
        time.sleep(random.uniform(3.0, 7.0))  # read the password page
        # Password via the VNC sibling as real keystrokes - NOT CDP synthetic
        # events and NOT a clipboard paste: Google rejects both as
        # wrong_password but accepts genuine typing. CDP stays read-only here:
        # it locates the field and the Next button, and the read-back verifies
        # the typed value. The secret itself never crosses this wire (the
        # sibling holds it in its own env and types it locally).
        pw_center = _screen_center(_eval(ws, mid, _PW_RECT_JS))
        mid += 1
        if not pw_center:
            log("password field rect not found")
            return "staging_failed"
        ok, _ = vnc_request("/click", {"x": pw_center[0], "y": pw_center[1]})
        if not ok:
            return "vnc_unreachable"
        # If a stale value from an interrupted/retried attempt lingers, wipe
        # it with a genuine select-all + Delete. On a fresh page the field is
        # empty, so a person (and this flow) simply starts typing.
        pw_cur = str(_eval(ws, mid, _PW_FIELD_JS + ".value") or "")
        mid += 1
        if pw_cur:
            ok, _ = vnc_request("/clear")
            if not ok:
                return "vnc_unreachable"
            time.sleep(random.uniform(0.5, 1.2))
        ok, _ = vnc_request("/type-password")
        if not ok:
            return "vnc_unreachable"
        # A person glances at the field to check the dot count before
        # submitting. Read the value once after a natural pause (a few
        # retries if the keystrokes are still settling), not a rapid poll.
        val = ""
        for _ in range(3):
            time.sleep(random.uniform(1.5, 3.5))
            val = str(_eval(ws, mid, _PW_FIELD_JS + ".value") or "")
            mid += 1
            if val == PASSWORD:
                break
        if val != PASSWORD:
            log("password read-back mismatch after VNC typing")
            return "vnc_type_failed"
        time.sleep(random.uniform(1.0, 2.5))  # look at what was typed
        # Record the pre-submit URL and text: a result is only readable once
        # the page has moved (URL or content; see verify_result). The
        # previous attempt's error text may still be on screen while Google
        # processes this submit.
        pre_state = _page_state(ws, mid)
        mid += 1
        pre_href = pre_state.get("href") or ""
        pre_text = pre_state.get("text") or ""
        next_center = _screen_center(_eval(ws, mid, _NEXT_RECT_JS))
        mid += 1
        if not next_center:
            log("Next button rect not found")
            return "staging_failed"
        ok, _ = vnc_request("/click", {"x": next_center[0], "y": next_center[1]})
        if not ok:
            return "vnc_unreachable"
        outcome = verify_result(ws, mid, pre_href, pre_text)
        if outcome == "success":
            mid = _park_tab_blank(ws, mid)
        return outcome
    finally:
        ws.close()


def main() -> None:
    if not PASSWORD:
        log("GOOGLE_PASSWORD not set; not running")
        return
    log(
        f"starting: cdp={CDP_HOST}:{CDP_PORT} delay={DELAY_MIN}-{DELAY_MAX}s "
        f"flow_max_age={FLOW_MAX_AGE}s max_attempts={MAX_ATTEMPTS}"
    )
    last_state: str | None = None
    human_needed = False
    attempts = 0
    resume_at = 0.0

    while True:
        try:
            state = read_state()
            if state == "down":
                if last_state != "down":
                    human_needed = False
                    attempts = 0
                    log("session down; arming auto re-auth")
                if not human_needed and time.time() >= resume_at:
                    delay = fuzz(DELAY_MIN, DELAY_MAX)
                    if attempts:
                        log(
                            f"retry {attempts}/{MAX_ATTEMPTS - 1}: typing credentials "
                            f"in {delay // 60}m{delay % 60:02d}s (fuzzed)"
                        )
                    else:
                        log(
                            f"typing credentials in {delay // 60}m{delay % 60:02d}s (fuzzed)"
                        )
                    still_down = sleep_fuzzed(delay, lambda: read_state() != "down")
                    if still_down:
                        outcome = attempt_signin(bypass_reentry=attempts > 0)
                        log(f"outcome: {outcome}")
                        if outcome == "success":
                            resume_at = time.time() + SUCCESS_COOLDOWN
                            attempts = 0
                        elif outcome in ("recent_attempt", "busy"):
                            # The guard mark or lock is held by a concurrent
                            # attempt (daemon + manual, or a pre-restart mark).
                            # Nothing was typed, so no strikes were burned:
                            # re-check once the guard window has elapsed
                            # instead of standing down forever (the state
                            # stays "down" until a sign-in happens, so
                            # human_needed would never be reset).
                            log("blocked by reentry guard; re-checking in 30m")
                            resume_at = time.time() + REENTRY_GUARD
                        elif outcome in RETRYABLE and attempts + 1 < MAX_ATTEMPTS:
                            attempts += 1
                        else:
                            human_needed = True
                            notify(
                                "manual re-auth needed",
                                f"auto sign-in could not restore the session "
                                f"({outcome}) after {attempts + 1} attempt(s); "
                                f"sign in via {VNC_HINT}",
                            )
            else:
                human_needed = False
        except Exception as exc:
            log(f"loop error: {exc}")
        last_state = state
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
