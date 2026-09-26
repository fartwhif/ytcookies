#!/usr/bin/env python3
"""VNC driver sibling for the ytcookies guest.

A raw RFB (VNC) client that connects to the guest's websockify
(ws://ytcookies:8300/websock -> x11vnc:5900) over the internal docker
network — no browser, no driver, no WireGuard. It exposes a small HTTP API
for the auto-signin daemon to perform *trusted OS-level* input (real X
key/mouse events via RFB) and to read the screen.

Why this exists: Google rejects the password when it is injected through
CDP synthetic Input events (the daemon saw `wrong_password` for the
byte-exact password). Driving the same keys through the VNC protocol makes
them real X events in the guest, which is what the re-auth needs.

The Google password is held in this container's own environment
(GOOGLE_PASSWORD); the daemon requests "type the password" and the secret
never crosses any wire.
"""

import base64
import io
import json
import os
import random
import queue
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pyDes
import websocket

import PIL.Image

WS_URL = os.environ.get("VNC_WS_URL", "ws://ytcookies:8300/websock")
VNC_PASSWORD = os.environ.get("VNC_PASSWORD", "")
GOOGLE_PASSWORD = os.environ.get("GOOGLE_PASSWORD", "")
HTTP_PORT = int(os.environ.get("VNC_DRIVER_PORT", "8123"))

# Framebuffer refresh policy. A full 1920x1080x4 frame is ~8.3MB; requesting
# one on a short timer floods the slow Python RFB parser, the backlog grows
# past the websockify->client TCP window, and websockify (a single-threaded
# proxy) blocks on write and stops forwarding our key/mouse input -- so the
# screen "works" but every VNC click/keystroke is silently dropped. Instead
# request incremental (dirty-only) updates frequently (cheap, ~0 on a static
# screen) and force a full frame only rarely, to correct any drift the
# incremental stream missed. /screen is for debugging; the sign-in path uses
# CDP, not the VNC screen.
INCR_REFRESH = 1.0
FULL_PERIOD = 30.0

XK_SHIFT_L = 0xFFE1
XK_CTRL_L = 0xFFE3


def log(msg: str) -> None:
    print(f"[vncdriver {time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def _bitrev(b: int) -> int:
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1
    return b


def vnc_key(password: bytes) -> bytes:
    """VNC DES key as libvncserver's OpenSSL build uses it.

    The stock RFB spec implies key = password zero-padded to 8 bytes, but
    libvncserver (crypto_openssl.c) bit-reverses each key byte before the
    DES call. x11vnc here is that build, so we must match it or auth fails.
    """
    pw = (password + b"\x00" * 8)[:8]
    return bytes(_bitrev(c) for c in pw)


def _des_block(key: bytes, block: bytes) -> bytes:
    d = pyDes.des(key, pyDes.ECB)
    return d.encrypt(block)


# Shifted ASCII symbol -> its unshifted base key (X11 keysym of the base).
_SHIFT_BASE = {}
for _a in range(26):
    _SHIFT_BASE[chr(ord("A") + _a)] = chr(ord("a") + _a)
for _s, _b in {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "-", "+": "=", "{": "[", "}": "]",
    "|": "\\", ":": ";", '"': "'", "<": ",", ">": ".", "?": "/", "~": "`",
}.items():
    _SHIFT_BASE[_s] = _b


def _ke(down: int, sym: int) -> bytes:
    """One RFB KeyEvent (type 4): down=1 press, down=0 release."""
    return struct.pack(">BBHI", 4, 1 if down else 0, 0, sym)


def _human_gap(prev: float) -> float:
    """Inter-key gap in human rhythm: momentum carried from the previous
    gap, plus an occasional (~6% of keys) 0.35-0.95s hesitation. An
    i.i.d. uniform distribution is a machine signature in keystroke
    dynamics analysis."""
    if random.random() < 0.06:
        return random.uniform(0.35, 0.95)
    gap = prev * random.uniform(0.7, 1.4) + random.uniform(-0.02, 0.03)
    return max(0.06, min(0.45, gap))


class Rfb:
    """Persistent RFB client over websockify.

    One background thread owns the socket: it does the handshake, then
    alternates non-blocking reads (applying framebuffer updates) with
    draining a command queue (clicks / key events). All socket I/O happens
    in that thread, so sends and recvs never race.
    """

    def __init__(self) -> None:
        self.ws = None
        self.buf = b""
        self.connected = False
        self.last_error = ""
        self.width = 0
        self.height = 0
        self.px = 0
        self.py = 0  # last pointer position we sent (motion trails)
        self.pxsz = 4
        self.pf = None  # raw 16-byte PixelFormat tuple (for logging)
        self.bpp = 32
        self.big_endian = False
        self.maxR = self.maxG = self.maxB = 255
        self.rsh, self.gsh, self.bsh = 16, 8, 0
        self.frame = None  # bytearray(W*H*pxsz)
        self._lock = threading.RLock()
        self._cmd = queue.Queue()
        self._stop = threading.Event()
        self._thread = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="rfb", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        backoff = 2
        while not self._stop.is_set():
            try:
                self._connect_and_loop()
                backoff = 2
            except Exception as exc:  # noqa: BLE001 - reconnect on anything
                if self._stop.is_set():
                    break
                self.connected = False
                self.last_error = f"{type(exc).__name__}: {exc}"
                log(f"rfb down ({self.last_error}); retry in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)

    def _connect_and_loop(self) -> None:
        log(f"connecting to {WS_URL}")
        ws = websocket.create_connection(WS_URL, timeout=None)
        self.ws = ws
        self._handshake(ws)
        self.connected = True
        log(f"connected: {self.width}x{self.height} pxsz={self.pxsz} pf={list(self.pf)}")
        self._request_full_fbu(ws)
        ws.settimeout(0.25)
        last_fbu = time.time()
        last_full = time.time()
        while not self._stop.is_set():
            try:
                data = ws.recv()
                if data:
                    self._ingest(data.encode() if isinstance(data, str) else data)
            except websocket.WebSocketTimeoutException:
                pass
            except (websocket.WebSocketConnectionClosedException,
                    websocket.WebSocketException, OSError) as exc:
                raise
            self._drain_commands(ws)
            # Flow control: only request more framebuffer data once the
            # receive buffer has been drained. Requesting a new full frame
            # while the previous one is still in flight queues unbounded
            # 8.3MB floods that clog the proxy and block our input.
            if self.connected and len(self.buf) < 1 << 20:
                now = time.time()
                if now - last_full >= FULL_PERIOD:
                    self._request_full_fbu(ws)
                    last_full = now
                    last_fbu = now
                elif now - last_fbu >= INCR_REFRESH:
                    self._request_incr_fbu(ws)
                    last_fbu = now

    # -- handshake ---------------------------------------------------------
    def _handshake(self, ws) -> None:
        buf = b""

        def recv(n: int) -> bytes:
            nonlocal buf
            while len(buf) < n:
                m = ws.recv()
                buf += m.encode() if isinstance(m, str) else m
            out, buf = buf[:n], buf[n:]
            return out

        def send(data: bytes) -> None:
            ws.send(data, opcode=2)

        send(b"RFB 003.007\n")
        ver = recv(12)
        if not ver.startswith(b"RFB 003."):
            raise RuntimeError(f"bad server version {ver!r}")
        nsec = recv(1)[0]
        types = recv(nsec)
        if 2 not in types:
            raise RuntimeError(f"server offers no VNC auth: {list(types)}")
        send(b"\x02")  # select VNC auth
        challenge = recv(16)
        key = vnc_key(VNC_PASSWORD.encode())
        send(_des_block(key, challenge[:8]) + _des_block(key, challenge[8:16]))
        result = struct.unpack(">I", recv(4))[0]
        if result != 0:
            raise RuntimeError(f"VNC auth rejected (result={result})")
        send(b"\x01")  # ClientInit: shared
        # ServerInit (no leading type byte):
        #   width(2) height(2) PixelFormat(16) desktopNameLength(4) name(N)
        # PixelFormat: bpp depth bigEndian trueColour
        #   maxRed(2) maxGreen(2) maxBlue(2) redShift greenShift blueShift pad(3)
        self.width, self.height = struct.unpack(">HH", recv(4))
        pf = recv(16)
        self.pf = tuple(pf)
        self.bpp = pf[0]
        self.big_endian = bool(pf[2])
        self.maxR = struct.unpack(">H", pf[4:6])[0]
        self.maxG = struct.unpack(">H", pf[6:8])[0]
        self.maxB = struct.unpack(">H", pf[8:10])[0]
        self.rsh, self.gsh, self.bsh = pf[10], pf[11], pf[12]
        self.pxsz = max(1, self.bpp // 8)
        namelen = struct.unpack(">I", recv(4))[0]
        name = recv(namelen)
        log(f"server init: {self.width}x{self.height} bpp={self.bpp} "
            f"max=({self.maxR},{self.maxG},{self.maxB}) "
            f"shifts=({self.rsh},{self.gsh},{self.bsh}) name={name!r}")
        # Raw encoding only.
        send(struct.pack(">BBHi", 2, 0, 1, 0))
        self.frame = bytearray(self.width * self.height * self.pxsz)

    def _request_full_fbu(self, ws) -> None:
        # FramebufferUpdateRequest: type=3, wantIncremental=0 (full), x, y, w, h
        ws.send(struct.pack(">BBHHHH", 3, 0, 0, 0, self.width, self.height), opcode=2)

    def _request_incr_fbu(self, ws) -> None:
        # FramebufferUpdateRequest: type=3, wantIncremental=1 (dirty only)
        ws.send(struct.pack(">BBHHHH", 3, 1, 0, 0, self.width, self.height), opcode=2)

    # -- server data -------------------------------------------------------
    def _ingest(self, data: bytes) -> None:
        with self._lock:
            self.buf += data
            while True:
                if len(self.buf) < 1:
                    break
                mtype = self.buf[0]
                if mtype == 0:  # FramebufferUpdate
                    if not self._parse_fbu():
                        break
                elif mtype == 1:  # SetColourMapEntries
                    if len(self.buf) < 6:
                        break
                    n = struct.unpack(">H", self.buf[4:6])[0]
                    need = 6 + n * 6
                    if len(self.buf) < need:
                        break
                    self.buf = self.buf[need:]
                elif mtype == 2:  # Bell
                    self.buf = self.buf[1:]
                elif mtype == 3:  # ServerCutText
                    if len(self.buf) < 5:
                        break
                    n = struct.unpack(">I", self.buf[1:5])[0]
                    if len(self.buf) < 5 + n:
                        break
                    self.buf = self.buf[5 + n:]
                else:
                    # Unknown message: drop the byte to keep making progress.
                    self.buf = self.buf[1:]

    def _parse_fbu(self) -> bool:
        """Parse one FramebufferUpdate from the front of self.buf.

        Returns True when a whole message was consumed, False when more
        bytes are needed. Only Raw (encoding 0) is expected (we request it
        exclusively); any other encoding triggers a resync.
        """
        if len(self.buf) < 4:
            return False
        nrects = struct.unpack(">H", self.buf[2:4])[0]
        pos = 4
        for _ in range(nrects):
            if len(self.buf) < pos + 12:
                return False
            x, y, w, h = struct.unpack(">4H", self.buf[pos:pos + 8])
            enc = struct.unpack(">I", self.buf[pos + 8:pos + 12])[0]
            pos += 12
            if enc != 0:
                log(f"unexpected FBU encoding {enc}; resyncing")
                self.buf = b""
                return True
            payload = w * h * self.pxsz
            if len(self.buf) < pos + payload:
                return False
            self._apply_raw_rect(x, y, w, h, self.buf[pos:pos + payload])
            pos += payload
        self.buf = self.buf[pos:]
        return True

    def _apply_raw_rect(self, x: int, y: int, w: int, h: int, pixels: bytes) -> None:
        with self._lock:
            if self.frame is None:
                return
            stride = self.width * self.pxsz
            rowsz = w * self.pxsz
            for row in range(h):
                src = row * rowsz
                dst = ((y + row) * self.width + x) * self.pxsz
                self.frame[dst:dst + rowsz] = pixels[src:src + rowsz]

    # -- commands ----------------------------------------------------------
    def _drain_commands(self, ws) -> None:
        while True:
            try:
                seq, ev = self._cmd.get_nowait()
            except queue.Empty:
                return
            try:
                for payload, delay in seq:
                    ws.send(payload, opcode=2)
                    if delay:
                        time.sleep(delay)
            except Exception:  # noqa: BLE001 - report via the event below
                pass
            ev.set()

    def send_seq(self, seq, timeout: float = 30.0) -> bool:
        """Queue an ordered sequence of (bytes, delay_after) and wait until
        the RFB thread has sent it. Returns True on success."""
        if not self.connected:
            return False
        ev = threading.Event()
        self._cmd.put((seq, ev))
        return ev.wait(timeout)

    def click(self, x: int, y: int) -> bool:
        """Move the pointer along a slightly curved path, then click.

        A real mouse never teleports: the motion events become
        pointermove events in the page, and a click with no preceding
        motion is a synthetic-input signature. Travel from the last known
        position (first click starts at the screen center), then press
        and release the button.
        """
        if self.px == 0 and self.py == 0:
            sx, sy = self.width // 2, self.height // 2
        else:
            sx, sy = self.px, self.py
        dist = ((x - sx) ** 2 + (y - sy) ** 2) ** 0.5
        steps = max(6, min(36, int(dist / 14)))
        # Quadratic-bezier control point: midpoint plus a random
        # perpendicular bow (hand-driven arcs are not straight lines).
        mx, my = (sx + x) / 2, (sy + y) / 2
        nx, ny = -(y - sy), (x - sx)
        nl = (nx * nx + ny * ny) ** 0.5 or 1.0
        bow = random.uniform(-0.2, 0.2) * dist
        cx, cy = mx + nx / nl * bow, my + ny / nl * bow
        seq = []
        for i in range(1, steps + 1):
            t = i / steps
            bx = (1 - t) ** 2 * sx + 2 * (1 - t) * t * cx + t * t * x
            by = (1 - t) ** 2 * sy + 2 * (1 - t) * t * cy + t * t * y
            seq.append(
                (struct.pack(">BBHH", 5, 0x00, int(bx), int(by)),
                 random.uniform(0.003, 0.010))
            )
        self.px, self.py = x, y
        seq.append((struct.pack(">BBHH", 5, 0x01, x, y), random.uniform(0.05, 0.12)))
        seq.append((struct.pack(">BBHH", 5, 0x00, x, y), random.uniform(0.08, 0.18)))
        return self.send_seq(seq)

    def type_text(self, text: str) -> bool:
        """Type text as real keystrokes in a human rhythm.

        A printable char sends its OWN keysym (for printable ASCII,
        keysym == byte value); shifted chars go with the Shift modifier
        held as separate events (the noVNC approach - Shift+base failed:
        the X server does not latch synthetic modifiers). Gaps carry
        momentum and occasional hesitations, never i.i.d. uniform.
        """
        seq = []
        gap = random.uniform(0.10, 0.22)
        for ch in text:
            if ch == "\n":
                seq.append((_ke(1, 0xFF0D), 0.08))
                seq.append((_ke(0, 0xFF0D), random.uniform(0.30, 0.80)))
                gap = random.uniform(0.10, 0.22)
                continue
            shifted = ch in _SHIFT_BASE
            sym = ord(ch)
            if shifted:
                seq.append((_ke(1, XK_SHIFT_L), random.uniform(0.04, 0.09)))
            seq.append((_ke(1, sym), random.uniform(0.055, 0.14)))
            seq.append((_ke(0, sym), random.uniform(0.03, 0.08)))
            if shifted:
                seq.append((_ke(0, XK_SHIFT_L), random.uniform(0.03, 0.08)))
            gap = _human_gap(gap)
            seq.append((b"", gap))
        return self.send_seq(seq)

    def clear_field(self) -> bool:
        """Genuine field clear: select-all (Ctrl+A), then Delete.

        The field must already be focused. Real key events, not DOM
        manipulation - used to wipe a stale value before typing.
        """
        seq = [
            (struct.pack(">BBHI", 4, 1, 0, XK_CTRL_L), 0.08),  # Ctrl down
            (struct.pack(">BBHI", 4, 1, 0, 0x61), 0.06),       # A down
            (struct.pack(">BBHI", 4, 0, 0, 0x61), 0.06),       # A up
            (struct.pack(">BBHI", 4, 0, 0, XK_CTRL_L), 0.12),  # Ctrl up
            (struct.pack(">BBHI", 4, 1, 0, 0xFFFF), 0.06),     # Delete down
            (struct.pack(">BBHI", 4, 0, 0, 0xFFFF), 0.15),     # Delete up
        ]
        return self.send_seq(seq)

    def combo(self, mod: str, key: str) -> bool:
        """Modifier + key chord (e.g. Ctrl+L focuses the address bar).

        The modifier is held as its own key events while the key is
        pressed; Chromium tracks its own modifier state from the event
        stream, so the chord is recognised.
        """
        keys = {"enter": 0xFF0D, "tab": 0xFF09, "backspace": 0xFF08,
                "delete": 0xFFFF, "escape": 0xFF1B, "space": 0x20}
        k = key.lower()
        if k in keys:
            sym = keys[k]
        elif len(key) == 1:
            sym = ord(k)
        else:
            return False
        mods = {"ctrl": XK_CTRL_L, "shift": XK_SHIFT_L, "alt": 0xFFE9}
        m = mods.get(mod)
        seq = []
        if m:
            seq.append((_ke(1, m), random.uniform(0.04, 0.09)))
        seq.append((_ke(1, sym), random.uniform(0.055, 0.12)))
        seq.append((_ke(0, sym), random.uniform(0.04, 0.08)))
        if m:
            seq.append((_ke(0, m), random.uniform(0.05, 0.10)))
        seq.append((b"", random.uniform(0.08, 0.20)))
        return self.send_seq(seq)

    # -- screen ------------------------------------------------------------
    def status(self) -> dict:
        return {
            "connected": self.connected,
            "width": self.width,
            "height": self.height,
            "pxsz": self.pxsz,
            "last_error": self.last_error,
            "ws_url": WS_URL,
        }

    def screenshot(self) -> bytes | None:
        with self._lock:
            if self.frame is None or not self.pf:
                return None
            frame = bytes(self.frame)
            W, H = self.width, self.height
            pxsz = self.pxsz
        # Build channels and encode outside the lock (encode is slow; we
        # must not hold the RFB lock while the reader thread applies FBU).
        # A channel occupies a whole byte when its shift is a multiple of 8 and
        # its max is 255. The channel byte position depends on endianness:
        #   little-endian: byte index = shift // 8
        #   big-endian:    byte index = 3 - shift // 8
        byte_aligned = (
            pxsz == 4
            and self.maxR == 255 and self.maxG == 255 and self.maxB == 255
            and self.rsh % 8 == 0 and self.gsh % 8 == 0 and self.bsh % 8 == 0
        )
        if byte_aligned:
            def off(shift: int) -> int:
                return (shift // 8) if not self.big_endian else (3 - shift // 8)
            r = frame[off(self.rsh) :: 4]
            g = frame[off(self.gsh) :: 4]
            b = frame[off(self.bsh) :: 4]
        else:
            endianness = "big" if self.big_endian else "little"
            maxR, maxG, maxB = self.maxR, self.maxG, self.maxB
            rsh, gsh, bsh = self.rsh, self.gsh, self.bsh
            r = bytearray()
            g = bytearray()
            b = bytearray()
            for i in range(0, len(frame), pxsz):
                p = int.from_bytes(frame[i:i + pxsz], endianness)
                r.append((p >> rsh) & maxR)
                g.append((p >> gsh) & maxG)
                b.append((p >> bsh) & maxB)
        img = PIL.Image.merge(
            "RGB",
            [
                PIL.Image.frombytes("L", (W, H), bytes(r)),
                PIL.Image.frombytes("L", (W, H), bytes(g)),
                PIL.Image.frombytes("L", (W, H), bytes(b)),
            ],
        )
        out = io.BytesIO()
        img.save(out, format="PNG")
        return out.getvalue()


RFb = Rfb()


class Handler(BaseHTTPRequestHandler):
    server_version = "vncdriver/1.0"

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _png(self, code: int, data: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw or b"{}")
        except Exception:
            return {}

    def do_GET(self):  # noqa: N802
        if self.path == "/status":
            self._json(200, RFb.status())
        elif self.path == "/screen":
            png = RFb.screenshot()
            if png is None:
                self._json(503, {"error": "no framebuffer yet"})
            else:
                self._png(200, png)
        elif self.path == "/screen_b64":
            png = RFb.screenshot()
            if png is None:
                self._json(503, {"error": "no framebuffer yet"})
            else:
                self._json(200, {"w": RFb.width, "h": RFb.height,
                                 "png_b64": base64.b64encode(png).decode()})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        body = self._body()
        if self.path == "/click":
            try:
                x, y = int(body["x"]), int(body["y"])
            except (KeyError, ValueError, TypeError):
                self._json(400, {"error": "need {x:int, y:int}"})
                return
            ok = RFb.click(x, y)
            self._json(200 if ok else 503, {"clicked": ok, "x": x, "y": y})
        elif self.path == "/type-password":
            # Types GOOGLE_PASSWORD one real keystroke at a time (no
            # clipboard, no CDP): Google rejects paste and CDP-synthetic
            # input as wrong_password but accepts genuine typing. The
            # sibling holds the secret in its own env, so it never crosses
            # this wire. The field must be focused by the caller (a prior
            # /click) before this is called.
            if not GOOGLE_PASSWORD:
                self._json(500, {"error": "GOOGLE_PASSWORD not set in sibling"})
                return
            ok = RFb.type_text(GOOGLE_PASSWORD)
            self._json(200 if ok else 503, {"typed": ok, "len": len(GOOGLE_PASSWORD)})
        elif self.path == "/type":
            text = body.get("text", "")
            ok = RFb.type_text(text)
            self._json(200 if ok else 503, {"typed": ok, "len": len(text)})
        elif self.path == "/clear":
            ok = RFb.clear_field()
            self._json(200 if ok else 503, {"cleared": ok})
        elif self.path == "/combo":
            ok = RFb.combo(str(body.get("mod", "none")), str(body.get("key", "")))
            self._json(200 if ok else 503, {"combo": ok})
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, *args) -> None:  # silence default stderr logging
        pass


def main() -> None:
    log(f"starting: vnc={WS_URL} http=:{HTTP_PORT} "
        f"google_pw={'set' if GOOGLE_PASSWORD else 'MISSING'}")
    RFb.start()
    httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    log("http listening")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        RFb.stop()


if __name__ == "__main__":
    main()
