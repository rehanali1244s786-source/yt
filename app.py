"""
YouTube video / playlist downloader  (Flask + yt-dlp)  -  v4

Big playlists   live per-video files, streamed ZIP parts, pipelined conversion, global limits
Reliability     jobs persist to disk and resume after a restart / redeploy; "retry failed";
                playlist preview with checkboxes; background queue; pause / resume;
                friendly bot-block / private / 429 messages; proxy + PO-token support;
                yt-dlp auto-update (start.sh + daily) with an in-place reload
Formats         MP4, MP3, M4A (no re-encode), Opus; cover art + tags; split by chapters; subtitles
Access          per-user codes -> expiring signed tokens, daily bandwidth cap per user
Operations      /admin page (jobs, disk, errors, usage, update + reload)
Public hardening YouTube-only links, rate limits, caps, CSP nonce, secrets via env vars

Environment variables: see README.txt
"""
import atexit
import base64
import functools
import hmac
import importlib.metadata
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from collections import deque
from datetime import date
from urllib.parse import urlparse

import yt_dlp
from flask import Flask, Response, abort, jsonify, render_template, request, send_file
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
_hops = int(os.environ.get("TRUST_PROXY", "1"))  # reverse proxies in front (Railway/Render/Nginx = 1)
if _hops:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_hops, x_proto=_hops, x_host=_hops)

ROOT = os.path.dirname(os.path.abspath(__file__))
_vol = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")  # set automatically by Railway when a volume is attached
BASE_DIR = (os.environ.get("DOWNLOAD_DIR")
            or (os.path.join(_vol, "downloads") if _vol else os.path.join(ROOT, "downloads")))
PRIV_DIR = os.path.join(ROOT, ".private")
os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(PRIV_DIR, mode=0o700, exist_ok=True)
START_TIME = time.time()


def _env_int(name, default, lo=0):
    try:
        return max(lo, int(os.environ.get(name, default)))
    except ValueError:
        return default


def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


PARALLEL_VIDEOS = _env_int("PARALLEL_VIDEOS", 2, 1)       # videos at once inside ONE job
MAX_GLOBAL_VIDEOS = _env_int("MAX_GLOBAL_VIDEOS", 6, 1)   # videos at once on the whole server
MAX_JOBS = _env_int("MAX_JOBS", 3, 1)                     # jobs downloading at once
MAX_QUEUE = _env_int("MAX_QUEUE", 20)                     # extra jobs allowed to wait in the queue
MAX_JOBS_PER_IP = _env_int("MAX_JOBS_PER_IP", 3, 1)
STARTS_PER_HOUR = _env_int("STARTS_PER_HOUR", 30, 1)
MAX_PLAYLIST = _env_int("MAX_PLAYLIST", 300, 0) or 10 ** 9   # videos per job (0 = unlimited)
MAX_JOB_BYTES = int(_env_float("MAX_JOB_GB", 15) * 1024 ** 3)
MAX_DISK_BYTES = int(_env_float("MAX_DISK_GB", 40) * 1024 ** 3)
DAILY_BYTES = int(_env_float("DAILY_GB_PER_USER", 0) * 1024 ** 3)   # 0 = no daily cap
TTL = _env_int("TTL_MIN", 120, 1) * 60
ZIP_PART_FILES = _env_int("ZIP_PART_FILES", 50, 2)
BIG_PLAYLIST = _env_int("BIG_PLAYLIST", 30, 1)
TOKEN_HOURS = _env_int("TOKEN_HOURS", 12, 1)
AUTO_UPDATE_HOURS = _env_int("AUTO_UPDATE_HOURS", 24)     # 0 = off
PROXY_URL = os.environ.get("PROXY_URL") or None
PO_TOKEN = os.environ.get("YT_PO_TOKEN") or None           # e.g. "web.gvs+XXXX"
VISITOR_DATA = os.environ.get("YT_VISITOR_DATA") or None
ALLOWED_HOSTS = tuple(
    h.strip().lower() for h in os.environ.get(
        "ALLOWED_HOSTS", "youtube.com,youtu.be,youtube-nocookie.com").split(",") if h.strip())
FORMATS = ("mp4", "mp3", "m4a", "opus")


# ------------------------------------------------------------------- users
def _parse_users():
    users = {}
    for part in os.environ.get("ACCESS_CODES", "").split(","):
        if ":" in part:
            n, c = part.split(":", 1)
            if n.strip() and c.strip():
                users[n.strip()] = c.strip()
    if os.environ.get("ACCESS_CODE"):
        users.setdefault("user", os.environ["ACCESS_CODE"])
    if os.environ.get("ADMIN_CODE"):
        users["admin"] = os.environ["ADMIN_CODE"]
    return users


USERS = _parse_users()
AUTH_ON = bool(USERS)
SECRET = os.environ.get("SECRET_KEY") or os.urandom(32).hex()   # set SECRET_KEY so tokens survive restarts


def make_token(user):
    exp = int(time.time() + TOKEN_HOURS * 3600)
    body = base64.urlsafe_b64encode(f"{user}|{exp}".encode()).decode().rstrip("=")
    sig = hmac.new(SECRET.encode(), body.encode(), "sha256").hexdigest()[:32]
    return f"{body}.{sig}"


def check_token(tok):
    try:
        body, sig = tok.split(".", 1)
        good = hmac.new(SECRET.encode(), body.encode(), "sha256").hexdigest()[:32]
        if not hmac.compare_digest(sig, good):
            return None
        user, exp = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode().rsplit("|", 1)
        if int(exp) < time.time() or user not in USERS:
            return None
        return user
    except Exception:  # noqa: BLE001
        return None


def current_user():
    if not AUTH_ON:
        return "anon"
    return check_token(request.headers.get("X-Token", ""))


def authed(admin=False):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            u = current_user()
            if u is None:
                return jsonify(error="Please enter the access code.", auth=True), 401
            if admin and (not AUTH_ON or u != "admin"):
                return jsonify(error="Admins only."), 403
            request.user = u
            return fn(*a, **k)
        return wrapper
    return deco


USAGE = {}  # (user, yyyy-mm-dd) -> bytes fetched today


def usage_today(user):
    return USAGE.get((user, date.today().isoformat()), 0)


def add_usage(user, n):
    k = (user, date.today().isoformat())
    USAGE[k] = USAGE.get(k, 0) + n
    for old in [x for x in USAGE if x[1] != k[1]]:
        USAGE.pop(old, None)


# ------------------------------------------------------------ tools / cookies
def _find_ffmpeg():
    p = shutil.which("ffmpeg")
    if p:
        return p
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:  # noqa: BLE001
        return None


def _find_deno():
    p = shutil.which("deno")
    if p:
        return p
    try:
        import deno
        return deno.find_deno_bin()
    except Exception:  # noqa: BLE001
        return None


FFMPEG = _find_ffmpeg()
HAS_FFMPEG = FFMPEG is not None
HAS_ARIA2 = shutil.which("aria2c") is not None
DENO = _find_deno()


def _load_cookies():
    """Cookies are a SECRET. Priority: COOKIES_FILE, YT_COOKIES_B64, YT_COOKIES, ./cookies.txt (local use)."""
    path = os.environ.get("COOKIES_FILE")
    if path and os.path.isfile(path):
        return path
    raw = None
    if os.environ.get("YT_COOKIES_B64"):
        try:
            raw = base64.b64decode(os.environ["YT_COOKIES_B64"]).decode("utf-8")
        except Exception:  # noqa: BLE001
            raw = None
    elif os.environ.get("YT_COOKIES"):
        raw = os.environ["YT_COOKIES"].replace("\\n", "\n")
    if raw:
        dst = os.path.join(PRIV_DIR, "cookies.txt")
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(raw)
        return dst
    local = os.path.join(ROOT, "cookies.txt")
    return local if os.path.isfile(local) else None


COOKIES = _load_cookies()

JOBS = {}
JOBS_LOCK = threading.Lock()
RATE = {}            # ip -> deque of timestamps (job starts)
PREV_RATE = {}       # ip -> deque of timestamps (previews)
BAD_CODE = {}        # ip -> deque of timestamps (wrong codes)
RATE_LOCK = threading.Lock()
GLOBAL_SEM = threading.BoundedSemaphore(MAX_GLOBAL_VIDEOS)
BOT_SEEN = [0.0]   # time of the last bot-check; while recent, skip straight to the cookies attempt
JOB_SEM = threading.BoundedSemaphore(MAX_JOBS)
ERRORS = deque(maxlen=60)          # recent failures for /admin
UPDATE = {"status": "idle", "log": "", "at": 0}

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\[[0-9;]*m")
PLAYLIST_HINT = re.compile(r"[?&]list=|/playlist|/@|/channel/|/c/|/user/")
ID_RE = re.compile(r"^[\w-]{6,20}$")
FINISHED = ("done", "error")
EXTRA_EXT = (".srt", ".vtt", ".mp3", ".m4a", ".opus", ".mp4", ".webm")


# ----------------------------------------------------------------- helpers
def clean(msg):
    msg = ANSI.sub("", str(msg)).strip()
    return re.sub(r"^ERROR:\s*", "", msg)[:400]


def friendly(err):
    """-> (human message, kind). kind 'bot' makes the UI show the cookies / proxy help."""
    raw = clean(err)
    low = raw.lower()
    if "not a bot" in low or "sign in to confirm" in low:
        return ("YouTube is asking this server to prove it is not a bot (common on cloud IPs). "
                "The owner can fix it with cookies (YT_COOKIES_B64) or a proxy (PROXY_URL)."), "bot"
    if "private video" in low:
        return "This video is private.", "private"
    if "confirm your age" in low or "age-restricted" in low or "age restricted" in low:
        return "Age-restricted video - the server needs cookies from a signed-in account.", "age"
    if "members-only" in low or "join this channel" in low:
        return "Members-only video - needs cookies from a member account.", "members"
    if "429" in low or "too many requests" in low or "rate-limit" in low or "rate limit" in low:
        return "YouTube is rate-limiting this server. Wait a bit and use Retry (or lower PARALLEL_VIDEOS).", "rate"
    if "not available in your country" in low or "blocked it in your country" in low or "geo" in low:
        return "This video is blocked in the server's country.", "geo"
    if "unavailable" in low or "has been removed" in low or "does not exist" in low:
        return "This video is unavailable or was removed.", "gone"
    return raw, "other"


def as_int(v):
    try:
        n = int(v)
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def url_allowed(url):
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS)


def dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def drop_job(jid):
    with JOBS_LOCK:
        JOBS.pop(jid, None)
    shutil.rmtree(os.path.join(BASE_DIR, jid), ignore_errors=True)


def make_room():
    """Disk guard: evict the oldest finished jobs until under MAX_DISK_BYTES. False if still full."""
    if dir_size(BASE_DIR) <= MAX_DISK_BYTES:
        return True
    with JOBS_LOCK:
        order = sorted((v["last"], k) for k, v in JOBS.items() if v["status"] in FINISHED)
    for _t, jid in order:
        drop_job(jid)
        if dir_size(BASE_DIR) <= MAX_DISK_BYTES:
            return True
    return False


# --------------------------------------------------------------- persistence
def save_job(j):
    """Atomically write the job's state next to its files, so a restart can resume it."""
    outdir = os.path.join(BASE_DIR, j["id"])
    if not os.path.isdir(outdir):
        return
    with j["lock"]:
        data = {k: j[k] for k in (
            "id", "ip", "user", "created", "status", "percent", "settled", "total", "multi", "pad", "failed",
            "failed_items", "error", "note", "bytes", "label", "p", "entries")}
        data["files"] = [{"name": f["name"], "size": f["size"], "rel": os.path.relpath(f["path"], outdir)}
                         for f in j["files"]]
    with j["save_lock"]:
        tmp = os.path.join(outdir, "state.json.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, os.path.join(outdir, "state.json"))
        except OSError:
            pass


def blank_job(jid, ip, user, p):
    now = time.time()
    return {
        "id": jid, "ip": ip, "user": user, "p": p, "lock": threading.RLock(), "save_lock": threading.Lock(),
        "created": now, "t0": now, "pct0": 0.0, "last": now, "pause": False, "pause_at": 0,
        "status": "queued", "percent": 0.0, "frac": {}, "settled": 0, "speeds": {}, "titles": {},
        "total": 1, "multi": False, "pad": 3, "failed": 0, "failed_items": [], "error": None, "note": "",
        "stop_reason": "", "files": [], "bytes": 0, "label": "", "entries": [],
        "cancel": False, "interrupt": False,
    }


def load_jobs():
    """On startup: restore finished jobs and RESUME unfinished ones (restart / redeploy / yt-dlp reload)."""
    try:
        names = os.listdir(BASE_DIR)
    except OSError:
        return
    for name in names:
        sp = os.path.join(BASE_DIR, name, "state.json")
        if not os.path.isfile(sp):
            continue
        try:
            with open(sp, encoding="utf-8") as fh:
                d = json.load(fh)
            outdir = os.path.join(BASE_DIR, name)
            j = blank_job(name, d.get("ip", "?"), d.get("user", "anon"), d["p"])
            for k in ("created", "status", "percent", "settled", "total", "multi", "pad", "failed", "failed_items",
                      "error", "note", "bytes", "label", "entries"):
                if k in d:
                    j[k] = d[k]
            for f in d.get("files", []):
                path = os.path.join(outdir, f["rel"])
                if os.path.isfile(path):
                    j["files"].append({"name": f["name"], "size": f["size"], "path": path})
            for e in j["entries"]:
                if e.get("st") == "running":
                    e["st"] = "pending"
            j["settled"] = sum(1 for e in j["entries"] if e.get("st") in ("done", "failed"))
            resume = j["status"] not in FINISHED
            if resume:
                j["status"] = "queued"
            with JOBS_LOCK:
                JOBS[name] = j
            if resume:
                threading.Thread(target=run_job, args=(j,), daemon=True).start()
        except Exception:  # noqa: BLE001
            continue


def save_all():
    with JOBS_LOCK:
        jobs = list(JOBS.values())
    for j in jobs:
        try:
            save_job(j)
        except Exception:  # noqa: BLE001
            pass


atexit.register(save_all)


def interrupt_all(wait=25):
    """Ask running jobs to stop cleanly (state is saved, they resume after the restart)."""
    with JOBS_LOCK:
        running = [v for v in JOBS.values() if v["status"] not in FINISHED]
    for j in running:
        j["interrupt"] = True
    t0 = time.time()
    while time.time() - t0 < wait:
        with JOBS_LOCK:
            if all(v["status"] in FINISHED or v["status"] == "queued" and v["interrupt"] for v in running):
                break
        time.sleep(0.3)
    save_all()


# ----------------------------------------------------------------- cleanup
def cleanup_old():
    """Remove finished jobs not touched for TTL, stray folders, expired pauses. Never touches running jobs."""
    now = time.time()
    with JOBS_LOCK:
        stale = [k for k, v in JOBS.items() if v["status"] in FINISHED and now - v["last"] > TTL]
        known = set(JOBS)
        for v in JOBS.values():
            if v["pause"] and now - v["pause_at"] > 3600:
                v["pause"] = False          # a forgotten pause must not block the queue forever
    for jid in stale:
        drop_job(jid)
    try:
        names = os.listdir(BASE_DIR)
    except OSError:
        return
    for name in names:
        if name in known:
            continue
        p = os.path.join(BASE_DIR, name)
        try:
            if now - os.path.getmtime(p) > TTL:
                shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)
        except OSError:
            pass
    with RATE_LOCK:
        for table, span in ((RATE, 3600), (PREV_RATE, 3600), (BAD_CODE, 900)):
            for ip in list(table):
                dq = table[ip]
                while dq and now - dq[0] > span:
                    dq.popleft()
                if not dq:
                    table.pop(ip, None)


# ---------------------------------------------------------------- yt-dlp update
def installed_version():
    try:
        return importlib.metadata.version("yt-dlp")
    except Exception:  # noqa: BLE001
        return "?"


def running_version():
    try:
        return yt_dlp.version.__version__
    except Exception:  # noqa: BLE001
        return "?"


UNDER_GUNICORN = "gunicorn" in sys.modules


def update_ytdlp(reload_after=True):
    """pip-upgrade yt-dlp, then (under gunicorn) reload the worker in place; jobs resume automatically."""
    if UPDATE["status"] == "running":
        return
    UPDATE.update(status="running", log="", at=time.time())
    try:
        r = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-U", "--no-cache-dir", "yt-dlp[default]"],
                           capture_output=True, text=True, timeout=300)
        UPDATE["log"] = (r.stdout + r.stderr)[-500:]
        if r.returncode != 0:
            UPDATE["status"] = "failed"
            return
        new, old = installed_version(), running_version()
        if new != old and reload_after and UNDER_GUNICORN:
            UPDATE["status"] = f"updated {old} -> {new}; reloading"
            interrupt_all()
            os.kill(os.getppid(), signal.SIGHUP)       # gunicorn master: graceful worker reload
        else:
            UPDATE["status"] = f"up to date ({new})" if new == old else f"updated to {new}; restart to apply"
    except Exception as e:  # noqa: BLE001
        UPDATE.update(status="failed", log=str(e))


_bg_started = False


def start_background():
    global _bg_started
    if _bg_started:
        return
    _bg_started = True

    def loop():
        last_update = time.time()
        while True:
            time.sleep(60)
            try:
                cleanup_old()
                if AUTO_UPDATE_HOURS and time.time() - last_update > AUTO_UPDATE_HOURS * 3600:
                    with JOBS_LOCK:
                        busy = any(v["status"] not in FINISHED for v in JOBS.values())
                    if not busy:                       # only when idle
                        last_update = time.time()
                        update_ytdlp()
            except Exception:  # noqa: BLE001
                pass

    threading.Thread(target=loop, daemon=True, name="background").start()


# ------------------------------------------------------------ yt-dlp options
def video_format(quality):
    h = "" if quality == "best" else f"[height<={quality}]"
    if HAS_FFMPEG:
        return (f"bv*{h}[vcodec^=avc1]+ba[ext=m4a]/bv*{h}[ext=mp4]+ba[ext=m4a]/"
                f"bv*{h}+ba/b{h}[ext=mp4]/b{h}/b")
    return f"b{h}[ext=mp4]/b{h}/b[ext=mp4]/b"


def build_opts(p, outdir, prefix, hook, cookie_copy, fallback=False, clients=None, parallel=1, spaced=False):
    fmt, quality = p["fmt"], p["quality"]
    frags = 16 if parallel <= 1 else max(4, 16 // parallel * 2)
    base = f"{prefix}%(title).80B [%(id)s]"
    outtmpl = os.path.join(outdir, base + ".%(ext)s")
    opts = {
        "outtmpl": outtmpl,
        "quiet": True, "no_warnings": True, "noprogress": True, "noplaylist": True,
        "windowsfilenames": True,
        "progress_hooks": [hook],
        "concurrent_fragment_downloads": frags,
        "http_chunk_size": 10 * 1024 * 1024,
        "retries": 10, "fragment_retries": 10, "extractor_retries": 3,
        "socket_timeout": 20, "buffersize": 1024 * 64,
        "overwrites": False, "continuedl": True,
    }
    if spaced:  # big playlist: small random pauses keep YouTube happy
        opts.update(sleep_interval_requests=0.5, sleep_interval=1, max_sleep_interval=3)
    if PROXY_URL:
        opts["proxy"] = PROXY_URL
    if HAS_FFMPEG:
        opts["ffmpeg_location"] = FFMPEG
    if HAS_ARIA2:
        c = max(4, 16 // max(parallel, 1))
        opts["external_downloader"] = {"default": "aria2c"}
        opts["external_downloader_args"] = {
            "aria2c": [f"-x{c}", f"-s{c}", "-k1M", "--min-split-size=1M", "--file-allocation=none"]}
    if cookie_copy:
        opts["cookiefile"] = cookie_copy
    ea = {}
    if clients:
        ea["player_client"] = clients
    if PO_TOKEN:
        ea["po_token"] = [PO_TOKEN]
    if VISITOR_DATA:
        ea["visitor_data"] = [VISITOR_DATA]
    if ea:
        opts["extractor_args"] = {"youtube": ea}
    if DENO:
        opts["js_runtimes"] = {"deno": {"path": DENO}}

    pps = []
    if fmt == "mp4":
        opts["format_sort"] = ["vcodec:h264", "res", "acodec:aac"]
        opts["format"] = "bv*[vcodec^=avc1]+ba/bv*+ba/b/best" if fallback else video_format(quality)
        if HAS_FFMPEG:
            opts["merge_output_format"] = "mp4"
    else:
        if fmt == "opus":
            opts["format"] = "ba/b/best" if fallback else "bestaudio[acodec=opus]/bestaudio/best"
        else:
            opts["format"] = "ba/b/best" if fallback else "bestaudio[ext=m4a]/bestaudio/best"
        if HAS_FFMPEG:   # m4a / opus: yt-dlp copies the stream when it is already that codec (no re-encode)
            pps.append({"key": "FFmpegExtractAudio", "preferredcodec": fmt, "preferredquality": "192"})
        if p.get("embed") and HAS_FFMPEG:
            pps.append({"key": "FFmpegMetadata", "add_metadata": True})
            if fmt in ("mp3", "m4a"):
                opts["writethumbnail"] = True
                pps.insert(0, {"key": "FFmpegThumbnailsConvertor", "format": "jpg", "when": "before_dl"})
                pps.append({"key": "EmbedThumbnail"})
    if p.get("subs") and HAS_FFMPEG:
        opts.update(writesubtitles=True, writeautomaticsub=True,
                    subtitleslangs=[x for x in re.split(r"[,\s]+", p["subs"]) if x][:6])
        pps.append({"key": "FFmpegSubtitlesConvertor", "format": "srt"})
    if p.get("chapters") and HAS_FFMPEG:
        opts["outtmpl"] = {"default": outtmpl,
                           "chapter": os.path.join(outdir, base + " - %(section_number)02d %(section_title).60B.%(ext)s")}
        pps.append({"key": "FFmpegSplitChapters", "force_keyframes": False})
    if pps:
        opts["postprocessors"] = pps
    return opts


# ------------------------------------------------------------ progress math
def recompute(j):
    """Overall percent in O(active videos). Caller must hold j['lock']."""
    total = max(j["total"], 1)
    acc = j["settled"] + sum(min(v, 0.95) for v in j["frac"].values())
    pct = acc / total * 100
    if j["status"] in ("downloading", "queued", "checking"):
        pct = min(pct, 99.0)
    j["percent"] = max(j["percent"], round(pct, 1))


def make_hook(j, idx):
    streams = {}

    def hook(d):
        if j["cancel"] or j["interrupt"]:
            raise yt_dlp.utils.DownloadCancelled("cancelled")
        status = d.get("status")
        info = d.get("info_dict") or {}
        fn = d.get("filename")
        with j["lock"]:
            if status == "downloading":
                streams[fn] = (d.get("downloaded_bytes") or 0,
                               d.get("total_bytes") or d.get("total_bytes_estimate") or 0)
                j["speeds"][(idx, fn)] = d.get("speed") or 0
            elif status == "finished":
                tot = d.get("total_bytes") or d.get("downloaded_bytes") or streams.get(fn, (0, 0))[1]
                streams[fn] = (tot, tot)
                j["speeds"].pop((idx, fn), None)
            else:
                return
            if info.get("title"):
                j["titles"][idx] = info["title"]
            rf = info.get("requested_formats") or [info]
            n = max(len(rf), 1)
            sizes = [(f.get("filesize") or f.get("filesize_approx") or 0) for f in rf]
            if sizes and all(sizes):
                frac = sum(v[0] for v in streams.values()) / float(sum(sizes))
            else:
                frac = sum((v[0] / v[1]) if v[1] else 0 for v in streams.values()) / n
            if idx in j["frac"]:
                j["frac"][idx] = max(j["frac"][idx], min(max(frac, 0.0), 1.0))
                recompute(j)

    return hook


# ---------------------------------------------------------------- ffmpeg fix
def _probe(path):
    try:
        out = subprocess.run([FFMPEG, "-hide_banner", "-i", path], capture_output=True,
                             text=True, timeout=60).stderr
    except Exception:  # noqa: BLE001
        return None, None
    v = re.search(r"Video: (\w+)", out)
    a = re.search(r"Audio: (\w+)", out)
    return (v.group(1) if v else None), (a.group(1) if a else None)


def ensure_playable(path):
    """Phones need H.264 + AAC. Re-encode only the part that is not."""
    v, a = _probe(path)
    if v is None:
        return
    vc = "copy" if v == "h264" else "libx264"
    ac = "copy" if (a is None or a in ("aac", "mp3")) else "aac"
    if vc == "copy" and ac == "copy":
        return
    tmp = path + ".fix.mp4"
    cmd = [FFMPEG, "-y", "-hide_banner", "-loglevel", "error", "-i", path, "-map", "0:v:0", "-map", "0:a?",
           "-c:v", vc, "-c:a", ac]
    if vc == "libx264":
        cmd += ["-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p"]
    cmd += ["-movflags", "+faststart", tmp]
    try:
        ok = subprocess.run(cmd, timeout=3600).returncode == 0 and os.path.exists(tmp)
    except Exception:  # noqa: BLE001
        ok = False
    if ok:
        os.replace(tmp, path)
    elif os.path.exists(tmp):
        os.remove(tmp)


# ---------------------------------------------------------------- one video
def fetch_video(opts, url):
    """Run yt-dlp for one URL and return the final file path. (Single seam - easy to stub in tests.)"""
    final = []
    opts = dict(opts, post_hooks=[final.append])
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(url, download=True)
    path = None
    for rd in (info or {}).get("requested_downloads") or []:
        if rd.get("filepath"):
            path = rd["filepath"]
    path = path or (final[-1] if final else None)
    if not path or not os.path.isfile(path):
        # split-by-chapters may have removed the main file; fall back to the newest matching file
        raise RuntimeError("Download finished but no file was produced.")
    return path


def _register(j, outdir, names):
    seen = {f["name"] for f in j["files"]}
    for fn in names:
        if fn in seen:
            continue
        path = os.path.join(outdir, fn)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        with j["lock"]:
            j["files"].append({"name": fn, "size": size, "path": path})
            j["bytes"] += size
        add_usage(j["user"], size)


def download_one(j, i, outdir, parallel, spaced):
    p, e = j["p"], j["entries"][i]
    prefix = f"{e['n']:0{j['pad']}d} - " if j["multi"] else ""
    has_ck = bool(COOKIES) and os.path.exists(COOKIES)
    cookie_copy = os.path.join(PRIV_DIR, f"ck-{j['id']}-{i}.txt") if has_ck else None
    if has_ck:
        shutil.copyfile(COOKIES, cookie_copy)
        os.chmod(cookie_copy, 0o600)
    # Attempt ladder (stops at first success): 1) plain  2) other YouTube clients  3) with cookies
    attempts = [
        dict(cookies=False, fallback=False, clients=None),
        dict(cookies=False, fallback=True, clients=["android_vr", "tv", "web_safari"]),
    ]
    if has_ck:
        attempts.append(dict(cookies=True, fallback=True, clients=None))
        if time.time() - BOT_SEEN[0] < 3600:        # bot-check seen recently: don't waste time on plain tries
            attempts = attempts[-1:]
            spaced = True                            # and go gently, so the cookies/account stay healthy
    try:
        if e.get("t"):
            with j["lock"]:
                j["titles"][i] = e["t"]
        path, last = None, None
        for a in attempts:
            opts = build_opts(p, outdir, prefix, make_hook(j, i), cookie_copy if a["cookies"] else None,
                              fallback=a["fallback"], clients=a["clients"], parallel=parallel, spaced=spaced)
            try:
                path = fetch_video(opts, e["u"])
                last = None
                break
            except yt_dlp.utils.DownloadError as ex:
                last = ex
                low = str(ex).lower()
                is_bot = "not a bot" in low or "sign in to confirm" in low
                if is_bot:
                    BOT_SEEN[0] = time.time()
                retryable = "format is not available" in low or is_bot
                if j["cancel"] or j["interrupt"] or not retryable:
                    raise
        if last is not None:
            raise last

        main = os.path.basename(path)
        stem, ext = os.path.splitext(main)
        names = [main]
        extras = [f for f in sorted(os.listdir(outdir))
                  if f != main and f.startswith(stem) and f.lower().endswith(EXTRA_EXT)]
        chapters = [f for f in extras if f.startswith(stem + " - ") and f.lower().endswith(ext.lower())]
        if p.get("chapters") and chapters:           # split by chapters: keep the parts, drop the whole file
            try:
                os.remove(path)
            except OSError:
                pass
            names = []
        names += extras
        if p["fmt"] == "mp4" and HAS_FFMPEG:
            for fn in names:
                if fn.lower().endswith(".mp4"):
                    ensure_playable(os.path.join(outdir, fn))   # pipelined with the other downloads
        _register(j, outdir, names)
    finally:
        with j["lock"]:
            for k in [k for k in j["speeds"] if k[0] == i]:
                j["speeds"].pop(k, None)
        if cookie_copy and os.path.exists(cookie_copy):
            try:
                os.remove(cookie_copy)
            except OSError:
                pass


def resolve_entries(url, want_playlist, start, end, cap=None):
    """-> (entries, label). entries = [{n, id, u, t, dur}]; n = position in the playlist."""
    if not (want_playlist and PLAYLIST_HINT.search(url)):
        return [{"n": 1, "id": None, "u": url, "t": None, "dur": None}], None
    opts = {"quiet": True, "no_warnings": True, "extract_flat": "in_playlist", "noplaylist": False,
            "skip_download": True, "socket_timeout": 30, "extractor_retries": 3}
    if PROXY_URL:
        opts["proxy"] = PROXY_URL
    if cap:
        opts["playlist_items"] = f"1:{cap}"
    elif start or end:
        opts["playlist_items"] = f"{start or 1}:{end or ''}"
    ck = None
    if COOKIES and os.path.exists(COOKIES):
        ck = os.path.join(PRIV_DIR, f"ck-list-{uuid.uuid4().hex}.txt")
        shutil.copyfile(COOKIES, ck)
        opts["cookiefile"] = ck
    try:
        with yt_dlp.YoutubeDL(opts) as ydl:
            info = ydl.extract_info(url, download=False)
    finally:
        if ck and os.path.exists(ck):
            os.remove(ck)
    raw = (info or {}).get("entries")
    label = (info or {}).get("title")
    if not raw:
        return [{"n": 1, "id": (info or {}).get("id"), "u": url, "t": label, "dur": None}], label
    first = 1 if cap else (start or 1)
    out = []
    for pos, en in enumerate(raw):
        if not en:
            continue
        u = en.get("url") or en.get("webpage_url")
        if u and not u.startswith("http"):
            u = None
        if not u and en.get("id"):
            u = "https://www.youtube.com/watch?v=" + en["id"]
        if u and url_allowed(u):
            out.append({"n": first + pos, "id": en.get("id"), "u": u, "t": en.get("title"),
                        "dur": en.get("duration")})
    return out, label


# ---------------------------------------------------------------- the job
def download_entries(j, outdir):
    entries = j["entries"]
    todo = deque(i for i, e in enumerate(entries) if e["st"] == "pending")
    parallel = max(1, min(PARALLEL_VIDEOS, len(todo)))
    spaced = j["total"] > BIG_PLAYLIST
    qlock = threading.Lock()

    def stop():
        return j["cancel"] or j["interrupt"] or bool(j["stop_reason"])

    def worker():
        while True:
            while j["pause"] and not stop():
                time.sleep(0.4)
            with qlock:
                if stop() or not todo:
                    return
                i = todo.popleft()
            e = entries[i]
            e["st"] = "running"
            with j["lock"]:
                j["frac"][i] = 0.0
            GLOBAL_SEM.acquire()
            outcome = "pending"
            try:
                if not stop():
                    download_one(j, i, outdir, parallel, spaced)
                    outcome = "done"
            except Exception as ex:  # noqa: BLE001
                if not (j["cancel"] or j["interrupt"]):
                    outcome = "failed"
                    msg, kind = friendly(ex)
                    with j["lock"]:
                        j["failed"] += 1
                        title = j["titles"].get(i) or e.get("t") or e["u"]
                        if len(j["failed_items"]) < 200:
                            j["failed_items"].append({"n": e["n"], "idx": i, "title": title, "error": msg, "kind": kind})
                    ERRORS.append({"t": time.time(), "job": j["id"][:8], "title": title, "error": msg, "raw": clean(ex)})
            finally:
                GLOBAL_SEM.release()
                with j["lock"]:
                    e["st"] = outcome
                    j["frac"].pop(i, None)
                    j["titles"].pop(i, None)
                    if outcome in ("done", "failed"):
                        j["settled"] += 1
                    if j["bytes"] > MAX_JOB_BYTES and not j["stop_reason"]:
                        j["stop_reason"] = (f"Size limit of {MAX_JOB_BYTES / 1024 ** 3:.0f} GB reached - "
                                            "the rest was skipped (use Retry to continue).")
                    if DAILY_BYTES and usage_today(j["user"]) >= DAILY_BYTES and not j["stop_reason"]:
                        j["stop_reason"] = "Your daily download limit was reached - the rest was skipped."
                    recompute(j)
                save_job(j)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(parallel)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def finalize(j):
    with j["lock"]:
        j["speeds"].clear()
        if j["interrupt"]:                      # restart in progress: stay resumable
            j["status"] = "queued"
            save_job(j)
            return
        pend = sum(1 for e in j["entries"] if e["st"] not in ("done", "failed"))
        if j["stop_reason"]:
            j["note"] = ((j["note"] + " ") if j["note"] else "") + j["stop_reason"]
        if j["files"]:
            if j["cancel"]:
                j["note"] = "Cancelled - the videos finished so far are still available."
            j["status"] = "done"
            j["percent"] = 100.0 if pend == 0 else max(j["percent"], round(j["settled"] / max(j["total"], 1) * 100, 1))
        else:
            j["status"] = "error"
            j["error"] = ("Cancelled." if j["cancel"] else
                          (j["failed_items"][0]["error"] if j["failed_items"] else
                           "No file was created. Check the link or range."))
    save_job(j)


def run_job(j):
    outdir = os.path.join(BASE_DIR, j["id"])
    os.makedirs(outdir, exist_ok=True)
    got_slot = False
    try:
        p = j["p"]
        if not j["entries"]:
            with j["lock"]:
                j["status"] = "checking"
            entries, label = resolve_entries(p["url"], p["playlist"], p["start"], p["end"])
            if p.get("ids"):
                want = set(p["ids"])
                entries = [e for e in entries if e["id"] in want]
            if not entries:
                raise RuntimeError("No videos found in this link.")
            note = ""
            if len(entries) > MAX_PLAYLIST:
                note = f"Playlist limited to the first {MAX_PLAYLIST} of {len(entries)} videos on this server."
                entries = entries[:MAX_PLAYLIST]
            for e in entries:
                e["st"] = "pending"
            with j["lock"]:
                j.update(entries=entries, total=len(entries), multi=len(entries) > 1, label=label or "", note=note,
                         pad=max(3, len(str(max(e["n"] for e in entries)))))
            save_job(j)
        with j["lock"]:
            j["status"] = "queued"                      # waiting for a free job slot
        while not (j["cancel"] or j["interrupt"]):
            if JOB_SEM.acquire(timeout=1):
                got_slot = True
                break
        if got_slot:
            with j["lock"]:
                j["status"] = "downloading"
                j["t0"], j["pct0"] = time.time(), j["percent"]
            download_entries(j, outdir)
    except Exception as ex:  # noqa: BLE001
        with j["lock"]:
            j["status"] = "error"
            j["error"] = friendly(ex)[0]
        if not j["entries"]:
            shutil.rmtree(outdir, ignore_errors=True)
        else:
            save_job(j)
    else:
        finalize(j)
    finally:
        if got_slot:
            JOB_SEM.release()
        j["last"] = time.time()


def snapshot(j, since=0):
    with j["lock"]:
        elapsed = max(time.time() - j["t0"], 0.001)
        gained = j["percent"] - j["pct0"]
        eta = None
        if j["status"] == "downloading" and gained >= 1 and not j["pause"]:
            eta = int(elapsed * (100 - j["percent"]) / gained)
        files = j["files"]
        since = max(0, min(since, len(files)))
        title = next(iter(j["titles"].values()), "") if j["titles"] else ""
        retryable = 0
        if j["status"] in FINISHED:
            retryable = sum(1 for e in j["entries"] if e["st"] in ("failed", "pending"))
        return {
            "status": j["status"], "percent": j["percent"], "paused": j["pause"],
            "speed": sum(j["speeds"].values()), "eta": eta, "title": title, "label": j["label"],
            "done": len(files) if j["total"] <= 1 else j["settled"] - j["failed"],
            "total": j["total"], "failed": j["failed"], "failed_items": j["failed_items"][-30:],
            "bot_block": any(f.get("kind") == "bot" for f in j["failed_items"]),
            "retryable": retryable, "error": j["error"], "note": j["note"],
            "nfiles": len(files), "since": since,
            "files": [{"i": since + k, "name": f["name"], "size": f["size"]}
                      for k, f in enumerate(files[since:since + 500])],
            "part_size": ZIP_PART_FILES, "bytes": j["bytes"],
        }


# -------------------------------------------------------------- zip streaming
class _Sink:
    """Write-only, non-seekable sink: zipfile then emits streaming entries (data descriptors)."""

    def __init__(self):
        self.buf = io.BytesIO()

    def write(self, b):
        return self.buf.write(b)

    def flush(self):
        pass

    def take(self):
        data = self.buf.getvalue()
        self.buf.seek(0)
        self.buf.truncate()
        return data


def stream_zip(j, items):
    """Yield a STORED zip built on the fly - no temp file, constant memory, any size (zip64)."""
    sink = _Sink()
    z = zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED, allowZip64=True)
    for path, name in items:
        j["last"] = time.time()
        try:
            src = open(path, "rb")
        except OSError:
            continue
        with src, z.open(name, "w", force_zip64=True) as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
                data = sink.take()
                if data:
                    yield data
        data = sink.take()
        if data:
            yield data
    z.close()
    data = sink.take()
    if data:
        yield data


# ------------------------------------------------------------------ routes
def client_ip():
    return request.remote_addr or "?"


def _window(table, ip, span):
    dq = table.setdefault(ip, deque())
    now = time.time()
    while dq and now - dq[0] > span:
        dq.popleft()
    return dq


@app.before_request
def _nonce():
    request.nonce = base64.b64encode(os.urandom(12)).decode()


@app.after_request
def _headers(resp):
    n = getattr(request, "nonce", "")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src 'nonce-{n}'; style-src 'nonce-{n}'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.path.startswith(("/api/", "/file/", "/zip/", "/admin")):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Robots-Tag"] = "noindex"
    return resp


@app.route("/")
def index():
    return render_template("index.html", needs_code=AUTH_ON, ffmpeg=HAS_FFMPEG, nonce=request.nonce,
                           max_playlist=MAX_PLAYLIST, daily_gb=DAILY_BYTES / 1024 ** 3)


@app.route("/admin")
def admin_page():
    if not (AUTH_ON and "admin" in USERS):
        abort(404)
    return render_template("admin.html", nonce=request.nonce)


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")


@app.route("/healthz")
def healthz():
    return jsonify(ok=True)


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    ip = client_ip()
    if not AUTH_ON:
        return jsonify(token="", user="anon", hours=0)
    with RATE_LOCK:
        if len(_window(BAD_CODE, ip, 900)) >= 10:
            return jsonify(error="Too many wrong codes. Try again in a few minutes."), 429
    code = str(data.get("code", "")).encode()
    matched = None
    for name, c in USERS.items():
        if hmac.compare_digest(code, c.encode()):
            matched = name
    if not matched:
        with RATE_LOCK:
            _window(BAD_CODE, ip, 900).append(time.time())
        return jsonify(error="Wrong access code."), 403
    return jsonify(token=make_token(matched), user=matched, hours=TOKEN_HOURS)


def _link_ok(url):
    if len(url) > 2000 or not url.startswith(("http://", "https://")):
        return "Please paste a valid link (starting with http/https)."
    if not url_allowed(url):
        return "Only YouTube links are supported on this server."
    return None


@app.route("/api/preview", methods=["POST"])
@authed()
def preview():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    err = _link_ok(url)
    if err:
        return jsonify(error=err), 400
    if not PLAYLIST_HINT.search(url):
        return jsonify(error="That link is a single video - no need to preview."), 400
    ip = client_ip()
    with RATE_LOCK:
        dq = _window(PREV_RATE, ip, 3600)
        if len(dq) >= 60:
            return jsonify(error="Too many previews. Try again later."), 429
        dq.append(time.time())
    try:
        entries, label = resolve_entries(url, True, None, None, cap=1000)
    except Exception as ex:  # noqa: BLE001
        return jsonify(error=friendly(ex)[0]), 502
    return jsonify(title=label or "", max=MAX_PLAYLIST, entries=[
        {"n": e["n"], "id": e["id"], "title": e["t"] or e["u"], "dur": e["dur"]} for e in entries if e["id"]])


@app.route("/api/start", methods=["POST"])
@authed()
def start():
    data = request.get_json(silent=True) or request.form
    ip, user = client_ip(), request.user
    url = (data.get("url") or "").strip()
    err = _link_ok(url)
    if err:
        return jsonify(error=err), 400

    fmt = data.get("format") if data.get("format") in FORMATS else "mp4"
    quality = str(data.get("quality", "720"))
    if quality != "best" and not quality.isdigit():
        quality = "best"
    ids = data.get("ids")
    if isinstance(ids, list):
        ids = [x for x in ids if isinstance(x, str) and ID_RE.match(x)][:2000] or None
    else:
        ids = None
    subs = re.sub(r"[^A-Za-z0-9,\-_. ]", "", str(data.get("subs") or ""))[:40].strip()
    p = {
        "url": url, "fmt": fmt, "quality": quality,
        "playlist": str(data.get("playlist", "")).lower() in ("1", "true", "on", "yes"),
        "start": as_int(data.get("start")), "end": as_int(data.get("end")), "ids": ids,
        "embed": bool(data.get("embed")), "chapters": bool(data.get("chapters")), "subs": subs,
    }
    if DAILY_BYTES and usage_today(user) >= DAILY_BYTES:
        return jsonify(error="Daily download limit reached. Try again tomorrow."), 429

    cleanup_old()
    with JOBS_LOCK:
        active = [v for v in JOBS.values() if v["status"] not in FINISHED]
        if len(active) >= MAX_JOBS + MAX_QUEUE:
            return jsonify(error="Server queue is full. Please try again in a few minutes."), 503
        if sum(1 for v in active if v["ip"] == ip) >= MAX_JOBS_PER_IP:
            return jsonify(error="You already have downloads running. Wait for one to finish."), 429
    with RATE_LOCK:
        dq = _window(RATE, ip, 3600)
        if len(dq) >= STARTS_PER_HOUR:
            return jsonify(error="Hourly limit reached. Please try again later."), 429
        dq.append(time.time())
    if not make_room():
        return jsonify(error="Server storage is full. Please try again later."), 503

    jid = uuid.uuid4().hex
    j = blank_job(jid, ip, user, p)
    os.makedirs(os.path.join(BASE_DIR, jid), exist_ok=True)
    with JOBS_LOCK:
        JOBS[jid] = j
    save_job(j)
    threading.Thread(target=run_job, args=(j,), daemon=True).start()
    return jsonify(ok=True, job=jid)


def _job(job):
    j = JOBS.get(job)
    if j:
        j["last"] = time.time()
    return j


@app.route("/api/progress/<job>")
def progress(job):
    j = _job(job)
    if not j:
        return jsonify(status="error", error="Job not found (expired or removed)."), 404
    return jsonify(snapshot(j, as_int(request.args.get("since")) or 0))


@app.route("/api/jobs")
def jobs_list():
    out = []
    for jid in (request.args.get("ids") or "").split(",")[:30]:
        j = JOBS.get(jid.strip())
        if j:
            with j["lock"]:
                out.append({"id": j["id"], "status": j["status"], "percent": j["percent"], "label": j["label"],
                            "total": j["total"], "failed": j["failed"], "files": len(j["files"]),
                            "created": j["created"], "paused": j["pause"]})
    return jsonify(jobs=out)


@app.route("/api/cancel/<job>", methods=["POST"])
def cancel(job):
    j = _job(job)
    if j:
        j["cancel"] = True
        j["pause"] = False
    return jsonify(ok=True)


@app.route("/api/pause/<job>", methods=["POST"])
def pause(job):
    j = _job(job)
    if j and j["status"] not in FINISHED:
        j["pause"], j["pause_at"] = True, time.time()
    return jsonify(ok=True)


@app.route("/api/resume/<job>", methods=["POST"])
def resume(job):
    j = _job(job)
    if j:
        j["pause"] = False
    return jsonify(ok=True)


@app.route("/api/retry/<job>", methods=["POST"])
@authed()
def retry(job):
    """Re-run only the failed (and cancelled / skipped) videos of a finished job."""
    j = _job(job)
    if not j:
        return jsonify(error="Job not found."), 404
    if DAILY_BYTES and usage_today(request.user) >= DAILY_BYTES:
        return jsonify(error="Daily download limit reached. Try again tomorrow."), 429
    with j["lock"]:
        if j["status"] not in FINISHED:
            return jsonify(error="Job is still running."), 409
        n = 0
        for e in j["entries"]:
            if e["st"] in ("failed", "pending"):
                e["st"] = "pending"
                n += 1
        if not n:
            return jsonify(error="Nothing to retry."), 400
        j.update(cancel=False, interrupt=False, pause=False, stop_reason="", error=None, note="", failed=0,
                 failed_items=[], status="queued", user=request.user)
        j["settled"] = sum(1 for e in j["entries"] if e["st"] == "done")
        j["percent"] = 0.0
        recompute(j)
    threading.Thread(target=run_job, args=(j,), daemon=True).start()
    return jsonify(ok=True, retrying=n)


def _ready(job):
    j = _job(job)
    if not j or (j["status"] == "error" and not j["files"]):
        abort(404, "File not found or expired. Please download again.")
    return j


@app.route("/file/<job>/<int:idx>")
def get_file(job, idx):
    j = _ready(job)
    with j["lock"]:
        f = j["files"][idx] if 0 <= idx < len(j["files"]) else None
    if not f or not os.path.exists(f["path"]):
        abort(404, "File not found or expired. Please download again.")
    return send_file(f["path"], as_attachment=True, download_name=f["name"], conditional=True)  # resumable


@app.route("/zip/<job>")
def get_zip(job):
    """All finished files as one streamed ZIP, or ?part=N (1-based) = N-th group of ZIP_PART_FILES files."""
    j = _ready(job)
    with j["lock"]:
        files = list(j["files"])
        done = j["status"] in FINISHED
    part = as_int(request.args.get("part"))
    if part:
        lo, hi = (part - 1) * ZIP_PART_FILES, part * ZIP_PART_FILES
        if lo >= len(files) or (len(files) < hi and not done):
            abort(404, "That part is not ready yet.")
        files = files[lo:hi]
        name = f"playlist-part-{part:02d}.zip"
    else:
        name = "playlist.zip"
    items = [(f["path"], f["name"]) for f in files if os.path.exists(f["path"])]
    if not items:
        abort(404, "Nothing to download yet.")
    resp = Response(stream_zip(j, items), mimetype="application/zip")
    resp.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


@app.route("/file/<job>")
def get_file_legacy(job):
    j = _ready(job)
    with j["lock"]:
        n = len(j["files"])
    return get_file(job, 0) if n == 1 else get_zip(job)


# ------------------------------------------------------------------- admin
@app.route("/api/admin/stats")
@authed(admin=True)
def admin_stats():
    try:
        du = shutil.disk_usage(BASE_DIR)
        disk = {"total": du.total, "free": du.free}
    except OSError:
        disk = {}
    with JOBS_LOCK:
        jobs = list(JOBS.values())
    rows = []
    for j in sorted(jobs, key=lambda v: -v["created"])[:100]:
        with j["lock"]:
            rows.append({"id": j["id"], "short": j["id"][:8], "user": j["user"], "ip": j["ip"], "status": j["status"],
                         "percent": j["percent"], "total": j["total"], "settled": j["settled"], "failed": j["failed"],
                         "files": len(j["files"]), "bytes": j["bytes"], "paused": j["pause"],
                         "label": j["label"] or j["p"]["url"][:60], "age": int(time.time() - j["created"])})
    today = date.today().isoformat()
    return jsonify(
        uptime=int(time.time() - START_TIME), ytdlp_running=running_version(), ytdlp_installed=installed_version(),
        update=UPDATE, ffmpeg=HAS_FFMPEG, aria2=HAS_ARIA2, deno=bool(DENO), cookies=bool(COOKIES),
        proxy=bool(PROXY_URL), po_token=bool(PO_TOKEN),
        disk=disk, downloads_bytes=dir_size(BASE_DIR), disk_limit=MAX_DISK_BYTES,
        active=sum(1 for r in rows if r["status"] not in FINISHED), jobs=rows,
        errors=list(ERRORS)[-30:][::-1],
        usage={u: b for (u, d), b in USAGE.items() if d == today}, daily_limit=DAILY_BYTES,
        limits={"parallel": PARALLEL_VIDEOS, "global": MAX_GLOBAL_VIDEOS, "jobs": MAX_JOBS, "queue": MAX_QUEUE,
                "playlist": MAX_PLAYLIST}, gunicorn=UNDER_GUNICORN)


@app.route("/api/admin/update", methods=["POST"])
@authed(admin=True)
def admin_update():
    threading.Thread(target=update_ytdlp, daemon=True).start()
    return jsonify(ok=True)


@app.route("/api/admin/job/<job>/<action>", methods=["POST"])
@authed(admin=True)
def admin_job(job, action):
    j = JOBS.get(job)
    if not j:
        return jsonify(error="No such job."), 404
    if action == "cancel":
        j["cancel"] = True
    elif action == "delete":
        j["cancel"] = True
        drop_job(job)
    else:
        return jsonify(error="Unknown action."), 400
    return jsonify(ok=True)


@app.errorhandler(404)
def _404(e):
    return (getattr(e, "description", None) or "Not found"), 404


def run():
    from waitress import serve
    start_background()
    port = int(os.environ.get("PORT", "5000"))
    print(f"Server running on port {port}  (ffmpeg={HAS_FFMPEG}, aria2c={HAS_ARIA2}, deno={bool(DENO)}, "
          f"cookies={'yes' if COOKIES else 'no'}, users={len(USERS)}, yt-dlp={running_version()}, "
          f"parallel={PARALLEL_VIDEOS}/{MAX_GLOBAL_VIDEOS}, max playlist={MAX_PLAYLIST})", flush=True)
    if not AUTH_ON:
        print("WARNING: no ACCESS_CODE set - anyone with the link can use this server.", flush=True)
    serve(app, host="0.0.0.0", port=port, threads=_env_int("THREADS", 32, 4))


load_jobs()
start_background()

if __name__ == "__main__":
    run()
