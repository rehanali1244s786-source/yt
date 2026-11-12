YT DOWNLOADER v4  -  Railway edition
====================================

WHAT'S NEW IN v4
  Reliability
   - Jobs are saved to disk and RESUME after a restart / redeploy / yt-dlp update.
   - "Retry" button re-runs only failed (or cancelled / skipped) videos.
   - Playlist preview: tick the videos you want before downloading.
   - Background queue: extra jobs wait for a free slot instead of being refused.
   - Pause / Resume (running videos finish; no new ones start). "My downloads" list
     lets you leave and come back to any job.
   - Clear messages: bot check, private, age-restricted, 429, geo-blocked.
     Bot-block help box points to cookies / proxy. PROXY_URL, YT_PO_TOKEN supported.
   - yt-dlp auto-update on every start (start.sh) and daily when idle, followed by
     an in-place reload; running jobs resume by themselves.
  Formats
   - MP4, MP3, M4A and Opus (M4A/Opus are copied without re-encoding when possible),
     cover art + tags, split by chapters, subtitles (.srt, manual or auto captions).
  Access / ops
   - Per-user codes -> expiring signed tokens (the code is never stored in the browser).
   - Optional daily download cap per user.
   - /admin page: jobs, disk, recent errors, usage, "Update yt-dlp & reload", cancel/delete.

DEPLOY ON RAILWAY
  1. Push this folder to a private GitHub repo (cookies.txt is git-ignored).
  2. railway.com > New Project > Deploy from GitHub repo. It builds the Dockerfile and
     uses railway.toml (health check /healthz).
  3. Service > Variables:
        ACCESS_CODE       one shared password            (or)
        ACCESS_CODES      alice:pw1,bob:pw2              (one code per person)
        ADMIN_CODE        password for /admin
        SECRET_KEY        any long random string (keeps logins valid across restarts)
        YT_COOKIES_B64    optional: base64 -w0 cookies.txt  (throw-away Google account!)
     Do NOT set PORT (Railway sets it). Without any code, ANYONE can use your server.
  4. Add a Volume (Service > Volume). Downloads AND job state live there, so jobs survive
     redeploys. Set MAX_DISK_GB slightly below the volume size.
  5. Settings > Networking > Generate Domain, open the https URL.
  Keep replicas at 1 (the queue lives in one process). The old cookies were in the zip you
  shared earlier: log out of that Google session so they stop working.

ENV VARS (all optional)
  Limits   PARALLEL_VIDEOS (2) per job   MAX_GLOBAL_VIDEOS (6) whole server   MAX_JOBS (3) at once
           MAX_QUEUE (20) waiting        MAX_JOBS_PER_IP (3)   STARTS_PER_HOUR (30)
           MAX_PLAYLIST (300; 0 = unlimited)   MAX_JOB_GB (15)   MAX_DISK_GB (40)
           DAILY_GB_PER_USER (0 = off)   TTL_MIN (120)   ZIP_PART_FILES (50)
  YouTube  PROXY_URL (http://user:pass@host:port)   YT_PO_TOKEN (web.gvs+...)   YT_VISITOR_DATA
           ALLOWED_HOSTS (default youtube.com,youtu.be,youtube-nocookie.com)
  Updates  AUTO_UPDATE_YTDLP=0 to skip the start-up update   AUTO_UPDATE_HOURS (24, 0 = off)
  Other    TOKEN_HOURS (12)  TRUST_PROXY (1)  DOWNLOAD_DIR  THREADS (32)
           YT_COOKIES_B64 / YT_COOKIES / COOKIES_FILE

NOTES
  - Preview shows up to 1000 videos; a job downloads at most MAX_PLAYLIST of them.
  - ZIP parts group ZIP_PART_FILES files (subtitle / chapter files count as files).
  - Chapter splitting, subtitles and cover art need ffmpeg (included in the Docker image).
  - Railway bills by usage - big playlists cost bandwidth and CPU.
  - Only download videos you own or have permission to download. A public downloader may
    breach YouTube's Terms of Service - keep it behind an access code.
