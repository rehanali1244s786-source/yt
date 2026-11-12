#!/bin/sh
# Keep yt-dlp fresh: YouTube changes often and an old yt-dlp is the #1 cause of sudden failures.
if [ "${AUTO_UPDATE_YTDLP:-1}" != "0" ]; then
  timeout 120 pip install -q -U --no-cache-dir "yt-dlp[default]" || echo "yt-dlp update skipped"
fi
exec gunicorn -c gunicorn.conf.py main:app
