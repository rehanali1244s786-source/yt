import os
bind = "0.0.0.0:" + os.environ.get("PORT", "5000")
worker_class = "gthread"   # long downloads must not be killed
workers = 1                # jobs live in memory -> keep ONE worker
threads = int(os.environ.get("THREADS", "32"))   # progress polls + streamed ZIPs hold a thread each
timeout = 0
graceful_timeout = 30
keepalive = 30
accesslog = "-"
forwarded_allow_ips = "*"  # we sit behind the host's proxy
