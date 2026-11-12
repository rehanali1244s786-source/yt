FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg aria2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Railway injects $PORT at runtime. Runs as root so an attached Railway volume is writable.
ENV PYTHONUNBUFFERED=1
CMD ["sh", "start.sh"]
