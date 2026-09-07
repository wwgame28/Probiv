FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Isolate OSINT engines because their dependency ranges can conflict.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

COPY requirements-bot.txt /app/

RUN python -m venv /app/runtime/bot \
 && /app/runtime/bot/bin/pip install --upgrade pip setuptools wheel \
 && /app/runtime/bot/bin/pip install -r /app/requirements-bot.txt \
 && python -m venv /app/runtime/maigret \
 && /app/runtime/maigret/bin/pip install --upgrade pip setuptools wheel \
 && /app/runtime/maigret/bin/pip install "maigret==0.6.5" \
 && python -m venv /app/runtime/sherlock \
 && /app/runtime/sherlock/bin/pip install --upgrade pip setuptools wheel \
 && /app/runtime/sherlock/bin/pip install "sherlock-project==0.16.0" \
 && mkdir -p /app/vendor/spiderfoot \
 && curl -fsSL https://github.com/smicallef/spiderfoot/archive/refs/tags/v4.0.tar.gz \
    | tar -xz --strip-components=1 -C /app/vendor/spiderfoot \
 && sed -i 's/^pyyaml>=5\.4\.1,<6$/PyYAML>=6.0.2,<7/' /app/vendor/spiderfoot/requirements.txt \
 && python -m venv /app/runtime/spiderfoot \
 && /app/runtime/spiderfoot/bin/pip install --upgrade pip setuptools wheel \
 && /app/runtime/spiderfoot/bin/pip install -r /app/vendor/spiderfoot/requirements.txt \
 && arch="$(dpkg --print-architecture)" \
 && case "$arch" in amd64) sfarch=amd64 ;; arm64) sfarch=arm64 ;; *) echo "Unsupported architecture: $arch"; exit 1 ;; esac \
 && curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_linux_${sfarch}.zip" -o /tmp/subfinder.zip \
 && unzip -q /tmp/subfinder.zip -d /tmp/subfinder \
 && install -m 0755 /tmp/subfinder/subfinder /app/runtime/subfinder \
 && rm -rf /tmp/subfinder /tmp/subfinder.zip

COPY bot.py main.py README.md .env.example PROJECT.json /app/
RUN mkdir -p /app/data/reports

CMD ["/app/runtime/bot/bin/python", "/app/main.py"]
