FROM python:3.12-slim

# System packages — only what's in debian:slim repos
# nikto and whatweb are Kali-only; skip apt, install nikto via git below
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    dnsutils \
    whois \
    traceroute \
    netcat-openbsd \
    openssl \
    net-tools \
    perl \
    git \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Install nikto from source (not in debian repos).
# Pinned to a release tag for reproducible builds.
RUN git clone --depth 1 --branch 2.6.0 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

WORKDIR /app

COPY pyproject.toml requirements.lock ./
# requirements.lock pins exact transitive versions for reproducible builds.
RUN pip install --no-cache-dir -e "." -c requirements.lock

COPY . .

EXPOSE 8000

# Honor the platform-injected $PORT (Render/Heroku/etc.); default to 8000 locally.
# Shell form so ${PORT} is expanded at runtime.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
