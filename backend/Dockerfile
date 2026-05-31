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
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Install nikto from source (not in debian repos)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

WORKDIR /app

COPY backend/pyproject.toml ./
RUN pip install --no-cache-dir -e "."

COPY backend/ .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
