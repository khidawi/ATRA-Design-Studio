FROM python:3.14-slim

# git reads the repositories that are connected (repo_connect.py); nothing from them is ever executed
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

# The API does not run as root. The code stays owned by root and read-only to the application, so a flaw in the application cannot rewrite it; the only place it
# writes is /tmp (the throwaway checkouts of connected repositories), which the production compose file mounts as a memory-only temporary filesystem.
RUN groupadd --system --gid 10001 astra && useradd --system --uid 10001 --gid astra --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin astra

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    FORWARDED_ALLOW_IPS=127.0.0.1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER 10001:10001

EXPOSE 8765

HEALTHCHECK --interval=15s --timeout=4s --start-period=40s --retries=4 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=3).status == 200 else 1)"

# --proxy-headers makes the API see the address and the https scheme that the proxy in front of it saw (so the session cookie is marked Secure). It trusts those headers only
# from FORWARDED_ALLOW_IPS: the production compose file sets it to the private network the proxy is on; never publish the API port when it is wider than 127.0.0.1.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8765", "--proxy-headers"]
