# The learned service (ASTRA phase 10): the temporal graph network. Its own image, so the main backend image, its scans and its CI do not change.
# Build from the repository root:  docker build -f learned/Dockerfile -t astra-learned .
FROM python:3.14-slim

RUN groupadd --system --gid 10002 astralearned && useradd --system --uid 10002 --gid astralearned --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin astralearned

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp LEARNED_MODELS=/models

COPY learned/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && python -m pip uninstall -y pip setuptools wheel

# The statistical baseline of phase 9 is the yardstick the network is judged against: the same file the platform uses, copied in, not a second copy to keep in step.
COPY backend/astra_baseline.py /app/astra_baseline.py
COPY learned/ /app/learned/

RUN mkdir -p /models && chown astralearned:astralearned /models
VOLUME ["/models"]
USER 10002:10002

ENTRYPOINT ["python", "-m", "learned.tgn.service"]
CMD ["loop"]
