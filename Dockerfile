FROM python:3.12-slim

# tcpdump is only used to compile a kernel BPF filter (optional - the tool
# falls back to Python-side filtering); tini gives clean signal handling.
# Capture uses AF_PACKET directly, so libpcap is not required.
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump tini && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt requirements-dashboard.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dashboard.txt

COPY . .

# Capture needs host networking + NET_RAW/NET_ADMIN. The dashboard must listen
# on 0.0.0.0 inside the container to be reachable through the published port:
#   docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -e WIT_HOST=0.0.0.0 wit --dashboard
ENTRYPOINT ["tini", "--", "python", "main.py"]
CMD ["--dashboard"]
