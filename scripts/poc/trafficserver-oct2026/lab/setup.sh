#!/bin/bash
# Builds two local Apache Traffic Server reverse-proxy labs from source, with a
# per-SNI mTLS policy so CVE-2026-111815 (session-ticket resumption skipping
# verify_client STRICT) can be checked:
#   vulnerable 10.2.0 -> https://127.0.0.1:28443
#   patched    10.2.1 -> https://127.0.0.1:29443
#   SNI open.lab   -> no client certificate required
#   SNI strict.lab -> verify_client STRICT (client certificate required)
# Building ATS takes several minutes per version.
# Usage: ./setup.sh        build and start
#        ./setup.sh down   stop and remove
set -e
cd "$(dirname "$0")"

if [ "${1:-}" = "down" ]; then
  docker compose down --rmi local
  exit 0
fi

echo "Setting up Apache Traffic Server lab (10.2.0 vulnerable, 10.2.1 patched)..."

cat > Dockerfile << 'EOF2'
FROM debian:bookworm-slim
ARG ATS_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build pkg-config ca-certificates curl bzip2 openssl \
      libssl-dev libpcre3-dev libpcre2-dev zlib1g-dev libcap-dev libhwloc-dev libncurses-dev \
      libcurl4-openssl-dev libunwind-dev libyaml-cpp-dev python3 \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://archive.apache.org/dist/trafficserver/trafficserver-${ATS_VERSION}.tar.bz2 | tar xj -C /tmp \
 && cd /tmp/trafficserver-${ATS_VERSION} \
 && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/ts -DBUILD_TESTING=OFF \
 && cmake --build build -j"$(nproc)" && cmake --install build \
 && rm -rf /tmp/trafficserver-${ATS_VERSION}
WORKDIR /opt/ts/etc/trafficserver
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=lab-ca -keyout ca.key -out ca.crt \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=open.lab \
      -addext "subjectAltName=DNS:open.lab,DNS:strict.lab" -keyout server.key -out server.crt \
 && printf 'dest_ip=* ssl_cert_name=server.crt ssl_key_name=server.key\n' > ssl_multicert.config \
 && printf 'map / http://127.0.0.1:8081/\n' > remap.config \
 && printf 'sni:\n  - fqdn: open.lab\n    verify_client: NONE\n  - fqdn: strict.lab\n    verify_client: STRICT\n    verify_client_ca_certs: /opt/ts/etc/trafficserver/ca.crt\n' > sni.yaml \
 && printf 'ip_allow:\n  - apply: in\n    ip_addrs: 0/0\n    action: allow\n    methods: ALL\n  - apply: in\n    ip_addrs: ::/0\n    action: allow\n    methods: ALL\n' > ip_allow.yaml \
 && chown -R nobody:nogroup /opt/ts/var /opt/ts/etc/trafficserver
COPY start.sh /start.sh
CMD ["/bin/bash", "/start.sh"]
EOF2

cat > start.sh << 'EOF2'
#!/bin/bash
# Tiny origin on 8081 plus ATS listening on 443 (TLS) with session tickets on (default).
mkdir -p /srv && echo "lab origin" > /srv/index.html
python3 -m http.server 8081 --directory /srv >/dev/null 2>&1 &
export PROXY_CONFIG_HTTP_SERVER_PORTS='8080 443:ssl'
/opt/ts/bin/traffic_server &
wait -n
EOF2

cat > docker-compose.yml << 'EOF2'
# Lab only: ports bind to loopback. Never expose these containers.
services:
  vulnerable:
    build: { context: ., args: { ATS_VERSION: "10.2.0" } }
    container_name: ats-lab-vulnerable
    ports: ["127.0.0.1:28443:443"]
  patched:
    build: { context: ., args: { ATS_VERSION: "10.2.1" } }
    container_name: ats-lab-patched
    ports: ["127.0.0.1:29443:443"]
EOF2

echo "Starting containers..."
docker compose up -d --build

echo ""
echo "Lab ready!"
echo "  vulnerable 10.2.0: https://127.0.0.1:28443"
echo "  patched    10.2.1: https://127.0.0.1:29443"
echo ""
echo "Run POCs:"
echo "  python3 ../poc/verify_exposure.py --target https://127.0.0.1:28443"
echo "  ../poc/verify_ticket_bypass.sh 127.0.0.1:28443 open.lab strict.lab"
echo "  ../poc/verify_ticket_bypass.sh 127.0.0.1:29443 open.lab strict.lab"
