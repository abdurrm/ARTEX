#!/bin/bash
# Builds two local NGINX labs from nginx.org sources, HTTP/2 over TLS, static files only:
#   vulnerable 1.31.8 -> https://127.0.0.1:8443
#   patched    1.31.9 -> https://127.0.0.1:9443
# Usage: ./setup.sh        build and start
#        ./setup.sh down   stop and remove
set -e
cd "$(dirname "$0")"

if [ "${1:-}" = "down" ]; then
  docker compose down --rmi local
  exit 0
fi

echo "Setting up NGINX HTTP/2 lab (1.31.8 vulnerable, 1.31.9 patched)..."

# Default-ish static server with HTTP/2 over TLS: the minimal affected configuration.
cat > nginx.conf << 'EOF2'
worker_processes 1;
events { worker_connections 1024; }
http {
    server {
        listen 443 ssl;
        http2 on;
        ssl_certificate     /etc/nginx/lab.crt;
        ssl_certificate_key /etc/nginx/lab.key;
        root /etc/nginx/html;   # big.bin gives a trigger a large response to queue
    }
}
EOF2

cat > Dockerfile << 'EOF2'
FROM debian:bookworm-slim
ARG NGINX_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl libpcre2-dev libssl-dev zlib1g-dev openssl \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSLO https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
 && tar xzf nginx-${NGINX_VERSION}.tar.gz && cd nginx-${NGINX_VERSION} \
 && ./configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx \
      --error-log-path=/dev/stderr --http-log-path=/dev/stdout \
      --with-http_ssl_module --with-http_v2_module \
 && make -j"$(nproc)" && make install && cd / && rm -rf nginx-${NGINX_VERSION}*
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=lab \
      -keyout /etc/nginx/lab.key -out /etc/nginx/lab.crt \
 && head -c 64M /dev/urandom > /etc/nginx/html/big.bin
COPY nginx.conf /etc/nginx/conf/nginx.conf
CMD ["nginx", "-g", "daemon off;"]
EOF2

cat > docker-compose.yml << 'EOF2'
# Lab only: ports bind to loopback. Never expose these containers.
services:
  vulnerable:
    build: { context: ., args: { NGINX_VERSION: "1.31.8" } }
    container_name: nginx2shell-lab-vulnerable
    ports: ["127.0.0.1:8443:443"]
  patched:
    build: { context: ., args: { NGINX_VERSION: "1.31.9" } }
    container_name: nginx2shell-lab-patched
    ports: ["127.0.0.1:9443:443"]
EOF2

echo "Starting containers..."
docker compose up -d --build

echo ""
echo "Lab ready!"
echo "  vulnerable 1.31.8: https://127.0.0.1:8443"
echo "  patched    1.31.9: https://127.0.0.1:9443"
echo ""
echo "Run POCs:"
echo "  python3 ../poc/verify_exposure.py remote https://127.0.0.1:8443"
echo "  python3 ../poc/verify_exposure.py remote https://127.0.0.1:9443"
echo "Watch for worker crashes: docker compose logs -f | grep 'exited on signal'"
