#!/bin/bash
# Builds two local Apache httpd labs with mod_http2 over TLS (h2) and cleartext (h2c):
#   vulnerable 2.4.70 -> https://127.0.0.1:18443  http://127.0.0.1:18480
#   patched    2.4.71 -> https://127.0.0.1:19443  http://127.0.0.1:19480
# Usage: ./setup.sh        build and start
#        ./setup.sh down   stop and remove
set -e
cd "$(dirname "$0")"

if [ "${1:-}" = "down" ]; then
  docker compose down --rmi local
  exit 0
fi

echo "Setting up Apache httpd mod_http2 lab (2.4.70 vulnerable, 2.4.71 patched)..."

cat > h2.conf << 'EOF2'
LoadModule ssl_module modules/mod_ssl.so
LoadModule http2_module modules/mod_http2.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
Protocols h2 h2c http/1.1
Listen 443
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /usr/local/apache2/conf/lab.crt
    SSLCertificateKeyFile /usr/local/apache2/conf/lab.key
    Protocols h2 http/1.1
</VirtualHost>
EOF2

cat > Dockerfile << 'EOF2'
ARG HTTPD_VERSION
FROM httpd:${HTTPD_VERSION}
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/* \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=lab \
      -keyout /usr/local/apache2/conf/lab.key -out /usr/local/apache2/conf/lab.crt \
 && echo 'Include conf/h2.conf' >> /usr/local/apache2/conf/httpd.conf
COPY h2.conf /usr/local/apache2/conf/h2.conf
EOF2

cat > docker-compose.yml << 'EOF2'
# Lab only: ports bind to loopback. Never expose these containers.
services:
  vulnerable:
    build: { context: ., args: { HTTPD_VERSION: "2.4.70" } }
    container_name: httpd-h2-lab-vulnerable
    ports: ["127.0.0.1:18443:443", "127.0.0.1:18480:80"]
  patched:
    build: { context: ., args: { HTTPD_VERSION: "2.4.71" } }
    container_name: httpd-h2-lab-patched
    ports: ["127.0.0.1:19443:443", "127.0.0.1:19480:80"]
EOF2

echo "Starting containers..."
docker compose up -d --build

echo ""
echo "Lab ready!"
echo "  vulnerable 2.4.70: https://127.0.0.1:18443  (h2c: http://127.0.0.1:18480)"
echo "  patched    2.4.71: https://127.0.0.1:19443  (h2c: http://127.0.0.1:19480)"
echo ""
echo "Run POCs:"
echo "  python3 ../poc/verify_exposure.py --target https://127.0.0.1:18443 --h2c http://127.0.0.1:18480"
echo "  python3 ../poc/verify_exposure.py --target https://127.0.0.1:19443 --h2c http://127.0.0.1:19480"
echo "Watch for child crashes (lab only race triggers): docker compose logs -f"
