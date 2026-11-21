#!/bin/bash
# Builds a local Apache Axis 1.4 lab (the stock axis webapp on Tomcat 9 / JRE 8):
#   vulnerable Axis 1.4 -> http://127.0.0.1:18083/axis/
# There is no fixed Axis 1.x release; the "patched" comparison is the same
# lab with the Axis servlet mappings blocked (see SKILL.md mitigations).
# Usage: ./setup.sh        build and start
#        ./setup.sh down   stop and remove
set -e
cd "$(dirname "$0")"

if [ "${1:-}" = "down" ]; then
  docker compose down --rmi local
  exit 0
fi

echo "Setting up Apache Axis 1.4 lab..."

cat > Dockerfile << 'EOF2'
FROM tomcat:9-jre8
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://archive.apache.org/dist/ws/axis/1_4/axis-bin-1_4.tar.gz | tar xz -C /tmp \
 && cp -r /tmp/axis-1_4/webapps/axis /usr/local/tomcat/webapps/axis \
 && rm -rf /tmp/axis-1_4
EOF2

cat > docker-compose.yml << 'EOF2'
# Lab only: port binds to loopback. Never expose this container.
services:
  axis:
    build: .
    container_name: axis1-lab
    ports: ["127.0.0.1:18083:8080"]
EOF2

echo "Starting containers..."
docker compose up -d --build
for _ in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:18083/axis/ && break; sleep 2; done

echo ""
echo "Lab ready!"
echo "  Axis 1.4: http://127.0.0.1:18083/axis/  (services: /axis/services, WSDL: /axis/services/Version?wsdl)"
echo ""
echo "Run POCs:"
echo "  python3 ../poc/verify_exposure.py --target http://127.0.0.1:18083"
