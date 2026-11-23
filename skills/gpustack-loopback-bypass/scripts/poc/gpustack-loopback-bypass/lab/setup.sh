#!/bin/bash
# Starts two local GPUStack servers (CPU only, no GPU needed for the auth check):
#   vulnerable v2.1.1 -> http://127.0.0.1:28090
#   patched    v2.2.2 -> http://127.0.0.1:28091
# Images are large (~3.3 GB and ~1.5 GB).
# Usage: ./setup.sh        pull and start
#        ./setup.sh down   stop and remove
set -e
cd "$(dirname "$0")"

if [ "${1:-}" = "down" ]; then
  docker compose down -v
  exit 0
fi

echo "Setting up GPUStack auth lab (v2.1.1 vulnerable, v2.2.2 patched)..."

cat > docker-compose.yml << 'EOF2'
# Lab only: ports bind to loopback. Never expose these containers.
services:
  vulnerable:
    image: gpustack/gpustack:v2.1.1
    container_name: gpustack-lab-vulnerable
    ports: ["127.0.0.1:28090:80"]
  patched:
    image: gpustack/gpustack:v2.2.2
    container_name: gpustack-lab-patched
    ports: ["127.0.0.1:28091:80"]
EOF2

echo "Starting containers..."
docker compose up -d
for port in 28090 28091; do
  for _ in $(seq 1 90); do curl -s -o /dev/null "http://127.0.0.1:${port}/version" && break; sleep 2; done
done

echo ""
echo "Lab ready!"
echo "  vulnerable v2.1.1: http://127.0.0.1:28090"
echo "  patched    v2.2.2: http://127.0.0.1:28091"
echo ""
echo "Run POCs:"
echo "  python3 ../poc/verify_loopback_bypass.py --target http://127.0.0.1:28090"
echo "  python3 ../poc/verify_loopback_bypass.py --target http://127.0.0.1:28091"
