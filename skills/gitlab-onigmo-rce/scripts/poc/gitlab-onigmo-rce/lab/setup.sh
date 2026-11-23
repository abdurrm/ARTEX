#!/bin/bash
# Starts two local GitLab CE labs and mints a read_api token on each:
#   vulnerable 19.4.1 (both CVEs) -> http://127.0.0.1:28100
#   patched    19.5.1 (both fixed) -> http://127.0.0.1:28101
# Each container needs ~4 GB RAM and several minutes to boot.
# Usage: ./setup.sh        pull, start, and print tokens
#        ./setup.sh down   stop and remove
set -e
cd "$(dirname "$0")"

if [ "${1:-}" = "down" ]; then
  docker compose down -v
  exit 0
fi

echo "Setting up GitLab regex-engine lab (19.4.1 vulnerable, 19.5.1 patched)..."

cat > docker-compose.yml << 'EOF2'
# Lab only: ports bind to loopback. Never expose these containers.
x-gitlab: &gitlab
  shm_size: 256m
  environment:
    GITLAB_ROOT_PASSWORD: "Lab-Only-Passw0rd!"
    GITLAB_OMNIBUS_CONFIG: |
      prometheus_monitoring['enable'] = false
      puma['worker_processes'] = 2
services:
  vulnerable:
    <<: *gitlab
    image: gitlab/gitlab-ce:19.4.1-ce.0
    container_name: gitlab-lab-vulnerable
    ports: ["127.0.0.1:28100:80"]
  patched:
    <<: *gitlab
    image: gitlab/gitlab-ce:19.5.1-ce.0
    container_name: gitlab-lab-patched
    ports: ["127.0.0.1:28101:80"]
EOF2

echo "Starting containers (first boot takes several minutes)..."
docker compose up -d
for port in 28100 28101; do
  for _ in $(seq 1 180); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/users/sign_in")" = "200" ] && break
    sleep 5
  done
done

echo "Minting lab tokens..."
for c in gitlab-lab-vulnerable gitlab-lab-patched; do
  tok=$(docker exec "$c" gitlab-rails runner \
    "t = User.find_by_username('root').personal_access_tokens.create!(name: 'lab', scopes: [:read_api], expires_at: 7.days.from_now); puts t.token" 2>/dev/null | tail -1)
  echo "$c=$tok" >> tokens.env
done

echo ""
echo "Lab ready! Tokens in lab/tokens.env"
echo "  vulnerable 19.4.1: http://127.0.0.1:28100"
echo "  patched    19.5.1: http://127.0.0.1:28101"
echo ""
echo "Run POCs:"
echo "  python3 ../poc/verify_exposure.py --target http://127.0.0.1:28100 --token <vulnerable token>"
echo "  python3 ../poc/verify_exposure.py --target http://127.0.0.1:28101 --token <patched token>"
