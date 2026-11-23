#!/bin/bash
# REDCap is only distributed to consortium members, so this lab is built from
# the release zip you download yourself (same version as the target, e.g.
# redcap16.0.48.zip for vulnerable and redcap16.0.49.zip for patched):
#   http://127.0.0.1:28110/redcap   (PHP 8.2 + Apache + MariaDB)
# Usage: REDCAP_ZIP=/path/redcapX.Y.Z.zip ./setup.sh
#        ./setup.sh down
set -e
cd "$(dirname "$0")"

if [ "${1:-}" = "down" ]; then
  docker compose down -v --rmi local
  rm -rf build
  exit 0
fi

: "${REDCAP_ZIP:?set REDCAP_ZIP to the REDCap release zip from the consortium download page}"
echo "Setting up REDCap lab from $REDCAP_ZIP..."

rm -rf build && mkdir -p build
unzip -q "$REDCAP_ZIP" -d build      # yields build/redcap/
cat > build/redcap/database.php << 'EOF2'
<?php
$hostname = 'db';
$db       = 'redcap';
$username = 'redcap';
$password = 'lab-only';
$salt     = 'lab-only-salt-0123456789';
EOF2

cat > Dockerfile << 'EOF2'
FROM php:8.2-apache
RUN apt-get update && apt-get install -y --no-install-recommends libzip-dev libpng-dev libicu-dev \
 && docker-php-ext-install mysqli zip gd intl \
 && rm -rf /var/lib/apt/lists/*
COPY build/redcap /var/www/html/redcap
RUN chown -R www-data:www-data /var/www/html/redcap
EOF2

cat > docker-compose.yml << 'EOF2'
# Lab only: port binds to loopback. Never expose these containers or load real data.
services:
  db:
    image: mariadb:10.11
    environment:
      MARIADB_DATABASE: redcap
      MARIADB_USER: redcap
      MARIADB_PASSWORD: lab-only
      MARIADB_ROOT_PASSWORD: lab-only-root
  web:
    build: .
    container_name: redcap-lab
    depends_on: [db]
    ports: ["127.0.0.1:28110:80"]
EOF2

echo "Starting containers..."
docker compose up -d --build

echo ""
echo "Lab ready! Finish the install wizard once:"
echo "  http://127.0.0.1:28110/redcap/install.php  (run the generated SQL into the 'db' service)"
echo ""
echo "Run POCs:"
echo "  python3 ../poc/verify_exposure.py --target http://127.0.0.1:28110/redcap"
