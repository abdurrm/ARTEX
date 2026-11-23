#!/bin/bash
# Builds two local Apache Roller labs on Tomcat 9 + embedded Derby:
#   vulnerable 6.1.4 -> http://127.0.0.1:18081/roller
#   patched    6.1.7 -> http://127.0.0.1:18082/roller
# Usage: ./setup.sh        build and start
#        ./setup.sh down   stop and remove
set -e
cd "$(dirname "$0")"

if [ "${1:-}" = "down" ]; then
  docker compose down --rmi local -v
  exit 0
fi

echo "Setting up Apache Roller XML-RPC lab (6.1.4 vulnerable, 6.1.7 patched)..."

cat > roller-custom.properties << 'EOF2'
installation.type=auto
database.configurationType=jdbc
database.jdbc.driverClass=org.apache.derby.jdbc.EmbeddedDriver
database.jdbc.connectionURL=jdbc:derby:/var/lib/roller/db;create=true
database.jdbc.username=roller
database.jdbc.password=roller
mediafiles.storage.dir=/var/lib/roller/mediafiles
search.index.dir=/var/lib/roller/searchindex
log4j.appender.roller.File=/var/lib/roller/roller.log
EOF2

cat > Dockerfile << 'EOF2'
FROM tomcat:9-jre11
ARG ROLLER_VERSION
ARG DERBY=10.14.2.0
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://archive.apache.org/dist/roller/roller-6.1/v${ROLLER_VERSION}/apache-roller-${ROLLER_VERSION}-binary.tar.gz \
    | tar xz -C /tmp \
 && cp /tmp/apache-roller-${ROLLER_VERSION}/webapp/roller.war /usr/local/tomcat/webapps/roller.war \
 && rm -rf /tmp/apache-roller-* \
 && curl -fsSL -o /usr/local/tomcat/lib/derby.jar https://repo1.maven.org/maven2/org/apache/derby/derby/${DERBY}/derby-${DERBY}.jar \
 && curl -fsSL -o /tmp/derbytools.jar https://repo1.maven.org/maven2/org/apache/derby/derbytools/${DERBY}/derbytools-${DERBY}.jar \
 && mkdir -p /var/lib/roller \
 && unzip -p /usr/local/tomcat/webapps/roller.war WEB-INF/classes/dbscripts/derby/createdb.sql > /tmp/createdb.sql \
 && printf "connect 'jdbc:derby:/var/lib/roller/db;create=true;user=roller;password=roller';\nrun '/tmp/createdb.sql';\nexit;\n" > /tmp/init.ij \
 && java -cp /usr/local/tomcat/lib/derby.jar:/tmp/derbytools.jar org.apache.derby.tools.ij /tmp/init.ij > /tmp/ij.log \
 && ! grep -q 'ERROR ' /tmp/ij.log \
 && rm -f /tmp/derbytools.jar /tmp/createdb.sql /tmp/init.ij
COPY roller-custom.properties /usr/local/tomcat/lib/roller-custom.properties
EOF2

cat > docker-compose.yml << 'EOF2'
# Lab only: ports bind to loopback. Never expose these containers.
services:
  vulnerable:
    build: { context: ., args: { ROLLER_VERSION: "6.1.4" } }
    container_name: roller-lab-vulnerable
    ports: ["127.0.0.1:18081:8080"]
  patched:
    build: { context: ., args: { ROLLER_VERSION: "6.1.7" } }
    container_name: roller-lab-patched
    ports: ["127.0.0.1:18082:8080"]
EOF2

echo "Starting containers..."
docker compose up -d --build

echo "Waiting for Roller to deploy..."
for port in 18081 18082; do
  for _ in $(seq 1 60); do
    curl -s -o /dev/null "http://127.0.0.1:${port}/roller/" && break
    sleep 2
  done
done

echo ""
echo "Lab ready!"
echo "  vulnerable 6.1.4: http://127.0.0.1:18081/roller"
echo "  patched    6.1.7: http://127.0.0.1:18082/roller"
echo ""
echo "Run POCs:"
echo "  python3 ../poc/verify_extension_probe.py --target http://127.0.0.1:18081/roller"
echo "  python3 ../poc/verify_extension_probe.py --target http://127.0.0.1:18082/roller"
