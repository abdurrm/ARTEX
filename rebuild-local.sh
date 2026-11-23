#!/usr/bin/env bash
# Rebuilds and restarts the Docker deployment with the current commit as the
# version shown in the dashboard footer: "<short sha>-<commit date>", plus
# "-dirty" when the working tree has uncommitted changes.
set -euo pipefail
cd "$(dirname "$0")"

version="$(git log -1 --format=%h-%cd --date=format:%Y-%m-%d)"
git diff --quiet HEAD -- . ':!skills' 2>/dev/null || version="${version}-dirty"

echo "Building ARTEX ${version}"
ARTEX_VERSION="$version" docker compose build artex
docker compose up -d
docker compose ps
