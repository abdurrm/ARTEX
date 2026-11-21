#!/bin/bash
# Synology DSM is licensed and cannot be built as a container here. The lab is an
# isolated spare NAS or DSM VM on the same build you own (vulnerable build, and ideally a second one on the
# fixed build). This script refuses anything that is not loopback/private, then
# runs the PoC against each lab instance so its output can be compared with the
# real target's output.
#
# Usage: LAB_VULNERABLE=https://10.0.0.50:5001 [LAB_PATCHED=https://10.0.0.51:5001] ./setup.sh [extra PoC args]
#   e.g. LAB_VULNERABLE=https://10.0.0.50:5001 ./setup.sh --fixed-build <build>
set -e
cd "$(dirname "$0")"

private() {
  python3 -I -c 'import ipaddress,socket,sys,urllib.parse as u; h=u.urlparse(sys.argv[1]).hostname or sys.argv[1]; ip=ipaddress.ip_address(socket.gethostbyname(h)); sys.exit(0 if ip.is_private or ip.is_loopback else 1)' "$1"
}

: "${LAB_VULNERABLE:?set LAB_VULNERABLE to your isolated lab instance}"
for t in "$LAB_VULNERABLE" ${LAB_PATCHED:-}; do
  if ! private "$t"; then
    echo "Refusing $t: lab instances must be on loopback or private addresses" >&2
    exit 1
  fi
  echo "== lab: $t"
  python3 -I ../poc/verify_exposure.py --target "$t" "$@" || true
done
echo ""
echo "Lab run complete. Now run the same PoC against the authorized target and compare."
