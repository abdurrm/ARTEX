#!/bin/bash
# CVE-2026-98432 is a kernel race: containers share the host kernel, so the lab
# is a disposable VM you own (e.g. an Ubuntu 24.04 or RHEL 9 cloud image booted
# with an unfixed kernel, plus a second VM on the fixed kernel).
# This script refuses non-private addresses, copies the PoC to each VM and runs it.
#
# Usage: LAB_VULNERABLE=user@10.0.0.5 [LAB_PATCHED=user@10.0.0.6] ./setup.sh
#
# Race triggers (if a reviewed one is ever added) run only on these VMs, with
# the expectation that the VM panics.
set -e
cd "$(dirname "$0")"

private() {
  python3 -I -c 'import ipaddress,socket,sys; ip=ipaddress.ip_address(socket.gethostbyname(sys.argv[1])); sys.exit(0 if ip.is_private or ip.is_loopback else 1)' "$1"
}

: "${LAB_VULNERABLE:?set LAB_VULNERABLE=user@host of a disposable VM}"
for t in "$LAB_VULNERABLE" ${LAB_PATCHED:-}; do
  host=${t#*@}
  if ! private "$host"; then
    echo "Refusing $t: lab VMs must be on loopback or private addresses" >&2
    exit 1
  fi
  echo "== $t"
  scp -q ../poc/verify_kernel.sh "$t:/tmp/verify_kernel.sh"
  ssh "$t" 'bash /tmp/verify_kernel.sh; rc=$?; rm -f /tmp/verify_kernel.sh; exit $rc' || true
done
