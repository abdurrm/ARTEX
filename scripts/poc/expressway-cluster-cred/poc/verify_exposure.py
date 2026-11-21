#!/usr/bin/env python3
"""
CVE-2026-76466 - Fingerprint Cisco Expressway and test whether cluster
replication ports are reachable from the tester's position. Never uses the
hard-coded credential.

Demonstrates:
  1. Expressway web admin identification and version (if shown on the login page)
  2. TCP reachability of the cluster ports given with --cluster-ports (take
     them from Cisco's "Expressway IP Port Usage" guide for the release)
  3. verdict: X15.5.20+ fixed; clustered + reachable + unfixed = affected

Usage:
  python3 verify_exposure.py --target https://exp.example --cluster-ports 4369,9001 [--clustered]

For authorized security testing only.
"""
import argparse
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--cluster-ports", default="", help="comma list from Cisco's port guide")
    ap.add_argument("--clustered", action="store_true", help="operator confirms the node is clustered")
    ap.add_argument("--version", help="version from the admin Overview page, e.g. X15.5.3")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()
    host = urlparse(args.target).hostname
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = ""
    try:
        with urllib.request.urlopen(args.target.rstrip("/") + "/login", timeout=args.timeout, context=ctx) as r:
            body = r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        print(f"[?] web admin unreachable: {e}")
    is_exp = bool(re.search(r"Expressway|TANDBERG|Cisco VCS", body, re.I))
    ver = args.version or (re.search(r"X\d+\.\d+(?:\.\d+)?", body) or [None])[0]
    print(f"[*] Expressway login page: {is_exp}  version: {ver}")

    reach = []
    for p in [int(x) for x in args.cluster_ports.split(",") if x.strip()]:
        try:
            socket.create_connection((host, p), timeout=3).close()
            reach.append(p)
        except OSError:
            pass
    print(f"[*] cluster ports reachable from here: {reach or 'none'}")

    m = re.match(r"X?(\d+)\.(\d+)(?:\.(\d+))?", ver or "")
    if not m:
        print("[?] Version unknown (pass --version). UNKNOWN")
        return 2
    v = tuple(int(x or 0) for x in m.groups())
    if v >= (15, 5, 20):
        print("[-] X15.5.20 or later: NOT AFFECTED")
        return 0
    if not args.clustered:
        print("[?] Unfixed version; confirm clustering (System > Clustering) and rerun with --clustered. UNKNOWN")
        return 2
    if reach:
        print("[+] AFFECTED: clustered, unfixed, cluster ports reachable (CVE-2026-76466, KEV)")
        return 1
    print("[~] Clustered and unfixed, cluster ports filtered from here: HARDENING-RELEVANT")
    return 2


if __name__ == "__main__":
    sys.exit(main())
