#!/usr/bin/env python3
"""
CVE-2026-111812..111815 - Fingerprint Apache Traffic Server and classify the version.

Demonstrates:
  1. ATS identification from Server / Via headers (one HEAD request)
  2. version against the fixed releases 9.2.16 / 10.1.5 / 10.2.1
Each CVE also needs a configuration (plugin or sni.yaml); this script only
settles the version half. Use verify_ticket_bypass.sh for CVE-2026-111815.

Usage:
  python3 verify_exposure.py --target https://127.0.0.1:28443

For authorized security testing only.
"""
import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request


def affected(v):
    if v < (9, 0, 0):
        return v >= (8, 0, 0)  # 8.x has no fixed release
    if v < (10, 0, 0):
        return v < (9, 2, 16)
    if v < (10, 2, 0):
        return v < (10, 1, 5)
    return v < (10, 2, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="https://127.0.0.1:28443")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(args.target, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=args.timeout, context=ctx) as r:
            hdrs = r.headers
    except urllib.error.HTTPError as e:
        hdrs = e.headers
    except (urllib.error.URLError, OSError) as e:
        print(f"[?] Connection failed: {e}. UNKNOWN")
        return 2
    server, via = hdrs.get("Server", ""), hdrs.get("Via", "")
    print(f"[*] Server: {server!r}  Via: {via!r}")
    m = re.search(r"ATS/(\d+)\.(\d+)\.(\d+)", server + " " + via)
    if not m:
        print("[?] No ATS version in headers (proxy.config.http.response_server_enabled off?). UNKNOWN")
        return 2
    v = tuple(map(int, m.groups()))
    print(f"[*] ATS {'.'.join(map(str, v))}")
    if affected(v):
        print("[+] Version AFFECTED by the October 2026 set; now check plugin.config / sni.yaml per CVE")
        return 1
    print("[-] Fixed version: NOT AFFECTED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
