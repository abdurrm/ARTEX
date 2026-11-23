#!/usr/bin/env python3
"""
CVE-2026-90817 - Read the REDCap version from its versioned code directory
(redcap_vX.Y.Z) and classify it. Read-only GETs; no exploit requests.

Demonstrates:
  1. version from asset URLs / footer on the login or survey pages
  2. verdict per track: 16.0.x LTS fixed 16.0.49, 17.3.x LTS fixed 17.3.10,
     17.4.x Standard fixed 17.4.4; affected from 13.3.0 otherwise

Usage:
  python3 verify_exposure.py --target https://redcap.example/redcap

For authorized security testing only.
"""
import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request

FIRST = (13, 3, 0)
FIXED = {(16, 0): 49, (17, 3): 10, (17, 4): 4}


def verdict(v):
    if v < FIRST:
        return "not affected (predates 13.3.0)"
    if v[:2] in FIXED:
        return "fixed" if v[2] >= FIXED[v[:2]] else "AFFECTED"
    if v > (17, 4, 4):
        return "fixed"
    return "AFFECTED (no fixed build on this branch: move to a fixed LTS/Standard)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="REDCap base URL")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(args.target.rstrip("/") + "/", timeout=args.timeout, context=ctx) as r:
            body = r.read(262144).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read(262144).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        print(f"[?] unreachable: {e}. UNKNOWN")
        return 2
    vers = sorted({tuple(map(int, m)) for m in re.findall(r"redcap_v(\d+)\.(\d+)\.(\d+)", body)})
    if not vers:
        m = re.search(r"REDCap\s+(\d+)\.(\d+)\.(\d+)", body)
        vers = [tuple(map(int, m.groups()))] if m else []
    if not vers:
        print("[-] No REDCap version marker on this page. NOT FOUND (try the login page URL)")
        return 0
    v = vers[-1]
    res = verdict(v)
    print(f"[*] REDCap {'.'.join(map(str, v))}: {res}")
    if res.startswith("AFFECTED"):
        print("[+] AFFECTED by CVE-2026-90817 (KEV)")
        return 1
    print("[-] NOT AFFECTED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
