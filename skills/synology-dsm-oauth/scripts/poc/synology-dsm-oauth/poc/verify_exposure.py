#!/usr/bin/env python3
"""
CVE-2026-120382 (and KEV CVE-2024-10441) - Fingerprint Synology DSM with
read-only GETs. Never calls the OAuth API or reads files.

Demonstrates:
  1. DSM login page reachable; build number from asset query strings (?v=NNNNN)
  2. SYNO.API.Info lists OAuth-related APIs (the vulnerable surface)
  3. build vs --fixed-build from Synology-SA-26:18/19 for the DSM line

Usage:
  python3 verify_exposure.py --target https://nas.example:5001 [--fixed-build 7XXXX]

For authorized security testing only.
"""
import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request


def get(url, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
            return r.status, r.read(262144).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, OSError):
        return None, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--fixed-build", type=int, help="first fixed DSM build for this line (from the advisory)")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()
    base = args.target.rstrip("/")

    st, body = get(base + "/", args.timeout)
    builds = sorted({int(b) for b in re.findall(r"[?&]v=(\d{4,6})\b", body)})
    dsm = "SYNO" in body or "webman" in body or "Synology" in body
    print(f"[*] / -> {st}  DSM markers: {dsm}  asset builds: {builds or 'none'}")

    st, body = get(base + "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all", args.timeout)
    oauth = []
    try:
        oauth = sorted(k for k in json.loads(body).get("data", {}) if "oauth" in k.lower())
    except ValueError:
        pass
    print(f"[*] SYNO.API.Info -> {st}  OAuth APIs: {oauth or 'none listed'}")

    if not dsm and not oauth:
        print("[-] Not a DSM web interface. NOT FOUND")
        return 0
    build = max(builds) if builds else None
    if build is None or args.fixed_build is None:
        print("[?] Pass --fixed-build from Synology-SA-26:18/19 (DSM 7.2: no fix yet = AFFECTED). UNKNOWN")
        return 2
    if build >= args.fixed_build:
        print("[-] Build at or above the fixed build: NOT AFFECTED")
        return 0
    print(f"[+] AFFECTED: DSM build {build} below {args.fixed_build} with OAuth APIs exposed (CVE-2026-120382)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
