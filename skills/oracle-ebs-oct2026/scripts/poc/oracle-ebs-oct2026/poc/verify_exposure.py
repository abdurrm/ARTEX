#!/usr/bin/env python3
"""
CVE-2026-101809 / CVE-2026-101767 - Fingerprint an Oracle E-Business Suite
12.2 web tier with read-only GETs. No injection or Workflow payloads.

Demonstrates:
  1. EBS login pages reachable (AppsLocalLogin.jsp / AppsLogin)
  2. 12.2.x markers (OA Framework, /OA_HTML/ paths, EBS cookies)
  3. patch level is not visible remotely: run check_cpu.sql as the DBA

Usage:
  python3 verify_exposure.py --target https://ebs.example

For authorized security testing only.
"""
import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request

PATHS = ["/OA_HTML/AppsLocalLogin.jsp", "/OA_HTML/AppsLogin", "/OA_HTML/RF.jsp?function_id=1"]


def get(url, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
            return r.status, " ".join(f"{k}={v}" for k, v in r.headers.items()), r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, " ".join(f"{k}={v}" for k, v in e.headers.items()), ""
    except (urllib.error.URLError, OSError):
        return None, "", ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--timeout", type=float, default=15)
    args = ap.parse_args()
    base = args.target.rstrip("/")
    ebs = False
    for p in PATHS:
        st, hdrs, body = get(base + p, args.timeout)
        mark = bool(re.search(r"OA_HTML|E-Business Suite|oracle\.apps|JSESSIONID.*OA|ICX_", hdrs + body, re.I))
        ebs = ebs or (st == 200 and mark)
        print(f"[*] {st} {p}{'  <- EBS' if mark else ''}")
    if not ebs:
        print("[-] No EBS web tier on this URL. NOT FOUND")
        return 0
    print("[+] EBS 12.2 web tier reachable from this position.")
    print("    Run check_cpu.sql as the DBA: no October 2026 CPU on 12.2.3-12.2.15 = AFFECTED.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
