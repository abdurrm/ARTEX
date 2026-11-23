#!/usr/bin/env python3
"""
CVE-2026-97229 / CVE-2026-110264 - Classify a self-managed GitLab instance.

Demonstrates:
  1. version from /api/v4/version (token) or --version supplied by the operator
  2. per-CVE verdict against the fixed release tables
  3. anonymous exposure that widens the unauthenticated path:
     open sign-up, public projects, anonymous API access

Never sends regular expressions or CI configuration to the target.

Usage:
  python3 verify_exposure.py --target http://127.0.0.1:28100 --token glpat-...
  python3 verify_exposure.py --target https://gitlab.example --version 19.3.4

For authorized security testing only.
"""
import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request

# (major, minor) branch -> first fixed patch release
FIX_97229 = {(19, 4): 2, (19, 3): 5, (19, 2): 8}
FIX_110264 = {(19, 5): 1, (19, 4): 3, (19, 3): 6, (19, 2): 9, (19, 1): 9, (19, 0): 10, (18, 11): 13}


def verdict_97229(v):
    branch, patch = v[:2], v[2]
    if v < (19, 1, 0):
        return "not affected (predates 19.1 per reported range)"
    if branch in FIX_97229:
        return "fixed" if patch >= FIX_97229[branch] else "AFFECTED"
    if branch > (19, 4):
        return "fixed"
    return "AFFECTED (19.1.x: no fixed release listed)"


def verdict_110264(v):
    branch, patch = v[:2], v[2]
    if branch in FIX_110264:
        return "fixed" if patch >= FIX_110264[branch] else "AFFECTED"
    if branch > (19, 5):
        return "fixed"
    return "AFFECTED (branch without backport: upgrade)"


def get(url, token, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"PRIVATE-TOKEN": token} if token else {}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout, context=ctx) as r:
            return r.status, r.read(262144).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, OSError):
        return None, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:28100")
    ap.add_argument("--token", help="any read_api token (version endpoint needs auth)")
    ap.add_argument("--version", help="version from the operator if no token, e.g. 19.3.4")
    ap.add_argument("--timeout", type=float, default=15)
    args = ap.parse_args()
    base = args.target.rstrip("/")

    ver = args.version
    if args.token:
        status, body = get(base + "/api/v4/version", args.token, args.timeout)
        if status == 200:
            ver = json.loads(body).get("version")
        print(f"[*] /api/v4/version -> {status} {ver}")

    s, body = get(base + "/users/sign_in", None, args.timeout)
    print(f"[*] sign-in page: {s}; open sign-up link: {'/users/sign_up' in body}")
    s, body = get(base + "/api/v4/projects?visibility=public&per_page=1", None, args.timeout)
    print(f"[*] anonymous public-project API: {s}{' (public projects visible)' if s == 200 and body.strip() not in ('', '[]') else ''}")

    m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver or "")
    if not m:
        print("[?] Version unknown: pass --token or --version. UNKNOWN")
        return 2
    v = tuple(map(int, m.groups()))
    a, b = verdict_97229(v), verdict_110264(v)
    print(f"[*] GitLab {'.'.join(map(str, v))}")
    print(f"    CVE-2026-97229  (KEV): {a}")
    print(f"    CVE-2026-110264       : {b}")
    if a.startswith("AFFECTED") or b.startswith("AFFECTED"):
        print("[+] AFFECTED: upgrade to a release fixed for both CVEs (self-built: also update Ruby)")
        return 1
    print("[-] Fixed for both: NOT AFFECTED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
