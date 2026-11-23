#!/usr/bin/env python3
"""
CVE-2026-94127 - Detect whether a BIG-IP virtual server exposes the APM OAuth
Authorization Server role, with benign GETs only (no overflow traffic).

Demonstrates:
  1. OAuth AS metadata / JWKS / authorize endpoints answer on the virtual server
  2. the answer looks like F5 APM (BIGipServer / MRHSession / F5 headers)
  3. optional version from --version (tmsh show sys version) for the verdict

Usage:
  python3 verify_exposure.py --target https://vip.example [--version 17.1.3]

For authorized security testing only.
"""
import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request

PATHS = [".well-known/openid-configuration", "f5-oauth2/v1/jwks", "f5-oauth2/v1/authorize",
         "f5-oauth2/v1/token", "f5-oauth2/v1/introspect"]
FIXED = {(17, 1): (17, 1, 3, 6), (17, 5): (17, 5, 1, 10), (21, 1): (21, 1, 0, 3)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def get(url, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(url, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(8192).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError):
        return None, {}, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--version", help="BIG-IP version, e.g. 17.1.3 or 17.5.1.9")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()
    base = args.target.rstrip("/")

    as_hits, f5 = [], False
    for p in PATHS:
        st, h, body = get(f"{base}/{p}", args.timeout)
        hs = " ".join(f"{k}={v}" for k, v in h.items())
        f5 = f5 or bool(re.search(r"BIGipServer|MRHSession|LastMRH_Session|F5_ST|TS01", hs))
        oauthish = ("jwks_uri" in body or '"keys"' in body or "invalid_request" in body
                    or "unsupported_response_type" in body or "invalid_client" in body)
        print(f"[*] {st} /{p}{'  <- OAuth AS response' if oauthish else ''}")
        if oauthish:
            as_hits.append(p)
    print(f"[*] F5 APM markers in headers: {f5}")
    if not as_hits:
        print("[-] No OAuth Authorization Server response on this virtual server. NOT EXPOSED here")
        return 0
    if not args.version:
        print("[?] OAuth AS exposed; pass --version to classify against the fixed builds. UNKNOWN")
        return 2
    v = tuple(int(x) for x in re.findall(r"\d+", args.version))[:4]
    v = v + (0,) * (4 - len(v))
    fixed = FIXED.get(v[:2])
    if fixed is None:
        print("[-] Branch not in the affected list (17.1, 17.5, 21.1). Check K000162605. NOT AFFECTED?")
        return 0
    if v >= fixed:
        print("[-] Fixed build: NOT AFFECTED")
        return 0
    print("[+] AFFECTED: OAuth AS exposed on an unfixed BIG-IP APM (CVE-2026-94127, KEV)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
