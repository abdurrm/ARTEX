#!/usr/bin/env python3
"""
CVE-2026-129448 / CVE-2026-82384 - Verify Apache Roller XML-RPC accepts vendor
extension types before authentication, without sending a serialized object.

Demonstrates (calibrated against lab/ 6.1.4 vs 6.1.7):
  1. /roller-services/xmlrpc is reachable without authentication
  2. enabledForExtensions=true: responses declare the ex: extensions namespace
  3. an <ex:nil/> parameter is parsed and the call reaches the auth check
     ("Invalid Username and/or Password") instead of failing at parse time.
     The same parse step handles <ex:serializable>, the RCE primitive.

Patched 6.1.7 answers "XML-RPC service is disabled" (or a parse error once
re-enabled, because extensions are off).

Usage:
  python3 verify_extension_probe.py --target http://127.0.0.1:18081/roller

For authorized security testing only.
"""
import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request

EXT_NS = "http://ws.apache.org/xmlrpc/namespaces/extensions"

LIST_METHODS = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
NIL_PROBE = (
    f'<?xml version="1.0"?><methodCall xmlns:ex="{EXT_NS}"><methodName>blogger.getUsersBlogs</methodName>'
    "<params><param><value><ex:nil/></value></param>"
    "<param><value>verify</value></param><param><value>verify</value></param></params></methodCall>"
)


def post(url, body, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body.encode(), headers={"Content-Type": "text/xml"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return None, f"connection failed: {e}"


def fault_string(body):
    m = re.search(r"<name>faultString</name>\s*<value>(?:<string>)?([^<]*)", body)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18081/roller", help="Roller base URL (context root)")
    ap.add_argument("--timeout", type=float, default=15)
    args = ap.parse_args()
    url = args.target.rstrip("/") + "/roller-services/xmlrpc"

    print(f"[*] Target endpoint: {url}")
    status, body = post(url, LIST_METHODS, args.timeout)
    print(f"[*] system.listMethods -> HTTP {status}")
    if status is None:
        print(f"[?] {body}. UNKNOWN")
        return 2

    if "XML-RPC service is disabled" in body:
        print("[-] 'XML-RPC service is disabled': patched behaviour (6.1.6+). NOT AFFECTED")
        return 0
    if status == 404:
        print("[-] XML-RPC servlet not mapped: NOT AFFECTED (mapping removed)")
        return 0
    if "<methodResponse" not in body:
        print("[?] Endpoint did not answer XML-RPC (installer page, WAF, or auth proxy). UNKNOWN")
        print(body[:300])
        return 2

    ns_declared = EXT_NS in body
    print(f"[*] Extensions namespace declared in response: {ns_declared}")

    status, body = post(url, NIL_PROBE, args.timeout)
    fs = fault_string(body) or ""
    print(f"[*] <ex:nil/> probe -> HTTP {status}, faultString: {fs!r}")
    parsed = bool(fs) and not re.search(r"pars|extension|nil|prefix|enabled", fs, re.I)

    if ns_declared and parsed:
        print("[+] VULNERABLE: vendor extension types are parsed before authentication")
        print("    (same parse path as <ex:serializable>, CVE-2026-129448). Stop here.")
        return 1
    if not ns_declared and not parsed:
        print("[-] Extensions rejected at parse time: NOT AFFECTED")
        return 0
    print("[?] Mixed signals; compare against lab/ responses before claiming. UNKNOWN")
    return 2


if __name__ == "__main__":
    sys.exit(main())
