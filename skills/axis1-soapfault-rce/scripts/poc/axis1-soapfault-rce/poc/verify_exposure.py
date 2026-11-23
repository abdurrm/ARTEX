#!/usr/bin/env python3
"""
CVE-2026-90436 - Locate pre-auth Apache Axis 1.x endpoints without sending fault payloads.

Demonstrates:
  1. which known Axis 1.x paths answer without a session (WSDL / service list)
  2. the Axis version from the WSDL generator comment or the Version service
  3. pre-auth reachability = the SOAP envelope is parsed before any service auth

Never sends a SOAP Fault / exceptionName (the class-instantiation primitive).

Usage:
  python3 verify_exposure.py --target http://127.0.0.1:18083

For authorized security testing only.
"""
import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request

PATHS = [
    "/axis/services/Version?wsdl",
    "/axis/services",
    "/axis/servlet/AxisServlet",
    "/services/Version?wsdl",
    "/services",
    "/servlet/AxisServlet",
    "/rpc/soap-axis/confluenceservice-v2?wsdl",  # Atlassian Confluence
    "/rpc/soap-axis/confluenceservice-v1?wsdl",
]
VERSION_SOAP = (
    '<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    '<soapenv:Body><getVersion/></soapenv:Body></soapenv:Envelope>'
)


def fetch(url, timeout, data=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"Content-Type": "text/xml", "SOAPAction": '""'} if data else {}
    req = urllib.request.Request(url, data=data.encode() if data else None, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(131072).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(131072).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError):
        return None, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18083", help="base URL (scheme://host:port)")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()
    base = args.target.rstrip("/")

    hits = []
    for p in PATHS:
        status, body = fetch(base + p, args.timeout)
        m = re.search(r"Apache Axis version: ([0-9.]+)", body)
        axis1 = bool(m) or "And now... Some Services" in body or "AxisServlet" in body or "Hi there, this is an AXIS service" in body
        print(f"[*] {status} {p}{'  <- Axis 1.x' if axis1 else ''}{'  version ' + m.group(1) if m else ''}")
        if status == 200 and axis1:
            hits.append((p, m.group(1) if m else None))

    status, body = fetch(base + "/axis/services/Version", args.timeout, VERSION_SOAP)
    m = re.search(r"Apache Axis version: ([0-9.]+)", body)
    if m:
        print(f"[*] Version service (pre-auth SOAP call): Apache Axis {m.group(1)}")
        hits.append(("/axis/services/Version", m.group(1)))

    if not hits:
        print("[-] No pre-auth Axis 1.x endpoint found on the probed paths. NOT FOUND (check app-specific paths)")
        return 0
    versions = {v for _, v in hits if v}
    if any(v.startswith("1.") for v in versions) or not versions:
        print(f"[+] Pre-auth Axis 1.x endpoint(s): {', '.join(p for p, _ in hits)}")
        print("    No fixed Axis 1.x exists: AFFECTED unless the product vendor patched its bundled copy.")
        return 1
    print(f"[-] Axis endpoint is not 1.x ({', '.join(sorted(versions))}). NOT AFFECTED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
