#!/usr/bin/env python3
"""
CVE-2026-123890 - Fingerprint a vCenter build and the reachability of VMware
Directory Service ports, without touching the directory protocol.

Demonstrates:
  1. exact product/version/build from the unauthenticated SOAP RetrieveServiceContent
  2. TCP connect reachability of vmdird ports (389/636 LDAP, 2012/2014/2020 DCE/RPC)
  3. verdict against the fixed versions (9.1.1.0200, 9.0.2.0200, 8.0 U3m) when the
     operator passes --fixed-build from Broadcom's build-number KB for that line

Usage:
  python3 verify_exposure.py --target https://10.0.0.20 [--fixed-build 24XXXXXX]

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

SOAP = ('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>'
        '<RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this>'
        '</RetrieveServiceContent></soapenv:Body></soapenv:Envelope>')
VMDIR_PORTS = [389, 636, 2012, 2014, 2020]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="https://vcenter")
    ap.add_argument("--fixed-build", type=int, help="first fixed build number for this vCenter line")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()
    host = urlparse(args.target).hostname
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(args.target.rstrip("/") + "/sdk", data=SOAP.encode(),
                                 headers={"Content-Type": "text/xml", "SOAPAction": "urn:vim25/8.0"})
    try:
        with urllib.request.urlopen(req, timeout=args.timeout, context=ctx) as r:
            body = r.read(65536).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        print(f"[?] /sdk unreachable: {e}. UNKNOWN")
        return 2
    info = {k: (re.search(f"<{k}>([^<]+)</{k}>", body) or [None, None])[1]
            for k in ("fullName", "version", "build", "productLineId", "apiType")}
    print(f"[*] {info}")
    if info["apiType"] != "VirtualCenter":
        print("[-] Not a vCenter (ESXi host or other). NOT APPLICABLE")
        return 0

    open_ports = []
    for p in VMDIR_PORTS:
        try:
            socket.create_connection((host, p), timeout=3).close()
            open_ports.append(p)
        except OSError:
            pass
    print(f"[*] vmdird ports reachable from here: {open_ports or 'none'}")

    if args.fixed_build is None:
        print("[?] Pass --fixed-build (Broadcom build KB for this line) to classify the build. UNKNOWN")
        return 2
    if int(info["build"] or 0) >= args.fixed_build:
        print("[-] Build at or above the fixed build: NOT AFFECTED (still hunt: exploited pre-patch)")
        return 0
    if open_ports:
        print("[+] AFFECTED: unfixed build with directory-service ports reachable (CVE-2026-123890)")
        return 1
    print("[~] Unfixed build, directory ports filtered from this position: HARDENING-RELEVANT")
    return 2


if __name__ == "__main__":
    sys.exit(main())
