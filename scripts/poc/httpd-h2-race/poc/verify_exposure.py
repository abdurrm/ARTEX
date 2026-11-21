#!/usr/bin/env python3
"""
CVE-2026-119618 - Verify Apache httpd mod_http2 exposure without sending HTTP/2 frames.

Demonstrates:
  1. TLS listener negotiates ALPN h2 (one handshake, no frames sent)
  2. Optional cleartext h2c upgrade is accepted (101 Switching Protocols)
  3. Server header version against the affected range 2.4.55-2.4.70

The race itself is never triggered here; that stays in lab/.

Usage:
  python3 verify_exposure.py --target https://127.0.0.1:18443 --h2c http://127.0.0.1:18080

For authorized security testing only.
"""
import argparse
import re
import socket
import ssl
import sys
from urllib.parse import urlparse

FIRST, FIXED = (2, 4, 55), (2, 4, 71)


def tls_probe(url, timeout):
    u = urlparse(url)
    host, port = u.hostname, u.port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            alpn = tls.selected_alpn_protocol()
    ctx.set_alpn_protocols(["http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            head = tls.recv(8192).decode("latin-1")
    m = re.search(r"(?im)^server:\s*(.+)$", head)
    return alpn, m.group(1).strip() if m else None


def h2c_probe(url, timeout):
    u = urlparse(url)
    host, port = u.hostname, u.port or 80
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade, HTTP2-Settings\r\n"
           "Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n").encode()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(req)
        first = s.recv(4096).decode("latin-1").split("\r\n", 1)[0]
    return first.startswith("HTTP/1.1 101")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="https://127.0.0.1:18443", help="https:// URL of the TLS listener")
    ap.add_argument("--h2c", help="optional http:// URL to test the cleartext h2c upgrade")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()

    try:
        alpn, server = tls_probe(args.target, args.timeout)
    except OSError as e:
        print(f"[?] TLS probe failed: {e}. UNKNOWN")
        return 2
    print(f"[*] ALPN negotiated: {alpn}   Server: {server}")
    h2 = alpn == "h2"
    if args.h2c:
        try:
            up = h2c_probe(args.h2c, args.timeout)
        except OSError as e:
            print(f"[?] h2c probe failed: {e}")
            up = False
        print(f"[*] h2c upgrade accepted on {args.h2c}: {up}")
        h2 = h2 or up

    m = re.search(r"Apache/(\d+)\.(\d+)\.(\d+)", server or "")
    ver = tuple(map(int, m.groups())) if m else None
    if ver:
        print(f"[*] Version: {'.'.join(map(str, ver))}")
    if not h2:
        print("[-] HTTP/2 not offered: NOT AFFECTED on this listener")
        return 0
    if ver is None:
        print("[?] HTTP/2 on, version hidden (ServerTokens Prod?): confirm with `apachectl -v`. UNKNOWN")
        return 2
    if FIRST <= ver < FIXED:
        print("[+] AFFECTED (version in 2.4.55-2.4.70 with HTTP/2 on); check distro backport and restart status")
        return 1
    print("[-] Version outside the affected range: NOT AFFECTED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
