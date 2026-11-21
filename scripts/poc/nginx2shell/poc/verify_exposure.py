#!/usr/bin/env python3
"""Non-intrusive CVE-2026-123007 (NGINX HTTP/2 send-window) exposure check.

remote: one TLS handshake offering ALPN h2,http/1.1 plus one HTTP/1.1 HEAD /.
        No HTTP/2 frames are sent; nothing here can trigger the bug.
local:  parses saved `nginx -V` and `nginx -T` output from a host you control.

Exit code: 0 not affected, 1 affected, 2 hardening-relevant / unknown.
"""
import argparse
import json
import re
import socket
import ssl
import sys
from urllib.parse import urlparse

FIXED_STABLE = (1, 30, 7)
FIXED_MAINLINE = (1, 31, 9)
FIRST_AFFECTED = (1, 9, 5)

VERSION_RE = re.compile(r"nginx/(\d+)\.(\d+)\.(\d+)")
HTTP2_RE = re.compile(r"^\s*(http2\s+on\s*;|listen\s+[^;]*\bhttp2\b[^;]*;)", re.M)


def version_verdict(v):
    """affected / fixed for an NGINX OSS version tuple (ignores distro backports)."""
    if v < FIRST_AFFECTED:
        return "fixed", "predates HTTP/2 support (1.9.5)"
    if v >= FIXED_MAINLINE:
        return "fixed", "1.31.9+ mainline"
    if (1, 31, 0) <= v:
        return "affected", "mainline before 1.31.9"
    if FIXED_STABLE <= v < (1, 31, 0):
        return "fixed", "1.30.7+ stable"
    return "affected", "1.9.5-1.30.6 (older stable branches have no fix of their own)"


def classify(version, h2):
    """Combine version and HTTP/2 exposure into a verdict."""
    if h2 is False:
        return "not-affected" if version and version_verdict(version)[0] == "fixed" else "hardening-relevant"
    if version is None:
        return "hardening-relevant"  # h2 on/unknown, version hidden: needs host evidence
    if version_verdict(version)[0] == "fixed":
        return "not-affected"
    return "affected" if h2 else "hardening-relevant"


def remote(url, timeout):
    u = urlparse(url if "://" in url else "https://" + url)
    host, port = u.hostname, u.port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    out = {"target": f"{host}:{port}", "alpn": None, "server": None}

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            out["alpn"] = tls.selected_alpn_protocol()

    ctx.set_alpn_protocols(["http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 65536:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                head += chunk
    for line in head.decode("latin-1").split("\r\n"):
        if line.lower().startswith("server:"):
            out["server"] = line.split(":", 1)[1].strip()

    h2 = out["alpn"] == "h2"
    m = VERSION_RE.search(out["server"] or "")
    version = tuple(int(x) for x in m.groups()) if m else None
    out["h2"] = h2
    out["version"] = ".".join(map(str, version)) if version else None
    out["verdict"] = classify(version, h2)
    notes = []
    if out["server"] and "nginx" not in out["server"].lower():
        notes.append("Server header is not nginx: a CDN/WAF may terminate h2; check the origin path")
    if version is None:
        notes.append("version hidden (server_tokens off?): confirm with `nginx -V` on the host")
    if version and version_verdict(version)[0] == "affected":
        notes.append("version string in range: check distro backport and that nginx was restarted")
    out["notes"] = notes
    return out


def local(nginx_v, nginx_t):
    out = {"version": None, "http2_lines": [], "notes": []}
    version = None
    if nginx_v:
        m = VERSION_RE.search(open(nginx_v, encoding="utf-8", errors="replace").read())
        if m:
            version = tuple(int(x) for x in m.groups())
            out["version"] = ".".join(map(str, version))
    h2 = None
    if nginx_t:
        conf = open(nginx_t, encoding="utf-8", errors="replace").read()
        conf = re.sub(r"#[^\n]*", "", conf)
        out["http2_lines"] = [m.group(1).strip() for m in HTTP2_RE.finditer(conf)]
        h2 = bool(out["http2_lines"])
    else:
        out["notes"].append("no `nginx -T` output given: HTTP/2 exposure unknown")
    out["h2"] = h2
    out["verdict"] = classify(version, h2)
    if version and version_verdict(version)[0] == "affected":
        out["notes"].append("upstream version in range: check the package changelog for a CVE-2026-123007 backport")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    r = sub.add_parser("remote", help="ALPN + Server header check against https://host[:port]")
    r.add_argument("url")
    r.add_argument("--timeout", type=float, default=10)
    lo = sub.add_parser("local", help="parse saved `nginx -V` / `nginx -T` output")
    lo.add_argument("--nginx-v", help="file with `nginx -V 2>&1` output")
    lo.add_argument("--nginx-t", help="file with `nginx -T 2>&1` output")
    a = ap.parse_args()

    try:
        res = remote(a.url, a.timeout) if a.mode == "remote" else local(a.nginx_v, a.nginx_t)
    except OSError as e:
        print(json.dumps({"error": str(e), "verdict": "unknown"}, indent=2))
        sys.exit(2)
    print(json.dumps(res, indent=2))
    sys.exit({"not-affected": 0, "affected": 1}.get(res["verdict"], 2))


if __name__ == "__main__":
    main()
