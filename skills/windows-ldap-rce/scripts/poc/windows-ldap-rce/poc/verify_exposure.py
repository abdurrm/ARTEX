#!/usr/bin/env python3
"""
CVE-2026-119958 - Map Windows LDAP exposure with connect checks and one
anonymous rootDSE read. Sends no malformed LDAP.

Demonstrates:
  1. TCP reachability of 389 / 636 / 3268 / 3269 from the tester's position
  2. anonymous rootDSE (base search, scope base) -> dnsHostName,
     domainControllerFunctionality, isGlobalCatalogReady: identifies DCs
  3. patch level is NOT visible over LDAP: use verify_patch.ps1 on the host

Usage:
  python3 verify_exposure.py --target 10.0.0.10

For authorized security testing only.
"""
import argparse
import socket
import sys

PORTS = [389, 636, 3268, 3269]
ATTRS = [b"dnsHostName", b"domainControllerFunctionality", b"isGlobalCatalogReady",
         b"defaultNamingContext", b"vendorName", b"supportedLDAPVersion"]


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, value):
    return bytes([tag]) + ber_len(len(value)) + value


def rootdse_request():
    attrs = tlv(0x30, b"".join(tlv(0x04, a) for a in ATTRS))
    search = tlv(0x63, tlv(0x04, b"") + tlv(0x0A, b"\x00") + tlv(0x0A, b"\x00") + tlv(0x02, b"\x00")
                 + tlv(0x02, b"\x00") + tlv(0x01, b"\x00") + tlv(0x87, b"objectClass") + attrs)
    return tlv(0x30, tlv(0x02, b"\x01") + search)


def read_tlv(buf, i):
    tag = buf[i]
    n = buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n


def parse_entry(msg):
    """Return {attr: [values]} from the first SearchResultEntry in msg."""
    out = {}
    _, body, _ = read_tlv(msg, 0)              # LDAPMessage SEQUENCE
    _, _, j = read_tlv(body, 0)                # messageID
    tag, entry, _ = read_tlv(body, j)
    if tag != 0x64:
        return out
    _, _, k = read_tlv(entry, 0)               # objectName
    _, attrs, _ = read_tlv(entry, k)
    p = 0
    while p < len(attrs):
        _, pa, p = read_tlv(attrs, p)
        _, name, q = read_tlv(pa, 0)
        _, vals, _ = read_tlv(pa, q)
        r, vs = 0, []
        while r < len(vals):
            _, v, r = read_tlv(vals, r)
            vs.append(v.decode("utf-8", "replace"))
        out[name.decode()] = vs
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="host or IP of the LDAP server / DC")
    ap.add_argument("--timeout", type=float, default=5)
    args = ap.parse_args()

    reach = []
    for p in PORTS:
        try:
            socket.create_connection((args.target, p), timeout=args.timeout).close()
            reach.append(p)
        except OSError:
            pass
    print(f"[*] LDAP ports reachable from here: {reach or 'none'}")
    if 389 not in reach:
        print("[-] 389 not reachable: no plaintext rootDSE read. Patch status still needed for DCs.")
        return 0 if not reach else 2

    with socket.create_connection((args.target, 389), timeout=args.timeout) as s:
        s.sendall(rootdse_request())
        data = s.recv(65536)
    try:
        entry = parse_entry(data)
    except (IndexError, ValueError):
        entry = {}
    print(f"[*] rootDSE: {entry or 'no anonymous answer'}")
    is_dc = "domainControllerFunctionality" in entry
    print(f"[*] Active Directory DC: {is_dc}")
    print("[?] Patch level is not exposed over LDAP: run verify_patch.ps1 (or authenticated scan) and")
    print("    compare with the 2026-11-10 cumulative update. Unpatched + reachable = AFFECTED.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
