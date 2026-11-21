# CVE-2026-119958: Windows LDAP out-of-bounds write

## Root cause (public)
An out-of-bounds write (CWE-787) in the Windows LDAP implementation,
reachable with a crafted sequence of LDAP calls and no authentication. On a
domain controller, the LDAP server runs inside LSASS, so code execution
there means domain compromise. A failed attempt crashes LSASS and reboots
the DC.

## Status
- CVSS 9.8. Fixed 2026-11-10.
- Microsoft rates it "Exploitation Less Likely", not public and not
  exploited.
- A GitHub repository (`googlesky/CVE-2026-119958`) claims a differential
  lab and a wire-level PoC. This is unverified.

## Verifiers
- `poc/verify_exposure.py`:
  - connect checks on 389/636/3268/3269;
  - one anonymous rootDSE base search, built by a handwritten BER encoder.
    The encoder was tested against OpenLDAP on 2026-11-21 and returned
    `supportedLDAPVersion: 3`.
- `poc/verify_patch.ps1` (on the host): compares build and UBR with the
  November UBR given via `-MinUBR`, and reports a pending reboot.

## Lab
A disposable evaluation DC on a private network (`lab/setup.sh` enforces
this). No LDAP exploit traffic is shipped.

## Sources
See `skills/windows-ldap-rce/SKILL.md`.
