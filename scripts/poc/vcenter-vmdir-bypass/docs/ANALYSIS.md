# CVE-2026-123890: vCenter VMware Directory Service authentication bypass

## Root cause (public)
`vmdird`, the directory/SSO service in vCenter, exposes an alternate
channel (CWE-288). Per GTIG, it discloses an SRP-6a session key over
DCE/RPC without authentication. An attacker with network reach to the
directory service acts as `Administrator@<sso-domain>`.

## In the wild
ARMORY CASTLE (Mandiant) used it as a zero-day from September 2026:
1. BONESAW steals the vmdir LMDB;
2. SAML signing material is extracted;
3. forged SSO assertions bypass MFA;
4. rogue admins are added.

The group also hit hosts already patched for CVE-2026-59309.

## Fixes
- 9.1.1.0200, 9.0.2.0200, 8.0 U3m (VMSA-2026-0009). No workaround.
- After patching an exposed system, rotate the STS signing certificates.

## Lab
vCenter is licensed. `lab/setup.sh` runs `poc/verify_exposure.py` against
an operator-owned nested or eval vCenter on a private address, so the
fingerprint and port results can be compared before the target run. No
directory-protocol traffic is ever sent.

## Sources
See `skills/vcenter-vmdir-bypass/SKILL.md`.
