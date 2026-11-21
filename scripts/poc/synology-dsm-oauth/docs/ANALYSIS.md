# CVE-2026-120382: Synology DSM OAuth API arbitrary file access

## The bug (public)
A flaw in DSM's OAuth API lets an unauthenticated attacker read arbitrary
files.
- CVSS 9.8. Affects DSM 7.1 through 7.4 (Synology-SA-26:18/19).
- The DSM 7.2 fix is still "Ongoing".

## Related KEV item
CVE-2024-10441 (CVSS 9.8) is an unauthenticated RCE in the DSM plugin
daemon. It entered KEV on 2026-11-18 because of active exploitation.

## Verifier
`poc/verify_exposure.py`:
- reads the DSM build from login-page asset query strings;
- lists OAuth APIs via `SYNO.API.Info`;
- compares the build with `--fixed-build` from the advisory.

It never calls the OAuth API.

## Lab
A spare NAS or DSM VM on the same build (`lab/setup.sh` enforces a private
address).

## Sources
See `skills/synology-dsm-oauth/SKILL.md`.
