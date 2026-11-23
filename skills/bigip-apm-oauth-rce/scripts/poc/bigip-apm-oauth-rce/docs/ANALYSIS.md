# CVE-2026-94127: BIG-IP APM OAuth Authorization Server heap overflow

## Root cause (public)
A heap-based buffer overflow (CWE-122) in the APM OAuth Authorization Server
request handling. A crafted unauthenticated request to the AS endpoints
overflows a heap buffer in the data plane, which leads to RCE.

## Preconditions
- Affected: 17.1.0 through 17.1.3, 17.5.0 through 17.5.1, and 21.1.0.
- A virtual server must carry an APM access policy **and** an OAuth profile
  with APM acting as the Authorization Server.
- APM acting only as a client or resource server is not affected.

## Fixes and status
- Fixed in 21.1.0.3, 17.5.1.10 and 17.1.3.6, plus engineering hotfixes and
  an iRule workaround through support (K000162605).
- KEV listed. F5 confirmed exploitation. No public PoC at disclosure.

## Lab
BIG-IP VE is licensed. `lab/setup.sh` runs the GET-only verifier against an
operator-owned VE on a private address. No overflow traffic, because a tmm
crash drops every service on the box.

## Sources
See `skills/bigip-apm-oauth-rce/SKILL.md`.
