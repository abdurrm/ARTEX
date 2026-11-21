---
name: bigip-apm-oauth-rce
description: "Invoke this skill when a task touches an F5 BIG-IP that may run APM 17.1.0-17.1.3, 17.5.0-17.5.1 or 21.1.0 with APM acting as an OAuth Authorization Server: assesses the unauthenticated heap overflow to RCE in the APM OAuth Authorization Server (CVE-2026-94127, CVSS 9.8, CISA KEV, exploited). Remote work is endpoint and version fingerprinting; overflow payloads are never sent."
---

# bigip-apm-oauth-rce: BIG-IP APM OAuth Authorization Server heap overflow (CVE-2026-94127)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (GET-only OAuth AS detection; overflow traffic is never sent), using the
vendored PoCs and lab under `scripts/poc/bigip-apm-oauth-rce/`. Run every PoC against the
lab first (`scripts/poc/bigip-apm-oauth-rce/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## What the bug is

- The bug is a heap-based buffer overflow (CWE-122) in the OAuth
  Authorization Server function of BIG-IP Access Policy Manager.
- A crafted unauthenticated request to the OAuth AS endpoints overflows a
  heap buffer in the data plane, which leads to RCE.
- Exposure requires a virtual server that has **both** an APM access policy
  and an OAuth profile, with APM acting as the **Authorization Server**. It
  is not exposed in the default configuration.
- F5 confirmed exploitation, and CISA added it to KEV. No public PoC was
  confirmed at disclosure (2026-09-22).
- Not affected: APM acting only as an OAuth client or resource server,
  BIG-IQ, BIG-IP Next, F5OS, NGINX, and F5 Distributed Cloud.

## Affected / fixed

- Affected: 17.1.0 through 17.1.3, 17.5.0 through 17.5.1, and 21.1.0.
- Fixed: 21.1.0.3, 17.5.1.10, and 17.1.3.6. Engineering hotfixes also
  exist per branch, and F5 offers an iRule workaround through support.
- Verify these against F5 K000162605, because the hotfix and release
  numbers in secondary sources do not line up exactly.

## Hard gates

1. **Authorization**: the BIG-IP is in scope.
2. **Never send overflow traffic**: a crash in tmm or the APM daemons drops
   production traffic for every service on the device. No lab
   reproduction either unless the engagement supplies a licensed lab
   BIG-IP; vendor confirmation plus KEV is enough evidence.
3. **Compromise first**: the bug is exploited. With device access, hunt
   before advising.
4. **Lab first**: run `scripts/poc/bigip-apm-oauth-rce/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   python3 scripts/poc/bigip-apm-oauth-rce/poc/verify_exposure.py --target https://{vip} --version <tmsh version>
   ```

## Detection workflow

1. **OAuth AS exposure (benign GETs)**: F5's AS endpoints live under
   `/f5-oauth2/v1/`. A metadata or JWKS response, or an OAuth-shaped error
   (rather than a 404 or an APM logon redirect), shows the AS is enabled on
   that virtual server.
   ```bash
   for p in .well-known/openid-configuration f5-oauth2/v1/jwks f5-oauth2/v1/authorize; do
     curl -sk -o /dev/null -w "%{http_code} $p\n" "https://{vip}/$p"; done
   ```
2. **Version**:
   - remotely, from the management GUI login page if it is in scope (it
     should never face the internet);
   - with access: `tmsh show sys version`.
3. **Config (device access)**: list the virtual servers that carry both an
   access profile and an OAuth AS profile.
   ```bash
   tmsh list ltm virtual one-line | grep -E 'profiles .*(access|oauth)'
   tmsh list apm oauth oauth-server
   ```
4. Classify:
   - **affected**: an affected version with an AS-enabled virtual server
     reachable by the attacker;
   - **hardening-relevant**: an affected version but no AS role;
   - **not affected**: fixed, or APM/OAuth AS is not provisioned.

## Hunting (device access)

- Core dumps or restarts of `tmm`, `apmd`, `oauth` daemons
  (`/var/core/`, `/var/log/ltm`).
- `/var/log/apm`: bursts of OAuth AS failures from one source. F5 treats 10
  or more failures from one IP as a signal, at medium confidence.
- New local users, modified iRules, and unexpected processes on the
  control plane.

## Mitigation to cite

- Upgrade to 21.1.0.3 / 17.5.1.10 / 17.1.3.6 or the branch hotfix.
- Interim: F5's iRule workaround (via support), or detach the OAuth AS
  profile from internet-facing virtual servers.

## Reporting

- Title: Pre-auth heap overflow in the BIG-IP APM OAuth Authorization
  Server (CVE-2026-94127).
- Include: the virtual server, the AS-endpoint evidence, the version, and
  hunting results. Reference K000162605 and the KEV listing.

## Vendored artifacts

Under `scripts/poc/bigip-apm-oauth-rce/`:

- `poc/verify_exposure.py` - probes `/.well-known/openid-configuration` and `/f5-oauth2/v1/*`, F5 header markers, `--version` vs fixed builds
- `lab/setup.sh` - runs the PoC against an operator-owned BIG-IP VE on a private address (refuses public IPs)
- `docs/ANALYSIS.md` - root cause, preconditions, fixes

## References

- https://www.rapid7.com/blog/post/etr-cve-2026-94127-critical-unauthenticated-rce-in-f5-big-ip-apm/
- https://ccb.belgium.be/advisories/warning-actively-exploited-cve-2026-94127-cvss-98-enables-unauthenticated-remote-code
- https://asec.ahnlab.com/en/95582/
- https://safeguard.sh/resources/blog/f5-big-ip-apm-cve-2026-94127-oauth-rce
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-94127
