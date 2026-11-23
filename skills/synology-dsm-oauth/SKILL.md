---
name: synology-dsm-oauth
description: "Invoke this skill when a task touches a Synology NAS running DSM 7.1-7.4 (or BeeStation OS): assesses the critical DSM OAuth API flaw that gives unauthenticated arbitrary file access (CVE-2026-120382, CVSS 9.8, November 2026; DSM 7.2 fix still ongoing). It also flags CVE-2024-10441, the older DSM plugin-daemon RCE that entered CISA KEV on 2026-11-18. Remote work is version fingerprinting; file-read payloads are lab-only."
---

# synology-dsm-oauth: DSM OAuth API arbitrary file access (CVE-2026-120382)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (fingerprint-only; the OAuth API is never called), using the
vendored PoCs and lab under `scripts/poc/synology-dsm-oauth/`. Run every PoC against the
lab first (`scripts/poc/synology-dsm-oauth/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/synology-dsm-oauth/...` are relative to this skill's base directory
(`<base>/scripts/poc/synology-dsm-oauth/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/synology-dsm-oauth/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/synology-dsm-oauth/lab ./synology-dsm-oauth-lab`
  and run `./synology-dsm-oauth-lab/setup.sh` from there.

## What the bugs are

- **CVE-2026-120382** (CVSS 9.8, critical):
  - a flaw in DSM's **OAuth API** that lets an unauthenticated remote
    attacker access arbitrary files;
  - affects DSM 7.1 through 7.4;
  - published in Synology's November 2026 advisories (SA-26:18/19);
  - Synology lists the DSM 7.2 fix as **"Ongoing"**, so some supported
    lines have no patch yet.
- **CVE-2024-10441** (CVSS 9.8):
  - an older unauthenticated RCE in the DSM system plugin daemon;
  - not new, but CISA added it to KEV on **2026-11-18** (due 2026-11-21)
    on evidence of active exploitation;
  - any NAS that never took the 2024 fix is being hit now.

## Affected / fixed

- CVE-2026-120382: DSM 7.1 through 7.4. Take the fixed builds per line from
  Synology-SA-26:18/19. 7.2 has no fix yet.
- CVE-2024-10441: see Synology's 2024 advisory for DSM and BeeStation fixed
  builds.

## Hard gates

1. **Authorization**: the NAS is in scope.
2. **No file reads or RCE on live NAS**: lab only (a DSM VM or a spare unit
   on the same build).
3. **No data access**: evidence is the build number and endpoint
   reachability.
4. **Lab first**: run `scripts/poc/synology-dsm-oauth/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   python3 scripts/poc/synology-dsm-oauth/poc/verify_exposure.py --target https://{host}:5001 --fixed-build <advisory build>
   ```

## Detection workflow

1. **Fingerprint**: DSM listens on 5000/5001 (or 80/443 through a reverse
   proxy). The login page loads assets with a build query string
   (`?v=<build>`), and the build maps to a DSM version.
   ```bash
   curl -sk https://{host}:5001/ | grep -oE '\?v=[0-9]+' | sort -u | head -3
   ```
2. **API presence (benign)**: query the API info endpoint and note whether
   OAuth-related APIs are listed.
   ```bash
   curl -sk "https://{host}:5001/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all" | tr ',' '\n' | grep -i oauth
   ```
3. **Version (admin access)**: Control Panel > Info Center, or
   `cat /etc.defaults/VERSION`.
4. **Exposure**: is DSM published to the internet directly, or through
   QuickConnect? QuickConnect relays still reach the vulnerable APIs.
5. Classify:
   - **affected (CVE-2026-120382)**: DSM 7.1 through 7.4 below the fixed
     build. On 7.2, affected with no fix available;
   - **affected (CVE-2024-10441)**: a build older than its 2024 fix, which
     is urgent because of KEV;
   - **not affected**: fixed builds.

## Mitigation to cite

- Update DSM to the fixed build for the line, and apply the 2024 fix if it
  is missing.
- For 7.2 (no fix yet), and as an interim measure generally:
  - remove internet exposure of DSM (ports 5000/5001 and reverse proxies);
  - disable QuickConnect if it is not needed;
  - use VPN for remote access.
- If the NAS was exposed, rotate the credentials stored on it.

## Reporting

- Report one finding per CVE.
- Include: the build and DSM version, the exposure path, KEV status (for
  CVE-2024-10441), and the fix status for the line ("no fix available on
  7.2" is itself material).

## Vendored artifacts

Under `scripts/poc/synology-dsm-oauth/`:

- `poc/verify_exposure.py` - DSM build from asset query strings, OAuth APIs from `SYNO.API.Info`, `--fixed-build` verdict
- `lab/setup.sh` - runs the PoC against a spare NAS / DSM VM on a private address
- `docs/ANALYSIS.md` - the bug, related KEV item, verifier notes

## References

- https://www.synology.com/en-global/security/advisory/Synology_SA_26_18
- https://www.synology.com/en-global/security/advisory/Synology_SA_26_19
- https://socprime.com/blog/cve-2026-120382-critical-synology-dsm-oauth-flaw-enables-arbitrary-file-access/
- https://securityonline.info/synology-dsm-vulnerabilities-cve-2026-120382/
- https://shattered.io/litellm-axis-redcap-synology-dsm-four-flaws-join-cisa-kev-nov-18/
