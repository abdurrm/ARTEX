---
name: redcap-rce
description: "Invoke this skill when a task touches a Vanderbilt REDCap research-data server (13.3.0 or later, before 16.0.49 LTS, 17.3.10 LTS or 17.4.4 Standard): assesses the unauthenticated remote code execution via crafted HTTP requests (CVE-2026-90817, CVSS 9.8, CISA KEV 2026-11-18, public exploit code). Remote work is version fingerprinting from the redcap_v path; exploit code is lab-only."
---

# redcap-rce: REDCap unauthenticated RCE (CVE-2026-90817)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (version classification; exploit code is never shipped), using the
vendored PoCs and lab under `scripts/poc/redcap-rce/`. Run every PoC against the
lab first (`scripts/poc/redcap-rce/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/redcap-rce/...` are relative to this skill's base directory
(`<base>/scripts/poc/redcap-rce/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/redcap-rce/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/redcap-rce/lab ./redcap-rce-lab`
  and run `./redcap-rce-lab/setup.sh` from there.

## What the bug is

- An unauthenticated attacker sends manipulated HTTP requests to REDCap's
  public-facing functionality (SentinelOne describes it as survey-related)
  and gets arbitrary code execution as the web server user. From there they
  can read or modify the database credentials and all project data.
- CVSS 3.1 9.8 (AV:N/AC:L/PR:N/UI:N). CISA added it to KEV on 2026-11-18
  (due 2026-11-21). Dataminr notes that public exploit code exists
  (`ExDev994/CVE-2026-90817` on GitHub; review it before trusting any
  claims).

## Affected / fixed

- Affected: REDCap 13.3.0 and later, with no upper bound named until the
  fixes.
- Fixed: 16.0.49 LTS, 17.3.10 LTS, 17.4.4 Standard Release.
- Below 13.3.0: not affected by this CVE, but these releases are old and
  usually carry other issues.

## Hard gates

1. **Authorization**: the instance is in scope. Data-protection rules
   (HIPAA, GDPR, IRB) usually apply, so confirm the rules of engagement
   cover a research-data system.
2. **No exploit code on live instances**: lab only. Use the REDCap
   community-download build matching the target's version on a disposable
   host. Never touch project data.
3. **Program policy**: the KEV listing is days old.
4. **Compromise first**: the bug is exploited. With host access, hunt
   before advising.
5. **Lab first**: run `scripts/poc/redcap-rce/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   python3 scripts/poc/redcap-rce/poc/verify_exposure.py --target https://{host}/redcap
   ```

## Detection workflow

1. **Version (remote, passive)**: REDCap serves its code from a versioned
   directory, so any page reveals the version in asset URLs.
   ```bash
   curl -sk https://{host}/redcap/ | grep -oE 'redcap_v[0-9]+\.[0-9]+\.[0-9]+' | sort -u
   ```
   Also check the footer ("REDCap x.y.z") and the survey pages
   (`/surveys/?s=...`).
2. **Exposure**: are public surveys or the login page reachable from the
   internet, or only from the institution's network?
3. **Track**: decide whether the instance is on an LTS or a Standard track
   (16.0.x LTS, 17.3.x LTS, or 17.4.x Standard) before comparing it with
   the fixed build.
4. Classify:
   - **affected**: 13.3.0 or later and below the fixed build for its track;
   - **not affected**: a fixed build, or below 13.3.0.

## Hunting (host access)

- Web logs: unusual POSTs to survey or public endpoints from unknown
  sources around and after 2026-11.
- New or modified PHP files under the REDCap webroot (especially in
  `edocs`, `temp`, or upload directories), and web-server-user processes
  spawning shells.
- Database: unexpected new super-users, API tokens, or exports.

## Mitigation to cite

- Upgrade to 16.0.49 LTS, 17.3.10 LTS, or 17.4.4 Standard (or later).
- Interim: restrict REDCap to institutional networks/VPN where public
  surveys are not required.
- After exposure:
  - rotate the `database.php` credentials, salts and API tokens;
  - review super-user accounts;
  - follow your data-breach procedure.

## Reporting

- Title: Unauthenticated remote code execution in REDCap
  (CVE-2026-90817).
- Include: the `redcap_v` version evidence, the track, internet exposure,
  and the KEV status. Never include any project data.

## Vendored artifacts

Under `scripts/poc/redcap-rce/`:

- `poc/verify_exposure.py` - reads `redcap_vX.Y.Z` from asset URLs, per-track verdict (16.0.49 / 17.3.10 / 17.4.4)
- `lab/setup.sh` - builds REDCap from your consortium zip on PHP 8.2 + Apache + MariaDB at :28110, loopback only, synthetic data only
- `docs/ANALYSIS.md` - the bug, fixes, lab notes

## References

- https://www.sentinelone.com/vulnerability-database/cve-2026-90817/
- https://www.dataminr.com/resources/intel-brief/lcve-2026-90817-redcap-unauthenticated-rce/
- https://cvefeed.io/vuln/detail/CVE-2026-90817
- https://shattered.io/litellm-axis-redcap-synology-dsm-four-flaws-join-cisa-kev-nov-18/
