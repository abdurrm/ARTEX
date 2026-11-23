---
name: oracle-ebs-oct2026
description: "Invoke this skill when a task touches Oracle E-Business Suite 12.2.3-12.2.15 without the October 2026 Critical Patch Update: assesses the unauthenticated HTTP takeover of the Workflow Notification Mailer (CVE-2026-101809, CVSS 10.0) and the unauthenticated Application Object Library SQL injection to RCE (CVE-2026-101767, CVSS 9.8, Horizon3). Remote work is fingerprinting and patch-level evidence; injection or takeover payloads are lab-only."
---

# oracle-ebs-oct2026: Oracle EBS October 2026 CPU critical pair (CVE-2026-101809, CVE-2026-101767)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (fingerprint + DBA patch evidence; payloads are never shipped), using the
vendored PoCs and lab under `scripts/poc/oracle-ebs-oct2026/`. Run every PoC against the
lab first (`scripts/poc/oracle-ebs-oct2026/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/oracle-ebs-oct2026/...` are relative to this skill's base directory
(`<base>/scripts/poc/oracle-ebs-oct2026/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/oracle-ebs-oct2026/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/oracle-ebs-oct2026/lab ./oracle-ebs-oct2026-lab`
  and run `./oracle-ebs-oct2026-lab/setup.sh` from there.

## What the bugs are

- **CVE-2026-101809** (CVSS 3.1 **10.0**): Workflow Notification Mailer.
  Reachable over HTTP without authentication, and leads to full takeover.
  The scope change behind the 10.0 means the impact extends beyond the
  component.
- **CVE-2026-101767** (CVSS 9.8): Application Object Library. Horizon3
  reported it to Oracle in July 2026. It is unauthenticated SQL injection
  that leads to RCE.
- Both are fixed in the October 2026 CPU (194 EBS patches, 31 of them
  remotely exploitable without auth).
- Oracle marks neither as exploited, and no reliable source confirms
  in-the-wild use. Given EBS history, expect exploitation soon after a PoC
  appears.

## Affected / fixed

- Affected: EBS 12.2.3 through 12.2.15 without the October 2026 CPU
  patches.
- Fixed: the October 2026 CPU patches for EBS (see the Oracle CPU
  advisory's EBS risk matrix and patch-availability document).

## Hard gates

1. **Authorization**: the EBS instance is in scope. Production ERP usually
   needs explicit change-window approval even for scanning.
2. **No SQLi or takeover payloads on production**: lab only, on a
   non-production clone (most EBS customers keep test/dev clones; use one
   with the same patch level).
3. **No data access**: never read business data. Evidence is the version,
   the patch level and endpoint reachability.
4. **Lab first**: run `scripts/poc/oracle-ebs-oct2026/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   python3 scripts/poc/oracle-ebs-oct2026/poc/verify_exposure.py --target https://{host}   # plus check_cpu.sql (DBA)
   ```

## Detection workflow

1. **Fingerprint (remote)**: check `/OA_HTML/AppsLogin`,
   `/OA_HTML/AppsLocalLogin.jsp`, and `/OA_HTML/` static assets. The login
   page HTML and the asset paths identify EBS 12.2.x.
   ```bash
   curl -sk -o /dev/null -w '%{http_code}\n' https://{host}/OA_HTML/AppsLocalLogin.jsp
   ```
2. **Exposure**: are the EBS web tier and its Workflow-related servlets
   reachable from the internet, or only internally? Internet-facing iSupplier
   and iRecruitment DMZ deployments are the high-risk case.
3. **Patch level (DBA/app access)**: query `AD_BUGS` / `AD_APPLIED_PATCHES`
   for the October 2026 CPU patch numbers, or have the DBA run Oracle's
   CPU-applied check.
   ```sql
   select bug_number, creation_date from ad_bugs where bug_number in (<oct-2026-cpu-patch-ids>);
   ```
   Also record the release level (`select release_name from fnd_product_groups;`).
4. Classify:
   - **affected**: 12.2.3 through 12.2.15 without the CPU and with the web
     tier reachable;
   - **hardening-relevant**: missing the CPU but reachable only from
     internal networks;
   - **not affected**: CPU applied.

## Hunting (app/host access)

- Web tier access logs: unusual unauthenticated requests to Workflow and
  AOL servlets, especially from internet sources after 2026-10-21.
- New FND users or responsibilities, and unexpected concurrent requests.
- Java processes on the web tier spawning shells.

## Mitigation to cite

- Apply the October 2026 CPU for EBS (and its prerequisites).
- Interim: block internet access to the EBS web tier except the required
  DMZ products, and restrict the Workflow servlets at the reverse proxy.

## Reporting

- Title: Unauthenticated takeover of Oracle E-Business Suite
  (CVE-2026-101809 / CVE-2026-101767).
- Include: the release level, missing CPU patch IDs, exposure, and hunting
  results. Never include business data.

## Vendored artifacts

Under `scripts/poc/oracle-ebs-oct2026/`:

- `poc/verify_exposure.py` - GET-only EBS 12.2 web-tier fingerprint
- `poc/check_cpu.sql` - read-only: release, AD/TXK code levels, patches applied since the October 2026 CPU
- `lab/setup.sh` - runs the PoC against a non-production EBS clone on a private address
- `docs/ANALYSIS.md` - the two bugs, preconditions, status

## References

- https://www.oracle.com/security-alerts/cpuoct2026.html
- https://securityonline.info/oracle-e-business-suite-vulnerability-cve-2026-101809/
- https://www.csoonline.com/article/4239850/oracle-patches-1295-security-vulnerabilities-in-october-including-six-scoring-10-0-2.html
- https://ncsa.gov.qa/en/media/cybersecurity-advisories/556145
