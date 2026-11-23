---
name: expressway-cluster-cred
description: "Invoke this skill when a task touches Cisco Expressway-C or Expressway-E (X15.5.3 or earlier, or X14) deployed as a cluster: assesses the hard-coded cluster database credential that gives unauthenticated root command execution (CVE-2026-76466, CVSS 9.8, CWE-798, CISA KEV 2026-11-20, public PoC). Remote work is version and cluster-port fingerprinting; root command execution needs explicit engagement approval."
---

# expressway-cluster-cred: Cisco Expressway hard-coded cluster DB credential (CVE-2026-76466)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (fingerprint and port reachability; the credential is never used by the shipped PoC), using the
vendored PoCs and lab under `scripts/poc/expressway-cluster-cred/`. Run every PoC against the
lab first (`scripts/poc/expressway-cluster-cred/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/expressway-cluster-cred/...` are relative to this skill's base directory
(`<base>/scripts/poc/expressway-cluster-cred/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/expressway-cluster-cred/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/expressway-cluster-cred/lab ./expressway-cluster-cred-lab`
  and run `./expressway-cluster-cred-lab/setup.sh` from there.

## What the bug is

- The database service that clustered Expressway peers use to replicate
  configuration ships with a **hard-coded credential** (CWE-798).
- An unauthenticated attacker who can reach that service uses the credential
  to run OS commands as **root** (described as persistent cookies in the
  database service). The result is full appliance takeover.
- Only **clustered** Expressway-C/E deployments are affected. There is no
  workaround.
- A public PoC exists. CISA added the bug to KEV on 2026-11-20 (due
  2026-11-23), and reports describe root takeover of four clustered gateways
  at one organization. Cisco's advisory (cisco-sa-vcs-static-cred-hr7EWZ8t,
  last revised 2026-10-21) still says it is unaware of malicious use.

## Affected / fixed

- Affected: clustered Expressway on X15.5.3 or earlier. X14 has to migrate.
- Fixed: X15.5.20. Confirm the exact range in Cisco's advisory.
- Not affected: standalone, non-clustered nodes.

## Hard gates

1. **Authorization**: the Expressway nodes are in scope.
2. **Using the credential is exploitation**: it gives root on a production
   edge appliance. Only do it if the engagement explicitly authorizes
   exploitation of this CVE, and then once: run `id`, capture the output,
   disconnect. Otherwise classify from version and cluster evidence alone.
3. **Review the public PoC** line by line before any authorized use. Run it
   only from the engagement's attack host.
4. **Compromise first**: the bug is exploited. With admin access, hunt
   before advising.
5. **Lab first**: run `scripts/poc/expressway-cluster-cred/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   python3 scripts/poc/expressway-cluster-cred/poc/verify_exposure.py --target https://{host} --cluster-ports <ports> --clustered
   ```

## Detection workflow

1. **Fingerprint**: check the web admin login page on 443, where
   Expressway branding and the version usually appear on the login page or
   in its assets. On -E nodes, check the MRA/edge ports (8443, 5061).
2. **Cluster evidence**: with admin access, look at
   System > Clustering, peer addresses, and the cluster name. From the
   network, check whether the inter-peer database/replication ports answer
   from the attacker's position. These ports should only be reachable
   between peers, so take the port list from Cisco's Expressway IP port
   usage guide for your release.
3. **Version (admin access)**: the Overview page, or `xstatus SystemUnit`
   over SSH.
4. Classify:
   - **affected**: clustered, X15.5.3 or earlier (or X14), and the cluster
     DB service is reachable from the attacker position;
   - **hardening-relevant**: clustered and unfixed, but peer ports are
     firewalled to peers only. The risk still holds if any peer is
     compromised;
   - **not affected**: X15.5.20 or later, or standalone.

## Hunting (admin/host access)

- Connections to the cluster DB ports from non-peer addresses.
- Unexpected root shell activity, new accounts, cron jobs, or changed
  binaries.
- Configuration changes nobody made (zones, search rules, admin accounts).

## Mitigation to cite

- Upgrade to X15.5.20 (migrate off X14).
- Firewall the cluster replication ports so only the peer nodes can reach
  them.
- After exposure, rebuild from known-good, rotate all credentials and
  certificates, and review call routing.

## Reporting

- Title: Unauthenticated root command execution on clustered Cisco
  Expressway via a hard-coded database credential (CVE-2026-76466).
- Include: the version, cluster evidence, port reachability from the
  attacker position, KEV status, and (only if authorized) the one-shot `id`
  output.

## Vendored artifacts

Under `scripts/poc/expressway-cluster-cred/`:

- `poc/verify_exposure.py` - login-page fingerprint, cluster-port reachability (`--cluster-ports` from Cisco's port guide), verdict vs X15.5.20
- `lab/setup.sh` - runs the PoC against an operator-owned two-node lab cluster on private addresses
- `docs/ANALYSIS.md` - root cause, status, lab notes

## References

- https://github.com/advisories/ghsa-p2jr-qv63-hjch
- https://hol.org/blog/cve-2026-76466-cisco-expressway-root-cisa-kev
- https://www.rescana.com/post/cisco-expressway-cve-2026-76466-unified-communications-hardening-october-2026
- https://blog.ostorlab.co/cisco-expressway-root-rce-cve-2026-76466.html
- https://threatfrontier.com/articles/cisco-expressway-cve-2026-76466-hard-coded-credential-root-rce
