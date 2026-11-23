---
name: windows-ldap-rce
description: "Invoke this skill when a task touches Windows domain controllers or other Windows Server hosts running LDAP (AD DS, AD LDS) that may be missing the November 2026 security update: assesses the unauthenticated out-of-bounds write in Windows LDAP that gives code execution in the LDAP service (CVE-2026-119958, CVSS 9.8, Patch Tuesday 2026-11-10). Assessment is by patch level and LDAP exposure; LDAP exploit traffic is lab-only."
---

# windows-ldap-rce: Windows LDAP out-of-bounds write (CVE-2026-119958)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (exposure + patch evidence; LDAP exploit traffic is never shipped), using the
vendored PoCs and lab under `scripts/poc/windows-ldap-rce/`. Run every PoC against the
lab first (`scripts/poc/windows-ldap-rce/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/windows-ldap-rce/...` are relative to this skill's base directory
(`<base>/scripts/poc/windows-ldap-rce/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/windows-ldap-rce/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/windows-ldap-rce/lab ./windows-ldap-rce-lab`
  and run `./windows-ldap-rce-lab/setup.sh` from there.

## What the bug is

- The bug is an out-of-bounds write (CWE-787) in the Windows LDAP
  implementation. An unauthenticated attacker sends a crafted set of LDAP
  calls and gains code execution in the context of the LDAP service.
- The attack is zero-click (PR:N, UI:N). It is worst on DCs, where the LDAP
  server runs inside LSASS. ZDI flags the amplified impact there.
- CVSS 3.1 9.8. Microsoft marks it "Exploitation Less Likely", not
  exploited and not publicly disclosed. However, a GitHub repository
  (`googlesky/CVE-2026-119958`) claims a containerised differential lab and
  a wire-level PoC. That claim is unverified: review it before use, and
  never run it outside a lab.

## Affected / fixed

- Affected: supported Windows and Windows Server releases without the
  2026-11-10 cumulative update, including Server 2016/2019/2022/2025 and
  client builds back to 1607. Exposure matters most where an LDAP server is
  listening (AD DS, AD LDS).
- Fixed: the November 2026 cumulative update or security-only update for
  each build. Take the KB numbers from the MSRC entry.

## Hard gates

1. **Authorization**: the domain and hosts are in scope.
2. **No LDAP exploit traffic against live DCs**: an LSASS crash reboots the
   DC and can break authentication across the domain. Lab reproduction
   needs an isolated, disposable DC built from an unpatched image.
3. **Read-only queries only**: anonymous rootDSE reads are acceptable for
   fingerprinting. Nothing else.
4. **Lab first**: run `scripts/poc/windows-ldap-rce/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   python3 scripts/poc/windows-ldap-rce/poc/verify_exposure.py --target {dc}   # plus verify_patch.ps1 on the DC
   ```

## Detection workflow

1. **Exposure**: from the attacker position, check TCP 389, 636, 3268 and
   3269 and UDP 389. Internet-facing LDAP on a DC is a critical finding on
   its own.
2. **Fingerprint (anonymous rootDSE, read-only)**:
   ```bash
   ldapsearch -x -H ldap://{dc} -s base -b '' dnsHostName domainControllerFunctionality supportedLDAPVersion
   ```
   This identifies DCs and the forest level. It does **not** reveal the
   patch level.
3. **Patch level (credentialed or inventory)**:
   ```powershell
   Get-HotFix | Sort-Object InstalledOn -Desc | Select -First 5
   (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
   ```
   Compare the build and UBR with the November 2026 build for that OS. You
   can also use WSUS, Intune, MECM or the vulnerability scanner's
   authenticated results.
4. **Reboot status**: the update must be installed **and** the host
   rebooted. Pending-reboot keys mean the host is still vulnerable.
5. Classify:
   - **affected**: unpatched and LDAP reachable;
   - **hardening-relevant**: unpatched but LDAP reachable only from
     trusted segments (still urgent for DCs);
   - **not affected**: patched and rebooted.

## Mitigation to cite

- Install the November 2026 update on every DC and LDAP-serving host first,
  then on everything else. Reboot.
- Keep 389, 636, 3268 and 3269 off the internet and away from untrusted
  segments until patched.
- Watch DCs for LSASS crashes (Event ID 1000/1015 for lsass.exe, and
  unexpected reboots via Event 1074/6008). These can indicate exploitation
  attempts.

## Reporting

- Title: Unauthenticated remote code execution in Windows LDAP
  (CVE-2026-119958).
- Include: the hosts, their DC role, the reachable LDAP ports and from
  where, the build/UBR versus the fixed build, and reboot status.

## Vendored artifacts

Under `scripts/poc/windows-ldap-rce/`:

- `poc/verify_exposure.py` - connect checks on 389/636/3268/3269 and one anonymous rootDSE read (identifies DCs)
- `poc/verify_patch.ps1` - on the host: build/UBR vs the November 2026 UBR (`-MinUBR`), pending reboot, LDAP roles
- `lab/setup.sh` - runs the PoC against a disposable evaluation DC on a private address
- `docs/ANALYSIS.md` - root cause, status, verifier notes

## References

- https://github.com/googlesky/CVE-2026-119958
- https://brandefense.io/knowledge-hub/vulnerabilities/cve-2026-119958/
- https://www.rescana.com/post/microsoft-patch-tuesday-november-2026-windows-search-ldap-rce-prepare-now
- https://www.tenable.com/blog/microsoft-november-2026-patch-tuesday-addresses-1093-cves-cve-2026-124194
- https://www.action1.com/patch-tuesday/patch-tuesday-november-2026/
