---
name: vcenter-vmdir-bypass
description: "Invoke this skill when a task touches a VMware vCenter Server (or VCF / vSphere Foundation appliance) that may predate 9.1.1.0200, 9.0.2.0200 or 8.0 U3m: assesses the unauthenticated VMware Directory Service authentication bypass to Administrator (CVE-2026-123890, CVSS 9.8, exploited in the wild since September 2026). Remote work is fingerprinting and compromise hunting; no exploitation of live vCenters."
---

# vcenter-vmdir-bypass: VMware Directory Service auth bypass (CVE-2026-123890)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (fingerprint-only; no directory-protocol traffic is ever sent), using the
vendored PoCs and lab under `scripts/poc/vcenter-vmdir-bypass/`. Run every PoC against the
lab first (`scripts/poc/vcenter-vmdir-bypass/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## What the bug is

- The flaw is an authentication bypass through an alternate path or channel
  (CWE-288) in the VMware Directory Service (`vmdird`), the LDAP/SSO
  directory built into vCenter.
- Per GTIG/Rescana, `vmdird` discloses an SRP-6a session key over DCE/RPC
  without authentication. An attacker who can reach the directory service
  uses it to act as `Administrator@<sso-domain>`.
- Exploitation seen in the wild (Mandiant, group "ARMORY CASTLE", tool
  BONESAW) followed these steps:
  1. steal the directory LMDB database;
  2. extract the SAML signing material;
  3. forge SSO admin assertions, which bypasses MFA;
  4. create rogue SSO admin accounts.
- The same group also hit servers that were already patched for the earlier
  bypass, CVE-2026-59309, so patching that one is not enough.
- CVSS 3.1 9.8 (AV:N/AC:L/PR:N/UI:N). Broadcom advisory VMSA-2026-0009 was
  published 2026-11-19. There is **no workaround**.

## Affected / not affected

Affected (until fixed): vCenter 9.1.x before 9.1.1.0200, 9.0.x before
9.0.2.0200, 8.0 before U3m, and the vCenter embedded in VCF, vSphere
Foundation and Telco Cloud. For 7.0, Rapid7 lists extended-support customers
as "contact Broadcom", and one table lists 5.x as fixed in 5.2.5. Confirm
both against VMSA-2026-0009.

Not affected: builds at or above the fixed versions. Exposure needs network
reach to the directory service (TCP 389/636, and DCE/RPC on 2012/2014/2020).
If only 443 is reachable from the attacker position, record the vCenter as
hardening-relevant for that position.

## Hard gates

1. **Authorization**: the vCenter is inside the authorized scope.
2. **No exploitation**: never send directory-service exploit traffic to a
   live vCenter. A successful bypass hands over every VM and the SSO trust
   chain. Prove the issue by version and reachability; cite Mandiant/GTIG
   for exploitability.
3. **Program policy**: the patch is days old. Check how the program treats
   fresh component zero-days.
4. **Compromise first**: the bug was exploited for more than two months
   before the patch. If you have host access, run the hunting checks
   before patch advice, and escalate any hit as an incident, not a
   finding.
5. **Lab first**: run `scripts/poc/vcenter-vmdir-bypass/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   python3 scripts/poc/vcenter-vmdir-bypass/poc/verify_exposure.py --target https://{host} --fixed-build <KB build>
   ```

## Detection workflow

1. **Version (remote, read-only)**: POST a `RetrieveServiceContent` SOAP
   request to `https://{host}/sdk`. The response's `<fullName>` and
   `<build>` give the exact build. `/sdk/vimServiceVersions.xml` gives
   the API level.
   ```bash
   curl -sk https://{host}/sdk -H 'Content-Type: text/xml' -H 'SOAPAction: urn:vim25/8.0' \
     -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent></soapenv:Body></soapenv:Envelope>' \
     | grep -oE '<(fullName|build)>[^<]+'
   ```
2. **Reachability**: from the attacker position, test TCP 389, 636, 2012,
   2014 and 2020. Use a connect scan only, with no LDAP binds.
3. **Map the build to fixed versions** with Broadcom's build-number KB.
   Product version strings alone can mislead.
4. **Hunt (host or SIEM access)**:
   - new or unexpected members of SSO `Administrators` / `SystemConfiguration.Administrators`;
   - SSO logins without a matching IdP/MFA event;
   - reads or copies of the vmdir LMDB (`/storage/db/vmware-vmdir/`);
   - unusual DCE/RPC connections to `vmdird` from non-vCenter hosts;
   - Mandiant's BONESAW IOCs.
5. Classify:
   - **affected**: unfixed build and the directory ports are reachable;
   - **hardening-relevant**: unfixed build but only 443 is reachable;
   - **not affected**: fixed build.

## Mitigation to cite

- Upgrade to 9.1.1.0200 / 9.0.2.0200 / 8.0 U3m (or the release Broadcom
  names for your line). No workaround exists.
- Restrict the vCenter management and directory ports to admin networks.
- After patching an exposed system, **rotate the SSO signing certificates
  (STS) and all SSO admin credentials**. Forged SAML keeps working after
  the patch until the signing material changes.

## Reporting

- Title: Unauthenticated Administrator access to vCenter via the VMware
  Directory Service (CVE-2026-123890).
- Include: `fullName`/build, which directory ports were reachable from
  where, the hunting results, and the patch status.

## Vendored artifacts

Under `scripts/poc/vcenter-vmdir-bypass/`:

- `poc/verify_exposure.py` - SOAP `RetrieveServiceContent` build fingerprint + vmdird port reachability; `--fixed-build` for the verdict
- `lab/setup.sh` - runs the PoC against an operator-owned nested/eval vCenter on a private address (refuses public IPs)
- `docs/ANALYSIS.md` - root cause, ARMORY CASTLE tradecraft, fixes

## References

- https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter/
- https://www.rapid7.com/db/vulnerabilities/cve-2026-123890/
- https://thehackernews.com/2026/11/critical-vmware-vcenter-flaw-cvss-98.html
- https://www.securityweek.com/newly-patched-vmware-vcenter-flaw-exploited-as-zero-day-by-chinese-apt
- https://www.rescana.com/post/vmware-vcenter-cve-2026-123890-directory-service-auth-bypass-patch-now
