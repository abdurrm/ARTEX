---
name: trafficserver-oct2026
description: "Invoke this skill when a task touches an Apache Traffic Server proxy/CDN node (8.x, 9.x before 9.2.16, 10.x before 10.1.5, or 10.2.0): assesses the four CVSS 3.1 10.0 flaws from the October 2026 release (CVE-2026-111812 origin_server_auth signing client-controlled AWS headers, CVE-2026-111813 magick plugin, CVE-2026-111814, CVE-2026-111815 TLS session-ticket bypass of per-SNI verify_client STRICT). Detection is version plus per-plugin config; verification is lab-first."
---

# trafficserver-oct2026: Apache Traffic Server October 2026 critical set (CVE-2026-111812..111815)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (version + per-CVE configuration; 111815 is provable with one resumption), using the
vendored PoCs and lab under `scripts/poc/trafficserver-oct2026/`. Run every PoC against the
lab first (`scripts/poc/trafficserver-oct2026/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/trafficserver-oct2026/...` are relative to this skill's base directory
(`<base>/scripts/poc/trafficserver-oct2026/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/trafficserver-oct2026/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/trafficserver-oct2026/lab ./trafficserver-oct2026-lab`
  and run `./trafficserver-oct2026-lab/setup.sh` from there.

## What the bugs are

| CVE | Component | Bug | Needs |
|---|---|---|---|
| 2026-111812 | `origin_server_auth` plugin | The plugin signs **client-controlled AWS headers** with the proxy's own IAM credentials, so a client can make signed S3 requests it should not be able to make. One analysis says the real impact is limited to reading what the proxy already serves. | The plugin enabled for an S3/AWS origin |
| 2026-111813 | `magick` plugin | Critical memory-safety flaw in the image-processing plugin (Safeguard's write-up). | `magick.so` loaded |
| 2026-111814 | (see Apache advisory) | One of the four critical (10.0) issues. Read the advisory text before assessing. | per advisory |
| 2026-111815 | TLS | **TLS session-ticket resumption bypasses per-SNI `verify_client STRICT`**: a session established for one SNI can be resumed for an SNI that requires a client certificate, which skips mTLS. | `sni.yaml` with `verify_client: STRICT` on some names, plus session tickets on |

- CVSS 4.0 scores are much lower (7.0 to 7.8), reflecting the
  configuration preconditions.
- No exploitation in the wild and no public PoC as of disclosure
  (2026-10-21/22).

## Affected / fixed

- Affected: 8.0.0 through 8.1.11 (no fix on 8.x), 9.0.0 through 9.2.15,
  10.0.0 through 10.1.4, and 10.2.0.
- Fixed: 9.2.16, 10.1.5, 10.2.1.

## Hard gates

1. **Authorization**: the proxy and the origins behind it are in scope.
   The 111812 impact lands on the **AWS account** behind the proxy, so
   that account must be in scope too.
2. **Lab first**: build ATS 10.2.0 and 10.2.1 with the same plugin and SNI
   configuration as the target, and prove each test there.
3. **Live verification limits**:
   - 111815: one resumption attempt against a STRICT SNI, using a ticket
     from a non-STRICT SNI. Request only a harmless resource and stop.
   - 111812: no live verification unless the AWS account owner explicitly
     authorizes it. Use read-only S3 verbs on a canary object only.
   - 111813 (memory safety): lab only.

## Detection workflow

1. **Fingerprint**: the `Server: ATS/x.y.z` and `Via:` headers. ATS often
   adds `[cMsSf ]`-style cache codes to Via.
   ```bash
   curl -skI https://{host}/ | grep -iE '^(server|via):'
   ```
2. **Version (host access)**: `traffic_server -V` / `traffic_ctl server
   status`.
3. **Config (host access)**:
   ```bash
   grep -nE 'origin_server_auth|magick' /etc/trafficserver/plugin.config /etc/trafficserver/remap.config
   grep -n -B2 -A4 'verify_client' /etc/trafficserver/sni.yaml
   traffic_ctl config get proxy.config.ssl.server.session_ticket.enable
   ```
4. **111815 probe (remote, lab-calibrated)**: find out whether the server
   issues session tickets and whether some SNIs demand client certs and
   others do not. Run the lab-verified script:
   ```bash
   scripts/poc/trafficserver-oct2026/poc/verify_ticket_bypass.sh {host}:443 <open-sni> <strict-sni>
   ```
   In the lab, 10.2.0 resumed an `open.lab` ticket on `strict.lab` without a
   certificate (TLS 1.3: HTTP 200; TLS 1.2: resumed, HTTP 403), and 10.2.1
   refused it.
5. Classify **per CVE**:
   - **affected**: unfixed version with the needed configuration present;
   - **hardening-relevant**: unfixed version without that configuration;
   - **not affected**: fixed version.

## Mitigation to cite

- Upgrade to 9.2.16 / 10.1.5 / 10.2.1. Migrate off 8.x.
- Interim:
  - 111815: disable session tickets, or apply `verify_client` STRICT
    globally;
  - 111812: unload `origin_server_auth` or scope down the IAM role;
  - 111813: unload `magick`.

## Reporting

- Report one finding per CVE that applies.
- Include: the ATS version, the relevant config excerpt, and lab evidence
  (plus the one-shot live result for 111815 if authorized).
- Mention both CVSS v3.1 10.0 and the lower v4.0 score.

## Vendored artifacts

Under `scripts/poc/trafficserver-oct2026/`:

- `poc/verify_exposure.py` - `Server`/`Via` fingerprint, version vs 9.2.16 / 10.1.5 / 10.2.1
- `poc/verify_ticket_bypass.sh` - CVE-2026-111815: baseline STRICT handshake, save ticket on the open SNI, resume on the STRICT SNI without a cert
- `lab/setup.sh` - ATS 10.2.0 (:28443) and 10.2.1 (:29443) built from source with `open.lab` (NONE) and `strict.lab` (STRICT), loopback only (verified 2026-11-21: 10.2.0 resumes into strict.lab -> VULNERABLE; 10.2.1 -> NOT AFFECTED)
- `docs/ANALYSIS.md` - per-CVE root causes and the lab results table

## References

- https://trafficserver.apache.org/security-2026-10.html
- https://lists.apache.org/thread/r95dq29ywcd1f4x30snxlqmb12z4s4kc
- https://securityonline.info/apache-traffic-server-vulnerabilities-october-2026/
- https://safeguard.sh/resources/blog/apache-traffic-server-9-2-16-10-1-5-15-cves-magick-plugin-cve-2026-111813
- https://www.strix.ai/cve/CVE-2026-111815
