---
name: httpd-h2-race
description: "Invoke this skill when a task touches an Apache HTTP Server target that may run 2.4.55-2.4.70 (or standalone mod_h2 2.0.8-2.0.42) with HTTP/2 enabled: assesses the mod_http2 assign_headers() race that corrupts the heap and can give unauthenticated RCE (CVE-2026-119618, Apache rates Critical; 9.8 per Orca, unconfirmed). Remote work is ALPN and version detection; heap-race triggers are lab-only."
---

# httpd-h2-race: Apache mod_http2 heap-corruption race (CVE-2026-119618)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (exposure detection; race triggers are never shipped), using the
vendored PoCs and lab under `scripts/poc/httpd-h2-race/`. Run every PoC against the
lab first (`scripts/poc/httpd-h2-race/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/httpd-h2-race/...` are relative to this skill's base directory
(`<base>/scripts/poc/httpd-h2-race/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/httpd-h2-race/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/httpd-h2-race/lab ./httpd-h2-race-lab`
  and run `./httpd-h2-race-lab/setup.sh` from there.

## What the bug is

- The bug is a race condition (CWE-362) in mod_http2's `assign_headers()`.
  Shared header state is touched by concurrent stream processing without
  proper synchronization, which corrupts heap memory in the httpd child
  process.
- With grooming, the corruption can become unauthenticated code execution
  as the httpd worker user. Red Hat's advisory reportedly cites public
  research with a reliable exploit against a default configuration.
  SecurityOnline reports no confirmed exploitation.
- Found by Google researchers and flagged by Anthropic's OSS scanner.
- Severity: Apache rates it "Critical" without a number. Orca lists CVSS
  9.8. Treat 9.8 as unconfirmed until NVD publishes a score.

## Affected / not affected

- Affected: httpd 2.4.55 through 2.4.70, and standalone mod_h2 2.0.8
  through 2.0.42 (archived repository). The server must have mod_http2
  loaded **and** `h2` or `h2c` in a `Protocols` directive.
- Fixed: httpd 2.4.71 (2026-11-11), or a distro backport (RHEL and Debian
  have published fixed builds).
- Not affected: HTTP/1.1-only servers (mod_http2 not loaded, or no `h2` /
  `h2c` in `Protocols`), and servers behind an edge that terminates HTTP/2.

## Hard gates

1. **Authorization**: the target is in scope.
2. **No race triggers on live targets**: heap corruption crashes children
   and can hit other users' requests. Lab only (httpd 2.4.70 versus 2.4.71
   containers).
3. **Restart status**: a package upgrade without a restart leaves the old
   module loaded.
4. **Lab first**: run `scripts/poc/httpd-h2-race/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   python3 scripts/poc/httpd-h2-race/poc/verify_exposure.py --target https://{host} --h2c http://{host}
   ```

## Detection workflow

1. **HTTP/2 exposure and version**: one TLS handshake (ALPN), an optional
   h2c upgrade test, and the `Server` version. No HTTP/2 frames are sent.
   ```bash
   python3 scripts/poc/httpd-h2-race/poc/verify_exposure.py --target https://{host} --h2c http://{host}
   ```
2. **h2c (cleartext)**: send an HTTP/1.1 request with
   `Upgrade: h2c` / `HTTP2-Settings`. A `101 Switching Protocols` response
   means h2c is enabled.
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' --http2 http://{host}/
   ```
3. **Version**: the `Server: Apache/2.4.x` header (hidden by
   `ServerTokens Prod`), error pages, and `/server-status` if it is
   exposed.
4. **Host access**:
   ```bash
   apachectl -v
   apachectl -M | grep http2
   grep -RniE '^\s*Protocols' /etc/httpd /etc/apache2
   ```
   Check the distro changelog for CVE-2026-119618 and compare the process
   start time with the package install time.
5. Classify:
   - **affected**: in range (no backport) and h2/h2c is on;
   - **not affected**: fixed, or HTTP/2 is off;
   - **hardening-relevant**: version unknown with h2 on, or in range but h2
     is terminated at the edge.

## Mitigation to cite

- Upgrade to 2.4.71 or the distro backport, then **restart** (not just a
  graceful reload).
- Interim: set `Protocols http/1.1`, or stop loading mod_http2.
- Migrate users of standalone mod_h2 to the bundled module.

## Reporting

- Title: Pre-auth heap corruption in Apache httpd mod_http2
  (CVE-2026-119618).
- Include: the version and its source, the ALPN/h2c results, the
  `Protocols` lines, and backport and restart status. Note that the score
  is unconfirmed.

## Vendored artifacts

Under `scripts/poc/httpd-h2-race/`:

- `poc/verify_exposure.py` - ALPN h2 handshake, optional h2c upgrade test, `Server` version vs 2.4.55-2.4.70
- `lab/setup.sh` - httpd 2.4.70 (:18443/:18480) and 2.4.71 (:19443/:19480) with mod_http2 on, loopback only (verified 2026-11-21: 2.4.70 -> AFFECTED, 2.4.71 -> NOT AFFECTED)
- `docs/ANALYSIS.md` - root cause, preconditions, lab results

## References

- https://orca.security/resources/research/cve-2026-119618-critical-apache-http-2-race-condition-enables-unauthenticated-remote-code-execution/
- https://redsift.com/blog/apache-http2-cve-2026-119618
- https://www.sysdig.com/blog/httpd-cve-2026-119618-detecting-heap-corruption-and-rce-in-apache-http-server-mod-http2
- https://flawfence.com/blog/en/cve-2026-119618-apache-http-server-mod-http2-rce/
- https://securityonline.info/apache-http-server-cve-2026-119618-rce-fixed/
