---
name: gpustack-loopback-bypass
description: "Invoke this skill when a task touches a GPUStack inference server (any release before 2.2.0, or 2.2.0-2.2.1 for the related SAML flaw): verifies the unauthenticated admin takeover via the trusted-loopback check (forged X-GPUStack-Real-IP header or a same-host reverse proxy) (CVE-2026-102895, CVSS 9.8, CISA KEV 2026-11-09). Verification is a single read-only admin request; no state changes."
---

# gpustack-loopback-bypass: GPUStack loopback auth bypass (CVE-2026-102895)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (one read-only request proves it), using the
vendored PoCs and lab under `scripts/poc/gpustack-loopback-bypass/`. Run every PoC against the
lab first (`scripts/poc/gpustack-loopback-bypass/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/gpustack-loopback-bypass/...` are relative to this skill's base directory
(`<base>/scripts/poc/gpustack-loopback-bypass/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/gpustack-loopback-bypass/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/gpustack-loopback-bypass/lab ./gpustack-loopback-bypass-lab`
  and run `./gpustack-loopback-bypass-lab/setup.sh` from there.

## What the bug is

- In `gpustack/api/auth.py`, `get_current_user` treats any request whose
  source looks like loopback as the built-in **administrator** whenever
  `force_auth_localhost=false` (the default).
- The source can look like loopback in two ways:
  - the client sends `X-GPUStack-Real-IP: 127.0.0.1`, which the server
    trusts;
  - NGINX, Caddy or similar runs on the same host and forwards to
    `127.0.0.1`, so every proxied request arrives from loopback.
- Admin access leads to RCE: an admin can deploy arbitrary model backends
  and commands onto workers. It also exposes API keys and connected
  credentials.
- Weaknesses: CWE-287, CWE-290, CWE-346. CVSS 9.8. KEV since 2026-11-09,
  and the vendor reports exploitation against a 2.1.1 deployment.
- A separate bug, CVE-2026-102894, is a SAML callback that accepts
  unverified `SAMLResponse`. It affects 0.7.1 through 2.2.1 and is fixed in
  2.2.2, so 2.2.0 alone is not enough.

## Affected / fixed

- CVE-2026-102895: every release before 2.2.0. 2.2.0 removes the loopback
  trust and deprecates `force_auth_localhost`.
- CVE-2026-102894: before 2.2.2, when SAML SSO is configured.

## Hard gates

1. **Authorization**: the GPUStack instance is in scope.
2. **Read-only verification**: send one GET to an admin-only list endpoint.
   Never call POST, PUT or DELETE, deploy models, or touch workers. Do not
   store or re-use any secrets the response returns; redact them in
   evidence.
3. **Program policy**: the KEV listing is recent, so check the policy on
   fresh component bugs.

## Detection and verification workflow

1. **Lab first**: `scripts/poc/gpustack-loopback-bypass/lab/setup.sh` starts
   v2.1.1 and v2.2.2. Run the verifier against both and keep the outputs.
2. **Fingerprint**: `GET /version` answers without auth (`{"version":"v2.1.1",...}`).
   The API prefix is `/v2/`; check `/openapi.json` if a release differs.
3. **Verify (two read-only GETs)**: a baseline `GET /v2/users/me`, then the
   same request with `X-GPUStack-Real-IP: 127.0.0.1`.
   ```bash
   python3 scripts/poc/gpustack-loopback-bypass/poc/verify_loopback_bypass.py --target https://{host}
   ```
   A 401 baseline followed by a 200 with `"is_admin": true` proves the bypass.
   `X-Forwarded-For` is **not** trusted (lab-verified), so only the
   GPUStack header matters. Save the redacted output as evidence.
4. **Proxy variant**: if the baseline is already 200 with no credentials,
   a same-host reverse proxy is presenting every request as loopback. That
   is the same CVE through the proxy path.
5. **SAML (CVE-2026-102894)**: if SSO is enabled and the version is below
   2.2.2, report it from the version alone. Do not forge SAML responses
   against production.
6. Classify:
   - **affected**: the bypass is proven, or the version is below 2.2.0;
   - **not affected**: 2.2.2 or later, and the header test returns 401/403.

## Hunting (host access)

- Access logs with `X-GPUStack-Real-IP` from non-proxy clients, and admin
  API calls with no session or key.
- New users, API keys, model deployments or backend commands that nobody
  can account for. Rotate every key if any appear.

## Mitigation to cite

- Upgrade to 2.2.2 or later (this covers both CVEs).
- Interim:
  - set `force_auth_localhost=true`;
  - strip client-supplied `X-GPUStack-Real-IP` at the edge;
  - keep the API off untrusted networks.
- After exposure, rotate API keys, upstream credentials and worker
  tokens.

## Reporting

- Title: Unauthenticated administrator access to GPUStack via a spoofed
  loopback source (CVE-2026-102895).
- Include: the baseline and header-test status codes, the redacted
  evidence, the version, and the KEV status.

## Vendored artifacts

Under `scripts/poc/gpustack-loopback-bypass/`:

- `poc/verify_loopback_bypass.py` - `GET /version`, baseline `GET /v2/users/me`, then the same with `X-GPUStack-Real-IP: 127.0.0.1`; output redacted
- `lab/setup.sh` - GPUStack v2.1.1 (:28090) and v2.2.2 (:28091), loopback only (verified 2026-11-21: v2.1.1 header -> 200 admin, v2.2.2 -> 401)
- `docs/ANALYSIS.md` - root cause and the lab results table

## References

- https://advisories.gitlab.com/pypi/gpustack/CVE-2026-102895/
- https://www.qovery.com/blog/gpustack-cve-2026-102895-kev-patch-hardening-runbook
- https://securityonline.info/gpustack-authentication-bypass-cve-2026-102895-exploited/
- https://www.thehackerwire.com/cve-2026-102894-gpustack-saml-bypass-permits-unauthenticated-administrator-account-takeover/
