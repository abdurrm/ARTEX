---
name: gitlab-onigmo-rce
description: "Invoke this skill when a task touches a self-managed GitLab CE/EE instance (or a self-built GitLab on system Ruby): assesses the two CVSS 10.0 unauthenticated RCEs in the Onigmo regular-expression engine, CVE-2026-97229 (CI/CD config regex, CISA KEV 2026-10-29, exploited against Alpine Linux) and CVE-2026-110264 (regex compiler integer overflow, GitLab 7.0 onward). Remote work is version fingerprinting; regex payloads are lab-only."
---

# gitlab-onigmo-rce: GitLab regex-engine RCEs (CVE-2026-97229, CVE-2026-110264)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (version and exposure classification; regex payloads are never shipped), using the
vendored PoCs and lab under `scripts/poc/gitlab-onigmo-rce/`. Run every PoC against the
lab first (`scripts/poc/gitlab-onigmo-rce/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## What the bugs are

- **CVE-2026-97229** (CVSS 10.0, KEV):
  - An integer overflow in the regex engine that GitLab uses to evaluate
    CI/CD configuration. An unauthenticated attacker can run commands on
    the GitLab server.
  - Fixed 2026-10-12. Attackers went after Alpine Linux's GitLab on
    2026-10-20/21, and Shadowserver tracked more than 1,000 vulnerable
    instances.
- **CVE-2026-110264** (CVSS 10.0):
  - An integer overflow while **compiling** a crafted regex, in a pattern
    with many repeats (internal ID overflow per Ruby's advisory).
  - "Under certain conditions" it gives unauthenticated RCE. It affects
    every self-managed release from 7.0 onward.
  - Fixed 2026-10-21. GitLab withheld the exact preconditions. One source
    says reducing public project visibility narrows the unauthenticated
    path.
- GitLab.com and Dedicated were patched before disclosure. Self-built
  installs also need the **Ruby** fix (Ruby 3.3 before 3.3.13 is listed for
  CVE-2026-97229).

## Affected / fixed

| CVE | Affected | Fixed releases |
|---|---|---|
| 2026-97229 | 19.1 through 19.4.1 (per one source) | 19.4.2, 19.3.5, 19.2.8 |
| 2026-110264 | 7.0 up to the fixes | 19.5.1, 19.4.3, 19.3.6, 19.2.9, 19.1.9, 19.0.10, 18.11.13 |

An instance on a fixed release for **both** CVEs (for example 19.4.3 or
later on 19.4) is not affected. Older branches without a backport are
affected by CVE-2026-110264.

## Hard gates

1. **Authorization**: the instance is in scope.
2. **No regex payloads on live instances**: both bugs corrupt memory in the
   Ruby process and can take down Puma/Sidekiq. Reproduce only against a
   lab GitLab of the same version, and only once a reviewed public trigger
   exists.
3. **Program policy**: both are fresh component zero-days. Check the policy.
4. **Compromise check**: one of them is exploited in the wild, so hunt
   before advising.
5. **Lab first**: run `scripts/poc/gitlab-onigmo-rce/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   python3 scripts/poc/gitlab-onigmo-rce/poc/verify_exposure.py --target https://{host} --token <read_api token>
   ```

## Detection workflow

1. **Version**:
   - With any valid token: `GET /api/v4/version`.
   - When signed in: `/help`.
   - Unauthenticated: compare the hashes of static assets
     (`/assets/webpack/*`, `/-/manifest.json`) with a release fingerprint
     database, or ask the operator.
   ```bash
   curl -sk -H "PRIVATE-TOKEN: $TOKEN" https://{host}/api/v4/version
   ```
2. **Exposure**:
   - Is sign-up open (`/users/sign_up`)?
   - Are there public projects (`/explore/projects`)?
   - Can anonymous users reach CI lint or pipeline features?
   Each of these widens the unauthenticated path. Record them.
3. **Self-built installs**: with host access, check `ruby -v` and the
   Onigmo version Ruby was built with.
4. Classify:
   - **affected**: unfixed for either CVE;
   - **not affected**: fixed for both;
   - **hardening-relevant**: unknown version, but anonymous access is
     restricted.

## Hunting (host access)

- `log/production_json.log` / `api_json.log`: unusually long or repetitive
  regex inputs. These include CI `rules:if =~` patterns, `only/except`
  regexes, and protected-branch patterns from unknown users.
- Puma or Sidekiq crashes (segfault, signal 11) around those requests.
- Child processes of `puma`/`sidekiq` that are not git or gitaly
  operations.
- Alpine's published incident timeline, which is a good model of what
  probing looks like.

## Mitigation to cite

- Upgrade to a release fixed for both CVEs. Self-built installs must also
  update Ruby.
- Interim:
  - restrict the instance to VPN or trusted networks;
  - disable open sign-up;
  - reduce public project visibility.

## Reporting

- Title: Unauthenticated RCE in GitLab via the Onigmo regex engine
  (CVE-2026-97229 / CVE-2026-110264).
- Include: the version and its source, the anonymous-exposure findings,
  the KEV status, and any hunting hits.

## Vendored artifacts

Under `scripts/poc/gitlab-onigmo-rce/`:

- `poc/verify_exposure.py` - version via `/api/v4/version` (token) or `--version`, per-CVE verdict tables, anonymous-exposure checks
- `lab/setup.sh` - GitLab CE 19.4.1 (:28100, both CVEs) and 19.5.1 (:28101, fixed) with lab `read_api` tokens, loopback only (verified 2026-11-21: 19.4.1 -> both AFFECTED, 19.5.1 -> both fixed)
- `docs/ANALYSIS.md` - root causes, fixed-release tables, in-the-wild notes

## References

- https://thehackernews.com/2026/10/critical-gitlab-flaw-cvss-100-could.html
- https://blog.ostorlab.co/gitlab-unauthenticated-rce-cve-2026-110264.html
- https://threatdefence.com/article/gitlab-cve-2026-97229-kev-threat-hunting
- https://securityonline.info/alpine-linux-gitlab-cve-2026-97229/
- https://aicybr.com/blog/gitlab-cve-2026-97229-cisa-kev-rce-patch-hunting-guide
