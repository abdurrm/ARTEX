# CVE-2026-97229 / CVE-2026-110264: GitLab and the Onigmo regex engine

## Root cause
Both are integer overflows in Onigmo, the regular-expression engine built
into Ruby, which GitLab uses on user-supplied patterns.
- **97229**: overflow while evaluating patterns from CI/CD configuration
  (for example `rules:if` `=~` expressions). Reachable by an unauthenticated
  attacker according to GitLab.
- **110264**: overflow of internal IDs while *compiling* a pattern with many
  repeats. GitLab withheld the exact unauthenticated path. Reducing public
  project visibility narrows it.

## Preconditions
- Self-managed GitLab on an unfixed release.
- Self-built installs also need the patched Ruby (3.3.13+ for 97229).
- GitLab.com and Dedicated were patched before disclosure.

## Fixes
- 97229: 19.4.2, 19.3.5, 19.2.8.
- 110264: 19.5.1, 19.4.3, 19.3.6, 19.2.9, 19.1.9, 19.0.10, 18.11.13.

## In the wild
- 97229: KEV 2026-10-29. Probed against Alpine Linux's GitLab on
  2026-10-20/21. Shadowserver counted more than 1,000 vulnerable instances.

## Lab
`lab/setup.sh` starts 19.4.1 (both CVEs) and 19.5.1 (both fixed) and mints a
`read_api` token so `poc/verify_exposure.py` reads `/api/v4/version`. No
regex payload is shipped.

Result on 2026-11-21:
- 19.4.1 -> both CVEs AFFECTED (exit 1);
- 19.5.1 -> both fixed (exit 0).

The stock image also showed an open sign-up link and an anonymous
public-project API (200), which are the anonymous-exposure signals the
verifier reports.

## Sources
See `skills/gitlab-onigmo-rce/SKILL.md`.
