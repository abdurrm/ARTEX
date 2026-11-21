# CVE-2026-90817: REDCap unauthenticated RCE

## The bug (public)
Manipulated HTTP requests to REDCap's public functionality (described as
survey-related) give code execution as the web-server user. That user has
access to `database.php` credentials and therefore to all project data.
- CVSS 9.8. KEV 2026-11-18.
- Public exploit code is referenced (`ExDev994/CVE-2026-90817`); review it
  before trusting it.

## Affected and fixed
- Affected: 13.3.0 and later.
- Fixed: 16.0.49 LTS, 17.3.10 LTS, 17.4.4 Standard.

## Verifier
`poc/verify_exposure.py` reads the version from the `redcap_vX.Y.Z` code
directory in asset URLs and classifies it per track. The version-table logic
was unit-checked on 2026-11-21.

## Lab
REDCap is consortium-licensed. `lab/setup.sh` builds PHP 8.2, Apache and
MariaDB from the zip you supply, and binds to loopback only. Use synthetic
data only.

## Sources
See `skills/redcap-rce/SKILL.md`.
