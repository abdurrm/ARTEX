# CVE-2026-76466: Cisco Expressway hard-coded cluster database credential

## Root cause
Clustered Expressway peers replicate configuration through a database
service protected by a credential that is the same on every installation
(CWE-798). Anyone who can reach that service authenticates with it and runs
OS commands as root. Cisco describes this as persistent cookies in the
database service.

## Preconditions
- Clustered Expressway-C/E on X15.5.3 or earlier, or X14 (migrate).
- Network reach to the cluster service ports.
- Standalone nodes are not affected.

## Status
- Public PoC.
- KEV 2026-11-20. Reported root takeover of four clustered gateways.
- Fixed in X15.5.20. No workaround.

## Lab
Expressway is licensed. `lab/setup.sh` runs the verifier against an
operator-owned two-node lab cluster on private addresses. The credential is
never used by the shipped PoC. Engagement-authorized one-shot use stays a
manual, reviewed step.

## Sources
See `skills/expressway-cluster-cred/SKILL.md`.
