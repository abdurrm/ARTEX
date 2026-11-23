# CVE-2026-101809 / CVE-2026-101767: Oracle EBS October 2026 CPU

## The bugs (public)
- **101809** (CVSS 10.0): Workflow Notification Mailer. Unauthenticated
  over HTTP, leading to takeover with scope change.
- **101767** (CVSS 9.8): Application Object Library. Unauthenticated SQL
  injection leading to RCE (Horizon3, reported July 2026).

## Preconditions
EBS 12.2.3 through 12.2.15 without the October 2026 CPU, with the web tier
reachable.

## Status
Oracle marks neither as exploited. EBS has a history of mass exploitation
shortly after a CPU.

## Verifiers
- `poc/verify_exposure.py`: GET-only web-tier fingerprint.
- `poc/check_cpu.sql`: release level, AD/TXK code levels, and patches
  applied since 2026-10-20. An empty list means the CPU is missing.

## Lab
A non-production EBS clone at the same patch level (`lab/setup.sh` enforces
a private address).

## Sources
See `skills/oracle-ebs-oct2026/SKILL.md`.
