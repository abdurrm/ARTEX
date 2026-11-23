# CVE-2026-119618: Apache httpd mod_http2 assign_headers() race

## Root cause
`assign_headers()` in mod_http2 updates shared header state from concurrent
stream processing without proper synchronization (CWE-362). Interleaved
streams can corrupt heap structures in the httpd child process.

## Preconditions
- httpd 2.4.55 through 2.4.70 (or standalone mod_h2 2.0.8 through 2.0.42).
- `mod_http2` must be loaded and `Protocols` must include `h2` or `h2c`.
- The client needs a direct HTTP/2 path: an edge that terminates h2 breaks
  the chain.

## Exploitation outline (public descriptions)
The attacker opens many concurrent streams whose header processing
interleaves, wins the race, grooms the heap, and gets code execution as the
httpd worker user. Red Hat reportedly cites a reliable exploit against a
default configuration. Apache rates the bug Critical; the 9.8 score is
Orca's and is unconfirmed.

## Lab results (scripts/poc/httpd-h2-race/lab, run 2026-11-21)
- 2.4.70: ALPN `h2`, the h2c upgrade is accepted, and the verifier reports
  AFFECTED.
- 2.4.71: ALPN `h2`, the h2c upgrade is accepted, and the verifier reports
  NOT AFFECTED (version).

No race trigger is shipped. Any trigger stays lab-only.

## Fix
2.4.71 (2026-11-11) or a distro backport. A **restart** is required.

## Sources
See `skills/httpd-h2-race/SKILL.md`.
