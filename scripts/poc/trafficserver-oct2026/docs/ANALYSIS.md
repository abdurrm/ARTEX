# Apache Traffic Server October 2026 critical set (CVE-2026-111812..111815)

## CVE-2026-111815: per-SNI verify_client STRICT bypass via resumption
ATS enforces client-certificate policy per SNI (`sni.yaml`), but a resumed
TLS session (ticket) skips that check. A client completes a full handshake
on an SNI that needs no certificate, saves the ticket, and resumes it with
the SNI that requires `verify_client: STRICT`. The server accepts the
resumption without asking for a certificate.

### Lab results (scripts/poc/trafficserver-oct2026/lab, run 2026-11-21)
`open.lab` uses `verify_client: NONE`; `strict.lab` uses `STRICT`. Session
tickets are on (the default).

| Step | 10.2.0 | 10.2.1 |
|---|---|---|
| Fresh handshake to `strict.lab`, no cert | rejected | rejected |
| Resume `open.lab` ticket on `strict.lab`, TLS 1.3 | **Reused, HTTP/1.1 200** | New, rejected |
| Same, TLS 1.2 | **Reused**, HTTP/1.1 403 | New, rejected |

On TLS 1.2 the handshake gate was bypassed, but ATS's HTTP layer answered
403 (host and SNI policy). TLS 1.3 served the request.

## CVE-2026-111812: origin_server_auth signs client-controlled AWS headers
The plugin signs requests to S3/AWS origins with the proxy's IAM
credentials and includes headers the client supplied in the signature.
Clients can therefore steer signed requests. One analysis limits the
practical impact to objects the proxy already serves. Needs the plugin on
an AWS origin.

## CVE-2026-111813 / CVE-2026-111814
- 111813: memory-safety flaw in the `magick` image plugin. Needs
  `magick.so` loaded.
- 111814: see the Apache advisory.
- Both are lab-only.

## Scores and fixes
- CVSS 3.1 10.0 for all four. CVSS 4.0 is 7.0 to 7.8.
- Fixed in 9.2.16, 10.1.5 and 10.2.1. 8.x has no fix.

## Sources
See `skills/trafficserver-oct2026/SKILL.md`.
