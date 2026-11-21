# CVE-2026-102895: GPUStack trusted-loopback admin bypass

## Root cause
`get_current_user` in `gpustack/api/auth.py` promotes any request whose
source looks like loopback to the built-in administrator when
`force_auth_localhost=false` (the default). The source IP is taken from the
client-controlled `X-GPUStack-Real-IP` header. Behind a same-host reverse
proxy, every request arrives from 127.0.0.1 anyway.

## Preconditions
- GPUStack before 2.2.0 with the API reachable.
- No other conditions.

## Impact
Full admin: users, API keys, cluster and worker control, and model and
backend deployment, which leads to command execution on workers. Weaknesses:
CWE-287, CWE-290, CWE-346; CVSS 9.8; KEV 2026-11-09.

## Lab results (scripts/poc/gpustack-loopback-bypass/lab, run 2026-11-21)

| Request | v2.1.1 | v2.2.2 |
|---|---|---|
| `GET /version` | `v2.1.1` (no auth) | `v2.2.2` (no auth) |
| `GET /v2/users/me` | 401 | 401 |
| `GET /v2/users/me` + `X-GPUStack-Real-IP: 127.0.0.1` | **200** `{"username":"admin","is_admin":true}` | 401 |
| `GET /v2/users/me` + `X-Forwarded-For: 127.0.0.1` | 401 | 401 |

Only the GPUStack-specific header is trusted. The API prefix is `/v2/`.

## Related
CVE-2026-102894 is a SAML callback that trusts an unverified `SAMLResponse`.
It affects versions before 2.2.2.

## Sources
See `skills/gpustack-loopback-bypass/SKILL.md`.
