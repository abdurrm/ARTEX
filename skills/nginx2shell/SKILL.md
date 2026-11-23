---
name: nginx2shell
description: "Invoke this skill when a task touches an NGINX target (or needs to assess one) that may run NGINX Open Source 1.9.5-1.31.8 or NGINX Plus before 37.0.8.1/37.3.0.1 with HTTP/2 enabled: assesses pre-auth RCE exposure via the HTTP/2 flow-control integer underflow and heap overflow (CVE-2026-123007, NGINX2Root/Nginx2Shell). Remote work is detection only; memory-corruption verification is lab-only, gated by program policy."
---

# nginx2shell: HTTP/2 send-window underflow -> heap overflow -> RCE (CVE-2026-123007)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (detection-first; the trigger stays lab-only), using the
vendored PoCs and lab under `scripts/poc/nginx2shell/`. Run every PoC against the
lab first (`scripts/poc/nginx2shell/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/nginx2shell/...` are relative to this skill's base directory
(`<base>/scripts/poc/nginx2shell/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/nginx2shell/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/nginx2shell/lab ./nginx2shell-lab`
  and run `./nginx2shell-lab/setup.sh` from there.

## What the bug is

- The bug is in the NGINX HTTP/2 module (`ngx_http_v2_module`), in how it
  accounts for the connection's flow-control **send window**. The protocol
  maximum for that window is 2^31-1.
- When a stream is cancelled (`RST_STREAM`), NGINX credits the unsent queued
  DATA back to the connection window **without checking the protocol
  maximum**. Mallory attributes this to `ngx_http_v2_filter_cleanup()`.
- Once the window passes 2^31-1, the overflow check on later `WINDOW_UPDATE`
  frames wraps around, so the client can keep raising the window.
- When NGINX prepares DATA to send, the oversized window becomes a
  **negative length**. That length drives a copy in TLS output staging,
  which reads and writes out of bounds on the heap.
- Weakness class: integer underflow (CWE-191) causes a heap-based buffer
  overflow (CWE-787). Sources pick one or the other, but both describe the
  same bug.
- Impact: unauthenticated remote memory corruption of the worker process.
  The result is either a crash (SIGSEGV) or code execution **as the worker
  user, not root**. Getting root needs a separate kernel bug (the SCTP
  use-after-free mentioned in the advisories).
- Severity: CVSS 4.0 9.2 (F5); CVSS 3.1 8.1 (Red Hat). Disclosed
  2026-11-18 together with CVE-2026-123633, -123634, -121810 and -113425
  (the "NGINX2Root" set).

## Affected / not affected

Affected:
- NGINX Open Source 1.9.5 through 1.30.6, and 1.31.0 through 1.31.8.
  Stable branches older than 1.30 (for example 1.26 and 1.28) are affected
  and have no fix on their own branch.
- NGINX Plus R33 or R34 through R36, and 37.x before 37.0.8.1 / 37.3.0.1.
  Sources disagree on whether R33 is the lower bound.
- HTTP/2 must be enabled on a listener: `http2 on;` (1.25.1+) or
  `listen ... http2`. Serving static files is enough; no proxy or upstream
  is needed.
- Distribution builds (RHEL, Debian, Ubuntu, Alpine) and container images
  built on them may carry backports. A version string alone cannot tell you
  whether a backport is present, so check the distribution tracker.

Not affected:
- NGINX OSS 1.30.7+ (stable) and 1.31.9+ (mainline); Plus 37.0.8.1 /
  37.3.0.1.
- Listeners without HTTP/2. That rules out this CVE only: the other four
  NGINX2Root CVEs (resolver, mail, HTTP/3, HTTP/2 proxy) are separate and are
  **not** mitigated by turning off HTTP/2.
- Clients that reach NGINX only through a CDN, WAF or load balancer that
  terminates HTTP/2. The edge downgrades the connection, so the attack frames
  never reach NGINX. Record this as hardening-relevant, because the origin
  may still be reachable directly.

## Hard gates

1. **Authorization**: the target is inside the task's authorized scope.
2. **Program policy first**: NGINX patched this on 2026-11-18, so it is a
   fresh component zero-day. Many programs exclude or do not pay for
   component zero-days within about 14 days of the patch. CHECK the policy
   before touching a live target, and claim the finding to match it (often
   "reportable, not payable").
3. **Detection only on live targets**: never send the trigger sequence
   (cancelled streams plus a `WINDOW_UPDATE` flood) to a remote target.
   Doing so corrupts worker memory, kills live connections, needs about
   120-128 GB of traffic, and can run code on a production host. Remote
   verdicts come from fingerprinting and configuration evidence alone.
4. **Lab first, lab only**: reproduce the crash with `scripts/poc/nginx2shell/lab/` (a vulnerable
   1.31.8 build next to a patched 1.31.9 build). The evidence is a worker
   SIGSEGV on the vulnerable build and a clean run on the patched one.
5. **No RCE chain**: do not build, adapt or run the public RCE exploit, not
   even in the lab, unless the engagement explicitly authorizes exploit
   development. A crash on the vulnerable build that does not occur on the
   patched build is enough proof for the report.
6. **Untrusted PoCs**: several public "PoC" repositories are unverified and
   some ship shell payloads. Read every line before running anything, and
   run it only against `scripts/poc/nginx2shell/lab/` with no route to other hosts.

## Detection workflow

1. **HTTP/2 exposure (remote)**: does the TLS listener negotiate ALPN `h2`?
   ```bash
   python3 scripts/poc/nginx2shell/poc/verify_exposure.py remote https://{host}
   ```
   The detector runs one TLS handshake with ALPN `h2,http/1.1` and one
   HTTP/1.1 `HEAD /`. It sends no HTTP/2 frames.
2. **Version (remote)**: read `Server: nginx/x.y.z` and error pages. With
   `server_tokens off` the version is hidden; record it as unknown and move
   on to the next step instead of guessing.
3. **Version and config (host access)**: run `nginx -V` and
   `nginx -T | grep -nE 'http2|listen'`, or pass the saved output to the
   detector:
   ```bash
   python3 scripts/poc/nginx2shell/poc/verify_exposure.py local --nginx-v nginx-V.txt --nginx-t nginx-T.txt
   ```
   Check the distribution changelog for a CVE-2026-123007 backport
   (Red Hat RHSB-2026-019, Debian security tracker).
4. **Path**: is a CDN or WAF in front? Can the origin be reached directly
   over h2? An edge that terminates HTTP/2 blocks the attack, but a direct
   path to the origin does not.
5. **Running binary**: a package upgrade without a **restart** leaves the
   vulnerable binary running, because `nginx -s reload` does not replace the
   master executable. Compare the package version with the process start
   time when you have host access.
6. Classify:
   - **affected**: the version is in range, h2 is reachable, and there is no
     backport.
   - **not affected**: the version is fixed, or the listener has no h2.
   - **hardening-relevant**: the version is in range but h2 is off or
     terminated at the edge. Also use this when the version is unknown but h2
     is on; state what evidence would settle it.

## Lab reproduction

`scripts/poc/nginx2shell/lab/setup.sh` builds NGINX from nginx.org sources so that the vulnerable and patched
builds differ only in version:

```bash
scripts/poc/nginx2shell/lab/setup.sh               # builds nginx 1.31.8 (:8443) and 1.31.9 (:9443), h2 over TLS
(cd scripts/poc/nginx2shell/lab && docker compose logs -f)   # watch for "worker process N exited on signal 11"
scripts/poc/nginx2shell/lab/setup.sh down
```

Run the reviewed trigger (for example the minimal trigger in the Rapid7
repository `sfewer-r7/CVE-2026-123007`, **not** its RCE exploit) against
`https://127.0.0.1:8443`, then against `:9443`. Proof that the bug is real:

- vulnerable build: `worker process N exited on signal 11` (SIGSEGV) in the
  error log, and the master respawns the worker;
- patched build: the same traffic ends without a crash (NGINX rejects the
  oversized window and closes the connection with a flow-control error).

Censys independently reproduced worker-level code execution with the public
exploit in an isolated lab. Cite that as third-party evidence instead of
reproducing RCE yourself.

## Mitigation to cite

- Upgrade to NGINX 1.30.7 / 1.31.9 (or Plus 37.0.8.1 / 37.3.0.1, or the
  distribution backport), then **restart**.
- Interim: `http2 off;` in the affected `server` blocks (1.25.1+), or remove
  `http2` from `listen`. Reload and confirm the old workers have exited.
- Defence in depth: run workers as an unprivileged user. Blacklist the
  `sctp` kernel module where it is not needed, since it is the reported path
  from worker to root.
- `ingress-nginx` is archived and will not receive a fix; recommend
  migrating away from it.

## Reporting

- Title: Pre-auth heap memory corruption in the NGINX HTTP/2 flow-control
  window (CVE-2026-123007, "NGINX2Root").
- Severity: Critical (CVSS 4.0 9.2) when h2 is reachable directly; lower
  when an edge terminates h2.
- Include: the exact NGINX version and source (`Server` header, `nginx -V`,
  or package), the ALPN result, the http2 config lines, what sits in front
  of NGINX, the backport and restart status, and the lab crash evidence if
  you have it.
- Use `{host}` placeholders in anything published.

## Vendored artifacts

Under `scripts/poc/nginx2shell/`:

- `poc/verify_exposure.py` - `remote`: one TLS handshake (ALPN h2) + one HEAD, no HTTP/2 frames; `local`: parses saved `nginx -V` / `nginx -T`
- `lab/setup.sh` - builds nginx 1.31.8 (:8443) and 1.31.9 (:9443) from nginx.org sources, h2 over TLS, loopback only (verified 2026-11-21: 1.31.8 -> affected, 1.31.9 -> not-affected)
- `docs/ANALYSIS.md` - root cause, preconditions, exploitation outline, related CVEs

## References

- https://research.jfrog.com/post/nginx2shell-all-you-need-to-know-about-cve-2026-123007-and-cve-2026-123633/
- https://www.tenable.com/blog/nginx2root-cve-2026-123007-frequently-asked-questions-about-five-critical-nginx
- https://access.redhat.com/security/vulnerabilities/RHSB-2026-019
- https://mallory.ai/vulnerabilities/CVE-2026-123007
- https://security-tracker.debian.org/tracker/CVE-2026-123007
