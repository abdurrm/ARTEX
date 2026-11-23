# CVE-2026-123007: technical analysis

This summary draws on JFrog, Tenable, Red Hat RHSB-2026-019 and Mallory.ai
(links in `skills/nginx2shell/SKILL.md`). Where the sources disagree, the disagreement is
noted.

## Background: HTTP/2 flow control

Each HTTP/2 connection and stream has a send window: the number of bytes
the peer still allows the sender to send. The receiver raises it with
`WINDOW_UPDATE`, and the sender lowers it every time it sends DATA. RFC 9113
caps the window at 2^31-1, and a window above that is a `FLOW_CONTROL_ERROR`.

## Root cause

1. NGINX queues response DATA while the connection window is exhausted.
2. When the client cancels a stream (`RST_STREAM`), the cleanup path
   credits the unsent queued bytes back to the connection send window.
   It does this **without checking the 2^31-1 maximum**. Mallory names
   `ngx_http_v2_filter_cleanup()`.
3. With the window already above the maximum, the overflow check on new
   `WINDOW_UPDATE` frames wraps, so the client can keep raising the window
   indefinitely.
4. When NGINX next prepares output, the oversized window is converted to
   a **negative length** (integer underflow, CWE-191).
5. That length drives a copy into the TLS output buffer, which reads and
   writes out of bounds on the heap (CWE-787).

The upstream fix makes the `WINDOW_UPDATE` check account for queued data.
JFrog cites commit `e27f5fa84fe`; Mallory lists `b89c4100bf...`.

## Preconditions

- NGINX OSS 1.9.5-1.30.6 or 1.31.0-1.31.8, or an affected NGINX Plus.
- HTTP/2 enabled (`http2 on;` / `listen ... http2`). Static content is
  sufficient.
- A direct h2 path from the attacker to NGINX. An edge that terminates h2
  breaks the chain.
- For code execution, as opposed to a crash: ASLR absent or defeated (the
  public exploit includes an in-band leak), plus x86-64 glibc copy-routine
  behaviour.
- About 119-128 GB of traffic on one long-lived connection, within the
  default one-hour connection limit.

## Exploitation outline

The attacker first queues large responses behind a zero window. They then
cancel streams so the queued bytes are refunded past the maximum, and
flood `WINDOW_UPDATE` to push the window through the wrap. This yields an
out-of-bounds copy primitive. The final stage grooms the heap, leaks
addresses, and redirects control flow to code running as the worker user.
The public exploit uses per-version profiles (1.31.6 and 1.31.8), so there
is no universal payload.

## Evidence that it is real

- The Rapid7 PoC (`sfewer-r7/CVE-2026-123007`) contains a minimal trigger
  that crashes the worker. The crash shows up as `worker process N exited
  on signal 11`.
- The same repository holds a full RCE exploit, demonstrated against
  1.31.8 in Docker over h2/TLS.
- Censys independently reproduced code execution as the worker user, not
  root, in an isolated lab.
- None of the sources report in-the-wild exploitation, and the CVE is not
  in CISA KEV as of disclosure week.

## Related CVEs (the "NGINX2Root" set)

| CVE | Area | Class | Mitigated by `http2 off`? |
|---|---|---|---|
| 2026-123633 | HTTP/2 proxy (upstream) | UAF | yes |
| 2026-123634 | resolver (SSI / mirror) | UAF | no |
| 2026-121810 | HTTP/3 / QUIC | UAF | no |
| 2026-113425 | mail proxy | UAF | no |
