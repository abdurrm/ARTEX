---
name: linux-tcp-inetopt-uaf
description: "Invoke this skill when a task needs to assess Linux hosts (any kernel 4.4 or later, including RHEL 8/9/10, Ubuntu, Amazon Linux, Kubernetes nodes, appliances) for the remote IPv4 TCP handshake use-after-free on IP options (CVE-2026-98432, kernel CNA CVSS 9.8). Assessment is by kernel build and sysctl evidence; triggering the race is lab-only, never against a live host."
---

# linux-tcp-inetopt-uaf: IPv4 TCP handshake use-after-free (CVE-2026-98432)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (local evidence only; the race is never triggered), using the
vendored PoCs and lab under `scripts/poc/linux-tcp-inetopt-uaf/`. Run every PoC against the
lab first (`scripts/poc/linux-tcp-inetopt-uaf/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/linux-tcp-inetopt-uaf/...` are relative to this skill's base directory
(`<base>/scripts/poc/linux-tcp-inetopt-uaf/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/linux-tcp-inetopt-uaf/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/linux-tcp-inetopt-uaf/lab ./linux-tcp-inetopt-uaf-lab`
  and run `./linux-tcp-inetopt-uaf-lab/setup.sh` from there.

## What the bug is

- During the IPv4 TCP handshake, the kernel hands the listener's IP options
  (`inet_opt` / `ireq_opt`) to the new child socket **without taking a
  fresh copy**. A concurrent path can free that option state while another
  CPU still reads it, which is a use-after-free.
- The upstream fix is "ipv4: free inet_opt and ireq_opt after an RCU grace
  period". It defers the free until RCU readers are done.
- The bug has been present since Linux 4.4.
- Severity is disputed:
  - the kernel CNA scores it 9.8;
  - Red Hat first rated it 5.9 because the race must be won, then raised it
    to 9.8;
  - CloudLinux could not reproduce remote root.
- Attack path: the publicly described exploit targets an **MPTCP**
  listener. The freed state lives in the regular IPv4 TCP code, so
  `net.mptcp.enabled=0` blocks the demonstrated path but is not a full
  fix.
- No confirmed in-the-wild exploitation in the reviewed sources.

## Affected / fixed (vendor builds)

- Affected: any kernel 4.4 or later without the RCU fix.
- RHEL 8: `kernel-4.18.0-553.182.1.el8_10` (RHSA-2026:93414).
- RHEL 9: `kernel-5.14.0-687.64.1.el9_8` (RHSA-2026:93412).
- RHEL 10: `kernel-6.12.0-211.72.1.el10_2` (RHSA-2026:93413).
- Amazon Linux: fixed by 2026-10-30.
- Ubuntu: fixes in -security, per the most recent reports. Check USN for
  your series.
- Upstream: any stable kernel containing the commit above.

## Hard gates

1. **Authorization**: the hosts are in scope.
2. **Never trigger the race on live hosts**: a failed race panics the
   kernel and takes down everything on the box (including every pod on a
   Kubernetes node). Lab reproduction needs a disposable VM and a reviewed
   trigger.
3. **Evidence, not inference**: `uname -r` alone does not prove a fix,
   because vendors backport. Confirm against the vendor advisory or the
   package changelog.
4. **Lab first**: run `scripts/poc/linux-tcp-inetopt-uaf/lab/setup.sh` and the PoC against
   the lab until its output is understood, then run it once against the
   authorized target and keep both outputs as evidence:
   ```bash
   scripts/poc/linux-tcp-inetopt-uaf/poc/verify_kernel.sh   # on the host
   ```

## Detection workflow (host or inventory access)

1. **Kernel and package**:
   ```bash
   uname -r
   rpm -q --changelog kernel-$(uname -r) 2>/dev/null | grep -m1 -i 'CVE-2026-98432'
   zgrep -m1 'CVE-2026-98432' /usr/share/doc/linux-image-$(uname -r)/changelog.Debian.gz 2>/dev/null
   ```
2. **Running vs installed**: the host must have **rebooted** into the fixed
   kernel. Compare `uname -r` with the newest installed kernel package.
   Livepatch is acceptable only if the vendor lists CVE-2026-98432 in the
   livepatch.
3. **MPTCP exposure**:
   ```bash
   sysctl net.mptcp.enabled
   ss -Mltn
   ```
   The second command lists MPTCP listeners.
4. **Network reach**: which TCP listeners face untrusted networks? The bug
   is reachable through any IPv4 TCP listener that accepts connections.
5. Classify:
   - **affected**: the running kernel lacks the fix and has an exposed
     listener;
   - **not affected**: the fixed kernel is running;
   - **hardening-relevant**: unfixed but MPTCP disabled. The demonstrated
     path is blocked, but the core bug remains.

## Mitigation to cite

- Install the vendor kernel with the fix and **reboot**, or apply the
  vendor livepatch.
- Interim: `sysctl -w net.mptcp.enabled=0`, persisted in
  `/etc/sysctl.d/`. This blocks the demonstrated path but not the
  underlying bug.
- Prioritize internet-facing hosts and Kubernetes nodes.

## Reporting

- Title: Remote use-after-free in the Linux IPv4 TCP handshake
  (CVE-2026-98432).
- Include: the running kernel, the fixed build for that distro, reboot
  status, the MPTCP state, and the exposed listeners.
- Note the CVSS dispute (CNA 9.8 versus Red Hat's earlier 5.9).

## Vendored artifacts

Under `scripts/poc/linux-tcp-inetopt-uaf/`:

- `poc/verify_kernel.sh` - running vs installed kernel, CVE in the package changelog, RHEL fixed builds, MPTCP state, exposed listeners
- `lab/setup.sh` - runs the verifier over SSH on disposable VMs you own (refuses public addresses; no container lab is possible for a kernel race)
- `docs/ANALYSIS.md` - root cause, exploitability dispute, verifier result on the ARTEX host

## References

- https://thehackernews.com/2026/11/red-hat-patches-98-rated-linux-tcp-rce.html
- https://www.bitsight.com/blog/cve-2026-98432-critical-linux-tcp-vulnerability
- https://blog.cloudlinux.com/cve-2026-98432-linux-kernel-ipv4-tcp-flaw-status-for-cloudlinux
- https://www.sophos.com/en-us/security-advisories/sophos-sa-20261102-linux-kernel-tcp
- https://www.devopsness.com/blog/linux-kernel-tcp-cve-2026-98432-mptcp-kubernetes-nodes
