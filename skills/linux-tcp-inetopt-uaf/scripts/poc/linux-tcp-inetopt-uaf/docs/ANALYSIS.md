# CVE-2026-98432: Linux IPv4 TCP handshake inet_opt use-after-free

## Root cause
During the IPv4 TCP handshake, the listener's IP options (`inet_opt` /
`ireq_opt`) are attached to the child socket without a fresh copy. A
concurrent path can free them while another CPU still reads them. The fix,
"ipv4: free inet_opt and ireq_opt after an RCU grace period", defers the
free until RCU readers finish. The bug has been present since 4.4.

## Exploitability
- The kernel CNA scores it 9.8. Red Hat first said 5.9 because the race must
  be won, then raised it to 9.8.
- CloudLinux could not reproduce remote root.
- The public demonstration used an MPTCP listener. `net.mptcp.enabled=0`
  blocks that path, but the use-after-free is in plain IPv4 TCP.

## Why there is no container lab
Containers share the host kernel. Racing it would panic the host. The lab is
a disposable VM (`lab/setup.sh` runs the verifier over SSH and refuses public
addresses).

## Verifier result on the ARTEX host (2026-11-21)
`poc/verify_kernel.sh` on Ubuntu kernel `6.8.0-137-generic` found no
`CVE-2026-98432` entry in the kernel package changelog, MPTCP enabled, and
no MPTCP listeners. It classified the host as affected and asked for
confirmation against the Ubuntu USN.

## Sources
See `skills/linux-tcp-inetopt-uaf/SKILL.md`.
