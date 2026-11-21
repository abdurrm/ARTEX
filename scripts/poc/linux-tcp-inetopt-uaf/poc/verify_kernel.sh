#!/bin/bash
# CVE-2026-98432 - Classify a Linux host for the IPv4 TCP inet_opt use-after-free
# from local evidence only. Never opens connections or races the kernel.
#
# Demonstrates:
#   1. running kernel vs newest installed kernel (reboot pending?)
#   2. CVE-2026-98432 in the running kernel package changelog (RPM / Debian)
#   3. RHEL fixed builds (RHSA-2026:93412/93413/93414) compared by version
#   4. MPTCP state and MPTCP listeners (the publicly demonstrated path)
#
# Usage (on the host, or via lab/setup.sh over SSH):
#   ./verify_kernel.sh
#
# Exit: 0 not affected, 1 affected, 2 unknown.
# For authorized security testing only.
set -u
CVE="CVE-2026-98432"
run=$(uname -r)
echo "[*] running kernel: $run"

fixed=""
if command -v rpm >/dev/null 2>&1 && { rpm -q "kernel-core-$run" >/dev/null 2>&1 || rpm -q "kernel-$run" >/dev/null 2>&1; }; then
  pkg=$(rpm -q "kernel-core-$run" 2>/dev/null || rpm -q "kernel-$run")
  rpm -q --changelog "$pkg" 2>/dev/null | grep -q "$CVE" && fixed=changelog
  newest=$(rpm -q --last kernel-core kernel 2>/dev/null | head -1 | awk '{print $1}')
  echo "[*] newest installed: ${newest:-?}"
  # RHEL fixed builds
  for f in 4.18.0-553.182.1.el8_10 5.14.0-687.64.1.el9_8 6.12.0-211.72.1.el10_2; do
    base=${f%%-*}
    if [[ $run == $base-* ]]; then
      lowest=$(printf '%s\n%s\n' "${run%.*}" "$f" | sort -V | head -1)
      [ "$lowest" = "$f" ] && fixed=${fixed:-version}
      echo "[*] RHEL fixed build for this stream: $f"
    fi
  done
elif [ -f "/usr/share/doc/linux-image-$run/changelog.Debian.gz" ]; then
  zgrep -q "$CVE" "/usr/share/doc/linux-image-$run/changelog.Debian.gz" && fixed=changelog
  newest=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's#/boot/vmlinuz-##' | sort -V | tail -1)
  echo "[*] newest installed: ${newest:-?}"
else
  echo "[?] no package changelog for the running kernel (custom kernel / container?)"
fi

if [ -n "${newest:-}" ] && [[ $newest != *"$run"* ]]; then
  echo "[!] reboot pending: running $run, newest installed $newest"
fi
if command -v canonical-livepatch >/dev/null 2>&1; then
  canonical-livepatch status 2>/dev/null | grep -q "$CVE" && fixed=${fixed:-livepatch}
fi

mptcp=$(sysctl -n net.mptcp.enabled 2>/dev/null || echo n/a)
listeners=$(ss -MlnH 2>/dev/null | wc -l)
echo "[*] net.mptcp.enabled=$mptcp  MPTCP listeners=$listeners"
echo "[*] TCP listeners on non-loopback addresses:"
ss -ltnH 2>/dev/null | awk '{print "      " $4}' | grep -vE '127\.0\.0\.|\[::1\]' | sort -u | head -20

if [ -n "$fixed" ]; then
  echo "[-] fix present ($fixed): NOT AFFECTED"
  exit 0
fi
if [ "$mptcp" = "0" ]; then
  echo "[~] no fix evidence, MPTCP disabled: HARDENING-RELEVANT (demonstrated path blocked, core UAF remains)"
  exit 2
fi
echo "[+] no fix evidence for $CVE in the running kernel: AFFECTED (confirm against the vendor advisory)"
exit 1
