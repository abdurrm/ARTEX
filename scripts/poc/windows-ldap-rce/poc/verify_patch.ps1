<#
CVE-2026-119958 - Local patch check for Windows LDAP (run on the DC / server).

Demonstrates:
  1. OS build + UBR vs the November 2026 (2026-11-10) cumulative update UBR
     you pass with -MinUBR (from the MSRC / KB page for this OS build)
  2. pending reboot (update installed but not active)
  3. whether this host serves LDAP (AD DS / AD LDS)

Usage:  powershell -ExecutionPolicy Bypass -File verify_patch.ps1 -MinUBR 1234
Exit:   0 not affected, 1 affected, 2 unknown.
For authorized security testing only.
#>
param([int]$MinUBR = 0)
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = "$($cv.CurrentBuild).$($cv.UBR)"
Write-Output "[*] $($cv.ProductName) build $build"
$pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
           (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
Write-Output "[*] reboot pending: $pending"
$ldap = @(Get-Service NTDS, 'ADAM_*' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')
Write-Output "[*] LDAP services running: $(($ldap | ForEach-Object Name) -join ', ')"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3 | ForEach-Object { Write-Output "    $($_.HotFixID) $($_.InstalledOn)" }
if ($MinUBR -le 0) { Write-Output "[?] Pass -MinUBR from the November 2026 KB for build $($cv.CurrentBuild). UNKNOWN"; exit 2 }
if ($cv.UBR -ge $MinUBR -and -not $pending) { Write-Output "[-] November 2026 update active: NOT AFFECTED"; exit 0 }
if ($cv.UBR -ge $MinUBR -and $pending) { Write-Output "[+] Update installed but reboot pending: still AFFECTED"; exit 1 }
Write-Output "[+] UBR $($cv.UBR) below $MinUBR: AFFECTED (CVE-2026-119958)"; exit 1
