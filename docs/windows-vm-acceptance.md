# Fresh x64 Windows VM acceptance — clean guest baseline verified

The user selected a new VM on the enrolled physical Windows PC instead of ARM
adaptation on the Mac. Existing host enrollment remains intact. Mac UTM/Kali was
only inspected; no new Mac VM or ARM code changes were made.

Read-only host inspection on 2026-09-19: i7-13620H (10 cores / 16 threads),
15.8 GiB RAM with 11.7 GiB free, D: 181.5 GiB free, C: 13.3 GiB free.
A hypervisor is active; VirtualMachinePlatform enabled, HypervisorPlatform disabled.
Before installation, no virtualization software found in the inspected HKLM uninstall records.

VMware's official download requires a Broadcom account. The user selected
VirtualBox instead. Created VM: x64 Windows, 4 vCPU, 6 GiB RAM, 80 GiB dynamic
disk on D:, NAT networking, no host directory shares. Retain current host security
settings; first assess operation with the existing hypervisor.

## Official media

Target directory: `D:\AgentRoad-VM-Test-20260919`.

- VirtualBox 7.2.18 build 175117 Windows installer, 178021472 bytes.
  SHA-256: `AAE27200546A21B9B7DC11CFC42BD04802329A29F69AE0ADA55682715A389D8D`.
  Downloaded and hash/signature verified by the Windows task.
- Windows 11 Enterprise 25H2 x64 English (US), Microsoft 90-day evaluation ISO.
  Source build: `26200.6584.250915-1905.25h2_ge_release_svc_refresh`.
  Expected size: 7092807680 bytes.
  Official SHA-256: `A61ADEAB895EF5A4DB436E0A7011C92A2FF17BB0357F58B13BBC4062E535E7B9`.
  Downloaded and independently hash verified; guest installation completed below.

Download job: `job_d5de29e603134dafaad9ca10701863d3`.
Initial capture: `agent-road-background-0sFV8w`.
Query this job after interruption; do not submit the same download job again.
Only files with verified hashes are renamed from `.partial`; receipts are in
`verified-downloads.json`. The download script never installs or reboots.

## Live results

- Download job SUCCEEDED, exit 0 at 2026-09-19T22:13:15Z; both hashes match.
- VirtualBox installed with ADDLOCAL=VBoxApplication and REBOOT=ReallySuppress.
  Version 7.2.18r175117; VBoxSup driver Running/System. No host reboot performed.
  The installer wrapper could not read ExitCode; independent version, registry,
  and driver checks establish installation. Do not repeat the installer.
- VM AgentRoad-Clean-Win11 registered as c941ee9f-e51e-4e8a-bf35-f721e9812d1d.
  4 vCPU, 6144 MiB, 80 GiB dynamic VDI, EFI/TPM 2.0, NAT, no shared folders,
  clipboard or drag-and-drop. VM files live under the target directory's VMs folder.
- Unattended preparation succeeded (exit 0), with Guest Additions selected.
  Generated credentials and answer files are in restricted private-install;
  never print or commit their contents.
- First headless start FAILED before guest installation. Job
  job_5af31346ad6b43808e2d932847fd92c4 is terminal FAILED, exit 1.
  VBoxHardening.log ends with Error -104 in supR3HardenedWinReSpawn,
  Error relaunching VirtualBox VM process: 5. Root cause is not established.
  No VBox.log was present in the inspected directory.
- Both terminal job definitions were subsequently removed; files and results retained.
- Private Mac evidence: ~/agent-road-private/windows-vm-20260919/.

## Startup investigation (2026-09-19, 22:25–22:38 UTC)

The guest remains uninstalled. No pairing attempt was made.

| Control | Observed result |
| --- | --- |
| Ordinary Agent Road exec instead of durable job | Same respawn failure |
| Logged-in desktop user, Interactive/Highest, headless | Same respawn failure |
| Host reboot after VirtualBox installation | SSH/Tailscale restored; startup still failed |
| Temporarily stop vgk through normal service control | Driver stopped; startup still failed |
| Also temporarily stop ACE-BOOT | Both drivers stopped; startup still failed |
| Second host reboot to restore original driver state | vgk and ACE-BOOT Running/System; SSH/Tailscale Running/Automatic |
| Direct VBoxHeadless scheduled action instead of VBoxManage startvm | Task exit 1; VM poweroff |

No driver startup setting, Defender setting, VBS setting or host firewall was
changed. The driver controls do not establish an anti-cheat cause or eliminate
all possible security interactions. Both reload checkpoints were performed after
three failed controls; subsequent tests used new evidence, not blind replay.

VirtualBox executables and VBoxSup.sys all report 7.2.18.175117 with Valid
Authenticode signatures. No matching VBox code-integrity block was returned in
the inspected event interval. Per-image IFEO keys only contained the observed
ImageExpansionMitigation=2; these were not edited.

Microsoft Process Monitor 4.11 (Valid Microsoft signature) captured one bounded
startup. Raw private Windows evidence is under:
`D:\AgentRoad-VM-Test-20260919\private-install\startup-trace`.
`startup.pml` is 156676805 bytes; exported `startup.csv` is 70933830 bytes.
Capture process exit was 1 despite producing readable evidence; CSV export exit
was 0. Do not describe the collector exit as a clean success. No collector was
left running at final inspection.

The filtered VBox rows have no ACCESS DENIED result. They show the second
VBoxHeadless child being created and exiting within about 2 ms (reported exit 0),
then the parent exiting 1. VBox's hardening log still reports CreateProcessW
failure with Win32 code 5. This narrows the stage, but does not identify the
failing API substep or root cause. File-permission and anti-cheat guesses are not
proven. Do not disable hardening or broad security controls to hide the failure.

Final live check: VM poweroff; no VBoxHeadless or Procmon process; the two temporary
VM launch task definitions removed; the two original terminal job definitions
removed. Installer, verified ISO, VM and private diagnostics retained. A second
VBox user registry exists in desktop-vbox-config for the same powered-off VM;
never start both registrations concurrently.

## Startup unblocked (2026-09-19, 22:46 UTC)

A broader running-driver inventory found MessageTransfer, a Valid-signed
PerfectWorld Ltd. Protection Kernel Driver 1.0.0.2 under the existing
perfectworldarena installation. Earlier vgk / ACE-BOOT controls had not stopped it.

A single-variable control stopped MessageTransfer through normal Stop-Service,
started the existing VM with VBoxManage, and restored MessageTransfer in finally.
VBoxManage returned 0 and VMState=running. Independent checks subsequently found
MessageTransfer Running/Automatic, vgk and ACE-BOOT Running/System, with the guest
still running and Windows Setup progressing through 10%, 26% and 55%.

This identifies an effective local startup workaround and strongly implicates
MessageTransfer in the observed conflict. It does not explain the kernel mechanism
or prove all versions of that driver conflict. No driver configuration was changed;
no VirtualBox downgrade, hardening patch or host reboot was needed for this control.
The pending cold-start workaround is operator-controlled: verify no game and VM
off, temporarily stop only MessageTransfer, start VM once, restore in finally and
verify driver/VM state. Do not turn it into an automatic generic enrollment step.

Private reproducible script and result: diagnosis/ar-vbox-mt-control.ps1 and
ar-vbox-mt-control.json under the private Mac evidence directory above.
Guest screenshot: guest-screen.png in that directory; do not mistake setup progress
for a completed guest or a passed pairing acceptance.

## Installation recovery (2026-09-19, 22:51–23:01 UTC)

Setup progressed to 55%, then produced a black framebuffer. VBoxHeadless CPU time
continued increasing while read/write counters stayed fixed across repeated samples;
Guest Additions were not yet available. A brief MessageTransfer stop/restore did
not recover this separate condition. Shift and the setup console shortcut did not
restore visible output. These observations do not establish the hang's root cause.

Saved the VM successfully, then took recovery snapshot
`Before-Setup-Resume-20260919` (`ab5c1f95-3f7d-47c7-894b-f09ad79e791b`). Host user
`HOST\example-user` was confirmed logged in. Resuming with the same startup workaround
succeeded and restored the driver, but the guest remained black. A controlled
reset of this disposable guest, with the snapshot retained, restored Windows boot
and then the next setup phase displayed Installing 42%. No host restart, disk
reformat, VM recreation or fresh unattended preparation was performed in this turn.

## Clean guest verified (2026-09-19, 23:12–23:13 UTC)

A second setup-stage stall was recovered with a guest-only reset after confirming
fixed disk I/O counters. Setup then reached 94%, completed first-login preparation,
and displayed the Windows desktop. Guest Additions 7.2.18 r175117 reached run level 3.
The repeated setup stalls remain an unresolved VM stability limitation, not a
proven MessageTransfer runtime mechanism.

The first guestcontrol attempts reported execution service not ready. A long GUI
keyboard command timed out before submission; screenshot reconciliation showed
partial input in Run and no residual VBoxManage process. Short input also did not
change the framebuffer. No partial command was replayed as a bootstrap.
A complete guest reboot with MessageTransfer temporarily stopped allowed guestcontrol
to execute the baseline. MessageTransfer was restored immediately afterward; a
second independent guestcontrol baseline succeeded with the driver running.
This control combines a reboot and a driver-state change, so it cannot isolate
which resolved guestcontrol readiness.

Both baseline executions returned guest exit 0 and:

- Hostname ROAD-CLEAN; user RoadTest.
- Microsoft Windows 11 Enterprise Evaluation, version 10.0.26200.
- PowerShell 5.1.26100.6584; ordinary guestcontrol token not elevated.
- Agent Road directory absent; Tailscale service absent; sshd service absent.

Module-initialization progress CLIXML was preserved separately from the baseline
JSON; this was not a production enrollment-verifier pass. Password stayed in the
private host password file. Pairing has not been attempted.

Final state: VM saved, with clean snapshot Clean-Before-Pairing-20260920
(UUID d162be13-9b84-4a7c-9e8a-a55fa750a598). All three host protection drivers
and sshd/Tailscale verified running; startup configurations unchanged.
The older installer-recovery snapshot is also retained.

## Public-command injection blocked by host Defender (2026-09-19, 23:20–23:24 UTC)

Resume from the clean saved state succeeded with the bounded MessageTransfer
startup workaround; the driver was restored. Fresh guestcontrol baseline again
returned exit 0 with Agent Road, Tailscale and sshd absent. The guest administrator
PowerShell was opened through the visible UAC consent dialog.

Two attempts to launch VBoxManage keyboardputstring with the public download-and-
execute command were denied on the host before the string was entered. Host
Defender events 1116/1117 identify the VBoxManage command line and detection
Trojan:Win32/Commando.A!ml (security intelligence 1.459.293.0). Screenshot after the
first denial shows an empty elevated PowerShell prompt. This is a separate
observed blocker from the MessageTransfer VM-start issue. It does not establish
that manual execution inside the guest is blocked, or that the detection is a
confirmed false positive. No attempt was made to bypass this detection.

The public loader downloaded with curl on Mac matches repository source exactly
with the configured public origin: SHA256
7829adcccf9863b4623644324d5c30185b81c2a6e8df7dd74b6d5c28d26cdd39 (3039 bytes).
A Python urllib request returned HTTP 403, whereas curl succeeded; client-dependent
front-door behavior remains a separate observation. On the host, Invoke-WebRequest
downloaded the same hash and Start-MpScan completed successfully with the file
remaining present. This file-only scan does not clear the command-line detection
or validate the full bootstrap chain. Defender real-time protection remained on;
no exclusions or protection changes were made. All five checked host services /
drivers (MessageTransfer, vgk, ACE-BOOT, sshd, Tailscale) remained running.

The VM was saved successfully after investigation; the clean pre-pair snapshot is
retained unchanged. The controller pair command was not started: no pairing key, claim, or new device
was created. Private evidence is under
/Users/example/agent-road-private/windows-vm-20260919/diagnosis/ (Defender events and
scan receipt); screenshots are one directory above. Source files contain no secrets.

Microsoft recommends submitting suspected false positives for analysis:
[Defender false-positive guidance](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-false-positives-negatives).
No external submission was made. Resolve the detected distribution / automation
path without disabling protection before claiming short-command acceptance.

## Next gates

1. Resume the clean pre-pairing snapshot with the bounded startup workaround.
2. Resolve the host Defender command-line detection; preserve the current no-bypass boundary.
3. Run pairing; verify SSH, transfers, core and reboot recovery on the new device.
4. Same-host NAT proves a fresh OS join, not arbitrary cross-network reliability.
5. Preserve install-stall limitations; do not claim reliable VM restart yet.

Sources: [Oracle checksums](https://download.virtualbox.org/virtualbox/7.2.18/SHA256SUMS),
[Oracle installation guide](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/installation.html),
[Microsoft evaluation downloads and verification](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise).
