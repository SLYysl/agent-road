# Native setup development preview

Development-only, unsigned x64 .NET Framework executable. The candidate now includes
fixed OpenSSH/Tailscale prerequisite installation and a data-only v2 pairing client.
Complete native onboarding remains under VM acceptance. Do not publish as a release.

Build using 64-bit Windows PowerShell 5.1: `Build.ps1 -OutputDirectory C:\YourNewBuildDirectory`.
From an elevated terminal, `AgentRoadNativeSetup.exe --inspect` checks capability
state and pending reboot. Installation requires both explicit arguments:
`AgentRoadNativeSetup.exe --install-openssh --accept-system-changes`.
It never elevates itself, restarts Windows or invokes PowerShell.

The fresh-machine path refuses existing SSH services/nonempty data, a port-22 listener,
pre-existing named firewall rules, pending reboot or an earlier attempt journal.
A plain existing empty SSH directory is accepted; its original ACL/owner/group
are recorded and checked after installation, without deleting the directory.
It creates an administrator/SYSTEM-only journal and an inbound TCP-22 block before
calling Windows DISM with fixed capability arguments and `/NoRestart`.
Windows Update may supply the feature. An already installed capability is reported
as present without claiming its SSH configuration is safe or ready.

Exit 0 means only that the capability was present or installation was verified;
exit 3 means DISM requires reboot; exit 2 means stopped/failed/uncertain.
Read-only DISM queries wait up to three minutes and report elapsed time and exit
code; installation waits up to twenty minutes. A timeout never kills or repeats
the servicing operation. The blocking firewall
rule and journal remain, including after failure, for inspection. No automatic
uninstall, rollback or retry is implemented. Preserve Windows DISM/CBS logs.

Journal: `%ProgramData%\AgentRoadNativeSetupPreview\journal.jsonl`.
Firewall rule: `AgentRoad-Native-Preview-Block-SSH`. Do not remove it until the
later tailnet-scoped SSH configuration is independently verified.
The OpenSSH prerequisite command creates no account, SSH key or Tailscale login,
and does not start SSH or claim remote readiness.
This stage is deliberately separate from the previous blocked bootstrap payload.

Validation on 2026-09-22: Windows compilation, four parser and two directory
self-checks passed. Non-admin inspect/install and missing-consent refusal checks
passed. After one retained-VM reboot cleared pending rename operations, elevated
installation completed with DISM exit 0 in approximately 11 minutes. Independent
inspection returned Installed with no pending reboot; sshd remained stopped,
TCP22 had no listener and the inbound block was active. Original SSH directory
ACL was unchanged, journal access was SYSTEM/Administrators only, Defender stayed
enabled and PowerShell policy remained Restricted. Repeated installation stopped
with PRIOR_ATTEMPT_REQUIRES_INSPECTION and did not replay DISM.
See `experiments/claude-onboarding/native-openssh-acceptance.json` for evidence.
DISM failure, 20-minute timeout, 3010 and live reparse-point branches remain
untested. This is not full native pairing acceptance or a signed installer release.

`AcceptNonAdmin.ps1` reproduces the refusal checks from a non-elevated test session;
it requires an explicit executable and a new output directory. It is a development
test harness, not an end-user entry point; do not lower script policy to run it.

Microsoft references:
- [DISM capability servicing](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-capabilities-package-servicing-command-line-options?view=windows-11)
- [DISM global options](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-global-options-for-command-line-syntax?view=windows-11)
- [OpenSSH setup and service start](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)

## Native pairing candidate

Commands require an elevated terminal; the executable never elevates or reboots itself.

SSH boot testing found an early tailnet-address bind failure despite the Tailscale
service dependency; existing SCM recovery restarted sshd successfully. Delayed
auto-start was tested on the same guest and avoided bind errors in two boots, but
added substantial waiting and did not resolve slow shutdown. It was not adopted
as the native default. Keep automatic startup, recovery and the scoped listener.
See `experiments/vm-recovery-20260923/sshd-delayed-start-retest.json`.

- `--install-tailscale --accept-system-changes`: download the pinned official 1.98.9
  installer, verify SHA-256 and trusted Tailscale publisher, then install without reboot.
- `--resume-tailscale-download --accept-system-changes`: explicit recovery only when
  the protected prerequisite directory contains exactly its valid DOWNLOAD_INTENT
  receipt. Refuses a downloaded payload, installation intent or other retained files;
  it never repeats an uncertain installation or removes earlier evidence.
- `--native-preflight`: read-only readiness check for a fresh Windows 11 AMD64 target.
- `--retain-unconfigured-attempt --accept-system-changes`: only after cancelling the
  old controller invitation, retain a stopped attempt under a unique sibling directory.
  Requires only a valid pre-configuration journal, no other state, and unchanged fresh
  system prerequisites. Refuses any attempt that may have received configuration.
- `--retain-unjoined-attempt --accept-system-changes`: after the original controller
  has stopped and its invitation is cancelled or consumed, retain a failed network-join
  attempt without deleting credentials or logs. Requires exactly the protected journal
  and auth-key file, no post-join checkpoint, all fresh-system checks and two NeedsLogin
  observations. Any joined identity or account/configuration prevents recovery.
- `--pair <12-character-code> --accept-system-changes`: after preflight and interactive
  YES, claim a v2 invitation, show the verification code, and receive typed configuration.
- `--native-inspect`: read-only retained phase/service/reboot report.

The controller candidate requires `AGENT_ROAD_NATIVE_PREVIEW=1 agent-road pair
--native-preview`. This is a development opt-in, not the public package default.
Before claiming, the client checks its clock against the fixed HTTPS site Date header
and refuses skew over five minutes without creating a journal. For tolerated skew,
claim expiry uses the authenticated HTTPS claim response Date plus a monotonic timer;
second precision and request latency are rounded forward, never extending server TTL.
The invitation and configuration are one-use; the controller must approve the displayed
verification code. The target accepts no fetched shell script or arbitrary command.

Pairing joins the approved tailnet, creates an administrator AgentRoad account with
random undisclosed password, installs the exchanged public key, and creates a private
host key/configuration. Password SSH is disabled. SSH listens only on the Tailscale IPv4;
firewall rules block other source ranges. SSH depends on the Tailscale service and
uses service restart recovery, including non-crash failures; reboot recovery must
still be verified against the actual tunnel-address readiness. The prerequisite block is removed only after
scoped listener and rule readback. Controller host-key verification and a real remote
command are still required before calling the device usable.

Native enrollment journal: `%ProgramData%\AgentRoad\bootstrap-native\journal.jsonl`.
Tailscale prerequisite receipts: `%ProgramData%\AgentRoadNativeTailscalePrerequisite`.
These paths are administrator/SYSTEM-only. Preserve them after failure; do not delete
state to force a fresh attempt. Timeouts and uncertain requests are never auto-replayed.
Error output contains finite state, exception type and HRESULT, not raw error bodies.

The 2026-09-22 VM trial reproduced a legacy .NET TLS bug: SecurityProtocol must be set
before constructing HttpWebRequest. After that fix, the guarded download-only resume
verified and installed Tailscale with exit 0. Pending reboot was then detected; exit 3
now reports that condition directly even if the underlying installer returned 0.
This prerequisite result does not establish complete v2 pairing or core acceptance.

Controller trial note: an isolated test state retained a previously used single-use
Tailscale key file. Native joining returned exit 1 and remained NeedsLogin. For repeated
trials, configure the existing API-token file so each pair creates its own short-lived
single-use key; never reuse old trial key files. Both credentials remain local/private.

Windows Firewall VM probe: setting RemoteAddresses accepted `::/0`, but Rules.Add
rejected it with E_INVALIDARG. An equivalent explicit full IPv6 range was accepted;
the candidate uses that range alongside the two IPv4 ranges outside 100.64.0.0/10.
The diagnostic rules were disabled and removed after the probe; the original SSH
block was retained. Native sshd configuration validation passed before this failure.
