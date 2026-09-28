# Windows installation delivery: release requirements

Status (2026-09-23): an unsigned native development installer has been built and
completed pairing, SSH and core preparation on one fresh Windows VM. It is not
signed or publicly released; real-hardware first onboarding and graceful reboot
recovery remain unaccepted. Ordinary public pairing still uses protocol v1; native
v2 requires the explicit private-test preview route. See the development acceptance
section below and onboarding-status.json. Do not treat a signature check as Defender approval.

## Historical offline prototype (no certificate required)

`src/installer/preview.mjs` implements an experimental, local-only data contract.
It is not accepted by the pairing service or Windows installer. Exact fields are
schemaVersion=1, purpose=agent-road-offline-preview, a 32-character lowercase hex
requestId, HTTPS origin, integer createdAt/expiresAt in Unix milliseconds, and
profile=core. The lifetime is at most ten minutes. The caller must supply the
expected origin separately; a matching string is not server authentication.
Commands, credentials, executable URLs, paths and unknown fields are rejected.

`previewInstaller` produces a canonical configuration digest and a fixed phase
list, always executable=false and authorized=false. `simulateInstaller` consumes
synthetic PASS/FAIL/UNKNOWN outcomes. UNKNOWN stops at reconciliation; FAIL stops
before later phases. Even an all-pass run produces SIMULATED_COMPLETE, never
runtime READY. These receipts have no authority in the real runtime.

Run from the checkout with a synthetic configuration (do not use real secrets):

```sh
node --input-type=module <<'JS'
import { previewInstaller, simulateInstaller } from './src/installer/preview.mjs';
const now = Date.now();
const plan = previewInstaller(JSON.stringify({schemaVersion:1,
  purpose:'agent-road-offline-preview', requestId:'a'.repeat(32),
  origin:'https://pair.example', createdAt:now, expiresAt:now+600000,
  profile:'core'}), {expectedOrigin:'https://pair.example', now});
console.log(JSON.stringify({plan, simulation:simulateInstaller(plan)}, null, 2));
JS
```

For a local JSON file, use `node tools/installer-preview.mjs /absolute/input.json
https://pair.example`. The tool refuses symlink inputs and files over 4 KiB, prints
finite errors and performs no network, shell, installation or registry actions.
The tool belongs to the development checkout; it is not a new production CLI route.
No certificate is required to test this offline contract. The offline prototype itself does not perform native setup or signed distribution.
Later native implementation, v2 service integration and development acceptance are
recorded below; they do not open the public installer release gate.

## Proposed user flow

The existing agent creates one invitation. The Windows owner downloads a versioned
installer, checks its publisher, launches it and enters the short pairing code.
The code remains short; it locates consent, not a command or network credential.
Both owners still compare the verification code. The installer handles a fixed,
reviewed set of setup actions and displays progress and a diagnostic result.

Separate the static executable from per-device configuration. Configuration is
validated data, not a shell command. No compressed script evaluation or downloaded
arbitrary-command execution belongs in the new installer. A versioned protocol
must reject unsupported controllers; never silently fall back to the old execution
path. Preserve existing host-key verification, signed bootstrap checks, bounded
network requests, single-use secrets and immutable recovery evidence.

This is a protocol/installer migration, not a change to the current loader designed
to evade a detection. The security product remains enabled. Vendor review and a
new clean-VM acceptance are required before claiming the detection is resolved.

## Concrete release gate

`windows/verify-installer.ps1` checks a local artifact without executing it. Provide
the SHA-256 of the final signed bytes and the expected publisher certificate
thumbprint from a separately reviewed release record, not from the downloaded file
itself. It requires a Windows-trusted valid Authenticode signature as well as both
pins. Unsigned, untrusted, mismatched or unreadable artifacts fail with exit 2.

```powershell
.\verify-installer.ps1 -Path C:\Downloads\AgentRoad-Setup.exe `
  -ExpectedSha256 <reviewed-final-file-sha256> `
  -ExpectedSignerThumbprint <reviewed-publisher-thumbprint>
```

Do not import a self-signed certificate into users' trust stores to satisfy this
gate. Signing requires the owner's real signing resources. Preserve version, source
revision, final file hash, signer, timestamp, verification result and build inputs.
A publisher rotation needs a reviewed pin update. A separate download verifier is
not a TOCTOU-safe launch boundary; the eventual installer/launcher must bind
verification to the bytes actually executed. This tool does not install anything.

## Failure evidence and acceptance

Current controller builds observe retrieval for up to 120 seconds after approval.
`delivery-observation.json` reports DELIVERED (executionConfirmed=false),
DELIVERY_UNCONFIRMED or OBSERVATION_STOPPED. An in-flight HTTP request can take up
to its existing 20-second deadline beyond the observation window. Observation
failure never cancels a possibly running installer or starts another invitation.
The enrollment timeout is still independent. Older services need no new endpoint.

For a stopped attempt retain finite Defender event ID, detection name/action,
security-intelligence version and guest/controller clock samples. Do not export
event command lines, tokens, private configuration or credentials in a vendor
submission. Review the exact artifacts first; a redacted reproduction is not
byte-identical evidence and must be labelled accordingly.

Accept the replacement only after a fresh VM, unchanged protection settings, one
invitation, visible consent, pinned SSH identity, core readiness and a real remote
command succeed. Test revoked/expired/wrong-owner codes, interrupted downloads,
signature/hash/publisher mismatches, and lost acknowledgements without replay.
Keep candidate and production results separate.

Microsoft references:
- [Developer FAQ and false-positive review](https://learn.microsoft.com/en-us/defender-xdr/developer-faq)
- [Official file submission](https://www.microsoft.com/en-us/wdsi/filesubmission)
- [Code signing and publisher identity](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-code-signing-for-better-control-and-protection)

## Installable local diagnostics preview

`tools/diagnostics-app/` now contains a .NET Framework WinForms diagnostic program,
a compiler script, a per-user install/uninstall script and Windows lifecycle
acceptance. This application performs only local read-only checks; it does not
contain the previous bootstrap and is not an onboarding replacement. The package
is unsigned. Its hash manifest is integrity metadata, not publisher verification.

On 2026-09-22, Windows compilation and six lifecycle checks passed: install, reject
a second install, export a report, refuse report overwrite, preserve unexpected
files during uninstall, and uninstall owned files while retaining the report.
Those initial checks used the PowerShell installation helper on the physical host.

The retained VM then rejected that helper under its effective `Restricted`
PowerShell policy. Native **Install for me** / **Uninstall** actions now perform
the diagnostic application's own per-user lifecycle without invoking PowerShell.
The original helper remains for development; the EXE is the default user entry.

Seven native lifecycle cases passed on both the physical host and retained VM:
install, duplicate refusal, report creation, report overwrite refusal, extra-file
preservation, changed-binary preservation, and uninstall with reports retained.
Real VM GUI checks also passed: open the app, run local checks, save through the
Save As dialog, confirm installation, then confirm removal. The VM remained under
`Restricted`; Defender antivirus and realtime protection remained enabled.
The report contained three historical Defender events, not a new detection claim.

The v3 ZIP contains only the EXE, helper, README and integrity manifest. It was
transferred through the existing host/VirtualBox channel; browser download,
Mark-of-the-Web and SmartScreen acceptance were not tested. This is a retained VM,
not a fresh-machine onboarding acceptance. The app has no Start menu shortcut or
Installed Apps registration; removal uses the original portable package.
Evidence: `experiments/claude-onboarding/diagnostics-vm-acceptance.json`.
See the application README for build and usage instructions.


## Candidate native pairing v2 (development opt-in)

The service accepts `/v2/create|claim|status|approve|receive|cancel` only when
`PAIR_NATIVE_V2_ENABLED=true`. The production Worker flag and exact `/v2` site
rewrites were enabled on 2026-09-22 for owner-authorized native VM trials. The
ordinary `pair` CLI and Windows loader continue to use v1. `pairRequest` supports
an explicit `protocolVersion: 2`; unsupported versions fail without fallback.
Both versions share invitation capacity, rate limits, serialized storage and
account-session revocation checks. An invitation's version is fixed at creation;
cross-version operations cannot approve, cancel or consume it.

V2 approval takes `configuration`, never `command`. The exact contract is:
- `schemaVersion: 2`, `kind: agent-road-native-enrollment`;
- `pairingOrigin` equal to the service's configured HTTPS origin;
- `deviceId` with a 32-character lowercase hexadecimal suffix;
- canonical HTTPS `controllerBaseUrl` under `.ts.net`, with the exact device path;
- `enrollmentToken` and single-use `tailscaleAuthKey` (credentials, never log them);
- integer `expiresAt`, in the future and no later than the invitation's expiry.

Unknown fields, arbitrary execution/download paths and API tokens are refused.
Configuration is validated before encryption and again before delivery. The stored
envelope is AES-GCM encrypted with v2-specific associated data binding it to the
invitation, owner and claimant. Consumption is persisted before a response leaves
the service. A lost response must be reconciled; it must not trigger another setup.
`DELIVERED` proves only configuration retrieval, not consent to local privileged
changes, installation, SSH verification or core readiness.

On 2026-09-22, 64 pairing/auth regression cases passed; both opt-in workerd tests
were then enabled and passed separately. Real local Durable Object tests confirmed
that competing claims produce one winner, competing receives release once, v1
cannot receive v2 configuration, and the existing v1 flow still works. All were
fixture credentials on localhost; there was no public service deployment or
Windows installation in this phase. To repeat, add
`--var PAIR_NATIVE_V2_ENABLED:true` to the local command in `docs/short-pairing.md`,
then run `AGENT_ROAD_PAIR_NATIVE_LOCAL_TEST=1 AGENT_ROAD_PAIR_LOCAL_TEST=1 node --test
test/pairing-native-worker-local.test.mjs test/pairing-worker-local.test.mjs`.

The development candidate now implements native consent, a bounded HTTPS client,
fixed local operations and a protected journal, the data-only receiver, and opt-in
controller integration. It does not fetch/evaluate the previous stage-one script.
Signed distribution and complete fresh Windows acceptance remain outstanding.
Enabling the v2 service alone does not resolve the previous Defender detection.


## Native OpenSSH prerequisite preview

`tools/native-setup/` contains an unsigned x64 native development program for one
fixed capability step, separate from both the diagnostic app and v2 delivery.
It requires elevation and explicit installation arguments. The fresh-machine
path records intent, adds and verifies an inbound TCP-22 block, invokes Windows
DISM with fixed OpenSSH capability arguments and `/NoRestart`, and records a finite
outcome. It never starts sshd or marks remote access ready. Any prior journal stops
re-execution; failure/timeout retains the block and evidence for inspection.

Windows compilation, parser self-checks and non-elevated VM refusal were observed.
Privileged DISM/firewall/reboot cases remain unaccepted: the inspection UAC prompt
expired during intermittent remote transfer failures, and subsequent attempts
failed to establish a connection. No install command was issued to the VM. The
implementation must not be presented as an accepted installer or combined with
real pairing credentials yet. See `experiments/claude-onboarding/native-openssh-preview.json`
and the tool README for the exact current boundary.


### Prerequisite timing before native pairing

The retained-VM trial observed Windows Update downloading 247,073,875 bytes while
DISM prepared OpenSSH; Windows Update also reported a system security update.
Do not assume this step is just a small SSH binary download, or attribute all
servicing latency to the network. The native flow should prepare OS capabilities
under local owner consent before starting the ten-minute invitation/configuration
lifetime. Keep the SSH listener stopped and its port blocked until the later
verified configuration is complete. Show bounded progress/waiting states and retain
the same attempt on lost observations; never restart setup solely because a
controller response was lost. This sequencing is a design requirement, not an
already deployed change to the v1 user flow.

### Subsequent retained-VM acceptance (2026-09-22)

The earlier pending administrator acceptance above is superseded for this one
prerequisite by `experiments/claude-onboarding/native-openssh-acceptance.json`.
Native v3 installed OpenSSH successfully (DISM exit 0), with independent Installed
readback and no pending reboot. sshd stayed stopped, TCP22 remained blocked with
no listener, original empty-directory ACL was preserved, and Defender remained on.
A repeated install was refused using the retained journal. The trial exposed a
read-only query timeout and an overly broad empty-directory refusal; query waits
now allow three minutes with elapsed/exit diagnostics, and plain empty directories
are accepted with recorded and verified ACLs. The original timeout cause is not
proven. Full native pairing, scoped SSH configuration and fresh-VM acceptance
remain future work; no production flow was changed.

### Data-only enrollment receiver candidate (2026-09-22)

`startEnrollmentReceiver({protocolVersion: 2, ...})` now exchanges a one-use token
for exactly protocolVersion, deviceId, sshPublicKey and completionTicket. It refuses
signer/stageOneBytes options and never signs or returns bootstrap code. Version 1
remains the default. Requests and completion acknowledgements must match the selected
wire version; verified internal completion snapshots retain the existing v1 shape
for registry/SSH verifier compatibility. Wrong-version requests cannot consume tokens.

34 receiver cases and 50 pairing/native/enrollment regressions passed locally. This
receiver was initially tested without online enrollment. The subsequent development
controller selects it only with `AGENT_ROAD_NATIVE_PREVIEW=1` and `pair --native-preview`;
the public package default remains v1. The native Windows client now invokes it.
Full fresh end-to-end acceptance remains required, and the website release gate
must not advertise a released native installer.


### Native integration trial in progress (2026-09-22)

The retained VM completed native Tailscale joining and the data-only exchange,
created its local account and SSH keys, and passed `sshd -t`. It stopped while
adding the scoped firewall rule: Windows accepted assigning `::/0` but rejected
`Rules.Add` with E_INVALIDARG. A disabled-rule probe verified that an explicit
full IPv6 range is accepted. The candidate now uses that form with equivalent
readback normalization. sshd remained stopped with no TCP-22 listener, and the
original inbound block and all partial enrollment evidence were preserved.
This was not a completed SSH connection.

Other observed fixes cover .NET TLS configuration before request construction,
a tolerated VM clock offset using the authenticated server Date and a monotonic
timer, capping configuration expiry at the invitation expiry, and replacing an
exhausted trial key with fresh per-pair keys from the existing private API
configuration. No credential material belongs in this document or distribution.

A fresh linked VM was created from the pre-pairing Windows snapshot, with no
Agent Road, Tailscale or sshd service confirmed before installation. Native build
10 compiled and passed its self-tests and core binding JSON round-trip check.
The fresh VM subsequently completed OpenSSH/Tailscale preparation, native pairing,
pinned SSH verification and automatic core preparation with pair exit 0. A real
remote command and a 71-byte Chinese/emoji file roundtrip passed. Defender remained
enabled and the listener/firewall readback was tailnet-scoped. The first recovery
reboot did not return within the observation window; guest-control and graphics
stopped during shutdown. A retained snapshot and external VM reset restored Windows.
The original SSH identity, core generation and transferred file were verified after
reset. SCM event 7031 confirmed the configured 5-second sshd restart action on boot.
Windows recorded a slow shutdown, but its root cause remains unproven. This does
not pass graceful reboot recovery or establish that SSH caused the shutdown stall.
Independent Claude acceptance then passed real commands, a Chinese/emoji file
roundtrip and one durable job with retrieved logs on the enrolled VM. This was
not a second fresh onboarding. Claude also exposed a job-status completion race;
a deterministic Windows regression failed before the fix and passed after
re-reading terminal state when the scheduler becomes inactive. See
`experiments/claude-onboarding/native-integration-acceptance.json`.
The executable is unsigned and unpublished; local owner-authorized testing does
not establish trusted public download or SmartScreen acceptance.
