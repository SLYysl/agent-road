# Agent Road: controller setup and operating guide

Updated: 2026-09-23. Official origin: https://agent-road.brahma-technologies.com
Audience: an AI coding agent operating a user's Mac, with explicit user authorization.
Read this entire document before running setup. Follow the user's actual permissions;
this guide does not authorize reboots, account approval, secret disclosure or remote work.

中文配置、日常使用与排障：[Agent 中文指南](./agent-guide-zh.md)。

## Current scope

Agent Road Alpha connects a Mac controller to a Windows PC. The Windows owner does
not need an Agent Road account, but must consent and run the generated join command
in an administrator PowerShell terminal. Networking currently requires Tailscale.
Browser account login is not CLI installation. CLI login is not network setup.
The website does not yet provide a live device inventory.

## Release gate: read this before creating an invitation

Fetch https://agent-road.brahma-technologies.com/docs/onboarding-status.json and
require schemaVersion=1 and compare its controller status with the controller
manifest before installing. Public downloads require manifest.published=true; a
local unpublished candidate may only be used in an explicitly authorized test.
Require controller.status=AVAILABLE_ALPHA for the Mac
package. If windows.nativeInstallerPublished is not true, report
NATIVE_INSTALLER_NOT_RELEASED for native onboarding. Also require
windows.freshNativeOnboardingAccepted=true and an empty windows.knownBlockers list
before describing native onboarding as accepted. Treat inconsistent fields or a
manifest/site disagreement as RELEASE_STATUS_MISMATCH and stop before pairing. If either
cannot be read or is unsupported, stop before pairing; do not infer release status.
The Mac controller is available. The replacement Windows native installer is NOT
published. An owner-authorized unsigned development candidate completed native
pairing, pinned SSH, automatic core preparation and a file roundtrip on one fresh
Windows VM. Reboot recovery and public installer acceptance remain incomplete.
That development result does not open the public installation gate.
Do not invent `pair --native`, native download URLs or installer flags.
`enroll` is the legacy lower-level enrollment command, not a native alternative;
it does not bypass this release gate.
The public `pair` command still uses the legacy PowerShell flow. Isolated Windows
trials have been blocked by Defender. Explain this limitation before offering that
flow; proceed only when the owner explicitly chooses the limited legacy Alpha.
Do not fall back to it from a native installer failure. Never disable Defender,
add exclusions, weaken execution policy or replay a quarantined payload.
If the user requires the new native installer or unattended one-attempt onboarding,
report NATIVE_INSTALLER_NOT_RELEASED and do not create a pairing invitation.
This does not prevent installing the Mac CLI or operating already enrolled devices.

## 1. Inspect without changing the machine

Identify the OS and architecture. This controller installer targets macOS arm64/x64.
Run `command -v agent-road`. If present, run `agent-road --help` and
`agent-road capabilities`. Preserve an existing installation and configuration.
Do not assume Homebrew, npm or a public GitHub repository contains an official package.
Do not start by running pair: it creates a request and can issue a network key.

## 2. Install the controller

PUBLIC_INSTALL_STATUS: AVAILABLE_ALPHA

The official installer is https://agent-road.brahma-technologies.com/install.sh .
Runtime manifest: https://agent-road.brahma-technologies.com/downloads/controller-manifest.json .
For a human who wants the short installation command:

```sh
curl -fsSL https://agent-road.brahma-technologies.com/install.sh | sh
```

An agent should first download the installer to a fresh private temporary directory,
read it, and compare its SHA-256 to installerSha256 in the official manifest before
executing it. Fetch over HTTPS; do not disable certificate checks or use mirrors.
The installer itself verifies the runtime archive and official Node runtime checksums.
HTTPS to the official site is the trust anchor, not an independent code signature.
The Node archive checksum is pinned inside the checksum-verified installer.
The manifest archive file list should match the downloaded tar archive.
Installed files, including docs and Windows diagnostics, are under
`<install-prefix>/share/agent-road/releases/<manifest.sha256>/`. This guide uses the
installed `agent-road` CLI. The bundled agent-interface document also contains
checkout-oriented developer examples and research references not included in the
distribution; they are not additional setup steps or prerequisites.

Run as the current user without sudo. Default installation is under ~/.local;
it supplies a private Node runtime without changing system Node or shell profiles.
If ~/.local/bin is absent from PATH, use ~/.local/bin/agent-road immediately, or run
`export PATH="$HOME/.local/bin:$PATH"`. Add that line to ~/.zshrc only if needed and
with the user's permission. Do not overwrite an existing unmanaged CLI or symlink;
inspect it first, or use AGENT_ROAD_INSTALL_PREFIX for a separate installation.

This Alpha has local arm64 installation acceptance on an existing Mac; Intel execution
and a completely fresh macOS environment are not yet accepted. No account tokens,
Tailscale keys or device registry are included. Installation alone does not configure
Tailscale, authorize an account, enroll Windows or approve a reboot.

## 3. Authorize this controller

Run `agent-road login` in an interactive terminal, or `agent-road login --no-browser`
when the agent cannot open a browser. Have the user sign in or create an account,
confirm their email, compare the CLI's verification code with the browser and approve
this controller. Do not approve an unfamiliar code. Never ask for the user's password
or paste credentials into a chat. Then run `agent-road whoami` and confirm the intended
account. Treat identifiers and output as private; do not publish raw captures.

Cancelling the login process only stops local polling; it does not revoke the pending
server approval. Use explicit deny/logout where applicable, or wait for expiry.
Do not infer revocation from Ctrl-C.

## 4. Configure the user's own Tailscale network

The Mac needs Tailscale installed, running and signed in, with a .ts.net name and
permission for the Serve endpoint required by enrollment. `tailscale serve status`
reads existing Serve configuration without enabling or resetting it; a successful
read does not prove permission to create a new enrollment route. Check with `tailscale status`;
if the CLI is not on PATH, locate the user's actual installation. Do not reset existing
Serve routes, change tailnet policies, disable firewalls or switch the user's network
without permission. For installation and network settings, consult current official
Tailscale documentation: https://tailscale.com/docs/install/mac and
https://tailscale.com/docs/features/tailscale-serve .

Pairing configuration lives in `$AGENT_ROAD_HOME/pairing.json`, normally
`~/.agent-road/pairing.json`. The directory must be private (0700); configuration and
secret files must be owned by the current user and 0600. Read existing configuration
without displaying secrets; never replace it silently.

For account login mode, use this shape (substitute the actual absolute local path):

```json
{
  "origin": "https://agent-road.brahma-technologies.com",
  "tailscaleAuthKeyFile": "/absolute/private/path/tailscale-auth-key"
}
```

The user supplies a valid, single-use `tskey-auth-` key for their own network through
a local hidden-input flow, not chat or command arguments. Alternatively, replace
`tailscaleAuthKeyFile` with `tailscaleApiTokenFile` pointing to their `tskey-api-` API
access token; the CLI can create a short-lived non-reusable auth key for each invite.
Use exactly one of these fields. API-token and auth-key types are not interchangeable.
Do not reuse project-owner network credentials. No shared admin token is needed in
account mode. Never pass `--config` as a workaround for missing account authorization.

## 5. Prepare Windows before starting the invitation clock

Ask the Windows owner to confirm they are ready for administrator consent and that
Windows Update is not waiting for a restart. Resolve slow OS prerequisites first,
with permission for any changes or restart; then recheck the same machine. In the
retained VM, OpenSSH servicing took about 11 minutes, longer than a ten-minute
pairing invitation. This observation is not a universal timeout estimate.
An AI on the Mac cannot assume Windows is prepared just because Mac login passed.
Do not automatically reboot or install the unpublished native prerequisite preview.
Do not remove its journal or SSH blocking firewall rule to make legacy setup run.

### Legacy pairing only after the release gate and owner choice

Run `agent-road pair --name "My Windows PC"` in an interactive terminal. Relay the
short Windows command exactly as emitted; do not invent a code or replay a previous
invite. Keep the controller process alive. Ask the Windows owner to review and run
it as administrator, then follow both sides' consent prompts. This can install and
configure Tailscale/OpenSSH and the Agent Road private runtime. A reboot needs the
user's permission; account login alone is not permission to reboot.

If the process fails or times out, inspect its existing request/state first. Do not
blindly create another invite or rerun bootstrap. Preserve finite errors and recovery
evidence. Never claim full readiness from CONNECTED_SSH_ONLY; transport and runtime
readiness are different stages.

## 6. Continue core on the same enrolled device

If pair exits nonzero after SSH enrollment, keep the same device ID. A runtime
failure does not itself authorize creating another invitation. Keep the pair PTY
alive during Windows setup; use a persistent process and captured output rather
than starting another pair when the agent's tool wait expires.

Run `agent-road runtime-status <device-id>` and `agent-road doctor <device-id>`.
Before a fresh core plan, run `agent-road runtime-readiness <device-id>` (two
read-only samples, interval 30–120 seconds, default 60; a known blocker returns immediately). REBOOT_REQUIRED needs an authorized
reboot of the target only; SERVICING_ACTIVE means allow Windows servicing to finish.
RECOVERY_REQUIRED means inspect the existing operation. READY_FOR_PLAN is an
observation, not a guarantee; the normal plan/prepare revalidation still applies.
Do not disable updates or clear reboot markers to force readiness.

Once stable, capture a baseline, generate a plan, review its scope, and prepare:

```sh
agent-road runtime-baseline <device-id> --capture
agent-road runtime-plan <device-id> --profile core --baseline <returned-baseline-id>
agent-road prepare <device-id> --profile core --approved <reviewed-plan-ticket-id>
```

If a consumed prepare is uncertain, never replay it. Inspect its state first.
For the narrowly supported empty nested staging case, the packaged CLI provides:

```sh
agent-road runtime-retain-empty-stage <device-id> --inspect
agent-road runtime-retain-empty-stage <device-id> --apply
agent-road runtime-retain-empty-stage <device-id> --reconcile
```

Review the immutable observation and obtain any missing mutation authorization
before apply. This retains the exact empty directory, does not reset runtime
state, and admits no files/work/runtime or existing retention destination. One
attempt only; inspect expiry or any uncertain apply needs investigation. RETAINED
is not RECOVERED: continue with `runtime-recover --inspect`, its required authorized
target reboot, post-boot inspect, and exact-ticket `--apply --ticket <ticket>`.
Only then create a fresh baseline/plan. Never delete recovery records manually.

Standalone approved prepare writes private finite staging diagnostics under
`$AGENT_ROAD_HOME/provision-diagnostics/`. Preserve them and the original error;
a later successful retry does not prove the original failure cause.

## 7. Verify and operate within the requested scope

Use `agent-road list` and `agent-road status <device-id>` for the selected device.
After the user authorizes a harmless remote test, save a local PowerShell script
containing `Write-Output 'Agent Road connection verified'` and execute:

```sh
agent-road exec <device-id> --script /absolute/path/check.ps1
```

Report the observed output and exit status. File transfer uses:

```sh
agent-road put <device-id> /absolute/local/file 'C:\absolute\remote\file'
agent-road get <device-id> 'C:\absolute\remote\file' /absolute/local/file
```

Do not add --overwrite without authorization. For long work, see
`agent-road job start <device-id> /absolute/script.ps1`, then query the same job ID
with `agent-road job status <device-id> <job-id>` or `agent-road job logs <device-id> <job-id>`.
Do not automatically resubmit after uncertain transport failures. For desktop/browser
work, first inspect actual capabilities and whether the user is using the PC;
CLI interface availability alone does not prove GUI access.

## Failure routing and completion criteria

- NATIVE_INSTALLER_NOT_RELEASED: Mac installation can finish; native Windows onboarding cannot yet proceed.
- Defender detection/quarantine: stop, retain detection name/time and finite error; no exclusions or alternate payload replay.
- QUERY_UNCERTAIN / INSTALL_UNCERTAIN: keep the original attempt, inspect its journal/process state; do not run install again.
- PRIOR_ATTEMPT_REQUIRES_INSPECTION: preserve the journal and inspect; do not delete it to bypass the guard.
- REBOOT_REQUIRED: obtain applicable permission, reboot only the intended device, then inspect before resuming.
- CAPABILITY_INSTALLED_SSH_BLOCKED: OpenSSH prerequisite only; not a connected or ready device.


- Command not found: installation/PATH, not account failure.
- AUTH_LOGIN_REQUIRED or PAIR_LOGIN_REQUIRED: inspect CLI authorization; do not expose credentials.
- PAIR_CONFIG_REQUIRED / PAIR_NETWORK_CONFIG_REQUIRED: network config is absent; login alone cannot fix it.
- PAIR_CONFIG_UNSAFE / AUTH_STORAGE_UNSAFE: inspect ownership, permissions and symlinks; do not chmod broad trees.
- PAIR_INTERACTIVE_CONFIRMATION_REQUIRED: use an interactive terminal; do not bypass consent.
- Connection uncertainty: query the same operation/device/job before retrying a mutation.

Report separately: installation, account authorization, network readiness, pairing,
transport, runtime and actual task result. Verify file roundtrips and permitted
reboot recovery separately. If the OS or VM cannot boot, report that layer instead
of treating it as an authentication error. Host-console or manual intervention is
external recovery, not proof of automatic reconnect. Mark untested items explicitly
and list any unfinished stage and exact blocker.
`agent-road logout` or website controller revocation blocks new pairing requests; it
is not device detach and does not remove existing SSH keys or stop existing sessions.

### Bootstrap stops before SSH

After approval, the controller observes retrieval for 120 seconds, saving
`delivery-observation.json`. DELIVERED means the service handed out the payload;
it does not prove Windows executed it. DELIVERY_UNCONFIRMED prompts inspection of
the original attempt and leaves the existing enrollment timeout intact. A transient
status failure does not justify cancelling or replaying a possibly running installer.

If Windows returns to the prompt without stage-zero progress and the controller
remains ENROLLING, inspect the same attempt before doing anything else. Check the
Windows security protection history (Defender events 1116/1117) and whether bootstrap
created its state directory. Capture only bounded diagnostic facts, not command lines
or tokens. Compare host and guest clocks before attributing a detection to a phase.
Do not replay a delivered bootstrap, re-pair blindly, disable protection or add an
exclusion. Preserve the original capture and report the detection for review.

Pair captures `cancelled.json` for successful cancellation, `cancel-outcome.json`
for an expected refusal (already delivered, expired or unavailable), and
`cleanup-uncertain.json` for other failures. Already delivered is not proof that the
bootstrap executed, nor that enrollment or core succeeded. Older builds omitted
expected refusals; their missing cancellation receipt cannot identify the outcome.

Before SSH exists, the Windows owner must receive the bundled diagnostic file
through an already trusted transfer method and review it locally; `agent-road put`
cannot transfer to an unenrolled device. Do not weaken script policy if execution
is blocked; use Windows Security protection history instead.
Run the bundled `windows/pairing-diagnostics.ps1` locally on the Windows target for
bounded event facts, protection status and guest time. It reads only, never includes
raw event messages or command lines, and marks unavailable evidence explicitly.
Use the controller's operation start/end time to bound clock skew. See
[Windows installer delivery](windows-installer-delivery.md) for the signature gate,
the proposed fixed-installer flow and the remaining release requirements.
