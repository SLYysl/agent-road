# What changes on Windows, and how to leave the Alpha

Updated 2026-09-28 · [中文版](windows-access-and-removal.zh-CN.md)

Read this **before approving setup**. Agent Road is administrative remote access, not a sandbox. The current Alpha has **no supported one-command device detach or complete uninstaller**. Leaving a trial requires a reviewed, owner-approved removal plan and verification. This document is an operator checklist, not a tested universal uninstall procedure.

## What you approve

| Area | Changes the supported setup can make | What must be preserved |
| --- | --- | --- |
| Windows account | Creates a local `AgentRoad` account and adds it to the local Administrators group | Other users, their profiles and files; an existing account must be diagnosed, not silently taken over |
| OpenSSH | Installs the Windows capability if needed; configures `sshd`, its startup/recovery policy and host-key-pinned access | Previous SSH configuration, service policy and other legitimate users |
| Authorized key | Uses `C:\ProgramData\AgentRoad\ssh\authorized_keys` for the Agent Road account | Keys and evidence must remain private; identify the exact controller before changing authorization |
| Network | Installs/configures Tailscale when required and joins the approved network | Existing Tailscale identity, policy and unrelated remote access |
| Firewall | Adds `AgentRoad-OpenSSH-Tailscale`, scopes SSH to Tailscale, and can disable the standard broad `OpenSSH-Server-In-TCP` rule | Previous rules and legitimate services; never restore a broad inbound rule just because a trial is ending |
| Runtime and records | Writes managed files under `C:\ProgramData\AgentRoad`, including bootstrap journals, private runtime and task records | Keep diagnostics and results until the owner agrees what can be removed |
| Submitted work | Jobs may create scheduled tasks and files; owner-approved scripts can also change files outside Agent Road's directory | Inventory the work actually performed; uninstalling connection tools cannot undo arbitrary scripts |

The exact set depends on the bundle version, existing environment and how far setup progressed. A failed or partial setup is not the same as an enrolled device. Use its journal and original instructions; do not rerun bootstrap rollback as a general uninstaller.

“No separate Agent Road account on Windows” means the Windows owner does not need a second **website account**. It does not mean no Windows local account is created. Windows does not need a second AI model.

## Three different ways to stop using it

| Action | What it does | What it does not do |
| --- | --- | --- |
| Website controller revocation / `agent-road logout` | Revoke the controller's account grant for new pairing requests | Remove Windows SSH authorization, terminate existing sessions, cancel jobs or uninstall anything |
| Device access withdrawal | Owner/maintainer removes the intended controller's effective SSH/network access and verifies it | Automatically cancel independent tasks or reverse prior task changes |
| Cleanup / uninstall | Remove trial-owned components after access and task shutdown are verified | Safely guess which shared tools/settings existed before the trial |

Deleting Mac controller state is **not** a reliable revocation method: copies of the key may still exist, and it destroys useful inventory. A lost controller must be handled from Windows or another authorized management path.

## Owner-assisted withdrawal checklist

1. **Arrange local access first.** Have the Windows owner at the machine, or retain another explicitly authorized management route. Do not sever the only channel and then assume remote cleanup can finish. If no independent access is available, record that blocker and arrange local help.
2. **Freeze new work and identify scope.** Record the exact bundle/version, intended controller, Windows account/SID, target device and running jobs privately. Distinguish dedicated Agent Road components from pre-existing/shared ones. Do not copy private keys or full controller state into support messages.
3. **Revoke the account grant.** Revoke the relevant controller in the website account UI. If the controller is available, `agent-road logout` uses that controller's existing state. Record the result; this step alone is not device withdrawal.
4. **Reconcile work before removing its records.** For each known job ID, query status/logs. With the owner's approval, cancel only that identified running job and recheck status. Remove a scheduler definition only after its terminal state is verified. `job remove` leaves files/results. Jobs or processes started outside this mechanism need separate review; disconnecting SSH is not proof they stopped.
5. **Remove device access with a Windows administrator.** Inspect the effective `sshd_config` and authorized key sources, match the controller's public-key fingerprint, and prepare the exact change. Remove only that controller's authorization while preserving ownership/ACLs and other users. Do not simply delete an entire key file. An owner-approved disable of the dedicated `AgentRoad` account can be part of containment, but is not proof that existing sessions ended. A shared account or ambiguous identity requires maintainer review.
6. **Close existing access separately.** Identify and end the intended sessions/processes. Stopping a shared SSH/Tailscale service or removing the entire device from a tailnet can affect other users and requires explicit scope approval. Even after such a change, verify old sessions and independent jobs; do not infer termination from a failed new connection.
7. **Verify before deleting.** Where safe and authorized, try a fresh connection from the revoked controller and verify refusal; also check old sessions are closed and agreed tasks have stopped. A timeout/offline PC alone is not proof the key was revoked. Record effective key/account state locally and confirm unrelated authorized access still works. If a verification cannot be performed, mark it **unknown**, not complete.
8. **Only then review cleanup.** Use pre-install evidence to decide what was newly installed. Remove the dedicated account/profile, runtime, task files or tools only after the owner approves each category. Restore exact prior SSH/service/firewall settings only if known and still appropriate. Keep pre-existing Git, Node.js, Python, OpenSSH and Tailscale. Missing baseline means retain shared components and report partial cleanup; never replace uncertainty with a blanket delete.

For suspected unauthorized active access, the owner may need local containment before the normal sequence. Disconnecting networking or stopping shared services affects other work and does not itself stop local jobs. Preserve evidence and arrange an independent recovery route.

## What counts as finished?

Report these separately:

```text
Bundle/version:
Account grant revoked: verified / unknown
New access with old controller key refused: verified / unknown
Existing sessions closed: verified / unknown
Known background work stopped or explicitly retained:
Components removed / shared components retained:
Previous settings restored / unavailable baseline:
Unrelated access checked:
Remaining files and reason retained:
Owner confirmed:
```

Do not say “fully uninstalled” when only logout succeeded. No end-to-end Windows removal acceptance was performed for this documentation update.

## Implementation pointers

For maintainers: `windows/bootstrap-stage-one.ps1` defines the account, authorized-key path, SSH policy, service changes, firewall and transactional rollback. `tools/native-setup/` is a separate unpublished candidate path. `src/auth/client.mjs` handles account logout; `docs/agent-interface.md` describes job lifecycle semantics. Their existence does not establish a supported device-uninstall command.
