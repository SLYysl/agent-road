# Windows physical acceptance

> Status: Windows 11 Home build 26200 SSH/bootstrap path accepted on 2026-07-28; the private PowerShell 7 runtime and fresh-machine Windows 10/11 Home/Pro matrix remain physically unaccepted.

Observed acceptance covered strict pinned-host-key administrative SSH, the automated 257-byte bidirectional transfer and cleanup, a normal reboot with automatic Tailscale/`sshd` return, exact Tailscale-only listener/PID and firewall checks, direct-LAN TCP-22 rejection, a temporary LAN host-route rejection with route cleanup, and empty Serve/Funnel status. An initial reboot exposed an `sshd`/Tailscale address-order race; bounded SCM restart actions fixed it without widening listeners or adding a separate target agent.

## Before enrollment

- [ ] Record Windows version, build, architecture, and edition. The x64 design target includes Windows 10 build 1809 or newer and Windows 11 Home/Pro, but the fresh-machine four-edition matrix remains pending.
- [ ] Confirm the test PowerShell is elevated and record its version.
- [ ] Inventory whether Tailscale is installed, signed in, and running; record its existing hostname/preferences without including credentials.
- [ ] Inventory whether OpenSSH Server, `sshd`, SSH configuration, firewall rules, and an `AgentRoad` account already exist.
- [ ] Record whether the exact Microsoft `OpenSSH-Server-In-TCP` rule or an explicit third-party SSH program/service or TCP-22 inbound allow rule exists; expect explicit conflicts to fail closed.
- [ ] Record weak-host receive/forwarding on every non-Tailscale interface, plus TCP-22 portproxy and TCP-22 static NAT state; expect any unsafe path to fail closed.
- [ ] Confirm the Mac Tailscale app is signed in and `Running`.
- [ ] Confirm the Mac has no existing Serve or Funnel configuration. Agent Road must stop rather than alter one.
- [ ] Confirm the Windows machine and any files used for the test have a recoverable backup.

## Enrollment

- [ ] On the Mac, run the exact enroll workflow from README and leave the CLI running.
- [ ] Choose and record the 5–30 minute `--timeout-minutes` value; default 10 is acceptable, while a slow first install may need 20 or 30.
- [ ] Confirm stdout contains exactly one PowerShell line; paste it once into elevated Windows PowerShell.
- [ ] If Mac Serve consent is requested, approve its URL once, rerun enrollment, and confirm Funnel was never enabled.
- [ ] Complete the Windows Tailscale browser login when prompted and confirm Tailscale reaches `Running`.
- [ ] Record whether pre-existing Tailscale and OpenSSH installations were reused or missing components were installed.
- [ ] If testing recovery from `COMPLETION_UNCERTAIN`, discard the old command, generate a new one, and confirm only an exact healthy pending baseline is superseded with the new device key; confirm altered/unhealthy state fails closed.
- [ ] Wait for the Mac to print `CONNECTED_SSH_ONLY`; record this as transport success, not runtime success.
- [ ] Keep the Mac CLI open while it automatically prepares core. Record `RUNTIME_READY` or the exact finite `RUNTIME_*` failure; a runtime failure must not retract `CONNECTED_SSH_ONLY` or disable pinned SSH.

## Verified channel

- [ ] Confirm enrollment's strict SSH probe used the reported pinned host key and did not disable host-key checking.
- [ ] Confirm the remote identity is `AgentRoad`, has administrator membership, and ran the structured PowerShell probe.
- [ ] Confirm the automated 257-byte Mac-to-Windows upload, Windows-to-Mac download, hash comparison, and temporary-file cleanup succeeded.
- [ ] Confirm the device record contains only expected non-secret Windows/Tailscale/SSH facts and reports `CONNECTED_SSH_ONLY`.
- [ ] Confirm the `AgentRoad-OpenSSH-Tailscale` rule has only the current Tailscale local addresses, Tailnet remote ranges, TCP 22, the verified `sshd.exe` program/service, and blocked edge traversal. If the exact Microsoft broad rule existed, confirm it is disabled.
- [ ] Confirm every TCP-22 listener address equals a current Tailscale address and every listener PID equals the verified LocalSystem `sshd` service PID; confirm no wildcard, LAN-address, or extra-process listener exists.
- [ ] From a separate LAN path, confirm the Windows LAN address cannot accept TCP 22. Add a temporary host route to the Windows Tailscale address through its LAN address and confirm that path also cannot connect; remove the route afterward.

## Reboot and recovery

- [ ] Reboot Windows normally.
- [ ] Confirm Tailscale reconnects without another login and `sshd` returns automatically.
- [ ] Repeat a strict pinned-host-key SSH administrative probe and bidirectional file transfer after reboot.
- [ ] Repeat the exact listener-address/PID checks and the LAN/temporary-host-route negative probes after reboot.
- [ ] Confirm ordinary user accounts, profiles, file ownership, SSH configuration, and unrelated non-port-22 firewall rules are unchanged; confirm Tailnet SSH reconnects while non-Tailnet inbound SSH remains intentionally blocked.
- [ ] Record rollback observations from any failed attempt: which Agent Road-owned changes were restored, which journal/error code remained, and whether pre-existing state stayed intact.
- [ ] When rollback follows disabling the exact Microsoft broad rule, confirm that rule's enabled state is restored only after the scoped Agent Road changes are reversed.

## Private core runtime (physical gate pending)

- [ ] Serialize all commands targeting the same device. Do not overlap `doctor`, `prepare`, `runtime-status`, or ad-hoc SSH probes through the cooperative device identity.
- [ ] Treat raw `list`, `status`, `runtime-status`, `runtime-recover`, `doctor`, `runtime-baseline`, and `runtime-plan` output and every exact baseline, plan, or recovery ticket ID as controller-private. Acceptance reports use only the bounded redacted facts required below.
- [ ] Run `runtime-status <device-id>` first. If it reports `FAILED/RUNTIME_COMPLETION_UNCERTAIN`, do not capture a baseline or prepare until the exact recovery sequence below is resolved.
- [ ] For a fresh uncertain state, run `runtime-recover <device-id> --inspect` without `--prior-ticket`. This first inspect records Mac-side evidence and should return `RUNTIME_REBOOT_REQUIRED`; stop and obtain separate authorization before rebooting Windows.
- [ ] After that separately authorized reboot, run the first post-reboot `runtime-recover <device-id> --inspect` again without `--prior-ticket`. `RECOVERY_READY` must stop for a separate review and authorization of the returned exact recovery ticket before `runtime-recover <device-id> --apply --ticket <the-exact-ticket-id>`.
- [ ] Use `--prior-ticket` only when controller evidence names an existing exact immediate-predecessor recovery lineage; never infer it or add it to either fresh inspect above. One inspect is read-only on Windows, but on the Mac it may create or retain owner-only recovery-managed directories and a persistent recovery lock file, publish an owner-only boot observation, and, depending on pre-existing recovery state or lineage, publish recovery-ticket or successor evidence; it may also refresh `known_hosts` and use temporary SSH locks and verification snapshots. Reboot and exact-ticket apply mutate external state.
- [ ] Run `doctor <device-id>` and retain only its bounded non-secret inventory and finite result.
- [ ] Run `runtime-baseline <device-id> --capture` before plan review. Preserve the exact opaque `rbl_...` ID only in the Agent's machine-readable structured handoff; stdout does not contain the HMAC key, raw surfaces, target address, or local/Windows paths. A separate human short-display projection is not part of this CLI slice.
- [ ] Run `runtime-plan <device-id> --profile core --baseline <the-exact-rbl-id>`, review its requested component, byte bounds, blockers, exact runtime mutation scope, temporary task transport scope, and external non-mutation claims, and retain the returned opaque `rpt_...` ID. In a separately authorized physical run, pass only that exact ID to `prepare <device-id> --profile core --approved <the-exact-rpt-id>`; bare `prepare`, `latest`, and a different ticket are invalid. Task 8 implemented this local gate but did not perform either physical command, so physical acceptance remains pending.
- [ ] Confirm the reviewed production catalog requests only PowerShell 7.6.4 x64, and that the Mac verifies the exact byte length, SHA-256, redirect-origin policy, and signed capsule before transfer.
- [ ] In that separately authorized physical run, confirm the exact approved `prepare` publishes a verified generation only below `C:\ProgramData\AgentRoad\runtime` and returns the canonical `READY` JSON record. Also confirm its separate transport scope uses only `C:\ProgramData\AgentRoad\tasks\<transportOperationId>.ps1`, `<transportOperationId>.result.json`, and `<transportOperationId>.result.json.tmp`: a no-op uses zero sets, while an actionable run uses at most two fresh distinct 32-character lowercase-hex sets for inventory and provision. The task root may be created and retained; cleanup of all three operation files is attempted, but uncertain execution or cleanup may leave bounded residue. The literal `RUNTIME_READY` marker belongs to the enrollment handoff, not the standalone `prepare` command.
- [ ] Immediately run `runtime-baseline <device-id> --compare --baseline <the-exact-rbl-id>`. Accept `UNCHANGED` only when every declared count and keyed MAC matches; `CHANGED` identifies only bounded surface IDs and does not assign causation. Stop and investigate either `CHANGED` or any finite `RUNTIME_*` error.
- [ ] Confirm the generation uses its absolute managed `pwsh.exe` and passes the fixed JSON round-trip smoke test.
- [ ] Confirm global PATH, registry application registration, Git, Node.js, Python, services, scheduled tasks, firewall, user profiles, and unrelated ACLs remain unchanged using bounded independent read-only checks. The runtime CLI schema alone does not prove every one of these external surfaces.
- [ ] Through a separately reviewed exact approval, run the approved prepare again and record an observed no-op with unchanged governed state. Compare managed state and artifacts, not the whole raw inventory: a no-op plan has a zero free-space requirement, so exact free bytes may drift while every other canonical fact remains exact. This physical observation does not prove that signing, acquisition, `provisionUpload`, or other controller hooks were never invoked; that requires separate controller tracing. The two read-only planning observations execute the same digest-bound gzip source in memory through the fixed pinned-SSH stdin loader; they do not use SCP or create a task-path script.
- [ ] Run `runtime-status <device-id>` and confirm its independent Mac-side record binds the expected device, core profile, manifest digest, and generation digest without secrets.
- [ ] Stop after any finite `RUNTIME_*` failure, preserve its bounded evidence, and diagnose before authorizing another physical `prepare`; do not blindly replay the same operation.
- [ ] Do not inject a Mac-controller crash, kill, or power loss while runtime state is intermediate until durable capsule persistence and same-operation controller reconciliation have their own local and physical acceptance. The current slice fails closed rather than guessing.

## Report hygiene and sign-off

- [ ] Inspect Mac stdout/stderr, Windows console output, controller state, and Windows journal for accidental secrets or sensitive command echo.
- [ ] Confirm temporary Serve routing and the localhost enrollment receiver are closed after success or failure; confirm Serve/Funnel status readback shows the owned path absent and Funnel was never used.
- [ ] Confirm no raw enrollment token, generated PowerShell command, password, signing private key, or device SSH private key was persisted or copied into evidence.
- [ ] Attach only redacted build/edition, stable error codes, timestamps, and non-secret observations to the acceptance report.
- [ ] Record SSH/bootstrap physical acceptance separately after enrollment, strict SSH, bidirectional transfer, reboot, and reconnection all pass.
- [ ] Record private core runtime physical acceptance separately only after the pending runtime checks above pass, including first install, verification, exact no-op, independent state readback, and preserved pinned SSH.
- [ ] Do not record the Windows 10/11 Home/Pro compatibility matrix as accepted until all four x64 edition targets pass the applicable SSH/bootstrap and private-runtime gates.

Never paste tokens, generated enrollment commands, passwords, or private keys into bug reports, chat, screenshots, or issue trackers.

## 2026-09-19 internal-API core acceptance

The enrolled Windows target reached `READY` with PowerShell core 7.6.4 through
production internal APIs. Its prior early rollback was resolved with the
[terminal confirmation protocol](terminal-rollback-confirmation.md), preserving
exact evidence before a new approved operation. No CLI integration or base
profile installation was performed in this slice.

Independent doctor and paired fresh inventories matched the local generation
and version, with the existing controller key pinned, no pending operation and
no pending reboot. The installation baseline comparison was `UNCHANGED` with
zero changed surfaces. A fresh approved plan then reported `present`; repeating
prepare returned the identical existing READY record. A second independent
inventory/baseline verification passed, with unchanged managed generation and
enrollment registry. This observes no-op behavior; it is not separate physical
tracing of every controller hook.

One initial doctor attempt ended with an unclassified harness error: its
underlying transport code was not retained. A subsequent instrumented production
transport check and both complete independent verifications passed. Its original
cause remains unproven, so this record does not assert universal first-attempt
reliability. All private receipts and both previously retained transactions are
preserved; no reboot was needed during this continuation.

## 2026-09-19 CLI integration acceptance

Real `node src/cli.mjs` child processes verified READY status, doctor inventory,
baseline capture, a fresh core plan with `present`, approved prepare returning
exactly the prior READY record, an `UNCHANGED` baseline (zero changed surfaces),
and identical final status. The new `runtime-confirm-rollback` command rejected
READY locally with `RUNTIME_STATE_UNSUPPORTED`; its successful path is covered
by controller-backed CLI tests rather than resetting a working physical target.

The final doctor invocation returned `RUNTIME_INVENTORY_FAILED`. Its exact CLI
receipt was retained; a separate instrumented production transport run then
passed all eight subprocess steps and verified the managed generation. This
intermittent inventory failure remains unresolved and is not hidden by automatic
retry. No installation was replayed and no reboot was performed. Private CLI
receipts live under `cli-core-acceptance-*`; no identifiers or raw inventory are
published here.

An independent CLI status/doctor recheck subsequently passed, confirming the
same generation, core 7.6.4, no pending operation or reboot, and an unchanged
enrollment registry. This recheck does not erase the preceding failure.

## 2026-09-19 native stdin repair acceptance

The original final-doctor failure was reproduced during diagnosis. Exact process
inspection found ten retained production bootstrap launchers; one authorized
reboot cleared them and automatic sshd/Tailscale returned. The common bootstrap
now reads the native stdin pipe through FileStream, retaining the same framed
protocol, validation and timeout budgets. See [diagnosis](doctor-intermittent-diagnosis.md).

After the repair, the full real CLI sequence passed both doctors, a fresh present
plan, approved prepare returning the identical READY record, unchanged baseline
and registry, and identical final status. Six subsequent production doctor
observations passed; a separate query found no retained bootstraps. The native
Windows fixture passed six open-pipe, maximum-size and corrupt-frame cases.
Core remained 7.6.4; retained transactions were preserved. These are bounded
physical observations, not a claim of universal first-attempt reliability.
