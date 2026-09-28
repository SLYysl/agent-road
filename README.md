# Agent Road

> Private open-source preparation snapshot — not a public release.
> Source: `335cfeee6614a6e7c2599cb1c1fe00cf2ce61787` (2026-09-28).
> Start with [release preparation](OPEN_SOURCE_PREPARATION.md) for current evidence, limitations and publication gates. Historical instructions below are retained for review; do not assume hosted endpoints or installer downloads constitute this release.

Agent Road is a Mac-hosted control plane for enrolling and operating remote computers. The target computer does not run a model.

## Windows bootstrap (SSH-only)

On the Mac, first make sure the Tailscale app is signed in and reports `Running`. Then keep this command running in Terminal:

```bash
cd /path/to/agent-road-checkout
node src/cli.mjs enroll --name "Home Windows PC"
```

Replace `/path/to/agent-road-checkout` with the checkout whose code is being accepted. Enrollment does not require a checkout or worktree with a particular historical name.

The command writes exactly one PowerShell line to stdout. Paste that one line into an **elevated Windows PowerShell** window; do not close the Mac CLI while enrollment is in progress. On a new Windows machine, complete the Tailscale browser login once. The Mac first prints `CONNECTED_SSH_ONLY`, then automatically prepares Agent Road's private core runtime and prints `RUNTIME_READY`. No second Windows command is required.

Enrollment waits 10 minutes by default. If the first Windows Feature on Demand or Tailscale installation may be slow, choose a 5–30 minute limit explicitly, for example `--timeout-minutes 20`. Before `CONNECTED_SSH_ONLY`, press Ctrl-C once (or send SIGTERM) and let the CLI finish removing its temporary Serve route and localhost receiver before it exits. Once transport publication begins, Agent Road completes that state update atomically. After `CONNECTED_SSH_ONLY` is printed, SIGINT/SIGTERM are deliberately absorbed until automatic core preparation reaches `RUNTIME_READY` or a finite `RUNTIME_*` failure, so the process cannot exit between the durable transport result and its runtime result.

The first Mac enrollment may wait up to 10 seconds, then stop with `TAILSCALE_SERVE_AUTH_REQUIRED` and a Tailscale consent URL. Approve Tailnet HTTPS/Serve once, then run the enroll command again. Agent Road never uses Tailscale Funnel. For safety, this release also stops if the Mac already has any Serve or Funnel configuration; remove or relocate that configuration before retrying rather than letting Agent Road alter it.

The x64 design target is Windows 10 build 1809 or newer and Windows 11, including Home and Pro. Current physical evidence covers the SSH/bootstrap path on one Windows 11 Home build 26200 machine only; the private core runtime installation and the fresh-machine four-edition matrix remain unaccepted. Windows needs internet access and an elevated Windows PowerShell 5.1 session, but it does not need Git, Node.js, Python, or a local model.

`CONNECTED_SSH_ONLY` means the Mac completed strict host-key-pinned administrative SSH verification and a bidirectional temporary-file probe. It is a durable transport fact, not runtime success. If later runtime preparation prints a finite `RUNTIME_*` error, the SSH rescue channel remains connected and the error is not reclassified as `BOOTSTRAP_FAILED`.

`RUNTIME_READY` currently means only that the reviewed portable PowerShell 7 core is installed and verified below `C:\ProgramData\AgentRoad\runtime`. Agent Road downloads and verifies the pinned artifact on the Mac, transfers the signed capsule and verified artifact through pinned SSH, and does not modify the user's global PATH, Git, Node.js, Python, services, scheduled tasks, or firewall. The `base` profile and desktop/browser helpers remain disabled until their artifacts and physical acceptance gates are complete.

The bootstrap also configures bounded Windows Service Control Manager restart actions for `sshd`, so a boot-time Tailscale-address race can recover without a desktop login. It preserves an existing matching policy, transactionally restores an initially empty policy on rollback, and refuses to overwrite any other pre-existing recovery policy. Neither transport nor core readiness means visible desktop or existing-browser-profile control is available; Windows-MCP, RustDesk, interactive desktop control, and a separate watchdog service remain deferred.

If Windows reports `COMPLETION_UNCERTAIN`, discard the old command and generate a new enrollment command on the Mac. When the preserved Agent Road account, SSH policy, service, and scoped firewall state are all healthy, the new run safely supersedes the pending transaction with its new device key; if that baseline is not exact, it fails closed for repair instead of guessing.

A valid existing Windows OpenSSH installation is reused. To enforce Tailnet-only SSH, `sshd` listens only on the machine's current Tailscale addresses and the `AgentRoad-OpenSSH-Tailscale` rule is restricted to those local addresses, Tailnet source ranges, TCP 22, and the verified Microsoft `sshd` program/service. The exact Microsoft `OpenSSH-Server-In-TCP` rule is disabled transactionally and restored on rollback. Explicit third-party SSH program/service or TCP-22 allow rules fail closed; unrelated AppContainer capability rules are preserved. Non-Tailscale interfaces with weak-host receive or forwarding, TCP-22 port proxies, and TCP-22 static NAT mappings also fail closed.

Agent Road operates only after Windows has booted normally and networking, Tailscale, and `sshd` can run. It cannot unlock BitLocker, repair WinRE/BIOS failures, recover a machine that cannot boot or reach the network, or fix hardware faults. It also does not bypass EFS, DPAPI, browser credentials, MFA, or another user's logged-in desktop identity.

The generated PowerShell line contains a recoverable, short-lived one-use enrollment token. Treat the whole line as secret until it expires or is used; do not save it in notes, chat, screenshots, or bug reports. Controller state is stored under `~/.agent-road` with device-specific SSH private keys kept separately from the non-secret registry.

## Agent work interface

Use the [unified agent interface](docs/agent-interface.md) for exec, put/get, shared
SSH sessions, durable background jobs and existing-tool binding. Run
`node src/cli.mjs capabilities` for a local machine-readable command inventory.
Earlier browser/agent experiments and their current boundaries are linked there.

## Other commands

```sh
node src/cli.mjs --help
node src/cli.mjs list
node src/cli.mjs status <device-id>
node src/cli.mjs runtime-status <device-id>

# Only when runtime-status reports FAILED/RUNTIME_COMPLETION_UNCERTAIN:
node src/cli.mjs runtime-recover <device-id> --inspect
# After separately authorizing and completing the requested reboot:
node src/cli.mjs runtime-recover <device-id> --inspect
# After separately authorizing the exact recovery ticket returned as RECOVERY_READY:
node src/cli.mjs runtime-recover <device-id> --apply --ticket <exact-recovery-ticket-id>

node src/cli.mjs doctor <device-id>
node src/cli.mjs runtime-baseline <device-id> --capture
node src/cli.mjs runtime-plan <device-id> --profile core --baseline <exact-rbl-id>
# Run only after a separate review and authorization of this exact ticket:
node src/cli.mjs prepare <device-id> --profile core --approved <exact-rpt-id>
node src/cli.mjs runtime-baseline <device-id> --compare --baseline <exact-rbl-id>
node src/cli.mjs runtime-status <device-id>
```

For fresh uncertain recovery, the first `--inspect` records Mac-side evidence and should return `RUNTIME_REBOOT_REQUIRED`; stop and obtain separate reboot authorization. The first post-reboot inspect is again run without `--prior-ticket`; `RECOVERY_READY` then requires another stop and separate authorization for `--apply --ticket <exact-recovery-ticket-id>`. Use `--prior-ticket` only to name an existing exact immediate-predecessor recovery lineage, never as a substitute for either fresh inspect. One inspect is read-only on Windows, but on the Mac it may create or retain owner-only recovery-managed directories and a persistent recovery lock file, publish an owner-only boot observation, and, depending on pre-existing recovery state or lineage, publish recovery-ticket or successor evidence; it may also refresh `known_hosts` and use temporary SSH locks and verification snapshots. Reboot and apply mutate external state.

For a supported initial-core terminal rollback, `node src/cli.mjs runtime-confirm-rollback <device-id>` verifies remote evidence and records the finite local failure. It does not install or make the runtime READY. See [terminal rollback confirmation](docs/terminal-rollback-confirmation.md) for its narrow admission rules and the fresh-plan workflow. READY devices are rejected.

`doctor` inventory does not change governed state, but its pinned-SSH transport performs bounded temporary Agent Road-owned staging and cleanup writes. Baseline capture returns an exact opaque `rbl_...` ID; plan review binds it into an exact opaque `rpt_...` ticket. Bare `prepare`, `latest`, a prefix, or a different ticket is invalid: only a separately reviewed `prepare --approved <exact-rpt-id>` may enter the runtime mutation path. Treat raw `list`, `status`, `runtime-status`, `runtime-recover`, `doctor`, `runtime-baseline`, and `runtime-plan` output and every exact ID as controller-private. `runtime-status` is the independently persisted Mac-side runtime record. Production `prepare --profile base` currently fails closed with `RUNTIME_PROFILE_UNAVAILABLE`. To assess reusable Git/Node/Python/ripgrep installations before adding tools, see [existing base tools](docs/existing-base.md) and run `node tools/inspect-existing-base.mjs <device-id>`.

For intermittent doctor failures, see [bounded doctor diagnostics](docs/doctor-intermittent-diagnosis.md). The diagnostic tool retains private process receipts and stops on the first error; it does not provision or retry a failed observation.

The first orchestration slice deliberately blocks a persisted intermediate or completion-uncertain controller state instead of rebuilding a signed capsule from incomplete facts. Durable capsule persistence and same-operation controller reconciliation must pass a separate gate before controller-crash or power-loss fault injection is claimed as supported.

If an inspect was invoked but its result was lost, stop without retrying. The [Task 9 local evidence guide](docs/task9-local-evidence.md) provides a Mac-only redacted observation command and the durable-result capture behavior. Local file presence never establishes the Windows outcome or authorizes another command.

For separately authorized future inspections, the [inspect capture CLI](docs/task9-inspect-cli.md) provides `node src/inspect-cli.mjs inspect <device-id> --run-directory <absolute-path>` and a local-only `readback` route. It persists a redacted result before display and blocks reuse of an existing run directory. Adding this entry point does not authorize repeating the earlier uncertain inspection.

## Development

```sh
npm test
npm run check
```

For bounded work which outlives its initiating SSH connection, use the explicit
[background task controller](docs/background-tasks.md) (start/status/logs/cancel).
It is separate from managed-runtime provisioning and visible desktop control.

A [Windows agent handoff example](docs/remote-agent-handoff.md) records Claude Code
authoring, testing and repairing code remotely, followed by Mac/Windows acceptance.
