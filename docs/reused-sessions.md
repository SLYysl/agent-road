# Explicit reused SSH sessions

The opt-in batch tool runs 1–20 local PowerShell scripts in order over one pinned
SSH connection. Ordinary exec, file transfer and provisioning still default to
fresh connections. This is transport reuse, not a persistent PowerShell shell:
variables, process state and working-directory changes do not carry between scripts.

```sh
node src/cli.mjs session <device-id> /absolute/first.ps1 /absolute/second.ps1
```

All source scripts are snapshotted before remote mutation. Each script has a
300-second timeout and its own operation ID, preflight, upload, hash verification,
execution receipt and guarded cleanup. One target selection/admin probe is shared.
The controller must remain running; this is not a durable background job or PTY.

The first output line identifies a private `agent-road-session-*` directory under
Node's `os.tmpdir()`. `request.json` records operation IDs before dispatch;
`results.json` retains completed results, including exact stdout, stderr and exit
codes. These files contain private device/path information and must not be
committed. Console output contains only the capture basename, counts and timing.
`closed: true` is printed only after transport shutdown succeeds.

A nonzero script exit stops the batch with CLI exit 2 and `SESSION_SCRIPT_FAILED`;
the original script exit code remains in `results.json`. Transport uncertainty also
stops immediately and writes `stopped.json`. Never resubmit an uncertain batch as
a recovery strategy: earlier scripts may have run. Inspect the saved operation IDs
and receipts first. There is no automatic replay or resume.

## Connection lifetime and trust

`withTrustedSshSession(..., { reuseConnection: true })` retains the existing
identity lock and immutable host-key/private-key snapshots for the whole batch.
Original and snapshot identities are rechecked around every invocation. The
private control directory is mode 0700; each socket must be owned by the current
user, inaccessible to group/others, and retain its recorded filesystem identity.
Overlapping calls and calls after closure are rejected.

The first SSH call creates a master with `ControlPersist=30`. Later SSH/SCP
calls use the same socket and `ProxyCommand=/usr/bin/false`, so a lost master
cannot silently fall back to a new network connection. See the official
[OpenSSH options](https://man.openbsd.org/ssh_config): ControlPersist is an **idle**
expiry, not a hard lifetime limit. Each session uses its own socket; no global SSH
configuration is changed.

Shutdown sends `ssh -O exit` and confirms socket disappearance before removing
the control directory and releasing trust snapshots. Uncertain shutdown reports
`SSH_VERIFY_CLEANUP_FAILED` and retains the private directory. The existing fixed
remote cleanup path may open a fresh pinned connection after a failure; this
exception only cleans staging resources and never replays the user script.

## Validation

Targeted regression covers trusted sessions, SSH verification, exec, transfer,
local publication, runtime provisioning, CLI remote work and background jobs.
217 tests passed. Socket fixtures cover disappearance, replacement, shutdown
failure, uncertain operation errors, overlapping calls and close-during-execution.
Default non-reuse argument vectors retain their existing tests.

Physical Windows checks confirmed a two-script batch with exact Chinese/emoji
output and successful explicit shutdown. Timing and failure probes are recorded
below. These are bounded background probes, with no foreground input, reboot,
package install or Windows configuration changes.

On 2026-09-19, ten independent executions of the same near-empty script took
87.597 s in total (median 8.619 s); one ten-script reused batch took 51.180 s
including CLI startup and close. This is a **41.6% observed total reduction**.
The reused per-script median was 4.927 s, excluding the shared initial connection,
admin probe and final close. All 20 outputs matched exactly and all exits were 0.
[Sanitized timings](reused-sessions-2026-09-19.json) include both boundaries.

This comparison combines connection reuse, one shared target/admin selection and
one controller process. It does not isolate pure SSH handshake savings. Independent
API timings exclude initial Node startup; batch outer wall time includes it.
Groups ran sequentially on the same uncontrolled live machine, with local tests
overlapping part of the work. Ten samples do not establish general tail latency,
reliability or long-task speedup. Existing PowerShell wrappers still account for
substantial per-script work; the remaining ~5 seconds is not pure network latency.

A physical failure probe retained exit 7 and exact stdout from script one, stopped
with `SESSION_SCRIPT_FAILED`, and independently confirmed script two's sentinel
file did not exist. No failed operation was replayed.

A physical disconnect probe closed its own master after socket validation but
before the next SSH dispatch. The dispatch failed without executing its marker or
opening a replacement master; uncertain shutdown surfaced as
`SSH_VERIFY_CLEANUP_FAILED`. The probe removed its retained private socket directory
only after confirming its explicit master exit and absent socket.
