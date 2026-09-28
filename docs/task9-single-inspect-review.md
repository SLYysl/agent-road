# Single physical inspect: local review and approval scope

## Authorized invocation result

On 2026-09-18 the user explicitly authorized this exact scope. The fixed device,
registry/state hashes, executable-source digest, and absent run directory passed
the local binding checks. The adapter was invoked once; the execution-session
handle was retained and awaited through completion.

- CLI exit: 2; projection: `FINITE_STOP / RUNTIME_STATE_UNSUPPORTED`.
- Local receipt readback returned the same projection; started and terminal
  records have the expected owner-only file permissions.
- Persisted runtime-state bytes are unchanged from the reviewed state.
- Local operation directory and persistent lock remain; boot observation and
  commit are absent, with zero current/legacy tickets, successors, and attempts.
- No second adapter call, remote diagnostic, reboot, apply, cleanup, doctor,
  baseline, plan, or prepare followed the terminal result.

The finite code does not identify the failed validation stage or establish that
the Windows recovery wrapper was reached. No SSH-command count or remote state
is inferred from it. The historical lost result and runtime recovery remain
unresolved. This invocation's outcome is durably available locally; its fixed
run directory is retained and must not be reused or replaced to retry.

The private review record's `PENDING` field describes its preparation-time
snapshot, not a reusable authorization. This conversation supplied the one-shot
authorization, which has now been used. Any later work starts with local
failure-stage analysis; this result supplies no authority for another remote call.

The sections below preserve the original local review and authorized scope.

## Status

Local review completed on 2026-09-18 against executable baseline `83b7be4`.
No Windows command, Tailscale query, connectivity test, or production CLI call
was executed. This is self-review, not independent review or physical acceptance.
Remote execution is pending separate user authorization.

## Current local evidence

- Exactly one eligible registered target; two registered transport addresses.
- Validated runtime state remains `FAILED/RUNTIME_COMPLETION_UNCERTAIN`.
- Operation directory and persistent recovery lock file exist; boot observation
  and recovery commit are absent. Current/legacy tickets, successors, and
  current/legacy attempts have zero entries.
- Private-key and known-hosts file metadata satisfy the local owner/0600 checks.
  No private-key content was read. This is not fresh host-key verification or a
  claim that Windows is online; production trusted SSH still performs its checks.
- Local process listing found zero named Node CLI processes. This does not prove
  that no in-process controller or residual Windows process exists.
- The inspect adapter, capture, and local-evidence tests passed 56/56.

## Exact local selection, kept private

The selected device ID, controller root, fixed run path, registry/state hashes,
and aggregate tracked executable-source hash are recorded in the owner-only
local `inspection-captures/next-inspect-review.json` under the configured
controller root. The record is 0600 under a 0700 parent and says authorization
is pending. It contains no copied private key, address, host key, or credential.
Its fields and digests must not be printed or committed.

The neutral fixed run label is `reviewed-inspect-01`. That run directory does
not yet exist; no started or terminal capture record has been fabricated.
Preparing the parent and review record is the only controller-local write made
during this review. Existing recovery records and locks were not changed.

Before the authorized invocation, recheck privately that the selected registry
and failed-state bytes and executable-source digest still match the review, the
local evidence remains as above, and the fixed run path is still absent. Stop
on any mismatch; do not refresh the binding or choose another target/path
automatically. Documentation-only commits do not alter the executable digest.
The review record itself is not execution authority; authorization must come
from the user for the scope below.

## Proposed remote scope

Invoke the inspect adapter exactly once with the privately selected device and
the fixed run directory. It awaits the existing production command
`runtime-recover <selected-device> --inspect`, without a prior ticket.

One CLI invocation is **not one SSH command**. Code inspection established:

1. `selectAddress` performs an existing read-only administrator probe, with a
   10-second process timeout, against each registered address until one succeeds.
   For this target there can be at most two probes. No additional diagnostic
   command or ad-hoc address is included.
2. Once an address is selected, `inspectRuntimeRecoveryRemote` invokes the
   recovery inspect wrapper once, with a 30-second process timeout. If all probes
   fail or a local prerequisite rejects, the recovery wrapper is not invoked.
3. The inspect wrapper calls `Get-AgentRoadRecoveryState $false`, reads directory
   identity/ACL/topology and the boot marker, and closes handles. The apply-only
   deletion and mutation mutex path is not invoked. No installation, managed
   directory deletion, service/firewall change, or reboot is authorized.

"Read-only" describes governed Windows state. It does not mean no OS side
effects: SSH authentication/logging and PowerShell `Add-Type` compilation can
produce normal system/runtime artifacts. No claim of zero disk writes is made.
Per-process timeouts are not a whole-operation deadline: existing Mac locks and
local work also take time; the trusted SSH lock can wait up to 15 minutes. Do
not add an outer timeout that causes an unfinished operation to be retried.

## Expected controller-local effects

- Create the capture run directory and fsynced started marker; persist a finite
  redacted terminal receipt when a result is available.
- Use existing runtime/recovery locks, trusted SSH verification snapshots, and
  known-hosts refresh behavior.
- With the currently absent boot observation, a valid empty pre-transaction
  remote state should publish a local boot observation and return
  `RUNTIME_REBOOT_REQUIRED`. That is a stop, not permission to reboot.
- The command can refuse locally, encounter a remote error, or remain uncertain.
  No result is promised. Existing controller validation remains authoritative.

## Mandatory end of this scope

Every terminal result stops. If the execution-session result is lost, read only
the existing receipt at the same fixed path. Missing, incomplete, or uncertain
readback stops; never invoke capture again or select another run path.

Do not run reboot, apply, prepare, doctor, baseline, plan, remote cleanup, lock
removal, or a second inspect under this authorization. A new inspection records
current evidence; it does not recover the historical lost result or repeat the
old prepare operation. The old uncertain outcome remains in the history.

Before actual remote execution, claim the physical-inspect topic on agent-bus
as `codex` without polling the board. Preserve pinned SSH, Tailnet-only access,
ACL checks, stderr/exit handling, and redaction. Retain/await any execution-session
handle and use only finite projections in chat and Git.
