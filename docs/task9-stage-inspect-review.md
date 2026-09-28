# Stage-diagnostic physical inspect: review and result

## Authorized invocation result

On 2026-09-18 the user explicitly authorized the proposed one-shot scope below.
The private source, registry/state, prior review/receipt, metadata, and absent-run
bindings passed recheck. The adapter was called exactly once. Execution session
42432 was retained and awaited to its terminal result.

- Adapter/process exit: 2.
- Durable projection: `FINITE_STOP / RUNTIME_STATE_UNSUPPORTED`.
- Last stage: `REMOTE_INSPECT`.
- Local readback exactly matched the invocation projection; both records use
  schema 2 with owner-only 0600 permissions and a single link.
- Registry and runtime-state bytes remain unchanged; prior started/terminal
  receipt bytes remain unchanged.
- Local observation still finds operation/lock present, boot observation/commit
  absent, and zero current/legacy tickets, successors, and attempts.

This identifies the remote-inspect call boundary, not an exact failure source.
That boundary includes trusted SSH setup, address selection, remote invocation,
and result parsing/validation. It does not prove the Windows wrapper was reached
or establish its command count. The controller did not record a later result
validation or publication stage. The historical lost result remains unresolved.

No second inspect, remote diagnostic, reboot, apply, cleanup, doctor, baseline,
plan, prepare, or lock removal followed. This authorization has been consumed.
The fixed run is now occupied and retained. The private review's `PENDING` value
is its preparation snapshot, not reusable authority. Next work can inspect this
call chain locally; no remote retry is implied.

The sections below preserve the preparation-time review and authorized scope.

## Local preparation

Reviewed locally on 2026-09-18 against executable baseline `426f98a`.
No Windows call, connectivity probe, Tailscale query, or production CLI invocation
was made. This is self-review and preparation, not physical acceptance.

The registered target is the same as the previous reviewed invocation. Registry
and failed-state bytes still match that review. Its receipt reads back as
`FINITE_STOP / RUNTIME_STATE_UNSUPPORTED`; the older lost result remains unresolved.
Local observation still finds the operation directory and persistent recovery
lock, no boot observation or commit, and zero current/legacy tickets, successors,
and attempts. Private-key and known-hosts metadata pass owner/0600/canonical-path
checks; no private-key contents were read and no new host trust was established.

The owner-only local `inspection-captures/stage-inspect-review.json` binds the
selected device, controller root, new fixed run path, registry/state digests,
tracked executable source digest, baseline commit, two registered addresses,
and prior review/started/terminal digests. Its fields remain private and must not
be printed or committed. Preparation wrote only this exclusive 0600 record and
synced its existing 0700 parent. Readback matched; the old review was unchanged.

The proposed neutral run label is `reviewed-stage-inspect-01`. That directory is
absent. The old capture directory remains intact. A new path does not authorize
a retry or settle the historical uncertainty: this proposal is a separately
reviewed current-state diagnostic observation, pending explicit authorization.
The record says `PENDING`, which is never execution authority.

## Exact proposed invocation and effects

Invoke `src/inspect-cli.mjs inspect <privately-bound-device> --run-directory
<privately-bound-run>` exactly once, without a prior ticket. The adapter awaits
the production recovery inspect and writes a schema 2 terminal receipt containing
the finite last-stage label. Never infer an exact cause or Windows execution
merely from that label; see [stage diagnostics](task9-inspect-stage-diagnostics.md).

One invocation allows up to two existing read-only administrator address probes
(10 seconds each), followed by at most one recovery inspect wrapper (30 seconds).
Local prerequisites may stop before any remote call. The existing trusted SSH
lock can wait up to 15 minutes; do not add an outer timeout that abandons a live
operation. Preserve pinned host-key, Tailnet address, ACL, stderr and exit checks.
The inspect wrapper reads governed Windows state, without the apply-only deletion
path. Normal SSH logs and PowerShell compilation artifacts may still be written.

Controller-local effects include the capture records, existing lock handling,
trusted SSH snapshots/known-hosts refresh, and potentially a boot observation.
A valid empty pre-transaction state can publish that observation and stop with
`RUNTIME_REBOOT_REQUIRED`; this supplies no permission to reboot.

## Execution gate and mandatory stop

Before execution, require explicit authorization for this proposed one-shot scope
and claim the physical-inspect topic as `codex`. Recheck all private bindings,
prior receipt integrity, local evidence, and absence of the new run directory.
Stop on mismatch; do not silently update the review or choose another target/path.
Documentation-only commits do not change the tracked executable source digest.

Retain and await the execution-session handle. Every terminal outcome ends this
scope. If display/session results are lost, read only the receipt at the bound
path. Missing/partial/unknown readback remains uncertain; never invoke again.
No reboot, apply, cleanup, lock removal, doctor, baseline, plan, prepare, or second
inspect is included. The historical lost result remains in the record regardless
of the new outcome.

The unchanged executable baseline already passed 110 focused tests and a full
suite of 1,275 tests (1,267 passed, 8 skipped, zero failures), plus syntax checks.
This preparation does not claim a fresh full-suite run or any physical result.
