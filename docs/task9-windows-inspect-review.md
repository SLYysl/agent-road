# Windows-stage inspect: review and authorized result

## Authorized invocation result

On 2026-09-18 the user explicitly authorized the one-shot scope below. Private
source, device/state, both prior review/receipt bindings, local evidence, metadata,
and absent-run checks passed. The adapter was invoked exactly once; execution
session 67290 was retained and awaited through completion.

- Adapter/process exit: 2.
- Durable result: `FINITE_STOP / RUNTIME_STATE_UNSUPPORTED`.
- Last reported stage: `WINDOWS_CHILDREN`.
- Local readback exactly matched the invocation. Started and terminal records
  use schema 2, owner-only 0600 permissions, and single links.
- Registry/runtime-state bytes and both prior reviews/receipts are unchanged.
- Local evidence still shows operation/lock present, boot observation/commit
  absent, and zero current/legacy tickets, successors, and attempts.

The new protocol successfully returned a validated Windows stage for this one
invocation. It narrows the last boundary to child enumeration or subsequent
structure checks; it does not identify which directory, entry, comparison, or
exception failed. Helpers overwrite the stage, and later checks can retain it.
This is not full Windows recovery acceptance or proof that the target is ready.
The historical lost result remains unresolved.

No second inspect, remote diagnostic, reboot, apply, cleanup, lock removal,
doctor, baseline, plan, or prepare followed. The run is retained and occupied.
This single authorization has been used; the private review's PENDING value is
a preparation snapshot, not further execution authority. Next work can analyze
the child-enumeration/structure-check code locally without another remote call.

The remaining sections preserve the preparation-time review and authorized scope.

## Prepared locally

Reviewed on 2026-09-18 against executable baseline `daa3108`. The worktree was
clean. No Windows call, SSH probe, Tailscale query, or production CLI invocation
was made during preparation.

The same single eligible device remains selected. Registry and failed-state bytes
match both previous reviews. Both retained receipts read back as
`FINITE_STOP / RUNTIME_STATE_UNSUPPORTED`; the newer one includes
`lastStage: REMOTE_INSPECT`. Their review and receipt bindings remain intact.
Local evidence still shows the operation directory and persistent lock, no boot
observation or recovery commit, and zero current/legacy tickets, successors, and
attempts. Private-key and known-hosts owner/0600/canonical metadata checks pass;
no private-key contents were read and no fresh remote trust was established.

An exclusive owner-only local record at
`inspection-captures/windows-inspect-review.json` under the configured controller
root binds the device/root, registry/state digests, tracked executable-source
digest, baseline commit, two registered addresses, both prior reviews/receipts,
and the proposed fixed run path. It was fsynced and read back successfully. Its
contents must remain private. `authorization: PENDING` is a preparation snapshot,
never reusable execution authority.

The proposed neutral run label is `reviewed-windows-inspect-01`; that directory
is absent. Both used run directories remain retained. The older lost result is
still unresolved. This is a separately proposed current-state diagnostic check;
choosing a new path does not itself authorize a retry or resolve prior uncertainty.

## Exact proposed operation

Invoke the existing inspect adapter once with the privately bound device and run
path, without a prior ticket. Existing address selection may perform up to two
administrator probes (10 seconds each), followed by at most one recovery inspect
wrapper (30 seconds). Local prerequisites can stop earlier. The trusted SSH lock
may wait up to 15 minutes; preserve and await the execution session rather than
abandoning a live operation with an outer retry timeout.

The new inspect wrapper reports finite Windows stages on rejected results;
[protocol and platform limits](task9-windows-inspect-diagnostics.md) apply.
A reported stage is the last boundary reached, not an exact exception origin.
Unknown exceptions remain rejected. Pinned trust, Tailnet addresses, ACL checks,
strict stderr/exit handling, and apply behavior remain unchanged.

The wrapper reads governed Windows state; normal SSH logging and PowerShell
compilation artifacts can still be written. Controller effects include capture
records, existing lock handling, trusted SSH snapshots/known-hosts refresh, and
possibly publication of a boot observation. A valid empty pre-transaction state
may return `RUNTIME_REBOOT_REQUIRED`; that is a stop, not reboot permission.

## Execution gate and terminal handling

Obtain explicit authorization for this exact proposed one-shot scope. Claim the
physical-inspect topic as `codex`, then recheck all private bindings, both old
receipts, local evidence, and absence of the fixed new run. Any mismatch stops;
do not silently refresh bindings or select another device/path. Documentation-only
commits do not change the tracked executable-source digest.

Invoke once, retain/await the execution-session handle, then read back the local
receipt. Every terminal result ends this scope. Lost display/session results permit
only readback at that same path. Missing, partial, or invalid receipts retain
uncertainty; do not invoke again. Retain all capture directories after every result.
No second inspect, ad-hoc remote diagnostic, reboot, apply, cleanup, lock removal,
doctor, baseline, plan, or prepare is included.

## Validation evidence

The unchanged executable baseline previously passed 236 related tests with 2
platform skips and zero failures, plus syntax checking. A representative apply
invocation was byte-identical to the pre-diagnostics generator. This preparation
uses that recorded validation and fresh local binding/receipt checks; it does not
claim a new test-suite run. Windows PowerShell 5.1 and native API behavior remain
unverified because the local machine has no PowerShell runtime.
