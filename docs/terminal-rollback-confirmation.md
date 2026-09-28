# Initial core terminal rollback confirmation

This API resolves one narrow history: the Mac recorded completion uncertainty,
while Windows completed rollback after the first four core phases, before any
activation. It does not resume or repeat an installation, delete files, reboot,
or change the remote machine.

## CLI

Run `agent-road runtime-confirm-rollback <device-id>` to invoke this confirmation.
It accepts no other arguments and never starts a new installation. Exit 0 emits
only `ROLLBACK_CONFIRMED`, `FAILED / RUNTIME_INSTALL_FAILED`, schema version,
and `remoteMutation: false`; it means the rollback was confirmed, not that the
runtime is ready. Local evidence and state may be written. Exit 2 emits a finite
error code to stderr, with no raw evidence or transport details. An already
READY device is rejected with `RUNTIME_STATE_UNSUPPORTED`.

After successful confirmation, use the existing baseline, plan and approval
commands for a fresh installation:

```sh
agent-road runtime-baseline <device-id> --capture
agent-road runtime-plan <device-id> --profile core --baseline <baseline-id>
agent-road prepare <device-id> --profile core --approved <plan-ticket-id>
agent-road runtime-status <device-id>
agent-road doctor <device-id>
agent-road runtime-baseline <device-id> --compare --baseline <baseline-id>
```

Use the identifiers returned by the capture and review commands. Review the plan
before using its one-use approval ticket. An uncertain execution must be inspected
before attempting another operation.

## Admission and evidence

The local state must be schema 1, `FAILED / RUNTIME_COMPLETION_UNCERTAIN`, core
only, with no ready profiles. Two fresh, pinned SSH observations must agree on
exact capsule and journal bytes, the signed archive's length and hash, and the
absence of active/previous pointers, the new generation, and its rollback
removal tombstone. The Windows observer holds the existing mutation mutex and
uses the provisioner's ACL, topology, manifest, signature, controller-trust,
transaction, journal and archive validators. It invokes none of its mutators.

Both sides require an exact `rolled-back / succeeded` journal, phase `rollback`,
failure `RUNTIME_INTERNAL_ERROR`, completed phases `discover`, `verify-manifest`,
`verify-artifacts`, `snapshot`, changes `[work-created]`, and empty pointer
snapshots. Later phases and other failures remain unsupported. The controller
also verifies the capsule with its existing public key, device/operation/digest
bindings, unchanged pinned target, source revision, current state and key.
The observation interval is bounded to four minutes. No reboot predicate is
needed to confirm an already terminal rollback; fresh installation admission
still applies its own machine and reboot checks.

## Durable publication and state update

`terminal-rollback-v1/commit.json` lives inside the existing per-operation
recovery directory. It preserves the exact signed capsule, exact terminal
journal, source and target digests, original uncertain state, and proposed
finite state. Existing hardened immutable publication, owner-only file checks,
parent checks, fsync, readback, and the kernel operation lock are reused. The
record keeps the existing 16 KiB store limit; oversized evidence fails closed.

`RuntimeStateStore.confirmTerminalRollback` performs a dedicated compare-and-swap
only after independently validating that commit. It changes only the failure
code to `RUNTIME_INSTALL_FAILED` and advances `updatedAt`. Ordinary `transition`
still rejects `FAILED -> FAILED`; no transient `PLAN_READY` workaround is used.
The original uncertain record survives verbatim inside the immutable commit.

If commit publication or state-write acknowledgement is lost, reentry reads the
existing commit and current state. It can finish the exact pending local CAS or
return the already-written finite state. It does not invoke the observer again
when a valid commit exists. A conflicting state, target, or public key blocks a
pending CAS. The confirmation scope rejects escaped/concurrent use and drains
unawaited store calls before releasing its kernel lock.

After confirmation, ordinary baseline capture, plan review, one-use approval,
and provisioning handle a new operation. The provisioner's existing strict
terminal rollback turnover cleans its own old staging only during that newly
approved installation. Retained transactions and confirmation receipts remain.

## Validation

Protocol tests reject signature/operation/archive changes, active pointers,
unfinished or later rollback, noncanonical/unknown JSON and hostile accessors.
Controller tests cover observation/target/source/key/time drift and interruption
before or after local CAS. Store tests cover missing/corrupt/replaced receipts,
publication acknowledgement loss, state acknowledgement loss, scope lifetime,
held-lock verification, and unchanged ordinary transition restrictions.
Physical receipts are private under `terminal-rollback-observe-*` and
`terminal-rollback-confirm-*`; raw evidence is never terminal output.

The direct state-confirmation entry point also takes the operation lock before
the state-file lock; calls inside the controller reuse its live scope. A separate
existing advisory-lock race was exposed by the broader regression: disappearance
between `lstat` and the ACL probe is now rechecked as a previous owner releasing
its lock. Only `ENOENT` receives that treatment; exclusive acquisition and all
post-acquisition permission checks remain in place.
Nested state CAS promises are tracked through publication/readback, including
calls that a scoped caller starts without awaiting; the operation lock cannot
be released before that work drains.
