# Windows Runtime Recovery and Acceptance Implementation Plan

> Design: `docs/superpowers/specs/2026-07-30-windows-runtime-recovery-acceptance-design.md`

**Goal:** recover only the exact empty pre-transaction runtime residue, then
make the next standalone physical prepare reviewable and independently
measurable without weakening pinned SSH, ACL, topology, or uncertain-result
boundaries.

**Scope rule:** all implementation and verification in this plan is local to
the Mac repository. No physical Windows command, reboot, cleanup, or prepare is
authorized by this plan.

## Task 1: Finite empty-operation inventory

**Files**

- Modify: `windows/runtime-inventory.ps1`
- Modify: `test/runtime-inventory.test.mjs`

**Steps**

1. Add failing source/fixture tests for an empty staging operation, empty
   staging, unsafe ACL, reparse point, extra child, and exceptions thrown by the
   ACL and direct-child enumeration boundaries.
2. Prove the exact empty-operation state path still emits a pending operation
   rather than adopting or deleting it.
3. Wrap only the native ACL and direct-enumeration calls so escaped exceptions
   become exit 41 / `RUNTIME_STATE_UNSUPPORTED`.
4. Keep all owner, protected ACL, canonical path, reparse, child-count, and
   journal/generation checks unchanged.
5. Run `node --test test/runtime-inventory.test.mjs test/runtime-doctor.test.mjs`.

## Task 2: Add the auditable `RECOVERED` state

**Files**

- Modify: `src/runtime/runtime-state-store.mjs`
- Modify: `test/runtime-state-store.test.mjs`
- Modify: `src/runtime/ensure-runtime.mjs`
- Modify: `test/ensure-runtime.test.mjs`

**Steps**

1. Add failing validation tests for schema-1
   `FAILED/RUNTIME_COMPLETION_UNCERTAIN` to schema-2 `RECOVERED` with unchanged
   identities and fail-closed old-controller behavior.
2. Add failing tests that every other failure, changed identity, ready profile,
   or direct `RECOVERED -> READY` transition is rejected.
3. Add failing tests for `RECOVERED -> INVENTORY_READY` with a distinct
   operation ID and for `RECOVERED` never being returned as runtime ready.
4. Keep the field set unchanged, reserve schema 2 only for `RECOVERED`, and
   return to schema 1 only after validating the immutable recovery-commit record
   and creating a distinct fresh attempt.
5. Run `node --test test/runtime-state-store.test.mjs test/ensure-runtime.test.mjs`.

## Task 3: Owner-only recovery records and authorization tickets

**Files**

- Modify: `src/core/paths.mjs`
- Create: `src/runtime/runtime-recovery-store.mjs`
- Create: `test/runtime-recovery-store.test.mjs`

**Steps**

1. Define exact bounded schemas for the non-authorizing boot observation,
   immutable uniquely identified ten-minute ticket, consumed
   `AUTHORIZED_DELETE_ATTEMPT`, and immutable retryable `RECOVERY_COMMIT`
   record. Bind `ALREADY_ABSENT` to an exact earlier delete attempt and retain
   the no-replace temporary/final witness pair instead of path-unlinking it.
2. Add tests for canonical device/state/proof bindings, clock rollback, expiry,
   one-time consumption, atomic publication, safe ancestors, owner-only modes,
   symlink/uncontrolled-hardlink rejection, retained witness pairs,
   cross-ticket time rollback, read-side namespace stabilization, replacement
   races, concurrent calls, and real child `SIGKILL` exact retry.
3. Exclusively create records under the existing private per-device runtime
   hierarchy; fsync every created namespace and its naming parent, and serialize
   each operation with a permanent empty owner-only anchor plus the fixed macOS
   kernel lock. Never overwrite or select a "latest" ticket, and never print or
   persist raw commands, target addresses, private keys, or tokens.
4. Bind the commit record to both expected failed-state and proposed
   recovered-state digests; make state publication validate the record so every
   crash point is unambiguous.
5. Reuse the runtime state store's safe-path and atomic-write behavior without
   broad refactoring.
6. Run `node --test test/runtime-recovery-store.test.mjs test/paths.test.mjs`.

## Task 4: Exact Windows recovery inspect/apply protocol

**Files**

- Modify: `src/remote/windows-remote.mjs`
- Create: `src/runtime/runtime-recovery-remote.mjs`
- Create: `test/runtime-recovery-remote.test.mjs`
- Modify: `test/windows-remote.test.mjs`

**Steps**

1. Add failing wrapper tests for strict payload schemas, ASCII-only source,
   Administrator context, canonical non-reparse chains, exact ACLs, direct-child
   bounds, and redacted fixed output.
2. Implement a read-only inspect wrapper that accepts the bound operation ID,
   returns the exact classification and file identities, and includes a
   canonical event-12 Windows boot marker. Require the prior event record to
   remain queryable and the later record ID to increase; fail closed on clock,
   sleep/hibernate, Fast Startup without a new event, or cleared-log ambiguity.
3. Implement an apply wrapper that repeats inspection in one process, pins the
   runtime/staging/operation handles, acquires and validates the existing
   `Global\AgentRoadRuntimeMutation` mutex, checks the authorized proof, and
   deletes only the verified empty operation through
   `SetFileInformationByHandle(FileDispositionInfo)`.
4. Treat an absent exact operation as read-only convergence only with the
   matching durable `AUTHORIZED_DELETE_ATTEMPT`; classify an absent operation
   without that record as `EXTERNALLY_ABSENT` and fail closed.
5. Use `withTrustedSshSession`, pinned known-hosts, the cooperative device lock,
   bounded output, fixed timeouts, and exact stdout/stderr/exit validation.
6. Distinguish pre-dispatch finite rejection from post-dispatch unknown result;
   never retry delete automatically.
7. Run
   `node --test test/windows-remote.test.mjs test/runtime-recovery-remote.test.mjs test/trusted-ssh-session.test.mjs`.

## Task 5: Recovery controller and CLI

**Files**

- Create: `src/runtime/runtime-recovery.mjs`
- Modify: `src/core/paths.mjs`
- Modify: `src/runtime/runtime-recovery-store.mjs`
- Modify: `src/runtime/production-runtime-dependencies.mjs`
- Modify: `src/cli.mjs`
- Create: `test/runtime-recovery.test.mjs`
- Modify: `test/runtime-recovery-store.test.mjs`
- Modify: `test/paths.test.mjs`
- Modify: `test/production-runtime-dependencies.test.mjs`
- Modify: `test/cli-runtime.test.mjs`

**Steps**

1. Add failing store and controller tests for exact eligibility, first boot
   observation, required observed boot change, actionable inspect,
   expired/changed ticket, same-parent sequential inspect and bounded concurrent
   ticket publication returning one ticket ID, pre-publication operation
   contention returning `RUNTIME_ALREADY_RUNNING` without a sibling, forced
   sibling rejection, same-ticket replay, unknown
   acknowledgement, apply with zero delete on already-absent topology, Mac CAS
   retry, and final `RECOVERED` publication.
2. Implement `runtime-recover <device> --inspect [--prior-ticket <ticket-id>]` and exact
   `--apply --ticket <ticket-id>`; output only target/ticket short fingerprints,
   finite classification, actionable/reboot flags, disposition, and expiry.
   The optional prior ID is the immediate authorization parent; derive deletion
   provenance separately, never enumerate attempts or select a "latest"
   record, and never expose `authorizationParent`. Add bounded structured
   `RECOVERY_PARENT_REQUIRED` with `actionable: false` and `eligibleAfter`, plus
   `RECOVERY_APPLY_REQUIRED` for an exact durable commit, so the Mac Agent can
   recover a lost ticket ID without errors, logs, or a human copy.
3. Add a fixed GENESIS / EXPIRED_TICKET / AUTHORIZED_ATTEMPT parent schema,
   parent digest, schema-version-2 ticket field, and V2 ticket digest. Keep the
   proof, attempt, commit, and remote protocol schemas unchanged. An expired
   unconsumed EMPTY ticket may be a parent but cannot attribute absence or later
   be consumed; an expired ALREADY_ABSENT ticket carries its proof's original
   EMPTY attempt provenance.
4. Derive one
   `authorization-successors/<parent-digest>.json` path, publish and fsync an
   envelope containing the complete new ticket before publishing its exact
   ticket path, and repair only a cleanly missing ticket from that envelope,
   including after TTL. Resolver repair revalidates the same envelope, never
   enters entropy/minting, and lets a durable direct child outrank later clock
   rollback; only a verified empty slot uses the current TTL gate. New
   authorization records use `tickets-v2/` and
   `authorized-delete-attempts-v2/`; under the operation lock, any presence of
   legacy `tickets/` or `authorized-delete-attempts/` fails closed without read,
   enumeration, migration, or deletion. Same-parent retry returns the same ID;
   only a current exact, valid, unconsumed ticket is actionable. Mismatch or
   partial residue fails closed and never creates a sibling. A valid expired-
   child slot permanently retires its predecessor even after clock rollback.
5. Keep the nine-method scoped store facade, including the finite exact-parent
   `resolveAuthorizationSuccessor(parent)` lookup/clean-alias-repair capability.
   Make only its exact
   `readAuthorizedDeleteAttempt(ticketId)` optional after fully validating the
   ticket and successor. Apply reads ticket -> optional commit -> optional
   attempt; an attempt without a commit returns
   `RUNTIME_COMPLETION_UNCERTAIN` with zero remote calls, while a valid commit is
   CAS-only even after later ticket expiry. Preserve the original uncertain state on any unknown result and
   require a fresh inspect with the immediate parent.
6. Publish the immutable `RECOVERY_COMMIT` record before the state CAS, then
   require the state store to validate that exact record. An already-absent
   follow-up may converge only through the earlier authorized-attempt record.
   Hold one callback-scoped operation lock across safe optional record reads,
   consume, remote apply, commit, and CAS; clean missing observation/commit is
   distinct from corrupt or unsafe state. An existing commit without its exact
   authorized attempt is invalid and must never be repaired after remote work.
7. Verify neither command calls prepare, signs, downloads, or widens transport.
8. Run
   `node --test test/runtime-recovery-store.test.mjs test/runtime-recovery.test.mjs test/paths.test.mjs test/cli-runtime.test.mjs test/production-runtime-dependencies.test.mjs`.

## Task 6: Independent external baseline

**Files**

- Create: `windows/runtime-baseline.ps1`
- Create: `src/runtime/runtime-baseline.mjs`
- Create: `src/runtime/runtime-baseline-store.mjs`
- Create: `test/runtime-baseline.test.mjs`
- Create: `test/runtime-baseline-store.test.mjs`

**Steps**

1. Freeze exact bounded baseline/result schemas, data sources, primitive/null/
   enum/array ordering, and domain-separated HMAC inputs for each fixed declared
   non-runtime sentinel.
2. Add source tests forbidding mutation cmdlets and volatile fields, and fixture
   tests for stable ordering, count/size ceilings, redaction, and PowerShell 5.1
   syntax when `powershell.exe` is available.
3. Implement the checked-in read-only script so only counts and keyed HMACs
   leave Windows; keep the random key only in the immutable owner-only Mac
   baseline and Windows process memory.
4. Implement strict execution parsing plus owner-only atomic capture/compare
   records. A mismatch reports only the changed surface IDs, never raw facts.
5. Run
   `node --test test/runtime-baseline.test.mjs test/runtime-baseline-store.test.mjs`.

## Task 7: Baseline command surface

**Files**

- Modify: `src/runtime/production-runtime-dependencies.mjs`
- Modify: `src/cli.mjs`
- Modify: `test/production-runtime-dependencies.test.mjs`
- Modify: `test/cli-runtime.test.mjs`
- Modify: `docs/windows-physical-acceptance.md`

**Steps**

1. Add failing tests for `runtime-baseline <device> --capture` and exact-ID
   `--compare --baseline <baseline-id>`, strict syntax, immutable captures,
   canonical redacted results, and stable finite errors.
2. Wire pinned read-only execution and the baseline store.
3. Document the acceptance-only ordering: recover, doctor, capture, plan,
   approved prepare, compare.
4. Run `node --test test/cli-runtime.test.mjs test/production-runtime-dependencies.test.mjs`.

## Task 8: First-class plan authorization

**Files**

- Create: `src/runtime/runtime-plan-authorization.mjs`
- Create: `src/runtime/runtime-plan-ticket-store.mjs`
- Modify: `src/runtime/ensure-runtime.mjs`
- Modify: `src/runtime/production-runtime-dependencies.mjs`
- Modify: `src/cli.mjs`
- Create: `test/runtime-plan-authorization.test.mjs`
- Create: `test/runtime-plan-ticket-store.test.mjs`
- Modify: `test/ensure-runtime.test.mjs`
- Modify: `test/cli-runtime.test.mjs`

**Steps**

1. Add failing tests for the redacted human projection and a separate full
   authorization projection containing every mutation/source/verifier/scope and
   baseline-binding field.
2. Prove the digest changes for every mutation-relevant field and remains stable
   only for documented volatile operation/time/free-space/inventory fields.
3. Implement
   `runtime-plan <device> --profile core --baseline <baseline-id>` as
   target/state/catalog, exact immutable-baseline, signing-key/mutator-revision,
   and double-inventory validation with no sign/acquire/upload.
4. Exclusively create an immutable uniquely identified short-lived plan ticket;
   never overwrite or select a latest ticket.
5. Implement `prepare ... --approved <plan-ticket-id>` to load the exact ticket,
   require unchanged state/catalog/baseline/signing identity/mutator hashes,
   redo double inventory, reproduce the plan and digest, consume the ticket, and
   then enter the existing pipeline. Bare public `prepare` fails before its
   dependency factory is called.
6. Keep the automatic post-enrollment internal path unchanged and exempt from
   this standalone acceptance gate.
7. Run
   `node --test test/runtime-plan-authorization.test.mjs test/runtime-plan-ticket-store.test.mjs test/ensure-runtime.test.mjs test/cli-runtime.test.mjs`.

## Task 9: Reviews, full verification, and checkpoint

**Files**

- Modify: `docs/windows-engineering-pitfalls.md`
- Modify: `CURRENT_STATE.md`

**Steps**

1. Run focused tests after each task, then `npm test` and `npm run check` if the
   script exists.
2. Run static secret/path/recursive-delete scans and `git diff --check`.
3. Obtain independent spec, security, and code-quality reviews; resolve all
   Critical/High findings and record any accepted lower-risk limitation.
4. Update the physical acceptance runbook without performing it.
5. Record the exact failure lessons and local evidence in the <=30-line
   checkpoint.
6. Confirm `git status`, inspect the staged diff for secrets, then commit and
   push the private branch without force.
