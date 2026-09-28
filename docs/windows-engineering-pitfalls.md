# Agent Road Windows Engineering Pitfalls

This is the durable cross-slice record for mistakes observed while building the Windows bootstrap, pinned SSH remote layer, and managed runtime. `CURRENT_STATE.md` remains a short checkpoint; this file records the rule that should survive the current thread.

## 1. Do not use long encoded commands as the human transport

**Mistake:** Asking the user to move very long enrollment or diagnostic commands through chat, phone, or remote-desktop clipboard.

**Consequence:** One-time material can enter attachments and require revocation, while the short diagnostic fact is lost in thousands of encoded characters.

**Rule:** The human pastes one bounded stage-zero command and returns only a short phase/result code. After pinned SSH exists, upload scripts, manifests, and artifacts as files and invoke them with a short fixed command.

Evidence: `docs/superpowers/specs/2026-07-26-windows-bootstrap-design.md`; `docs/superpowers/specs/2026-07-29-windows-runtime-provisioning-design.md`.

## 2. PowerShell 5.1 collection and CIM projections are not a stable wire format

**Mistake:** Depending on implicit array flattening, `$null` enumeration, enum stringification, or one Windows build's CIM projection.

**Consequence:** Values became `System.Object[]`, empty replacement paths reached `File.Replace`, missing WinNAT classes looked like unsafe state, and legitimate firewall rules failed equality checks.

**Rule:** Filter nulls, flatten explicitly, validate types, and canonicalize every OS projection before comparing it. Treat only proven equivalent forms as equivalent. Keep PowerShell 5.1 as a small staging layer; use uploaded files and the managed PowerShell 7 runtime for normal work.

Evidence: `windows/bootstrap-stage-one.ps1`; `docs/superpowers/specs/2026-07-29-windows-runtime-provisioning-design.md`.

## 3. Compare firewall security semantics, not raw projected fields

**Mistake:** Requiring one exact text form for profile, CIDR, program path, interface type, or filter count, and treating broad application rules as explicit SSH rules.

**Consequence:** AppContainer rules, Tailscale rules, CIDR netmask forms, and expanded `%SystemRoot%` paths produced false `FIREWALL_CONFIG_FAILED` results.

**Rule:** Canonicalize each projection, then compare the strict security meaning. The accepted rule must still be limited to Tailnet-local addresses, Tailnet source ranges, TCP/22, and the verified Microsoft `sshd` program/service. Compatibility must never widen that boundary.

Evidence: `windows/bootstrap-stage-one.ps1`; `docs/superpowers/specs/2026-07-26-windows-bootstrap-design.md`.

## 4. Rollback must not erase bounded diagnostic evidence

**Mistake:** Retaining only a coarse failure code after rollback while clearing the last safe stage and validation trace.

**Consequence:** Repeated runs returned only `FIREWALL_CONFIG_FAILED` or `SSHD_CONFIG_INVALID`, forcing new enrollment attempts and manual probes.

**Rule:** Persist a bounded, secret-free failure site before rollback. Rollback may clear restored mutation records, but it must retain the finite code, last stage, and validation trail needed to diagnose the failure.

Evidence: `windows/bootstrap-stage-one.ps1`; `docs/superpowers/plans/2026-07-26-windows-bootstrap.md`.

## 5. OpenSSH configuration has scope as well as syntax

**Mistake:** Appending global directives after an active `Match` block, or accepting generated text without checking the effective policy.

**Consequence:** `ListenAddress` entered a `Match` scope and failed `sshd -t`; other candidates could be syntactically valid while resolving to the wrong authorization policy.

**Rule:** Flatten lines explicitly, place global directives before the first active `Match`, and place the Agent Road authorization block before generic administrator matches. Before activation run bounded `sshd -t` and `sshd -T`; the final authority remains a LocalSystem service start plus the Mac pinned-host-key SSH probe.

Evidence: `docs/superpowers/specs/2026-07-26-windows-bootstrap-design.md`; `docs/superpowers/plans/2026-07-26-windows-bootstrap.md`.

## 6. Connection bootstrap and runtime provisioning are different states

**Mistake:** Treating `CONNECTED_SSH_ONLY` as proof that Git, Node, Python, or browser tooling is ready, or putting all workstation setup into the first pasted command.

**Consequence:** The rescue channel becomes coupled to package managers, OS differences, and tool-install failures; a runtime failure can be misreported as a bootstrap failure.

**Rule:** Bootstrap establishes only Tailscale plus pinned SSH. Track transport and runtime independently. After the transport commit, run inventory, plan, provision, and verify through a separate idempotent state machine. Runtime failure must leave SSH usable.

Evidence: `docs/superpowers/specs/2026-07-29-windows-runtime-provisioning-design.md`; `docs/superpowers/plans/2026-07-29-windows-runtime-provisioning.md`.

## 7. A timeout after execution starts has unknown completion

**Mistake:** Treating a post-start timeout like a safe retryable network error.

**Consequence:** The first operation may already have mutated Windows; a second address attempt, retry, reboot, or diagnostic command can duplicate non-idempotent work and split state.

**Rule:** `executionStarted + timeout = completion uncertain`. Pin one address and one attempt, stop, then reconcile journals and observed facts on the next operation. Never blindly reinstall or retry.

Evidence: `docs/superpowers/specs/2026-07-28-remote-work-layer-design.md`; `docs/superpowers/specs/2026-07-29-windows-runtime-provisioning-design.md`; `CURRENT_STATE.md`.

## 8. Never interpolate rich text into a shell command string

**Risk identified on 2026-07-29:** Backticks inside a shell command string were interpreted by `zsh` as command substitution during a local documentation check.

**Consequence:** The shell can rewrite or execute content before the intended program receives it, corrupting diagnostics or causing unintended local execution.

**Rule:** Production process launches use argv arrays with `shell: false`. Script bodies move through files or integrity-checked stdin frames. For ad hoc local inspection, avoid embedding backticks or dynamic document text in a shell command string.

Evidence: `src/process/run-process.mjs`; `docs/superpowers/plans/2026-07-26-windows-bootstrap.md`.

## 9. A pending operation is not automatically a conflicting operation

**Mistake caught during runtime-plan review:** Treating every non-null `pendingOperationId` as a conflict.

**Consequence:** A safe retry of the same operation could never reach reconciliation, encouraging a fresh operation that ignores uncertain prior mutations.

**Rule:** Null means `new`, the same operation ID means `reconcile`, and a different ID means `conflict`. Reconcile must inspect the journal and active pointer; it is never a fresh apply.

Evidence: `src/runtime/runtime-plan.mjs`; `docs/superpowers/specs/2026-07-29-windows-runtime-provisioning-design.md`.

## 10. Version labels alone do not prove safe repair or rollback

**Mistakes caught during runtime-plan review:** Naming an unverified older artifact as a rollback target; checking only digest format; and treating a verified same-revision catalog digest mismatch as ordinary repair.

**Consequence:** A corrupt generation can be presented as a rescue point, or one catalog revision can be silently redefined with different bytes.

**Rule:** Bind digests to canonical validated content in tests and plans. Only a supported, verified generation may supply a rollback version. A verified newer catalog revision blocks downgrade; a verified same-revision/different-digest state is equivocation and fails closed.

Evidence: `src/runtime/runtime-plan.mjs`; `test/runtime-plan.test.mjs`.

## 11. A signed manifest still needs a first-delivery trust anchor

**Risk identified during runtime-capsule design:** Uploading a public key beside a signed manifest and then calling the signature trusted without explaining why that key is trusted.

**Consequence:** An attacker who can replace both files can create a self-consistent but untrusted capsule. A digest can also become circular if the manifest tries to contain its own hash.

**Rule:** Pinned SSH anchors the first restricted delivery of the existing controller public key. Persist it and require exact matches on every later operation. Keep a stable `generationDigest` for desired content separate from the operation-specific `manifestDigest`; sign the domain-separated canonical manifest bytes.

Evidence: `docs/superpowers/specs/2026-07-29-windows-runtime-provisioning-design.md`.

## 12. Run decisive fail-closed state checks before incidental inventory probes

**Mistake caught during runtime-doctor review:** Checking CIM, disk, registry, and session facts before checking whether an unsupported runtime root already exists.

**Consequence:** An incidental probe failure could hide the more important `RUNTIME_STATE_UNSUPPORTED` condition and return the wrong finite recovery path.

**Rule:** Perform the highest-priority state classification first, then gather secondary facts. Lock the ordering with a focused test, not only keyword-presence assertions.

Evidence: `windows/runtime-inventory.ps1`; `test/runtime-doctor.test.mjs`.

## 13. A timeout and an atomic publish claim must include cleanup and crash recovery

**Mistakes caught during artifact-cache review:** Clearing the deadline before awaiting stream cancellation; checking time only around network reads while later hashing could still publish success; and using a hardlink/lock sequence whose narrow crash window permanently poisoned the cache.

**Consequence:** A ten-second acquisition could hang forever, return success after its deadline, or require manual deletion after a normal process crash.

**Rule:** Use one absolute deadline across lock wait, I/O, verification, publication, and bounded cleanup. After expiry, never return success or start publication. Every multi-step atomic-publication claim must have a tested crash reconciliation path that deletes only a cryptographically and structurally proven owned orphan; unknown links, locks, or residue fail closed.

Evidence: `src/runtime/artifact-cache.mjs`; `test/runtime-artifact-cache.test.mjs`; `docs/superpowers/specs/2026-07-29-windows-runtime-provisioning-design.md`.

## 14. Never verify mutable dependency input by reusing the same buffer

**Mistakes caught during manifest review:** Passing the canonical signed bytes directly to an injected signer and then verifying that same mutable `Buffer`; cloning JSON into `{}` so an enumerable `__proto__` field could disappear through the legacy prototype setter.

**Consequence:** A signer could mutate and sign different bytes while the returned manifest appeared valid, and a non-exact nested plan could collapse into the expected JSON form.

**Rule:** Give dependencies disposable copies and verify against independently reconstructed canonical bytes. Hostile-safe JSON snapshots use null-prototype containers (or reject dangerous keys) so every enumerable data field survives exact comparison.

Evidence: `src/runtime/runtime-manifest.mjs`; `test/runtime-manifest.test.mjs`.

## 15. Internal limits must compose across the entire pipeline

**Mistake caught during provision-upload review:** Letting catalog/cache accept
8 GiB and 64 components while snapshots, SCP wrappers, and PowerShell frames
could handle only 256 MiB and fewer than 56 maximum-sized records.

**Consequence:** Agent Road could sign a locally valid plan that its own next
layer could never transmit, sometimes discovering that fact only after Windows
had already been mutated.

**Rule:** One v1 contract applies end to end: 256 MiB per artifact and 32
components. Boundary tests use maximum-length legal fields and every fixed
invocation is constructed before dispatching the first remote mutation.

Evidence: `src/runtime/runtime-catalog.mjs`; `src/runtime/artifact-cache.mjs`;
`src/runtime/provision-upload.mjs`; `src/remote/windows-remote.mjs`.

## 16. Effective Windows ACLs include inherited rules

**Mistake caught during provision-upload review:** Inspecting only explicit ACEs
on an SCP-created temp file even though the file normally inherits the exact
Administrators/SYSTEM rules from its protected parent.

**Consequence:** A legitimate first upload is rejected before publication,
despite having the intended effective security boundary.

**Rule:** Revalidate the restricted parent, inspect explicit plus inherited
effective ACEs, reject every extra or deny rule, then convert the temp to the
protected exact final-file ACL and verify it again.

Evidence: `src/remote/windows-remote.mjs`; `test/windows-remote.test.mjs`.

## 17. A completion marker requires one final whole-batch verification

**Mistake caught during provision-upload review:** Publishing `capsule.json`
after checking each artifact only at an earlier point in the transfer.

**Consequence:** An earlier finalized component could disappear or change while
the capsule still made the batch look complete.

**Rule:** Inspect before transfer and reinspect every finalized component
immediately before the capsule. The capsule is the final marker only when every
artifact is exact at that boundary. One operation ID also binds permanently to
one original capsule and manifest digest.

Evidence: `src/runtime/provision-upload.mjs`; `test/provision-upload.test.mjs`.

## 18. Green timeout tests must prove resource reclamation

**Mistakes caught during independent cache review:** A cancellation test asserted
only that timeout returned; a final lock was exposed before its JSON was
complete; a late fetch body and an oversized chunk escaped the intended bounds;
and POSIX mode checks ignored macOS extended ACLs.

**Consequence:** All focused tests passed while crashes could permanently poison
the cache, late network bodies could leak, a single chunk could exhaust memory,
or another local account could mutate an apparently `0700` cache.

**Rule:** Assert the cleanup action itself, atomically publish complete lock
records, bound chunks before allocating/copying, reclaim late response bodies,
and validate the platform's effective ACL rather than mode bits alone. Test
normal SIGKILL residue, not only caught exceptions.

Evidence: `src/runtime/artifact-cache.mjs`; `test/runtime-artifact-cache.test.mjs`.

## 19. One remote transaction must own one SSH session and one address

**Mistake caught during controller integration:** Composing public `exec` and
`put` helpers inside a larger provisioning operation. Each helper acquired its
own device lock and could select a different Tailnet address.

**Consequence:** The controller could self-deadlock, or inventory one endpoint
and mutate another after fallback ordering changed.

**Rule:** Prepare all local inputs first, then hold one trusted SSH session,
select one pinned address once, and pass single-use prepared capabilities to
inventory, upload, and apply. Do not nest public lock-owning helpers.

Evidence: `src/remote/remote-exec.mjs`; `src/runtime/provision-upload.mjs`;
`src/runtime/runtime-provision.mjs`.

## 20. A fixed provisioner that reads stdin needs its own fixed wrapper

**Mistake caught during core wiring:** Reusing the generic remote-exec wrapper,
which deliberately closes the child process stdin without writing any bytes,
for a provisioner whose only input is a canonical transaction record.

**Consequence:** The fixed script could never receive its operation binding, or
the generic wrapper would have to gain an unsafe optional command/input mode.

**Rule:** Keep generic exec input-free. Use a dedicated constant wrapper that
writes the exact bounded UTF-8 record, flushes it, and closes child stdin. The
record contains only schema version, operation ID, and manifest digest.

Evidence: `src/remote/windows-remote.mjs`; `test/windows-remote.test.mjs`;
`windows/runtime-provision-core.ps1`.

## 21. An abandoned Windows mutex transfers ownership to the waiter

**Mistake caught during provisioner review:** Treating
`AbandonedMutexException` as a failed lock acquisition.

**Consequence:** A crashed prior provisioner could permanently block recovery,
even though Windows had granted the mutex to the current thread.

**Rule:** When `WaitOne` throws `AbandonedMutexException`, treat the mutex as
acquired, continue reconciliation, and still release and dispose it in the
normal `finally` path.

Evidence: `windows/runtime-provision-core.ps1`;
`test/runtime-provision.test.mjs`.

## 22. Dead-lock cleanup is itself a concurrent protocol

**Mistake caught during cache stress testing:** Two recovery contenders both
proved the same dead lock, then one deleted it while the other treated `ENOENT`
as cleanup failure or attempted to act on a replacement path.

**Consequence:** Valid concurrent acquisition intermittently failed, and a
stale recovery actor could threaten a new owner's lock.

**Rule:** Serialize same-process recovery, bind every deletion to an exact
snapshot, and treat disappearance or replacement as a signal to re-inspect and
retry. Never delete the replacement. Stress the two-contender race repeatedly.

Evidence: `src/runtime/artifact-cache.mjs`;
`test/runtime-artifact-cache.test.mjs`.

## 23. Committed cleanup must be recoverable before full staging validation

**Mistake caught during transaction review:** Requiring the original complete
upload tree before reading a committed journal, and validating cleanup residue
as though no earlier deletion could have completed.

**Consequence:** A crash after durable commit but during staging cleanup made a
healthy active runtime impossible to acknowledge or clean without manual work.

**Rule:** Classify and cryptographically revalidate the committed active
generation first. Then allow only a safe remaining subset of the exact capsule,
artifact, and known `.next` nodes; reject unknown children and clean the subset
idempotently before reporting certain success.

Evidence: `windows/runtime-provision-core.ps1`;
`test/runtime-provision.test.mjs`;
`docs/superpowers/specs/2026-07-29-windows-runtime-core-contract.md`.

## 35. The bootstrap producer must satisfy the runtime consumer's ACL contract

**Mistake caught during the final cross-layer review:** Requiring the runtime
core and inventory to accept only a protected, explicit two-rule stage-zero
journal while the stage-zero producer created its temporary file with ordinary
`File.Open(CreateNew)` inheritance.

**Consequence:** Bootstrap could report success, but the first SSH-driven
runtime inventory would deterministically reject its identity journal. On an
older installation, `File.Replace` could also retain or merge the destination
DACL, so a secure temporary file alone did not migrate the legacy final ACL.

**Rule:** Freeze producer and both consumers in one cross-layer test. Create the
journal temporary file with the exact protected file descriptor, flush and
verify its bytes and ACL, publish the content atomically, then explicitly apply
and verify the exact final ACL to migrate a preexisting destination. Keep the
runtime consumer strict; never solve a producer mismatch by accepting inherited
or user-owned state.

**v1 residual boundary:** Migrating an already permissive destination with
`File.Replace` followed by `SetAccessControl` is recoverable and fail-closed,
but the content replacement and ACL migration are not one atomic filesystem
operation. A crash or a process that already held suitable access can observe
that interval. Stage zero therefore verifies both final ACL and bytes before
continuing, and runtime remains strict on retry; this is not evidence of
hostile-local or sudden-power-loss atomicity.

Evidence: `src/enrollment/windows-stage-zero.mjs`;
`windows/runtime-provision-core.ps1`;
`windows/runtime-inventory.ps1`;
`test/windows-stage-zero.test.mjs`.

## 24. An absolute deadline must be checked after every awaited operation

**Mistake caught during cache review:** Checking the clock only before starting
an asynchronous operation. A synchronously blocking redirect-body cancellation
could finish after expiry and still authorize the next network request before
the timer callback ran.

**Consequence:** The function eventually returned a timeout, but it had already
performed a post-deadline fetch and therefore exceeded the promised side-effect
boundary.

**Rule:** Invoke the operation inside the deadline guard, check the monotonic
clock again after both fulfillment and rejection, and never begin the next
side effect from a result that settled after expiry.

Evidence: `src/runtime/artifact-cache.mjs`;
`test/runtime-artifact-cache.test.mjs`.

## 25. Bind an existing journal before validating a new transaction

**Mistake caught during provisioner review:** Loading journal A, then validating
operation B's capsule and machine state before proving that the journal belongs
to B. An early B failure could enter rollback using A's snapshots.

**Consequence:** A different operation could rewrite A's journal or pointers and
delete a generation derived from the ambient B invocation.

**Rule:** Immediately bind every nonterminal journal to the exact stdin operation
ID and manifest digest. Until that succeeds, no trust mutation, precondition
check, rollback, pointer write, or generation deletion is authorized. Deletion
targets come from the bound journal plus a verified receipt, never ambient input.

Evidence: `windows/runtime-provision-core.ps1`;
`test/runtime-provision.test.mjs`.

## 26. Rollback needs the same compare-before-write discipline as activation

**Mistake caught during provisioner review:** Forward pointer replacement
accepted only the exact before/after values, while rollback unconditionally
restored snapshots over whatever was currently present.

**Consequence:** An unknown third pointer state could be destroyed under the
label of recovery, making a diagnosable conflict into data loss.

**Rule:** Validate all rollback pointer transitions before changing either one.
Each current value must be the exact snapshot or this transaction's verified
new value; otherwise change nothing and return rollback-incomplete.

Evidence: `windows/runtime-provision-core.ps1`;
`test/runtime-provision.test.mjs`.

## 27. A committed journal is a turnover boundary, not a permanent mutex

**Mistake caught during provisioner review:** Treating every committed journal
whose operation ID differed from the new request as an operation conflict.

**Consequence:** The first successful PowerShell generation made every later
upgrade unreachable.

**Rule:** Replay the exact committed operation idempotently. For a wholly new
operation, first revalidate the committed runtime and finish only its strictly
owned cleanup, then atomically initialize a new journal; partial identity reuse
remains a conflict.

Evidence: `windows/runtime-provision-core.ps1`;
`test/runtime-provision.test.mjs`.

## 28. Dead-lock recovery needs a cross-process gate

**Mistake caught during cache review:** Serializing dead-lock inspection and
recovery with an in-process set. Two independent Agent Road processes could
both decide that the same owner was dead, while one of them was already
publishing the replacement lock.

**Consequence:** A recovery path could remove or misclassify another process's
new lock, turning safe contention into corruption or false success.

**Rule:** Guard inspect/recover/create with an atomically created owner-only
directory. Remove only the exact gate created by this process after revalidating
its identity and every pinned parent; preserve unknown or abandoned gates and
fail closed. Verify the rule with real child-process contention, not only two
promises in one process.

Evidence: `src/runtime/artifact-cache.mjs`;
`test/runtime-artifact-cache.test.mjs`.

## 29. One mutation domain must have one verified global mutex

**Mistake caught during provisioner review:** Falling back from a Windows
global named mutex to a file lock when mutex creation, ACL validation, or name
resolution failed.

**Consequence:** Two callers could enter different lock domains and mutate the
same runtime concurrently, while both believed they had exclusive ownership.

**Rule:** Use one fixed `Global\...` mutex for the complete transaction, verify
its owner and exact ACL after opening it, and fail closed on every setup error.
Only ordinary contention maps to already-running; there is no fallback lock.

Evidence: `windows/runtime-provision-core.ps1`;
`test/runtime-provision.test.mjs`.

## 30. Recursive generation deletion needs a deterministic tombstone

**Mistake caught during recovery review:** Deleting an unreferenced generation
directly after pointer checks.

**Consequence:** Power loss halfway through recursive deletion left a partial
directory whose identity and cleanup authority could no longer be proven.

**Rule:** Fully verify the generation, recheck that no pointer references it,
then rename it on the same volume to one transaction-bound `.retired-*` or
`.rollback-*` tombstone. Recovery may delete only the exact allowlisted partial
tombstone and must reject source-plus-tombstone ambiguity.

Evidence: `windows/runtime-provision-core.ps1`;
`test/runtime-provision.test.mjs`.

## 31. Runtime inventory cannot remain an absent-only bootstrap probe

**Mistake caught during lifecycle review:** Designing inventory only for the
first installation and rejecting every managed runtime node as residue.

**Consequence:** The first successful install made later inventory, repair, and
upgrade planning fail closed, so self-provisioning worked only once.

**Rule:** The read-only inventory must recognize the finite installed,
nonterminal, committed, rolled-back, staging, and tombstone topologies used by
the provisioner. It may report an active generation only after revalidating its
pointer, receipt, signed capsule, pinned key, fixed hashes, signer, version, and
smoke test; unknown nodes still fail closed.

Evidence: `windows/runtime-inventory.ps1`;
`test/runtime-doctor.test.mjs`;
`windows/runtime-provision-core.ps1`.

## 32. A signed expansion maximum is a ceiling, not an expected size

**Mistake caught during contract review:** Saying actual ZIP output must equal
`maximumExpandedBytes`, even though the field is a conservative extraction and
disk-planning bound.

**Consequence:** The written contract contradicted the catalog and the safe
streaming extractor; implementing it literally would reject every archive
whose real size was below its conservative bound.

**Rule:** The actual bytes for every entry and the aggregate must exactly equal
the ZIP metadata, while both remain at or below the signed maximum. Freeze that
distinction in the contract and regression tests.

Evidence: `docs/superpowers/specs/2026-07-29-windows-runtime-core-contract.md`;
`windows/runtime-provision-core.ps1`;
`test/runtime-provision.test.mjs`.

## 33. Apply the final descriptor at creation, with a translated owner

**Mistake caught on physical Windows and again during runtime review:** Creating
an owned node first and repairing its ACL afterward, or passing the built-in
Administrators `SecurityIdentifier` directly to `SetOwner`.

**Consequence:** A crash can expose an inherited intermediate node, while some
Windows builds reject the raw SID owner with “the security identifier is not
allowed to be the owner of this object.” Either result can make first-run
recovery fail before the Agent has a stable runtime.

**Rule:** Translate the Administrators SID to `NTAccount`, supply the protected
descriptor to the security-aware directory or file creation API, then reread
and verify the canonical owner and exact two-rule ACL. Post-creation ACL repair
is not a substitute for secure creation.

Evidence: `windows/runtime-provision-core.ps1`;
`src/remote/windows-remote.mjs`;
`test/runtime-provision.test.mjs`;
`test/windows-remote.test.mjs`.

## 34. Secure creation does not make file contents atomic

**Mistake caught during trust-anchor review:** Writing the first pinned
controller key directly to its final, securely created file before a journal
exists.

**Consequence:** Power loss after creation but before the final flush can leave
an exact-ACL partial trust file. Later runs must not overwrite a mismatching
pinned key, so the machine becomes fail-closed but unrecoverable.

**Rule:** Write and flush the initial key to one fixed operation-bound file in
the same-volume work directory, verify its exact ACL, bytes, and hash, then
publish it without replacement using a write-through rename. Recovery may
replace only that recognized temporary file after revalidating the signed
staged operation; it never deletes or replaces an existing final trust key.

Evidence: `windows/runtime-provision-core.ps1`;
`test/runtime-provision.test.mjs`;
`docs/superpowers/specs/2026-07-29-windows-runtime-core-contract.md`.

## 36. A runtime status summary is not a durable resume capsule

**Mistake caught during Task 6 orchestration review:** Assuming that an operation ID plus manifest and generation digests is enough for a new Mac process to resume a signed remote transaction.

**Consequence:** The controller cannot reproduce the original `createdAt`, inventory-bound plan, canonical capsule bytes, or signature. Re-signing reconstructed data under the old operation ID would violate the same-operation identity contract, while starting a new operation could collide with Windows residue.

**Rule:** Until the controller persists the exact bounded signed capsule and the facts needed to validate it, persisted intermediate and completion-uncertain states must fail closed. Do not advertise or fault-inject automatic controller-crash recovery. A later slice must add owner-only durable capsule storage, exact readback validation, and same-operation reconciliation before enabling that path.

Evidence: `src/runtime/ensure-runtime.mjs`;
`src/runtime/runtime-state-store.mjs`;
`docs/superpowers/specs/2026-07-29-windows-runtime-provisioning-design.md`.

## 37. Missing state is not authoritative while its publication lock exists

**Mistake caught during Task 6 state-store review:** Returning
`UNPROVISIONED` as soon as `state.json` was absent, even when the reader had
already observed the writer's live lock.

**Consequence:** A read overlapping first publication could report a false
missing state instead of the record that the active writer was about to make
durable.

**Rule:** If either the state or its lock is observed, enter the same cooperative
lock domain and decide whether state is absent only after acquiring the lock.
The no-lock/no-state case may still linearize before a later writer begins.

Evidence: `src/runtime/runtime-state-store.mjs`;
`test/runtime-state-store.test.mjs`.

## 38. ACL checks need a closed observation window

**Mistake caught during Task 6 state-store review:** Probing a directory's macOS
ACL once, then accepting the endpoint after checking only identity, mode, and
owner. An ACL-only mutation does not change those fields.

**Consequence:** An ACL introduced between the probe and final endpoint check
could escape detection. Comparing directory `ctime` instead also rejected
legitimate concurrent lock-file creation.

**Rule:** Probe the ACL both before and after canonical-path validation, and
require both observations to be clean. Keep directory-entry concurrency out of
the ACL predicate; verify the injection window with a deterministic test hook.

Evidence: `src/runtime/runtime-state-store.mjs`;
`test/runtime-state-store.test.mjs`.

## 39. Exact inventory evidence is not a stability predicate

**Mistake caught during the first physical core prepare:** Comparing two exact
inventory digests to decide whether the target stayed safe between read-only
planning and provisioning. Exact `freeBytes` legitimately changed between the
two observations, so an otherwise unchanged machine failed before mutation
with `RUNTIME_INVENTORY_CHANGED`.

**Consequence:** A cryptographically correct audit digest made the physical
workflow unusable, while adding a tolerance or coarse disk bucket would have
hidden a real crossing of the signed disk requirement.

**Rule:** Keep the exact canonical inventory digest as signed evidence. For
stability, compare every nonvolatile fact exactly and compare disk space only
by whether both observations are on the same side of `requiredFreeBytes`.
Reject either threshold crossing. Bind the second exact snapshot into the
signed operation, repeat the semantic check before upload, and retain the
Windows-side post-upload reserve check before incoming new-plan mutation.
Exact-owned terminal reconciliation cleanup is the sole pre-gate carve-out.

Evidence: `src/runtime/runtime-inventory.mjs`;
`src/runtime/ensure-runtime.mjs`;
`src/runtime/runtime-provision.mjs`;
`windows/runtime-provision-core.ps1`;
`test/runtime-inventory.test.mjs`.

## 40. Same-device physical probes must be serialized

**Mistake caught during physical diagnosis:** Running overlapping controller
diagnostics against one Windows device while the transport used a cooperative
SSH identity lock.

**Consequence:** Lock contention briefly surfaced as `DEVICE_NOT_READY`, which
looked like a reboot or network failure even though the pinned transport was
healthy.

**Rule:** Run `doctor`, `prepare`, `runtime-status`, and ad-hoc SSH probes for
one device serially. Treat a command as complete only after its bounded result
and exit status are observed; blank or delayed terminal output is not success.

Evidence: `src/remote/ssh-identity-lock.mjs`;
`src/runtime/ensure-runtime.mjs`;
`docs/windows-physical-acceptance.md`.

## 41. Finish the acceptance review and capture independent baselines before mutation

**Mistake caught during the second physical core prepare attempt:** Starting the
authorized mutation while a read-only acceptance review was still running. A
custom local script did display the expected actionable core plan, but the
review later identified that the runbook had no first-class plan command bound
to the plan consumed by `prepare`, and no exact pre-mutation baselines for PATH,
registry registration, services, scheduled tasks, firewall, profiles, or
unrelated ACLs.

**Consequence:** The runtime result can still be evaluated fail-closed, but a
post-hoc sample cannot prove those external machine surfaces were unchanged.
The physical attempt therefore cannot satisfy the full acceptance claim even
if runtime publication is later recovered.

**Rule:** Treat the acceptance review and every required baseline as a hard
pre-mutation gate. Do not dispatch `prepare` until they have completed. Provide
a first-class bounded plan/authorization surface, or an equivalent exact plan
binding, plus checked-in pre/post baseline commands before the next physical
attempt. A custom one-off plan printout is not a substitute for the documented
and reproducible evidence boundary.

Evidence: `docs/windows-physical-acceptance.md`;
`docs/superpowers/plans/2026-07-29-windows-runtime-provisioning.md`.

## 42. Provision-init uncertainty can leave an empty operation root

**Mistake exposed on physical Windows:** Treating the provision-init wrapper as
one indivisible acknowledgement boundary. The wrapper created the exact
operation directory, but no transaction directory, capsule, artifact, trust
key, journal, active pointer, or version generation existed when the controller
returned `RUNTIME_COMPLETION_UNCERTAIN`.

**Consequence:** The Mac correctly persists a bound uncertain failure and
refuses a blind retry, while the Windows inventory path cannot currently
classify the exact empty pre-transaction residue. On the observed PowerShell
5.1 machine the inventory script returned exit `42` with empty stdout/stderr,
so `doctor` surfaced only `RUNTIME_INVENTORY_FAILED`.

**Rule:** Add a physical-semantic regression for an exact empty staging
operation root. Inventory must classify it deterministically without relaxing
ACL/path ownership, and recovery must be a separately reviewed exact-owned
reconciliation step. Never replay `prepare`, infer commit, or delete an
operation directory merely because it looks empty.

Evidence: `src/runtime/provision-upload.mjs`;
`src/runtime/runtime-provision.mjs`;
`windows/runtime-inventory.ps1`;
`windows/runtime-provision-core.ps1`.

## 43. Parse canonical exec output even when the CLI process exits nonzero

**Mistake caught while diagnosing the uncertain operation:** A local diagnostic
wrapper treated any nonzero `agent-road exec` process status as a transport
failure and discarded its stdout.

**Consequence:** The first read-only probe hid the useful distinction between a
CLI failure and a successfully transported remote script whose own exit code
was nonzero.

**Rule:** For `exec`, first require the CLI's stderr contract, then parse the
canonical stdout envelope even when the CLI process status is nonzero. Compare
the process status with the envelope's remote exit code before classifying the
result. Do not print raw remote stdout/stderr while diagnosing a bounded
failure.

Evidence: `src/cli.mjs`; `test/cli-remote-work.test.mjs`.

## 44. A Mac lock does not serialize independent Windows mutations

**Mistake caught during recovery design review:** Treating the controller's
per-device lock as sufficient after an SSH call has dispatched work.

**Consequence:** A disconnected Windows process or a second controller can
still mutate the same runtime tree after the Mac lock is gone.

**Rule:** Every Windows runtime mutator must acquire the same fixed global
mutex, validate its owner and DACL, and hold it through final postconditions.
The Mac lock remains useful, but it is not the Windows concurrency boundary.

## 45. Never authorize an implicit latest ticket

**Mistake caught during plan and recovery review:** Allowing a short-lived
authorization to be found by recency or replaced at a stable path.

**Consequence:** Concurrent inspection or planning can substitute a different
target, proof, baseline, artifact, or mutation decision at apply time.

**Rule:** Create every recovery, baseline, and plan record immutably with an
unpredictable exact ID. Require that full ID at apply/compare, forbid `latest`,
and consume mutation tickets by same-filesystem no-replace rename before
dispatch.

## 46. Cross-machine timestamps do not prove a reboot

**Mistake caught during uncertain-result review:** Comparing a Mac failure time
with a Windows boot time, or assuming Kernel-General event 12 has a portable
numeric `BootId` field.

**Consequence:** Clock changes, localization, Fast Startup, sleep, hibernation,
or event-log replacement can produce a false safety barrier.

**Rule:** Persist the exact bounded event-12 record marker. On the later inspect,
require the prior record to remain queryable and a new greater EventRecordID;
never order clocks. If Windows emits no new qualifying record or the log is
cleared, malformed, or unreadable, fail closed.

## 47. Uncertain cleanup needs durable attribution before deletion

**Mistake caught during crash-consistency review:** Treating an absent operation
as proof of authorized cleanup and writing audit state at the same time as the
final state transition.

**Consequence:** A crash can make external deletion indistinguishable from an
authorized lost acknowledgement, or leave `RECOVERED` without its proof.

**Rule:** Publish an immutable `AUTHORIZED_DELETE_ATTEMPT` before dispatch.
Without it, absence is `EXTERNALLY_ABSENT`. Publish the exact
`RECOVERY_COMMIT` before the state CAS, and make every `RECOVERED` read validate
that record.

## 48. The inventory script has no safe growth margin

**Mistake exposed while normalizing PowerShell 5.1 exceptions:** Adding finite
ACL and directory-enumeration guards brought `windows/runtime-inventory.ps1`
to 65,509 bytes under a checked 65,536-byte source ceiling.

**Consequence:** A trivial diagnostic or formatting addition can fail the
source contract even when behavior is correct.

**Rule:** Do not expand this script casually. Split or deliberately revise the
transport/source budget before adding another inventory feature. Keep the exact
Windows PowerShell 5.1 fixture as a physical gate; macOS can only skip it, not
prove it.

## 49. Simulated exceptions do not prove controller-crash recovery

**Mistakes caught during immutable recovery-store review:** Treating a hook
exception as process death, treating a visible hard-link pair as durable before
its parent directory is synced, cleaning a stale lock by PID inference, and
checking only the current ticket's local timestamps for `ALREADY_ABSENT`.

**Consequence:** A real crash could leave a cooperative lock forever, a reader
could accept publication that had not crossed the namespace durability barrier,
or a rolled-back controller clock could finalize an earlier authorization out
of order.

**Rule:** Exercise the crash point with a real child `SIGKILL`. Hold recovery
serialization through a permanent owner-only anchor and a kernel-released lock;
never unlink or infer a stale lock from process metadata. Writers must fsync the
record and exact naming directories, while readers must sync and then revalidate
the record, publication pair, path, and bytes. For `ALREADY_ABSENT`, require the
prior attempt's authorization time not to follow the new ticket inspection.

## 50. Pure transition rejection must precede disk-state verification

**Mistake caught during schema-2 recovery integration:** Moving the only
semantic `assertTransition` behind layout creation, lock acquisition, and
persisted commit validation so a corrupt current record would win error
precedence.

**Consequence:** A structurally valid but semantically illegal request could
create runtime directories or lock files and return a disk-state or concurrency
code instead of `RUNTIME_INPUT_INVALID`.

**Rule:** Keep canonical and semantic transition validation as a zero-write
preflight before computing or creating filesystem state. After acquiring the
state lock, independently validate the persisted current `RECOVERED` commit,
compare CAS state, optionally repeat transition validation defensively,
validate an exact next `RECOVERED` commit before publication, and revalidate a
saved `RECOVERED` record after publication. Prove the preflight boundary with a
RED-then-GREEN test against a nonexistent runtime root.

## 51. PowerShell return enumeration can invent a child

**Mistake caught during Task 4 review:** `Get-DirectChildren` returned
`,$values.ToArray()` while every caller also captured the pipeline with
`@(...)`.

**Consequence:** An empty directory became one nested empty array, so
`CLEAN_ABSENT` was unreachable and a successful deletion could never satisfy
its postcondition.

**Rule:** Decide which layer owns PowerShell collection preservation. Here the
function returns `$values.ToArray()` normally and the caller alone uses
`@(...)`; execute 0/1-child fixtures under Windows PowerShell 5.1.

## 52. A managed bool is not every Win32 boolean

**Mistake caught during the PowerShell security audit:**
`FILE_DISPOSITION_INFO.DeleteFile` used `UnmanagedType.Bool`, which marshals a
four-byte `BOOL`, although the native field is a one-byte `BOOLEAN`.

**Consequence:** The sole handle-bound delete could fail with an invalid native
buffer and leave recovery unnecessarily uncertain.

**Rule:** Freeze P/Invoke field width and `Marshal.SizeOf`, not just names. Use a
one-byte field, assign `1`, execute a Windows size fixture, and keep exactly one
native mutation call.

## 53. Prior authorization attributes absence, not presence

**Mistake caught during spec review:** Inspect rejected a supplied prior
authorized-attempt reference when the exact empty operation still existed.

**Consequence:** After an unknown acknowledgement, the controller could neither
attribute later absence nor authorize a fresh explicit attempt when deletion
had not happened.

**Rule:** Use the prior reference only to classify clean absence as
`ALREADY_ABSENT`; when the exact empty operation is present, return
`EMPTY_PRE_TRANSACTION` with a null prior proof and permit a new explicit
authorization.

## 54. A one-shot mutator cannot probe after authorization

**Mistake caught during protocol review:** Apply used the normal read-only
address selector, which sent an Administrator probe before the mutation wrapper.

**Consequence:** One logical apply used two or more SSH processes, weakening the
frozen one-process acknowledgement boundary after the durable attempt existed.

**Rule:** Read-only inspect may probe and fall back. Apply fixes the first
already-trusted session address, sends exactly one SSH process with no fallback,
and classifies every unacknowledged outcome from that invocation as uncertain.

## 55. Source-token tests do not prove Windows PowerShell semantics

**Mistake caught during independent review:** Static wrapper assertions passed
while `DateTimeOffset.Parse(..., RoundtripKind)` would throw on Windows
PowerShell 5.1 and the nested-array bug remained executable.

**Consequence:** macOS tests could report green for a wrapper that could not
produce a boot marker or clean-absence topology on the target.

**Rule:** Keep source invariants, but pair them with a conditional executable
WinPS5.1 fixture for collection behavior, timestamp parsing, and native layout.
A macOS skip is an honest missing physical gate, never Windows acceptance.

## 56. Stable lock errors need unforgeable provenance

**Mistake caught by a late JavaScript protocol review:** Recovery initially
classified trusted-session contention from a generic path-bearing lock error.
Matching only its message or a public `code` would also let an injected runner
or a later operation imitate a finite contention result.

**Consequence:** Genuine pre-dispatch contention could be mislabeled as an
inventory failure, while a post-dispatch transport failure could be spoofed as
`RUNTIME_ALREADY_RUNNING` instead of remaining completion-uncertain.

**Rule:** Mint contention provenance only before the trusted lock callback is
entered, keep it in a module-private identity set, and erase it if the same
error is ever rethrown from a later operation. Test real contention with zero
SSH calls, message/code lookalikes, and capture-then-reuse of a genuine error.

## 57. A parent review cannot finish before its child reviews

**Mistake in the Task 4 review process:** The parent reviewer returned an
approval while a nested protocol reviewer was still running; that late child
then found two real mapping defects after the initial checkpoint was written.

**Consequence:** A locally green range and a parent verdict can create a false
completion claim while delegated review evidence is still outstanding.

**Rule:** Before recording review completion, inspect the full live agent tree
and await or explicitly terminate every descendant. Treat a parent verdict as
provisional while any child review remains active, then rerun the affected
focused tests and final verification after all late fixes.

## 58. Absence attribution needs an explicit prior authorization ID

**Mistake caught during Task 5 contract review:** The first recovery CLI draft
had no input that could name the exact prior ticket after an apply result became
unknown, while runtime state intentionally retained no ticket ID and the store
forbade enumeration or a `latest` selector.

**Consequence:** A later clean absence could never be proven
`ALREADY_ABSENT` across invocations without weakening the exact-ID model.

**Rule:** Permit only an optional explicit `--prior-ticket <exact-id>` on
read-only inspect. Read that ticket and its attempt directly, never enumerate,
and require a distinct new ticket for finalization.

## 59. Optional means verified missing, not unreadable

**Mistake caught during Task 5 contract review:** Existing recovery reads used
one failure path for a cleanly absent observation/commit and for corrupt,
replaced, or unsafe records.

**Consequence:** Treating every read failure as first use could authorize new
remote work beside ambiguous crash evidence; treating every absence as corrupt
would make first inspection and commit-after-crash recovery impossible.

**Rule:** Under the operation lock, return `null` only after proving the exact
final and related publication residue are safely absent. Map every unsafe,
corrupt, replaced, or ambiguous state to `RUNTIME_STATE_UNSUPPORTED`.

## 60. A reporter cannot reject a producer's valid post-mutation result

**Mistake caught by independent Task 5 review:** The controller accepted and
returned enrolled display names up to 512 UTF-8 bytes, while the CLI result
validator rejected anything above 256 bytes.

**Consequence:** Inspect could create the only full authorization ticket, or
apply could finish cleanup, commit, and CAS, then the CLI would print only
`RUNTIME_INPUT_INVALID` and hide the valid result.

**Rule:** Freeze one bound in the protocol and enforce it before publication
and at every output boundary. Test a value above the old bound after simulated
apply success, the exact maximum, and one byte above it.

## 61. Stable errors are scoped by command authority

**Mistake caught by independent Task 5 review:** Recovery reused one global
runtime error whitelist, so read-only inspect could relay an apply-only
completion-uncertain or artifact error, and older commands could expose a
recovery-only boot code.

**Consequence:** Error text no longer truthfully described whether mutation
could have happened, weakening retry decisions and the separate-authority
boundary.

**Rule:** Keep parse, inspect, apply, and legacy-command error allowlists
separate. Inspect never emits mutation/artifact codes; only apply may preserve
`RUNTIME_COMPLETION_UNCERTAIN`; unknown or cross-mode codes become the bounded
internal error.

## 62. Package-script flags are forwarded, not interpreted

**Mistake during Task 5 verification (repeated during recovery closeout):**
Running `npm run check -- --quiet` appended `--quiet` to every `node --check`
invocation even though Node's syntax checker has no such option.

**Consequence:** The verification command failed before checking source and
could be mistaken for a code regression.

**Rule:** Run the repository's exact package script unless its own contract
documents pass-through flags. Control tool output outside the script, then
rerun the canonical command after any invocation mistake.

## 63. CLI help text is literal data, not an unescaped regex

**Mistake during Task 5 TDD:** A help assertion interpolated
`[--prior-ticket <ticket-id>]` directly into `RegExp`, turning the brackets and
hyphen into an invalid character class.

**Consequence:** The intended RED test failed in its assertion construction
instead of proving the missing command surface.

**Rule:** Use literal containment for fixed help lines, or escape every regex
metacharacter before construction. Re-run RED after repairing the test itself.

## 64. An unexplained timing failure remains evidence

**Mistake signal during the store-lock regression run:** The first full suite
returned one unexpected concurrency error once, then the exact test passed 30
isolated runs, five same-prefix sequences, and two fresh full suites without an
identified cause.

**Consequence:** Calling the first result irrelevant would erase a possible
race; calling the later green runs a proof of root-cause repair would overstate
what was learned.

**Rule:** Preserve the failure and exact reproduction attempts, keep the old
expectation, require repeated fresh full green runs, and report residual timing
risk until a cause is established or broader evidence closes it.

## 65. Serialization is not single-use authorization

**Mistake caught by independent Task 5 review:** The operation lock serialized
apply calls, but inspect could mint two sibling tickets before either was
consumed. Each sibling still had its own exact-ID attempt path.

**Consequence:** After the first remote result became unknown, the second
sibling could acquire the same lock later and dispatch another delete.

**Rule:** Give every authorization parent one deterministic immutable successor
slot at ticket creation time. Repeated or concurrent inspect for that parent
must return the same ticket ID or fail closed; an apply-time lock alone is not
an authorization linearization point.

## 66. Exactly-once ticket delivery needs an acknowledgement protocol

**Mistake in the first ticket wording:** It promised that a full ticket ID was
returned only once even though the store had no durable client acknowledgement.

**Consequence:** A lost response made the only authorization unreachable, while
minting another ID would recreate the sibling-ticket flaw.

**Rule:** Without a delivery ACK, promise idempotent same-ID retry for the same
valid parent, never exactly-once delivery. Do not expose the ID in errors or
logs, and do not manufacture a sibling to recover a lost response.

## 67. Publish the unique successor before its lookup alias

**Mistake caught while freezing crash order:** Publishing the random ticket path
before recording which ticket uniquely belongs to a parent leaves a crash
window where retry can mint a second ID.

**Consequence:** The store can no longer prove which sibling owns the parent.

**Rule:** Publish and fsync the parent-keyed successor envelope first, embedding
the complete ticket. Publish the exact ticket path second; if it is cleanly
missing, restore the same embedded ticket. A ticket without its slot or any
ambiguous temporary residue fails closed and is never overwritten.

## 68. A consumed ticket is never a retry token

**Mistake caught by the sibling-ticket counterexample:** Apply read a missing
commit and immediately called `consumeTicket`; an already-existing attempt could
then be reused or mapped loosely enough to reach remote work again.

**Consequence:** The same explicit authorization could dispatch twice after an
unknown result.

**Rule:** Apply order is exact ticket, optional commit, optional attempt. A
commit is CAS-only; an attempt without a commit is
`RUNTIME_COMPLETION_UNCERTAIN` with zero remote calls. Only two verified
absences permit consume and one remote dispatch.

## 69. Observing a rejected Promise is part of transaction safety

**Mistake caught by a Node 22 strict-unhandled-rejection test:** A callback could
fire-and-forget a failing scoped store call; its rejection was not observed
until the final drain and could terminate the process first.

**Consequence:** The kernel lock could be released by process death before the
transaction returned its finite failure, and a caught rejection could otherwise
be lost.

**Rule:** Return a native Promise, attach an internal rejection observer before
exposing it, retain every invocation until callback settlement, and poison an
otherwise successful transaction with the first scoped failure. Preserve the
callback's own error identity when the callback itself fails.

## 70. Full-suite evidence belongs to one exact worktree snapshot

**Mistake signal during parallel Task 5 work:** A new successor RED test landed
while a store reviewer was running its final full suite, changing 96 tests into
99 and invalidating the planned second confirmation run.

**Consequence:** A red result from newly added work could be misreported as a
regression in the already-reviewed lock fix, or an earlier green run could be
misreported as coverage of tests that did not yet exist.

**Rule:** Record the exact test count and snapshot boundary. On concurrent
shared-worktree changes, let the current command finish, preserve its TAP,
stop overlapping edits, and rerun final evidence only after the tree is frozen.

## 71. A schema bump needs a physical namespace barrier

**Mistake caught by Task 5 protocol rereview:** V2 tickets initially shared the
old ticket and attempt directories while the new protocol also prohibited
enumeration. An unknown V1 attempt therefore could not be disproved from a new
GENESIS slot.

**Consequence:** Old durable authorization could become invisible and a new V2
ticket could authorize a second remote dispatch.

**Rule:** Put V2 tickets and attempts in versioned namespaces. Under the same
operation lock, require both legacy authorization directories to be absent
before every V2 authority path and immediately before dispatch publication.
Never read, migrate, enumerate, or delete legacy residue automatically.

## 72. Idempotent delivery must survive ticket expiry

**Mistake caught by Task 5 protocol rereview:** Same-parent retry returned the
same ticket only before TTL. If the first structured response was lost and the
retry arrived after expiry, the controller rejected the ticket without any
safe channel that could reveal its exact ID.

**Consequence:** The immediate-parent protocol became permanently unreachable
despite having a complete durable successor envelope.

**Rule:** Repair and return the same embedded lineage ticket even after TTL.
Use a bounded non-authorizing `RECOVERY_PARENT_REQUIRED` result with the exact ID
and eligibility time; never put that ID in an error or mint a sibling.

## 73. A durable commit needs a machine-readable resume handoff

**Mistake caught by Task 5 protocol rereview:** Inspect rejected an existing
commit to avoid remote replay, but after a controller restart the caller might
no longer know the ticket ID required for the CAS-only apply replay.

**Consequence:** Remote cleanup and commit could both be durable while Mac state
remained permanently failed for lack of an identifier.

**Rule:** Exact-read the deterministic commit and its attempt, then return
`RECOVERY_APPLY_REQUIRED` with the exact ticket ID and zero Windows calls. Apply
must ignore later ticket expiry only for that already-committed CAS replay.

## 74. Authorization retirement cannot depend on a reversible clock

**Mistake caught by Task 5 protocol rereview:** Consume checked the current TTL
before treating an already-published expired-ticket successor as permanent
retirement of its predecessor.

**Consequence:** Moving the local clock backwards could make an old ticket look
live again and reopen a dispatch path after its successor already existed.

**Rule:** Exact-check the predecessor's deterministic expired-child slot before
the current-time gate. A valid child permanently retires the predecessor; a
corrupt child is unsupported, and both paths stop before remote work.

## 75. A verifier inside a held operation lock needs a private read context

**Mistake caught by the real state-CAS integration test:** The recovery
controller held the operation lock, but the state-store verifier called public
recovery reads that attempted to acquire the same non-reentrant lock again.

**Consequence:** A valid `RECOVERED` transition failed as unsupported after a
self-inflicted lock timeout.

**Rule:** Install a private exact-bound, read-only context only for the lifetime
of the held lock. Reuse the scoped invocation/drain lifecycle for verifier
reads, invalidate inherited asynchronous contexts on exit, and never make the
public lock or public reads generally reentrant.

## 76. Structured handoffs are successful command results

**Mistake caught by CLI RED tests:** The controller legally returned
`RECOVERY_PARENT_REQUIRED` and `RECOVERY_APPLY_REQUIRED`, while the CLI result
validator accepted only `RECOVERY_READY` for inspect.

**Consequence:** Safe non-authorizing recovery handoffs were converted into
input errors even though the controller had done the correct work.

**Rule:** Admit each finite status through its own exact schema. Validate
actionability, timestamps, mode, accessors, and extra fields without executing
getters or proxy traps; never weaken the schema into a generic result object.

## 77. Resolve deterministic authorization state before remote topology

**Mistake caught by the lost-ID/absent-topology case:** Inspect queried Windows
before checking the exact parent successor. A consumed ticket whose response
was lost could therefore look like externally absent state and become
unrecoverable without its prior ID.

**Consequence:** A durable authorization ID was stranded even though its
deterministic successor slot already identified it.

**Rule:** Resolve the exact parent slot locally before Windows. Return consumed
or expired successors as zero-Windows handoffs; only a live unconsumed ticket
needs current read-only remote proof. The resolver must not enumerate, select
latest, call entropy, or create new authority.

## 78. State the lock contention guarantee at its real linearization point

**Mistake caught by concurrent-ticket testing:** The protocol wording promised
all concurrent same-parent inspect calls would return one ID, but the outer
operation lock can be contended before any successor exists.

**Consequence:** Meeting that wording would require an unbounded wait, while a
bounded fail-fast lock legitimately returns `RUNTIME_ALREADY_RUNNING`.

**Rule:** Promise same-ID coalescing only once ticket publication is reached or
the durable successor exists. Pre-publication outer-lock contention may fail
boundedly, but no path may create a sibling. Keep the longer wait policy scoped
to ticket publication rather than every recovery operation.

## 79. Recovery fixture chronology is part of the proof

**Mistake caught while repairing controller tests:** A child ticket fixture was
inspected before its parent attempt was authorized.

**Consequence:** The test described an impossible lineage and could reject a
correct chronological validator for the wrong reason.

**Rule:** Keep every parent attempt timestamp no later than the child inspect
time, and keep creation/expiry times canonical and monotonic within the
fixture. A GREEN test must represent a possible durable history.

## 80. Durable lineage outranks a later wall-clock rollback

**Mistake caught by final Task 5 review:** Inspect required an unconsumed parent
to look expired under the current clock before resolving its already-published
`EXPIRED_TICKET` child.

**Consequence:** After a legitimate child publication, moving the Mac clock
backwards made an old ancestor unable to recover its direct successor even
though the durable lineage had already retired it.

**Rule:** Construct and resolve the exact parent slot first. A valid direct
child proves the historical eligibility decision; only a verified cleanly
missing slot may use current time to decide whether new child creation is
eligible.

## 81. A read-only resolver must never fall back into a mint path

**Mistake caught by final Task 5 review:** The successor resolver read an
existing envelope, then delegated alias repair to generic ticket creation. If
the envelope disappeared between those reads, the second path could call
entropy and mint replacement authority.

**Consequence:** A hostile filesystem race could turn a finite read/repair
capability into a new authorization source.

**Rule:** Repair from the first verified embedded ticket only, revalidate the
same deterministic slot, and fail closed if it disappears or changes. The
resolver never calls entropy or a generic create path; test disappearance,
residue, corruption, and replacement directly.

## 82. New authority must not inherit legacy final-only compatibility

**Mistake caught by Task 5 security review:** The generic immutable reader
accepted a final file with link count one for every record, including new V2
successors, tickets, and attempts whose publication protocol always retains a
temporary/final witness pair.

**Consequence:** Deleting the retained witness could silently downgrade a new
authorization record into a weaker legacy representation.

**Rule:** Scope final-only compatibility to the old boot-observation and commit
paths. Every V2 authorization record requires the exact same-inode,
link-count-two witness pair; missing, extra, or mismatched residue fails closed.

## 83. Canonical-directory checks do not prove a regular file's exact case

**Mistake caught by Task 5 security review:** Managed directories were checked
with `realpath`, but immutable record files were accepted through a
case-insensitive APFS alias.

**Consequence:** A wrong-case final or related temporary name could be read as
the canonical authority path or escape exact-name residue checks.

**Rule:** Canonical-check every regular-file endpoint and require the exact
directory entry name. Reject case-fold collisions for both the final name and
its publication-residue prefix; exercise this on a case-insensitive filesystem.

## 84. A no-entropy resolver includes publication bookkeeping

**Mistake caught by Task 5 spec review:** Alias repair preserved the embedded
ticket ID but called the generic publisher, which generated a random temporary
publication name.

**Consequence:** The resolver violated its finite read/repair contract even
though it did not mint a different ticket authority.

**Rule:** Derive repair-only publication bookkeeping deterministically from the
already-verified ticket digest. Treat every randomness source, not only ticket
ID generation, as entropy that a resolver is forbidden to enter.

## 85. A downgrade barrier belongs immediately before the irreversible link

**Mistake caught by Task 5 spec review:** The legacy-namespace check ran before
several awaited temporary-file operations rather than at the final no-replace
publication boundary.

**Consequence:** Legacy residue introduced in that window could coexist with a
new durable V2 attempt before the later path rejected the mixed state.

**Rule:** Pass a fail-closed publication guard into the immutable publisher and
run it after temporary fsync and endpoint revalidation, immediately before the
final hardlink. Retain earlier checks for fast rejection, but do not mistake
them for the linearization-point barrier.

## 86. Unrelated compression and a looser test are not a valid feature diff

**Mistake caught during Task 8 implementation:** An unrelated source file was
minified while a source-size assertion was relaxed to make the edited tree pass.

**Consequence:** The authorization change became harder to review, and the test
stopped enforcing the boundary it was meant to protect.

**Rule:** Keep feature diffs surgical. If an intentional source grows past a
bound, justify that bound against the real transport budget and change only the
specific assertion. Never offset growth by rewriting unrelated code or by
loosening a test without a contract-level reason.

## 87. A consume call is not proof that authorization was consumed

**Mistake caught during Task 8 review:** The approved controller awaited
`consumePlanTicket` but did not validate its returned durable record before
starting state transitions, signing, acquisition, or provisioning.

**Consequence:** A missing or forged acknowledgement could produce a false
authorization handoff and allow later authority to run without evidence of the
one-shot consume linearization point.

**Rule:** Validate the exact frozen consumed-record schema, ticket and
authorization digests, canonical timestamp, and record digest before exposing
any later authority. Missing, accessor-backed, substituted, or malformed
acknowledgements fail closed before apply.

Evidence: `src/runtime/runtime-plan-authorization.mjs`;
`test/runtime-plan-authorization.test.mjs`.

## 88. A named ACL check must inspect the effective platform ACL

**Mistake caught during Task 8 review:** A helper named as an ACL check examined
only POSIX mode bits and never queried macOS extended ACL entries.

**Consequence:** A namespace could look owner-only while an extended ACE still
granted another principal access, and the test suite would report a false
security boundary.

**Rule:** On Darwin, inspect the actual endpoint with `/bin/ls -lde -- <path>`
in addition to owner, mode, link, and symlink checks. Apply the check to both
ticket and consumed namespace chains, and exercise a real added ACE in a test.

Evidence: `src/runtime/runtime-plan-ticket-store.mjs`;
`test/runtime-plan-ticket-store.test.mjs`.

## 89. Approved execution must not create or repair its signing identity

**Mistake caught during Task 8 review:** The approved dependency factory used
`BootstrapSigner.getOrCreate()` before consumption and the legacy `sign()` path
afterward.

**Consequence:** A supposedly validating preflight could create, chmod, repair,
or lock local identity state, while post-consume signing could silently enter
the same mutation path.

**Rule:** Planning may establish the controller identity, but approved
execution uses existing-only reads. Validate canonical parent paths, ownership,
modes, no-follow regular endpoints, stable double reads, and the private/public
pair without mkdir, chmod, locks, or repair. Bind signing to the reviewed
controller identity and map drift, unsafe state, and unexpected failures to
their distinct finite controller codes.

Evidence: `src/identity/bootstrap-signer.mjs`;
`src/runtime/production-runtime-dependencies.mjs`;
`test/bootstrap-signer.test.mjs`.

## 90. A compressed loader has two independent byte budgets

**Mistake caught during Task 8 implementation:** The raw inventory script grew
beyond the old stdin-sized source assertion, and gzip decompression accepted
the expected script even when ignorable trailing bytes followed the gzip
member.

**Consequence:** Treating compressed and decompressed limits as one number
either rejects a valid checked-in script or leaves an unbound compressed
envelope that can carry bytes outside the reviewed source.

**Rule:** Bound canonical base64/compressed stdin separately from decompressed
script bytes. Bind the exact compressed SHA-256 as well as the decompressed
length and SHA-256, reject extra stdin bytes, and keep the decompression limit
enforced during streaming rather than after allocation.

Evidence: `src/runtime/runtime-plan-inventory.mjs`;
`test/runtime-plan-inventory.test.mjs`.

## 91. Proxy rejection must precede every reflective operation

**Mistake caught during Task 8 hostile-input review:** Target validation called
`Object.isFrozen` before rejecting a proxy; the inventory adapter called a
session method through property lookup and read `error.code` through optional
chaining.

**Consequence:** Hostile traps could run during a fail-closed validation path,
leak private detail, or create side effects before the controller returned its
finite error.

**Rule:** Check primitive shape and `isProxy` first. Snapshot callable data
descriptors without invoking accessors, use intrinsic `Reflect.apply`, and read
error codes only from own data descriptors. Tests must count traps and require
zero.

Evidence: `src/runtime/runtime-plan-authorization.mjs`;
`src/runtime/runtime-plan-inventory.mjs`.

## 92. Only a post-freeze test run counts as verification

**Mistake caught during Task 8 implementation:** A full `node --test` run was
started while security fixes were still changing the same worktree and its
process survived after the initiating command was believed to be stopped.

**Consequence:** Partial output from a stale tree could be misreported as the
final test count while also consuming resources and obscuring the real gate.

**Rule:** Stop the exact stale process tree, do not count that run, freeze the
implementation, then launch a fresh observed gate. Record the exact command,
exit status, pass/fail/skip counts, and distinguish focused evidence from the
final full suite.

## 93. A checked-in source drift gate is not loaded-byte attestation

**Mistake caught during Task 8 revision review:** Describing source revisions
as proof of the complete running controller, or recursively hashing every
transitive import without a finite trust boundary.

**Consequence:** The claim becomes circular or unbounded while still failing to
prove which controller bytes the current process actually loaded.

**Rule:** Runtime-plan revisions bind only their enumerated checked-in source
components. The provision execution revision covers its PowerShell core,
transport, upload, orchestration, manifest, and ensure-runtime sources; the
inventory revision separately binds its PowerShell source and planning adapter.
The already-running controller and authorization/production adapters remain the
trust root. These revisions detect checked-in source drift; they are not
loaded-byte attestation or proof of an unlimited dependency closure.

Evidence: `src/runtime/production-runtime-dependencies.mjs`;
`test/production-runtime-dependencies.test.mjs`.
