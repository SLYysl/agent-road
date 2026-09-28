# Obsolete staged transaction recovery

## Implemented boundary

`staged-retirement-observation.mjs` composes the existing strict Windows inventory
validators with a read-only staged observation. The collector accepts only one
operation containing one complete transaction (capsule plus one archive), with no
work directory, temporary upload, installed generation, or other runtime entries.
It verifies the capsule against the existing Mac controller public key. Capsule
bytes travel as canonical base64: legacy Windows console encoding must not alter
non-ASCII signed manifest content.

`assessStagedRetirement` independently verifies the RSA-SHA256 signature, exact
failed-state bindings, capsule/archive byte hashes, supported core component,
strict staged facts, and two semantically matching inventories. Only a change to
the signed Windows PowerShell version is accepted by this narrow classifier.
Other platform changes, unknown shapes, partial uploads, started work, foreign
keys, changed inventories, and corrupt evidence are rejected. Unsupported staged
contents take priority over incidental reboot requirements.

The result is always `actionable=false`, `authority=OBSERVATION_ONLY`. It is not a
recovery ticket. Neither module moves files, publishes a boot observation, clears
a lock/failure, transitions state, invokes the CLI, or starts an installation.
The Windows retention executor and trusted controller are implemented below;
retention remains separate from the existing empty-operation recovery protocol.
No new installation plan is issued by this slice.

## Selected recovery sequence

1. Acquire the existing Mac operation lock; reread the exact failed state and
   pinned target. Obtain fresh strict staged evidence and preserve the original
   capsule bytes. A diagnostic JSON report alone is not execution authority.
2. Publish a durable, bounded retention proposal binding target, state digest,
   source revision, original capsule/archive hashes, directory identities, and a
   fixed destination outside `runtime`. The fixed layout is
   `C:\ProgramData\AgentRoad\retained-runtime\<operationId>\<manifestDigest>`.
   Paths must be derived from validated identifiers, never supplied by callers.
3. Consume the proposal exactly once before dispatch. The executor must
   hold the Windows runtime mutation mutex, revalidate content/ACLs, and preserve
   bound identities during a nonreplacement move. It holds ancestor and transaction handles, closes descendant handles only
   for the directory rename, then reopens and revalidates them.
   Leave the operation directory in staging. Preserve bytes, signatures, and ACLs;
   do not re-sign the old operation or reinterpret its stale platform binding.
4. An acknowledged result still needs a read-only postcheck. An uncertain result
   must not trigger another move. Reconcile source and retained destination using
   the same operation, content, and directory identities:

   | Source transaction | Exact retained destination | Interpretation |
   | --- | --- | --- |
   | Present | Absent | No proven retention; inspect the recorded attempt |
   | Absent | Present | Retention candidate only with matching durable attempt |
   | Present | Present | Conflict; reject |
   | Absent | Absent | Evidence missing; reject |

5. Once retention is proven and the original operation is actually empty, use
   the existing empty-operation recovery protocol for that now-empty directory.
   Its formal boot fence and immutable ticket/attempt/commit chain remain required.
   The earlier CIM diagnostic reboot receipts must not be imported as production
   boot authority. Whether a formal observation is captured before retention is a
   protocol change requiring implementation/tests, not an assumed shortcut.
6. Only a verified recovery commit permits `FAILED -> RECOVERED`. Create a distinct
   new operation and collect fresh admission inventory before generating a new
   signed installation plan. A retained transaction never directly means READY.

The retention implementation must test destination conflicts, path/ACL/identity
replacement, incomplete or changed files, crashes before/after rename, lost SSH
acknowledgements, attempted repeated dispatch, missing durable provenance, and
races with old writers. Do not ship an untested rename wrapper as recovery.

## Physical verification on 2026-09-18

The new collector passed on the enrolled machine. The first prototype reused
inventory definitions but omitted the inventory main routine's UTF-8 output
setup. Text output therefore altered non-ASCII signed content and failed
independent signature verification; original remote bytes/signature remained valid. Base64
transport corrected this, and independent signature/content/state checks then
passed before the environmental gate returned `RUNTIME_REBOOT_REQUIRED`.

The fresh production inventory pair again passed (5.452 seconds), but pending
reboot had changed back to true since the earlier post-reboot observation.
Read-only registry checks found no CBS or Windows Update reboot-required key;
`PendingFileRenameOperations` contained 20 nonempty entries, all classified under
SYSTEM32. Their raw paths were not printed or removed. The source of these entries was not established.

The user subsequently authorized one second reboot. A single request was accepted;
a fresh pinned-SSH observation confirmed a changed boot marker and both sshd and
Tailscale running with automatic startup. The production inventory pair completed
in 5.926 seconds with pendingReboot=false in both observations. The three registry
checks were clear, including zero remaining file-rename entries; a later repeat
registry check was also clear.

Fresh byte-preserving staged evidence passed the independent assessment as
`OBSOLETE_STAGED_TRANSACTION`, reason `WINDOWS_POWERSHELL_VERSION_CHANGED`, with
`actionable=false` and `authority=OBSERVATION_ONLY`. The next required step remains
retention before empty-operation recovery. Local device registry and failed-state
bytes remain unchanged. No retention, recovery state change, or installation was
dispatched. Private second-reboot receipts are retained; this diagnostic boot
comparison is not production recovery authority. These observations establish the
post-reboot state, not a guarantee that pending operations cannot recur.

Prior implementation validation: 52 related tests passed; 3 existing Windows-only tests skipped on
macOS. New assessment/encoding cases passed, and the collector executed on the
physical Windows target. `npm run check` passed. These checks do not cover a
retention executor, because that executor is not implemented in this slice.


## Local retention record protocol (2026-09-18)

`staged-retention-protocol.mjs` and `StagedRetentionStore` in
`runtime-recovery-store.mjs` implement the local proposal, attempt, and successful
reconciliation records. The store deliberately reuses the existing per-operation
kernel lock and immutable publication/readback checks; it does not weaken or
replace the existing empty-operation recovery protocol.

A proposal binds the signed capsule, failed state, pinned target digest, executor
bundle digest, both admission inventories, source file/directory identities,
source ACL digests, and the observed destination-parent identities. All source
nodes must be distinct on the same volume; retained destination aliases and
unexpected fields are rejected. Proposals expire after five minutes. Fresh
admission still passes the original assessment; only above-threshold free-space
variation is ignored between proposal and consumption.

The store publishes and rereads an immutable attempt before returning it to the
controller. A second consumption fails, including after a lost publication
acknowledgement. An incomplete publication also fails closed. There is currently
one proposal per operation, with **no automatic proposal renewal or retry path**;
expired or interrupted proposals need a separately designed continuation policy.
At that 2026-09-18 checkpoint, no production proposal or attempt had been created.
The 2026-09-19 physical result is recorded below.

Reconciliation requires the exact durable proposal and attempt, matching target
and bundle bindings, unchanged source parents and ACLs, an empty original
operation, and only the retained transaction at the destination. Capsule/archive
hashes, lengths, file IDs and ACL digests must match. Source-only, both-present,
neither-present, replaced identities, changed permissions, or unexpected topology
cannot authorize another dispatch. A late read-only postcheck may reconcile a
lost acknowledgement after proposal expiry. Success records `RETAINED`, with
`runtimeRecovered=false`; the formal empty-operation boot fence remains required.

These APIs validate and persist **supplied evidence**, not its transport origin.
They are not wired to CLI or runtime state transitions. The production
controller captures current state under the
operation lock, derives both target and executor digests itself, uses pinned SSH,
validates restricted destination ACLs, and collects source/destination facts
under the Windows mutation mutex with pinned handles. Caller-supplied booleans,
IDs, ACL hashes, or executor digests do not prove a Windows operation occurred.

Before the user requested a pause to play Apex, two isolated temporary-directory
probes attempted handle-based directory renaming while a child file remained
open. Both returned Windows error 5; neither touched the real staged transaction.
Changing the child handle's delete-sharing flag alone did not resolve it. There
was no matched closed-child control, so the probes alone do not isolate the cause.
Subsequent read-only research found that Microsoft's
[FileRenameInformation algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/87f86c9b-6c2a-4803-84b7-131a74a434fa)
requires `STATUS_ACCESS_DENIED` when the source directory contains open files.
This is consistent with both probes and invalidates the original assumption that
all child handles could remain open through a directory rename. Do not ship that
prototype or silently release protection and substitute an unguarded path move.
The handle-lifetime/race guarantee must be redesigned and verified before any
production use of these records. The
[Microsoft FILE_RENAME_INFO contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
specifies nonreplacement behavior when `ReplaceIfExists` is false; the production
implementation still needs an isolated successful fixture and race tests.

The user temporarily paused Windows work to play Apex, then resumed it and
explicitly allowed reboot. The continuation results are recorded below.


Local validation for this slice: 118 targeted tests passed (32 protocol cases,
8 durable-store cases, and 78 existing assessment/controller cases); the full
existing recovery-store suite passed 126 tests. `npm run check` and diff checks
passed. Tests include concurrent consumption, prepublication interruption, lost
publication acknowledgement across a new store instance, symlink rejection,
expired proposals, safe disk drift, changed state/target/executor/ACL/identity,
and uncertain source/destination layouts. These results validate the local record
protocol, not a Windows move executor. Local enrollment and failed-state file
hashes were also reread and remain unchanged from the reviewed baseline.


## Resumed controls and third system reboot (2026-09-18)

The matched closed-child control now succeeds on the enrolled Windows machine:
close the child file handle, keep the source directory handle with DELETE access,
rename through that directory handle without replacement, then reopen the child.
Both directory and file IDs remain unchanged. Three negative controls also pass:
a conflicting destination is preserved, a path-based attempt to replace the held
source directory is rejected, and changed child bytes between validation and
rename are detected after the move. All four cases ran in a unique temporary
fixture, and its files were cleaned up; no production transaction was moved.
The exact tested fixture is retained in
`test/windows/staged-retention-rename-control.ps1`, with a Windows-only Node test.
The Node test skips on macOS; the four physical cases passed through pinned SSH.

This establishes a candidate handle lifetime, not a complete retention executor.
The future implementation must hold the mutation mutex and ancestor/transaction
handles throughout, release descendant handles only for the rename, then reopen
and verify IDs, ACLs, topology and content before acknowledging success. A
noncooperating child mutation is detectable after the move, not prevented by the
closed-child interval; such a result must remain uncertain, preserve the moved
bytes and reject recovery advancement. Mutex contention, parent substitution,
full ACL/topology checks, process loss and acknowledgement loss still need the
complete executor tests. These controls do not fill that gap.

Fresh production inventory before reboot showed both pendingReboot=true and an
interactive session. The pending rename list had 36 entries: 18 temporary paths
and 18 empty entries, unlike the earlier SYSTEM32 category. Their registering
process was not identified and raw paths were not printed. One reboot request
was accepted following the user's explicit authorization. After reconnection, a
changed diagnostic boot marker and automatic running sshd/Tailscale were verified.
The production inventory pair completed in 5.858 seconds: both pendingReboot=false,
interactiveSession=false. CBS, Windows Update and pending file-rename registry
checks were clear; a later repeat registry check was also clear. Fresh
capsule/archive/state checks again classified the stage
as obsolete solely because its signed PowerShell version is stale.

Local enrollment and failed-state hashes remain unchanged. This system reboot is
not the empty-operation protocol's formal boot observation. No real retention,
state recovery, installation, or subsequent reboot was dispatched.


## Retention executor and trusted controller (2026-09-19)

`staged-retention-controller.mjs` holds the existing Mac operation kernel lock
across fresh inventory, observation, immutable proposal/attempt publication,
one apply invocation, and independent reconciliation. Restarting with a consumed
attempt permits only reconciliation. Remote receipts are private observations;
they do not replace the durable proposal/attempt chain. The captured Windows
bundle digest must match on continuation.

`staged-retention.ps1` reuses strict capsule, topology and ACL validators, checks
fresh admission under the Windows mutation mutex, and pins source ancestors and
the transaction directory. `staged-retention-native.cs` creates protected
destination directories atomically and renames without replacement. Descendant
handles are closed only around rename; reopened identities, ACLs, hashes and
exact topology must match. A changed child during that interval is detected,
not prevented. Failure after destination creation begins is uncertain and can
never authorize another apply.

The same Windows executor passed eleven isolated physical cases: success and
independent reconciliation, destination conflict, parent identity mismatch,
changed ACL/content, extra entry, content mutation during the closed-handle gap,
destination race, lost acknowledgement with later successful reconciliation,
parent replacement rejection, and ACL mutation during the gap. Local
validation: 11 durable-store tests, 67 protocol/controller/assessment/builder
tests and 85 existing recovery/controller-remote tests passed; one Windows-only
fixture test skips on Mac. Syntax checks passed. These results alone do not
establish physical retention, recovery, a new installation or readiness.


### Physical retention and remaining boot fence

Two fresh production inventory attempts timed out before retention. A diagnostic
pair passed, and a separate Windows subprocess fixture reproduced the loader
waiting for EOF despite receiving the entire authenticated payload. Removing the
extra `ReadByte()` EOF probe made the same fixture complete with stdin still open.
Exact byte framing, compressed/script SHA-256, decompression limits and strict
UTF-8 remain enforced. This establishes and repairs an EOF-dependent blocking
condition; it does not prove every historical timeout had that cause. Four local
inventory-adapter tests passed; the Windows pipe fixture skips on Mac and passed
physically. The formal production preflight then passed with pendingReboot=false
and interactiveSession=false in both observations.

The production controller subsequently published its proposal and one attempt,
performed one apply, independently reconciled over pinned SSH, and durably
recorded `RETAINED`. The complete original capsule/archive transaction is outside
runtime in the fixed retained location. File/directory identities, contents and
ACLs match, and the original operation directory is empty. No bytes were deleted,
no installation started, and retention did not change FAILED to RECOVERED.

Formal `inspectRuntimeRecovery` now reached `BOOT_OBSERVATION_PUBLISH`, stored a
validated boot observation on the genuinely empty operation and returned
`RUNTIME_REBOOT_REQUIRED`. The next step is one authorized system reboot, followed
by formal inspection and the existing ticket/attempt/commit recovery sequence.
Earlier diagnostic reboots cannot satisfy this newly established boot fence.
The user subsequently authorized necessary reboots until explicitly paused. One
fourth reboot was accepted and the target reconnected.


### Formal recovery compatibility fixes

After that reboot, the latest Event 12 marker had advanced and the earlier
record still matched exactly. The reader nevertheless returned an array of two
entries for a one-event query: the second entry was the null end-of-log sentinel.
`Read-EventPair` now emits only actual records. The same physical query changed
from two array entries/one event to one entry/one event, preserving the marker
comparison and all boot validation.

The first recovery apply then returned completion uncertainty. Independent
inspection established the original operation remained empty and present; the
consumed attempt was preserved. A read-only version of the same apply wrapper
identified a pre-mutation field-order rejection: the Windows exact-record check
listed `agentRoadAcl` before `afterBootMarker`, while canonical JSON sorts them
in the reverse order. Correcting the expected order allowed every apply
precondition to pass without invoking deletion. A regression checks canonical
field ordering in both generated wrappers. Continuation uses the existing
consumed-attempt parent/ticket protocol, not redispatch of the consumed ticket.

Related local validation after these fixes: 127 tests passed, with three
Windows-only cases skipped on Mac. The actual Windows event reader and complete
read-only apply preconditions were independently verified. Syntax checks passed.

Formal continuation then returned `RECOVERED / REMOVED`. Independent store
readback verified the retained proposal/attempt/reconciliation and the formal
boot/ticket/attempt/commit chain; enrollment registry bytes remain unchanged.
The failed state transitioned only through the recovery commit. A fresh baseline
and actionable core plan now select PowerShell 7.6.4 in the Agent Road runtime
root with initial pinning of the original controller key. One approved-runtime
invocation is in progress; its terminal result and independent postchecks are
still required before any readiness claim. CLI integration remains out of scope.

### Core child stdin and current-platform unstarted retention

The new core invocation staged its complete capsule/archive but returned
uncertainty before creating work. A read-only Windows capability check confirmed
.NET Framework 4 has no `ProcessStartInfo.StandardInputEncoding` property. The
runtime-specific transport set that property before `child.Start()`, so the child
could not start. It now writes the already validated UTF-8 byte array to the
child's stdin BaseStream, flushes and closes that stream. A real subprocess
fixture confirms exact input and EOF; the actual core provisioner's read-only
preconditions (topology, signed manifest, binding, machine and archive) also pass.

A separate `assessUnstartedStagedRetention` admits a complete current-platform
capsule under the same strict no-work/no-runtime-state conditions. The existing
obsolete-only classifier remains unchanged at its public boundary. The retention
protocol uses the wider unstarted-stage assessor, preserving both current and
obsolete capsules rather than resuming a consumed installation attempt. Signature,
state, paired inventory, topology, IDs, ACLs and no-retry requirements remain.
Other platform drift, work directories, temporary files and runtime generation
state still block admission. Local regression covers the current-platform case
and these rejection boundaries; the second real stage passed fresh preflight.
