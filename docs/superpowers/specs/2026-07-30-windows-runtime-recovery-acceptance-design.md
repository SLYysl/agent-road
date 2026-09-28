# Agent Road Windows Runtime Recovery and Acceptance Design

## Goal

Close the first physical core-runtime acceptance gap without weakening the
existing transport or runtime boundaries.

The current machine is in a Mac-side `FAILED` state with
`RUNTIME_COMPLETION_UNCERTAIN`. The corresponding Windows runtime tree contains
one operation directory created before the transaction directory, and no
transaction, capsule, artifact, trust key, journal, pointer, or version. Agent
Road must recover that exact pre-transaction residue without guessing that a
mutation did or did not finish, and without asking a human to paste another
Windows command.

Before a later physical `prepare`, the controller must also expose and bind the
actual reviewed plan and capture an independent read-only baseline for the
declared external mutation surfaces.

Success means:

- inventory either recognizes the exact empty-operation topology or returns a
  finite state failure instead of a generic exit 42;
- recovery deletes only the exact empty operation directory after a separate
  inspect and authorization, never recursively;
- an uncertain delete acknowledgement converges through read-only inspection;
- Mac state preserves an auditable `RECOVERED` boundary before a new operation;
- `prepare --approved` consumes the plan reviewed by the preceding first-class
  plan command without making the user copy a digest;
- baseline capture and comparison expose only bounded counts and digests for
  declared external surfaces;
- no recovery command starts a new prepare automatically.

## Facts and Root-Cause Boundary

`provisionInitWrapper` creates `runtime`, `staging`, and the operation root
before it creates the manifest transaction and files roots. A lost SSH result
at that boundary can therefore leave exactly:

```text
C:\ProgramData\AgentRoad\runtime\staging\<operationId>\
```

with an empty final directory.

The existing inventory state machine already intends to accept this topology.
`Read-AgentRoadStagedOperation` returns a record with null manifest/capsule and
no temporary/work content, and `Get-AgentRoadRuntimeStateSnapshot` publishes the
operation ID as `pendingOperationId` when there is no journal.

Therefore the observed exit 42 does not prove an empty-array or pending-state
logic error. In the exact topology, a successful path exists. Exit 42 proves an
unobserved native or PowerShell exception escaped the finite
`RUNTIME_STATE_UNSUPPORTED` boundary. The first newly exercised boundaries are
the directory ACL APIs and direct child enumeration. Platform/CIM/registry
probes had already passed before the runtime root existed.

The implementation must not add an ACL-bypassing empty-directory shortcut. It
must first add a Windows PowerShell 5.1 fixture for the exact topology. Raw
exceptions from only the ACL and direct-enumeration boundaries are normalized
to `RUNTIME_STATE_UNSUPPORTED`; all existing path, reparse, owner, ACL, count,
and topology checks remain intact. A bounded test diagnostic may retain only an
exception type, fully-qualified error ID, and script line number. It must never
retain an exception message, path, operation ID, command, or key material.

The current Mac publication boundary is not sufficient for authorization
linearity. Authorized attempts are stored at
`authorized-delete-attempts/<ticketId>.json`, so two sibling tickets issued
before either is consumed can both publish and dispatch sequentially. The
operation lock serializes those dispatches but does not make the authorization
single-use. Recovery therefore needs a deterministic successor slot keyed by
the authorization chain, independently of deletion provenance.

## Considered Recovery Approaches

### 1. Classify the empty operation and retry prepare

Required but insufficient. Even if inventory returns the pending operation,
the Mac controller correctly refuses an uncertain `FAILED` state before
inventory. It also lacks the original durable signed capsule, so it cannot
legally resume or re-sign the same operation.

### 2. Inspect, authorize, and remove the exact empty operation

Selected. This solves the current pre-transaction residue with the smallest
remote mutation. It preserves fail-closed behavior for every topology that
contains evidence of a transaction or another operation.

### 3. Implement complete durable capsule resume now

Deferred. Durable capsule persistence prevents a future controller restart
from losing the original operation inputs, but it cannot reconstruct the
already-lost capsule for the current machine. It does not remove the need for
the exact empty-operation recovery path.

## Recovery Command Surface

Recovery is a two-command, non-interactive protocol:

```text
agent-road runtime-recover <device-id> --inspect [--prior-ticket <ticket-id>]
agent-road runtime-recover <device-id> --apply --ticket <ticket-id>
```

`--inspect` is read-only on Windows. When actionable, it creates or reads one
immutable owner-only authorization successor. The first inspect uses the exact
failed recovery episode as its `GENESIS` parent. A later inspect may name only
the exact immediately preceding ticket through `--prior-ticket`; that ticket
must either be expired and unconsumed or have one exact authorized attempt. The
authorization parent is separate from deletion provenance. It prints one
bounded summary containing the enrolled display name (at most 512 UTF-8 bytes),
a short non-secret target fingerprint, finite classification, whether a
post-failure reboot is required,
whether exact cleanup is actionable, a short ticket fingerprint, and expiry.
The full ticket ID is returned only through a structured Agent/CLI result for
the next local invocation and is not repeated by errors or logs. Before any
Windows call, inspect resolves only the exact parent-keyed successor slot. An
expired or consumed successor returns its same exact ID as bounded
`RECOVERY_PARENT_REQUIRED` with `actionable: false` and zero Windows calls. A
live unconsumed successor still requires the current read-only Windows proof:
equal proof returns that same `RECOVERY_READY` ticket, while drift returns the
same ID as `RECOVERY_PARENT_REQUIRED`. The store cannot prove delivery
acknowledgement, so it must never mint a different sibling to recover a lost
response.
The Mac Agent then supplies that ID through `--prior-ticket` when the parent is
eligible; a human never copies it. This also recovers an exact ID whose first
response was lost beyond the ticket TTL. Supplying an older ancestor resolves
only to its already-published direct successor and can neither advance the
chain nor create a fork. Inspect never enumerates attempts or selects a
"latest" record. Neither result nor errors expose `authorizationParent`. The
summary does not print a Tailnet address, operation ID, full
manifest/generation/proof digest, path, or command.

Concurrent callers that reach ticket publication, or that encounter an
already-durable successor, coalesce on the same ID within the bounded ticket
publication window. A caller contending on the outer operation lock before a
successor exists may instead receive `RUNTIME_ALREADY_RUNNING`; it still cannot
create a sibling. Public ticket creation uses a five-second coalescing window;
the remaining recovery operations keep the one-second fail-fast lock bound.

`RECOVERY_PARENT_REQUIRED` includes `eligibleAfter`: it is null when the named
parent is already consumed or expired, and equals the ticket expiry when a live
unconsumed ticket must first age out. If inspect finds a valid immutable commit
and its exact attempt while Mac state is still the original failed state, it
returns bounded `RECOVERY_APPLY_REQUIRED` with that exact ticket ID and performs
zero Windows inspection or ticket creation. The Agent then invokes apply, which
can only replay the already-committed Mac CAS. These structured handoffs are not
new cleanup authority.

The display-only target fingerprint is the first 12 uppercase hexadecimal
characters of the already domain-separated target-binding digest. The
display-only ticket fingerprint is the first 12 uppercase hexadecimal
characters of the domain-separated ticket-record digest. Neither truncated
value participates in authorization. The first non-authorizing observation
stores the boot marker and returns only `RUNTIME_REBOOT_REQUIRED`. A later
`RECOVERY_READY` result has `actionable: true`; a lineage-only
`RECOVERY_PARENT_REQUIRED` result has `actionable: false`, `eligibleAfter`, and
the otherwise same bounded ticket handoff fields. `RECOVERY_APPLY_REQUIRED` also
has `actionable: false` and the same ticket handoff fields.

Ticket creation first publishes and fsyncs one immutable successor envelope at
the deterministic path below, where the lowercase filename is derived from the
complete uppercase domain-separated parent digest:

```text
authorization-successors/<parent-digest>.json
```

The envelope embeds the complete canonical schema-version-2 ticket and its
digest. New tickets and attempts live only below `tickets-v2/` and
`authorized-delete-attempts-v2/`. Under the same operation lock, every V2
create, inspect, apply, and commit path, plus the instant immediately before
attempt publication, exact-checks that the legacy `tickets/` and
`authorized-delete-attempts/` directories are absent. Either legacy directory,
even empty, is unsupported crash or downgrade residue; recovery never reads,
migrates, enumerates, or deletes it.

Only after the successor slot is durable does the store publish the exact V2
ticket path. If the slot is durable and the ticket path is cleanly missing
after a crash, retry restores the same embedded ticket and ID even after
expiry; it never generates new entropy. An existing ticket without its exact
slot, a slot/ticket mismatch, or unsafe, substituted, extra, or partial
publication residue is `RUNTIME_STATE_UNSUPPORTED`. A changed proof or topology
on the same pinned target cannot authorize through the occupied slot and cannot
create a sibling; the slot may only return its embedded ticket as the
non-actionable lineage handoff above. A changed failed-state episode, target
binding, or parent fails closed. No mtime, PID, authorization-record
enumeration, mutable head, or "latest" selection participates.

`--apply --ticket <ticket-id>` is the explicit cleanup authorization. It loads
that exact immutable ticket and its matching successor envelope, then
revalidates all inputs. The complete proof digest remains an internal binding;
the user never copies it. Apply exact-reads the operation commit and that
ticket's authorized attempt before applying the current ticket TTL gate or
consuming anything. A valid commit plus its exact attempt permits only its exact
CAS-only replay even if the ticket has since expired. A commit without that
attempt is `RUNTIME_STATE_UNSUPPORTED`. An existing attempt without a commit returns
`RUNTIME_COMPLETION_UNCERTAIN` with zero remote calls. Only when both are
cleanly absent does a missing, expired, unsafe, or changed ticket fail before
remote mutation; a valid current ticket may then exclusively publish and fsync one immutable
`AUTHORIZED_DELETE_ATTEMPT` keyed by the exact ticket ID before dispatching one
remote operation. The durable attempt is the ticket-consumption and
remote-dispatch linearization point; the original ticket and successor envelope
remain for audit.

A pre-publication temporary record with no final record is not published and
fails closed as unsupported residue; recovery does not delete or reuse it
automatically. Each newly successful immutable publication retains the exact
temporary and final names as a same-inode, link-count-two witness pair after
fsync. Readers require that pair for every V2 successor, ticket, and attempt;
only pre-existing boot observations and recovery commits retain bounded
final-only read compatibility. Readers reject extra, replaced, mismatched, or
ambiguous links. A legacy schema-version-1 ticket has no unique successor proof. Its legacy namespace
presence is `RUNTIME_STATE_UNSUPPORTED`; this pre-release format is not read,
migrated, enumerated, or deleted. Recovery never performs a path-based cleanup unlink because an
`lstat`-then-`unlink` sequence cannot bind deletion to the inspected inode. A
retained attempt pair is already consumed and can never authorize a new remote
dispatch.

Every newly created managed directory is fsynced together with its naming
parent. Before accepting an immutable record, a reader fsyncs the exact opened
record inode and its verified parent directory, then rechecks the path,
metadata, publication pair, and bytes. This can stabilize a visible
post-link/pre-directory-fsync witness pair after a controller crash; it does not
adopt or delete a pre-link temporary residue.

Both commands use the existing pinned-host-key SSH target and a recovery-only
per-operation Mac lock. That lock is a permanent empty owner-only anchor held by
the controller through the fixed macOS `lockf` helper on an inherited file
descriptor. A callback-scoped, operation-bound store facade holds the same lock
across state revalidation, safe optional observation/commit reads, immutable
record publication, remote work, commit, and state CAS without nested lock
acquisition. A cleanly missing observation or commit is `null`; an unsafe,
corrupt, replaced, or ambiguous record remains `RUNTIME_STATE_UNSUPPORTED`.
The kernel releases the lock on descriptor close or process death; v1 does not
infer stale ownership from a PID, timestamp, or process name and never unlinks
the anchor. A legacy nonempty cooperative-lock file is unsupported and fails
closed. Apply additionally acquires the existing Windows
`Global\AgentRoadRuntimeMutation` kernel mutex, validates its exact owner and
DACL, and holds it across the final inspect, handle deletion, postcondition, and
fixed result publication. Contention is `RUNTIME_ALREADY_RUNNING`; recovery
never creates a second Windows mutation lock. Neither command falls back to
password authentication, a LAN address, Tailscale SSH, a public listener, or a
target-side model.

## Recovery Eligibility

The Mac state must be exactly:

```text
runtimeStatus = FAILED
failureCode = RUNTIME_COMPLETION_UNCERTAIN
requestedProfiles = [core]
readyProfiles = []
operationId, manifestDigest, generationDigest = canonical non-null values
```

`RUNTIME_ROLLBACK_INCOMPLETE` is not eligible for empty-operation cleanup. It
may represent a real transaction and remains a separate recovery problem.

The first uncertain upload wrapper did not hold a Windows lease that survives
individual SSH calls. A disconnected remote process must not be assumed dead,
and comparing a Mac failure timestamp with a Windows boot timestamp would rely
on unsafe cross-machine clock synchronization.

The first post-failure inspect therefore stores a non-authorizing observation
containing the Windows boot identity and returns the existing finite
`RUNTIME_REBOOT_REQUIRED`. After a separately authorized reboot, a later inspect
must observe a different canonical boot identity while the same exact topology
still passes. Only that observed boot change can create an actionable cleanup
ticket. This proves the old process cannot later resume and recreate the
deleted path without comparing clocks. Recovery never reboots the target
implicitly.

The boot identity is not a timestamp comparison. It is the bounded immutable
marker from the latest System log event whose provider GUID is
`{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}`
(`Microsoft-Windows-Kernel-General`) and event ID is 12. The marker contains the
provider GUID, channel, event ID/version, unsigned `EventRecordID`, canonical
UTC `TimeCreated`, canonical UTC `EventData/StartTime`, and a domain-separated
SHA-256 digest of those fields. It does not assume that event 12 exposes a
`BootId` field and does not order either timestamp.

On the later inspect, the exact prior event record must still be queryable and
must reproduce the stored marker. The latest matching event must have a
strictly greater `EventRecordID` and a different marker. This rejects a cleared
or rewritten log rather than interpreting record-number reuse as a reboot.
Clock changes do not mutate an existing event marker. Sleep and hibernation do
not satisfy the barrier. Restart, shutdown/start, and Fast Startup satisfy it
only if Windows emits a new qualifying event; otherwise recovery remains
blocked. Provider/event/payload schema, one unique latest match, string/number
bounds, and both reads must validate. Missing, cleared, duplicated, malformed,
or unreadable evidence is `RUNTIME_BOOT_IDENTITY_UNAVAILABLE` and fails closed.

## Exact Windows Topologies

Inspect recognizes three classifications, but only the first two can converge
an Agent Road authorized attempt.

### `EMPTY_PRE_TRANSACTION`

- `AgentRoad`, `runtime`, and `staging` are canonical non-reparse directories;
- every managed directory has the exact protected Administrators/SYSTEM
  FullControl ACL and Administrators owner;
- runtime contains only `staging`;
- staging contains only the operation bound by the Mac failed state;
- the operation directory is empty;
- `trust`, `state`, `versions`, transaction, work, capsule, artifacts, journal,
  active, previous, and every sibling operation are absent.

### `ALREADY_ABSENT`

- the same parent directory and ACL checks pass;
- runtime contains only `staging`;
- staging is empty;
- every other runtime node listed above is absent.

`ALREADY_ABSENT` exists only when an immutable durable
`AUTHORIZED_DELETE_ATTEMPT` record for the exact ticket/proof/operation was
published before the prior dispatch. It converges an authorized attempt whose
SSH acknowledgement or Mac state publication was lost; it does not claim that
Agent Road can prove which process performed the deletion.

### `EXTERNALLY_ABSENT`

The exact clean absent topology without a matching prior authorized-attempt
record is classified separately and fails closed. It cannot be relabeled as
`ALREADY_ABSENT`, cannot enter `RECOVERED`, and requires a separate future
adjudication outside this slice.

Any extra entry, path or directory identity change, ACL difference, reparse
point, inaccessible node, or transaction evidence is
`RUNTIME_STATE_UNSUPPORTED`. A different operation is
`RUNTIME_OPERATION_CONFLICT`.

## Proof and Ticket

Inspect constructs a canonical internal proof from:

- schema and protocol revision;
- device binding from the pinned target;
- exact failed-state operation/manifest/generation binding;
- failed-state identity and the before/after Windows boot-identity relation;
- classification;
- runtime and staging directory handle identities, plus the operation directory
  identity when it is present;
- exact normalized ACL facts and direct-child counts.

The proof is domain-separated and SHA-256 hashed. The immutable Mac ticket is
schema version 2 and stores the canonical proof and digest, exact failed-state
snapshot, canonical `authorizationParent` and parent digest, inspection time,
and ten-minute expiry. Its ticket digest uses the V2 domain. Proof, attempt,
commit, and Windows remote protocol schemas remain version 1; the attempt's
existing complete ticket digest automatically binds the V2 ticket. Ticket and
successor files and all ancestors are canonical, owner-only, non-symlink paths
with the same protections as runtime state. They store no private key, token,
raw command, address, user data, or target output.

`authorizationParent` has this fixed exact field set:

```text
schemaVersion, kind, deviceId, operationId, failedStateDigest,
ticketId, ticketDigest, attemptDigest
```

It has one of three mutually exclusive forms:

```text
GENESIS             = episode device/operation/failed-state digest;
                      ticketId/ticketDigest/attemptDigest are null
EXPIRED_TICKET      = same episode plus exact prior ticket ID and ticket digest
                      and a null attemptDigest
AUTHORIZED_ATTEMPT  = same episode plus exact prior ticket ID, ticket digest,
                      and authorized-attempt digest
```

For an explicit prior ID, an existing attempt always selects
`AUTHORIZED_ATTEMPT`, even after ticket expiry. A cleanly missing attempt may
select `EXPIRED_TICKET` only when both controller and store clocks establish
`now >= expiresAt`; an unexpired, unconsumed prior is
`RUNTIME_INPUT_INVALID`. Once an expired-ticket successor is published, the
expired predecessor can never later be consumed, even if the local clock later
moves backwards. Consume exact-checks that direct successor: a valid occupied
slot is `RUNTIME_INPUT_INVALID`, while corrupt or ambiguous durable state is
`RUNTIME_STATE_UNSUPPORTED`; both stop before remote work. The store exact-reads and
validates every named predecessor against the same device, operation, failed
state, and target binding. A malformed, missing, live-unconsumed, or
non-immediate predecessor is `RUNTIME_INPUT_INVALID`; corrupt, substituted,
ambiguous, or contradictory durable state is `RUNTIME_STATE_UNSUPPORTED`.

The successor envelope is schema version 1 and binds its canonical parent and
parent digest to the complete embedded ticket and ticket digest. The parent
digest domain is
`AGENT_ROAD_RUNTIME_RECOVERY_AUTHORIZATION_PARENT_V1`. The ticket digest domain
is `AGENT_ROAD_RUNTIME_RECOVERY_TICKET_V2`. A direct successor slot is the only
authority to create or recover its ticket. Reusing an older ancestor reads only
that ancestor's occupied direct slot; advancing from A to B to C requires naming
A and then B explicitly.

The nine-method scoped store facade includes the finite
`resolveAuthorizationSuccessor(parent)` capability. It exact-reads only the
deterministic slot for that canonical parent and returns either null for a
verified clean absence or the exact embedded ticket. If the slot is complete
but its ticket lookup path is cleanly missing, it may republish only that same
embedded ticket. It cannot enumerate, select a latest record, call entropy, or
create new authority; residue, mismatch, replacement, and cross-operation input
fail closed. The resolver revalidates the same slot before and after alias
repair and never delegates to a minting path. For an `EXPIRED_TICKET` parent,
the durable direct child proves that historical eligibility even after clock
rollback; the current-time expiry gate applies only after the exact slot is
verified absent.

The proof separately contains `priorAuthorizedAttempt`, which is deletion
provenance only. It is always null for `EMPTY_PRE_TRANSACTION`, including a
fresh empty-directory reapply whose authorization parent is an attempt. For
`ALREADY_ABSENT`, an immediate parent whose proof was
`EMPTY_PRE_TRANSACTION` contributes its exact attempt; an immediate parent
whose proof was `ALREADY_ABSENT` carries forward that proof's original EMPTY
attempt, including when that ALREADY_ABSENT parent later expires unconsumed. An
expired unconsumed `EMPTY_PRE_TRANSACTION` ticket has no attempt and therefore
cannot attribute absence. Neither the authorization chain nor deletion
provenance is reconstructed by scanning.

The scoped `readAuthorizedDeleteAttempt(ticketId)` exact-reads and validates the
ticket plus successor envelope first. A cleanly missing attempt then returns
null; unsafe, corrupt, replaced, or mismatched state remains
`RUNTIME_STATE_UNSUPPORTED`. Its public strict API may continue to reject a
missing attempt. The same exact references are followed by consumption, commit
creation, commit reads, and pure recovered-state verification; neither
enumeration nor a "latest" selector can supply them.

A ticket is an authorization snapshot, not a lock. Apply must reread the Mac
state and Windows topology and reproduce the exact proof digest immediately
before mutation.

## Exact Cleanup and Unknown Results

For `EMPTY_PRE_TRANSACTION`, apply:

1. under the per-operation lock, reads the exact commit and ticket attempt. A
   valid commit performs only exact Mac CAS; an attempt without a commit returns
   `RUNTIME_COMPLETION_UNCERTAIN`; both paths perform zero remote calls;
2. only when both are cleanly absent, writes and fsyncs the canonical attempt to
   an owner-only exclusive temporary file, publishes its exact ticket-ID path
   with a no-replacement hard link, verifies the controlled temporary/final
   inode pair, fsyncs the namespace, and re-reads the attempt. The durable pair
   binds the failed state, ticket, proof, operation, and authorization time and
   is the consumption and dispatch boundary before any remote call;
3. acquires and validates `Global\AgentRoadRuntimeMutation`;
4. opens and pins the runtime and staging parent identities;
5. performs the complete inspect again and matches the ticket digest;
6. rechecks the observed boot-change barrier;
7. opens the verified operation directory with no-follow and delete access,
   rechecks its file identity and emptiness, then marks that exact handle for
   non-recursive deletion with `SetFileInformationByHandle`;
8. verifies that the operation is absent, staging is empty, both parent
   identities are unchanged, and no other runtime node appeared;
9. returns a fixed success record before releasing the Windows mutex.

It never performs a path-based delete after validation, uses
`Remove-Item -Recurse`, deletes `staging` or `runtime`, follows a reparse point,
repairs an ACL, or cleans an unknown sibling.

For `ALREADY_ABSENT`, apply performs no Windows mutation. It repeats the exact
read-only proof, verifies the matching authorized-attempt record, and proceeds
only to Mac finalization.

If deletion was dispatched and the result is unknown, Mac state remains the
original uncertain `FAILED` state. The controller does not automatically issue
another delete. A later `--inspect` determines:

- exact empty operation still present: a fresh inspect with
  `--prior-ticket <A>` may authorize a successor even though its
  `proof.priorAuthorizedAttempt` remains null;
- exact clean absent topology plus the durable authorized-attempt record: a
  fresh inspect with that immediate parent may finalize as already absent
  without deleting, inheriting original EMPTY provenance across repeated
  already-absent successors;
- exact clean absent topology without that record: `EXTERNALLY_ABSENT` and stop;
- anything else: fail closed.

If remote cleanup succeeded but the Mac CAS failed, the same already-absent
path permits a later idempotent Mac finalization. Reapplying A itself after its
attempt exists never calls Windows again: with an exact commit it performs only
the Mac CAS, and without a commit it remains
`RUNTIME_COMPLETION_UNCERTAIN`. A new remote authorization requires a fresh
inspect naming A and the unique successor ticket it returns.

## Mac Recovery State

Add `RECOVERED` as the only schema-version-2 runtime state. Its field set stays
unchanged, but the schema bump makes older controllers reject it fail closed
instead of silently assigning new meaning to schema 1. A recovered state
retains the original requested profiles, operation ID, manifest digest, and
generation digest, clears ready profiles and failure code, and advances
`updatedAt`.

The only new transitions are:

```text
schema 1 FAILED / RUNTIME_COMPLETION_UNCERTAIN -> schema 2 RECOVERED
schema 2 RECOVERED -> schema 1 INVENTORY_READY with a new operation ID
```

No other failure may enter `RECOVERED`; identity fields cannot change during
the first transition; the new operation cannot reuse the recovered operation
ID. Before the state CAS, recovery publishes an immutable, owner-only
`RECOVERY_COMMIT` record at the deterministic original-operation path. It binds
the authorized-attempt record, expected failed-state digest, proposed recovered
state digest, proof digest, disposition (`REMOVED` or `ALREADY_ABSENT`), and
times, including the proposed recovered-state `updatedAt` needed to reconstruct
an interrupted state CAS. `EMPTY_PRE_TRANSACTION` can commit only `REMOVED`;
`ALREADY_ABSENT` can commit only `ALREADY_ABSENT`, and its proof transitively
binds the exact earlier delete attempt. The local time chain is
`failed.updatedAt <= observedAt <= inspectedAt <= authorizedAt < expiresAt` and
`authorizedAt <= recovered.updatedAt <= committedAt`; Windows event timestamps
remain unordered digest inputs. The record does not claim success by itself:
recovery is committed only when the state equals its proposed recovered-state
digest. Repeating commit creation with the same exact bindings reads and returns
the existing record so a crash before CAS is retryable; any mismatch fails
closed.

An existing commit is valid only when the exact authorized attempt keyed by its
ticket ID is present, the ticket still matches its authorization-successor
envelope, and the attempt digest matches the commit. A commit without that
exact attempt is
`RUNTIME_STATE_UNSUPPORTED`; recovery must never repair or publish the missing
attempt after remote work.

`RuntimeStateStore.transition` verifies that exact record before publishing
schema 2, and `read` refuses a `RECOVERED` state whose record is missing,
unsafe, or mismatched. A crash before CAS leaves a harmless uncommitted record;
a crash after CAS leaves a complete state/record pair without requiring a
second-file update. The fresh schema-1 transition is allowed only after that
pair validates. `RECOVERED` is never treated as `READY`.

Recovery success does not call `prepare`. A later fresh plan and separate
prepare authorization are required.

## First-Class Plan Authorization

Add:

```text
agent-road runtime-plan <device-id> --profile core --baseline <baseline-id>
agent-road prepare <device-id> --profile core --approved <plan-ticket-id>
```

`runtime-plan` requires the exact immutable baseline ID and performs the same
target/state/catalog validation and double inventory stability gate as prepare,
but does not sign, acquire, upload, or mutate Windows. Each call creates a new
immutable owner-only, short-lived plan ticket by exclusive creation; no command
can overwrite or select a "latest" ticket. It prints a redacted plan projection
containing:

- status and finite blockers;
- requested/resolved profiles and acquisition mode;
- transaction mode;
- required free bytes;
- each artifact ID, action, reason, desired version, download bytes, maximum
  expanded bytes, and rollback version;
- artifact source-host policy, signer rule, verifier ID, and short non-secret
  artifact fingerprint;
- controller signing-key identity, whether first trust pinning is required, and
  short revisions for the inventory, provision, and recovery mutators;
- the exact declared mutation scope below the private runtime root;
- explicit non-mutation claims for PATH, registry registration, services,
  scheduled tasks, firewall, profiles, and unrelated ACLs.

The output excludes device/operation IDs, timestamps, inventory/catalog/
manifest/generation digests, addresses, local paths, and commands.

The ticket retains the exact operation ID, created time, validated second
inventory, full plan, stable authorization projection, immutable baseline ID
and record digest, controller public-key ID, first-pin action, exact artifact
hash/source/redirect/signer/verifier fields, hashes of the checked-in inventory,
provision, and recovery code, and local runtime-state snapshot. The
authorization digest excludes operation ID, creation time, exact free bytes,
and the snapshot-specific inventory digest, but includes every field that can
change the mutation decision, artifact bytes, expansion bound, source policy,
verification policy, signing identity, mutator code, baseline binding, or
scope.

`prepare --approved <plan-ticket-id>` must load that exact immutable ticket,
require unchanged local state, catalog, baseline record, signing identity, and
checked-in mutator hashes, repeat the double inventory, recreate the plan with
the ticket's operation/time, and reproduce the authorization digest. Free space
may vary only under the existing above-threshold rule. It consumes the exact
ticket by exclusively publishing and fsyncing an immutable exact-ID
consumed-plan record, retains the original ticket for audit, and then enters the
existing signing/acquisition/provision pipeline. An existing consumed-plan
record always forbids another dispatch.
No ticket or a changed/expired ticket is `RUNTIME_INPUT_INVALID`; semantic drift
is `RUNTIME_INVENTORY_CHANGED`.

The public standalone `prepare` command without `--approved` and an exact ticket
fails before dependency construction, inventory, signing, acquisition, upload,
or mutation. The automatic post-enrollment path uses a separate internal API
whose one-command authorization is already established; it is not exposed as a
CLI bypass.

The automatic post-enrollment core handoff retains its existing one-command
authorization and may use the internal non-preview path. Standalone physical
acceptance uses `runtime-plan` followed by exact-ticket `prepare --approved`.

This slice does not claim durable same-operation resume. The approved plan
ticket is retained for audit on an uncertain failure but is not sufficient to
retry without the later durable-capsule contract.

## Independent External Baseline

Add:

```text
agent-road runtime-baseline <device-id> --capture
agent-road runtime-baseline <device-id> --compare --baseline <baseline-id>
```

Capture runs one fixed, checked-in, read-only Windows PowerShell 5.1 script over
pinned SSH and exclusively creates an immutable owner-only Mac record with a
random baseline ID; it never overwrites a previous capture. Compare requires
that exact baseline ID, reruns the same script, and returns `UNCHANGED` only when
every declared external surface count and MAC is exact. The Agent passes the
full ID internally; the user sees only a short fingerprint and copies no
digest.

Capture generates a random HMAC key, stores it only in the owner-only baseline
record, and supplies it in memory through pinned SSH; Windows never persists it.
The Windows script emits only schema/revision plus bounded record counts and
domain-separated HMAC-SHA-256 values. This avoids offline dictionary recovery
of low-entropy paths, SIDs, names, and commands. Raw surface values never leave
Windows. The HMAC key exists only in the owner-only Mac record and Windows
process memory delivered over pinned SSH; it is never emitted or persisted on
Windows. Every surface has a count and size ceiling; exceeding one fails closed.

The v1 surfaces deliberately cover fixed declared non-mutation sentinels rather
than every service, task, application, or firewall rule on the machine:

- the 64-bit machine environment registry key including PATH, plus the fixed
  AgentRoad-account environment key only when its hive is already mounted;
- fixed global Git/Node/Python/PowerShell command-resolution facts from the
  AgentRoad SSH context;
- static definitions for `sshd`, Tailscale, and Agent Road named services;
- static definitions only below the Agent Road scheduled-task namespace;
- PersistentStore rules selected by fixed Agent Road/OpenSSH/Tailscale identities
  and their address/port/application/service/interface filters;
- the three local firewall profiles' fixed policy fields;
- the fixed AgentRoad account/profile identity sentinel;
- ACLs on fixed runtime-external sentinels and Agent Road bootstrap/SSH sibling
  roots, excluding transient task/transfer contents.

Every surface freezes its data source and primitive normalization. Registry
reads use the explicit 64-bit view and ordinal key/value ordering. Missing and
unmounted values use named sentinels rather than null. CIM and NetSecurity enums
are converted to numeric primitives; null is an empty array; associations and
arrays are ordinal-sorted and deduplicated. Localized display text, inherited
ACL order, and volatile task XML elements are excluded. ACLs are normalized by
owner SID plus sorted explicit rule SID/type/mask/inheritance tuples. Each
surface has a documented item/field/byte ceiling shared by Windows 10/11,
Home/Pro, Chinese/English PowerShell 5.1 fixtures.

Volatile facts are deliberately excluded: process/service runtime status and
PID, task state/history/last/next run, active firewall counters or enforcement
status, profile loaded/last-use state, file timestamps, free space, boot time,
and interactive session state.

An exact comparison failure proves only that a declared surface changed; it
does not assign causation to Agent Road. Acceptance stops and investigates.
The baseline does not claim that every file or every ACL on the machine was
unchanged.

`runtime-plan` for standalone physical acceptance requires one explicit
immutable baseline ID and binds its ID, schema, revision, capture aggregate MAC,
record digest, captured time, and expiry into the plan ticket. It does not
recapture or mutate the baseline. `prepare --approved` does not silently capture
a missing baseline and rejects a replaced, expired, or changed record. The
physical runbook requires capture before plan and exact-ID compare immediately
after prepare. The automatic post-enrollment path remains exempt from this
separate acceptance-only baseline gate.

## Stable Results

Reuse existing finite errors wherever possible:

- malformed command, ticket, or confirmation: `RUNTIME_INPUT_INVALID`;
- wrong local status, unsafe ACL/path/topology, or unknown residue:
  `RUNTIME_STATE_UNSUPPORTED`;
- another operation: `RUNTIME_OPERATION_CONFLICT`;
- lock contention: `RUNTIME_ALREADY_RUNNING`;
- read-only SSH/inspection failure: `RUNTIME_INVENTORY_FAILED`;
- missing or ambiguous boot-session evidence:
  `RUNTIME_BOOT_IDENTITY_UNAVAILABLE`;
- missing observed boot-change barrier: `RUNTIME_REBOOT_REQUIRED`;
- mutation dispatched with an unknown result:
  `RUNTIME_COMPLETION_UNCERTAIN`;
- changed approved plan inputs: `RUNTIME_INVENTORY_CHANGED`.

`RUNTIME_COMPLETION_UNCERTAIN` is recovery-apply-only. Read-only inspect cannot
emit mutation or artifact errors, and recovery-only boot errors are not valid
results for `doctor`, `prepare`, or `runtime-status`.

Success and non-authorizing local handoffs are expressed by canonical result
states (`RECOVERY_READY`, `RECOVERY_PARENT_REQUIRED`,
`RECOVERY_APPLY_REQUIRED`, `RECOVERED`, `PLAN_REVIEW_READY`, and `UNCHANGED`),
not success-shaped error codes. `RECOVERY_PARENT_REQUIRED` supplies the exact
immediate lineage ticket and eligibility time; `RECOVERY_APPLY_REQUIRED`
supplies the exact already-committed ticket for CAS-only replay. A successfully
read baseline that differs returns bounded `CHANGED` with only surface IDs and
count/MAC mismatch flags; read, parse, or bound failures remain finite errors.

## Verification

Local tests must cover:

- a Windows PowerShell 5.1 exact empty-operation fixture, empty staging, wrong
  ACL, extra node, reparse point, and finite native-boundary normalization;
- canonical event-12 boot markers on Windows 10/11, same-boot clock changes,
  sleep/hibernate, reboot, Fast Startup, cleared logs, and unreadable logs;
- read-only inspect with zero deletion calls;
- exact Windows global-mutex acquisition, DACL validation, contention, and
  release around the entire recovery mutation;
- expired/changed tickets and wrong local states failing before mutation;
- sequential same-parent inspect and bounded concurrent ticket publication
  returning one ticket ID, while pre-publication outer-lock contention may
  return `RUNTIME_ALREADY_RUNNING` but can never create a sibling;
  response-loss before and after TTL returning that same ID; same-target proof
  drift returning `RECOVERY_PARENT_REQUIRED` with exact `eligibleAfter`; changed
  target/episode failing closed; and forced sibling records being rejected;
- GENESIS, expired-ticket, and authorized-attempt parents; A -> B -> C exact
  predecessor chains; old-ancestor replay never forking; expired EMPTY tickets
  never attributing absence; expired ALREADY_ABSENT tickets carrying original
  EMPTY provenance; and an expired-child slot preventing predecessor consume
  after clock rollback;
- successor-slot-before-ticket recovery of the same ID; slot-only, ticket-only,
  mismatch, ACL, symlink, replacement, and every immutable-publication crash
  cutpoint failing closed or stabilizing only as specified;
- same-ticket replay and sibling-after-unknown paths performing zero second
  remote calls; immutable exact-ticket selection and no implicit latest
  recovery/plan/baseline record;
- exact parent-derived successor paths, V2 ticket domain, separate
  authorization/deletion-provenance chains, V2 ticket/attempt namespaces, and
  even empty legacy authorization directories failing closed before remote;
- handle-bound non-recursive exact deletion and unchanged parent identities;
- lost delete acknowledgement, already-absent finalization, durable-commit
  `RECOVERY_APPLY_REQUIRED`, and Mac CAS-only retry after ticket expiry;
- externally absent without an authorized-attempt record failing closed;
- crash injection before/after attempt record, delete dispatch, recovery-commit
  record, and state CAS;
- only uncertain failed state entering `RECOVERED`, followed by a distinct new
  operation;
- plan projection/digest sensitivity to every mutation-relevant field and
  insensitivity only to the documented volatile fields;
- plan rejection when signing identity or any checked-in mutator changes, and
  bare public `prepare` performing zero inventory/sign/acquire/upload calls;
- approved prepare consuming the stored exact plan and rejecting drift before
  sign/acquire/upload;
- baseline deterministic ordering, bounds, redaction, volatile-field
  exclusion, exact compare, and PowerShell 5.1 parse/run gates;
- actual Windows PowerShell 5.1 fixtures on Windows 10/11 Home/Pro and
  Chinese/English images for NTFS ACLs, directory handles, NetSecurity, registry
  views, and baseline canonicalization before physical mutation is authorized;
- unchanged existing enrollment, doctor, prepare, runtime-status, exec, put,
  get, pinned SSH, and private-runtime tests;
- static scans forbidding recursive recovery deletion and secret/path output.

After local tests and independent spec/security reviews pass, the first
physical action is a separately authorized read-only recovery inspect. If the
boot-change barrier is missing, reboot is separately authorized and verified
over the existing pinned rescue channel. Only after exact recovery, doctor,
baseline capture, and reviewed plan pass may one new core prepare be authorized.

## Deferred

- reconstructing or resigning the lost current capsule;
- automatic retry of an uncertain operation;
- durable capsule/controller restart resume;
- automatic adoption or cleanup of a pre-link immutable-publication temporary
  file; that crash cutpoint deliberately remains fail-closed and requires
  investigation, so this slice does not claim automatic recovery from every
  publication cutpoint;
- cleanup of any transaction, trust, journal, pointer, generation, work,
  tombstone, or non-empty directory;
- recursive runtime cleanup;
- automatic reboot during recovery;
- base or task profiles;
- widening SSH/firewall/listener scope;
- physical recovery or prepare in this local implementation turn.
