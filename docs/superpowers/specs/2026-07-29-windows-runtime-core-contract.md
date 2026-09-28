# Agent Road Windows Core Runtime Contract

## Scope

This contract freezes Task 5 persistence and recovery semantics. The only human
action remains the connection bootstrap. Everything here happens after
`CONNECTED_SSH_ONLY`, is driven by the Mac Agent, and preserves pinned SSH as
the independent rescue path.

Task 5 installs only the signed portable PowerShell 7 core. It adds no service,
scheduled task, firewall rule, reboot, registry registration, global PATH, or
user-profile mutation.

## Runtime tree

```text
C:\ProgramData\AgentRoad\runtime\
  trust\controller-key.json
  staging\
    <operationId>\
      <manifestDigest>\
        capsule.json
        files\powershell-7-<version>.zip
      work-<manifestDigest>\
        .controller-key.next          # transient only before first trust publish
        generation\
  versions\
    <manifestDigest>\
      capsule.json
      receipt.json
      tools\powershell-7\...
      bin\pwsh.cmd
      env.ps1
      env.cmd
      scripts\runtime-inventory.ps1
      scripts\runtime-provision-core.ps1
    .retired-<manifestDigest>\      # transient committed cleanup tombstone
    .rollback-<manifestDigest>\     # transient rollback cleanup tombstone
  state\
    journal.json
    active.json
    previous.json
```

- `operationId` is exactly 32 lowercase hexadecimal characters.
- SHA-256 and `manifestDigest` values are exactly 64 uppercase hexadecimal
  characters.
- `work-<manifestDigest>` is a sibling of the immutable upload transaction. It
  is never inside `<operationId>\<manifestDigest>`, whose complete allowlist is
  `capsule.json` plus `files`.
- `versions\<manifestDigest>` is published only by a non-replacing same-volume
  directory rename. It is never edited in place.
- A clean committed v1 state permits only the active and previous referenced
  version directories. An in-flight upgrade may temporarily contain the exact
  old previous, old active, and journal-owned new generation. Cleanup first
  atomically renames an unreferenced exact-owned generation to its deterministic
  tombstone; a retry may resume deletion only from that journal-bound tombstone.
- A complete generation root has exactly the four fixed root files and the
  `bin`, `scripts`, and `tools` directories shown above. `bin` contains only
  `pwsh.cmd`, `scripts` contains only the two fixed scripts, and `tools`
  contains only `powershell-7`. Receipt verification does not authorize extra
  siblings.
- Every runtime node is a non-reparse canonical path. Files are single-link.
  Owner is Administrators and the protected ACL is exactly Administrators and
  SYSTEM FullControl, with `PropagationFlags.None` on every rule. Every owned
  directory and file receives that descriptor in the creation API itself;
  creation followed by an ACL repair is forbidden. The provisioner then
  rereads and verifies the exact owner and ACL.
- Task 5 uses the generation's absolute `pwsh.exe` path.

Erratum (2026-07-30): the original contract scheduled a stable root launcher for
Task 6. Task 6 retains the generation-specific absolute path and does not deliver
that launcher. A stable root launcher remains deferred to a later separately
reviewed slice; any incompatible launcher-format change must advance the
catalog/receipt revision rather than reuse an existing generation identity.

The filesystem race threat model excludes a malicious local Administrator or
SYSTEM principal: either can replace the runtime despite any Agent Road ACL.
Task 5 still revalidates every parent, path, ACL, reparse/link fact, byte length,
and hash before and after publication, and serializes one controller operation.

## Controller trust key

`trust\controller-key.json` is the exact canonical UTF-8, no-BOM, no-newline
byte string already carried by `controllerPublicKeyJson`:

```json
{"algorithm":"RSA-SHA256","modulusBase64Url":"...","exponentBase64Url":"AQAB"}
```

Pinned SSH anchors the first write. The target first verifies the RSA-3072
shape and domain-separated `controllerKeyId`. Later runs require byte equality;
the key is never rotated or replaced automatically. A verified key without an
activated runtime is a supported `trust-key-only` state. An empty trust
directory is supported only as an interruption of the same staged operation.

The first write never writes `controller-key.json` directly. After the signed
capsule and exact staged-operation binding are verified, the provisioner creates
the fixed `work-<manifestDigest>\.controller-key.next` file with the exact
protected ACL in the creation API, flushes it through to disk, and verifies its
length, SHA-256, and bytes. It then revalidates both restricted parents and
atomically moves that same-volume file to `trust\controller-key.json` with
`WRITE_THROUGH` and without replacement. A retry may inspect, remove, and
recreate only that exact operation-bound temp, only while the final path is
absent. A complete temp is reused. A partial temp is deleted and rewritten.
An existing final key is only reread and compared; mismatch, a coexisting temp,
or any other residue fails closed without deleting or overwriting the final.

## Pointer

`active.json` and `previous.json` have exactly these eight fields in this order:

```json
{
  "schemaVersion": 1,
  "receiptFormatRevision": 1,
  "manifestDigest": "<SHA256>",
  "generationDigest": "<SHA256>",
  "catalogRevision": 7,
  "catalogDigest": "<SHA256>",
  "receiptBytes": 1234,
  "receiptSha256": "<SHA256>"
}
```

Both revisions and `receiptBytes` are positive integers; `receiptBytes` is at
most 32768. A receipt path is derived from `manifestDigest`, never persisted.
A fresh install has no `previous.json`. During an upgrade, `previous.json`
contains the exact prior active pointer.

## Immutable receipt

`versions\<manifestDigest>\receipt.json` has this ordered schema:

```json
{
  "schemaVersion": 1,
  "receiptFormatRevision": 1,
  "operationId": "<operationId>",
  "manifestDigest": "<SHA256>",
  "generationDigest": "<SHA256>",
  "catalogRevision": 7,
  "catalogDigest": "<SHA256>",
  "controllerKeyId": "<SHA256>",
  "profiles": ["core"],
  "components": [
    {
      "id": "powershell-7",
      "version": "7.x.y",
      "bytes": 1,
      "sha256": "<SHA256>",
      "installRoot": "tools/powershell-7",
      "fileCount": 1,
      "directoryCount": 0,
      "expandedBytes": 1,
      "treeSha256": "<SHA256>",
      "verificationCommandId": "powershell-json-roundtrip",
      "verified": true
    }
  ],
  "files": [
    {"path":"bin/pwsh.cmd","bytes":1,"sha256":"<SHA256>"}
  ],
  "restartRequired": false
}
```

Task 5 requires exactly `profiles=["core"]` and one `powershell-7` component.
Components and files are ordinal-sorted. `files` completely covers
`capsule.json`, `bin/pwsh.cmd`, `env.cmd`, `env.ps1`, and both fixed scripts.
It does not list `receipt.json`, which is bound by pointer length and hash.

The tool-tree digest covers every directory and file below
`tools\powershell-7`. Before extraction or hashing, the provisioner rejects
absolute and parent paths, ADS, case collisions, trailing dot/space, device
names, control characters, non-regular entries, reparse points, hard links,
more than 8192 ZIP entries, and expansion beyond signed
`maximumExpandedBytes`. Each file is streamed to a `CreateNew` destination whose
protected security descriptor is applied by the security-aware `FileStream`
constructor, with bounded per-entry and aggregate counters; actual copied bytes
must equal both ZIP metadata and must not exceed the signed maximum, and an incomplete
destination is removed before failure. `pwsh.exe` must pass signer, exact version, and bounded strict
JSON round-trip checks. Raw verifier output is not persisted.

The signed manifest uses exact scalar and JSON-array types. Its `deviceId` must
equal the value in the restricted stage-zero bootstrap journal. Target
preflight also binds exact Windows version/build/edition/architecture, Windows
PowerShell version, and elevated state; a mismatch is inventory drift. The
embedded controller-key JSON must be byte-for-byte canonical before key-ID or
signature verification. The stage-zero journal itself must be owned by
Administrators with a protected canonical DACL containing only explicit,
non-inherited SYSTEM and Administrators FullControl rules.

## Journal

`state\journal.json` has exactly these ordered fields:

```json
{
  "schemaVersion": 1,
  "revision": 1,
  "operationId": "<operationId>",
  "manifestDigest": "<SHA256>",
  "generationDigest": "<SHA256>",
  "catalogDigest": "<SHA256>",
  "inventoryDigest": "<SHA256>",
  "controllerKeyId": "<SHA256>",
  "requestedProfiles": [],
  "status": "running",
  "phase": "materialize-generation",
  "completedPhases": [
    "discover",
    "verify-manifest",
    "verify-artifacts",
    "snapshot"
  ],
  "changes": [],
  "snapshot": {"active":null,"previous":null},
  "restartRequired": false,
  "failureCode": null,
  "rollbackStatus": "not-attempted"
}
```

- `revision` increases on every journal publication.
- `status` is `running`, `uncertain`, `failed`, `rolled-back`, or `committed`.
- `phase` is `discover`, `verify-manifest`, `verify-artifacts`, `snapshot`,
  `materialize-generation`, `self-test`, `atomic-activate`, `validate`,
  `commit`, `rollback`, or `reconcile`.
- `completedPhases` is a strict prefix of the first nine forward phases.
  `rollback` and `reconcile` may only be the current phase.
- `changes` is a strict prefix of `work-created`,
  `generation-publish-planned`, `previous-replace-planned`, and
  `active-replace-planned`.
- The pointer snapshot is null or a complete exact pointer.
- `rollbackStatus` is `not-attempted`, `pending`, `succeeded`, or `failed`.
  Committed has no failure; rolled-back requires succeeded. An incomplete
  rollback preserves the original failure and returns
  `RUNTIME_ROLLBACK_INCOMPLETE`.
- No path, key material, token, command, stdout/stderr, or user data is stored.

## Atomic publication

Every mutable JSON publication uses the operation work directory:

1. create a unique next file with `CreateNew`, `FileShare.None`,
   `WriteThrough`, and the exact protected owner/ACL supplied to the
   security-aware `FileStream` constructor;
2. flush and verify the exact ACL;
3. reopen without following reparse points and verify bytes/hash;
4. revalidate source and destination parents;
5. call same-volume `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`;
6. reread and byte-verify the final path.

Generation publication is write-ahead logged, fully materialized and verified
under `work-<manifestDigest>\generation`, then renamed without replacement.
An existing destination may be adopted only if receipt, capsule, operation,
digests, tree, signer, version, and smoke test all match exactly.

The immutable first controller trust anchor uses its separate pre-journal
publication rule above. It is never published with `REPLACE_EXISTING`.

Activation order is fixed:

1. immediately after the trusted journal is durable, and before reconciliation
   or any other fallible forward phase, persist the complete old
   active/previous snapshot;
2. log `previous-replace-planned`;
3. publish previous from old active, or keep it absent for a fresh install;
4. log `active-replace-planned`;
5. atomically publish the new active pointer;
6. validate pointer -> receipt -> capsule signature -> tree -> smoke;
7. publish committed journal;
8. if the snapshot had an older previous generation, recheck both live pointers,
   fully verify exact ownership, and atomically rename it to
   `.retired-<manifestDigest>` before resumable deletion;
9. strictly clean staging/work before reporting certain success.

## Interruption reconciliation

| Visible boundary | Required decision |
|---|---|
| Mixed staged temp/final, no journal | Same operation resumes `provisionUpload`; another operation conflicts. |
| Partial operation-bound `.controller-key.next`, no final key, no journal | Only the same signed staged operation may validate the exact temp path and ACL, delete the partial file, rewrite, verify, and perform the non-replacing move. |
| Complete operation-bound `.controller-key.next`, no final key, no journal | Only the same signed staged operation may byte/hash verify and resume the non-replacing move. |
| Key written, no journal | Exact key must match; reverify the original capsule. Never replace or delete a mismatch. |
| Final key plus `.controller-key.next` | Fail closed; do not clean either path automatically. |
| Snapshot journal, old pointers intact | Continue from the next forward phase. |
| Partial work generation | Delete only the verified owned work generation and re-expand. |
| Complete work before rename | Reverify tree/signer/version/smoke, then publish. |
| Version exists before journal update | Adopt only on complete exact equality. |
| Previous changed, active old | Continue active replacement. |
| Active new before validation | Revalidate; commit or roll back. |
| Committed with staging residue | Perform only strict owned cleanup, then succeed. |
| Committed with `.retired-<digest>` residue | Require exact `snapshot.previous` binding and no live reference, then resume allowlisted restricted-tree deletion. |
| Interrupted rollback | Restore active, restore previous, verify old smoke, then remove new generation. |
| Rollback with `.rollback-<digest>` residue | Require the rollback journal digest, restored/non-referencing pointers, and an allowlisted restricted subtree, then resume deletion. |
| Terminal rolled-back plus a different exact staged operation | Finish only the old journal-bound tombstone and staging cleanup, then replace the terminal journal with the new operation. |
| Any other combination | Do not delete; return unsupported or rollback-incomplete. |

Any upload ambiguity or apply timeout after dispatch is
`RUNTIME_COMPLETION_UNCERTAIN`; it is never blindly retried. The same
`operationId` permanently reuses its original capsule and `manifestDigest`.
If that capsule is lost, reconciliation fails closed; it never re-signs a new
manifest with the old operation ID.

## Inventory and controller serialization

The fixed provisioner receives exactly one canonical UTF-8, no-BOM,
no-newline stdin record. Field order and spelling are exact:

```json
{"schemaVersion":1,"operationId":"<32 lowercase hex>","manifestDigest":"<64 uppercase hex>"}
```

The dedicated controller wrapper writes those bytes to the child process and
then closes stdin. The provisioner rejects an empty, oversized, reordered,
non-canonical, or extra-field record. It never discovers an operation by
enumerating staging directories and accepts no arbitrary command line.

The outer inventory schema stays unchanged. Runtime recognition covers absent,
trust-key-only, exact staged/work-only, pending journal plus old active,
committed plus cleanup residue, clean active, active plus previous, and clean
rolled-back states. Unknown extra operations, versions, nodes, ACLs, or digest
relationships are `RUNTIME_STATE_UNSUPPORTED`.

`runtimeProvision` holds one per-device trusted-session lock, selects one pinned
address, and inventories before upload. The signed baseline remains the exact
validated snapshot whose exact digest (including exact `freeBytes`) is bound by
the plan and capsule. Controller input must prove that exact digest binding
before SSH. Stability is then evaluated separately: every canonical field other
than `freeBytes` must remain exact, and the live `freeBytes` must still be at
least the actionable plan's explicit `requiredFreeBytes`. Only above-threshold
free-space volatility is accepted; there is no tolerance or bucket. A threshold
drop or any other fact change fails before every runtime upload or apply.

The controller then stages and invokes the provisioner in that same session.
Upload changes free space and runtime state, so post-upload inventory cannot be
compared with the original digest. After acquiring the target mutation lock,
the provisioner independently rechecks architecture/build, elevation, all three
pending-reboot sources (CBS, Windows Update, and
`PendingFileRenameOperations`), the post-upload disk threshold derived from the
signed `maximumExpandedBytes`, pointers, and journal before mutation.

Terminal exact-owned cleanup is the sole pre-gate mutation carve-out. A
previously `committed` or `rolled-back` journal may resume only its exact
journal/receipt/pointer-bound staging or deterministic tombstone cleanup; it may
not materialize or activate the incoming plan, and unknown residue fails
closed. Every new-plan path validates the signed manifest, embedded controller
identity/signature, and staged-operation binding before the machine gate. That
gate precedes its first restricted directory/trust/journal creation and every
generation materialization or pointer activation.

The Windows lock is the single machine-wide
`Global\AgentRoadRuntimeMutation` kernel mutex. Its owner and protected DACL are
re-read before `WaitOne`: owner is Administrators and the only two explicit,
non-inherited rules are Administrators and SYSTEM FullControl with no
inheritance or propagation. The security supplied to the constructor is not
trusted for an already-existing mutex. Inaccessible, incompatible, or
wrong-security objects fail closed; only contention on a verified mutex is
`RUNTIME_ALREADY_RUNNING`. There is no file-lock fallback or timestamp lease.
