# Agent Road Windows Runtime Provisioning Design

## Goal

Turn the existing one-line Windows enrollment into a true human-to-Agent handoff. The human performs only the minimum action needed to establish the permanent rescue channel: paste one elevated PowerShell command and, on a new Tailnet device, complete the Tailscale browser sign-in. The generated-command notice states that continuing also authorizes Agent Road to install its private default runtime below `C:\ProgramData\AgentRoad` after SSH verification. Once the Mac publishes `CONNECTED_SSH_ONLY`, the Mac-side Agent owns all later environment preparation and task execution without a second human command.

The Windows computer continues to run no local model. It receives a deterministic, Agent Road-managed work environment so the Mac Agent can build websites, organize local material, conduct research, write papers, install task software, and maintain the machine without asking the human to paste more commands.

## Core Boundary

The initial command is a connection bootstrap, not a complete workstation installer.

```text
Human: one elevated command + optional Tailscale browser confirmation
                               |
                               v
                    CONNECTED_SSH_ONLY
                               |
                               v
Mac Agent: inventory -> plan -> provision -> verify -> work -> maintain
```

Tailscale plus pinned-host-key OpenSSH remains the independent rescue path. It is not replaced by the provisioned runtime and must remain usable if provisioning, an individual tool, or a later task fails.

`CONNECTED_SSH_ONLY` is a transport fact and the control handoff barrier, not runtime success. The controller tracks transport and runtime independently:

```text
transportStatus = CONNECTED_SSH_ONLY
runtimeStatus   = UNPROVISIONED | INVENTORY_READY | PLAN_READY |
                  ACQUIRING | STAGED | VERIFYING | READY | FAILED
```

Task 6 uses only the coarse Mac checkpoints `UNPROVISIONED`,
`INVENTORY_READY`, `PLAN_READY`, `ACQUIRING`, `READY`, and `FAILED`. `STAGED` and
`VERIFYING` are reserved controller summaries of trusted Windows-journal progress
for a later phase-streaming slice; the current black-box provision call does not
persist or print them.

Normal enrollment automatically calls `ensureRuntime` for the default runtime generation after transport publication and after the enrollment signal/cleanup barrier has ended. Provisioning failure leaves `transportStatus` and the SSH rescue channel intact. The first slice publishes `runtimeStatus=READY` independently and does not reuse the existing top-level device `READY`, whose older contract represents capabilities beyond the private core runtime.

The existing device registry remains the source of transport truth. Runtime truth is stored separately on the Mac below `~/.agent-road/runtime/devices/<device-id>/state.json`; a missing record for an already connected device means `UNPROVISIONED`. This preserves the exact device-record schema and makes a crash between transport commit and runtime preparation recoverable through the next idempotent `ensureRuntime`.

The Mac state-store checks defend against unsafe modes or ACLs, other local
principals, symlink/rename endpoint races, and cooperative concurrent Agent Road
controllers. Its file lock is a concurrency primitive, not a security boundary.
A malicious process already running as the same Mac login user is outside this
threat model because that process can also replace the controller executable,
device private keys, or state before launch; every opened endpoint is still
pinned and revalidated during a legitimate operation.

## Selected Approach

Agent Road creates a private, versioned runtime below:

```text
C:\ProgramData\AgentRoad\runtime\
  trust\
  staging\
  versions\
  state\
```

The exact Task 5 tree and JSON contracts are frozen in
`2026-07-29-windows-runtime-core-contract.md`. Downloads and catalogs remain on
the Mac; they are not a second package manager on Windows.

The base runtime uses portable or self-contained distributions wherever practical. It does not depend on Git, Node.js, Python, `winget`, Microsoft Store, Chocolatey, or a pre-existing package manager. It does not replace compatible user installations, alter the user's global PATH, or make the task depend on whichever version happens to be installed globally.

After the tiny core runtime is ready, the normal `base` profile and task-specific profiles add only what the task requires. A website task may add web and headless-browser profiles; a paper task may add research; visible desktop control remains a later optional profile.

## Why This Replaces Long Remote Commands

Before the runtime exists, Agent Road may use Windows PowerShell 5.1 only as a small, signed staging launcher. The controller uploads complete scripts, manifests, and artifacts through the already pinned SSH/SFTP channel, verifies their digests, and invokes them with a short fixed command.

After PowerShell 7 and the runtime launcher are installed, all normal work uses uploaded files and the private runtime. Agent Road does not repeatedly embed large scripts in `-EncodedCommand`, parse localized human-readable output, or assume PowerShell 5.1 enum and CIM projections are identical across builds.

## Runtime Layers

### 1. Core capsule

The implicit `core` capsule contains only the deterministic runner needed to stop depending on the target's original shell environment:

- PowerShell 7;
- Agent Road launch, environment, inventory, transaction, and verification scripts.

The PowerShell ZIP is expanded with bounded built-in .NET archive APIs, so core does not need another archive tool. Core is installed first and verified before any larger profile. It is intentionally small enough to recover, replace, or upload again through SSH.

### 2. Base profile

The normal `base` profile extends core with fixed, independently verifiable builds of:

- MinGit or an equivalent portable Git-for-Windows distribution;
- one supported Node.js LTS runtime;
- one explicitly selected Python runtime and environment strategy;
- `ripgrep`;

Python is never assumed to exist before provisioning. The Python distribution/provider decision remains a release-catalog gate: production `base` stays disabled until its provenance, redistribution boundary, fixed artifact metadata, package-management behavior, and `venv`/package-install smoke tests are independently verified. The exact versions, architectures, vendor URLs, controller-reviewed redirect origins, download bytes, maximum expanded bytes, hashes, signer expectations, install mode, and verification commands live in a reviewed pinned local catalog rather than in task prompts. The catalog file is not itself described as signed; its canonical digest is bound into the controller-signed transaction manifest.

### 3. Task profiles

The intended profile vocabulary is finite. The first schema reserves `core` and `base`, while the first executable transaction is deliberately `core`-only:

- `web`: base plus the pinned JavaScript package-manager policy and web build tools;
- `browser-headless`: a dedicated Playwright/Chromium build and an Agent Road-owned browser profile;
- `research`: a pinned Python runtime, isolated Python environment, and document/PDF conversion tools;
- `media`: pinned media inspection and conversion tools such as FFmpeg;
- `desktop`: reserved for a future interactive-session helper and never implied by base readiness.

Profiles are composable, versioned desired states. A task asks for capabilities, the controller maps them to profiles, and the planner returns the exact delta. The first transaction implementation accepts only `core`; `base` is reserved in the catalog and planner but remains disabled until its release artifacts and verifiers pass their own gate. Unknown or not-yet-executable profile names fail before transport.

### 4. System-integrated software

Portable runtime tools are the default. Software that must register services, drivers, shell extensions, browsers, Office automation, or machine-wide components uses a separate system-install plan. Such a plan must declare its mutations, reboot behavior, rollback limits, licensing boundary, and verification before execution. It is never silently smuggled into `base`.

## Provisioning Protocol

### Inventory

The first post-SSH operation is read-only. Inventory represents only bounded target facts; it contains no device ID, operation ID, timestamp, path, user name, session ID, global-tool discovery, URL, command, or stdout/stderr. Its exact object schema is:

```text
schemaVersion
platform { os, version, build, edition, architecture,
           windowsPowerShellVersion, elevated }
freeBytes
pendingReboot
interactiveSession
runtime { schemaVersion, catalogRevision, catalogDigest,
          generationDigest, generationVerified,
          pendingOperationId, restartRequired }
managedArtifacts[] { id, version, bytes, sha256, verified }
```

Managed artifacts are sorted by ID and limited to 32. An unverified record may use null bytes/hash; a verified record must have bounded bytes and an uppercase SHA-256. A verified generation requires a complete schema/catalog/generation tuple and verified managed records. A null generation requires the tuple to be null and `generationVerified=false`. `pendingOperationId` is null or one canonical operation ID.

The object validator accepts bounded platform facts such as `arm64` or a build below the catalog minimum so the planner can return an explicit unsupported-platform result. The Windows source maps native `AMD64` to catalog `x64`; it never compares the raw architecture string directly.

Task 2 canonicalizes a validated object and computes its digest. The exact digest
includes the exact `freeBytes` value and remains the signed audit identity of
that inventory snapshot; it is not, by itself, a stability predicate across
successive reads. Task 3 additionally requires the Windows source to emit
exactly that canonical UTF-8 JSON text, capped at 32 KiB. Agent Road never
infers success from localized console text.

Task 3 initially recognizes only the completely absent runtime state. If `C:\ProgramData\AgentRoad\runtime` does not exist, it emits the null generation tuple, `generationVerified=false`, `pendingOperationId=null`, `restartRequired=false`, and an empty managed-artifact list. Any runtime root, active/previous pointer, journal, staging operation, generation, reparse point, or inconsistent residue fails closed as `RUNTIME_STATE_UNSUPPORTED`; it is never reported as unprovisioned. Task 5 must first freeze the signed manifest, immutable generation receipt, active pointer, and journal contracts, then extend only `Get-AgentRoadRuntimeStateSnapshot` and its focused tests. The outer inventory schema, pinned transport, canonical parser, and 32 KiB boundary remain unchanged.

### Plan

The Mac computes a deterministic desired-state plan. Each item is exactly one of:

- `present`: the managed version and verification already match;
- `install`: no managed version exists;
- `repair`: state exists but its content or postcondition is invalid;
- `upgrade`: an older managed version may be retained for rollback;
- `blocked`: compatibility, disk, a newer managed version, or restart requirements prevent safe work.

Planning is side-effect free. It validates and hashes the complete catalog and inventory snapshots itself; it never accepts a caller-supplied digest. The caller provides only primitive, validated `deviceId`, 32-hex `operationId`, and canonical millisecond UTC `createdAt` values. The plan binds those values, the calculated inventory/catalog digests, requested and resolved profiles, `acquisition=mac-relay`, a finite blocker list, conservative required free bytes, and artifact items in ID order.

The exact plan shape is:

```text
schemaVersion, operationId, createdAt, deviceId
inventoryDigest, catalogDigest
requestedProfiles[], profiles[]
acquisition, transactionMode, status, blockedReasons[], requiredFreeBytes
items[] {
  artifactId, action, reason,
  desired { version, bytes, maximumExpandedBytes, sha256 },
  current null | { version, bytes, sha256, verified },
  rollbackVersion
}
```

`transactionMode` is exactly `new`, `reconcile`, or `conflict`. Global blockers use the canonical order `platform-architecture-unsupported`, `platform-build-unsupported`, `windows-powershell-unsupported`, `elevation-required`, `pending-reboot`, `runtime-schema-unsupported`, `catalog-revision-newer`, `catalog-revision-equivocation`, `runtime-operation-conflict`, `runtime-restart-required`, and `disk-insufficient`; `managed-version-newer` follows them when present. A verified active catalog revision newer than the desired catalog is an anti-rollback blocker. A supported, verified generation with the same revision but a different digest is `catalog-revision-equivocation`, never an automatic repair; an unverified generation may still be repaired. A pending operation blocks only a different operation ID; the same ID yields `reconcile` and is reserved for Task 5 journal and active-pointer reconciliation rather than a fresh apply. An older artifact version is named as a rollback candidate only when the runtime schema is supported and both the record and its active generation are verified.

If every item is present, required free bytes are zero. If any mutation is needed, the conservative requirement is a 256 MiB transaction reserve plus the sum of each resolved artifact's download bytes and maximum expanded bytes, allowing a complete new generation to coexist with the active generation. No compression ratio or caller-provided disk estimate is used.

Task 2 does not claim the inventory changed: it creates a plan for the snapshot
it received. The orchestration stability gate compares two validated
inventories exactly except for `freeBytes`, whose only stable meaning is whether
it is at least the plan's `requiredFreeBytes`. Both readings above the threshold
or both readings below it are semantically stable; crossing the threshold in
either direction or changing any other canonical fact is
`RUNTIME_INVENTORY_CHANGED`. Plans must also be equal after excluding only their
snapshot-specific `inventoryDigest`. The second exact snapshot and its exact
digest become the signed baseline. This permits ordinary free-space churn
without tolerance windows or buckets, while a stable below-threshold pair still
produces the deterministic `disk-insufficient` blocker.

Task 5 holds one trusted session/address and, before any upload, re-inventories
against that signed exact baseline. It again permits only `freeBytes` volatility,
and only while the live value remains at least the actionable plan's explicit
`requiredFreeBytes`; a drop below the threshold or any other fact change is
`RUNTIME_INVENTORY_CHANGED` before upload. Upload changes disk/runtime state, so
the original digest is not compared after upload. After acquiring the target
mutation lock, the provisioner independently rechecks the complete pending
reboot predicate (including `PendingFileRenameOperations`), the post-upload disk
threshold derived from the signed expansion ceiling, decision-critical
platform/elevation facts, pointers, and journal before mutation. A mismatch
returns `RUNTIME_INVENTORY_CHANGED` without applying the plan.

The only mutation permitted before that machine gate is narrow terminal
reconciliation cleanup for an already `committed` or `rolled-back` journal. It
may remove only exact journal/receipt/pointer-bound staging or deterministic
cleanup tombstones already owned by that terminal transaction; unknown residue
fails closed. This carve-out never materializes a generation or changes an
active/previous pointer for the incoming plan. Every new-plan path first
validates the signed manifest, embedded controller identity/signature, and
operation binding, then passes the machine gate before its first restricted
directory/trust/journal creation and before materialization or activation.

### Acquire

The first implementation has one acquisition path: the Mac downloads an artifact from the exact catalog source, verifies it, caches it, and uploads it over pinned SSH. The target needs no public internet route or VPN. Windows re-verifies the same pinned byte length and SHA-256 and, where applicable, the expected Authenticode signer and valid signature. Each ZIP also carries a pinned `maximumExpandedBytes` used as both an extraction ceiling and a conservative disk-planning input. There is no `latest` URL, `irm | iex`, unpinned mirror, or package-manager search result in the execution path.

Before the first production catalog, schema v1 was amended to require `redirectOrigins` on every artifact. It is a canonical sorted array of zero through four unique HTTPS origins, cannot repeat the artifact source origin, and is included in the catalog digest. The Mac fetcher handles redirects manually with a small fixed limit and permits every hop only when its origin is the source origin or one of that artifact's controller-reviewed `redirectOrigins`; an unbound HTTP `Location` is never trusted. The amendment was necessary because the official GitHub release URL redirects from `github.com` to `release-assets.githubusercontent.com`. No temporary signed CDN URL or query is persisted in the catalog or evidence. One absolute acquisition deadline covers lock wait, download, body cancellation, cache hashing, publication, and bounded cleanup; expiration can never return success or begin a fresh publication. The policy validator accepts at most 30 minutes so the 116,979,293-byte core artifact is not structurally limited to 120 seconds; the orchestration slice must still choose the exact production value. Cache files and lock state are owner-only, no-follow, single-link regular files, and all public acquisition errors are finite and path-free. A crashed publisher or lock owner is reconciled only from a narrowly verified same-inode temporary/final pair or a strictly validated dead-owner lock record; unknown residue is never deleted automatically.

Provisioning uses a private `provisionUpload` primitive rather than relaxing public `put/get`. It reuses the trusted SSH session, per-device lock, strict stderr, and transfer bounds, but can write only operation-bound component files below `runtime\staging\<operation-id>`. Each component is independently bound to its byte length and SHA-256.

The v1 transfer contract is at most 32 components and at most 256 MiB per
component. The same bounds apply to catalog validation, cache acquisition,
manifest validation, local snapshots, wrapper schemas, and target verification.
Every fixed invocation is constructed on the Mac before init can mutate the
target. One operation ID binds to one manifest digest and only the matching
`work-<manifestDigest>` sibling. Finalized artifacts are batch-reinspected
immediately before the capsule is published as the completion marker.

The signed runtime manifest uses the existing RSA-3072 controller key with protocol-domain separation. The signed bytes are exactly:

```text
AGENT_ROAD_RUNTIME_V1 NUL canonical-manifest-bytes
```

The canonical manifest binds device ID, operation ID, platform, catalog digest, inventory digest, profile set, generation digest, and every component record. A bootstrap/stage-one signature cannot be replayed as a runtime manifest signature or vice versa.

`generationDigest` and `manifestDigest` are intentionally different. The generation digest domain-separates and hashes the stable desired generation record: catalog identity, catalog platform, resolved profiles, and every resolved artifact component record. It excludes device ID, operation ID, inventory, and time. The manifest then binds that generation digest to one device, operation, inventory snapshot, timestamp, acquisition mode, and the finite phase vocabulary; `manifestDigest` hashes those canonical manifest bytes. This avoids a self-referential digest while allowing repeated operations to identify the same desired generation. Fixed provisioning scripts continue to use the existing hash-verified `executeRemoteScript` path; their installed outputs and hashes belong to the immutable Task 5 receipt. Any incompatible provisioner or launcher-format change must advance the catalog/receipt revision rather than silently reuse an old generation identity.

The canonical generation record has exactly these fields, in this order: `schemaVersion`, `catalogRevision`, `catalogDigest`, `platform`, `profiles`, and `components`. `platform` is the catalog's desired platform record, not the device inventory platform. Keeping this preimage explicit prevents the controller and Windows provisioner from recomputing different generation identities.

The generation hash input is `AGENT_ROAD_GENERATION_V1 NUL canonical-generation-bytes`. The persisted controller key ID hashes `AGENT_ROAD_CONTROLLER_KEY_V1 NUL canonical-public-key-bytes`. All digests are uppercase SHA-256; the canonical JSON contains no URL, local path, remote path, or command line.

The signed capsule also carries the controller's existing RSA-3072 public payload. On the first runtime creation, pinned SSH is the trust anchor that delivers this public key and capsule into the new administrator/SYSTEM-only runtime root. The target persists the key before activation. Every later prepare/reconcile requires an exact match with that persisted key and never replaces it automatically. Runtime signatures therefore protect stored transaction state and later reconciliation; they do not pretend to replace pinned SSH as the first-delivery trust boundary.

At the controller boundary, the runtime manifest dependency adapter maps `getSigningPublicKey` to the existing `BootstrapSigner.getOrCreate()` method and maps `sign` to a bound call of `BootstrapSigner.sign(bytes)`. The methods are never passed unbound.

The signed phase vocabulary is exactly `discover`, `verify-manifest`, `verify-artifacts`, `snapshot`, `materialize-generation`, `self-test`, `atomic-activate`, `validate`, `commit`, `rollback`, and `reconcile`. The journal may record only these values. A controller-key-only state after a failed first verification is a recognized restricted runtime state in Task 5; it is not an empty runtime and it does not authorize activation.

### Stage and publish

Artifacts enter `staging\<operation-id>\<manifest-digest>` with an administrator/SYSTEM-only ACL. Mutable extraction uses its sibling `work-<manifest-digest>`, never the immutable upload transaction. Agent Road extracts only into a new generation and publishes it by a non-replacing same-volume rename at `versions\<manifest-digest>`. The active pointer records both the operation-specific manifest digest and the stable generation digest. Agent Road verifies canonical paths, rejects reparse points and path escapes, caps entry count and expanded bytes, and never overlays a live generation in place.

Every generation contains its own tools, `bin` launchers, `env.ps1`, `env.cmd`, and verified manifest. After all tool-specific verification succeeds, Agent Road atomically replaces only `state\active.json`; `state\previous.json` identifies the last verified generation for rollback. Task 5 and Task 6 call the generation's absolute PowerShell path. The stable root launcher originally scheduled for Task 6 remains deferred to a later separately reviewed slice; any incompatible launcher-format change advances the catalog/receipt revision. Normal tasks receive the generation environment explicitly; the user's global PATH is unchanged.

### Verify

Every tool has a machine-readable verifier that checks:

- canonical executable path below the managed version directory;
- file length/hash and non-reparse state;
- exact or allowed version output;
- bounded exit code/stdout/stderr;
- one minimal functional probe, such as a local Node script, Git repository read, Python import, or PowerShell JSON round trip.

Profile readiness is the conjunction of all tool verifiers. Merely finding an executable on PATH is not success.

## Idempotence, Resume, and Rollback

Only one provisioning operation may hold an exclusive Windows kernel mutex or an exclusively opened lock file for its complete lifetime. A restricted journal records schema version, operation ID, requested profiles, catalog digest, completed checkpoints, changes owned by that operation, restart requirement, and finite failure code. It contains no enrollment token, private key, proxy credential, browser credential, or raw task content.

The pointer, receipt, journal, atomic-publication, and interruption decision
tables are normative in `2026-07-29-windows-runtime-core-contract.md`. The same
operation ID always reuses its original capsule and manifest digest; losing it
fails closed rather than re-signing a different manifest with the old ID.

Re-running after interruption:

1. acquires the exclusive machine lock rather than trusting an expired timestamp;
2. reloads the journal;
3. revalidates every completed checkpoint;
4. reconciles the active pointer, manifest digest, staged bytes, and smoke-test facts before deciding to resume;
5. otherwise rolls back only Agent Road-owned staged/current pointers and returns a finite blocked state.

It never deletes or replaces a pre-existing user tool installation. A timeout after any mutation begins returns `RUNTIME_COMPLETION_UNCERTAIN`; a later attempt must reconcile facts and cannot blindly reinstall.

Task 6 local implementation boundary: the Windows provisioner can reconcile only when it receives the exact original signed capsule, but the first Mac orchestration slice does not yet persist that capsule durably across controller-process death. It therefore rejects persisted intermediate and completion-uncertain Mac states rather than reconstructing or re-signing incomplete facts. This is a fail-closed implementation gap, not a relaxation of the resume contract. Owner-only durable capsule persistence, exact readback validation, and same-operation controller re-entry are required before automatic controller-crash recovery or its physical fault injection may be claimed.

Core and portable profiles do not need a permanent service, startup task, reboot, MSI, PATH change, or registry change. Reboot-resume support belongs to a later system-integrated software slice.

## Controller Surface

The intended Mac commands are:

```text
agent-road doctor <device>
agent-road prepare <device> --profile base
agent-road runtime-status <device>
```

`ensureRuntime` is invoked automatically after enrollment and later before a task whose required profiles are not ready. `doctor` is read-only. `prepare` is the explicit repair/maintenance entry, not a required second human step. Task 6 prints bounded transport/runtime results and persists only coarse controller checkpoints. It does not stream or claim the Windows provisioner's intermediate journal progress. Raw installer output is bounded and retained only in the restricted remote operation log when needed for diagnosis.

The post-enrollment controller flow is ordered exactly as follows:

1. `runWindowsEnrollment` returns and the transport record has already been atomically published;
2. enrollment signal handlers and its final-publication barrier are removed;
3. the CLI prints `CONNECTED_SSH_ONLY`;
4. the CLI awaits `ensureRuntime(core)` rather than launching it in the background;
5. it prints `RUNTIME_READY` or a finite `RUNTIME_*` result without reclassifying that result as `BOOTSTRAP_FAILED`.

`runWindowsEnrollment`, the device-record schema, and the existing remote-target readiness contract stay unchanged.

Ordinary `exec`, `put`, and `get` remain available through SSH. Once base is ready, `exec` may explicitly request the managed environment; it never silently falls back to global tool versions.

## Desktop and Browser Boundary

The standard runtime works when no user is logged in and supports headless browser tasks through a dedicated Agent Road browser profile. It does not imply control of the currently visible desktop or the user's existing browser profile.

Windows services and SSH sessions do not reliably inhabit the interactive user's desktop. A future `desktop` profile must install a separate helper in the chosen logged-in user session. It must fail closed while logged out, locked, on the UAC secure desktop, or when multiple sessions are ambiguous. It must not disable UAC, unlock Windows, take over the default browser profile, or expose a new LAN/public listener.

## Files and User Data

The dedicated Agent Road administrator may work with ordinary files that its token can lawfully read. Provisioning must not recursively take ownership of a user profile or relax unrelated ACLs. EFS, DPAPI-bound secrets, browser credential stores, MFA, hardware keys, and another user's interactive identity remain outside the guarantee.

Task workspaces are explicit paths. Agent Road records which task owns a workspace and never treats an entire drive or user profile as a disposable working directory.

## Compatibility Boundary

The first runtime implementation targets x64 Windows 10 and Windows 11 Home/Pro versions already supported by the SSH bootstrap. Home and Pro share the same runtime path; edition-specific features cannot be base requirements. ARM64 and enterprise policy environments require separate catalog entries and acceptance evidence rather than architecture emulation or disabled policy.

No part of the design assumes `winget`, Microsoft Store, Git, Node, Python, PowerShell 7, a particular system locale, a visible desktop, or Windows internet access.

## Finite States and Failures

The Task 6 Mac controller state machine is intentionally coarse:

```text
CONNECTED_SSH_ONLY
  -> INVENTORY_READY
  -> PLAN_READY
  -> ACQUIRING
  -> RUNTIME_READY
```

When Task 6 records a runtime failure, its terminal state is `FAILED`; the error
does not retract `CONNECTED_SSH_ONLY`.
Inside the black-box provision call, Windows still follows the signed 11-phase
journal vocabulary defined above. `STAGED` and `VERIFYING` are reserved Mac-side
summaries for a future trusted journal-streaming adapter; they are valid schema
states but are not transitions on the current Task 6 controller path.

Representative stable failures are:

- `RUNTIME_INPUT_INVALID`
- `RUNTIME_INVENTORY_INVALID`
- `RUNTIME_INVENTORY_FAILED`
- `RUNTIME_STATE_UNSUPPORTED`
- `RUNTIME_PLATFORM_UNSUPPORTED`
- `RUNTIME_INVENTORY_CHANGED`
- `RUNTIME_ALREADY_RUNNING`
- `RUNTIME_DISK_INSUFFICIENT`
- `RUNTIME_DOWNLOAD_FAILED`
- `RUNTIME_ARTIFACT_INVALID`
- `RUNTIME_SIGNATURE_INVALID`
- `RUNTIME_STAGE_FAILED`
- `RUNTIME_INSTALL_FAILED`
- `RUNTIME_VERIFY_FAILED`
- `RUNTIME_REBOOT_REQUIRED`
- `RUNTIME_ROLLBACK_INCOMPLETE`
- `RUNTIME_COMPLETION_UNCERTAIN`

Failures retain the last verified SSH state and stop the current plan. Unknown execution after a timeout is never retried automatically.

## Acceptance

Local acceptance requires exact schema tests, hostile-object tests, path/archive escape tests, artifact/signature fixtures, deterministic plan tests, resumable-journal tests, rollback ownership tests, bounded process/output tests, and regression tests for pinned SSH `exec/put/get`.

Physical acceptance requires at least:

- Windows 10 Home, Windows 10 Pro, Windows 11 Home, and Windows 11 Pro on x64;
- a near-bare target with no Git/Node/Python/PowerShell 7/`winget` dependency;
- existing conflicting global tool versions that remain untouched;
- Mac-relayed acquisition while Windows has no public internet route;
- non-English Windows locale;
- interrupted Mac download, interrupted upload/extraction, failed verifier, activation interruption reconciliation, and repeated no-op ensure;
- locked, logged-out, and no-interactive-user states for base/headless work;
- proof that no new inbound port exists and pinned SSH remains usable after every failure.

The first physical installation on the current Windows device requires a separate explicit authorization. A successful runtime installation does not by itself prove the four-edition matrix.

## Deferred

- a permanent Agent Road Windows service or replacement transport;
- target-side artifact download;
- visible desktop/session helper;
- automatic UAC interaction or Windows unlock;
- directory-wide arbitrary synchronization;
- public artifact hosting, VPS relays, or alternate VPN products;
- ARM64 support;
- reboot-resume and transaction-scoped startup tasks;
- automatic machine-wide software profiles without declared mutation plans.
