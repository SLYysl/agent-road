# Windows Runtime Provisioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Each task requires a spec-compliance review followed by a code-quality/security review before the next task begins.

**Goal:** Make `CONNECTED_SSH_ONLY` the final human handoff, then let the Mac controller deterministically prepare and maintain a private Windows runtime without depending on preinstalled development tools, target internet, global PATH, or long pasted commands.

**Architecture:** Build pure catalog/profile/inventory/plan primitives first. Then add a read-only Windows inventory over the existing pinned SSH execution layer, a Mac-side verified artifact cache, an operation-bound private `provisionUpload`, and a transaction-scoped PowerShell 5.1 core installer. Core publishes an immutable portable PowerShell 7 generation by atomically replacing one active-state pointer. Enrollment automatically ensures core after `CONNECTED_SSH_ONLY`; transport state remains independent if runtime preparation fails. Later profiles reuse the verified core runner. No new listener or permanent service is introduced.

**Tech Stack:** Node.js 22 ESM, built-in `node:test`, existing trusted SSH/SFTP modules, Windows PowerShell 5.1 staging, portable PowerShell 7, canonical JSON, RSA-SHA256 release signing, SHA-256 and Authenticode verification.

---

## File map

- Create `src/runtime/runtime-catalog.mjs`: hostile-input-safe catalog and finite profile resolution.
- Create `test/runtime-catalog.test.mjs`.
- Create `src/runtime/runtime-inventory.mjs`: exact inventory parser and digest.
- Create `test/runtime-inventory.test.mjs`.
- Create `src/runtime/runtime-plan.mjs`: deterministic desired-state delta.
- Create `test/runtime-plan.test.mjs`.
- Create `windows/runtime-inventory.ps1`: bounded read-only inventory source.
- Create `src/runtime/runtime-doctor.mjs` and `test/runtime-doctor.test.mjs`: transport and parse inventory.
- Create `src/runtime/artifact-cache.mjs` and `test/runtime-artifact-cache.test.mjs`: Mac acquisition/cache with stable-file verification.
- Create `src/runtime/runtime-manifest.mjs` and `test/runtime-manifest.test.mjs`: domain-separated signed operation manifest.
- Create `src/runtime/provision-upload.mjs` and `test/provision-upload.test.mjs`: private operation-bound upload below runtime staging.
- Create `windows/runtime-provision-core.ps1`: transaction-scoped core materialization and verification.
- Create `src/runtime/runtime-provision.mjs` and `test/runtime-provision.test.mjs`: upload and invoke the core capsule.
- Create `src/runtime/runtime-state-store.mjs` and `test/runtime-state-store.test.mjs`: independent atomic Mac-side runtime truth.
- Modify `src/core/paths.mjs`: add owner-only runtime artifact/cache paths.
- Modify only the post-enrollment CLI/controller orchestration and its focused tests: preserve transport publication, then automatically ensure core.
- Modify `src/cli.mjs` and `test/cli-remote-work.test.mjs`: add `doctor`, repair-only `prepare`, and `runtime-status` only after lower layers pass.
- Add a production catalog only after exact upstream artifacts, lengths, hashes, signer rules, architecture, and minimum build are independently verified.
- Update `README.md`, `docs/windows-physical-acceptance.md`, and `CURRENT_STATE.md` after local implementation/review.

## Global rules

- Do not access Windows, SSH, Tailscale, or a public package source while Tasks 1–3 are implemented and reviewed.
- Any later physical inventory or installation requires a separate explicit user authorization.
- Preserve pinned host keys, dedicated SSH identity, Tailnet-only listener/firewall, strict stderr, bounded outputs, and unknown-execution semantics.
- The first acquisition path is Mac download/verification/cache/upload only. Do not implement target-side downloads in this slice.
- Do not use `winget`, Store, Chocolatey, `latest`, `irm | iex`, global PATH mutation, or an existing global Git/Node/Python as an accepted runtime postcondition.
- Do not add a permanent service, SYSTEM task, inbound port, desktop helper, MSI flow, registry mutation, or automatic reboot.
- Use uploaded files plus short fixed commands; no new large `-EncodedCommand` work path.
- Never expose or journal enrollment tokens, private keys, proxy credentials, browser credentials, raw installer command lines, or user document contents.

### Task 1: Add the exact catalog and profile resolver

**Files:**
- Create: `src/runtime/runtime-catalog.mjs`
- Create: `test/runtime-catalog.test.mjs`

- [ ] **Step 1: Write RED exact-schema tests**

Define fixture catalogs with these finite concepts:

- schema version and catalog revision;
- platform tuple (`windows`, `x64`, minimum build);
- artifacts with ID, version, URL, zero through four controller-reviewed canonical HTTPS `redirectOrigins`, download byte length, maximum expanded bytes, uppercase SHA-256, packaging mode, expected signer rule, and verification command ID;
- profiles with exact artifact IDs and profile dependencies;
- implicit `core` plus user-selectable `base`. Later profile names are rejected until their catalog and verifier contracts are separately implemented.

Tests reject missing/extra fields, prototypes, proxies, getters, symbols, duplicate IDs, cycles, unknown artifacts/profiles, unbounded strings/counts/download bytes/expanded bytes, noncanonical URL/hash/version/build/architecture, `latest`, mutable output, and profile-order ambiguity.

- [ ] **Step 2: Verify RED**

Run:

```bash
node --test test/runtime-catalog.test.mjs
```

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement the minimum immutable resolver**

Expose only:

```js
validateRuntimeCatalog(input)
resolveRuntimeProfiles(catalog, requestedProfiles)
```

The resolver always includes core, expands the finite `base` dependency, deduplicates artifacts, and returns a frozen canonical snapshot ordered by catalog artifact ID. It performs no I/O and accepts no caller functions.

- [ ] **Step 4: Verify GREEN and review**

Run `node --check src/runtime/runtime-catalog.mjs` and `node --test test/runtime-catalog.test.mjs`. Then run independent spec and quality/security reviews, fix findings, and repeat.

### Task 2: Add bounded inventory and deterministic planning

**Files:**
- Create: `src/runtime/runtime-inventory.mjs`
- Create: `test/runtime-inventory.test.mjs`
- Create: `src/runtime/runtime-plan.mjs`
- Create: `test/runtime-plan.test.mjs`

- [ ] **Step 1: Write RED inventory tests**

The accepted inventory has the exact design schema: platform facts; free bytes; pending reboot; interactive-session boolean; the finite runtime generation tuple; and managed artifact ID/version/bytes/hash/verified records. It contains no device/operation ID, timestamp, path, user/session identity, global-tool list, URL/download capability, command, or stdout/stderr. Managed records are ID-sorted, unique, and limited to 32.

Reject duplicate/missing/extra fields, wrong types, unsafe objects, unsupported size/count, invalid generation/null combinations, duplicate or unsorted artifact IDs, a verified generation with unverified records, and verified records without bounded bytes/uppercase hashes. The object validator may accept bounded unsupported architecture/build values so the planner can report them. Object insertion order cannot change the canonical snapshot or digest. Raw canonical-JSON text validation belongs to the Task 3 doctor boundary.

Until Task 5 freezes the signed generation receipt, active pointer, and journal schemas, Task 3 recognizes only a completely absent runtime root. Any existing runtime root or residue returns `RUNTIME_STATE_UNSUPPORTED`; it must not be interpreted as an empty runtime.

- [ ] **Step 2: Write RED plan tests**

Given a validated catalog, profile resolution, and inventory, prove exact deterministic outcomes:

- no managed record -> `install`;
- exact verified record -> `present`;
- matching version but invalid hash/bytes/verified flag -> `repair`;
- older managed version -> `upgrade` while retaining rollback revision;
- newer managed version -> `blocked`, never implicit downgrade;
- unsupported architecture/build/PowerShell, missing elevation, insufficient disk, pending reboot/restart, or conflicting transaction -> a finite blocker;
- unrelated global tools never satisfy an artifact;
- repeated identical inputs produce byte-identical canonical plans;
- requested profile order cannot change the plan;
- plan binds calculated inventory/catalog digests, device ID, requested/resolved profiles, operation ID, canonical creation time, and `acquisition=mac-relay`;
- no-op plans require zero free bytes; mutation plans require a 256 MiB reserve plus every resolved artifact's download and maximum expanded bytes.

Do not test “changed inventory digest” in the initial pure planner. The exact
digest, including exact free bytes, is signed audit evidence. Task 5
apply/reconcile must bind an exact baseline with
`baseline.freeBytes >= requiredFreeBytes`, re-inventory immediately before
upload, and require `live.freeBytes >= requiredFreeBytes`. It rejects every
other canonical change; only free-space movement for which both explicit
inequalities remain true may proceed.

- [ ] **Step 3: Verify RED**

Run:

```bash
node --test test/runtime-inventory.test.mjs test/runtime-plan.test.mjs
```

- [ ] **Step 4: Implement pure parsers and planner**

Expose only bounded immutable data. Hash only validated canonical snapshots and emit uppercase SHA-256. The planner never accepts caller-provided digests and performs no filesystem, network, SSH, process, random, or clock access; device ID, 32-hex operation ID, and canonical millisecond UTC creation time are explicit primitive inputs.

- [ ] **Step 5: Verify GREEN and review**

Run syntax checks and both focused tests, then independent spec and quality/security reviews.

### Task 3: Add read-only runtime doctor over pinned SSH

**Files:**
- Create: `windows/runtime-inventory.ps1`
- Create: `src/runtime/runtime-doctor.mjs`
- Create: `test/runtime-doctor.test.mjs`
- Modify only if required: `src/remote/windows-remote.mjs`
- Modify only if required: `test/windows-remote.test.mjs`

- [ ] **Step 1: Write RED source and transport tests**

Tests prove the PowerShell source is read-only, PowerShell 5.1-compatible, locale-independent, bounded, and emits exactly one compressed canonical JSON object. It must not install, download, change ACLs, touch PATH/registry/services/tasks/firewall, reboot, or enumerate user data.

Transport tests inject the existing trusted target/session and prove one address is pinned, stdin/file framing remains bounded, stderr must be empty, output is capped, failures are finite, and raw output cannot leak through public errors.

- [ ] **Step 2: Verify RED**

Run `node --test test/runtime-doctor.test.mjs`.

- [ ] **Step 3: Implement the inventory source and doctor**

Prefer staging the inventory source as a file and invoking a short fixed `powershell.exe -File` command. If the existing `executeRemoteScript` is reused, preserve its cleanup/uncertainty semantics and parse only the exact final canonical inventory result.

- [ ] **Step 4: Verify GREEN and local regression**

Run:

```bash
node --check src/runtime/runtime-doctor.mjs
node --test test/runtime-doctor.test.mjs test/remote-exec.test.mjs test/windows-remote.test.mjs
```

Then complete both reviews. Do not run the doctor physically yet.

### Task 4: Add the Mac artifact cache and signed transaction capsule

**Files:**
- Create: `src/runtime/artifact-cache.mjs`
- Create: `test/runtime-artifact-cache.test.mjs`
- Create: `src/runtime/runtime-manifest.mjs`
- Create: `test/runtime-manifest.test.mjs`
- Create: `src/runtime/provision-upload.mjs`
- Create: `test/provision-upload.test.mjs`
- Modify: `src/core/paths.mjs`
- Modify: `test/device-model.test.mjs`
- Reuse: `src/identity/bootstrap-signer.mjs`

- [ ] **Step 1: Write RED cache/supply-chain tests**

Cover owner-only cache directories, no-follow regular-file snapshots, stable double reads, exact byte/hash checks, atomic publication, concurrent fetch lock, dead-owner lock recovery, crash-window hardlink reconciliation, interrupted download cleanup, cache poisoning, hardlink/symlink/FIFO rejection, HTTP redirect policy, maximum bytes, one absolute deadline through cancellation/verification/publication/cleanup, and public-error redaction.

Before the first production catalog, schema v1 is amended so every artifact carries a mandatory canonical, sorted, unique `redirectOrigins` array. Manual bounded HTTPS redirects allow only the source origin plus that controller-reviewed list on every hop; the cache never trusts an unbound `Location`. This amendment is required because the official GitHub release URL redirects from `github.com` to `release-assets.githubusercontent.com`; the observed temporary signed CDN URL and query are never stored, while a synthetic query regression proves that an allowed-origin redirect preserves runtime query data.

The signed transaction manifest binds the validated catalog/profile resolution, inventory digest, artifact records, target platform, device ID, operation ID, and finite phase vocabulary. It reuses the existing RSA-3072 signer but signs `AGENT_ROAD_RUNTIME_V1\0 || canonical-manifest-bytes`, never unscoped bytes and never URLs discovered from the target.

Use separate stable `generationDigest` and operation-specific `manifestDigest` values. The former domain-separates and hashes catalog identity, desired platform, resolved profiles, and every resolved artifact component; the latter hashes the canonical manifest that additionally binds device, operation, inventory, acquisition mode, timestamp, and the fixed 11-phase vocabulary. The capsule carries the existing public payload plus its domain-separated key ID. Pinned SSH anchors its first restricted write; later operations require an exact match with the persisted controller key. The fixed Task 5 script remains on the existing hash-verified `executeRemoteScript` path, and its installed outputs belong to the immutable receipt.

Freeze the canonical generation preimage as exactly `{schemaVersion,catalogRevision,catalogDigest,platform,profiles,components}` in that order, with `platform` taken from the resolved catalog. At orchestration, adapt the existing signer with bound functions: `getSigningPublicKey: () => signer.getOrCreate()` and `sign: (bytes) => signer.sign(bytes)`.

The private upload tests prove the public `put/get` denylist is unchanged. `provisionUpload` reuses the pinned trusted session, per-device lock, strict stderr, and transfer bounds, but its destination is derived internally and confined to `C:\ProgramData\AgentRoad\runtime\staging\<operation-id>`. Every uploaded component is checked against manifest-bound length and SHA-256 before use.

Catalog, cache, manifest, local snapshot, wrapper, and target limits are
composable: at most 32 components and 256 MiB per component. Preconstruct every
fixed invocation before init, bind one operation ID to one manifest, and
reinspect the whole batch immediately before publishing the capsule marker.

- [ ] **Step 2: Implement against injected fetch/sign dependencies**

Production network acquisition remains disabled until the production catalog is pinned and reviewed. Tests use local fixtures and injected fetch, signer, and trusted-transfer dependencies; no live downloads or SSH occur.

- [ ] **Step 3: Verify and review**

Run focused tests plus existing bootstrap-signer tests, then both reviews.

### Task 5: Add transaction-scoped core provisioning

The normative persistence, identity, atomic-publication, and recovery contract
for this task is
`docs/superpowers/specs/2026-07-29-windows-runtime-core-contract.md`. Do not
invent or relax an on-disk field while implementing the script.

**Files:**
- Create: `windows/runtime-provision-core.ps1`
- Create: `src/runtime/runtime-provision.mjs`
- Create: `test/runtime-provision.test.mjs`
- Modify only when necessary: remote transfer/execution modules and their tests.

- [ ] **Step 1: Write RED Windows state-machine tests**

Use source-level and fixture-driven tests for exact phases: discover, verify manifest, verify artifacts, snapshot, materialize new generation, self-test, atomic activate, validate, commit, rollback, and reconcile. Cover every interruption boundary, existing transaction conflict, same-operation resume, inventory mismatch, ZIP escape/reparse/size/count attacks, signature/signer/hash mismatch, previous-generation rollback, cleanup uncertainty, and no-op re-run. The mutation lock must be a Windows kernel mutex or an exclusively held file handle, never a timestamp lease.

- [ ] **Step 2: Implement only the core capsule path**

Core installs only the pinned portable PowerShell 7 ZIP and fixed Agent Road apply/launch scripts into `runtime\versions\<manifest-digest>`. PowerShell 5.1 expands the ZIP with bounded built-in .NET APIs, so no pre-existing archive utility is required. It does not install base or later profile artifacts yet. Every generation owns its tools, `bin`, `env.ps1`, `env.cmd`, and verified manifest; successful later work uses the new PowerShell 7 absolute path.

Activation atomically replaces only `runtime\state\active.json`; `previous.json` retains the prior verified generation for rollback. No global PATH, registry application registration, permanent service, firewall rule, scheduled task, reboot, or user-profile mutation is allowed in this task.

- [ ] **Step 3: Implement controller orchestration**

The Mac stages the signed manifest and exact artifacts through private `provisionUpload`, invokes one short fixed remote script path, then parses the finite final result. Any post-mutation timeout returns `RUNTIME_COMPLETION_UNCERTAIN` and is never blindly retried. The next call reconciles the active pointer, manifest digest, operation journal, and core smoke test before deciding whether to resume, commit, or roll back.

After upload, under the Windows mutation lock and before mutation, the target
must independently require available free space of at least `256 MiB + signed
maximumExpandedBytes`. It must also re-evaluate the complete three-source
pending-reboot predicate: CBS `RebootPending`, Windows Update
`RebootRequired`, and Session Manager `PendingFileRenameOperations`.

Keep one explicit pre-gate carve-out: an already terminal `committed` or
`rolled-back` journal may resume only exact journal/receipt/pointer-bound
staging or deterministic tombstone cleanup. It must reject unknown residue and
must not materialize or activate the incoming plan. Every new-plan path first
validates the signed manifest, embedded controller identity/signature, and
staged-operation binding, then passes the machine gate before its first
restricted directory/trust/journal creation and before materialization or
activation.

The fixed provisioner receives only the core contract's canonical stdin record
(`schemaVersion`, `operationId`, `manifestDigest`) through a dedicated bounded
exec wrapper. It never enumerates staging to choose an operation and accepts no
arbitrary command line.

- [ ] **Step 4: Verify and review**

Run focused provision, transfer, execution, and trust tests. Complete both reviews and a mutator/sensitive-output audit before any physical install authorization is requested.

### Task 6: Add CLI surface and first production catalog

Task 6 retains the generation-specific absolute `pwsh.exe` contract. It does not
deliver the stable root launcher previously scheduled here; that launcher is
deferred to a later separately reviewed slice, where any incompatible format
change must advance the catalog/receipt revision.

**Files:**
- Create: `src/runtime/runtime-state-store.mjs`
- Create: `test/runtime-state-store.test.mjs`
- Modify: `src/core/paths.mjs`
- Modify: `test/paths.test.mjs`
- Modify: `src/cli.mjs`
- Modify: `test/cli-enrollment.test.mjs`
- Modify: `test/cli-remote-work.test.mjs`
- Create: `config/runtime-catalog.json`, the canonical reviewed production runtime catalog.
- Create: `src/runtime/production-runtime-catalog.mjs` and `test/production-runtime-catalog.test.mjs` for fixed-path bounded loading.
- Create: `docs/runtime-catalog-evidence.md` with primary-source and local artifact evidence.
- Modify: `README.md`
- Modify: `docs/windows-physical-acceptance.md`
- Modify: `CURRENT_STATE.md`

- [ ] **Step 1: Add RED CLI tests**

Add exact parsing/output/error tests for:

```text
agent-road doctor <device>
agent-road prepare <device> --profile base
agent-road runtime-status <device>
```

Reject duplicates, unknown profiles/options, hostile runtime dependencies, noncanonical results, promise/getter/proxy traps, and output injection. `prepare` is a repair/maintenance command, not a required human handoff step. Keep enrollment and remote-work help/regressions unchanged except for the new lines.

- [ ] **Step 2: Pin the core catalog**

Use primary vendor release sources to select an explicit supported PowerShell 7 portable ZIP for Windows x64. Independently record URL, controller-reviewed redirect origins, exact bytes, SHA-256, architecture, minimum build, packaging limits, expected signer where applicable, and verification command in a reviewed pinned local catalog. Its canonical digest is controller-signed in the transaction manifest; the catalog file is not described as independently signed. Load it only through the fixed-path, bounded, strict-UTF-8, stable no-follow loader with canonical byte equality and path-free `RUNTIME_INTERNAL_ERROR` failures. Do not use current/latest aliases. Keep production `base` disabled until every base artifact has the same independently verified metadata.

- [ ] **Step 3: Implement independent runtime state**

Store exact bounded runtime records atomically below `~/.agent-road/runtime/devices/<device-id>/state.json`, reusing the existing local file-lock and atomic JSON primitives. A missing record for a connected device means `UNPROVISIONED`. Do not add `runtimeStatus` to the exact DeviceRecord schema and do not reinterpret top-level `READY` as core readiness.

The current Mac orchestration uses coarse checkpoints only:
`UNPROVISIONED`, `INVENTORY_READY`, `PLAN_READY`, `ACQUIRING`, `READY`, and
`FAILED`. `STAGED` and `VERIFYING` remain reserved summaries of trusted
Windows-journal progress for a future streaming adapter; Task 6 neither persists
nor prints them and may move directly from `ACQUIRING` to verified `READY`.

- [ ] **Step 4: Implement automatic handoff and CLI orchestration**

The enrollment notice states that continuing authorizes installation of Agent Road's private runtime below `C:\ProgramData\AgentRoad`. Keep `runWindowsEnrollment` unchanged: after pinned SSH succeeds it atomically publishes `CONNECTED_SSH_ONLY` and returns. In the CLI/controller layer, first remove the enrollment SIGINT/SIGTERM handlers and final-publication barrier, print `CONNECTED_SSH_ONLY`, then await `ensureRuntime(core)`. Do not fire-and-forget. Runtime errors retain their finite `RUNTIME_*` code instead of being mapped to `BOOTSTRAP_FAILED`, and they must not retract the transport fact. Print `RUNTIME_READY` only after the core verifier succeeds. The final intended default expands this automatic ensure to `base` only after base is implemented and physically accepted.

Do not modify `device-model.mjs`, `device-registry.mjs`, `run-windows-enrollment.mjs`, or the existing `remote-target.mjs` contract in this slice. Provisioning gets a separate dependency factory rather than widening the exact remote dependency shape.

The initial Mac orchestration stores only bounded runtime status and transaction identities, not the original signed capsule. Consequently, a persisted intermediate or completion-uncertain controller state must remain fail-closed in this slice. Do not reconstruct or re-sign a capsule under an old operation ID. Durable owner-only capsule persistence and same-operation controller re-entry are a separate prerequisite for controller-crash fault injection.

Run focused enrollment/CLI/runtime tests, the complete remote-layer suite, full repository tests, syntax checks, diff checks, and a secret/sensitive-marker scan.

- [ ] **Step 5: Final reviews and checkpoint**

Run one complete spec review and one code-quality/security review with different agents. Update `CURRENT_STATE.md` to 30 lines or fewer with exact local counts and the next physical boundary. Do not claim Windows runtime readiness before a separately authorized install succeeds.

### Task 7: Physical core/base acceptance (separately authorized)

This task is intentionally not authorized by the implementation plan.

After the user explicitly authorizes the exact operation:

1. run `doctor` once and stop on any failure;
2. display the finite core plan without secrets;
3. provision core once and verify pinned SSH remains available;
4. repeat prepare and prove an exact no-op;
5. only after core acceptance, authorize `base` as a separate plan;
6. stop on timeout, uncertain completion, signature mismatch, unexpected reboot requirement, or rollback uncertainty;
7. record evidence as one-machine evidence, not Win10/11 Home/Pro matrix proof.

The first-install and exact no-op checks may run before durable controller resume exists. Do not perform the interruption/crash portion of this acceptance task until the exact original capsule can be durably recovered and revalidated by a new Mac process.

## Commit boundary

Temporary physical-gate artifacts are never added. After local implementation, reviews, full tests, and secret scan pass, commit the planned remote-layer plus runtime changes to the private branch and push for synchronization. Push is not deployment. If a production catalog is not yet independently pinned, commit schemas/tests with production prepare disabled rather than inventing release metadata.
