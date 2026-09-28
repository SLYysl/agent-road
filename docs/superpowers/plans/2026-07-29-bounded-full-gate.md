# Bounded Full-Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and locally verify a finite, read-only 18-probe preflight that can inspect the known Agent Road production gate residue without granting cleanup authority or weakening the trusted SSH boundary.

**Architecture:** Extend the existing short PowerShell 5.1 children in the temporary `bounded-direct-probe` harness, keeping each remote command independently bounded and canonically parsed. Add one Mac-side coordinator that runs an exact allowlisted sequence once, stops on first failure, and exposes no raw remote evidence. Recovery remains a separate, explicitly authorized program that must revalidate its own mutation boundaries.

**Tech Stack:** Node.js 22 ESM, built-in `node:test`, Windows PowerShell 5.1 source generation, existing pinned-host-key trusted SSH session, local-only static/source-model verification.

---

## Safety and file map

- Design authority: `docs/superpowers/specs/2026-07-29-bounded-full-gate-design.md`
- Modify temporary harness: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-direct-probe.mjs`
- Modify temporary tests: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-direct-probe.test.mjs`
- Create temporary coordinator: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-full-gate.mjs`
- Create temporary coordinator tests: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-full-gate.test.mjs`
- Read-only semantic references: `gate-recovery.mjs`, `gate-recovery.test.mjs`, `gate-acl-diagnostic.mjs`, and `gate-acl-diagnostic.test.mjs` in the same temporary directory.
- Update after local verification: `CURRENT_STATE.md`

Hard rules for every task:

- Do not run `bounded-direct-probe.mjs`, `bounded-full-gate.mjs`, SSH, SCP, Tailscale, or any Windows command during implementation or review.
- Do not modify the already physically passed `transport`, `control`, or `watchdog` child sources or their wrapper semantics.
- Keep nonempty stderr fatal, remote argv length at most 7,200, modeled `cmd.exe /d /s /c` length below 7,500, child stdout at most 1,024 bytes, and local captured output at most 2,048 bytes.
- Children are read-only. They must not write files, change ACLs, stop processes, install software, move/delete/copy state, or invoke another mutation path.
- Temporary gate files are evidence artifacts and are not committed. Persistent repository documentation is committed only after the complete local gate and reviews pass.

### Task 1: Lock the manifest, exact shape, and age bounds

**Files:**
- Modify: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-direct-probe.test.mjs`
- Modify: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-direct-probe.mjs`
- Reference only: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/gate-recovery.mjs`
- Reference only: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/gate-acl-diagnostic.mjs`

- [ ] **Step 1: Add RED manifest and probe-contract tests**

Extend the test probe allowlist with `dirs` and `age`. Add tests that assert:

- the one bounded manifest contains exactly 16 canonical relative directories, nine published file records, and one 48-byte proof record;
- every bounded record is present with the same length/hash in both semantic reference sources;
- `path` rejects a non-`C:\\` drive root, a reparse root, a canonical-path mismatch, and quarantine existing as either a leaf or container;
- `dirs` emits only `{"status":"ok","directories":16}` after checking every exact directory as canonical and non-reparse;
- every `hashNN` checks `FullName` against its expected canonical path in addition to leaf/reparse/length/hash;
- `age` traverses exactly 27 canonical non-reparse nodes and emits only `status`, `minimumSeconds`, `maximumSeconds`, and `capped`;
- parser fixtures reject missing/extra/reordered fields, non-integers, `-0`, future/capped ages, `minimumSeconds < 60`, `minimumSeconds > maximumSeconds`, and `maximumSeconds > 31_536_000`.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
cd /private/tmp/agent-road-task8.ctv4Oa/production-gate
node --test --test-name-pattern='manifest|path|directories|hash|age|schema' bounded-direct-probe.test.mjs
```

Expected: FAIL because `dirs`, `age`, and the hardened checks do not exist.

- [ ] **Step 3: Implement the smallest bounded manifest and shape probes**

Keep one frozen in-memory manifest in `bounded-direct-probe.mjs`. Derive the ten hash children and the directory literal from it. Harden `path`, add `dirs`, and add the exact-path check to `hashProbe`.

PowerShell children must use `GetFullPath`, ordinal comparison, `Get-Item -Force`, explicit `PSIsContainer`, and the reparse attribute. `path` must use an untyped `Test-Path` for quarantine so a leaf cannot masquerade as absence.

- [ ] **Step 4: Implement the bounded age child and parser**

The child must enumerate the same root plus 26 descendants, reject any noncanonical or reparse node, reject a count other than 27, floor each age, and set `capped=true` for future or over-one-year values. The Node parser accepts only canonical JSON with integer `60 <= minimumSeconds <= maximumSeconds <= 31_536_000` and `capped === false`.

- [ ] **Step 5: Verify GREEN and unchanged physical controls**

Run:

```bash
cd /private/tmp/agent-road-task8.ctv4Oa/production-gate
node --check bounded-direct-probe.mjs
node --test bounded-direct-probe.test.mjs
```

Expected: all tests PASS, and tests explicitly prove the original `transport`, `control`, and `watchdog` decoded child sources are byte-for-byte unchanged from frozen pre-task identities.

- [ ] **Step 6: Review task before proceeding**

Run one independent spec-compliance review, fix any findings, then run one independent code-quality/security review and fix any findings. Re-run the full temporary test file after each fix. Do not commit the temporary files.

### Task 2: Replace ACL smoke tests with two exact policies

**Files:**
- Modify: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-direct-probe.test.mjs`
- Modify: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-direct-probe.mjs`
- Reference only: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/gate-acl-diagnostic.mjs`
- Reference only: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/gate-recovery.mjs`

- [ ] **Step 1: Add RED ACL policy tests**

Replace the obsolete `aclget`, `aclraw`, and `aclmeta` expectations with `aclinherited` and `aclpublished`. Tests must prove the decoded children implement these exact policies:

- `aclinherited`: root + 16 directories + owner proof, `checked:18`; present non-null DACL, canonical, unprotected, no explicit rules, owner current SID or Administrators, and no inherited Allow rule granting any mutating right to an untrusted SID; Creator Owner is accepted only with `InheritOnly`.
- `aclpublished`: nine published files, `checked:9`; present non-null DACL, protected and canonical, Administrators owner, exactly two non-inherited Allow FullControl entries for SYSTEM and Administrators, with no inheritance or propagation.

Use small pure fixture evaluators in the test file to cover descriptor absent/null, owner mismatch, protection/canonical mismatch, explicit rules, deny/allow shape, trustee set, rights bitmask, inheritance, propagation, duplicate/missing rules, and Creator Owner handling. Assert children never emit SID, owner, ACL text, or path.

- [ ] **Step 2: Verify RED**

Run:

```bash
cd /private/tmp/agent-road-task8.ctv4Oa/production-gate
node --test --test-name-pattern='ACL|acl|descriptor|trustee|owner' bounded-direct-probe.test.mjs
```

Expected: FAIL because the exact ACL probes do not exist.

- [ ] **Step 3: Implement shared read-only ACL helpers and two children**

Port only the validated read-only policy logic from `gate-acl-diagnostic.mjs`: descriptor binary-form validation, DACL-present/non-null check, exact-set comparison, inherited policy, and restricted-file policy. Do not port `icacls`, ACL setters, or recovery code. Derive node paths from the frozen bounded manifest.

Each child catches all local detail and emits only its exact success JSON or `{"status":"error"}` with exit 91.

- [ ] **Step 4: Verify GREEN, length, and mutator bans**

Run:

```bash
cd /private/tmp/agent-road-task8.ctv4Oa/production-gate
node --check bounded-direct-probe.mjs
node --test bounded-direct-probe.test.mjs
```

Expected: PASS; both new wrapped invocations remain within both command limits, and the generic decoded-child mutator scan still passes.

- [ ] **Step 5: Review task before proceeding**

Run independent spec-compliance and code-quality/security reviews sequentially, fixing and retesting before moving on. Do not commit the temporary files.

### Task 3: Add two complete CIM reference scans

**Files:**
- Modify: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-direct-probe.test.mjs`
- Modify: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-direct-probe.mjs`
- Reference only: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/gate-recovery.mjs`
- Reference only: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/residue-inspector.mjs`
- Reference only: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/transfer-residue-recovery.mjs`

- [ ] **Step 1: Add RED exact-schema and classification tests**

Replace `cimget`, `cimgate`, and `cimremote` with `cimfirst` and `cimsecond`. Their only accepted schemas are:

```json
{"status":"ok","scan":"first","total":2,"taskPs":0,"sftp":0,"gateRef":0,"otherRemotePs":0,"unknown":0}
{"status":"ok","scan":"second","total":2,"taskPs":0,"sftp":0,"gateRef":0,"otherRemotePs":0,"unknown":0}
```

Add pure fixture tests for: exactly one self and parent; missing/duplicate self or parent; invalid/duplicate/out-of-range PIDs; total 2 and 1,024 bounds; task PowerShell; SFTP with empty command line; gate/quarantine reference; encoded and stdin remote PowerShell; an unrelated process; unknown relevant rows; and overlapping rows proving task -> SFTP -> gate -> other remote PowerShell priority. Every nonzero category must be rejected by the Node parser.

- [ ] **Step 2: Verify RED**

Run:

```bash
cd /private/tmp/agent-road-task8.ctv4Oa/production-gate
node --test --test-name-pattern='CIM|cim|scan|process|classification' bounded-direct-probe.test.mjs
```

Expected: FAIL because the two complete scans do not exist.

- [ ] **Step 3: Implement identity-distinct scan children**

Each child takes one `Get-CimInstance Win32_Process -OperationTimeoutSec 5` snapshot, filters null rows, requires 2..1,024 rows, validates finite uint32 PIDs, finds exactly one self and exactly one parent row, removes them, and classifies the rest once in the specified priority order.

Potentially relevant but incomplete/unsafe rows increment `unknown`; unrelated well-formed processes are not counted. The output contains counts only—never PID, process name, command line, task path, gate path, address, or identity.

- [ ] **Step 4: Verify GREEN and identity/size constraints**

Run:

```bash
cd /private/tmp/agent-road-task8.ctv4Oa/production-gate
node --check bounded-direct-probe.mjs
node --test bounded-direct-probe.test.mjs
```

Expected: PASS; first and second children have distinct identities, every category must be zero, and both invocations fit the 7,200/7,500 limits.

- [ ] **Step 5: Review task before proceeding**

Run independent spec-compliance and code-quality/security reviews sequentially, fixing and retesting before moving on. Do not commit the temporary files.

### Task 4: Add the exact Mac-side 18-probe coordinator

**Files:**
- Create: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-full-gate.test.mjs`
- Create: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-full-gate.mjs`
- Reference: `/private/tmp/agent-road-task8.ctv4Oa/production-gate/bounded-direct-probe.mjs`

- [ ] **Step 1: Write the coordinator RED tests**

Test the exact frozen sequence:

```js
[
  'cimfirst', 'path', 'tree', 'dirs',
  'hash01', 'hash02', 'hash03', 'hash04', 'hash05',
  'hash06', 'hash07', 'hash08', 'hash09', 'hash10',
  'age', 'aclinherited', 'aclpublished', 'cimsecond',
]
```

Required cases:

- success calls all 18 exactly once and returns only `{ status: 'ok', probes: 18 }`;
- failure at every index stops immediately, never retries, and returns only `{ status: 'failed', probe, completed }` where `completed` counts prior successes;
- synchronous throw, asynchronous rejection, malformed dependency, proxy/getter result, and raw sensitive error all reduce to the same finite failure envelope;
- concurrent second invocation is rejected locally without starting another probe;
- the coordinator never names or calls `transport`, `control`, `watchdog`, recovery, cleanup, SSH directly, or a mutating helper;
- CLI accepts no arguments, prints exactly one canonical JSON line, and uses exit 0 for success / exit 2 for failure.

- [ ] **Step 2: Verify RED**

Run:

```bash
cd /private/tmp/agent-road-task8.ctv4Oa/production-gate
node --test bounded-full-gate.test.mjs
```

Expected: FAIL because `bounded-full-gate.mjs` does not exist.

- [ ] **Step 3: Implement the minimal serial coordinator**

Export one immutable sequence and a `runBoundedFullGate(dependencies)` function. Snapshot `dependencies.runProbe` as an own data property before starting; default it to the imported `runProbe`. Hold a module-local in-process lease for the entire sequence, await each call once, ignore its successful raw value, stop on the first failure, and release only in `finally`.

The coordinator must not accept a caller-supplied sequence or probe name. Build output through a null-prototype copy so inherited `toJSON` pollution, getters, proxies, and symbols cannot alter the line.

- [ ] **Step 4: Verify GREEN**

Run:

```bash
cd /private/tmp/agent-road-task8.ctv4Oa/production-gate
node --check bounded-full-gate.mjs
node --test bounded-full-gate.test.mjs bounded-direct-probe.test.mjs
```

Expected: PASS with exact order and fail-stop behavior.

- [ ] **Step 5: Review task before proceeding**

Run independent spec-compliance and code-quality/security reviews sequentially, fixing and retesting before integrated verification. Do not commit the temporary files.

### Task 5: Integrated local verification and checkpoint

**Files:**
- Modify: `CURRENT_STATE.md`
- Verify: `docs/superpowers/specs/2026-07-29-bounded-full-gate-design.md`
- Verify: `docs/superpowers/plans/2026-07-29-bounded-full-gate.md`
- Verify temporary gate files listed above.

- [ ] **Step 1: Run syntax and focused gate tests**

```bash
cd /private/tmp/agent-road-task8.ctv4Oa/production-gate
node --check bounded-direct-probe.mjs
node --check bounded-full-gate.mjs
node --test bounded-direct-probe.test.mjs bounded-full-gate.test.mjs
```

- [ ] **Step 2: Run the existing remote-layer regression suite locally**

```bash
cd /Users/example/agent-road/.worktrees/windows-bootstrap
node --test \
  test/trusted-ssh-session.test.mjs \
  test/windows-remote.test.mjs \
  test/remote-exec.test.mjs \
  test/remote-files.test.mjs
```

Expected: all runnable local tests PASS; only an already-declared platform skip is acceptable.

- [ ] **Step 3: Enumerate identities and command lengths without execution**

Use `buildProbeInvocation` for every allowed probe and assert:

- all outer and child identities are pairwise distinct and distinct from the frozen production identity;
- every remote argv is at most 7,200 characters;
- every modeled `cmd.exe /d /s /c` command is below 7,500 characters;
- `transport`, `control`, and `watchdog` decoded children still match their frozen pre-implementation SHA-256 identities.

- [ ] **Step 4: Run a bounded sensitive/mutator scan**

Scan only the changed repository documentation and the four temporary bounded-gate files. Reject enrollment tokens, private-key material, reusable bootstrap commands, device IDs, Tailnet addresses, host-key paths, raw command lines, and mutation verbs inside read-only child sources. Do not print matching secret content; report file and rule only.

- [ ] **Step 5: Run final independent reviews**

Have one reviewer compare all implementation against the design and this plan, then a different reviewer assess code quality, hostile-input behavior, TOCTOU statements, and scope. Fix all Critical/High findings and any correctness-relevant Medium findings, then repeat Steps 1–4.

- [ ] **Step 6: Update the checkpoint, but do not access Windows**

Keep `CURRENT_STATE.md` at 30 lines or fewer. Record local test counts, maximum remote/modeled lengths, review result, and the exact next boundary: ask for separate authorization before the first full read-only 18-probe physical gate. Do not claim Windows acceptance from local tests.

- [ ] **Step 7: Commit and push only persistent, secret-free repository changes**

After checking the complete diff and secret scan:

```bash
cd /Users/example/agent-road/.worktrees/windows-bootstrap
git add -A
git commit -m "feat: harden remote work acceptance gate"
git push
```

The commit includes the already planned remote-layer changes plus design/plan/checkpoint, but never the temporary gate artifacts. This private-repository push is synchronization, not deployment.

## Later physical boundary (not part of this implementation run)

Only after the user gives a fresh explicit authorization:

1. Recompute and report local file hashes, mode 0600, syntax, tests, identities, and exact maximum command lengths.
2. Execute `bounded-full-gate.mjs` once and accept only the exact finite success envelope.
3. Stop on any failure; do not retry or append diagnostics without another authorization.
4. Treat success only as evidence for reviewing a separately authorized recovery. It is not cleanup authority.
