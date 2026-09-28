# Windows Runtime Physical Task 9 Phase A Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the physical-acceptance instructions and classify the one enrolled Windows target's existing `RUNTIME_COMPLETION_UNCERTAIN` episode without mutating Windows.

**Architecture:** Work only from the isolated Task 9 checkout at `d517e3b`. First fix the stale public command surface and split read-only recovery inspection from separately authorized reboot/apply operations. Then run one serialized production `runtime-recover --inspect` through an in-process redacting wrapper so exact device, operation, ticket, address, key, fingerprint, path, and digest values never enter chat or Git.

**Tech Stack:** Node.js 22, Agent Road CLI, pinned OpenSSH/Tailscale production dependencies, Markdown acceptance records.

---

### Task 1: Correct the acceptance instructions

**Files:**
- Modify: `README.md`
- Modify: `docs/windows-physical-acceptance.md`

- [ ] **Step 1: Remove the invalid bare standalone prepare command**

Replace the README's standalone runtime examples with the current sequence:

```text
runtime-status -> runtime-recover when required -> doctor -> runtime-baseline --capture -> runtime-plan --baseline <exact-id> -> separately approved prepare --approved <exact-ticket>
```

State that raw `list`, `status`, recovery, baseline, plan, and runtime outputs remain controller-private and must not be pasted into chat or reports.

- [ ] **Step 2: Correct fresh recovery ordering**

Split the runbook's recovery line into these independent gates:

```text
first inspect -> RUNTIME_REBOOT_REQUIRED -> separately authorized reboot
first post-reboot inspect without --prior-ticket -> RECOVERY_READY or finite stop
separately authorized apply with the exact returned ticket
```

Allow `--prior-ticket` only for an already-existing exact immediate predecessor/successor lineage. State explicitly that one inspect is read-only on Windows, but on the Mac may create or retain owner-only recovery-managed directories and a persistent recovery lock file, publish an owner-only boot observation, and, depending on pre-existing recovery state or lineage, publish recovery-ticket or successor evidence; it may also refresh `known_hosts` and use temporary SSH locks and verification snapshots. Reboot and apply mutate external state.

- [ ] **Step 3: Narrow the no-op evidence claim**

Replace any claim that state equality alone proves hooks were never called with the bounded claim `observed no-op with unchanged governed state`; stronger hook non-invocation requires separately implemented controller tracing.

- [ ] **Step 4: Verify documentation consistency**

Run:

```sh
if rg -n '^[[:space:]]*node src/cli\.mjs prepare <device-id> --profile core[[:space:]]*$' README.md docs/windows-physical-acceptance.md; then
  echo 'invalid bare prepare example found' >&2
  exit 1
fi
if rg -n -F -- '--inspect --prior-ticket' README.md docs/windows-physical-acceptance.md; then
  echo 'invalid inspect/prior-ticket command found' >&2
  exit 1
fi
git diff --check
```

Expected: both fail-if-found checks return no matches, and the whitespace check exits zero.

### Task 2: Verify the isolated controller baseline

**Files:**
- Read: `CURRENT_STATE.md`
- Read: controller state below `~/.agent-road`

- [ ] **Step 1: Confirm exact checkout and bounded documentation diff**

Require branch `codex/windows-physical-task9-isolated` based on `d517e3bc5ae34bd16e0a127610eed96ab2beec51`. Before checkpointing, require the only worktree changes to be `README.md`, `docs/windows-physical-acceptance.md`, and this plan; review that complete documentation/plan diff and reject any other tracked or untracked path.

- [ ] **Step 2: Create the reviewed docs-only local checkpoint**

After review, create one local commit containing exactly those three documentation/plan files. Do not push it yet.

- [ ] **Step 3: Verify the Mac transport preflight**

Require Tailscale `Running`, one IPv4 and one IPv6 self-address, empty Serve/Funnel configurations, one privately selected connected target, and no concurrent Agent Road operation. Emit only booleans and counts.

- [ ] **Step 4: Verify the frozen software baseline**

Run:

```sh
npm test
npm run check
```

Expected: 1199 tests, 0 failures, with only platform skips; syntax check exits zero.

- [ ] **Step 5: Require the exact docs checkpoint and a clean executable baseline**

Immediately before Task 3, mechanically require the docs-only checkpoint to contain exactly the reviewed allowlist, with no executable-source drift or worktree dirt:

```sh
task9_expected_paths="$(printf '%s\n' \
  README.md \
  docs/superpowers/plans/2026-08-08-windows-runtime-physical-task9-phase-a.md \
  docs/windows-physical-acceptance.md)"
test "$(git diff --name-only d517e3bc5ae34bd16e0a127610eed96ab2beec51...HEAD)" = "$task9_expected_paths"
test -z "$(git diff d517e3bc5ae34bd16e0a127610eed96ab2beec51 -- src windows package.json test)"
test -z "$(git status --porcelain)"
```

Expected: every test exits zero without output. Any path outside the exact allowlist, executable-source drift, or worktree dirt blocks the Windows inspection.

### Task 3: Perform one redacted read-only recovery inspection

**Files:**
- No repository file changes
- Controller-local effects: one inspect may create or retain owner-only recovery-managed directories and a persistent recovery lock file; publish an owner-only boot observation and, depending on pre-existing recovery state or lineage, recovery-ticket or successor evidence; refresh `known_hosts`; and use temporary SSH locks and verification snapshots
- Windows effect: read-only inspection through the production pinned-SSH path

- [ ] **Step 1: Invoke the production command without exposing private identifiers**

Run this exact in-process wrapper from the Task 9 worktree:

```js
let inspectInvoked = false;

try {
  const { readFile } = await import('node:fs/promises');
  const { homedir } = await import('node:os');
  const { join } = await import('node:path');
  const { main } = await import('./src/cli.mjs');

  const finiteInspectErrors = new Set([
    'RUNTIME_ALREADY_RUNNING',
    'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
    'RUNTIME_INPUT_INVALID',
    'RUNTIME_INTERNAL_ERROR',
    'RUNTIME_INVENTORY_FAILED',
    'RUNTIME_OPERATION_CONFLICT',
    'RUNTIME_REBOOT_REQUIRED',
    'RUNTIME_STATE_UNSUPPORTED',
  ]);
  const classifications = new Set([
    'EMPTY_PRE_TRANSACTION',
    'ALREADY_ABSENT',
  ]);
  const statusSemantics = Object.freeze({
    RECOVERY_READY: Object.freeze({ rebootRequired: false, actionable: true }),
    RECOVERY_PARENT_REQUIRED: Object.freeze({ rebootRequired: false, actionable: false }),
    RECOVERY_APPLY_REQUIRED: Object.freeze({ rebootRequired: false, actionable: false }),
  });

  const root = process.env.AGENT_ROAD_HOME || join(homedir(), '.agent-road');
  const registry = JSON.parse(await readFile(join(root, 'devices.json'), 'utf8'));
  const candidates = registry.devices.filter(({ status }) => (
    status === 'CONNECTED_SSH_ONLY'
    || status === 'READY'
    || status === 'DEGRADED_RECOVERY_AVAILABLE'
  ));
  if (candidates.length !== 1) throw new Error();

  let rawStdout = '';
  let rawStderr = '';
  const stdout = { write(value) { rawStdout += String(value); return true; } };
  const stderr = { write(value) { rawStderr += String(value); return true; } };
  inspectInvoked = true;
  const cliExitCode = await main(
    ['runtime-recover', candidates[0].id, '--inspect'],
    process.env,
    { stdout, stderr },
  );

  let projection;
  if (cliExitCode === 2) {
    const errorCode = rawStderr.endsWith('\n')
      ? rawStderr.slice(0, -1)
      : '';
    if (
      rawStdout !== ''
      || rawStderr !== `${errorCode}\n`
      || !finiteInspectErrors.has(errorCode)
    ) throw new Error();
    projection = {
      phase: 'recovery-inspect',
      outcome: 'FINITE_STOP',
      code: errorCode,
    };
  } else if (cliExitCode === 0) {
    if (rawStderr !== '') throw new Error();
    const result = JSON.parse(rawStdout);
    const semantics = (
      result !== null
      && typeof result === 'object'
      && !Array.isArray(result)
      && Object.hasOwn(statusSemantics, result.status)
    ) ? statusSemantics[result.status] : null;
    if (
      result.schemaVersion !== 1
      || semantics === null
      || !classifications.has(result.classification)
      || typeof result.rebootRequired !== 'boolean'
      || typeof result.actionable !== 'boolean'
      || result.rebootRequired !== semantics.rebootRequired
      || result.actionable !== semantics.actionable
    ) throw new Error();
    projection = {
      phase: 'recovery-inspect',
      outcome: 'FINITE_RESULT',
      status: result.status,
      classification: result.classification,
      rebootRequired: result.rebootRequired,
      actionable: result.actionable,
    };
  } else {
    throw new Error();
  }

  process.stdout.write(`${JSON.stringify(projection)}\n`);
  process.exitCode = cliExitCode;
} catch {
  const projection = inspectInvoked
    ? {
        phase: 'recovery-inspect',
        outcome: 'STOP_UNKNOWN',
        code: 'INSPECT_INVOKED_RESULT_UNCERTAIN',
      }
    : {
        phase: 'pre-inspection',
        outcome: 'BLOCKED',
        code: 'REDACTION_WRAPPER_FAILED',
      };
  process.stdout.write(`${JSON.stringify(projection)}\n`);
  process.exitCode = inspectInvoked ? 4 : 3;
}
```

No branch prints or persists `rawStdout`, `rawStderr`, or the selected device record. The catch block has no error binding and never projects an exception, message, stack, input, raw output, or private identifier.

- [ ] **Step 2: Enforce the stop rule**

Every wrapper outcome stops Phase A. A pre-inspection `BLOCKED/REDACTION_WRAPPER_FAILED` means inspect was not invoked; diagnose the wrapper locally without contacting Windows. `STOP_UNKNOWN/INSPECT_INVOKED_RESULT_UNCERTAIN` means inspect was invoked but its result is uncertain: never retry it and run no second Windows command. If the bounded finite result is `RUNTIME_REBOOT_REQUIRED`, request separate reboot authorization. On any other allowed finite error or successful recovery handoff, stop and review it; do not run reboot, `runtime-recover --apply`, `doctor`, baseline, plan, prepare, ad-hoc SSH, or cleanup in Phase A.

### Task 4: Freeze the Phase A checkpoint

**Files:**
- Modify: `CURRENT_STATE.md`

- [ ] **Step 1: Record only bounded evidence**

Record checkout commit, test counts, Mac transport booleans, the finite recovery-inspect result, and the exact next authorization gate. Do not record device/ticket/operation/baseline IDs, addresses, host keys/fingerprints, HMAC/MAC values, paths, commands, credentials, or raw output.

- [ ] **Step 2: Verify and synchronize**

Run `npm test`, `npm run check`, `git diff --check`, and high-confidence secret/identifier scans. Only after every gate passes, commit the bounded Phase A evidence update and push the isolated branch, including the earlier docs-only local checkpoint; do not merge, clean another worktree, contact Windows again, or claim `RUNTIME_READY`.
