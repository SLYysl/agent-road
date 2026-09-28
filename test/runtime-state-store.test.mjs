import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import {
  RUNTIME_STATUSES,
  RuntimeStateStore,
  validateRuntimeStateRecord,
} from '../src/runtime/runtime-state-store.mjs';
import { runtimeDeviceRecoveryPaths } from '../src/core/paths.mjs';
import * as recoveryModule from '../src/runtime/runtime-recovery-store.mjs';

const DEVICE_ID = 'dev_abc123';
const OPERATION_ID = 'a'.repeat(32);
const NEXT_OPERATION_ID = 'b'.repeat(32);
const MANIFEST_DIGEST = 'A'.repeat(64);
const GENERATION_DIGEST = 'B'.repeat(64);
const RUNTIME_STATE_TEST_HOOK = Symbol.for('agent-road.runtime-state-store.test-hook');
const execFile = promisify(execFileCallback);

async function createStore(t) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-runtime-state-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = join(directory, 'runtime', 'devices');
  return { root, store: new RuntimeStateStore(root) };
}

async function addExtendedAcl(t, path) {
  await execFile('/bin/chmod', ['+a', 'everyone allow read', path]);
  t.after(async () => {
    try {
      await execFile('/bin/chmod', ['-N', path]);
    } catch {}
  });
}

function runtimeState(overrides = {}) {
  return {
    schemaVersion: 1,
    deviceId: DEVICE_ID,
    runtimeStatus: 'INVENTORY_READY',
    requestedProfiles: ['core'],
    readyProfiles: [],
    operationId: OPERATION_ID,
    manifestDigest: null,
    generationDigest: null,
    failureCode: null,
    updatedAt: '2026-07-30T00:00:00.000Z',
    ...overrides,
  };
}

function recoveredState(overrides = {}) {
  return runtimeState({
    schemaVersion: 2,
    runtimeStatus: 'RECOVERED',
    requestedProfiles: ['core'],
    operationId: OPERATION_ID,
    manifestDigest: MANIFEST_DIGEST,
    generationDigest: GENERATION_DIGEST,
    updatedAt: '2026-07-30T00:00:07.000Z',
    ...overrides,
  });
}

function recoveryBootMarkerInput(overrides = {}) {
  return {
    schemaVersion: 1,
    providerGuid: '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}',
    channel: 'System',
    eventId: 12,
    version: 0,
    eventRecordId: '100',
    timeCreated: '2026-07-30T00:00:02.000Z',
    startTime: '2026-07-30T00:00:02.000Z',
    ...overrides,
  };
}

function recoveryAclFacts() {
  return {
    ownerSid: 'S-1-5-32-544',
    protected: true,
    canonical: true,
    accessRuleCount: 2,
    administratorsFullControl: true,
    systemFullControl: true,
    aclDigest: 'C'.repeat(64),
  };
}

function recoveryDirectoryFacts(fileId, directChildren) {
  return {
    volumeSerialNumber: 'D'.repeat(16),
    fileId,
    acl: recoveryAclFacts(),
    directChildCount: directChildren.length,
    directChildren,
  };
}

function recoveryProofInput(failedState) {
  return {
    schemaVersion: 1,
    protocolRevision: 1,
    deviceId: DEVICE_ID,
    targetBindingDigest: 'E'.repeat(64),
    failedState,
    beforeBootMarker: recoveryModule.createRuntimeRecoveryBootMarker(
      recoveryBootMarkerInput(),
    ),
    afterBootMarker: recoveryModule.createRuntimeRecoveryBootMarker(
      recoveryBootMarkerInput({
        eventRecordId: '101',
        timeCreated: '2026-07-30T00:00:03.000Z',
        startTime: '2026-07-30T00:00:03.000Z',
      }),
    ),
    classification: 'EMPTY_PRE_TRANSACTION',
    priorAuthorizedAttempt: null,
    agentRoadAcl: recoveryAclFacts(),
    runtimeDirectory: recoveryDirectoryFacts('1'.repeat(32), ['staging']),
    stagingDirectory: recoveryDirectoryFacts('2'.repeat(32), [OPERATION_ID]),
    operationDirectory: recoveryDirectoryFacts('3'.repeat(32), []),
  };
}

async function createRecoveryFixture(t, { commit = true, recovered = false } = {}) {
  const fixture = await createStore(t);
  const missing = await fixture.store.read(DEVICE_ID);
  const failed = operationState('FAILED', 3, {
    failureCode: 'RUNTIME_COMPLETION_UNCERTAIN',
  });
  await fixture.store.transition(missing, failed);

  let now = new Date('2026-07-30T00:00:04.000Z');
  const recoveryStore = new recoveryModule.RuntimeRecoveryStore(fixture.root, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, 0x55),
  });
  const proofSource = recoveryProofInput(failed);
  const proof = recoveryModule.createRuntimeRecoveryProof(proofSource);
  await recoveryStore.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failed,
    bootMarker: proofSource.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:00:05.000Z');
  const ticket = await recoveryStore.createTicket({
    deviceId: DEVICE_ID,
    failedState: failed,
    proof,
    authorizationParent: recoveryModule.createRuntimeRecoveryAuthorizationParent({
      schemaVersion: 1,
      kind: 'GENESIS',
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      failedStateDigest: recoveryModule.runtimeRecoveryStateDigest(failed),
      ticketId: null,
      ticketDigest: null,
      attemptDigest: null,
    }),
  });
  now = new Date('2026-07-30T00:00:06.000Z');
  await recoveryStore.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: failed,
    proof,
  });

  const proposed = recoveredState();
  let recoveryCommit = null;
  if (commit) {
    now = new Date('2026-07-30T00:00:08.000Z');
    recoveryCommit = await recoveryStore.createRecoveryCommit({
      expectedFailedState: failed,
      proposedRecoveredState: proposed,
      ticketId: ticket.ticketId,
      proofDigest: ticket.proofDigest,
      disposition: 'REMOVED',
    });
  }
  if (recovered) await fixture.store.transition(failed, proposed);

  const paths = runtimeDeviceRecoveryPaths(fixture.root, DEVICE_ID, OPERATION_ID);
  return {
    ...fixture,
    failed,
    proposed,
    recoveryCommit,
    recoveryStore,
    paths,
  };
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error?.code, code);
    assert.equal(error.message, code);
    assert.deepEqual(Object.keys(error), ['code']);
    return true;
  });
}

function throwsCode(operation, code) {
  assert.throws(operation, (error) => {
    assert.equal(error?.code, code);
    assert.equal(error.message, code);
    assert.deepEqual(Object.keys(error), ['code']);
    return true;
  });
}

function at(second) {
  return `2026-07-30T00:00:${String(second).padStart(2, '0')}.000Z`;
}

function operationState(runtimeStatus, second, overrides = {}) {
  const hasManifest = !['INVENTORY_READY'].includes(runtimeStatus);
  return runtimeState({
    runtimeStatus,
    manifestDigest: hasManifest ? MANIFEST_DIGEST : null,
    generationDigest: hasManifest ? GENERATION_DIGEST : null,
    readyProfiles: runtimeStatus === 'READY' ? ['core'] : [],
    updatedAt: at(second),
    ...overrides,
  });
}

test('returns the exact frozen UNPROVISIONED snapshot when state is missing', async (t) => {
  const { store } = await createStore(t);

  assert.equal(Object.isFrozen(store), true);
  assert.equal(Object.hasOwn(store, 'root'), false);

  assert.deepEqual(RUNTIME_STATUSES, [
    'UNPROVISIONED',
    'INVENTORY_READY',
    'PLAN_READY',
    'ACQUIRING',
    'STAGED',
    'VERIFYING',
    'READY',
    'FAILED',
    'RECOVERED',
  ]);
  assert.equal(Object.isFrozen(RUNTIME_STATUSES), true);

  const state = await store.read(DEVICE_ID);
  assert.deepEqual(Object.keys(state), [
    'schemaVersion',
    'deviceId',
    'runtimeStatus',
    'requestedProfiles',
    'readyProfiles',
    'operationId',
    'manifestDigest',
    'generationDigest',
    'failureCode',
    'updatedAt',
  ]);
  assert.deepEqual(state, {
    schemaVersion: 1,
    deviceId: DEVICE_ID,
    runtimeStatus: 'UNPROVISIONED',
    requestedProfiles: [],
    readyProfiles: [],
    operationId: null,
    manifestDigest: null,
    generationDigest: null,
    failureCode: null,
    updatedAt: null,
  });
  assert.equal(Object.isFrozen(state), true);
  assert.equal(Object.isFrozen(state.requestedProfiles), true);
  assert.equal(Object.isFrozen(state.readyProfiles), true);
});

test('rejects invalid transitions before creating any runtime state layout', async (t) => {
  const { root, store } = await createStore(t);
  const expected = await store.read(DEVICE_ID);
  const invalid = operationState('PLAN_READY', 1);

  await rejectsCode(
    store.transition(expected, invalid),
    'RUNTIME_INPUT_INVALID',
  );
  for (const path of [
    root,
    join(root, DEVICE_ID),
    join(root, DEVICE_ID, 'state.json'),
    join(root, DEVICE_ID, 'state.json.lock'),
  ]) {
    await assert.rejects(stat(path), { code: 'ENOENT' });
  }
});

test('accepts canonical combined profile facts and freezes validator snapshots', () => {
  const state = operationState('READY', 1, {
    requestedProfiles: ['base'],
    readyProfiles: ['core', 'base'],
  });
  const snapshot = validateRuntimeStateRecord(state);

  assert.deepEqual(snapshot, state);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.requestedProfiles), true);
  assert.equal(Object.isFrozen(snapshot.readyProfiles), true);
});

test('accepts only the exact ten-field schema-2 RECOVERED structural record', () => {
  const state = recoveredState();
  const snapshot = validateRuntimeStateRecord(state);

  assert.deepEqual(Object.keys(snapshot), [
    'schemaVersion',
    'deviceId',
    'runtimeStatus',
    'requestedProfiles',
    'readyProfiles',
    'operationId',
    'manifestDigest',
    'generationDigest',
    'failureCode',
    'updatedAt',
  ]);
  assert.deepEqual(snapshot, state);
  assert.equal(snapshot.schemaVersion, 2);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.requestedProfiles), true);
  assert.equal(Object.isFrozen(snapshot.readyProfiles), true);
});

test('rejects wrong-schema, malformed, and hostile RECOVERED records without traps', () => {
  const schemaCases = [
    recoveredState({ schemaVersion: 1 }),
    runtimeState({ schemaVersion: 2 }),
    operationState('PLAN_READY', 2, { schemaVersion: 2 }),
    operationState('ACQUIRING', 2, { schemaVersion: 2 }),
    operationState('STAGED', 2, { schemaVersion: 2 }),
    operationState('VERIFYING', 2, { schemaVersion: 2 }),
    operationState('READY', 2, { schemaVersion: 2 }),
    operationState('FAILED', 2, {
      schemaVersion: 2,
      failureCode: 'RUNTIME_COMPLETION_UNCERTAIN',
    }),
    runtimeState({
      schemaVersion: 2,
      runtimeStatus: 'UNPROVISIONED',
      requestedProfiles: [],
      operationId: null,
      updatedAt: null,
    }),
  ];
  const malformedCases = [
    recoveredState({ requestedProfiles: ['base'] }),
    recoveredState({ requestedProfiles: ['core', 'base'] }),
    recoveredState({ readyProfiles: ['core'] }),
    recoveredState({ operationId: null }),
    recoveredState({ manifestDigest: null }),
    recoveredState({ generationDigest: null }),
    recoveredState({ failureCode: 'RUNTIME_COMPLETION_UNCERTAIN' }),
    { ...recoveredState(), extra: true },
  ];
  for (const record of [...schemaCases, ...malformedCases]) {
    throwsCode(() => validateRuntimeStateRecord(record), 'RUNTIME_INPUT_INVALID');
  }

  let traps = 0;
  const proxy = new Proxy(recoveredState(), {
    get() { traps += 1; throw new Error('HOSTILE_RECOVERED_GET'); },
    ownKeys() { traps += 1; throw new Error('HOSTILE_RECOVERED_KEYS'); },
  });
  const accessor = recoveredState();
  Object.defineProperty(accessor, 'runtimeStatus', {
    enumerable: true,
    get() { traps += 1; throw new Error('HOSTILE_RECOVERED_ACCESSOR'); },
  });
  const hostileProfiles = new Proxy(['core'], {
    get() { traps += 1; throw new Error('HOSTILE_RECOVERED_PROFILES'); },
  });
  for (const record of [proxy, accessor, recoveredState({ requestedProfiles: hostileProfiles })]) {
    throwsCode(() => validateRuntimeStateRecord(record), 'RUNTIME_INPUT_INVALID');
  }
  assert.equal(traps, 0);
});

test('atomically transitions and persists an exact owner-only runtime record', async (t) => {
  const { root, store } = await createStore(t);
  const expected = await store.read(DEVICE_ID);
  const next = runtimeState();

  const saved = await store.transition(expected, next);

  assert.deepEqual(saved, next);
  assert.equal(Object.isFrozen(saved), true);
  assert.equal(Object.isFrozen(saved.requestedProfiles), true);
  assert.equal(Object.isFrozen(saved.readyProfiles), true);
  assert.deepEqual(await store.read(DEVICE_ID), next);

  const statePath = join(root, DEVICE_ID, 'state.json');
  assert.deepEqual(JSON.parse(await readFile(statePath, 'utf8')), next);
  assert.equal((await stat(root)).mode & 0o777, 0o700);
  assert.equal((await stat(join(root, DEVICE_ID))).mode & 0o777, 0o700);
  assert.equal((await stat(statePath)).mode & 0o777, 0o600);
});

test('allows only the ordered operation lifecycle and a fresh READY recheck', async (t) => {
  const { store } = await createStore(t);
  let current = await store.read(DEVICE_ID);

  for (const next of [
    operationState('INVENTORY_READY', 1),
    operationState('PLAN_READY', 2),
    operationState('ACQUIRING', 3),
    operationState('STAGED', 4),
    operationState('VERIFYING', 5),
    operationState('READY', 6),
  ]) {
    current = await store.transition(current, next);
  }

  const recheck = operationState('INVENTORY_READY', 7, {
    operationId: NEXT_OPERATION_ID,
    manifestDigest: null,
    generationDigest: null,
    readyProfiles: [],
  });
  assert.deepEqual(await store.transition(current, recheck), recheck);
});

test('allows a verified black-box provisioner to commit directly from ACQUIRING to READY', async (t) => {
  const { store } = await createStore(t);
  let current = await store.read(DEVICE_ID);
  current = await store.transition(current, operationState('INVENTORY_READY', 1));
  current = await store.transition(current, operationState('PLAN_READY', 2));
  current = await store.transition(current, operationState('ACQUIRING', 3));

  assert.deepEqual(
    await store.transition(current, operationState('READY', 4)),
    operationState('READY', 4),
  );
});

test('accepts the finite elevation blocker failure code', () => {
  assert.deepEqual(validateRuntimeStateRecord(operationState('FAILED', 2, {
    failureCode: 'RUNTIME_ELEVATION_REQUIRED',
  })), operationState('FAILED', 2, {
    failureCode: 'RUNTIME_ELEVATION_REQUIRED',
  }));
});

test('allows no-op readiness only when it binds a verified generation', async (t) => {
  const { store } = await createStore(t);
  let current = await store.read(DEVICE_ID);
  current = await store.transition(current, operationState('INVENTORY_READY', 1));
  const ready = operationState('READY', 2, {
    operationId: null,
    manifestDigest: null,
    generationDigest: GENERATION_DIGEST,
  });

  assert.deepEqual(await store.transition(current, ready), ready);
});

test('records finite failures and permits only safe retry identities', async (t) => {
  const { store } = await createStore(t);
  let current = await store.read(DEVICE_ID);
  current = await store.transition(current, operationState('INVENTORY_READY', 1));
  current = await store.transition(current, operationState('PLAN_READY', 2));
  const uncertain = operationState('FAILED', 3, {
    failureCode: 'RUNTIME_COMPLETION_UNCERTAIN',
  });
  current = await store.transition(current, uncertain);

  await rejectsCode(store.transition(current, operationState('INVENTORY_READY', 4, {
    operationId: NEXT_OPERATION_ID,
    manifestDigest: null,
    generationDigest: null,
  })), 'RUNTIME_INPUT_INVALID');

  current = await store.transition(current, operationState('PLAN_READY', 4));
  const failed = operationState('FAILED', 5, { failureCode: 'RUNTIME_INSTALL_FAILED' });
  current = await store.transition(current, failed);
  const recheck = operationState('INVENTORY_READY', 6, {
    operationId: NEXT_OPERATION_ID,
    manifestDigest: null,
    generationDigest: null,
  });
  assert.deepEqual(await store.transition(current, recheck), recheck);
});

test('publishes RECOVERED only from exact completion uncertainty with a real commit', async (t) => {
  const fixture = await createRecoveryFixture(t);

  assert.deepEqual(
    await fixture.store.transition(fixture.failed, fixture.proposed),
    fixture.proposed,
  );
  assert.deepEqual(await fixture.store.read(DEVICE_ID), fixture.proposed);
});

test('publishes and revalidates RECOVERED under the exact recovery operation lock', async (t) => {
  const fixture = await createRecoveryFixture(t);
  let acquisitions = 0;
  const recoveryTestHook = Symbol.for('agent-road.runtime-recovery-store.test-hook');
  globalThis[recoveryTestHook] = async (event) => {
    if (event === 'afterRecoveryKernelLockAcquired') acquisitions += 1;
  };
  t.after(() => { delete globalThis[recoveryTestHook]; });

  const saved = await fixture.recoveryStore.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, () => fixture.store.transition(fixture.failed, fixture.proposed));

  assert.deepEqual(saved, fixture.proposed);
  assert.equal(acquisitions, 1);
});

test('rejects every other failure and changed RECOVERED identity before publication', async (t) => {
  for (const failureCode of [
    'RUNTIME_ROLLBACK_INCOMPLETE',
    'RUNTIME_INSTALL_FAILED',
  ]) {
    await t.test(failureCode, async (t) => {
      const { store } = await createStore(t);
      const missing = await store.read(DEVICE_ID);
      const failed = operationState('FAILED', 3, { failureCode });
      await store.transition(missing, failed);
      await rejectsCode(
        store.transition(failed, recoveredState()),
        'RUNTIME_INPUT_INVALID',
      );
      assert.deepEqual(await store.read(DEVICE_ID), failed);
    });
  }

  const fixture = await createRecoveryFixture(t);
  for (const next of [
    recoveredState({ deviceId: 'dev_changed' }),
    recoveredState({ operationId: NEXT_OPERATION_ID }),
    recoveredState({ manifestDigest: 'C'.repeat(64) }),
    recoveredState({ generationDigest: 'C'.repeat(64) }),
    recoveredState({ requestedProfiles: ['base'] }),
    recoveredState({ readyProfiles: ['core'] }),
    recoveredState({ schemaVersion: 1 }),
    recoveredState({ updatedAt: fixture.failed.updatedAt }),
  ]) {
    await rejectsCode(
      fixture.store.transition(fixture.failed, next),
      'RUNTIME_INPUT_INVALID',
    );
  }
  assert.deepEqual(await fixture.store.read(DEVICE_ID), fixture.failed);
});

test('starts a distinct fresh schema-1 attempt from committed RECOVERED', async (t) => {
  const fixture = await createRecoveryFixture(t, { recovered: true });
  const inventoryReady = operationState('INVENTORY_READY', 9, {
    operationId: NEXT_OPERATION_ID,
    manifestDigest: null,
    generationDigest: null,
  });

  assert.deepEqual(
    await fixture.store.transition(fixture.proposed, inventoryReady),
    inventoryReady,
  );
  assert.equal(inventoryReady.schemaVersion, 1);
  assert.deepEqual(inventoryReady.requestedProfiles, ['core']);
  assert.deepEqual(inventoryReady.readyProfiles, []);
  assert.equal(inventoryReady.manifestDigest, null);
  assert.equal(inventoryReady.generationDigest, null);
  assert.equal(inventoryReady.failureCode, null);
});

test('rejects direct or malformed transitions out of RECOVERED', async (t) => {
  const fixture = await createRecoveryFixture(t, { recovered: true });
  const cases = [
    operationState('READY', 9),
    operationState('PLAN_READY', 9),
    operationState('ACQUIRING', 9),
    operationState('STAGED', 9),
    operationState('VERIFYING', 9),
    operationState('FAILED', 9, { failureCode: 'RUNTIME_INSTALL_FAILED' }),
    recoveredState({ updatedAt: at(9) }),
    operationState('INVENTORY_READY', 9),
    operationState('INVENTORY_READY', 9, {
      requestedProfiles: ['base'],
      operationId: NEXT_OPERATION_ID,
    }),
    operationState('INVENTORY_READY', 9, {
      operationId: NEXT_OPERATION_ID,
      manifestDigest: MANIFEST_DIGEST,
      generationDigest: GENERATION_DIGEST,
    }),
    operationState('INVENTORY_READY', 7, {
      operationId: NEXT_OPERATION_ID,
    }),
  ];
  for (const next of cases) {
    await rejectsCode(
      fixture.store.transition(fixture.proposed, next),
      'RUNTIME_INPUT_INVALID',
    );
  }
  assert.deepEqual(await fixture.store.read(DEVICE_ID), fixture.proposed);
});

test('ordinary FAILED reads ignore an uncommitted recovery attempt', async (t) => {
  const fixture = await createRecoveryFixture(t, { commit: false });

  assert.deepEqual(await fixture.store.read(DEVICE_ID), fixture.failed);
});

test('requires a valid immutable commit before publishing RECOVERED', async (t) => {
  const attacks = [
    ['missing', async ({ paths }) => rm(paths.recoveryCommit)],
    ['corrupt', async ({ paths }) => writeFile(paths.recoveryCommit, '{not-json}\n')],
    ['mismatched', async ({ paths, recoveryCommit }) => {
      const mismatched = recoveredState({ manifestDigest: 'C'.repeat(64) });
      await writeFile(paths.recoveryCommit, `${JSON.stringify({
        ...recoveryCommit,
        proposedRecoveredState: mismatched,
        proposedRecoveredStateDigest: recoveryModule.runtimeRecoveryStateDigest(mismatched),
      }, null, 2)}\n`);
    }],
  ];

  for (const [name, attack] of attacks) {
    await t.test(name, async (t) => {
      const fixture = await createRecoveryFixture(t);
      await attack(fixture);

      await rejectsCode(
        fixture.store.transition(fixture.failed, fixture.proposed),
        'RUNTIME_STATE_UNSUPPORTED',
      );
      assert.deepEqual(await fixture.store.read(DEVICE_ID), fixture.failed);
      const persisted = JSON.parse(await readFile(
        join(fixture.root, DEVICE_ID, 'state.json'),
        'utf8',
      ));
      assert.deepEqual(persisted, fixture.failed);
    });
  }
});

test('rejects unsafe, linked, and replaced commits when reading RECOVERED', async (t) => {
  const attacks = [
    ['symlink', async ({ root, paths, recoveryCommit }) => {
      const target = join(root, 'symlink-commit-target.json');
      await writeFile(target, `${JSON.stringify(recoveryCommit, null, 2)}\n`, { mode: 0o600 });
      await rm(paths.recoveryCommit);
      await symlink(target, paths.recoveryCommit);
    }],
    ['extra hardlink', async ({ root, paths }) => {
      await link(paths.recoveryCommit, join(root, 'extra-commit-link.json'));
    }],
    ['broad permissions', async ({ paths }) => chmod(paths.recoveryCommit, 0o644)],
    ['replacement inode', async ({ paths, recoveryCommit }) => {
      await rename(paths.recoveryCommit, `${paths.recoveryCommit}.moved`);
      await writeFile(
        paths.recoveryCommit,
        `${JSON.stringify(recoveryCommit, null, 2)}\n`,
        { mode: 0o600 },
      );
    }],
  ];

  for (const [name, attack] of attacks) {
    await t.test(name, async (t) => {
      const fixture = await createRecoveryFixture(t, { recovered: true });
      await attack(fixture);
      await rejectsCode(
        fixture.store.read(DEVICE_ID),
        'RUNTIME_STATE_UNSUPPORTED',
      );
    });
  }
});

test('validates the persisted RECOVERED commit before comparing CAS state', async (t) => {
  const fixture = await createRecoveryFixture(t, { recovered: true });
  await writeFile(fixture.paths.recoveryCommit, '{corrupt-commit}\n');
  const stale = recoveredState({ updatedAt: '2026-07-30T00:00:07.001Z' });
  const next = operationState('INVENTORY_READY', 9, {
    operationId: NEXT_OPERATION_ID,
  });

  await rejectsCode(
    fixture.store.transition(stale, next),
    'RUNTIME_STATE_UNSUPPORTED',
  );
});

test('revalidates a RECOVERED commit after state publication before success', async (t) => {
  const fixture = await createRecoveryFixture(t);
  const statePath = join(fixture.root, DEVICE_ID, 'state.json');
  let replaced = false;
  globalThis[RUNTIME_STATE_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterStatePublication' || context.path !== statePath || replaced) return;
    replaced = true;
    await rename(fixture.paths.recoveryCommit, `${fixture.paths.recoveryCommit}.moved`);
    await writeFile(fixture.paths.recoveryCommit, '{replaced-commit}\n', { mode: 0o600 });
  };
  t.after(() => { delete globalThis[RUNTIME_STATE_TEST_HOOK]; });

  await rejectsCode(
    fixture.store.transition(fixture.failed, fixture.proposed),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  assert.equal(replaced, true);
});

test('rejects stale CAS records and concurrent lost updates', async (t) => {
  const { store } = await createStore(t);
  const missing = await store.read(DEVICE_ID);
  const first = operationState('INVENTORY_READY', 1);
  const second = operationState('INVENTORY_READY', 1, { operationId: NEXT_OPERATION_ID });

  const results = await Promise.allSettled([
    store.transition(missing, first),
    store.transition(missing, second),
  ]);
  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.equal(results.filter(({ status }) => status === 'rejected').length, 1);
  assert.equal(results.find(({ status }) => status === 'rejected').reason.code, 'RUNTIME_ALREADY_RUNNING');

  await rejectsCode(
    store.transition(missing, operationState('INVENTORY_READY', 2)),
    'RUNTIME_ALREADY_RUNNING',
  );
});

test('rejects skipped, backward, same-state, identity-changing, and non-monotone transitions', async (t) => {
  const { store } = await createStore(t);
  let current = await store.read(DEVICE_ID);
  current = await store.transition(current, operationState('INVENTORY_READY', 1));

  for (const next of [
    operationState('INVENTORY_READY', 2),
    operationState('STAGED', 2),
    operationState('PLAN_READY', 1),
    operationState('PLAN_READY', 2, { operationId: NEXT_OPERATION_ID }),
    operationState('PLAN_READY', 2, { requestedProfiles: ['base'] }),
  ]) {
    await rejectsCode(store.transition(current, next), 'RUNTIME_INPUT_INVALID');
  }

  current = await store.transition(current, operationState('PLAN_READY', 2));
  for (const next of [
    operationState('INVENTORY_READY', 3, {
      operationId: NEXT_OPERATION_ID,
      manifestDigest: null,
      generationDigest: null,
    }),
    operationState('VERIFYING', 3),
    operationState('FAILED', 3, {
      manifestDigest: 'C'.repeat(64),
      failureCode: 'RUNTIME_INSTALL_FAILED',
    }),
  ]) {
    await rejectsCode(store.transition(current, next), 'RUNTIME_INPUT_INVALID');
  }
});

test('rejects extra, missing, noncanonical, and semantically inconsistent records', async (t) => {
  const { store } = await createStore(t);
  const expected = await store.read(DEVICE_ID);
  const cases = [
    { ...runtimeState(), extra: true },
    Object.fromEntries(Object.entries(runtimeState()).filter(([field]) => field !== 'failureCode')),
    runtimeState({ schemaVersion: 2 }),
    runtimeState({ deviceId: '../escape' }),
    runtimeState({ runtimeStatus: 'CONNECTED_SSH_ONLY' }),
    runtimeState({ requestedProfiles: ['base', 'core'] }),
    runtimeState({ requestedProfiles: ['core', 'core'] }),
    runtimeState({ requestedProfiles: ['web'] }),
    runtimeState({ readyProfiles: ['base'] }),
    runtimeState({ operationId: 'A'.repeat(32) }),
    runtimeState({ manifestDigest: 'a'.repeat(64) }),
    runtimeState({ generationDigest: 'B'.repeat(65) }),
    runtimeState({ failureCode: 'RUNTIME_INSTALL_FAILED' }),
    runtimeState({ updatedAt: '2026-07-30' }),
    operationState('PLAN_READY', 2, { manifestDigest: null }),
    operationState('READY', 2, { readyProfiles: [] }),
    operationState('FAILED', 2, { failureCode: 'RUNTIME_NOT_A_REAL_CODE' }),
  ];

  for (const record of cases) {
    await rejectsCode(store.transition(expected, record), 'RUNTIME_INPUT_INVALID');
  }
});

test('accepts the finite cache safety failure but never arbitrary RUNTIME-shaped text', async (t) => {
  const { store } = await createStore(t);
  const expected = await store.read(DEVICE_ID);
  const failed = operationState('FAILED', 1, {
    manifestDigest: null,
    generationDigest: null,
    failureCode: 'RUNTIME_CACHE_UNSAFE',
  });

  assert.deepEqual(await store.transition(expected, failed), failed);
});

test('rejects promises, proxies, accessors, symbols, and hostile arrays without executing them', async (t) => {
  const { store } = await createStore(t);
  const expected = await store.read(DEVICE_ID);
  let traps = 0;
  const proxy = new Proxy(runtimeState(), {
    get() { traps += 1; throw new Error('HOSTILE_RECORD_GET'); },
    ownKeys() { traps += 1; throw new Error('HOSTILE_RECORD_KEYS'); },
  });
  const getter = runtimeState();
  Object.defineProperty(getter, 'runtimeStatus', {
    enumerable: true,
    get() { traps += 1; throw new Error('HOSTILE_RECORD_GETTER'); },
  });
  const symbol = runtimeState();
  symbol[Symbol('hostile')] = true;
  const hostileProfiles = new Proxy(['core'], {
    get() { traps += 1; throw new Error('HOSTILE_ARRAY_GET'); },
  });

  for (const record of [Promise.resolve(runtimeState()), proxy, getter, symbol, runtimeState({ requestedProfiles: hostileProfiles })]) {
    await rejectsCode(store.transition(expected, record), 'RUNTIME_INPUT_INVALID');
  }
  assert.equal(traps, 0);
});

test('snapshots caller data before waiting for the state lock', async (t) => {
  const { root, store } = await createStore(t);
  const expected = await store.read(DEVICE_ID);
  const next = runtimeState();
  await mkdir(join(root, DEVICE_ID), { recursive: true, mode: 0o700 });
  const lockPath = join(root, DEVICE_ID, 'state.json.lock');
  await writeFile(lockPath, JSON.stringify({
    owner: 'held-owner',
    pid: process.pid,
    createdAt: new Date().toISOString(),
  }), { mode: 0o600 });

  const transitioning = store.transition(expected, next);
  next.requestedProfiles.push('base');
  next.runtimeStatus = 'FAILED';
  await new Promise((resolve) => setTimeout(resolve, 25));
  await rm(lockPath);

  assert.deepEqual(await transitioning, runtimeState());
});

test('rejects symlinks, non-files, hardlinks, and broad permissions without leaking paths', async (t) => {
  async function unsafeCase(setup) {
    const fixture = await createStore(t);
    await mkdir(join(fixture.root, DEVICE_ID), { recursive: true, mode: 0o700 });
    const statePath = join(fixture.root, DEVICE_ID, 'state.json');
    await setup({ ...fixture, statePath });
    await assert.rejects(fixture.store.read(DEVICE_ID), (error) => {
      assert.equal(error?.code, 'RUNTIME_STATE_UNSUPPORTED');
      assert.equal(error.message, 'RUNTIME_STATE_UNSUPPORTED');
      assert.doesNotMatch(error.message, /agent-road-runtime-state|state\.json|dev_abc123/u);
      return true;
    });
  }

  await unsafeCase(async ({ root, statePath }) => {
    const target = join(root, 'linked-state.json');
    await writeFile(target, `${JSON.stringify(runtimeState())}\n`, { mode: 0o600 });
    await symlink(target, statePath);
  });
  await unsafeCase(({ statePath }) => mkdir(statePath, { mode: 0o700 }));
  await unsafeCase(async ({ root, statePath }) => {
    const target = join(root, 'hardlinked-state.json');
    await writeFile(target, `${JSON.stringify(runtimeState())}\n`, { mode: 0o600 });
    await link(target, statePath);
  });
  await unsafeCase(async ({ statePath }) => {
    await writeFile(statePath, `${JSON.stringify(runtimeState())}\n`, { mode: 0o644 });
    await chmod(statePath, 0o644);
  });
});

test('rejects unsafe runtime directories and lock endpoints', async (t) => {
  const { root, store } = await createStore(t);
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o755);
  await rejectsCode(store.read(DEVICE_ID), 'RUNTIME_STATE_UNSUPPORTED');
  await chmod(root, 0o700);

  const linkedDevice = join(root, DEVICE_ID);
  const targetDevice = join(root, 'target-device');
  await mkdir(targetDevice, { mode: 0o700 });
  await symlink(targetDevice, linkedDevice);
  await rejectsCode(store.read(DEVICE_ID), 'RUNTIME_STATE_UNSUPPORTED');
  await rm(linkedDevice);

  await mkdir(linkedDevice, { mode: 0o700 });
  const expected = await store.read(DEVICE_ID);
  const lockTarget = join(root, 'lock-target');
  await writeFile(lockTarget, '{}\n', { mode: 0o600 });
  await symlink(lockTarget, join(linkedDevice, 'state.json.lock'));
  await rejectsCode(store.read(DEVICE_ID), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(
    store.transition(expected, runtimeState()),
    'RUNTIME_STATE_UNSUPPORTED',
  );
});

test('rejects Darwin extended ACLs on the runtime root, device, state, and lock', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  for (const endpoint of ['root', 'device', 'state', 'lock']) {
    await t.test(endpoint, async (t) => {
      const { root, store } = await createStore(t);
      const initial = await store.read(DEVICE_ID);
      await store.transition(initial, runtimeState());
      const devicePath = join(root, DEVICE_ID);
      const statePath = join(devicePath, 'state.json');
      const lockPath = `${statePath}.lock`;
      const paths = { root, device: devicePath, state: statePath, lock: lockPath };
      if (endpoint === 'lock') {
        await writeFile(lockPath, `${JSON.stringify({
          owner: 'held-owner',
          pid: process.pid,
          createdAt: new Date().toISOString(),
        })}\n`, { mode: 0o600 });
      }
      await addExtendedAcl(t, paths[endpoint]);
      await rejectsCode(store.read(DEVICE_ID), 'RUNTIME_STATE_UNSUPPORTED');
    });
  }
});

test('rejects a directory ACL injected after its ACL probe', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const { root, store } = await createStore(t);
  const initial = await store.read(DEVICE_ID);
  await store.transition(initial, runtimeState());
  const devicePath = join(root, DEVICE_ID);
  let injected = false;
  globalThis[RUNTIME_STATE_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterDirectoryAclCheck' || injected || context.path !== devicePath) return;
    injected = true;
    await addExtendedAcl(t, devicePath);
  };
  t.after(() => { delete globalThis[RUNTIME_STATE_TEST_HOOK]; });

  await rejectsCode(store.read(DEVICE_ID), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(injected, true);
});

test('waits for an observed active lock before reporting missing state', async (t) => {
  const { root, store } = await createStore(t);
  const devicePath = join(root, DEVICE_ID);
  const statePath = join(devicePath, 'state.json');
  const lockPath = `${statePath}.lock`;
  await mkdir(devicePath, { recursive: true, mode: 0o700 });
  await writeFile(lockPath, `${JSON.stringify({
    owner: 'held-owner',
    pid: process.pid,
    createdAt: new Date().toISOString(),
  })}\n`, { mode: 0o600 });

  let settled = false;
  const reading = store.read(DEVICE_ID).finally(() => { settled = true; });
  await new Promise((resolve) => setTimeout(resolve, 30));
  const settledWhileLocked = settled;
  const published = runtimeState();
  await writeFile(statePath, `${JSON.stringify(published, null, 2)}\n`, { mode: 0o600 });
  await rm(lockPath);

  assert.equal(settledWhileLocked, false);
  assert.deepEqual(await reading, published);
});

test('rejects a state file replaced after its ACL probe', async (t) => {
  const { root, store } = await createStore(t);
  const initial = await store.read(DEVICE_ID);
  await store.transition(initial, runtimeState());
  const statePath = join(root, DEVICE_ID, 'state.json');
  const movedPath = `${statePath}.moved`;
  let swapped = false;
  globalThis[RUNTIME_STATE_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterStateAclCheck' || swapped || context.path !== statePath) return;
    swapped = true;
    await rm(movedPath, { force: true });
    await rename(statePath, movedPath);
    await writeFile(statePath, `${JSON.stringify(runtimeState({
      operationId: NEXT_OPERATION_ID,
    }), null, 2)}\n`, { mode: 0o600 });
  };
  t.after(() => { delete globalThis[RUNTIME_STATE_TEST_HOOK]; });

  await rejectsCode(store.read(DEVICE_ID), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(swapped, true);
});

test('revalidates a published state file before returning success', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const { root, store } = await createStore(t);
  const expected = await store.read(DEVICE_ID);
  const statePath = join(root, DEVICE_ID, 'state.json');
  let injected = false;
  globalThis[RUNTIME_STATE_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterStatePublication' || injected || context.path !== statePath) return;
    injected = true;
    await addExtendedAcl(t, statePath);
  };
  t.after(() => { delete globalThis[RUNTIME_STATE_TEST_HOOK]; });

  await rejectsCode(store.transition(expected, runtimeState()), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(injected, true);
});

test('does not create runtime state through a symlinked ancestor', async (t) => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-runtime-state-')));
  const anchor = join(directory, 'anchor');
  const movedAnchor = join(directory, 'moved-anchor');
  const outside = join(directory, 'outside');
  await mkdir(anchor, { mode: 0o700 });
  await mkdir(outside, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = join(anchor, 'runtime', 'devices');
  const store = new RuntimeStateStore(root);
  const expected = await store.read(DEVICE_ID);
  await rename(anchor, movedAnchor);
  await symlink(outside, anchor);

  await rejectsCode(store.transition(expected, runtimeState()), 'RUNTIME_STATE_UNSUPPORTED');
  await assert.rejects(stat(join(outside, 'runtime')), { code: 'ENOENT' });
});

test('rejects a device directory swapped after layout validation without publishing outside', async (t) => {
  const { root, store } = await createStore(t);
  let current = await store.read(DEVICE_ID);
  current = await store.transition(current, operationState('INVENTORY_READY', 1));
  const devicePath = join(root, DEVICE_ID);
  const movedDevice = join(root, 'moved-device');
  const outsideDevice = join(root, 'outside-device');
  await mkdir(outsideDevice, { mode: 0o700 });
  let swapped = false;
  globalThis[RUNTIME_STATE_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterStateLayoutCheck' || swapped || context.path !== devicePath) return;
    swapped = true;
    await rename(devicePath, movedDevice);
    await symlink(outsideDevice, devicePath);
  };
  t.after(() => { delete globalThis[RUNTIME_STATE_TEST_HOOK]; });

  await rejectsCode(
    store.transition(current, operationState('PLAN_READY', 2)),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  assert.equal(swapped, true);
  await assert.rejects(stat(join(outsideDevice, 'state.json')), { code: 'ENOENT' });
});

test('maps corrupt disk records and unexpected filesystem errors to finite codes', async (t) => {
  const { root, store } = await createStore(t);
  await mkdir(join(root, DEVICE_ID), { recursive: true, mode: 0o700 });
  const statePath = join(root, DEVICE_ID, 'state.json');
  await writeFile(statePath, '{not-json}\n', { mode: 0o600 });
  await rejectsCode(store.read(DEVICE_ID), 'RUNTIME_STATE_UNSUPPORTED');

  await writeFile(statePath, `${JSON.stringify({ ...runtimeState(), extra: '/private/path' })}\n`, { mode: 0o600 });
  await rejectsCode(store.read(DEVICE_ID), 'RUNTIME_STATE_UNSUPPORTED');

  const missingProjection = {
    schemaVersion: 1,
    deviceId: DEVICE_ID,
    runtimeStatus: 'UNPROVISIONED',
    requestedProfiles: [],
    readyProfiles: [],
    operationId: null,
    manifestDigest: null,
    generationDigest: null,
    failureCode: null,
    updatedAt: null,
  };
  await writeFile(statePath, `${JSON.stringify(missingProjection, null, 2)}\n`, { mode: 0o600 });
  await rejectsCode(store.read(DEVICE_ID), 'RUNTIME_STATE_UNSUPPORTED');
});

test('tolerates a previous owner releasing its lock during the optional ACL probe', async (t) => {
  const {root,store} = await createStore(t);
  const expected = await store.read(DEVICE_ID);
  const lockPath = join(root,DEVICE_ID,'state.json.lock');
  await mkdir(join(root,DEVICE_ID),{recursive:true,mode:0o700});
  await writeFile(lockPath,JSON.stringify({owner:'previous-owner',pid:process.pid,createdAt:new Date().toISOString()}),{mode:0o600});
  let released = false;
  globalThis[RUNTIME_STATE_TEST_HOOK] = async (event,context) => {
    if(event === 'afterOptionalLockObservation' && context.path === lockPath && !released){released=true;await rm(lockPath);}
  };
  try {assert.deepEqual(await store.transition(expected,runtimeState()),runtimeState());}
  finally {delete globalThis[RUNTIME_STATE_TEST_HOOK];}
  assert.equal(released,true);
});
