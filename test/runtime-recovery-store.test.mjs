import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import * as pathModule from '../src/core/paths.mjs';
import * as recoveryModule from '../src/runtime/runtime-recovery-store.mjs';

const DEVICE_ID = 'dev_abc123';
const OPERATION_ID = 'a'.repeat(32);
const MANIFEST_DIGEST = 'A'.repeat(64);
const GENERATION_DIGEST = 'B'.repeat(64);
const RECOVERY_TEST_HOOK = Symbol.for('agent-road.runtime-recovery-store.test-hook');
const execFile = promisify(execFileCallback);

function failedState(overrides = {}) {
  return {
    schemaVersion: 1,
    deviceId: DEVICE_ID,
    runtimeStatus: 'FAILED',
    requestedProfiles: ['core'],
    readyProfiles: [],
    operationId: OPERATION_ID,
    manifestDigest: MANIFEST_DIGEST,
    generationDigest: GENERATION_DIGEST,
    failureCode: 'RUNTIME_COMPLETION_UNCERTAIN',
    updatedAt: '2026-07-30T00:00:00.000Z',
    ...overrides,
  };
}

function recoveredState(overrides = {}) {
  return {
    schemaVersion: 2,
    deviceId: DEVICE_ID,
    runtimeStatus: 'RECOVERED',
    requestedProfiles: ['core'],
    readyProfiles: [],
    operationId: OPERATION_ID,
    manifestDigest: MANIFEST_DIGEST,
    generationDigest: GENERATION_DIGEST,
    failureCode: null,
    updatedAt: '2026-07-30T00:02:00.000Z',
    ...overrides,
  };
}

function bootMarkerInput(overrides = {}) {
  return {
    schemaVersion: 1,
    providerGuid: '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}',
    channel: 'System',
    eventId: 12,
    version: 0,
    eventRecordId: '18446744073709551614',
    timeCreated: '2026-07-30T00:00:00.000Z',
    startTime: '2026-07-29T23:59:59.000Z',
    ...overrides,
  };
}

function aclFacts(overrides = {}) {
  return {
    ownerSid: 'S-1-5-32-544',
    protected: true,
    canonical: true,
    accessRuleCount: 2,
    administratorsFullControl: true,
    systemFullControl: true,
    aclDigest: 'C'.repeat(64),
    ...overrides,
  };
}

function directoryFacts(fileId, directChildren, overrides = {}) {
  return {
    volumeSerialNumber: 'D'.repeat(16),
    fileId,
    acl: aclFacts(),
    directChildCount: directChildren.length,
    directChildren,
    ...overrides,
  };
}

function proofInput(overrides = {}) {
  return {
    schemaVersion: 1,
    protocolRevision: 1,
    deviceId: DEVICE_ID,
    targetBindingDigest: 'E'.repeat(64),
    failedState: failedState(),
    beforeBootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput({
      eventRecordId: '100',
      timeCreated: '2026-07-30T02:00:00.000Z',
      startTime: '2026-07-30T02:00:00.000Z',
    })),
    afterBootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput({
      eventRecordId: '101',
      timeCreated: '2026-07-30T01:00:00.000Z',
      startTime: '2026-07-30T01:00:00.000Z',
    })),
    classification: 'EMPTY_PRE_TRANSACTION',
    priorAuthorizedAttempt: null,
    agentRoadAcl: aclFacts(),
    runtimeDirectory: directoryFacts('1'.repeat(32), ['staging']),
    stagingDirectory: directoryFacts('2'.repeat(32), [OPERATION_ID]),
    operationDirectory: directoryFacts('3'.repeat(32), []),
    ...overrides,
  };
}

function genesisAuthorizationParent(state = failedState()) {
  return recoveryModule.createRuntimeRecoveryAuthorizationParent({
    schemaVersion: 1,
    kind: 'GENESIS',
    deviceId: state.deviceId,
    operationId: state.operationId,
    failedStateDigest: recoveryModule.runtimeRecoveryStateDigest(state),
    ticketId: null,
    ticketDigest: null,
    attemptDigest: null,
  });
}

function expiredTicketAuthorizationParent(ticket) {
  return recoveryModule.createRuntimeRecoveryAuthorizationParent({
    schemaVersion: 1,
    kind: 'EXPIRED_TICKET',
    deviceId: ticket.deviceId,
    operationId: ticket.operationId,
    failedStateDigest: ticket.failedStateDigest,
    ticketId: ticket.ticketId,
    ticketDigest: recoveryModule.runtimeRecoveryTicketDigest(ticket),
    attemptDigest: null,
  });
}

function authorizedAttemptAuthorizationParent(ticket, attempt) {
  return recoveryModule.createRuntimeRecoveryAuthorizationParent({
    schemaVersion: 1,
    kind: 'AUTHORIZED_ATTEMPT',
    deviceId: ticket.deviceId,
    operationId: ticket.operationId,
    failedStateDigest: ticket.failedStateDigest,
    ticketId: ticket.ticketId,
    ticketDigest: recoveryModule.runtimeRecoveryTicketDigest(ticket),
    attemptDigest: recoveryModule.runtimeRecoveryAuthorizedAttemptDigest(attempt),
  });
}

function ticketInput(source, proof, authorizationParent = genesisAuthorizationParent(
  source.failedState,
)) {
  return {
    deviceId: source.failedState.deviceId,
    failedState: source.failedState,
    proof,
    authorizationParent,
  };
}

async function createStore(t, options = {}) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-runtime-recovery-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = join(directory, 'runtime', 'devices');
  const store = new recoveryModule.RuntimeRecoveryStore(root, {
    now: () => new Date('2026-07-30T00:05:00.000Z'),
    ...options,
  });
  return { directory, root, store };
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error?.code, code);
    assert.equal(error.message, code);
    assert.deepEqual(Object.keys(error), ['code']);
    return true;
  });
}

async function addExtendedAcl(t, path) {
  await execFile('/bin/chmod', ['+a', 'everyone allow read', path]);
  t.after(async () => {
    try { await execFile('/bin/chmod', ['-N', path]); } catch {}
  });
}

async function immutableTemporaryPaths(finalPath) {
  const finalName = basename(finalPath);
  const pattern = new RegExp(
    `^${finalName.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}\\.[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.tmp$`,
    'u',
  );
  return (await readdir(dirname(finalPath)))
    .filter((name) => pattern.test(name))
    .map((name) => join(dirname(finalPath), name));
}

function deterministicPublicationIdForDigest(digest) {
  const value = digest.toLowerCase();
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-4${value.slice(13, 16)}-a${value.slice(17, 20)}-${value.slice(20, 32)}`;
}

async function createConsumedFixture(t, entropyByte = 0x33) {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const fixture = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, entropyByte),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await fixture.store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const ticket = await fixture.store.createTicket(ticketInput(source, proof));
  now = new Date('2026-07-30T00:07:00.000Z');
  const attempt = await fixture.store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: source.failedState,
    proof,
  });
  return {
    ...fixture,
    source,
    proof,
    ticket,
    attempt,
    setNow(value) { now = new Date(value); },
  };
}

async function createTicketFixture(t, entropyByte = 0x34) {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const fixture = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, entropyByte),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await fixture.store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const ticket = await fixture.store.createTicket(ticketInput(source, proof));
  return {
    ...fixture,
    source,
    proof,
    ticket,
    setNow(value) { now = new Date(value); },
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => { resolve = resolvePromise; });
  return Object.freeze({ promise, resolve });
}

async function replaceWithUnsafeSymlink(path) {
  const target = join(dirname(path), 'replacement-target');
  await writeFile(target, '{}\n', { mode: 0o600 });
  await rm(path);
  await symlink(target, path);
}

async function createAlreadyAbsentFixture(t, { consumeCurrent = true } = {}) {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const entropyBytes = [0x81, 0x82];
  let entropyIndex = 0;
  const fixture = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, entropyBytes[entropyIndex++]),
  });
  const priorSource = proofInput();
  const priorProof = recoveryModule.createRuntimeRecoveryProof(priorSource);
  await fixture.store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: priorSource.failedState,
    bootMarker: priorSource.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const priorTicket = await fixture.store.createTicket(ticketInput(priorSource, priorProof));
  now = new Date('2026-07-30T00:07:00.000Z');
  const priorAttempt = await fixture.store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: priorTicket.ticketId,
    failedState: priorSource.failedState,
    proof: priorProof,
  });
  const source = proofInput({
    classification: 'ALREADY_ABSENT',
    priorAuthorizedAttempt: {
      ticketId: priorTicket.ticketId,
      attemptDigest: recoveryModule.runtimeRecoveryAuthorizedAttemptDigest(priorAttempt),
    },
    stagingDirectory: directoryFacts('2'.repeat(32), []),
    operationDirectory: null,
  });
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  now = new Date('2026-07-30T00:08:00.000Z');
  const ticket = await fixture.store.createTicket(ticketInput(
    source,
    proof,
    authorizedAttemptAuthorizationParent(priorTicket, priorAttempt),
  ));
  let attempt = null;
  if (consumeCurrent) {
    now = new Date('2026-07-30T00:09:00.000Z');
    attempt = await fixture.store.consumeTicket({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      ticketId: ticket.ticketId,
      failedState: source.failedState,
      proof,
    });
  }
  return {
    ...fixture,
    priorSource,
    priorProof,
    priorTicket,
    priorAttempt,
    source,
    proof,
    ticket,
    attempt,
    setNow(value) { now = new Date(value); },
  };
}

test('derives bounded recovery record paths under one exact device and operation', () => {
  assert.equal(typeof pathModule.runtimeDeviceRecoveryPaths, 'function');

  const paths = pathModule.runtimeDeviceRecoveryPaths(
    '/tmp/agent-road/runtime/devices',
    'dev_abc123',
    'a'.repeat(32),
    `rct_${'b'.repeat(64)}`,
  );

  assert.deepEqual(paths, {
    device: '/tmp/agent-road/runtime/devices/dev_abc123',
    recovery: '/tmp/agent-road/runtime/devices/dev_abc123/recovery',
    operation: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}`,
    bootObservation: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/boot-observation.json`,
    legacyTickets: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/tickets`,
    tickets: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/tickets-v2`,
    ticket: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/tickets-v2/rct_${'b'.repeat(64)}.json`,
    authorizationSuccessors: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/authorization-successors`,
    legacyAuthorizedDeleteAttempts: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/authorized-delete-attempts`,
    authorizedDeleteAttempts: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/authorized-delete-attempts-v2`,
    authorizedDeleteAttempt: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/authorized-delete-attempts-v2/rct_${'b'.repeat(64)}.json`,
    recoveryCommit: `/tmp/agent-road/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/recovery-commit.json`,
  });
  assert.equal(Object.isFrozen(paths), true);
});

test('rejects noncanonical recovery operation and ticket ids without echoing them', () => {
  for (const [operationId, ticketId] of [
    ['../escape', `rct_${'b'.repeat(64)}`],
    ['A'.repeat(32), `rct_${'b'.repeat(64)}`],
    ['a'.repeat(33), `rct_${'b'.repeat(64)}`],
    ['a'.repeat(32), '../escape'],
    ['a'.repeat(32), `rct_${'B'.repeat(64)}`],
    ['a'.repeat(32), `rct_${'b'.repeat(65)}`],
  ]) {
    assert.throws(
      () => pathModule.runtimeDeviceRecoveryPaths(
        '/tmp/agent-road/runtime/devices',
        'dev_abc123',
        operationId,
        ticketId,
      ),
      (error) => {
        assert.equal(error?.code, 'RUNTIME_INPUT_INVALID');
        assert.equal(error.message, 'RUNTIME_INPUT_INVALID');
        assert.doesNotMatch(error.message, /escape|AAAA|BBBB/u);
        return true;
      },
    );
  }
});

test('derives deterministic observation and commit paths without selecting a ticket', () => {
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    '/tmp/agent-road/runtime/devices',
    DEVICE_ID,
    OPERATION_ID,
  );

  assert.equal(paths.ticket, null);
  assert.equal(paths.authorizedDeleteAttempt, null);
  assert.equal(
    paths.recoveryCommit,
    `/tmp/agent-road/runtime/devices/${DEVICE_ID}/recovery/operations/${OPERATION_ID}/recovery-commit.json`,
  );
});

test('rejects a canonical root whose longest derived recovery path exceeds 4096 UTF-8 bytes', () => {
  const root = `/${'a'.repeat(4_000)}`;
  assert.throws(
    () => pathModule.runtimeDeviceRecoveryPaths(
      root,
      DEVICE_ID,
      OPERATION_ID,
      `rct_${'b'.repeat(64)}`,
    ),
    (error) => error?.code === 'RUNTIME_INPUT_INVALID'
      && error.message === 'RUNTIME_INPUT_INVALID',
  );
});

test('canonicalizes and domain-separates the fixed authorization-parent variants', () => {
  const state = failedState();
  const common = {
    schemaVersion: 1,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    failedStateDigest: recoveryModule.runtimeRecoveryStateDigest(state),
  };
  const variants = [
    {
      ...common,
      kind: 'GENESIS',
      ticketId: null,
      ticketDigest: null,
      attemptDigest: null,
    },
    {
      ...common,
      kind: 'EXPIRED_TICKET',
      ticketId: `rct_${'a'.repeat(64)}`,
      ticketDigest: 'B'.repeat(64),
      attemptDigest: null,
    },
    {
      ...common,
      kind: 'AUTHORIZED_ATTEMPT',
      ticketId: `rct_${'c'.repeat(64)}`,
      ticketDigest: 'D'.repeat(64),
      attemptDigest: 'E'.repeat(64),
    },
  ];

  for (const input of variants) {
    const parent = recoveryModule.createRuntimeRecoveryAuthorizationParent(input);
    assert.deepEqual(parent, input);
    assert.equal(Object.isFrozen(parent), true);
    assert.equal(
      recoveryModule.runtimeRecoveryAuthorizationParentDigest(parent),
      createHash('sha256')
        .update('AGENT_ROAD_RUNTIME_RECOVERY_AUTHORIZATION_PARENT_V1\0', 'utf8')
        .update(JSON.stringify(parent), 'utf8')
        .digest('hex')
        .toUpperCase(),
    );
  }
  for (const invalid of [
    { ...variants[0], ticketId: `rct_${'a'.repeat(64)}` },
    { ...variants[1], attemptDigest: 'F'.repeat(64) },
    { ...variants[2], attemptDigest: null },
    { ...variants[0], latest: true },
  ]) {
    assert.throws(
      () => recoveryModule.createRuntimeRecoveryAuthorizationParent(invalid),
      (error) => error?.code === 'RUNTIME_INPUT_INVALID'
        && error.message === 'RUNTIME_INPUT_INVALID',
    );
  }
});

test('digests exact eligible failed and recovered states with canonical field ordering', () => {
  const expected = failedState();
  const canonical = JSON.stringify(expected);
  const expectedDigest = createHash('sha256')
    .update('AGENT_ROAD_RUNTIME_RECOVERY_STATE_V1\0', 'utf8')
    .update(canonical, 'utf8')
    .digest('hex')
    .toUpperCase();
  const reordered = Object.fromEntries(Object.entries(expected).reverse());

  assert.equal(recoveryModule.runtimeRecoveryStateDigest(expected), expectedDigest);
  assert.equal(recoveryModule.runtimeRecoveryStateDigest(reordered), expectedDigest);
  assert.notEqual(
    recoveryModule.runtimeRecoveryStateDigest(expected),
    recoveryModule.runtimeRecoveryStateDigest(recoveredState()),
  );
});

test('rejects ineligible and hostile recovery state bindings with one finite input code', () => {
  let traps = 0;
  const accessor = failedState();
  Object.defineProperty(accessor, 'runtimeStatus', {
    enumerable: true,
    get() { traps += 1; throw new Error('HOSTILE_STATE_GETTER'); },
  });
  const hostileDevice = {
    toString() { traps += 1; throw new Error('HOSTILE_DEVICE_STRING'); },
  };
  const proxy = new Proxy(failedState(), {
    ownKeys() { traps += 1; throw new Error('HOSTILE_STATE_KEYS'); },
  });

  for (const input of [
    failedState({ requestedProfiles: ['base'] }),
    failedState({ readyProfiles: ['core'] }),
    failedState({ failureCode: 'RUNTIME_ROLLBACK_INCOMPLETE' }),
    failedState({ manifestDigest: 'a'.repeat(64) }),
    failedState({ deviceId: hostileDevice }),
    recoveredState({ operationId: 'A'.repeat(32) }),
    accessor,
    proxy,
  ]) {
    assert.throws(
      () => recoveryModule.runtimeRecoveryStateDigest(input),
      (error) => {
        assert.equal(error?.code, 'RUNTIME_INPUT_INVALID');
        assert.equal(error.message, 'RUNTIME_INPUT_INVALID');
        assert.deepEqual(Object.keys(error), ['code']);
        return true;
      },
    );
  }
  assert.equal(traps, 0);
});

test('creates and validates one canonical domain-separated event-12 boot marker', () => {
  assert.equal(typeof recoveryModule.createRuntimeRecoveryBootMarker, 'function');
  assert.equal(typeof recoveryModule.validateRuntimeRecoveryBootMarker, 'function');

  const input = bootMarkerInput();
  const expectedDigest = createHash('sha256')
    .update('AGENT_ROAD_WINDOWS_BOOT_EVENT_12_V1\0', 'utf8')
    .update(JSON.stringify(input), 'utf8')
    .digest('hex')
    .toUpperCase();
  const marker = recoveryModule.createRuntimeRecoveryBootMarker(input);

  assert.deepEqual(marker, { ...input, markerDigest: expectedDigest });
  assert.equal(Object.isFrozen(marker), true);
  assert.deepEqual(recoveryModule.validateRuntimeRecoveryBootMarker(marker), marker);
});

test('rejects malformed or rewritten boot markers without comparing their clocks', () => {
  const valid = recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput({
    timeCreated: '2026-07-29T23:00:00.000Z',
    startTime: '2026-07-30T01:00:00.000Z',
  }));
  assert.deepEqual(recoveryModule.validateRuntimeRecoveryBootMarker(valid), valid);

  for (const input of [
    bootMarkerInput({ eventRecordId: '0' }),
    bootMarkerInput({ eventRecordId: '01' }),
    bootMarkerInput({ eventRecordId: '18446744073709551616' }),
    bootMarkerInput({ providerGuid: '{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}' }),
    bootMarkerInput({ version: 256 }),
  ]) {
    assert.throws(
      () => recoveryModule.createRuntimeRecoveryBootMarker(input),
      (error) => error?.code === 'RUNTIME_INPUT_INVALID'
        && error.message === 'RUNTIME_INPUT_INVALID',
    );
  }
  assert.throws(
    () => recoveryModule.validateRuntimeRecoveryBootMarker({
      ...valid,
      markerDigest: 'C'.repeat(64),
    }),
    (error) => error?.code === 'RUNTIME_INPUT_INVALID'
      && error.message === 'RUNTIME_INPUT_INVALID',
  );
});

test('normalizes and digests the exact device, failed-state, reboot, ACL, and topology proof', () => {
  assert.equal(typeof recoveryModule.createRuntimeRecoveryProof, 'function');
  assert.equal(typeof recoveryModule.runtimeRecoveryProofDigest, 'function');

  const input = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(input);
  assert.deepEqual(proof, {
    schemaVersion: 1,
    protocolRevision: 1,
    deviceId: DEVICE_ID,
    targetBindingDigest: 'E'.repeat(64),
    failedStateDigest: recoveryModule.runtimeRecoveryStateDigest(input.failedState),
    operationId: OPERATION_ID,
    manifestDigest: MANIFEST_DIGEST,
    generationDigest: GENERATION_DIGEST,
    beforeBootMarker: input.beforeBootMarker,
    afterBootMarker: input.afterBootMarker,
    classification: 'EMPTY_PRE_TRANSACTION',
    priorAuthorizedAttempt: null,
    agentRoadAcl: input.agentRoadAcl,
    runtimeDirectory: input.runtimeDirectory,
    stagingDirectory: input.stagingDirectory,
    operationDirectory: input.operationDirectory,
  });
  assert.equal(Object.isFrozen(proof), true);
  assert.equal(Object.isFrozen(proof.runtimeDirectory), true);
  assert.equal(Object.isFrozen(proof.runtimeDirectory.directChildren), true);
  assert.equal(
    recoveryModule.runtimeRecoveryProofDigest(proof),
    createHash('sha256')
      .update('AGENT_ROAD_RUNTIME_RECOVERY_PROOF_V1\0', 'utf8')
      .update(JSON.stringify(proof), 'utf8')
      .digest('hex')
      .toUpperCase(),
  );
});

test('requires classification-specific exact prior-attempt provenance in every proof', () => {
  const priorAuthorizedAttempt = {
    ticketId: `rct_${'f'.repeat(64)}`,
    attemptDigest: 'F'.repeat(64),
  };
  const alreadyAbsent = proofInput({
    classification: 'ALREADY_ABSENT',
    priorAuthorizedAttempt,
    stagingDirectory: directoryFacts('2'.repeat(32), []),
    operationDirectory: null,
  });

  assert.deepEqual(
    recoveryModule.createRuntimeRecoveryProof(alreadyAbsent).priorAuthorizedAttempt,
    priorAuthorizedAttempt,
  );
  for (const input of [
    proofInput({ priorAuthorizedAttempt }),
    {
      ...alreadyAbsent,
      priorAuthorizedAttempt: null,
    },
    {
      ...alreadyAbsent,
      priorAuthorizedAttempt: { ...priorAuthorizedAttempt, extra: true },
    },
  ]) {
    assert.throws(
      () => recoveryModule.createRuntimeRecoveryProof(input),
      (error) => error?.code === 'RUNTIME_INPUT_INVALID'
        && error.message === 'RUNTIME_INPUT_INVALID',
    );
  }
});

test('exclusively publishes and reads one canonical owner-only boot observation', async (t) => {
  assert.equal(typeof recoveryModule.RuntimeRecoveryStore, 'function');
  const { root, store } = await createStore(t);
  const state = failedState();
  const bootMarker = recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput({
    eventRecordId: '100',
  }));

  const observation = await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: state,
    bootMarker,
  });

  assert.deepEqual(observation, {
    schemaVersion: 1,
    recordType: 'BOOT_OBSERVATION',
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    failedState: state,
    failedStateDigest: recoveryModule.runtimeRecoveryStateDigest(state),
    bootMarker,
    observedAt: '2026-07-30T00:05:00.000Z',
  });
  assert.equal(Object.isFrozen(observation), true);
  assert.equal(Object.isFrozen(observation.failedState), true);
  const loaded = await store.readBootObservation({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  });
  assert.deepEqual(loaded, observation);

  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  assert.equal(
    await readFile(paths.bootObservation, 'utf8'),
    `${JSON.stringify(observation, null, 2)}\n`,
  );
  for (const directory of [root, paths.device, paths.recovery, paths.operation]) {
    assert.equal((await stat(directory)).mode & 0o777, 0o700);
  }
  assert.equal((await stat(paths.bootObservation)).mode & 0o777, 0o600);
  const observationTemporaries = await immutableTemporaryPaths(paths.bootObservation);
  assert.equal(observationTemporaries.length, 1);
  assert.equal((await stat(paths.bootObservation)).nlink, 2);
  assert.deepEqual(
    (await readdir(paths.operation)).sort(),
    [
      'boot-observation.json',
      basename(observationTemporaries[0]),
      'recovery-commit.json.lock',
    ].sort(),
  );
  assert.equal((await stat(`${paths.recoveryCommit}.lock`)).size, 0);
});

test('rejects a canonical record stored under different exact path identifiers', async (t) => {
  const { root, store } = await createStore(t);
  const otherOperationId = 'b'.repeat(32);
  const marker = recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput());
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: marker,
  });
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState({ operationId: otherOperationId }),
    bootMarker: marker,
  });
  const requestedPaths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  const otherPaths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, otherOperationId);
  await writeFile(requestedPaths.bootObservation, await readFile(otherPaths.bootObservation));

  await rejectsCode(store.readBootObservation({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('rejects ticket and attempt records whose IDs do not match their exact requested paths', async (t) => {
  const f = await createConsumedFixture(t, 0xac);
  const requestedTicketId = `rct_${'d'.repeat(64)}`;
  const requestedPaths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    requestedTicketId,
  );
  await writeFile(requestedPaths.ticket, `${JSON.stringify(f.ticket, null, 2)}\n`, { mode: 0o600 });
  await writeFile(
    requestedPaths.authorizedDeleteAttempt,
    `${JSON.stringify(f.attempt, null, 2)}\n`,
    { mode: 0o600 },
  );

  await rejectsCode(f.store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: requestedTicketId,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(f.store.readAuthorizedDeleteAttempt({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: requestedTicketId,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(f.store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: requestedTicketId,
    failedState: f.source.failedState,
    proof: f.proof,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('rejects a boot observation earlier than the failed-state timestamp', async (t) => {
  const { root, store } = await createStore(t, {
    now: () => new Date('2026-07-29T23:59:59.999Z'),
  });

  await rejectsCode(store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  }), 'RUNTIME_STATE_UNSUPPORTED');
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  await assert.rejects(stat(paths.bootObservation), { code: 'ENOENT' });
});

test('issues one exact immutable ten-minute ticket bound to observation, state, and proof', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const { root, store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.from('ab'.repeat(32), 'hex'),
  });
  const proofSource = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(proofSource);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: proofSource.failedState,
    bootMarker: proofSource.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');

  assert.equal(typeof store.createTicket, 'function');
  const authorizationParent = genesisAuthorizationParent(proofSource.failedState);
  const ticket = await store.createTicket(ticketInput(
    proofSource,
    proof,
    authorizationParent,
  ));

  assert.deepEqual(ticket, {
    schemaVersion: 2,
    recordType: 'RECOVERY_TICKET',
    ticketId: `rct_${'ab'.repeat(32)}`,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    authorizationParent,
    authorizationParentDigest:
      recoveryModule.runtimeRecoveryAuthorizationParentDigest(authorizationParent),
    failedState: proofSource.failedState,
    failedStateDigest: recoveryModule.runtimeRecoveryStateDigest(proofSource.failedState),
    proof,
    proofDigest: recoveryModule.runtimeRecoveryProofDigest(proof),
    inspectedAt: '2026-07-30T00:06:00.000Z',
    expiresAt: '2026-07-30T00:16:00.000Z',
  });
  assert.equal(Object.isFrozen(ticket), true);
  assert.equal(Object.isFrozen(ticket.proof), true);
  assert.deepEqual(await store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
  }), ticket);

  const paths = pathModule.runtimeDeviceRecoveryPaths(
    root,
    DEVICE_ID,
    OPERATION_ID,
    ticket.ticketId,
  );
  assert.equal((await stat(paths.tickets)).mode & 0o777, 0o700);
  assert.equal((await stat(paths.ticket)).mode & 0o777, 0o600);
  assert.equal(await readFile(paths.ticket, 'utf8'), `${JSON.stringify(ticket, null, 2)}\n`);
  const successor = pathModule.runtimeRecoveryAuthorizationSuccessorPath(
    root,
    DEVICE_ID,
    OPERATION_ID,
    ticket.authorizationParentDigest,
  );
  assert.equal((await stat(paths.authorizationSuccessors)).mode & 0o777, 0o700);
  assert.equal((await stat(successor)).mode & 0o777, 0o600);
  assert.equal((await stat(successor)).nlink, 2);
  assert.equal((await immutableTemporaryPaths(successor)).length, 1);
});

test('rejects a ticket timestamp earlier than its failed-state timestamp', async (t) => {
  const f = await createConsumedFixture(t, 0xad);
  assert.throws(
    () => recoveryModule.runtimeRecoveryTicketDigest({
      ...f.ticket,
      inspectedAt: '2026-07-29T23:59:59.999Z',
      expiresAt: '2026-07-30T00:09:59.999Z',
    }),
    (error) => error?.code === 'RUNTIME_INPUT_INVALID'
      && error.message === 'RUNTIME_INPUT_INVALID',
  );
});

test('revalidates failed-state to observation to ticket timestamp ordering on read', async (t) => {
  const f = await createConsumedFixture(t, 0xae);
  const paths = pathModule.runtimeDeviceRecoveryPaths(f.root, DEVICE_ID, OPERATION_ID);
  const observation = JSON.parse(await readFile(paths.bootObservation, 'utf8'));
  await writeFile(
    paths.bootObservation,
    `${JSON.stringify({
      ...observation,
      observedAt: '2026-07-30T00:06:00.001Z',
    }, null, 2)}\n`,
  );

  await rejectsCode(f.store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('refuses an ALREADY_ABSENT ticket without its exact prior authorized attempt', async (t) => {
  const { store } = await createStore(t, {
    now: () => new Date('2026-07-30T00:06:00.000Z'),
    randomBytes: () => Buffer.alloc(32, 0xaa),
  });
  const source = proofInput({
    classification: 'ALREADY_ABSENT',
    priorAuthorizedAttempt: {
      ticketId: `rct_${'f'.repeat(64)}`,
      attemptDigest: 'F'.repeat(64),
    },
    stagingDirectory: directoryFacts('2'.repeat(32), []),
    operationDirectory: null,
  });
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });

  await rejectsCode(store.createTicket(ticketInput(
    source,
    proof,
    recoveryModule.createRuntimeRecoveryAuthorizationParent({
      schemaVersion: 1,
      kind: 'AUTHORIZED_ATTEMPT',
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      failedStateDigest: recoveryModule.runtimeRecoveryStateDigest(source.failedState),
      ticketId: `rct_${'f'.repeat(64)}`,
      ticketDigest: 'E'.repeat(64),
      attemptDigest: 'F'.repeat(64),
    }),
  )), 'RUNTIME_STATE_UNSUPPORTED');
});

test('rejects self-satisfying and target-mismatched prior-attempt provenance', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const entropyBytes = [0xca];
  let entropyIndex = 0;
  const { store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, entropyBytes[entropyIndex++]),
  });
  const priorSource = proofInput({ targetBindingDigest: 'D'.repeat(64) });
  const priorProof = recoveryModule.createRuntimeRecoveryProof(priorSource);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: priorSource.failedState,
    bootMarker: priorSource.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const priorTicket = await store.createTicket(ticketInput(priorSource, priorProof));
  now = new Date('2026-07-30T00:07:00.000Z');
  const priorAttempt = await store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: priorTicket.ticketId,
    failedState: priorSource.failedState,
    proof: priorProof,
  });
  const currentSource = proofInput({
    classification: 'ALREADY_ABSENT',
    priorAuthorizedAttempt: {
      ticketId: priorTicket.ticketId,
      attemptDigest: recoveryModule.runtimeRecoveryAuthorizedAttemptDigest(priorAttempt),
    },
    stagingDirectory: directoryFacts('2'.repeat(32), []),
    operationDirectory: null,
  });
  const currentProof = recoveryModule.createRuntimeRecoveryProof(currentSource);
  now = new Date('2026-07-30T00:08:00.000Z');

  for (let attempt = 0; attempt < 2; attempt += 1) {
    await rejectsCode(store.createTicket(ticketInput(
      currentSource,
      currentProof,
      authorizedAttemptAuthorizationParent(priorTicket, priorAttempt),
    )), 'RUNTIME_STATE_UNSUPPORTED');
    assert.equal(entropyIndex, 1);
  }
});

test('revalidates exact prior-attempt provenance whenever an ALREADY_ABSENT ticket is used', async (t) => {
  const f = await createAlreadyAbsentFixture(t, { consumeCurrent: false });
  assert.notEqual(f.ticket.ticketId, f.priorTicket.ticketId);
  const priorPaths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.priorTicket.ticketId,
  );
  await writeFile(
    priorPaths.authorizedDeleteAttempt,
    `${JSON.stringify({
      ...f.priorAttempt,
      authorizedAt: '2026-07-30T00:07:00.001Z',
    }, null, 2)}\n`,
  );

  await rejectsCode(f.store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(f.store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
    failedState: f.source.failedState,
    proof: f.proof,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('durably consumes one exact ticket into a distinct attempt and never redispatches it', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const { root, store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.from('cd'.repeat(32), 'hex'),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const ticket = await store.createTicket(ticketInput(source, proof));
  now = new Date('2026-07-30T00:15:59.999Z');

  assert.equal(typeof store.consumeTicket, 'function');
  const attempt = await store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: source.failedState,
    proof,
  });

  assert.deepEqual(attempt, {
    schemaVersion: 1,
    recordType: 'AUTHORIZED_DELETE_ATTEMPT',
    ticketId: ticket.ticketId,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketDigest: recoveryModule.runtimeRecoveryTicketDigest(ticket),
    failedStateDigest: recoveryModule.runtimeRecoveryStateDigest(source.failedState),
    proofDigest: recoveryModule.runtimeRecoveryProofDigest(proof),
    classification: 'EMPTY_PRE_TRANSACTION',
    authorizedAt: '2026-07-30T00:15:59.999Z',
  });
  assert.deepEqual(await store.readAuthorizedDeleteAttempt({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
  }), attempt);

  const paths = pathModule.runtimeDeviceRecoveryPaths(
    root,
    DEVICE_ID,
    OPERATION_ID,
    ticket.ticketId,
  );
  assert.equal((await stat(paths.ticket)).nlink, 2);
  assert.equal((await immutableTemporaryPaths(paths.ticket)).length, 1);
  assert.equal((await stat(paths.authorizedDeleteAttempt)).nlink, 2);
  assert.equal((await immutableTemporaryPaths(paths.authorizedDeleteAttempt)).length, 1);
  assert.equal((await stat(paths.authorizedDeleteAttempt)).mode & 0o777, 0o600);
  assert.equal(
    await readFile(paths.authorizedDeleteAttempt, 'utf8'),
    `${JSON.stringify(attempt, null, 2)}\n`,
  );
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: source.failedState,
    proof,
  }), 'RUNTIME_ALREADY_RUNNING');
});

test('reuses one durable successor ticket for sequential same-parent creation', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  let entropyCalls = 0;
  const { root, store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => {
      entropyCalls += 1;
      return Buffer.alloc(32, 0xd1);
    },
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  const authorizationParent = genesisAuthorizationParent(source.failedState);
  const input = ticketInput(source, proof, authorizationParent);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });

  now = new Date('2026-07-30T00:06:00.000Z');
  const ticketA = await store.createTicket(input);
  now = new Date('2026-07-30T00:06:01.000Z');
  const ticketB = await store.createTicket(input);
  const resolved = await store.resolveAuthorizationSuccessor(authorizationParent);

  assert.deepEqual(ticketB, ticketA);
  assert.deepEqual(resolved, ticketA);
  assert.equal(entropyCalls, 1);
  assert.equal(ticketA.schemaVersion, 2);
  assert.deepEqual(ticketA.authorizationParent, authorizationParent);
  assert.equal(
    ticketA.authorizationParentDigest,
    recoveryModule.runtimeRecoveryAuthorizationParentDigest(authorizationParent),
  );
  const successor = pathModule.runtimeRecoveryAuthorizationSuccessorPath(
    root,
    DEVICE_ID,
    OPERATION_ID,
    ticketA.authorizationParentDigest,
  );
  assert.equal((await stat(successor)).nlink, 2);
  assert.equal((await immutableTemporaryPaths(successor)).length, 1);
  assert.equal((await immutableTemporaryPaths(
    pathModule.runtimeDeviceRecoveryPaths(
      root,
      DEVICE_ID,
      OPERATION_ID,
      ticketA.ticketId,
    ).ticket,
  )).length, 1);
  assert.equal(
    recoveryModule.runtimeRecoveryTicketDigest(ticketA),
    createHash('sha256')
      .update('AGENT_ROAD_RUNTIME_RECOVERY_TICKET_V2\0', 'utf8')
      .update(JSON.stringify(ticketA), 'utf8')
      .digest('hex')
      .toUpperCase(),
  );
});

test('returns the occupied lineage ticket after proof drift, consumption, or expiry', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  let entropyCalls = 0;
  const { store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => {
      entropyCalls += 1;
      return Buffer.alloc(32, 0xd5);
    },
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  const parent = genesisAuthorizationParent(source.failedState);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const ticket = await store.createTicket(ticketInput(source, proof, parent));

  const driftedSource = proofInput({ targetBindingDigest: 'D'.repeat(64) });
  const driftedProof = recoveryModule.createRuntimeRecoveryProof(driftedSource);
  assert.deepEqual(
    await store.createTicket(ticketInput(driftedSource, driftedProof, parent)),
    ticket,
  );

  now = new Date('2026-07-30T00:07:00.000Z');
  await store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: source.failedState,
    proof,
  });
  assert.deepEqual(await store.createTicket(ticketInput(source, proof, parent)), ticket);

  now = new Date(ticket.expiresAt);
  assert.deepEqual(await store.createTicket(ticketInput(source, proof, parent)), ticket);
  assert.equal(entropyCalls, 1);
});

test('rejects any legacy ticket or attempt namespace before V2 authorization', async (t) => {
  for (const legacyName of ['tickets', 'authorized-delete-attempts']) {
    await t.test(`${legacyName} exists even when empty`, async (st) => {
      let entropyCalls = 0;
      const { root, store } = await createStore(st, {
        now: () => new Date('2026-07-30T00:06:00.000Z'),
        randomBytes: () => {
          entropyCalls += 1;
          return Buffer.alloc(32, 0xd6);
        },
      });
      const source = proofInput();
      const proof = recoveryModule.createRuntimeRecoveryProof(source);
      const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
      await store.createBootObservation({
        deviceId: DEVICE_ID,
        failedState: source.failedState,
        bootMarker: source.beforeBootMarker,
      });
      await mkdir(join(paths.operation, legacyName), { mode: 0o700 });

      await rejectsCode(
        store.createTicket(ticketInput(source, proof)),
        'RUNTIME_STATE_UNSUPPORTED',
      );
      assert.equal(entropyCalls, 0);
      await assert.rejects(stat(paths.authorizationSuccessors), { code: 'ENOENT' });
    });
  }
});

test('gives an existing expired-child slot precedence over clock rollback on consume', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  let entropy = 0xd7;
  const { store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, entropy++),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const ticketA = await store.createTicket(ticketInput(source, proof));
  const expiredParent = expiredTicketAuthorizationParent(ticketA);
  now = new Date(ticketA.expiresAt);
  const ticketB = await store.createTicket(ticketInput(source, proof, expiredParent));

  now = new Date('2026-07-30T00:05:00.000Z');
  assert.deepEqual(await store.createTicket(ticketInput(source, proof, expiredParent)), ticketB);
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticketA.ticketId,
    failedState: source.failedState,
    proof,
  }), 'RUNTIME_INPUT_INVALID');
});

test('advances only through exact authorized parents and old ancestors resolve their direct child', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  let entropyCalls = 0;
  const { store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => {
      entropyCalls += 1;
      return Buffer.alloc(32, 0xe0 + entropyCalls);
    },
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const ticketA = await store.createTicket(ticketInput(source, proof));
  now = new Date('2026-07-30T00:07:00.000Z');
  const attemptA = await store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticketA.ticketId,
    failedState: source.failedState,
    proof,
  });
  const parentA = authorizedAttemptAuthorizationParent(ticketA, attemptA);
  now = new Date('2026-07-30T00:08:00.000Z');
  const ticketB = await store.createTicket(ticketInput(source, proof, parentA));
  assert.deepEqual(await store.createTicket(ticketInput(source, proof, parentA)), ticketB);
  now = new Date('2026-07-30T00:09:00.000Z');
  const attemptB = await store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticketB.ticketId,
    failedState: source.failedState,
    proof,
  });
  const parentB = authorizedAttemptAuthorizationParent(ticketB, attemptB);
  now = new Date('2026-07-30T00:10:00.000Z');
  const ticketC = await store.createTicket(ticketInput(source, proof, parentB));

  assert.deepEqual(ticketB.authorizationParent, parentA);
  assert.deepEqual(ticketC.authorizationParent, parentB);
  assert.deepEqual(await store.createTicket(ticketInput(source, proof, parentA)), ticketB);
  assert.equal(entropyCalls, 3);
});

test('carries original EMPTY deletion provenance across repeated already-absent parents', async (t) => {
  const f = await createAlreadyAbsentFixture(t);
  const source = proofInput({
    classification: 'ALREADY_ABSENT',
    priorAuthorizedAttempt: {
      ticketId: f.priorTicket.ticketId,
      attemptDigest: recoveryModule.runtimeRecoveryAuthorizedAttemptDigest(f.priorAttempt),
    },
    stagingDirectory: directoryFacts('2'.repeat(32), []),
    operationDirectory: null,
  });
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  f.setNow('2026-07-30T00:10:00.000Z');
  const ticketC = await f.store.createTicket(ticketInput(
    source,
    proof,
    authorizedAttemptAuthorizationParent(f.ticket, f.attempt),
  ));

  assert.deepEqual(ticketC.proof.priorAuthorizedAttempt, {
    ticketId: f.priorTicket.ticketId,
    attemptDigest: recoveryModule.runtimeRecoveryAuthorizedAttemptDigest(f.priorAttempt),
  });
  assert.equal(ticketC.authorizationParent.ticketId, f.ticket.ticketId);
});

test('carries original EMPTY deletion provenance through an expired unconsumed already-absent parent', async (t) => {
  const f = await createAlreadyAbsentFixture(t, { consumeCurrent: false });
  f.setNow(f.ticket.expiresAt);

  const ticketC = await f.store.createTicket(ticketInput(
    f.source,
    f.proof,
    expiredTicketAuthorizationParent(f.ticket),
  ));

  assert.deepEqual(ticketC.proof.priorAuthorizedAttempt, {
    ticketId: f.priorTicket.ticketId,
    attemptDigest: recoveryModule.runtimeRecoveryAuthorizedAttemptDigest(f.priorAttempt),
  });
  assert.equal(ticketC.authorizationParent.kind, 'EXPIRED_TICKET');
  assert.equal(ticketC.authorizationParent.ticketId, f.ticket.ticketId);
});

test('rejects a forced V2 sibling ticket that has no exact successor authority', async (t) => {
  const f = await createTicketFixture(t, 0xe5);
  const sibling = {
    ...f.ticket,
    ticketId: `rct_${'f'.repeat(64)}`,
  };
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    sibling.ticketId,
  );
  await writeFile(paths.ticket, `${JSON.stringify(sibling, null, 2)}\n`, { mode: 0o600 });

  await rejectsCode(f.store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: sibling.ticketId,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.deepEqual(await f.store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
  }), f.ticket);
});

test('publishes the durable successor before its exact ticket and repairs only clean absence', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  let entropyCalls = 0;
  const { root, store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => {
      entropyCalls += 1;
      return Buffer.alloc(32, 0xd2);
    },
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  const parent = genesisAuthorizationParent(source.failedState);
  const parentDigest = recoveryModule.runtimeRecoveryAuthorizationParentDigest(parent);
  const successor = pathModule.runtimeRecoveryAuthorizationSuccessorPath(
    root,
    DEVICE_ID,
    OPERATION_ID,
    parentDigest,
  );
  const expectedTicketPath = pathModule.runtimeDeviceRecoveryPaths(
    root,
    DEVICE_ID,
    OPERATION_ID,
    `rct_${'d2'.repeat(32)}`,
  ).ticket;
  const order = [];
  let crashed = false;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterImmutablePublicationValidation') return;
    if (context.path === successor) order.push('successor');
    if (context.path === expectedTicketPath) order.push('ticket');
    if (context.path === successor && !crashed) {
      crashed = true;
      throw new Error('SIMULATED_AFTER_SUCCESSOR');
    }
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');

  await rejectsCode(store.createTicket(ticketInput(source, proof, parent)), 'RUNTIME_INTERNAL_ERROR');
  await assert.rejects(stat(expectedTicketPath), { code: 'ENOENT' });
  assert.deepEqual(order, ['successor']);
  delete globalThis[RECOVERY_TEST_HOOK];

  now = new Date('2026-07-30T00:16:00.000Z');
  const repaired = await store.resolveAuthorizationSuccessor(parent);
  assert.equal(repaired.ticketId, `rct_${'d2'.repeat(32)}`);
  assert.equal(entropyCalls, 1);
  assert.equal((await stat(successor)).nlink, 2);
  assert.equal((await stat(expectedTicketPath)).nlink, 2);
  const [repairedTemporaryPath] = await immutableTemporaryPaths(expectedTicketPath);
  assert.equal(
    basename(repairedTemporaryPath),
    `${basename(expectedTicketPath)}.${deterministicPublicationIdForDigest(
      recoveryModule.runtimeRecoveryTicketDigest(repaired),
    )}.tmp`,
  );
});

test('resolver never mints authority if its verified successor disappears before repair', async (t) => {
  let entropyCalls = 0;
  const { root, store } = await createStore(t, {
    now: () => new Date('2026-07-30T00:06:00.000Z'),
    randomBytes: () => {
      entropyCalls += 1;
      return Buffer.alloc(32, 0xd6 + entropyCalls);
    },
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  const parent = genesisAuthorizationParent(source.failedState);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  const ticket = await store.createTicket(ticketInput(source, proof, parent));
  const successorPath = pathModule.runtimeRecoveryAuthorizationSuccessorPath(
    root,
    DEVICE_ID,
    OPERATION_ID,
    recoveryModule.runtimeRecoveryAuthorizationParentDigest(parent),
  );
  const [successorTemporaryPath] = await immutableTemporaryPaths(successorPath);
  let removed = false;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (
      event === 'afterAuthorizationSuccessorResolved'
      && context.path === successorPath
      && !removed
    ) {
      removed = true;
      await rm(successorPath);
      await rm(successorTemporaryPath);
    }
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  await rejectsCode(
    store.resolveAuthorizationSuccessor(parent),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  assert.equal(entropyCalls, 1);
  assert.equal(ticket.ticketId, `rct_${'d7'.repeat(32)}`);
});

test('resolver fails closed on direct successor and ticket corruption', async (t) => {
  await t.test('successor pre-link residue', async (st) => {
    const { root, store } = await createStore(st);
    const source = proofInput();
    const parent = genesisAuthorizationParent(source.failedState);
    const successorPath = pathModule.runtimeRecoveryAuthorizationSuccessorPath(
      root,
      DEVICE_ID,
      OPERATION_ID,
      recoveryModule.runtimeRecoveryAuthorizationParentDigest(parent),
    );
    await store.createBootObservation({
      deviceId: DEVICE_ID,
      failedState: source.failedState,
      bootMarker: source.beforeBootMarker,
    });
    await mkdir(dirname(successorPath), { recursive: true, mode: 0o700 });
    await writeFile(
      `${successorPath}.00000000-0000-4000-8000-000000000000.tmp`,
      '{}\n',
      { mode: 0o600 },
    );
    await rejectsCode(
      store.resolveAuthorizationSuccessor(parent),
      'RUNTIME_STATE_UNSUPPORTED',
    );
  });

  for (const endpoint of ['successor', 'ticket']) {
    for (const replacement of ['corrupt', 'symlink']) {
      await t.test(`${replacement} ${endpoint}`, async (st) => {
        const f = await createTicketFixture(st, 0xd8);
        const paths = pathModule.runtimeDeviceRecoveryPaths(
          f.root,
          DEVICE_ID,
          OPERATION_ID,
          f.ticket.ticketId,
        );
        const targetPath = endpoint === 'successor'
          ? pathModule.runtimeRecoveryAuthorizationSuccessorPath(
              f.root,
              DEVICE_ID,
              OPERATION_ID,
              f.ticket.authorizationParentDigest,
            )
          : paths.ticket;
        if (replacement === 'corrupt') {
          for (const path of [targetPath, ...(await immutableTemporaryPaths(targetPath))]) {
            await rm(path);
          }
          await writeFile(targetPath, '{}\n', { mode: 0o600 });
        } else {
          await replaceWithUnsafeSymlink(targetPath);
        }
        await rejectsCode(
          f.store.resolveAuthorizationSuccessor(f.ticket.authorizationParent),
          'RUNTIME_STATE_UNSUPPORTED',
        );
      });
    }
  }
});

test('fails closed on successor residue and ticket-without-successor state', async (t) => {
  await t.test('pre-link successor residue', async (st) => {
    const { root, store } = await createStore(st, {
      now: () => new Date('2026-07-30T00:06:00.000Z'),
      randomBytes: () => Buffer.alloc(32, 0xd3),
    });
    const source = proofInput();
    const proof = recoveryModule.createRuntimeRecoveryProof(source);
    const parent = genesisAuthorizationParent(source.failedState);
    const successor = pathModule.runtimeRecoveryAuthorizationSuccessorPath(
      root,
      DEVICE_ID,
      OPERATION_ID,
      recoveryModule.runtimeRecoveryAuthorizationParentDigest(parent),
    );
    await store.createBootObservation({
      deviceId: DEVICE_ID,
      failedState: source.failedState,
      bootMarker: source.beforeBootMarker,
    });
    await mkdir(dirname(successor), { recursive: true, mode: 0o700 });
    await writeFile(
      `${successor}.00000000-0000-4000-8000-000000000000.tmp`,
      '{}\n',
      { mode: 0o600 },
    );
    await rejectsCode(
      store.createTicket(ticketInput(source, proof, parent)),
      'RUNTIME_STATE_UNSUPPORTED',
    );
  });

  await t.test('exact ticket remains without its successor', async (st) => {
    const f = await createTicketFixture(st, 0xd4);
    const successor = pathModule.runtimeRecoveryAuthorizationSuccessorPath(
      f.root,
      DEVICE_ID,
      OPERATION_ID,
      f.ticket.authorizationParentDigest,
    );
    for (const path of [successor, ...(await immutableTemporaryPaths(successor))]) {
      await rm(path);
    }
    await rejectsCode(
      f.store.createTicket(ticketInput(f.source, f.proof, f.ticket.authorizationParent)),
      'RUNTIME_STATE_UNSUPPORTED',
    );
    await assert.rejects(stat(successor), { code: 'ENOENT' });
  });
});

test('never creates recovery records through a replaced or symlinked ancestor', async (t) => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-runtime-recovery-')));
  const anchor = join(directory, 'anchor');
  const movedAnchor = join(directory, 'moved-anchor');
  const outside = join(directory, 'outside');
  await mkdir(anchor, { mode: 0o700 });
  await mkdir(outside, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new recoveryModule.RuntimeRecoveryStore(join(anchor, 'runtime', 'devices'), {
    now: () => new Date('2026-07-30T00:05:00.000Z'),
  });
  await rename(anchor, movedAnchor);
  await symlink(outside, anchor);

  await rejectsCode(store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await assert.rejects(stat(join(outside, 'runtime')), { code: 'ENOENT' });
});

test('rejects symlinked, hardlinked, and broadly readable recovery record endpoints', async (t) => {
  async function unsafeCase(mutate) {
    const { root, store } = await createStore(t);
    const marker = recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput());
    await store.createBootObservation({
      deviceId: DEVICE_ID,
      failedState: failedState(),
      bootMarker: marker,
    });
    const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
    await mutate(paths);
    await rejectsCode(store.readBootObservation({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
    }), 'RUNTIME_STATE_UNSUPPORTED');
  }

  await unsafeCase(async (paths) => {
    await link(paths.bootObservation, `${paths.bootObservation}.hardlink`);
  });
  await unsafeCase(async (paths) => {
    const target = `${paths.bootObservation}.target`;
    await rename(paths.bootObservation, target);
    await symlink(target, paths.bootObservation);
  });
  await unsafeCase(async (paths) => {
    await chmod(paths.bootObservation, 0o644);
  });
});

test('rejects Darwin extended ACLs on recovery ancestors and records', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  for (const endpoint of ['recovery', 'record']) {
    await t.test(endpoint, async (t) => {
      const { root, store } = await createStore(t);
      await store.createBootObservation({
        deviceId: DEVICE_ID,
        failedState: failedState(),
        bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
      });
      const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
      await addExtendedAcl(t, endpoint === 'recovery' ? paths.recovery : paths.bootObservation);

      await rejectsCode(store.readBootObservation({
        deviceId: DEVICE_ID,
        operationId: OPERATION_ID,
      }), 'RUNTIME_STATE_UNSUPPORTED');
    });
  }
});

test('rejects a recovery record replaced after its metadata probe', async (t) => {
  const { root, store } = await createStore(t);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  });
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  const content = await readFile(paths.bootObservation, 'utf8');
  let replaced = false;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterRecordAclCheck' || replaced || context.path !== paths.bootObservation) {
      return;
    }
    replaced = true;
    await rename(paths.bootObservation, `${paths.bootObservation}.moved`);
    await writeFile(paths.bootObservation, content, { mode: 0o600 });
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  await rejectsCode(store.readBootObservation({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(replaced, true);
});

test('rejects an operation directory replaced after layout validation', async (t) => {
  const { directory, root, store } = await createStore(t);
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  const movedOperation = join(directory, 'moved-operation');
  const outside = join(directory, 'outside');
  await mkdir(outside, { mode: 0o700 });
  let replaced = false;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterRecoveryLayoutCheck' || replaced || context.path !== paths.operation) {
      return;
    }
    replaced = true;
    await rename(paths.operation, movedOperation);
    await symlink(outside, paths.operation);
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  await rejectsCode(store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(replaced, true);
  await assert.rejects(stat(join(outside, 'boot-observation.json')), { code: 'ENOENT' });
});

test('retains the exact published temporary link and never enters path-unlink cleanup', async (t) => {
  const { root, store } = await createStore(t);
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  let cleanupHookCalled = false;
  globalThis[RECOVERY_TEST_HOOK] = async (event) => {
    if (event !== 'beforePublishedTemporaryCleanup') return;
    cleanupHookCalled = true;
    throw new Error('PATH_UNLINK_CLEANUP_MUST_NOT_RUN');
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  const observation = await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  });
  const temporaries = await immutableTemporaryPaths(paths.bootObservation);
  assert.equal(cleanupHookCalled, false);
  assert.equal(temporaries.length, 1);
  const finalStats = await stat(paths.bootObservation);
  const temporaryStats = await stat(temporaries[0]);
  assert.equal(finalStats.nlink, 2);
  assert.equal(temporaryStats.nlink, 2);
  assert.equal(finalStats.dev, temporaryStats.dev);
  assert.equal(finalStats.ino, temporaryStats.ino);
  assert.deepEqual(await store.readBootObservation({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), observation);
});

test('retains an unpublished immutable temporary and fails closed on the residue', async (t) => {
  const { root, store } = await createStore(t);
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  let unpublishedTemporaryPath;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterTemporarySyncBeforePublish') return;
    unpublishedTemporaryPath = context.temporaryPath;
    throw new Error('SIMULATED_PRE_PUBLICATION_CRASH');
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  await rejectsCode(store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  }), 'RUNTIME_INTERNAL_ERROR');
  await assert.rejects(stat(paths.bootObservation), { code: 'ENOENT' });
  assert.equal((await stat(unpublishedTemporaryPath)).nlink, 1);
  await rejectsCode(store.readBootObservation({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('accepts legacy final-only records but rejects any separate related temporary', async (t) => {
  const { root, store } = await createStore(t);
  const observation = await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  });
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  const [retainedTemporaryPath] = await immutableTemporaryPaths(paths.bootObservation);
  await rm(retainedTemporaryPath);
  assert.equal((await stat(paths.bootObservation)).nlink, 1);
  assert.deepEqual(await store.readBootObservation({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), observation);

  const separateTemporaryPath = `${paths.bootObservation}.00000000-0000-4000-8000-000000000000.tmp`;
  await writeFile(separateTemporaryPath, await readFile(paths.bootObservation), { mode: 0o600 });
  await rejectsCode(store.readBootObservation({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal((await stat(paths.bootObservation)).nlink, 1);
  assert.equal((await stat(separateTemporaryPath)).nlink, 1);
});

test('rejects wrong-case final aliases and related immutable residue', async (t) => {
  await t.test('wrong-case V2 final alias', async (st) => {
    const f = await createTicketFixture(st, 0xa1);
    const paths = pathModule.runtimeDeviceRecoveryPaths(
      f.root,
      DEVICE_ID,
      OPERATION_ID,
      f.ticket.ticketId,
    );
    const aliasPath = join(dirname(paths.ticket), basename(paths.ticket).toUpperCase());
    await rename(paths.ticket, aliasPath);
    try {
      await stat(paths.ticket);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        st.skip('filesystem is case-sensitive');
        return;
      }
      throw error;
    }

    await rejectsCode(f.store.readTicket({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      ticketId: f.ticket.ticketId,
    }), 'RUNTIME_STATE_UNSUPPORTED');
  });

  await t.test('wrong-case related temporary beside a legacy final', async (st) => {
    const { root, store } = await createStore(st);
    const observation = await store.createBootObservation({
      deviceId: DEVICE_ID,
      failedState: failedState(),
      bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
    });
    const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
    const [retainedTemporaryPath] = await immutableTemporaryPaths(paths.bootObservation);
    await rm(retainedTemporaryPath);
    const wrongCaseTemporaryPath = join(
      dirname(paths.bootObservation),
      `${basename(paths.bootObservation).toUpperCase()}.00000000-0000-4000-8000-000000000000.tmp`,
    );
    await writeFile(
      wrongCaseTemporaryPath,
      `${JSON.stringify(observation, null, 2)}\n`,
      { mode: 0o600 },
    );

    await rejectsCode(store.readBootObservation({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
    }), 'RUNTIME_STATE_UNSUPPORTED');
  });
});

test('requires the retained witness pair for every V2 authorization record', async (t) => {
  for (const [endpoint, readRecord] of [
    ['successor', (f) => f.store.resolveAuthorizationSuccessor(f.ticket.authorizationParent)],
    ['ticket', (f) => f.store.readTicket({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      ticketId: f.ticket.ticketId,
    })],
    ['attempt', (f) => f.store.readAuthorizedDeleteAttempt({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      ticketId: f.ticket.ticketId,
    })],
  ]) {
    await t.test(endpoint, async (st) => {
      const f = await createConsumedFixture(st, 0xb0 + endpoint.length);
      const paths = pathModule.runtimeDeviceRecoveryPaths(
        f.root,
        DEVICE_ID,
        OPERATION_ID,
        f.ticket.ticketId,
      );
      const recordPath = endpoint === 'successor'
        ? pathModule.runtimeRecoveryAuthorizationSuccessorPath(
            f.root,
            DEVICE_ID,
            OPERATION_ID,
            f.ticket.authorizationParentDigest,
          )
        : endpoint === 'ticket'
          ? paths.ticket
          : paths.authorizedDeleteAttempt;
      const [temporaryPath] = await immutableTemporaryPaths(recordPath);
      await rm(temporaryPath);
      assert.equal((await stat(recordPath)).nlink, 1);

      await rejectsCode(readRecord(f), 'RUNTIME_STATE_UNSUPPORTED');
    });
  }
});

test('rejects an immutable publication temporary replaced before the no-replace link', async (t) => {
  const { root, store } = await createStore(t);
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  let replaced = false;
  let replacementTemporaryPath;
  const replacementContent = Buffer.from('replacement-must-survive');
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterTemporarySyncBeforePublish' || replaced) return;
    replaced = true;
    replacementTemporaryPath = context.temporaryPath;
    await rename(context.temporaryPath, `${context.temporaryPath}.moved`);
    await writeFile(context.temporaryPath, replacementContent, { mode: 0o600 });
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  await rejectsCode(store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(replaced, true);
  await assert.rejects(stat(paths.bootObservation), { code: 'ENOENT' });
  assert.deepEqual(await readFile(replacementTemporaryPath), replacementContent);
});

test('revalidates an immutable final endpoint immediately before returning success', async (t) => {
  const { root, store } = await createStore(t);
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  let replaced = false;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterImmutablePublicationValidation' || replaced) return;
    replaced = true;
    const content = await readFile(context.path);
    await rename(context.path, `${context.path}.moved`);
    await writeFile(context.path, content, { mode: 0o600 });
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  await rejectsCode(store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(replaced, true);
  assert.equal((await stat(paths.bootObservation)).mode & 0o777, 0o600);
});

test('fails closed on pre-link attempt residue and retains exact durable temp/final pairs', async (t) => {
  async function setupConsumed(t, entropyByte) {
    let now = new Date('2026-07-30T00:05:00.000Z');
    const fixture = await createStore(t, {
      now: () => new Date(now),
      randomBytes: () => Buffer.alloc(32, entropyByte),
    });
    const source = proofInput();
    const proof = recoveryModule.createRuntimeRecoveryProof(source);
    await fixture.store.createBootObservation({
      deviceId: DEVICE_ID,
      failedState: source.failedState,
      bootMarker: source.beforeBootMarker,
    });
    now = new Date('2026-07-30T00:06:00.000Z');
    const ticket = await fixture.store.createTicket(ticketInput(source, proof));
    now = new Date('2026-07-30T00:07:00.000Z');
    const attempt = await fixture.store.consumeTicket({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      ticketId: ticket.ticketId,
      failedState: source.failedState,
      proof,
    });
    const paths = pathModule.runtimeDeviceRecoveryPaths(
      fixture.root,
      DEVICE_ID,
      OPERATION_ID,
      ticket.ticketId,
    );
    return { ...fixture, source, proof, ticket, attempt, paths };
  }

  await t.test('valid pre-link temp without final', async (t) => {
    const f = await setupConsumed(t, 0x11);
    const [temporaryPath] = await immutableTemporaryPaths(f.paths.authorizedDeleteAttempt);
    await rm(f.paths.authorizedDeleteAttempt);

    await rejectsCode(f.store.consumeTicket({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      ticketId: f.ticket.ticketId,
      failedState: f.source.failedState,
      proof: f.proof,
    }), 'RUNTIME_STATE_UNSUPPORTED');
    await assert.rejects(stat(f.paths.authorizedDeleteAttempt), { code: 'ENOENT' });
    assert.equal((await stat(temporaryPath)).nlink, 1);
  });

  await t.test('same-inode durable temp and final', async (t) => {
    const f = await setupConsumed(t, 0x22);
    const [temporaryPath] = await immutableTemporaryPaths(f.paths.authorizedDeleteAttempt);
    assert.equal((await stat(f.paths.authorizedDeleteAttempt)).nlink, 2);

    await rejectsCode(f.store.consumeTicket({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      ticketId: f.ticket.ticketId,
      failedState: f.source.failedState,
      proof: f.proof,
    }), 'RUNTIME_ALREADY_RUNNING');
    assert.equal((await stat(f.paths.authorizedDeleteAttempt)).nlink, 2);
    assert.equal((await stat(temporaryPath)).nlink, 2);
  });
});

test('rechecks legacy authorization namespaces immediately before attempt publication', async (t) => {
  const f = await createTicketFixture(t, 0xc1);
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.ticket.ticketId,
  );
  let injected = false;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (
      event !== 'afterTemporarySyncBeforePublish'
      || context.path !== paths.authorizedDeleteAttempt
      || injected
    ) return;
    injected = true;
    await mkdir(paths.legacyTickets, { mode: 0o700 });
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  await rejectsCode(f.store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
    failedState: f.source.failedState,
    proof: f.proof,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(injected, true);
  await assert.rejects(stat(paths.authorizedDeleteAttempt), { code: 'ENOENT' });
  assert.equal((await immutableTemporaryPaths(paths.authorizedDeleteAttempt)).length, 1);
});

test('publishes one deterministic commit and verifies the exact attempt and two state digests', async (t) => {
  const f = await createConsumedFixture(t, 0x44);
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:08:00.000Z' });
  f.setNow('2026-07-30T00:08:00.000Z');

  assert.equal(typeof f.store.createRecoveryCommit, 'function');
  const commit = await f.store.createRecoveryCommit({
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
  });

  assert.deepEqual(commit, {
    schemaVersion: 1,
    recordType: 'RECOVERY_COMMIT',
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
    authorizedAttemptDigest: recoveryModule.runtimeRecoveryAuthorizedAttemptDigest(f.attempt),
    expectedFailedStateDigest: recoveryModule.runtimeRecoveryStateDigest(f.source.failedState),
    proposedRecoveredState: proposed,
    proposedRecoveredStateDigest: recoveryModule.runtimeRecoveryStateDigest(proposed),
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
    authorizedAt: f.attempt.authorizedAt,
    committedAt: '2026-07-30T00:08:00.000Z',
  });
  assert.deepEqual(await f.store.readRecoveryCommit({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), commit);
  assert.deepEqual(await recoveryModule.verifyRuntimeRecoveryCommit({
    runtimeDevicesRoot: f.root,
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
  }), commit);
  assert.deepEqual(await recoveryModule.verifyRuntimeRecoveredState({
    runtimeDevicesRoot: f.root,
    proposedRecoveredState: proposed,
  }), commit);

  const paths = pathModule.runtimeDeviceRecoveryPaths(f.root, DEVICE_ID, OPERATION_ID);
  assert.equal((await stat(paths.recoveryCommit)).mode & 0o777, 0o600);
  assert.equal(await readFile(paths.recoveryCommit, 'utf8'), `${JSON.stringify(commit, null, 2)}\n`);
});

test('requires commit disposition to match the current proof classification', async (t) => {
  await t.test('EMPTY_PRE_TRANSACTION only permits REMOVED', async (t) => {
    const f = await createConsumedFixture(t, 0x45);
    f.setNow('2026-07-30T00:08:00.000Z');
    await rejectsCode(f.store.createRecoveryCommit({
      expectedFailedState: f.source.failedState,
      proposedRecoveredState: recoveredState({ updatedAt: '2026-07-30T00:08:00.000Z' }),
      ticketId: f.ticket.ticketId,
      proofDigest: f.ticket.proofDigest,
      disposition: 'ALREADY_ABSENT',
    }), 'RUNTIME_INPUT_INVALID');
  });

  await t.test('ALREADY_ABSENT only permits ALREADY_ABSENT', async (t) => {
    const f = await createAlreadyAbsentFixture(t);
    f.setNow('2026-07-30T00:10:00.000Z');
    await rejectsCode(f.store.createRecoveryCommit({
      expectedFailedState: f.source.failedState,
      proposedRecoveredState: recoveredState({ updatedAt: '2026-07-30T00:10:00.000Z' }),
      ticketId: f.ticket.ticketId,
      proofDigest: f.ticket.proofDigest,
      disposition: 'REMOVED',
    }), 'RUNTIME_INPUT_INVALID');
  });
});

test('requires authorizedAt <= proposed.updatedAt <= committedAt', async (t) => {
  await t.test('accepts an exact proposed timestamp inside the interval', async (t) => {
    const f = await createConsumedFixture(t, 0x46);
    f.setNow('2026-07-30T00:08:00.000Z');
    const proposed = recoveredState({ updatedAt: '2026-07-30T00:07:30.000Z' });
    const commit = await f.store.createRecoveryCommit({
      expectedFailedState: f.source.failedState,
      proposedRecoveredState: proposed,
      ticketId: f.ticket.ticketId,
      proofDigest: f.ticket.proofDigest,
      disposition: 'REMOVED',
    });
    assert.equal(commit.authorizedAt, '2026-07-30T00:07:00.000Z');
    assert.equal(commit.proposedRecoveredState.updatedAt, '2026-07-30T00:07:30.000Z');
    assert.equal(commit.committedAt, '2026-07-30T00:08:00.000Z');
  });

  for (const [name, entropyByte, updatedAt] of [
    ['before authorization', 0x48, '2026-07-30T00:06:59.999Z'],
    ['after commit', 0x49, '2026-07-30T00:08:00.001Z'],
  ]) {
    await t.test(name, async (t) => {
      const f = await createConsumedFixture(t, entropyByte);
      f.setNow('2026-07-30T00:08:00.000Z');
      await rejectsCode(f.store.createRecoveryCommit({
        expectedFailedState: f.source.failedState,
        proposedRecoveredState: recoveredState({ updatedAt }),
        ticketId: f.ticket.ticketId,
        proofDigest: f.ticket.proofDigest,
        disposition: 'REMOVED',
      }), 'RUNTIME_INPUT_INVALID');
    });
  }
});

test('revalidates persisted proposed-state identity against the exact failed ticket', async (t) => {
  const f = await createConsumedFixture(t, 0x47);
  f.setNow('2026-07-30T00:08:00.000Z');
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:08:00.000Z' });
  const commit = await f.store.createRecoveryCommit({
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
  });
  const mismatched = recoveredState({
    manifestDigest: 'C'.repeat(64),
    updatedAt: commit.committedAt,
  });
  const paths = pathModule.runtimeDeviceRecoveryPaths(f.root, DEVICE_ID, OPERATION_ID);
  await writeFile(paths.recoveryCommit, `${JSON.stringify({
    ...commit,
    proposedRecoveredState: mismatched,
    proposedRecoveredStateDigest: recoveryModule.runtimeRecoveryStateDigest(mismatched),
  }, null, 2)}\n`);

  await rejectsCode(f.store.readRecoveryCommit({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('rejects a persisted classification-to-disposition mismatch on read and verification', async (t) => {
  const f = await createConsumedFixture(t, 0x4a);
  f.setNow('2026-07-30T00:08:00.000Z');
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:08:00.000Z' });
  const commit = await f.store.createRecoveryCommit({
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
  });
  const paths = pathModule.runtimeDeviceRecoveryPaths(f.root, DEVICE_ID, OPERATION_ID);
  await writeFile(paths.recoveryCommit, `${JSON.stringify({
    ...commit,
    disposition: 'ALREADY_ABSENT',
  }, null, 2)}\n`);

  await rejectsCode(f.store.readRecoveryCommit({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(recoveryModule.verifyRuntimeRecoveredState({
    runtimeDevicesRoot: f.root,
    proposedRecoveredState: proposed,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('revalidates commit through current ticket and exact prior attempt provenance', async (t) => {
  const f = await createAlreadyAbsentFixture(t);
  f.setNow('2026-07-30T00:10:00.000Z');
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:10:00.000Z' });
  await f.store.createRecoveryCommit({
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'ALREADY_ABSENT',
  });
  const priorPaths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.priorTicket.ticketId,
  );
  await writeFile(
    priorPaths.authorizedDeleteAttempt,
    `${JSON.stringify({
      ...f.priorAttempt,
      authorizedAt: '2026-07-30T00:07:00.001Z',
    }, null, 2)}\n`,
  );

  await rejectsCode(f.store.readRecoveryCommit({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(recoveryModule.verifyRuntimeRecoveredState({
    runtimeDevicesRoot: f.root,
    proposedRecoveredState: proposed,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(recoveryModule.verifyRuntimeRecoveryCommit({
    runtimeDevicesRoot: f.root,
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('retries the exact commit after response loss following durable publication', async (t) => {
  const f = await createConsumedFixture(t, 0x4b);
  f.setNow('2026-07-30T00:08:00.000Z');
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:07:30.000Z' });
  const input = {
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
  };
  const paths = pathModule.runtimeDeviceRecoveryPaths(f.root, DEVICE_ID, OPERATION_ID);
  let crashed = false;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (
      event === 'afterPublishDirectorySync'
      && context.path === paths.recoveryCommit
      && !crashed
    ) {
      crashed = true;
      throw new Error('SIMULATED_COMMIT_RESPONSE_LOSS');
    }
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  await rejectsCode(f.store.createRecoveryCommit(input), 'RUNTIME_INTERNAL_ERROR');
  assert.equal(crashed, true);
  assert.equal((await stat(paths.recoveryCommit)).nlink, 2);
  assert.equal((await immutableTemporaryPaths(paths.recoveryCommit)).length, 1);
  f.setNow('2026-07-30T00:09:00.000Z');
  const commit = await f.store.createRecoveryCommit(input);
  assert.deepEqual(commit.proposedRecoveredState, proposed);
  assert.equal(commit.committedAt, '2026-07-30T00:08:00.000Z');
});

test('releases the recovery kernel lock after a real controller SIGKILL and retries the exact commit', async (t) => {
  const f = await createConsumedFixture(t, 0x4c);
  f.setNow('2026-07-30T00:08:00.000Z');
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:07:30.000Z' });
  const input = {
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
  };
  const paths = pathModule.runtimeDeviceRecoveryPaths(f.root, DEVICE_ID, OPERATION_ID);
  const lockPath = `${paths.recoveryCommit}.lock`;
  const before = await stat(lockPath);
  assert.equal(before.size, 0);
  assert.equal(before.nlink, 1);
  assert.equal(before.mode & 0o777, 0o600);

  const moduleUrl = new URL('../src/runtime/runtime-recovery-store.mjs', import.meta.url).href;
  const childSource = `
    import { RuntimeRecoveryStore } from ${JSON.stringify(moduleUrl)};
    const [root, encoded] = process.argv.slice(1);
    const input = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    globalThis[Symbol.for('agent-road.runtime-recovery-store.test-hook')] = async (event, context) => {
      if (event === 'afterPublishLinkBeforeDirectorySync' && context.path.endsWith('/recovery-commit.json')) {
        process.kill(process.pid, 'SIGKILL');
      }
    };
    const store = new RuntimeRecoveryStore(root, {
      now: () => new Date('2026-07-30T00:08:00.000Z'),
    });
    await store.createRecoveryCommit(input);
    process.exitCode = 97;
  `;
  await assert.rejects(
    execFile(process.execPath, [
      '--input-type=module',
      '--eval',
      childSource,
      f.root,
      Buffer.from(JSON.stringify(input), 'utf8').toString('base64url'),
    ], {
      encoding: 'utf8',
      env: Object.freeze({
        HOME: process.env.HOME,
        LANG: 'C',
        LC_ALL: 'C',
        NODE_TEST_CONTEXT: process.env.NODE_TEST_CONTEXT,
        PATH: '/usr/bin:/bin',
      }),
      maxBuffer: 16 * 1024,
      timeout: 5_000,
    }),
    (error) => error?.signal === 'SIGKILL',
  );

  assert.equal((await stat(paths.recoveryCommit)).nlink, 2);
  const afterCrash = await stat(lockPath);
  assert.equal(afterCrash.dev, before.dev);
  assert.equal(afterCrash.ino, before.ino);
  assert.equal(afterCrash.size, 0);
  f.setNow('2026-07-30T00:09:00.000Z');
  const commit = await f.store.createRecoveryCommit(input);
  assert.deepEqual(commit.proposedRecoveredState, proposed);
  assert.equal(commit.committedAt, '2026-07-30T00:08:00.000Z');
  const afterRetry = await stat(lockPath);
  assert.equal(afterRetry.dev, before.dev);
  assert.equal(afterRetry.ino, before.ino);
  assert.equal(afterRetry.size, 0);
});

test('stabilizes every immutable recovery record namespace before accepting its bytes', async (t) => {
  const f = await createConsumedFixture(t, 0x4d);
  f.setNow('2026-07-30T00:08:00.000Z');
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:08:00.000Z' });
  await f.store.createRecoveryCommit({
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
  });
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.ticket.ticketId,
  );
  const stabilized = new Set();
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (event === 'afterImmutableReadDirectorySync') stabilized.add(context.path);
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });

  await f.store.readBootObservation({ deviceId: DEVICE_ID, operationId: OPERATION_ID });
  await f.store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
  });
  await f.store.readAuthorizedDeleteAttempt({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
  });
  await f.store.readRecoveryCommit({ deviceId: DEVICE_ID, operationId: OPERATION_ID });

  assert.deepEqual(
    [...stabilized].sort(),
    [
      paths.bootObservation,
      pathModule.runtimeRecoveryAuthorizationSuccessorPath(
        f.root,
        DEVICE_ID,
        OPERATION_ID,
        f.ticket.authorizationParentDigest,
      ),
      paths.ticket,
      paths.authorizedDeleteAttempt,
      paths.recoveryCommit,
    ].sort(),
  );
});

test('rejects an already-absent ticket created before its exact prior authorization time', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  let entropy = 0x4e;
  const f = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, entropy++),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await f.store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const priorTicket = await f.store.createTicket(ticketInput(source, proof));
  now = new Date('2026-07-30T00:07:00.000Z');
  const priorAttempt = await f.store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: priorTicket.ticketId,
    failedState: source.failedState,
    proof,
  });
  const alreadyAbsentSource = proofInput({
    classification: 'ALREADY_ABSENT',
    priorAuthorizedAttempt: {
      ticketId: priorTicket.ticketId,
      attemptDigest: recoveryModule.runtimeRecoveryAuthorizedAttemptDigest(priorAttempt),
    },
    stagingDirectory: directoryFacts('2'.repeat(32), []),
    operationDirectory: null,
  });
  now = new Date('2026-07-30T00:06:59.999Z');
  await rejectsCode(f.store.createTicket(ticketInput(
    alreadyAbsentSource,
    recoveryModule.createRuntimeRecoveryProof(alreadyAbsentSource),
    authorizedAttemptAuthorizationParent(priorTicket, priorAttempt),
  )), 'RUNTIME_STATE_UNSUPPORTED');
});

test('revalidates the prior authorization time against a persisted already-absent ticket', async (t) => {
  const f = await createAlreadyAbsentFixture(t, { consumeCurrent: false });
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.ticket.ticketId,
  );
  await writeFile(paths.ticket, `${JSON.stringify({
    ...f.ticket,
    inspectedAt: '2026-07-30T00:06:59.999Z',
    expiresAt: '2026-07-30T00:16:59.999Z',
  }, null, 2)}\n`);

  await rejectsCode(f.store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('fails closed on controller clock rollback and at the exact ten-minute expiry', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const { store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, 0x55),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });

  now = new Date('2026-07-30T00:04:59.999Z');
  await rejectsCode(store.createTicket(ticketInput(source, proof)), 'RUNTIME_STATE_UNSUPPORTED');

  now = new Date('2026-07-30T00:06:00.000Z');
  const ticket = await store.createTicket(ticketInput(source, proof));
  now = new Date('2026-07-30T00:05:59.999Z');
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: source.failedState,
    proof,
  }), 'RUNTIME_STATE_UNSUPPORTED');

  now = new Date(ticket.expiresAt);
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: source.failedState,
    proof,
  }), 'RUNTIME_INPUT_INVALID');
  assert.deepEqual(await store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
  }), ticket);
});

test('holds one recovery kernel lock across consume, remote work, commit, and state CAS', async (t) => {
  const f = await createTicketFixture(t, 0x65);
  let acquisitions = 0;
  globalThis[RECOVERY_TEST_HOOK] = async (event) => {
    if (event === 'afterRecoveryKernelLockAcquired') acquisitions += 1;
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.ticket.ticketId,
  );
  const lockPath = `${paths.recoveryCommit}.lock`;
  const lockBefore = await stat(lockPath);
  const remoteEntered = deferred();
  const releaseRemote = deferred();
  const casEntered = deferred();
  const releaseCas = deferred();
  const consumeInput = {
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
    failedState: f.source.failedState,
    proof: f.proof,
  };
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:07:30.000Z' });
  const commitInput = {
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
  };
  f.setNow('2026-07-30T00:07:00.000Z');

  const operation = f.store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, async (scope) => {
    assert.equal(Object.isFrozen(scope), true);
    assert.equal(Object.getPrototypeOf(scope), null);
    assert.deepEqual(
      Object.getOwnPropertyNames(scope).sort(),
      [
        'consumeTicket',
        'createBootObservation',
        'createRecoveryCommit',
        'createTicket',
        'readAuthorizedDeleteAttempt',
        'readBootObservation',
        'readRecoveryCommit',
        'readTicket',
        'resolveAuthorizationSuccessor',
      ],
    );
    assert.deepEqual(Object.getOwnPropertySymbols(scope), []);
    for (const forbidden of ['fd', 'token', 'release', 'lockHeld']) {
      assert.equal(forbidden in scope, false);
    }
    const attempt = await scope.consumeTicket(consumeInput);
    remoteEntered.resolve();
    await releaseRemote.promise;
    f.setNow('2026-07-30T00:08:00.000Z');
    const commit = await scope.createRecoveryCommit(commitInput);
    casEntered.resolve();
    await releaseCas.promise;
    return Object.freeze({ attempt, commit });
  });

  try {
    await remoteEntered.promise;
    const attemptEntries = (await readdir(paths.authorizedDeleteAttempts)).sort();
    await rejectsCode(f.store.consumeTicket(consumeInput), 'RUNTIME_ALREADY_RUNNING');
    await rejectsCode(f.store.readRecoveryCommit({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
    }), 'RUNTIME_ALREADY_RUNNING');
    assert.deepEqual((await readdir(paths.authorizedDeleteAttempts)).sort(), attemptEntries);
    await assert.rejects(stat(paths.recoveryCommit), { code: 'ENOENT' });
    releaseRemote.resolve();

    await casEntered.promise;
    const commitBytes = await readFile(paths.recoveryCommit);
    await rejectsCode(f.store.createRecoveryCommit(commitInput), 'RUNTIME_ALREADY_RUNNING');
    assert.deepEqual(await readFile(paths.recoveryCommit), commitBytes);
  } finally {
    releaseRemote.resolve();
    releaseCas.resolve();
  }

  const result = await operation;
  assert.equal(result.attempt.ticketId, f.ticket.ticketId);
  assert.deepEqual(result.commit.proposedRecoveredState, proposed);
  assert.equal(acquisitions, 1);
  const lockAfter = await stat(lockPath);
  assert.equal(lockAfter.dev, lockBefore.dev);
  assert.equal(lockAfter.ino, lockBefore.ino);
  assert.equal(lockAfter.size, 0);
  assert.equal(lockAfter.nlink, 1);
});

test('rejects cross-operation and closed-facade use before changing durable state', async (t) => {
  const f = await createTicketFixture(t, 0x67);
  const otherOperationId = 'b'.repeat(32);
  const otherFailedState = failedState({ operationId: otherOperationId });
  const otherProof = recoveryModule.createRuntimeRecoveryProof(proofInput({
    failedState: otherFailedState,
    stagingDirectory: directoryFacts('2'.repeat(32), [otherOperationId]),
  }));
  const exactInput = {
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
    failedState: f.source.failedState,
    proof: f.proof,
  };
  const crossOperationInput = {
    deviceId: DEVICE_ID,
    operationId: otherOperationId,
    ticketId: f.ticket.ticketId,
    failedState: otherFailedState,
    proof: otherProof,
  };
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.ticket.ticketId,
  );
  const otherPaths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    otherOperationId,
    f.ticket.ticketId,
  );
  let retainedScope;

  await rejectsCode(f.store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, async (scope) => {
    retainedScope = scope;
    await scope.resolveAuthorizationSuccessor(
      genesisAuthorizationParent(otherFailedState),
    );
  }), 'RUNTIME_INPUT_INVALID');

  await rejectsCode(f.store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, async (scope) => {
    await scope.consumeTicket(crossOperationInput);
  }), 'RUNTIME_INPUT_INVALID');

  await rejectsCode(retainedScope.consumeTicket(exactInput), 'RUNTIME_INPUT_INVALID');
  await assert.rejects(stat(paths.authorizedDeleteAttempt), { code: 'ENOENT' });
  await assert.rejects(stat(otherPaths.operation), { code: 'ENOENT' });
  await rejectsCode(f.store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, null), 'RUNTIME_INPUT_INVALID');
});

test('rejects concurrent methods on one active facade without a second publication', async (t) => {
  const f = await createTicketFixture(t, 0x68);
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.ticket.ticketId,
  );
  const publicationEntered = deferred();
  const releasePublication = deferred();
  let blocked = false;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (
      event === 'afterTemporarySyncBeforePublish'
      && context.path === paths.authorizedDeleteAttempt
      && !blocked
    ) {
      blocked = true;
      publicationEntered.resolve();
      await releasePublication.promise;
    }
  };
  t.after(() => {
    releasePublication.resolve();
    delete globalThis[RECOVERY_TEST_HOOK];
  });
  const input = {
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
    failedState: f.source.failedState,
    proof: f.proof,
  };
  f.setNow('2026-07-30T00:07:00.000Z');

  await rejectsCode(f.store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, async (scope) => {
    const first = scope.consumeTicket(input);
    try {
      await publicationEntered.promise;
      await scope.consumeTicket(input);
    } finally {
      releasePublication.resolve();
    }
    await first;
  }), 'RUNTIME_ALREADY_RUNNING');

  assert.equal(blocked, true);
  const relatedEntries = (await readdir(paths.authorizedDeleteAttempts))
    .filter((name) => name.startsWith(`${f.ticket.ticketId}.json`));
  assert.equal(relatedEntries.length, 2);
});

test('propagates the exact callback failure and releases the unchanged lock anchor', async (t) => {
  const f = await createTicketFixture(t, 0x69);
  const paths = pathModule.runtimeDeviceRecoveryPaths(f.root, DEVICE_ID, OPERATION_ID);
  const lockPath = `${paths.recoveryCommit}.lock`;
  const lockBefore = await stat(lockPath);
  const callbackError = new Error('CALLER_ABORTED');
  callbackError.code = 'CALLER_CODE';

  await assert.rejects(f.store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, async () => {
    throw callbackError;
  }), (error) => error === callbackError && error.code === 'CALLER_CODE');

  assert.equal(await f.store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, async () => 'LOCK_RELEASED'), 'LOCK_RELEASED');
  const lockAfter = await stat(lockPath);
  assert.equal(lockAfter.dev, lockBefore.dev);
  assert.equal(lockAfter.ino, lockBefore.ino);
  assert.equal(lockAfter.size, 0);
  assert.equal(lockAfter.nlink, 1);
});

test('returns native promises and drains an unawaited facade rejection', async (t) => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-strict-rejection-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = join(directory, 'runtime', 'devices');
  const storeUrl = JSON.stringify(
    new URL('../src/runtime/runtime-recovery-store.mjs', import.meta.url).href,
  );
  const pathsUrl = JSON.stringify(new URL('../src/core/paths.mjs', import.meta.url).href);
  const script = `
    import { stat } from 'node:fs/promises';
    import { RuntimeRecoveryStore } from ${storeUrl};
    import { runtimeDeviceRecoveryPaths } from ${pathsUrl};

    const root = process.argv[1];
    const deviceId = 'dev_abc123';
    const operationId = '${OPERATION_ID}';
    const missingTicketId = 'rct_' + 'f'.repeat(64);
    const store = new RuntimeRecoveryStore(root, {
      now: () => new Date('2026-07-30T00:05:00.000Z'),
    });
    const binding = { deviceId, operationId };
    const lockPath = runtimeDeviceRecoveryPaths(root, deviceId, operationId)
      .recoveryCommit + '.lock';

    let scopeFailure;
    try {
      await store.withOperationLock(binding, async (scope) => {
        const failed = scope.readTicket(missingTicketId);
        if (Object.getPrototypeOf(failed) !== Promise.prototype) {
          throw new Error('NON_NATIVE_SCOPE_PROMISE');
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
      });
    } catch (error) {
      scopeFailure = error;
    }
    if (scopeFailure?.code !== 'RUNTIME_INPUT_INVALID') {
      throw new Error('FINITE_SCOPE_ERROR_NOT_RETURNED');
    }
    const before = await stat(lockPath);

    const callbackFailure = Object.assign(new Error('CALLBACK_FAILURE'), {
      code: 'CALLBACK_SENTINEL',
    });
    let returnedFailure;
    try {
      await store.withOperationLock(binding, async (scope) => {
        scope.readTicket(missingTicketId);
        await new Promise((resolve) => setTimeout(resolve, 50));
        throw callbackFailure;
      });
    } catch (error) {
      returnedFailure = error;
    }
    if (returnedFailure !== callbackFailure) {
      throw new Error('CALLBACK_IDENTITY_NOT_PRESERVED');
    }

    const reused = await store.withOperationLock(binding, async () => 'REUSED');
    const after = await stat(lockPath);
    process.stdout.write(JSON.stringify({
      reused,
      sameAnchor: before.dev === after.dev && before.ino === after.ino,
      size: after.size,
      links: after.nlink,
    }));
  `;

  const { stdout, stderr } = await execFile(process.execPath, [
    '--unhandled-rejections=strict',
    '--input-type=module',
    '--eval',
    script,
    root,
  ]);
  assert.equal(stderr, '');
  assert.deepEqual(JSON.parse(stdout), {
    reused: 'REUSED',
    sameAnchor: true,
    size: 0,
    links: 1,
  });
});

test('poisons a successful callback that catches a native scope rejection', async (t) => {
  const f = await createStore(t);
  const binding = { deviceId: DEVICE_ID, operationId: OPERATION_ID };
  const missingTicketId = `rct_${'d'.repeat(64)}`;

  await rejectsCode(f.store.withOperationLock(binding, async (scope) => {
    const failed = scope.readTicket(missingTicketId);
    assert.equal(Object.getPrototypeOf(failed), Promise.prototype);
    await rejectsCode(failed, 'RUNTIME_INPUT_INVALID');
    return 'CALLBACK_SUCCEEDED';
  }), 'RUNTIME_INPUT_INVALID');
});

test('maps an unsafe operation-scoped lock anchor without deleting it', async (t) => {
  const f = await createTicketFixture(t, 0x6a);
  const paths = pathModule.runtimeDeviceRecoveryPaths(f.root, DEVICE_ID, OPERATION_ID);
  const lockPath = `${paths.recoveryCommit}.lock`;
  const target = join(paths.operation, 'operation-lock-target');
  const targetBytes = Buffer.from('unsafe-lock-anchor\n', 'utf8');
  await writeFile(target, targetBytes, { mode: 0o600 });
  await rm(lockPath);
  await symlink(target, lockPath);

  await rejectsCode(f.store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, async () => 'UNREACHABLE'), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(await realpath(lockPath), await realpath(target));
  assert.deepEqual(await readFile(lockPath), targetBytes);
});

test('holds one inspect lock across observation, remote inspection, and ticket publication', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const f = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, 0x6b),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  const remoteEntered = deferred();
  const releaseRemote = deferred();
  let acquisitions = 0;
  globalThis[RECOVERY_TEST_HOOK] = async (event) => {
    if (event === 'afterRecoveryKernelLockAcquired') acquisitions += 1;
  };
  t.after(() => {
    releaseRemote.resolve();
    delete globalThis[RECOVERY_TEST_HOOK];
  });

  const inspect = f.store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, async (scope) => {
    assert.equal(await scope.readBootObservation(), null);
    assert.equal(await scope.readRecoveryCommit(), null);
    const observation = await scope.createBootObservation({
      deviceId: DEVICE_ID,
      failedState: source.failedState,
      bootMarker: source.beforeBootMarker,
    });
    assert.deepEqual(await scope.readBootObservation(), observation);
    remoteEntered.resolve();
    await releaseRemote.promise;
    now = new Date('2026-07-30T00:06:00.000Z');
    const ticket = await scope.createTicket(ticketInput(source, proof));
    assert.deepEqual(await scope.readTicket(ticket.ticketId), ticket);
    return ticket;
  });

  try {
    await remoteEntered.promise;
    await rejectsCode(
      f.store.createTicket(ticketInput(source, proof)),
      'RUNTIME_ALREADY_RUNNING',
    );
    assert.equal(acquisitions, 1);
  } finally {
    releaseRemote.resolve();
  }

  const ticket = await inspect;
  assert.equal(ticket.operationId, OPERATION_ID);
  assert.equal(acquisitions, 1);
});

test('optional recovery reads return null only for verified exact absence', async (t) => {
  const f = await createStore(t);
  const ids = { deviceId: DEVICE_ID, operationId: OPERATION_ID };
  const missingTicketId = `rct_${'f'.repeat(64)}`;

  const result = await f.store.withOperationLock(ids, async (scope) => ({
    observation: await scope.readBootObservation(),
    commit: await scope.readRecoveryCommit(),
    successor: await scope.resolveAuthorizationSuccessor(
      genesisAuthorizationParent(failedState()),
    ),
  }));
  assert.equal(result.observation, null);
  assert.equal(result.commit, null);
  assert.equal(result.successor, null);
  await rejectsCode(
    f.store.withOperationLock(ids, (scope) => scope.readTicket(missingTicketId)),
    'RUNTIME_INPUT_INVALID',
  );
  await rejectsCode(
    f.store.withOperationLock(
      ids,
      (scope) => scope.readAuthorizedDeleteAttempt(missingTicketId),
    ),
    'RUNTIME_INPUT_INVALID',
  );
});

test('optional recovery reads reject related residue and corrupt finals', async (t) => {
  const f = await createTicketFixture(t, 0x6d);
  const ids = { deviceId: DEVICE_ID, operationId: OPERATION_ID };
  const paths = pathModule.runtimeDeviceRecoveryPaths(f.root, DEVICE_ID, OPERATION_ID);
  const commitResidue = `${paths.recoveryCommit}.00000000-0000-4000-8000-000000000000.tmp`;
  await writeFile(commitResidue, '{}\n', { mode: 0o600 });
  await rejectsCode(
    f.store.withOperationLock(ids, (scope) => scope.readRecoveryCommit()),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  await rm(commitResidue);

  await writeFile(paths.recoveryCommit, '{}\n', { mode: 0o600 });
  await rejectsCode(
    f.store.withOperationLock(ids, (scope) => scope.readRecoveryCommit()),
    'RUNTIME_STATE_UNSUPPORTED',
  );
});

test('preserves public mutation errors for missing ticket and attempt state', async (t) => {
  const missingTicketId = `rct_${'f'.repeat(64)}`;

  await t.test('consume with a missing ticket', async (st) => {
    const f = await createStore(st);
    const source = proofInput();
    const proof = recoveryModule.createRuntimeRecoveryProof(source);
    await rejectsCode(f.store.consumeTicket({
      deviceId: DEVICE_ID,
      operationId: OPERATION_ID,
      ticketId: missingTicketId,
      failedState: source.failedState,
      proof,
    }), 'RUNTIME_STATE_UNSUPPORTED');
  });

  await t.test('commit with a missing ticket', async (st) => {
    const f = await createStore(st);
    const source = proofInput();
    const proof = recoveryModule.createRuntimeRecoveryProof(source);
    await rejectsCode(f.store.createRecoveryCommit({
      expectedFailedState: source.failedState,
      proposedRecoveredState: recoveredState(),
      ticketId: missingTicketId,
      proofDigest: recoveryModule.runtimeRecoveryProofDigest(proof),
      disposition: 'REMOVED',
    }), 'RUNTIME_STATE_UNSUPPORTED');
  });

  await t.test('commit with a valid ticket and missing attempt', async (st) => {
    const f = await createTicketFixture(st, 0x71);
    await rejectsCode(f.store.createRecoveryCommit({
      expectedFailedState: f.source.failedState,
      proposedRecoveredState: recoveredState(),
      ticketId: f.ticket.ticketId,
      proofDigest: f.ticket.proofDigest,
      disposition: 'REMOVED',
    }), 'RUNTIME_STATE_UNSUPPORTED');
  });
});

test('maps exact facade ticket and attempt storage states at the missing boundary', async (t) => {
  const missingTicketId = `rct_${'e'.repeat(64)}`;
  const binding = { deviceId: DEVICE_ID, operationId: OPERATION_ID };

  await t.test('clean missing ticket and attempt are input errors', async (st) => {
    const f = await createStore(st);
    await rejectsCode(
      f.store.withOperationLock(binding, (scope) => scope.readTicket(missingTicketId)),
      'RUNTIME_INPUT_INVALID',
    );
    await rejectsCode(
      f.store.withOperationLock(
        binding,
        (scope) => scope.readAuthorizedDeleteAttempt(missingTicketId),
      ),
      'RUNTIME_INPUT_INVALID',
    );
  });

  for (const kind of ['corrupt', 'replaced']) {
    await t.test(`${kind} ticket is state-unsupported for both exact reads`, async (st) => {
      const f = await createTicketFixture(st, kind === 'corrupt' ? 0x72 : 0x73);
      const paths = pathModule.runtimeDeviceRecoveryPaths(
        f.root,
        DEVICE_ID,
        OPERATION_ID,
        f.ticket.ticketId,
      );
      if (kind === 'corrupt') await writeFile(paths.ticket, '{}\n');
      else await replaceWithUnsafeSymlink(paths.ticket);
      await rejectsCode(
        f.store.withOperationLock(binding, (scope) => scope.readTicket(f.ticket.ticketId)),
        'RUNTIME_STATE_UNSUPPORTED',
      );
      await rejectsCode(
        f.store.withOperationLock(
          binding,
          (scope) => scope.readAuthorizedDeleteAttempt(f.ticket.ticketId),
        ),
        'RUNTIME_STATE_UNSUPPORTED',
      );
    });
  }

  await t.test('valid ticket with clean missing attempt is null only on the scoped facade', async (st) => {
    const f = await createTicketFixture(st, 0x74);
    assert.equal(
      await f.store.withOperationLock(
        binding,
        (scope) => scope.readAuthorizedDeleteAttempt(f.ticket.ticketId),
      ),
      null,
    );
    await rejectsCode(f.store.readAuthorizedDeleteAttempt({
      ...binding,
      ticketId: f.ticket.ticketId,
    }), 'RUNTIME_STATE_UNSUPPORTED');
  });

  for (const kind of ['corrupt', 'replaced']) {
    await t.test(`${kind} attempt is state-unsupported`, async (st) => {
      const f = await createConsumedFixture(st, kind === 'corrupt' ? 0x75 : 0x76);
      const paths = pathModule.runtimeDeviceRecoveryPaths(
        f.root,
        DEVICE_ID,
        OPERATION_ID,
        f.ticket.ticketId,
      );
      if (kind === 'corrupt') await writeFile(paths.authorizedDeleteAttempt, '{}\n');
      else await replaceWithUnsafeSymlink(paths.authorizedDeleteAttempt);
      await rejectsCode(
        f.store.withOperationLock(
          binding,
          (scope) => scope.readAuthorizedDeleteAttempt(f.ticket.ticketId),
        ),
        'RUNTIME_STATE_UNSUPPORTED',
      );
    });
  }
});

test('maps public mutation ticket and attempt corruption or replacement as unsupported', async (t) => {
  for (const kind of ['corrupt', 'replaced']) {
    await t.test(`consume with ${kind} ticket`, async (st) => {
      const f = await createTicketFixture(st, kind === 'corrupt' ? 0x77 : 0x78);
      const paths = pathModule.runtimeDeviceRecoveryPaths(
        f.root,
        DEVICE_ID,
        OPERATION_ID,
        f.ticket.ticketId,
      );
      if (kind === 'corrupt') await writeFile(paths.ticket, '{}\n');
      else await replaceWithUnsafeSymlink(paths.ticket);
      await rejectsCode(f.store.consumeTicket({
        deviceId: DEVICE_ID,
        operationId: OPERATION_ID,
        ticketId: f.ticket.ticketId,
        failedState: f.source.failedState,
        proof: f.proof,
      }), 'RUNTIME_STATE_UNSUPPORTED');
    });

    await t.test(`commit with ${kind} ticket`, async (st) => {
      const f = await createTicketFixture(st, kind === 'corrupt' ? 0x7b : 0x7c);
      const paths = pathModule.runtimeDeviceRecoveryPaths(
        f.root,
        DEVICE_ID,
        OPERATION_ID,
        f.ticket.ticketId,
      );
      if (kind === 'corrupt') await writeFile(paths.ticket, '{}\n');
      else await replaceWithUnsafeSymlink(paths.ticket);
      await rejectsCode(f.store.createRecoveryCommit({
        expectedFailedState: f.source.failedState,
        proposedRecoveredState: recoveredState(),
        ticketId: f.ticket.ticketId,
        proofDigest: f.ticket.proofDigest,
        disposition: 'REMOVED',
      }), 'RUNTIME_STATE_UNSUPPORTED');
    });

    await t.test(`commit with ${kind} attempt`, async (st) => {
      const f = await createConsumedFixture(st, kind === 'corrupt' ? 0x79 : 0x7a);
      const paths = pathModule.runtimeDeviceRecoveryPaths(
        f.root,
        DEVICE_ID,
        OPERATION_ID,
        f.ticket.ticketId,
      );
      if (kind === 'corrupt') await writeFile(paths.authorizedDeleteAttempt, '{}\n');
      else await replaceWithUnsafeSymlink(paths.authorizedDeleteAttempt);
      await rejectsCode(f.store.createRecoveryCommit({
        expectedFailedState: f.source.failedState,
        proposedRecoveredState: recoveredState(),
        ticketId: f.ticket.ticketId,
        proofDigest: f.ticket.proofDigest,
        disposition: 'REMOVED',
      }), 'RUNTIME_STATE_UNSUPPORTED');
    });
  }
});

test('linearizes concurrent exact-ticket consumption to one durable attempt', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const { root, store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, 0x66),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const ticket = await store.createTicket(ticketInput(source, proof));
  now = new Date('2026-07-30T00:07:00.000Z');
  const consume = () => store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: source.failedState,
    proof,
  });

  const results = await Promise.allSettled([consume(), consume()]);
  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.equal(results.filter(({ status }) => status === 'rejected').length, 1);
  assert.equal(
    results.find(({ status }) => status === 'rejected').reason.code,
    'RUNTIME_ALREADY_RUNNING',
  );
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID, ticket.ticketId);
  const [temporaryPath] = await immutableTemporaryPaths(paths.authorizedDeleteAttempt);
  assert.equal((await stat(paths.authorizedDeleteAttempt)).nlink, 2);
  assert.equal((await stat(temporaryPath)).nlink, 2);
  assert.deepEqual(
    (await readdir(paths.authorizedDeleteAttempts))
      .filter((name) => name.startsWith(`${ticket.ticketId}.json`))
      .sort(),
    [`${ticket.ticketId}.json`, basename(temporaryPath)].sort(),
  );
});

test('serializes deterministic observation publication before creating retained temps', async (t) => {
  const { root, store } = await createStore(t);
  const marker = recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput());
  const create = () => store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: marker,
  });

  const results = await Promise.allSettled([create(), create()]);
  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.deepEqual(
    results.filter(({ status }) => status === 'rejected').map(({ reason }) => reason.code),
    ['RUNTIME_ALREADY_RUNNING'],
  );
  assert.deepEqual(await store.readBootObservation({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }), results.find(({ status }) => status === 'fulfilled').value);
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  assert.equal((await immutableTemporaryPaths(paths.bootObservation)).length, 1);
  assert.equal((await stat(paths.bootObservation)).nlink, 2);
});

test('serializes same-ID ticket publication before creating retained temps', async (t) => {
  let entropyCalls = 0;
  const { root, store } = await createStore(t, {
    now: () => new Date('2026-07-30T00:06:00.000Z'),
    randomBytes: () => {
      entropyCalls += 1;
      return Buffer.alloc(32, 0xbc);
    },
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  const create = () => store.createTicket(ticketInput(source, proof));

  const results = await Promise.allSettled([create(), create()]);
  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 2);
  assert.equal(entropyCalls, 1);
  const [ticket, replay] = results.map(({ value }) => value);
  assert.deepEqual(replay, ticket);
  assert.deepEqual(await store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
  }), ticket);
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    root,
    DEVICE_ID,
    OPERATION_ID,
    ticket.ticketId,
  );
  assert.equal((await immutableTemporaryPaths(paths.ticket)).length, 1);
  assert.equal((await stat(paths.ticket)).nlink, 2);
});

test('serializes concurrent reconciliation of one controlled durable attempt pair', async (t) => {
  const f = await createConsumedFixture(t, 0x77);
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.ticket.ticketId,
  );
  const [temporaryPath] = await immutableTemporaryPaths(paths.authorizedDeleteAttempt);
  const consume = () => f.store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
    failedState: f.source.failedState,
    proof: f.proof,
  });

  const results = await Promise.allSettled([consume(), consume()]);
  assert.deepEqual(
    results.map((result) => result.status === 'rejected' ? result.reason.code : 'FULFILLED').sort(),
    ['RUNTIME_ALREADY_RUNNING', 'RUNTIME_ALREADY_RUNNING'],
  );
  assert.equal((await stat(paths.authorizedDeleteAttempt)).nlink, 2);
  assert.equal((await stat(temporaryPath)).nlink, 2);
});

test('rejects an unsafe cooperative recovery lock endpoint as disk state', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const { root, store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, 0x78),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const ticket = await store.createTicket(ticketInput(source, proof));
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  const target = join(paths.operation, 'lock-target');
  await writeFile(target, '{}\n', { mode: 0o600 });
  await rm(`${paths.recoveryCommit}.lock`);
  await symlink(target, `${paths.recoveryCommit}.lock`);

  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: source.failedState,
    proof,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('fails closed on a legacy nonempty recovery lock without deleting it', async (t) => {
  const { root, store } = await createStore(t);
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  const lockPath = `${paths.recoveryCommit}.lock`;
  const legacy = '{"owner":"legacy","pid":1}\n';
  await writeFile(lockPath, legacy, { mode: 0o600 });

  await rejectsCode(store.createTicket(ticketInput(source, proof)), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(await readFile(lockPath, 'utf8'), legacy);
});

test('treats a crash after attempt-directory fsync as consumed and never dispatchable again', async (t) => {
  let now = new Date('2026-07-30T00:05:00.000Z');
  const { root, store } = await createStore(t, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, 0x79),
  });
  const source = proofInput();
  const proof = recoveryModule.createRuntimeRecoveryProof(source);
  await store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: source.failedState,
    bootMarker: source.beforeBootMarker,
  });
  now = new Date('2026-07-30T00:06:00.000Z');
  const ticket = await store.createTicket(ticketInput(source, proof));
  now = new Date('2026-07-30T00:07:00.000Z');
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID, ticket.ticketId);
  let crashTemporaryPath;
  globalThis[RECOVERY_TEST_HOOK] = async (event, context) => {
    if (
      event === 'afterPublishDirectorySync'
      && context.path === paths.authorizedDeleteAttempt
      && crashTemporaryPath === undefined
    ) {
      crashTemporaryPath = context.temporaryPath;
      throw new Error('SIMULATED_CONTROLLER_CRASH');
    }
  };
  t.after(() => { delete globalThis[RECOVERY_TEST_HOOK]; });
  const consume = () => store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    failedState: source.failedState,
    proof,
  });

  await rejectsCode(consume(), 'RUNTIME_INTERNAL_ERROR');
  assert.equal((await stat(paths.authorizedDeleteAttempt)).nlink, 2);
  assert.equal((await stat(crashTemporaryPath)).nlink, 2);
  await rejectsCode(consume(), 'RUNTIME_ALREADY_RUNNING');
  assert.equal((await stat(paths.authorizedDeleteAttempt)).nlink, 2);
  assert.equal((await stat(crashTemporaryPath)).nlink, 2);
});

test('does not create descendants below an existing non-owner-only device directory', async (t) => {
  const { root, store } = await createStore(t);
  const devicePath = join(root, DEVICE_ID);
  await mkdir(devicePath, { recursive: true, mode: 0o750 });
  await chmod(devicePath, 0o750);

  await rejectsCode(store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await assert.rejects(stat(join(devicePath, 'recovery')), { code: 'ENOENT' });
});

test('rejects malformed store dependencies with the finite input error', () => {
  for (const options of [null, [], { now: null }, { randomBytes: null }]) {
    assert.throws(
      () => new recoveryModule.RuntimeRecoveryStore('/tmp/runtime/devices', options),
      (error) => error?.code === 'RUNTIME_INPUT_INVALID'
        && error.message === 'RUNTIME_INPUT_INVALID',
    );
  }
});

test('maps a hostile controller clock to the finite internal error', async (t) => {
  const hostileDate = new Date('2026-07-30T00:05:00.000Z');
  hostileDate.getTime = () => { throw new Error('HOSTILE_CLOCK_GET_TIME'); };
  const { store } = await createStore(t, { now: () => hostileDate });

  await rejectsCode(store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: failedState(),
    bootMarker: recoveryModule.createRuntimeRecoveryBootMarker(bootMarkerInput()),
  }), 'RUNTIME_INTERNAL_ERROR');
});

test('rejects hostile ticket timestamps without invoking coercion hooks', async (t) => {
  const f = await createConsumedFixture(t, 0x7a);
  let traps = 0;
  const hostileTimestamp = {
    toString() { traps += 1; throw new Error('HOSTILE_TIMESTAMP'); },
  };

  assert.throws(
    () => recoveryModule.runtimeRecoveryTicketDigest({
      ...f.ticket,
      inspectedAt: hostileTimestamp,
    }),
    (error) => error?.code === 'RUNTIME_INPUT_INVALID'
      && error.message === 'RUNTIME_INPUT_INVALID',
  );
  assert.equal(traps, 0);
});

test('never unlinks a retained controlled-attempt temporary on repeat consumption', async (t) => {
  const f = await createConsumedFixture(t, 0x7b);
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.ticket.ticketId,
  );
  const [temporaryPath] = await immutableTemporaryPaths(paths.authorizedDeleteAttempt);
  const before = await readFile(temporaryPath);

  await rejectsCode(f.store.consumeTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: f.ticket.ticketId,
    failedState: f.source.failedState,
    proof: f.proof,
  }), 'RUNTIME_ALREADY_RUNNING');
  assert.deepEqual(await readFile(temporaryPath), before);
  assert.equal((await stat(paths.authorizedDeleteAttempt)).nlink, 2);
  assert.equal((await stat(temporaryPath)).nlink, 2);
});

test('rejects latest selectors and secret-bearing fields without persisting their values', async (t) => {
  const f = await createConsumedFixture(t, 0x7c);
  const sentinels = [
    'RAW-COMMAND-MUST-NOT-PERSIST',
    '100.64.0.1',
    'PRIVATE-KEY-MUST-NOT-PERSIST',
    'TOKEN-MUST-NOT-PERSIST',
  ];

  await rejectsCode(f.store.createBootObservation({
    deviceId: DEVICE_ID,
    failedState: f.source.failedState,
    bootMarker: f.source.beforeBootMarker,
    rawCommand: sentinels[0],
  }), 'RUNTIME_INPUT_INVALID');
  assert.throws(
    () => recoveryModule.createRuntimeRecoveryProof({
      ...proofInput(),
      targetAddress: sentinels[1],
    }),
    (error) => error?.code === 'RUNTIME_INPUT_INVALID',
  );
  await rejectsCode(f.store.createTicket({
    deviceId: DEVICE_ID,
    failedState: f.source.failedState,
    proof: f.proof,
    authorizationParent: f.ticket.authorizationParent,
    privateKey: sentinels[2],
    token: sentinels[3],
  }), 'RUNTIME_INPUT_INVALID');
  await rejectsCode(f.store.readTicket({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: 'latest',
  }), 'RUNTIME_INPUT_INVALID');

  f.setNow('2026-07-30T00:08:00.000Z');
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:08:00.000Z' });
  await f.store.createRecoveryCommit({
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
  });
  const paths = pathModule.runtimeDeviceRecoveryPaths(
    f.root,
    DEVICE_ID,
    OPERATION_ID,
    f.ticket.ticketId,
  );
  const persisted = (await Promise.all([
    readFile(paths.bootObservation, 'utf8'),
    readFile(paths.ticket, 'utf8'),
    readFile(paths.authorizedDeleteAttempt, 'utf8'),
    readFile(paths.recoveryCommit, 'utf8'),
  ])).join('\n');
  for (const sentinel of sentinels) assert.doesNotMatch(persisted, new RegExp(sentinel, 'u'));
});

test('treats a commit record as success only for its exact failed and recovered state pair', async (t) => {
  const f = await createConsumedFixture(t, 0x7d);
  f.setNow('2026-07-30T00:08:00.000Z');
  const proposed = recoveredState({ updatedAt: '2026-07-30T00:08:00.000Z' });
  const input = {
    expectedFailedState: f.source.failedState,
    proposedRecoveredState: proposed,
    ticketId: f.ticket.ticketId,
    proofDigest: f.ticket.proofDigest,
    disposition: 'REMOVED',
  };
  const commit = await f.store.createRecoveryCommit(input);

  await rejectsCode(recoveryModule.verifyRuntimeRecoveredState({
    runtimeDevicesRoot: f.root,
    proposedRecoveredState: recoveredState({ updatedAt: '2026-07-30T00:08:01.000Z' }),
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(recoveryModule.verifyRuntimeRecoveryCommit({
    runtimeDevicesRoot: f.root,
    expectedFailedState: failedState({ updatedAt: '2026-07-30T00:00:01.000Z' }),
    proposedRecoveredState: proposed,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  f.setNow('2026-07-30T00:09:00.000Z');
  assert.deepEqual(await f.store.createRecoveryCommit(input), commit);
  await rejectsCode(f.store.createRecoveryCommit({
    ...input,
    proposedRecoveredState: recoveredState({ updatedAt: '2026-07-30T00:08:01.000Z' }),
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('rejects malformed operation scopes before creating a lock anchor', async (t) => {
  const { root, store } = await createStore(t);
  const paths = pathModule.runtimeDeviceRecoveryPaths(root, DEVICE_ID, OPERATION_ID);
  const lockPath = `${paths.recoveryCommit}.lock`;

  await rejectsCode(store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    latest: true,
  }, async () => {}), 'RUNTIME_INPUT_INVALID');
  await rejectsCode(store.withOperationLock({
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
  }, null), 'RUNTIME_INPUT_INVALID');
  await assert.rejects(stat(lockPath), { code: 'ENOENT' });
});
