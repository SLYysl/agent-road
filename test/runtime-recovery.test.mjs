import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createRecoveryInspectStageCapture } from '../src/runtime/recovery-inspect-stage.mjs';
import { main as cliMain } from '../src/cli.mjs';
import { main as captureMain } from '../src/inspect-cli.mjs';
import { readRecoveryInspectCapture } from '../src/runtime/recovery-inspect-capture.mjs';

import {
  applyRuntimeRecovery,
  inspectRuntimeRecovery,
} from '../src/runtime/runtime-recovery.mjs';
import {
  createRuntimeRecoveryAuthorizationParent,
  createRuntimeRecoveryBootMarker,
  createRuntimeRecoveryProof,
  runtimeRecoveryAuthorizationParentDigest,
  runtimeRecoveryAuthorizedAttemptDigest,
  runtimeRecoveryProofDigest,
  runtimeRecoveryStateDigest,
  runtimeRecoveryTicketDigest,
} from '../src/runtime/runtime-recovery-store.mjs';
import { runtimeRecoveryTargetBindingDigest } from '../src/runtime/runtime-recovery-remote.mjs';

const DEVICE_ID = 'dev_fixture1';
const OPERATION_ID = 'a'.repeat(32);
const TICKET_ID = `rct_${'b'.repeat(64)}`;
const SIBLING_TICKET_ID = `rct_${'d'.repeat(64)}`;
const PRIOR_TICKET_ID = `rct_${'c'.repeat(64)}`;
const THIRD_TICKET_ID = `rct_${'e'.repeat(64)}`;
const FOURTH_TICKET_ID = `rct_${'f'.repeat(64)}`;
const MANIFEST_DIGEST = 'D'.repeat(64);
const GENERATION_DIGEST = 'E'.repeat(64);
const TARGET_ACL_DIGEST = 'DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44';

function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function sshString(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function target(displayName = 'Synthetic Windows Fixture') {
  const blob = Buffer.concat([
    sshString(Buffer.from('ssh-ed25519')),
    sshString(Buffer.alloc(32, 23)),
  ]);
  const hostKey = `ssh-ed25519 ${blob.toString('base64')} fixture-host`;
  const fingerprint = `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/u, '')}`;
  return freezeDeep({
    device: {
      id: DEVICE_ID,
      displayName,
      controllerPlatform: 'darwin',
      targetPlatform: 'windows',
      status: 'CONNECTED_SSH_ONLY',
      capabilities: ['ssh', 'sftp', 'admin-powershell'],
      createdAt: '2026-07-30T00:00:00.000Z',
      updatedAt: '2026-07-30T00:00:00.000Z',
      target: {
        version: '10.0.26200',
        build: 26_200,
        edition: 'Home',
        architecture: 'AMD64',
      },
      transport: {
        tailscaleAddresses: ['100.64.0.10'],
        sshUsername: 'AgentRoad',
        sshHostKeys: [hostKey],
        sshHostKeyFingerprints: [fingerprint],
      },
    },
    identity: {
      privateKeyPath: `/tmp/agent-road/identity/devices/${DEVICE_ID}/id_ed25519`,
      publicKeyPath: `/tmp/agent-road/identity/devices/${DEVICE_ID}/id_ed25519.pub`,
      publicKey: `ssh-ed25519 fixture agent-road:${DEVICE_ID}`,
    },
    knownHostsPath: `/tmp/agent-road/known-hosts/agent-road-known-hosts-${DEVICE_ID}`,
  });
}

function failedState(overrides = {}) {
  return freezeDeep({
    schemaVersion: 1,
    deviceId: DEVICE_ID,
    runtimeStatus: 'FAILED',
    requestedProfiles: ['core'],
    readyProfiles: [],
    operationId: OPERATION_ID,
    manifestDigest: MANIFEST_DIGEST,
    generationDigest: GENERATION_DIGEST,
    failureCode: 'RUNTIME_COMPLETION_UNCERTAIN',
    updatedAt: '2026-07-30T10:00:00.000Z',
    ...overrides,
  });
}

function bootMarker(eventRecordId, second) {
  return createRuntimeRecoveryBootMarker({
    schemaVersion: 1,
    providerGuid: '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}',
    channel: 'System',
    eventId: 12,
    version: 7,
    eventRecordId,
    timeCreated: `2026-07-30T10:00:${second}.000Z`,
    startTime: `2026-07-30T10:00:${second}.000Z`,
  });
}

function acl() {
  return freezeDeep({
    ownerSid: 'S-1-5-32-544',
    protected: true,
    canonical: true,
    accessRuleCount: 2,
    administratorsFullControl: true,
    systemFullControl: true,
    aclDigest: TARGET_ACL_DIGEST,
  });
}

function directory(fileId, directChildren) {
  return freezeDeep({
    volumeSerialNumber: '0000000000000001',
    fileId,
    acl: acl(),
    directChildCount: directChildren.length,
    directChildren,
  });
}

function remoteInspectResult(targetBindingDigest, classification = 'EMPTY_PRE_TRANSACTION', prior = null) {
  const empty = classification === 'EMPTY_PRE_TRANSACTION';
  return freezeDeep({
    schemaVersion: 1,
    protocolRevision: 1,
    deviceId: DEVICE_ID,
    targetBindingDigest,
    operationId: OPERATION_ID,
    bootMarker: bootMarker('102', '02'),
    classification,
    priorAuthorizedAttempt: empty ? null : prior,
    agentRoadAcl: acl(),
    runtimeDirectory: directory('01'.repeat(16), ['staging']),
    stagingDirectory: directory('02'.repeat(16), empty ? [OPERATION_ID] : []),
    operationDirectory: empty ? directory('03'.repeat(16), []) : null,
  });
}

function proofFromRemote(state, observation, result) {
  return createRuntimeRecoveryProof({
    schemaVersion: 1,
    protocolRevision: 1,
    deviceId: DEVICE_ID,
    targetBindingDigest: result.targetBindingDigest,
    failedState: state,
    beforeBootMarker: observation.bootMarker,
    afterBootMarker: result.bootMarker,
    classification: result.classification,
    priorAuthorizedAttempt: result.priorAuthorizedAttempt,
    agentRoadAcl: result.agentRoadAcl,
    runtimeDirectory: result.runtimeDirectory,
    stagingDirectory: result.stagingDirectory,
    operationDirectory: result.operationDirectory,
  });
}

function genesisParent(state) {
  return createRuntimeRecoveryAuthorizationParent({
    schemaVersion: 1,
    kind: 'GENESIS',
    deviceId: state.deviceId,
    operationId: state.operationId,
    failedStateDigest: runtimeRecoveryStateDigest(state),
    ticketId: null,
    ticketDigest: null,
    attemptDigest: null,
  });
}

function expiredTicketParent(ticket) {
  return createRuntimeRecoveryAuthorizationParent({
    schemaVersion: 1,
    kind: 'EXPIRED_TICKET',
    deviceId: ticket.deviceId,
    operationId: ticket.operationId,
    failedStateDigest: ticket.failedStateDigest,
    ticketId: ticket.ticketId,
    ticketDigest: runtimeRecoveryTicketDigest(ticket),
    attemptDigest: null,
  });
}

function authorizedAttemptParent(ticket, attempt) {
  return createRuntimeRecoveryAuthorizationParent({
    schemaVersion: 1,
    kind: 'AUTHORIZED_ATTEMPT',
    deviceId: ticket.deviceId,
    operationId: ticket.operationId,
    failedStateDigest: ticket.failedStateDigest,
    ticketId: ticket.ticketId,
    ticketDigest: runtimeRecoveryTicketDigest(ticket),
    attemptDigest: runtimeRecoveryAuthorizedAttemptDigest(attempt),
  });
}

function ticketRecord(
  state,
  proof,
  ticketId = TICKET_ID,
  authorizationParent = genesisParent(state),
  times = {},
) {
  return freezeDeep({
    schemaVersion: 2,
    recordType: 'RECOVERY_TICKET',
    ticketId,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    authorizationParent,
    authorizationParentDigest: runtimeRecoveryAuthorizationParentDigest(authorizationParent),
    failedState: state,
    failedStateDigest: runtimeRecoveryStateDigest(state),
    proof,
    proofDigest: runtimeRecoveryProofDigest(proof),
    inspectedAt: times.inspectedAt ?? '2026-07-30T10:03:00.000Z',
    expiresAt: times.expiresAt ?? '2026-07-30T10:13:00.000Z',
  });
}

function attemptRecord(ticket, authorizedAt = '2026-07-30T10:04:00.000Z') {
  return freezeDeep({
    schemaVersion: 1,
    recordType: 'AUTHORIZED_DELETE_ATTEMPT',
    ticketId: ticket.ticketId,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketDigest: runtimeRecoveryTicketDigest(ticket),
    failedStateDigest: ticket.failedStateDigest,
    proofDigest: ticket.proofDigest,
    classification: ticket.proof.classification,
    authorizedAt,
  });
}

function unsafePerTicketV1Record(state, proof, ticketId) {
  return freezeDeep({
    schemaVersion: 1,
    recordType: 'RECOVERY_TICKET',
    ticketId,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    failedState: state,
    failedStateDigest: runtimeRecoveryStateDigest(state),
    proof,
    proofDigest: runtimeRecoveryProofDigest(proof),
    inspectedAt: '2026-07-30T10:03:00.000Z',
    expiresAt: '2026-07-30T10:13:00.000Z',
  });
}

function recoveredState(state, updatedAt = '2026-07-30T10:05:00.000Z') {
  return freezeDeep({
    schemaVersion: 2,
    deviceId: state.deviceId,
    runtimeStatus: 'RECOVERED',
    requestedProfiles: ['core'],
    readyProfiles: [],
    operationId: state.operationId,
    manifestDigest: state.manifestDigest,
    generationDigest: state.generationDigest,
    failureCode: null,
    updatedAt,
  });
}

function commitRecord(ticket, attempt, proposed, disposition) {
  return freezeDeep({
    schemaVersion: 1,
    recordType: 'RECOVERY_COMMIT',
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketId: ticket.ticketId,
    authorizedAttemptDigest: runtimeRecoveryAuthorizedAttemptDigest(attempt),
    expectedFailedStateDigest: ticket.failedStateDigest,
    proposedRecoveredState: proposed,
    proposedRecoveredStateDigest: runtimeRecoveryStateDigest(proposed),
    proofDigest: ticket.proofDigest,
    disposition,
    authorizedAt: attempt.authorizedAt,
    committedAt: '2026-07-30T10:06:00.000Z',
  });
}

function observationRecord(state) {
  return freezeDeep({
    schemaVersion: 1,
    recordType: 'BOOT_OBSERVATION',
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    failedState: state,
    failedStateDigest: runtimeRecoveryStateDigest(state),
    bootMarker: bootMarker('101', '01'),
    observedAt: '2026-07-30T10:01:30.000Z',
  });
}

function nullPrototypeFacade(methods) {
  return Object.freeze(Object.assign(Object.create(null), methods));
}

function runtimeError(code) {
  return Object.assign(new Error(code), { code });
}

function trapCounter() {
  return { runs: 0 };
}

function accessorClone(base, field, counter) {
  const clone = Object.assign(Object.create(Object.getPrototypeOf(base)), base);
  Object.defineProperty(clone, field, {
    enumerable: true,
    get() {
      counter.runs += 1;
      throw new Error('accessor trap executed');
    },
  });
  return Object.freeze(clone);
}

function proxyTrap(base, counter) {
  const trap = () => {
    counter.runs += 1;
    throw new Error('proxy trap executed');
  };
  return new Proxy(base, {
    get: trap,
    getOwnPropertyDescriptor: trap,
    getPrototypeOf: trap,
    ownKeys: trap,
  });
}

function hostileThenable(counter) {
  const thenable = {};
  Object.defineProperty(thenable, 'then', {
    enumerable: true,
    get() {
      counter.runs += 1;
      return (_resolve, reject) => reject(new Error('then trap executed'));
    },
  });
  return Object.freeze(thenable);
}

function withDependencies(base, overrides) {
  return Object.freeze({ ...base, ...overrides });
}

function harness(options = {}) {
  const calls = [];
  const createTicketInputs = [];
  const loadedTarget = target(options.displayName);
  const binding = runtimeRecoveryTargetBindingDigest(loadedTarget);
  const original = options.state ?? failedState();
  let currentState = original;
  let observation = Object.hasOwn(options, 'observation')
    ? options.observation
    : observationRecord(original);
  let ticket = options.ticket ?? null;
  let attempt = options.attempt ?? null;
  const attemptsByTicket = new Map();
  if (attempt !== null) attemptsByTicket.set(attempt.ticketId, attempt);
  let commit = options.commit ?? null;
  const defaultRemote = () => remoteInspectResult(binding);

  const scope = nullPrototypeFacade({
    async readBootObservation() {
      calls.push('scope.readBootObservation');
      if (options.readObservationError) throw runtimeError(options.readObservationError);
      return observation;
    },
    async createBootObservation(input) {
      calls.push('scope.createBootObservation');
      observation = observationRecord(input.failedState);
      observation = freezeDeep({
        ...observation,
        bootMarker: options.createdObservationMarker ?? input.bootMarker,
      });
      return observation;
    },
    async createTicket(input) {
      calls.push('scope.createTicket');
      createTicketInputs.push(input);
      const createdTicket = ticketRecord(
        input.failedState,
        input.proof,
        options.createdTicketId ?? TICKET_ID,
        options.createdAuthorizationParent ?? input.authorizationParent,
        options.createdTicketTimes,
      );
      ticket = options.createdTicketMutator
        ? options.createdTicketMutator(createdTicket)
        : createdTicket;
      return ticket;
    },
    async resolveAuthorizationSuccessor(authorizationParent) {
      calls.push('scope.resolveAuthorizationSuccessor');
      if (
        ticket === null
        || runtimeRecoveryAuthorizationParentDigest(ticket.authorizationParent)
          !== runtimeRecoveryAuthorizationParentDigest(authorizationParent)
      ) return null;
      return ticket;
    },
    async readTicket(ticketId) {
      calls.push('scope.readTicket');
      if (options.readTicketError) throw runtimeError(options.readTicketError);
      if (ticket === null || ticket.ticketId !== ticketId) throw runtimeError('RUNTIME_INPUT_INVALID');
      return ticket;
    },
    async readAuthorizedDeleteAttempt(ticketId) {
      calls.push('scope.readAuthorizedDeleteAttempt');
      if (options.readAttemptError) throw runtimeError(options.readAttemptError);
      return attemptsByTicket.get(ticketId) ?? null;
    },
    async consumeTicket(input) {
      calls.push('scope.consumeTicket');
      if (options.consumeError) throw runtimeError(options.consumeError);
      attempt = attemptRecord(ticket ?? ticketRecord(
        input.failedState,
        input.proof,
        TICKET_ID,
        input.authorizationParent,
      ));
      attemptsByTicket.set(attempt.ticketId, attempt);
      return attempt;
    },
    async readRecoveryCommit() {
      calls.push('scope.readRecoveryCommit');
      if (options.readCommitError) throw runtimeError(options.readCommitError);
      return commit;
    },
    async createRecoveryCommit(input) {
      calls.push('scope.createRecoveryCommit');
      if (options.createCommitError) throw runtimeError(options.createCommitError);
      const proposed = input.proposedRecoveredState;
      commit = commitRecord(ticket, attempt, proposed, input.disposition);
      return commit;
    },
  });

  const dependencies = Object.freeze({
    async loadTarget(deviceId) {
      calls.push('loadTarget');
      assert.equal(deviceId, DEVICE_ID);
      return loadedTarget;
    },
    async readState(deviceId) {
      calls.push('readState');
      assert.equal(deviceId, DEVICE_ID);
      return currentState;
    },
    async transitionState(expected, next) {
      calls.push('transitionState');
      if (options.transitionResponseLoss) {
        currentState = next;
        throw runtimeError('RUNTIME_INTERNAL_ERROR');
      }
      if (options.transitionError) throw runtimeError(options.transitionError);
      assert.deepEqual(expected, original);
      currentState = next;
      return currentState;
    },
    async withRecoveryOperation(ids, callback) {
      calls.push('withRecoveryOperation');
      assert.deepEqual(ids, { deviceId: DEVICE_ID, operationId: OPERATION_ID });
      if (options.lockError) throw runtimeError(options.lockError);
      if (options.lockState !== undefined) currentState = options.lockState;
      return callback(scope);
    },
    async inspectRemote(input) {
      calls.push('inspectRemote');
      if (options.inspectError) throw runtimeError(options.inspectError);
      return (options.inspectResult ?? defaultRemote)(input, { binding, observation, attempt, ticket });
    },
    async applyRemote(input) {
      calls.push('applyRemote');
      if (options.applyError) throw runtimeError(options.applyError);
      return freezeDeep({
        schemaVersion: 1,
        disposition: input.proof.classification === 'EMPTY_PRE_TRANSACTION'
          ? 'REMOVED'
          : 'ALREADY_ABSENT',
      });
    },
    clock() {
      calls.push('clock');
      return new Date(options.clockAt ?? '2026-07-30T10:05:00.000Z');
    },
  });

  return {
    binding,
    calls,
    createTicketInputs,
    dependencyFactory: () => dependencies,
    getAttempt: () => attempt,
    getCommit: () => commit,
    getState: () => currentState,
    loadedTarget,
    original,
    scope,
    setAttempt(value) {
      attempt = value;
      if (value !== null) attemptsByTicket.set(value.ticketId, value);
    },
    setTicket(value) { ticket = value; },
  };
}

function multiTicketSuccessorHarness(options = {}) {
  const calls = [];
  const loadedTarget = target();
  const binding = runtimeRecoveryTargetBindingDigest(loadedTarget);
  const original = failedState();
  const observation = observationRecord(original);
  const ticketIds = [...(options.ticketIds ?? [TICKET_ID, SIBLING_TICKET_ID])];
  const tickets = new Map();
  const attemptsByTicket = new Map();
  const successorTickets = new Map();
  let dispatchCount = 0;
  let inspectCount = 0;
  let commit = null;
  let clockAt = options.clockAt ?? '2026-07-30T10:05:00.000Z';

  const scope = nullPrototypeFacade({
    async readBootObservation() {
      calls.push('scope.readBootObservation');
      return observation;
    },
    async createBootObservation() {
      calls.push('scope.createBootObservation');
      throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
    },
    async createTicket(input) {
      calls.push('scope.createTicket');
      if (!Object.hasOwn(input, 'authorizationParent')) {
        throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
      }
      const slot = runtimeRecoveryAuthorizationParentDigest(input.authorizationParent);
      const existing = successorTickets.get(slot);
      if (existing !== undefined) return existing;
      const ticketId = ticketIds.shift();
      if (ticketId === undefined) throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
      const ticket = ticketRecord(
        input.failedState,
        input.proof,
        ticketId,
        input.authorizationParent,
        {
          inspectedAt: clockAt,
          expiresAt: new Date(Date.parse(clockAt) + 10 * 60 * 1_000).toISOString(),
        },
      );
      tickets.set(ticketId, ticket);
      successorTickets.set(slot, ticket);
      return ticket;
    },
    async resolveAuthorizationSuccessor(authorizationParent) {
      calls.push('scope.resolveAuthorizationSuccessor');
      return successorTickets.get(
        runtimeRecoveryAuthorizationParentDigest(authorizationParent),
      ) ?? null;
    },
    async readTicket(ticketId) {
      calls.push(`scope.readTicket:${ticketId}`);
      const ticket = tickets.get(ticketId);
      if (ticket === undefined) throw runtimeError('RUNTIME_INPUT_INVALID');
      return ticket;
    },
    async readAuthorizedDeleteAttempt(ticketId) {
      calls.push(`scope.readAuthorizedDeleteAttempt:${ticketId}`);
      const ticket = tickets.get(ticketId);
      if (ticket === undefined) throw runtimeError('RUNTIME_INPUT_INVALID');
      const attempt = attemptsByTicket.get(ticketId);
      return attempt ?? null;
    },
    async consumeTicket(input) {
      calls.push(`scope.consumeTicket:${input.ticketId}`);
      const ticket = tickets.get(input.ticketId);
      if (ticket === undefined) throw runtimeError('RUNTIME_INPUT_INVALID');
      if (attemptsByTicket.has(ticket.ticketId)) throw runtimeError('RUNTIME_ALREADY_RUNNING');
      const expiredSuccessor = successorTickets.get(
        runtimeRecoveryAuthorizationParentDigest(expiredTicketParent(ticket)),
      );
      if (expiredSuccessor !== undefined) throw runtimeError('RUNTIME_INPUT_INVALID');
      const attempt = attemptRecord(ticket, clockAt);
      attemptsByTicket.set(ticket.ticketId, attempt);
      return attempt;
    },
    async readRecoveryCommit() {
      calls.push('scope.readRecoveryCommit');
      return commit;
    },
    async createRecoveryCommit(input) {
      calls.push('scope.createRecoveryCommit');
      const ticket = tickets.get(input.ticketId);
      const attempt = attemptsByTicket.get(input.ticketId);
      if (ticket === undefined || attempt === undefined) {
        throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
      }
      commit = commitRecord(
        ticket,
        attempt,
        input.proposedRecoveredState,
        input.disposition,
      );
      return commit;
    },
  });

  const dependencies = Object.freeze({
    async loadTarget() {
      calls.push('loadTarget');
      return loadedTarget;
    },
    async readState() {
      calls.push('readState');
      return original;
    },
    async transitionState() {
      calls.push('transitionState');
      throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
    },
    async withRecoveryOperation(_ids, callback) {
      calls.push('withRecoveryOperation');
      return callback(scope);
    },
    async inspectRemote(input) {
      calls.push('inspectRemote');
      if (options.inspectResult) {
        const result = options.inspectResult(input, {
          binding,
          inspectIndex: inspectCount,
          original,
          observation,
        });
        inspectCount += 1;
        return result;
      }
      const classification = options.inspectClassifications?.[inspectCount]
        ?? 'EMPTY_PRE_TRANSACTION';
      inspectCount += 1;
      return remoteInspectResult(
        binding,
        classification,
        classification === 'ALREADY_ABSENT' ? input.priorAuthorizedAttempt : null,
      );
    },
    async applyRemote() {
      calls.push('applyRemote');
      dispatchCount += 1;
      throw runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
    },
    clock() {
      calls.push('clock');
      return new Date(clockAt);
    },
  });

  return Object.freeze({
    calls,
    dependencyFactory: () => dependencies,
    dispatchCount: () => dispatchCount,
    attempt: (ticketId) => attemptsByTicket.get(ticketId) ?? null,
    slot: (parent) => successorTickets.get(runtimeRecoveryAuthorizationParentDigest(parent)) ?? null,
    ticket: (ticketId) => tickets.get(ticketId) ?? null,
    setClockAt(value) { clockAt = value; },
  });
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => (
    error?.code === code
    && error.message === code
    && error.cause === undefined
  ));
}

test('exports only the two exact runtime recovery controller entry points', async () => {
  const recovery = await import('../src/runtime/runtime-recovery.mjs');
  assert.deepEqual(Object.keys(recovery).sort(), ['applyRuntimeRecovery', 'inspectRuntimeRecovery']);
});

test('rejects malformed inputs and non-exact dependency surfaces before acquiring an operation lock', async () => {
  const fx = harness();
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_INPUT_INVALID');
  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: 'latest',
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_INPUT_INVALID');

  const extra = Object.freeze({
    ...fx.dependencyFactory(),
    prepare: () => assert.fail('recovery cannot prepare'),
  });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: () => extra,
  }), 'RUNTIME_INPUT_INVALID');
  assert.equal(fx.calls.includes('withRecoveryOperation'), false);
});

test('rejects factory accessor, proxy, and thenable results without executing their traps', async () => {
  const fx = harness();
  const base = fx.dependencyFactory();
  const cases = [];
  const accessor = trapCounter();
  cases.push({ counter: accessor, value: accessorClone(base, 'loadTarget', accessor) });
  const proxy = trapCounter();
  cases.push({ counter: proxy, value: proxyTrap(base, proxy) });
  const thenable = trapCounter();
  cases.push({ counter: thenable, value: hostileThenable(thenable) });

  for (const entry of cases) {
    await rejectsCode(inspectRuntimeRecovery({
      deviceId: DEVICE_ID,
      priorTicketId: null,
      dependencyFactory: () => entry.value,
    }), 'RUNTIME_INPUT_INVALID');
    assert.equal(entry.counter.runs, 0);
  }
});

test('rejects scope accessor, proxy, and thenable results without executing their traps', async () => {
  {
    const fx = harness();
    const counter = trapCounter();
    const scope = accessorClone(fx.scope, 'readBootObservation', counter);
    const dependencies = withDependencies(fx.dependencyFactory(), {
      withRecoveryOperation: (_ids, callback) => callback(scope),
    });
    await rejectsCode(inspectRuntimeRecovery({
      deviceId: DEVICE_ID,
      priorTicketId: null,
      dependencyFactory: () => dependencies,
    }), 'RUNTIME_INPUT_INVALID');
    assert.equal(counter.runs, 0);
  }
  {
    const fx = harness();
    const counter = trapCounter();
    const scope = proxyTrap(fx.scope, counter);
    const dependencies = withDependencies(fx.dependencyFactory(), {
      withRecoveryOperation: (_ids, callback) => callback(scope),
    });
    await rejectsCode(inspectRuntimeRecovery({
      deviceId: DEVICE_ID,
      priorTicketId: null,
      dependencyFactory: () => dependencies,
    }), 'RUNTIME_INPUT_INVALID');
    assert.equal(counter.runs, 0);
  }
  {
    const fx = harness();
    const counter = trapCounter();
    const scope = nullPrototypeFacade({
      ...fx.scope,
      readBootObservation: () => hostileThenable(counter),
    });
    const dependencies = withDependencies(fx.dependencyFactory(), {
      withRecoveryOperation: (_ids, callback) => callback(scope),
    });
    await rejectsCode(inspectRuntimeRecovery({
      deviceId: DEVICE_ID,
      priorTicketId: null,
      dependencyFactory: () => dependencies,
    }), 'RUNTIME_STATE_UNSUPPORTED');
    assert.equal(counter.runs, 0);
  }
});

test('rejects remote accessor, proxy, and thenable results without executing their traps', async () => {
  for (const kind of ['accessor', 'proxy', 'thenable']) {
    const fx = harness();
    const counter = trapCounter();
    const valid = remoteInspectResult(fx.binding);
    const result = kind === 'accessor'
      ? accessorClone(valid, 'schemaVersion', counter)
      : kind === 'proxy'
        ? proxyTrap(valid, counter)
        : hostileThenable(counter);
    const dependencies = withDependencies(fx.dependencyFactory(), {
      inspectRemote: () => result,
    });
    await rejectsCode(inspectRuntimeRecovery({
      deviceId: DEVICE_ID,
      priorTicketId: null,
      dependencyFactory: () => dependencies,
    }), 'RUNTIME_INVENTORY_FAILED');
    assert.equal(counter.runs, 0);
  }
});

test('rejects every ineligible local state before lock or remote inspection', async () => {
  for (const state of [
    failedState({ failureCode: 'RUNTIME_ROLLBACK_INCOMPLETE' }),
    failedState({ requestedProfiles: ['core', 'base'] }),
    failedState({ readyProfiles: ['core'] }),
    failedState({ runtimeStatus: 'READY', failureCode: null, readyProfiles: ['core'] }),
  ]) {
    const fx = harness({ state, observation: null });
    await rejectsCode(inspectRuntimeRecovery({
      deviceId: DEVICE_ID,
      priorTicketId: null,
      dependencyFactory: fx.dependencyFactory,
    }), 'RUNTIME_STATE_UNSUPPORTED');
    assert.equal(fx.calls.includes('withRecoveryOperation'), false);
    assert.equal(fx.calls.includes('inspectRemote'), false);
  }
});

test('inspect does not expose apply-only errors from a hostile operation-lock adapter', async () => {
  const fx = harness({ lockError: 'RUNTIME_COMPLETION_UNCERTAIN' });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(fx.calls.includes('inspectRemote'), false);
});

test('inspect stops on any existing recovery commit before remote inspection or successor publication', async () => {
  const fx = harness({ commit: freezeDeep({ durable: true }) });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');

  assert.deepEqual(
    fx.calls.filter((call) => call === 'readState' || call.startsWith('scope.') || call === 'inspectRemote'),
    [
      'readState',
      'readState',
      'scope.readBootObservation',
      'scope.readRecoveryCommit',
    ],
  );
  assert.equal(fx.calls.includes('inspectRemote'), false);
  assert.equal(fx.calls.includes('scope.createTicket'), false);
});

test('inspect returns a bounded apply handoff for an exact commit and attempt without touching Windows', async () => {
  const seed = harness();
  const result = remoteInspectResult(seed.binding);
  const proof = proofFromRemote(seed.original, observationRecord(seed.original), result);
  const ticket = ticketRecord(seed.original, proof);
  const attempt = attemptRecord(ticket);
  const proposed = recoveredState(seed.original);
  const commit = commitRecord(ticket, attempt, proposed, 'REMOVED');
  const fx = harness({
    ticket,
    attempt,
    commit,
    clockAt: '2026-07-30T11:00:00.000Z',
  });

  const handoff = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.deepEqual(handoff, {
    schemaVersion: 1,
    status: 'RECOVERY_APPLY_REQUIRED',
    deviceId: DEVICE_ID,
    displayName: 'Synthetic Windows Fixture',
    targetFingerprint: fx.binding.slice(0, 12),
    classification: 'EMPTY_PRE_TRANSACTION',
    rebootRequired: false,
    actionable: false,
    ticketId: TICKET_ID,
    ticketFingerprint: runtimeRecoveryTicketDigest(ticket).slice(0, 12),
    expiresAt: ticket.expiresAt,
  });
  assert.equal(fx.calls.includes('inspectRemote'), false);
  assert.equal(fx.calls.includes('scope.createTicket'), false);
  assert.equal(fx.calls.includes('clock'), false);
  assert.equal(fx.calls.filter((call) => call === 'scope.readAuthorizedDeleteAttempt').length, 1);
});

test('inspect rejects a recovery commit whose exact authorized attempt is missing', async () => {
  const seed = harness();
  const result = remoteInspectResult(seed.binding);
  const proof = proofFromRemote(seed.original, observationRecord(seed.original), result);
  const ticket = ticketRecord(seed.original, proof);
  const missingAttempt = attemptRecord(ticket);
  const proposed = recoveredState(seed.original);
  const commit = commitRecord(ticket, missingAttempt, proposed, 'REMOVED');
  const fx = harness({ ticket, attempt: null, commit });

  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(fx.calls.includes('inspectRemote'), false);
  assert.equal(fx.calls.includes('scope.createTicket'), false);
});

test('first exact empty inspect records one boot observation and requires an explicit reboot without a ticket', async () => {
  const fx = harness({ observation: null });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_REBOOT_REQUIRED');

  assert.deepEqual(fx.calls.filter((call) => [
    'inspectRemote',
    'scope.createBootObservation',
    'scope.createTicket',
  ].includes(call)), ['inspectRemote', 'scope.createBootObservation']);
});

test('rejects a created boot observation whose canonical marker differs from the remote marker', async () => {
  const fx = harness({
    observation: null,
    createdObservationMarker: bootMarker('103', '03'),
  });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(fx.calls.includes('scope.createTicket'), false);
});

test('creates one exact actionable ticket only after the observed reboot barrier', async () => {
  const fx = harness();
  const result = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });
  const ticket = await fx.scope.readTicket(TICKET_ID);
  const expectedParent = genesisParent(fx.original);

  assert.deepEqual(fx.createTicketInputs, [Object.freeze({
    deviceId: DEVICE_ID,
    failedState: fx.original,
    proof: ticket.proof,
    authorizationParent: expectedParent,
  })]);
  assert.deepEqual(ticket.authorizationParent, expectedParent);
  assert.equal(
    ticket.authorizationParentDigest,
    runtimeRecoveryAuthorizationParentDigest(expectedParent),
  );

  assert.deepEqual(result, {
    schemaVersion: 1,
    status: 'RECOVERY_READY',
    deviceId: DEVICE_ID,
    displayName: 'Synthetic Windows Fixture',
    targetFingerprint: fx.binding.slice(0, 12),
    classification: 'EMPTY_PRE_TRANSACTION',
    rebootRequired: false,
    actionable: true,
    ticketId: TICKET_ID,
    ticketFingerprint: runtimeRecoveryTicketDigest(ticket).slice(0, 12),
    expiresAt: ticket.expiresAt,
  });
  assert.equal(Object.isFrozen(result), true);
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(
    serialized,
    /100\.64|id_ed25519|operationId|proof|manifestDigest|generationDigest|authorizationParent/u,
  );
});

test('rejects a created ticket whose canonical authorization parent differs from the requested slot', async () => {
  const state = failedState();
  const wrongParent = createRuntimeRecoveryAuthorizationParent({
    schemaVersion: 1,
    kind: 'EXPIRED_TICKET',
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    failedStateDigest: runtimeRecoveryStateDigest(state),
    ticketId: PRIOR_TICKET_ID,
    ticketDigest: 'A'.repeat(64),
    attemptDigest: null,
  });
  const fx = harness({ state, createdAuthorizationParent: wrongParent });

  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(fx.calls.filter((call) => call === 'scope.createTicket').length, 1);
});

test('accepts a 512-byte display name and rejects 513 bytes before recovery publication', async () => {
  const acceptedName = 'a'.repeat(512);
  const accepted = harness({ displayName: acceptedName });
  const result = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: accepted.dependencyFactory,
  });
  assert.equal(result.displayName, acceptedName);

  const rejected = harness({ displayName: 'a'.repeat(513) });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: rejected.dependencyFactory,
  }), 'RUNTIME_INVENTORY_FAILED');
  assert.equal(rejected.calls.includes('withRecoveryOperation'), false);
});

test('rejects a non-canonical ACL digest from the remote inventory before ticket publication', async () => {
  const fx = harness({
    inspectResult: (_input, context) => {
      const valid = remoteInspectResult(context.binding);
      return freezeDeep({
        ...valid,
        agentRoadAcl: { ...valid.agentRoadAcl, aclDigest: 'A'.repeat(64) },
      });
    },
  });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_INVENTORY_FAILED');
  assert.equal(fx.calls.includes('scope.createTicket'), false);
});

test('fails closed on clean absence without provenance and uses only an explicit exact prior ticket', async () => {
  const external = harness({
    inspectResult: (_input, context) => remoteInspectResult(
      context.binding,
      'EXTERNALLY_ABSENT',
      null,
    ),
  });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: external.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(external.calls.includes('scope.createTicket'), false);

  const seed = harness();
  const sourceResult = remoteInspectResult(seed.binding);
  const sourceProof = proofFromRemote(seed.original, observationRecord(seed.original), sourceResult);
  const priorTicket = ticketRecord(seed.original, sourceProof, PRIOR_TICKET_ID);
  const priorAttempt = attemptRecord(priorTicket);
  const prior = {
    ticketId: PRIOR_TICKET_ID,
    attemptDigest: runtimeRecoveryAuthorizedAttemptDigest(priorAttempt),
  };
  const fx = harness({
    ticket: priorTicket,
    attempt: priorAttempt,
    inspectResult: (input, context) => {
      assert.deepEqual(input.priorAuthorizedAttempt, prior);
      return remoteInspectResult(context.binding, 'ALREADY_ABSENT', prior);
    },
  });
  const result = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: PRIOR_TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.equal(result.classification, 'ALREADY_ABSENT');
  assert.deepEqual(
    fx.createTicketInputs[0].authorizationParent,
    authorizedAttemptParent(priorTicket, priorAttempt),
  );
  assert.deepEqual(fx.createTicketInputs[0].proof.priorAuthorizedAttempt, prior);
  assert.deepEqual(
    fx.calls.filter((call) => call.startsWith('scope.readAuthorized') || call === 'scope.readTicket'),
    [
      'scope.readTicket',
      'scope.readAuthorizedDeleteAttempt',
      'scope.readAuthorizedDeleteAttempt',
    ],
  );
});

test('rejects a finalization ticket that reuses its explicit prior ticket ID', async () => {
  const seed = harness();
  const sourceResult = remoteInspectResult(seed.binding);
  const sourceProof = proofFromRemote(seed.original, observationRecord(seed.original), sourceResult);
  const priorTicket = ticketRecord(seed.original, sourceProof, PRIOR_TICKET_ID);
  const priorAttempt = attemptRecord(priorTicket);
  const prior = Object.freeze({
    ticketId: PRIOR_TICKET_ID,
    attemptDigest: runtimeRecoveryAuthorizedAttemptDigest(priorAttempt),
  });
  const fx = harness({
    ticket: priorTicket,
    attempt: priorAttempt,
    createdTicketId: PRIOR_TICKET_ID,
    inspectResult: (_input, context) => remoteInspectResult(
      context.binding,
      'ALREADY_ABSENT',
      prior,
    ),
  });

  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: PRIOR_TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('an authorized parent is independent from null deletion provenance on a fresh empty reapply', async () => {
  const seed = harness();
  const sourceRemote = remoteInspectResult(seed.binding);
  const sourceProof = proofFromRemote(
    seed.original,
    observationRecord(seed.original),
    sourceRemote,
  );
  const parentTicket = ticketRecord(seed.original, sourceProof, PRIOR_TICKET_ID);
  const parentAttempt = attemptRecord(parentTicket);
  const deletionCandidate = Object.freeze({
    ticketId: PRIOR_TICKET_ID,
    attemptDigest: runtimeRecoveryAuthorizedAttemptDigest(parentAttempt),
  });
  const fx = harness({
    ticket: parentTicket,
    attempt: parentAttempt,
    inspectResult: (input, context) => {
      assert.deepEqual(input.priorAuthorizedAttempt, deletionCandidate);
      return remoteInspectResult(context.binding);
    },
  });

  const result = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: PRIOR_TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.equal(result.classification, 'EMPTY_PRE_TRANSACTION');
  assert.deepEqual(
    fx.createTicketInputs[0].authorizationParent,
    authorizedAttemptParent(parentTicket, parentAttempt),
  );
  assert.equal(fx.createTicketInputs[0].proof.priorAuthorizedAttempt, null);
});

test('an expired unconsumed exact parent can authorize only an empty successor', async () => {
  const seed = harness();
  const sourceRemote = remoteInspectResult(seed.binding);
  const sourceProof = proofFromRemote(
    seed.original,
    observationRecord(seed.original),
    sourceRemote,
  );
  const parentTicket = ticketRecord(seed.original, sourceProof, PRIOR_TICKET_ID);
  const fx = harness({
    ticket: parentTicket,
    attempt: null,
    clockAt: parentTicket.expiresAt,
    inspectResult: (input, context) => {
      assert.equal(input.priorAuthorizedAttempt, null);
      return remoteInspectResult(context.binding);
    },
  });

  await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: PRIOR_TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.deepEqual(
    fx.createTicketInputs[0].authorizationParent,
    expiredTicketParent(parentTicket),
  );
  assert.equal(fx.createTicketInputs[0].proof.priorAuthorizedAttempt, null);

  const absent = harness({
    ticket: parentTicket,
    attempt: null,
    clockAt: parentTicket.expiresAt,
    inspectResult: (_input, context) => remoteInspectResult(
      context.binding,
      'EXTERNALLY_ABSENT',
      null,
    ),
  });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: PRIOR_TICKET_ID,
    dependencyFactory: absent.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(absent.calls.includes('scope.createTicket'), false);
});

test('a live unconsumed prior ticket is input-invalid before remote inspection', async () => {
  const seed = harness();
  const sourceRemote = remoteInspectResult(seed.binding);
  const sourceProof = proofFromRemote(
    seed.original,
    observationRecord(seed.original),
    sourceRemote,
  );
  const parentTicket = ticketRecord(seed.original, sourceProof, PRIOR_TICKET_ID);
  const fx = harness({
    ticket: parentTicket,
    attempt: null,
    clockAt: '2026-07-30T10:12:59.999Z',
  });

  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: PRIOR_TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_INPUT_INVALID');
  assert.equal(fx.calls.includes('inspectRemote'), false);
  assert.equal(fx.calls.includes('scope.createTicket'), false);
});

test('publishing an expired-ticket successor permanently fences the predecessor from apply', async () => {
  const fx = multiTicketSuccessorHarness({
    ticketIds: [TICKET_ID, SIBLING_TICKET_ID],
    clockAt: '2026-07-30T10:03:00.000Z',
    inspectClassifications: ['EMPTY_PRE_TRANSACTION', 'EMPTY_PRE_TRANSACTION'],
  });
  const inspectedA = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });
  fx.setClockAt(fx.ticket(inspectedA.ticketId).expiresAt);
  const inspectedB = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: inspectedA.ticketId,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.equal(inspectedB.ticketId, SIBLING_TICKET_ID);
  assert.equal(fx.ticket(SIBLING_TICKET_ID).authorizationParent.kind, 'EXPIRED_TICKET');

  fx.setClockAt('2026-07-30T10:05:00.000Z');
  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: inspectedA.ticketId,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_INPUT_INVALID');
  assert.equal(fx.dispatchCount(), 0);
  assert.equal(fx.calls.includes('applyRemote'), false);

  const remoteInspectsBeforeReplay = fx.calls.filter(
    (call) => call === 'inspectRemote',
  ).length;
  const replayedChild = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: inspectedA.ticketId,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.equal(replayedChild.status, 'RECOVERY_READY');
  assert.equal(replayedChild.ticketId, inspectedB.ticketId);
  assert.equal(
    fx.calls.filter((call) => call === 'inspectRemote').length,
    remoteInspectsBeforeReplay + 1,
  );
  assert.equal(fx.ticket(THIRD_TICKET_ID), null);

  fx.setClockAt('2026-07-30T10:14:00.000Z');
  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: inspectedB.ticketId,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  fx.setClockAt('2026-07-30T10:05:00.000Z');
  const remoteInspectsBeforeConsumedHandoff = fx.calls.filter(
    (call) => call === 'inspectRemote',
  ).length;
  const consumedHandoff = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: inspectedA.ticketId,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.equal(consumedHandoff.status, 'RECOVERY_PARENT_REQUIRED');
  assert.equal(consumedHandoff.ticketId, inspectedB.ticketId);
  assert.equal(
    fx.calls.filter((call) => call === 'inspectRemote').length,
    remoteInspectsBeforeConsumedHandoff,
  );
});

test('an already-absent parent carries original empty deletion provenance but remains the immediate authorization parent', async () => {
  const seed = harness();
  const emptyRemote = remoteInspectResult(seed.binding);
  const emptyProof = proofFromRemote(
    seed.original,
    observationRecord(seed.original),
    emptyRemote,
  );
  const ticketA = ticketRecord(seed.original, emptyProof, TICKET_ID);
  const attemptA = attemptRecord(ticketA);
  const originalDeletion = Object.freeze({
    ticketId: ticketA.ticketId,
    attemptDigest: runtimeRecoveryAuthorizedAttemptDigest(attemptA),
  });
  const alreadyRemote = remoteInspectResult(
    seed.binding,
    'ALREADY_ABSENT',
    originalDeletion,
  );
  const alreadyProof = proofFromRemote(
    seed.original,
    observationRecord(seed.original),
    alreadyRemote,
  );
  const ticketB = ticketRecord(
    seed.original,
    alreadyProof,
    PRIOR_TICKET_ID,
    authorizedAttemptParent(ticketA, attemptA),
    {
      inspectedAt: '2026-07-30T10:05:00.000Z',
      expiresAt: '2026-07-30T10:15:00.000Z',
    },
  );
  const attemptB = attemptRecord(ticketB, '2026-07-30T10:06:00.000Z');
  const fx = harness({
    ticket: ticketB,
    attempt: attemptB,
    createdTicketId: THIRD_TICKET_ID,
    createdTicketTimes: {
      inspectedAt: '2026-07-30T10:07:00.000Z',
      expiresAt: '2026-07-30T10:17:00.000Z',
    },
    inspectResult: (input, context) => {
      assert.deepEqual(input.priorAuthorizedAttempt, originalDeletion);
      return remoteInspectResult(context.binding, 'ALREADY_ABSENT', originalDeletion);
    },
  });

  await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: PRIOR_TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.deepEqual(
    fx.createTicketInputs[0].authorizationParent,
    authorizedAttemptParent(ticketB, attemptB),
  );
  assert.deepEqual(
    fx.createTicketInputs[0].proof.priorAuthorizedAttempt,
    originalDeletion,
  );
});

test('an expired unconsumed already-absent parent still carries original empty deletion provenance', async () => {
  const seed = harness();
  const emptyRemote = remoteInspectResult(seed.binding);
  const emptyProof = proofFromRemote(
    seed.original,
    observationRecord(seed.original),
    emptyRemote,
  );
  const ticketA = ticketRecord(seed.original, emptyProof, TICKET_ID);
  const attemptA = attemptRecord(ticketA);
  const originalDeletion = Object.freeze({
    ticketId: ticketA.ticketId,
    attemptDigest: runtimeRecoveryAuthorizedAttemptDigest(attemptA),
  });
  const alreadyRemote = remoteInspectResult(
    seed.binding,
    'ALREADY_ABSENT',
    originalDeletion,
  );
  const alreadyProof = proofFromRemote(
    seed.original,
    observationRecord(seed.original),
    alreadyRemote,
  );
  const ticketB = ticketRecord(
    seed.original,
    alreadyProof,
    PRIOR_TICKET_ID,
    authorizedAttemptParent(ticketA, attemptA),
    {
      inspectedAt: '2026-07-30T10:05:00.000Z',
      expiresAt: '2026-07-30T10:15:00.000Z',
    },
  );
  const fx = harness({
    ticket: ticketB,
    attempt: null,
    clockAt: ticketB.expiresAt,
    createdTicketId: THIRD_TICKET_ID,
    createdTicketTimes: {
      inspectedAt: '2026-07-30T10:16:00.000Z',
      expiresAt: '2026-07-30T10:26:00.000Z',
    },
    inspectResult: (input, context) => {
      assert.deepEqual(input.priorAuthorizedAttempt, originalDeletion);
      return remoteInspectResult(context.binding, 'ALREADY_ABSENT', originalDeletion);
    },
  });

  await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: PRIOR_TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.deepEqual(
    fx.createTicketInputs[0].authorizationParent,
    expiredTicketParent(ticketB),
  );
  assert.deepEqual(
    fx.createTicketInputs[0].proof.priorAuthorizedAttempt,
    originalDeletion,
  );
});

test('rechecks the eligible state under the operation lock before any remote call', async () => {
  const fx = harness({
    lockState: failedState({ updatedAt: '2026-07-30T10:00:00.001Z' }),
  });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_ALREADY_RUNNING');
  assert.equal(fx.calls.includes('inspectRemote'), false);
});

test('reports a concurrent transition to an ineligible state as lock-time state change', async () => {
  const fx = harness({
    lockState: failedState({
      runtimeStatus: 'READY',
      readyProfiles: ['core'],
      failureCode: null,
    }),
  });
  await rejectsCode(inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_ALREADY_RUNNING');
  assert.equal(fx.calls.includes('inspectRemote'), false);
});

test('apply durably consumes before one remote call, commits before CAS, and returns bounded RECOVERED', async () => {
  const fx = harness();
  const result = remoteInspectResult(fx.binding);
  const proof = proofFromRemote(fx.original, observationRecord(fx.original), result);
  const ticket = ticketRecord(fx.original, proof);
  fx.setTicket(ticket);

  const recovered = await applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  });
  const attempt = fx.getAttempt();

  assert.ok(
    fx.calls.indexOf('scope.readRecoveryCommit')
      < fx.calls.indexOf('scope.readAuthorizedDeleteAttempt'),
  );
  assert.ok(
    fx.calls.indexOf('scope.readAuthorizedDeleteAttempt')
      < fx.calls.indexOf('scope.consumeTicket'),
  );
  assert.ok(fx.calls.indexOf('scope.consumeTicket') < fx.calls.indexOf('applyRemote'));
  assert.ok(fx.calls.indexOf('applyRemote') < fx.calls.indexOf('scope.createRecoveryCommit'));
  assert.ok(fx.calls.indexOf('scope.createRecoveryCommit') < fx.calls.indexOf('transitionState'));
  assert.equal(fx.calls.filter((call) => call === 'applyRemote').length, 1);
  assert.deepEqual(recovered, {
    schemaVersion: 1,
    status: 'RECOVERED',
    deviceId: DEVICE_ID,
    displayName: 'Synthetic Windows Fixture',
    targetFingerprint: fx.binding.slice(0, 12),
    classification: 'EMPTY_PRE_TRANSACTION',
    ticketFingerprint: runtimeRecoveryTicketDigest(ticket).slice(0, 12),
    disposition: 'REMOVED',
  });
  assert.equal(
    runtimeRecoveryAuthorizedAttemptDigest(attempt),
    fx.getCommit().authorizedAttemptDigest,
  );
  assert.equal(fx.getState().runtimeStatus, 'RECOVERED');
  assert.equal(Object.isFrozen(recovered), true);
});

test('repeated same-parent inspect returns one immutable genesis successor ticket', async () => {
  const fx = multiTicketSuccessorHarness();
  const inspectedA = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });
  const inspectedB = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.equal(inspectedA.ticketId, TICKET_ID);
  assert.equal(inspectedB.ticketId, TICKET_ID);

  const ticketA = fx.ticket(TICKET_ID);
  assert.equal(ticketA.schemaVersion, 2);
  assert.equal(ticketA.authorizationParent.kind, 'GENESIS');
  assert.equal(fx.slot(ticketA.authorizationParent), ticketA);
  assert.equal(fx.ticket(SIBLING_TICKET_ID), null);
  assert.equal(fx.attempt(TICKET_ID), null);
  assert.equal(fx.attempt(SIBLING_TICKET_ID), null);
  assert.equal(fx.dispatchCount(), 0);
  assert.equal(fx.calls.filter((call) => call === 'clock').length, 3);
});

test('same-parent inspect returns a structured parent handoff after its ticket was consumed', async () => {
  const fx = multiTicketSuccessorHarness({
    ticketIds: [TICKET_ID, SIBLING_TICKET_ID],
    inspectResult: (_input, context) => (
      context.inspectIndex === 0
        ? remoteInspectResult(context.binding, 'EMPTY_PRE_TRANSACTION', null)
        : remoteInspectResult(context.binding, 'EXTERNALLY_ABSENT', null)
    ),
  });
  const ready = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });
  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: ready.ticketId,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  const handoff = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });

  assert.deepEqual(handoff, {
    schemaVersion: 1,
    status: 'RECOVERY_PARENT_REQUIRED',
    deviceId: DEVICE_ID,
    displayName: 'Synthetic Windows Fixture',
    targetFingerprint: runtimeRecoveryTargetBindingDigest(target()).slice(0, 12),
    classification: 'EMPTY_PRE_TRANSACTION',
    rebootRequired: false,
    actionable: false,
    ticketId: TICKET_ID,
    ticketFingerprint: runtimeRecoveryTicketDigest(fx.ticket(TICKET_ID)).slice(0, 12),
    expiresAt: fx.ticket(TICKET_ID).expiresAt,
    eligibleAfter: null,
  });
  assert.equal(fx.ticket(SIBLING_TICKET_ID), null);
  assert.equal(fx.dispatchCount(), 1);
  assert.equal(fx.calls.filter((call) => call === 'inspectRemote').length, 1);
  assert.doesNotMatch(JSON.stringify(handoff), /authorizationParent|operationId|proof/u);
});

test('same-parent inspect recovers an expired slot-only ticket ID as a non-actionable handoff', async () => {
  const fx = multiTicketSuccessorHarness({
    ticketIds: [TICKET_ID, SIBLING_TICKET_ID],
    inspectClassifications: ['EMPTY_PRE_TRANSACTION', 'EMPTY_PRE_TRANSACTION'],
  });
  const ready = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });
  fx.setClockAt(fx.ticket(ready.ticketId).expiresAt);
  const handoff = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });

  assert.equal(handoff.status, 'RECOVERY_PARENT_REQUIRED');
  assert.equal(handoff.actionable, false);
  assert.equal(handoff.ticketId, ready.ticketId);
  assert.equal(handoff.expiresAt, fx.ticket(TICKET_ID).expiresAt);
  assert.equal(handoff.eligibleAfter, null);
  assert.equal(fx.ticket(SIBLING_TICKET_ID), null);
  assert.equal(fx.dispatchCount(), 0);
});

test('same-parent live proof drift returns a handoff eligible at the occupied ticket expiry', async () => {
  const fx = multiTicketSuccessorHarness({
    ticketIds: [TICKET_ID, SIBLING_TICKET_ID],
    inspectResult: (_input, context) => {
      const valid = remoteInspectResult(context.binding);
      if (context.inspectIndex === 0) return valid;
      return freezeDeep({
        ...valid,
        operationDirectory: directory('04'.repeat(16), []),
      });
    },
  });
  const ready = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });
  const handoff = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });

  assert.equal(handoff.status, 'RECOVERY_PARENT_REQUIRED');
  assert.equal(handoff.actionable, false);
  assert.equal(handoff.ticketId, ready.ticketId);
  assert.equal(handoff.eligibleAfter, fx.ticket(TICKET_ID).expiresAt);
  assert.equal(fx.ticket(SIBLING_TICKET_ID), null);
  assert.equal(fx.dispatchCount(), 0);
});

test('same-ticket replay after an uncertain dispatch is zero-remote and remains completion-uncertain', async () => {
  const fx = harness({ applyError: 'RUNTIME_COMPLETION_UNCERTAIN' });
  const result = remoteInspectResult(fx.binding);
  const proof = proofFromRemote(fx.original, observationRecord(fx.original), result);
  fx.setTicket(ticketRecord(fx.original, proof));

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(fx.calls.filter((call) => call === 'applyRemote').length, 1);

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(fx.calls.filter((call) => call === 'applyRemote').length, 1);
  assert.equal(fx.calls.filter((call) => call === 'scope.consumeTicket').length, 1);
  assert.equal(fx.calls.includes('scope.createRecoveryCommit'), false);
  assert.equal(fx.calls.includes('transitionState'), false);
});

test('an uncertain A requires a fresh inspect naming A before B can dispatch', async () => {
  const fx = multiTicketSuccessorHarness({
    ticketIds: [TICKET_ID, SIBLING_TICKET_ID],
    inspectClassifications: ['EMPTY_PRE_TRANSACTION', 'EMPTY_PRE_TRANSACTION'],
  });
  const inspectedA = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: null,
    dependencyFactory: fx.dependencyFactory,
  });
  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: inspectedA.ticketId,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');

  const inspectedB = await inspectRuntimeRecovery({
    deviceId: DEVICE_ID,
    priorTicketId: inspectedA.ticketId,
    dependencyFactory: fx.dependencyFactory,
  });
  const ticketA = fx.ticket(TICKET_ID);
  const attemptA = fx.attempt(TICKET_ID);
  const ticketB = fx.ticket(SIBLING_TICKET_ID);
  assert.equal(inspectedB.ticketId, SIBLING_TICKET_ID);
  assert.deepEqual(ticketB.authorizationParent, authorizedAttemptParent(ticketA, attemptA));
  assert.equal(ticketB.proof.priorAuthorizedAttempt, null);

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: inspectedB.ticketId,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(fx.dispatchCount(), 2);
});

test('unknown remote acknowledgement preserves the exact FAILED state and never retries or commits', async () => {
  const fx = harness({ applyError: 'RUNTIME_COMPLETION_UNCERTAIN' });
  const result = remoteInspectResult(fx.binding);
  const proof = proofFromRemote(fx.original, observationRecord(fx.original), result);
  fx.setTicket(ticketRecord(fx.original, proof));

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(fx.calls.filter((call) => call === 'applyRemote').length, 1);
  assert.equal(fx.calls.includes('scope.createRecoveryCommit'), false);
  assert.equal(fx.calls.includes('transitionState'), false);
  assert.deepEqual(fx.getState(), fx.original);
});

test('an unclassified apply failure is also completion-uncertain after remote dispatch begins', async () => {
  const fx = harness({ applyError: 'UNCLASSIFIED_REMOTE_FAILURE' });
  const result = remoteInspectResult(fx.binding);
  const proof = proofFromRemote(fx.original, observationRecord(fx.original), result);
  fx.setTicket(ticketRecord(fx.original, proof));

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(fx.calls.filter((call) => call === 'applyRemote').length, 1);
  assert.equal(fx.calls.includes('scope.createRecoveryCommit'), false);
  assert.equal(fx.calls.includes('transitionState'), false);
});

test('missing or expired exact tickets fail before remote mutation', async () => {
  for (const option of [
    { readTicketError: 'RUNTIME_INPUT_INVALID' },
    { consumeError: 'RUNTIME_INPUT_INVALID' },
  ]) {
    const fx = harness(option);
    const result = remoteInspectResult(fx.binding);
    const proof = proofFromRemote(fx.original, observationRecord(fx.original), result);
    fx.setTicket(ticketRecord(fx.original, proof));
    await rejectsCode(applyRuntimeRecovery({
      deviceId: DEVICE_ID,
      ticketId: TICKET_ID,
      dependencyFactory: fx.dependencyFactory,
    }), 'RUNTIME_INPUT_INVALID');
    assert.equal(fx.calls.includes('applyRemote'), false);
  }
});

test('rejects shallow-frozen ticket data before consumption or remote mutation', async () => {
  const seed = harness();
  const result = remoteInspectResult(seed.binding);
  const proof = proofFromRemote(seed.original, observationRecord(seed.original), result);
  const valid = ticketRecord(seed.original, proof);
  const unsafeTicket = Object.freeze({ ...valid, proof: { ...valid.proof } });
  const fx = harness({ ticket: unsafeTicket });

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(fx.calls.includes('scope.consumeTicket'), false);
  assert.equal(fx.calls.includes('applyRemote'), false);
});

test('a corrupt recovery commit fails closed before ticket consumption or Windows mutation', async () => {
  const fx = harness({ readCommitError: 'RUNTIME_STATE_UNSUPPORTED' });
  const result = remoteInspectResult(fx.binding);
  const proof = proofFromRemote(fx.original, observationRecord(fx.original), result);
  fx.setTicket(ticketRecord(fx.original, proof));

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(fx.calls.includes('scope.consumeTicket'), false);
  assert.equal(fx.calls.includes('applyRemote'), false);
});

test('a schema-version-1 ticket is unsupported before attempt reads or remote mutation', async () => {
  const seed = harness();
  const result = remoteInspectResult(seed.binding);
  const proof = proofFromRemote(seed.original, observationRecord(seed.original), result);
  const legacy = unsafePerTicketV1Record(seed.original, proof, TICKET_ID);
  const fx = harness({ ticket: legacy });

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(fx.calls.includes('scope.readAuthorizedDeleteAttempt'), false);
  assert.equal(fx.calls.includes('scope.consumeTicket'), false);
  assert.equal(fx.calls.includes('applyRemote'), false);
});

test('a commit for a different exact ticket cannot drive CAS or any remote work', async () => {
  const seed = harness();
  const result = remoteInspectResult(seed.binding);
  const proof = proofFromRemote(seed.original, observationRecord(seed.original), result);
  const requestedTicket = ticketRecord(seed.original, proof, TICKET_ID);
  const committedTicket = ticketRecord(seed.original, proof, SIBLING_TICKET_ID);
  const committedAttempt = attemptRecord(committedTicket);
  const proposed = recoveredState(seed.original);
  const commit = commitRecord(committedTicket, committedAttempt, proposed, 'REMOVED');
  const fx = harness({ ticket: requestedTicket, commit });

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(fx.calls.includes('scope.consumeTicket'), false);
  assert.equal(fx.calls.includes('applyRemote'), false);
  assert.equal(fx.calls.includes('transitionState'), false);
});

test('an exact commit without its exact attempt is unsupported and never repaired or dispatched', async () => {
  const seed = harness();
  const result = remoteInspectResult(seed.binding);
  const proof = proofFromRemote(seed.original, observationRecord(seed.original), result);
  const ticket = ticketRecord(seed.original, proof);
  const absentAttempt = attemptRecord(ticket);
  const proposed = recoveredState(seed.original);
  const commit = commitRecord(ticket, absentAttempt, proposed, 'REMOVED');
  const fx = harness({ ticket, attempt: null, commit });

  await rejectsCode(applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(fx.calls.filter((call) => call === 'scope.readAuthorizedDeleteAttempt').length, 1);
  assert.equal(fx.calls.includes('scope.consumeTicket'), false);
  assert.equal(fx.calls.includes('applyRemote'), false);
  assert.equal(fx.calls.includes('scope.createRecoveryCommit'), false);
  assert.equal(fx.calls.includes('transitionState'), false);
});

test('an existing exact commit performs CAS-only recovery and never consumes or calls Windows', async () => {
  const seed = harness();
  const result = remoteInspectResult(seed.binding);
  const proof = proofFromRemote(seed.original, observationRecord(seed.original), result);
  const ticket = ticketRecord(seed.original, proof);
  const attempt = attemptRecord(ticket);
  const proposed = recoveredState(seed.original);
  const commit = commitRecord(ticket, attempt, proposed, 'REMOVED');
  const fx = harness({
    ticket,
    attempt,
    commit,
    clockAt: '2026-07-30T11:00:00.000Z',
  });

  const recovered = await applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.equal(recovered.status, 'RECOVERED');
  assert.equal(fx.calls.includes('scope.consumeTicket'), false);
  assert.equal(fx.calls.includes('applyRemote'), false);
  assert.equal(fx.calls.includes('scope.createRecoveryCommit'), false);
  assert.equal(fx.calls.includes('clock'), false);
  assert.equal(fx.calls.filter((call) => call === 'transitionState').length, 1);
  assert.ok(
    fx.calls.indexOf('scope.readRecoveryCommit')
      < fx.calls.indexOf('scope.readAuthorizedDeleteAttempt'),
  );
  assert.ok(
    fx.calls.indexOf('scope.readAuthorizedDeleteAttempt')
      < fx.calls.indexOf('transitionState'),
  );
});

test('reconciles a lost CAS response by reading the committed RECOVERED state', async () => {
  const fx = harness({ transitionResponseLoss: true });
  const result = remoteInspectResult(fx.binding);
  const proof = proofFromRemote(fx.original, observationRecord(fx.original), result);
  fx.setTicket(ticketRecord(fx.original, proof));

  const recovered = await applyRuntimeRecovery({
    deviceId: DEVICE_ID,
    ticketId: TICKET_ID,
    dependencyFactory: fx.dependencyFactory,
  });
  assert.equal(recovered.status, 'RECOVERED');
  assert.equal(fx.calls.filter((call) => call === 'transitionState').length, 1);
  assert.equal(fx.calls.filter((call) => call === 'readState').length, 3);
  assert.equal(fx.getState().runtimeStatus, 'RECOVERED');
});

for (const [stage, options] of [
  ['STATE_READ', { observation: null, state: failedState({ requestedProfiles: ['base'] }) }],
  ['RECOVERY_LOCK', { lockError: 'RUNTIME_STATE_UNSUPPORTED' }],
  ['BOOT_OBSERVATION_READ', { readObservationError: 'RUNTIME_STATE_UNSUPPORTED' }],
  ['COMMIT_READ', { readCommitError: 'RUNTIME_STATE_UNSUPPORTED' }],
  ['REMOTE_INSPECT', { observation: null, inspectError: 'RUNTIME_STATE_UNSUPPORTED' }],
  ['BOOT_OBSERVATION_PUBLISH', { observation: null, createdObservationMarker: bootMarker('103', '03') }],
]) {
  test(`diagnostics distinguish identical errors at ${stage} without changing calls`, async () => {
    const baseline = harness(options);
    const observed = harness(options);
    const input = (fx) => ({ deviceId: DEVICE_ID, priorTicketId: null, dependencyFactory: fx.dependencyFactory });
    await rejectsCode(inspectRuntimeRecovery(input(baseline)), 'RUNTIME_STATE_UNSUPPORTED');
    const stages = createRecoveryInspectStageCapture();
    await rejectsCode(stages.run(() => inspectRuntimeRecovery(input(observed))), 'RUNTIME_STATE_UNSUPPORTED');
    assert.equal(stages.snapshot(), stage);
    assert.deepEqual(observed.calls, baseline.calls);
  });
}

test('expected reboot stop records publication stage without changing recovery behavior', async () => {
  const fx = harness({ observation: null });
  const stages = createRecoveryInspectStageCapture();
  await rejectsCode(stages.run(() => inspectRuntimeRecovery({
    deviceId: DEVICE_ID, priorTicketId: null, dependencyFactory: fx.dependencyFactory,
  })), 'RUNTIME_REBOOT_REQUIRED');
  assert.equal(stages.snapshot(), 'BOOT_OBSERVATION_PUBLISH');
  assert.equal(fx.calls.filter((value) => value === 'inspectRemote').length, 1);
  assert.equal(fx.calls.includes('applyRemote'), false);
});

for (const [stage, options] of [
  ['REMOTE_INSPECT', { observation: null, inspectError: 'RUNTIME_STATE_UNSUPPORTED' }],
  ['BOOT_OBSERVATION_PUBLISH', { observation: null, createdObservationMarker: bootMarker('103', '03') }],
]) {
  test(`actual CLI/controller preserve ${stage} into capture receipt with synthetic dependencies`, async (t) => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'inspect-stage-cli-')));
    await chmod(root, 0o700);
    t.after(() => rm(root, { recursive: true, force: true }));
    const run = join(root, 'run');
    const fx = harness(options);
    const lines = [];
    const exit = await captureMain(['inspect', DEVICE_ID, '--run-directory', run], {},
      { stdout: { write(value) { lines.push(value); } } },
      async () => (argv, env, io) => cliMain(argv, env, {
        ...io, runtimeRecoveryDependencyFactory: fx.dependencyFactory,
      }));
    assert.equal(exit, 2);
    assert.equal(lines.length, 1);
    const result = JSON.parse(lines[0]);
    assert.equal(result.code, 'RUNTIME_STATE_UNSUPPORTED');
    assert.equal(result.lastStage, stage);
    assert.deepEqual(await readRecoveryInspectCapture(run), result);
    assert.doesNotMatch(lines[0], /dev_fixture|operationId|manifestDigest|targetBindingDigest/);
    assert.equal(fx.calls.filter((call) => call === 'inspectRemote').length, 1);
    assert.equal(fx.calls.includes('applyRemote'), false);
  });
}
