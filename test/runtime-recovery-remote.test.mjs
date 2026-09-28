import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { WINDOWS_INSPECT_STAGES, createRecoveryInspectStageCapture } from '../src/runtime/recovery-inspect-stage.mjs';
import { captureRecoveryInspect, readRecoveryInspectCapture } from '../src/runtime/recovery-inspect-capture.mjs';
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  createRuntimeRecoveryBootMarker,
  createRuntimeRecoveryProof,
  runtimeRecoveryAuthorizedAttemptDigest,
  runtimeRecoveryProofDigest,
} from '../src/runtime/runtime-recovery-store.mjs';
import { withTrustedSshSession } from '../src/ssh/trusted-ssh-session.mjs';
import { decodedPowerShell } from './support/powershell-frame.mjs';

const recoveryRemote = await import('../src/runtime/runtime-recovery-remote.mjs').catch(() => null);

test('exports the exact runtime recovery remote public API', () => {
  assert.deepEqual(
    Object.keys(recoveryRemote ?? {}).sort(),
    [
      'applyRuntimeRecoveryRemote',
      'inspectRuntimeRecoveryRemote',
      'parseRuntimeRecoveryApplyProcess',
      'parseRuntimeRecoveryInspectProcess',
      'runtimeRecoveryTargetBindingDigest',
    ],
  );
  for (const name of Object.keys(recoveryRemote ?? {})) {
    assert.equal(typeof recoveryRemote[name], 'function');
  }
});

const DEVICE_ID = 'dev_fixture1';
const ADDRESS = '100.64.0.10';
const SECOND_ADDRESS = '100.64.0.11';
const OPERATION_ID = 'a'.repeat(32);
const TICKET_ID = `rct_${'b'.repeat(64)}`;
const PRIOR_TICKET_ID = `rct_${'c'.repeat(64)}`;
const ACL_DIGEST = 'DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44';
const REJECTION_EXIT_CODE = 73;
const PROBE_OUTPUT = 'AGENT_ROAD_ADMINISTRATOR_OK';

function sshString(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function hostFixture(byte, label) {
  const blob = Buffer.concat([
    sshString(Buffer.from('ssh-ed25519')),
    sshString(Buffer.alloc(32, byte)),
  ]);
  return {
    hostKey: `ssh-ed25519 ${blob.toString('base64')} ${label}`,
    fingerprint: `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/u, '')}`,
  };
}

const FIRST_HOST = hostFixture(23, 'fixture-host-a');
const SECOND_HOST = hostFixture(29, 'fixture-host-b');

function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
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
    aclDigest: ACL_DIGEST,
  });
}

function directory(volumeSerialNumber, fileId, directChildren) {
  return freezeDeep({
    volumeSerialNumber,
    fileId,
    acl: acl(),
    directChildCount: directChildren.length,
    directChildren,
  });
}

function rawInspect(rawClassification = 'EMPTY_PRE_TRANSACTION', overrides = {}) {
  const empty = rawClassification === 'EMPTY_PRE_TRANSACTION';
  return freezeDeep({
    schemaVersion: 1,
    rawClassification,
    bootMarker: bootMarker('42', '02'),
    agentRoadAcl: acl(),
    runtimeDirectory: directory('0000000000000001', '01'.repeat(16), ['staging']),
    stagingDirectory: directory(
      '0000000000000001',
      '02'.repeat(16),
      empty ? [OPERATION_ID] : [],
    ),
    operationDirectory: empty
      ? directory('0000000000000001', '03'.repeat(16), [])
      : null,
    ...overrides,
  });
}

function inspectStdout(value = rawInspect()) {
  return JSON.stringify({
    schemaVersion: value.schemaVersion,
    rawClassification: value.rawClassification,
    bootMarker: value.bootMarker,
    agentRoadAcl: value.agentRoadAcl,
    runtimeDirectory: value.runtimeDirectory,
    stagingDirectory: value.stagingDirectory,
    operationDirectory: value.operationDirectory,
  });
}

function processResult(overrides = {}) {
  return {
    command: '/usr/bin/ssh',
    args: [],
    exitCode: 0,
    signal: null,
    stdout: inspectStdout(),
    stderr: '',
    ...overrides,
  };
}

function rejection(code) {
  return processResult({
    exitCode: REJECTION_EXIT_CODE,
    stdout: JSON.stringify({ schemaVersion: 1, error: code }),
  });
}

function rejectsCode(value, code) {
  return assert.rejects(value, (error) => (
    error?.code === code
    && error.message === code
    && error.cause === undefined
  ));
}

function throwsCode(operation, code) {
  return assert.throws(operation, (error) => (
    error?.code === code
    && error.message === code
    && error.cause === undefined
  ));
}

function failedState() {
  return freezeDeep({
    schemaVersion: 1,
    deviceId: DEVICE_ID,
    runtimeStatus: 'FAILED',
    requestedProfiles: ['core'],
    readyProfiles: [],
    operationId: OPERATION_ID,
    manifestDigest: 'D'.repeat(64),
    generationDigest: 'E'.repeat(64),
    failureCode: 'RUNTIME_COMPLETION_UNCERTAIN',
    updatedAt: '2026-07-30T09:59:00.000Z',
  });
}

function proof(targetBindingDigest, classification = 'EMPTY_PRE_TRANSACTION') {
  const empty = classification === 'EMPTY_PRE_TRANSACTION';
  return createRuntimeRecoveryProof({
    schemaVersion: 1,
    protocolRevision: 1,
    deviceId: DEVICE_ID,
    targetBindingDigest,
    failedState: failedState(),
    beforeBootMarker: bootMarker('41', '01'),
    afterBootMarker: bootMarker('42', '02'),
    classification,
    priorAuthorizedAttempt: empty ? null : {
      ticketId: PRIOR_TICKET_ID,
      attemptDigest: 'F'.repeat(64),
    },
    agentRoadAcl: acl(),
    runtimeDirectory: directory('0000000000000001', '01'.repeat(16), ['staging']),
    stagingDirectory: directory(
      '0000000000000001',
      '02'.repeat(16),
      empty ? [OPERATION_ID] : [],
    ),
    operationDirectory: empty
      ? directory('0000000000000001', '03'.repeat(16), [])
      : null,
  });
}

function authorizedAttempt(proofValue, overrides = {}) {
  return freezeDeep({
    schemaVersion: 1,
    recordType: 'AUTHORIZED_DELETE_ATTEMPT',
    ticketId: TICKET_ID,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    ticketDigest: 'A'.repeat(64),
    failedStateDigest: proofValue.failedStateDigest,
    proofDigest: runtimeRecoveryProofDigest(proofValue),
    classification: proofValue.classification,
    authorizedAt: '2026-07-30T10:01:00.000Z',
    ...overrides,
  });
}

function payloadFromScript(script) {
  const encoded = /FromBase64String\('([^']+)'\)/u.exec(script)?.[1];
  assert.ok(encoded, 'trusted wrapper must carry one canonical payload');
  return JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
}

function sshAddress(args) {
  return args.find((arg) => arg.startsWith('AgentRoad@'))?.slice('AgentRoad@'.length);
}

async function fixture(t, options = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-recovery-remote-')));
  await chmod(root, 0o700);
  const identityDirectory = join(root, 'identity', 'devices', DEVICE_ID);
  const privateKeyPath = join(identityDirectory, 'id_ed25519');
  const knownHostsPath = join(root, 'known-hosts', `agent-road-known-hosts-${DEVICE_ID}`);
  await mkdir(identityDirectory, { recursive: true, mode: 0o700 });
  await chmod(join(root, 'identity'), 0o700);
  await chmod(join(root, 'identity', 'devices'), 0o700);
  await chmod(identityDirectory, 0o700);
  await writeFile(privateKeyPath, 'PRIVATE FIXTURE NEVER RETURN\n', { mode: 0o600 });
  t.after(() => rm(root, { recursive: true, force: true }));

  const addresses = options.addresses ?? [ADDRESS];
  const target = freezeDeep({
    device: {
      id: DEVICE_ID,
      displayName: 'Synthetic Windows Fixture',
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
        tailscaleAddresses: addresses,
        sshUsername: 'AgentRoad',
        sshHostKeys: options.hostKeys ?? [FIRST_HOST.hostKey],
        sshHostKeyFingerprints: options.fingerprints ?? [FIRST_HOST.fingerprint],
      },
    },
    identity: {
      privateKeyPath,
      publicKeyPath: `${privateKeyPath}.pub`,
      publicKey: `ssh-ed25519 fixture agent-road:${DEVICE_ID}`,
    },
    knownHostsPath,
  });

  const state = {
    calls: [],
    probes: [],
    inspectCalls: [],
    applyCalls: [],
    payloads: [],
  };
  const runner = async (command, args, processOptions) => {
    state.calls.push({ command, args: [...args], options: processOptions });
    if (command === '/usr/bin/ssh-keygen') {
      return processResult({
        command,
        args: [...args],
        stdout: (options.fingerprints ?? [FIRST_HOST.fingerprint])
          .map((fingerprint) => `256 ${fingerprint} fixture-host (ED25519)\n`)
          .join(''),
      });
    }
    assert.equal(command, '/usr/bin/ssh');
    const address = sshAddress(args);
    const script = decodedPowerShell(args.slice(-8), processOptions);
    if (script.includes(PROBE_OUTPUT)) {
      state.probes.push(address);
      if (options.failedProbeAddresses?.includes(address)) throw new Error('synthetic probe failure');
      return processResult({ command, args: [...args], stdout: PROBE_OUTPUT });
    }
    const payload = payloadFromScript(script);
    state.payloads.push(payload);
    if (Object.hasOwn(payload, 'beforeBootMarker')) {
      state.inspectCalls.push({ address, processOptions, script });
      if (options.inspectThrow) throw options.inspectThrow;
      if (options.changeTrustAfterInspect) await chmod(privateKeyPath, 0o644);
      return options.inspectResult ?? processResult({ command, args: [...args] });
    }
    state.applyCalls.push({ address, processOptions, script });
    if (options.applyThrow) throw options.applyThrow;
    return options.applyResult ?? processResult({
      command,
      args: [...args],
      stdout: JSON.stringify({ schemaVersion: 1, disposition: 'REMOVED' }),
    });
  };

  return { target, runner, state };
}

function trustedSessionInput(fx) {
  const { device, identity, knownHostsPath } = fx.target;
  return {
    deviceId: device.id,
    addresses: device.transport.tailscaleAddresses,
    hostKeys: device.transport.sshHostKeys,
    fingerprints: device.transport.sshHostKeyFingerprints,
    privateKeyPath: identity.privateKeyPath,
    knownHostsPath,
    runProcess: fx.runner,
  };
}

async function whileTrustedSessionIsHeld(fx, operation) {
  let enter;
  let release;
  const entered = new Promise((resolve) => { enter = resolve; });
  const held = new Promise((resolve) => { release = resolve; });
  const owner = withTrustedSshSession(
    trustedSessionInput(fx),
    async () => {
      enter();
      await held;
    },
    { lockTimeoutMs: 1_000 },
  );
  await entered;
  try {
    return await operation();
  } finally {
    release();
    await owner;
  }
}

test('computes the frozen sorted fingerprint-set target binding without addresses, paths, or host keys', async (t) => {
  const first = await fixture(t, {
    addresses: [ADDRESS],
    hostKeys: [FIRST_HOST.hostKey, SECOND_HOST.hostKey],
    fingerprints: [SECOND_HOST.fingerprint, FIRST_HOST.fingerprint],
  });
  const expected = createHash('sha256')
    .update('AGENT_ROAD_RUNTIME_RECOVERY_TARGET_V1\0', 'utf8')
    .update(JSON.stringify({
      deviceId: DEVICE_ID,
      sshHostKeyFingerprints: [FIRST_HOST.fingerprint, SECOND_HOST.fingerprint].sort(),
    }), 'utf8')
    .digest('hex')
    .toUpperCase();
  assert.equal(recoveryRemote.runtimeRecoveryTargetBindingDigest(first.target), expected);

  const changedSurface = freezeDeep({
    ...first.target,
    device: {
      ...first.target.device,
      transport: {
        ...first.target.device.transport,
        tailscaleAddresses: [SECOND_ADDRESS],
        sshHostKeys: [SECOND_HOST.hostKey, FIRST_HOST.hostKey],
      },
    },
  });
  assert.equal(recoveryRemote.runtimeRecoveryTargetBindingDigest(changedSurface), expected);
});

test('strictly parses and deep-freezes exact inspect and apply process acknowledgements', () => {
  const parsedInspect = recoveryRemote.parseRuntimeRecoveryInspectProcess(processResult());
  assert.deepEqual(parsedInspect, rawInspect());
  assert.equal(Object.isFrozen(parsedInspect), true);
  assert.equal(Object.isFrozen(parsedInspect.bootMarker), true);
  assert.equal(Object.isFrozen(parsedInspect.runtimeDirectory.directChildren), true);

  for (const disposition of ['REMOVED', 'ALREADY_ABSENT']) {
    const parsedApply = recoveryRemote.parseRuntimeRecoveryApplyProcess(processResult({
      stdout: JSON.stringify({ schemaVersion: 1, disposition }),
    }));
    assert.deepEqual(parsedApply, { schemaVersion: 1, disposition });
    assert.equal(Object.isFrozen(parsedApply), true);
  }
});

test('parsers accept only exact canonical stdout, empty stderr, null signal, and frozen rejection code 73', () => {
  for (const code of [
    'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
    'RUNTIME_REBOOT_REQUIRED',
    'RUNTIME_OPERATION_CONFLICT',
    'RUNTIME_STATE_UNSUPPORTED',
  ]) {
    throwsCode(() => recoveryRemote.parseRuntimeRecoveryInspectProcess(rejection(code)), code);
  }
  for (const code of [
    'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
    'RUNTIME_REBOOT_REQUIRED',
    'RUNTIME_OPERATION_CONFLICT',
    'RUNTIME_STATE_UNSUPPORTED',
    'RUNTIME_ALREADY_RUNNING',
  ]) {
    throwsCode(() => recoveryRemote.parseRuntimeRecoveryApplyProcess(rejection(code)), code);
  }

  const malformed = [
    processResult({ stdout: `${inspectStdout()}\r\n` }),
    processResult({ stderr: 'warning' }),
    processResult({ signal: 'SIGTERM' }),
    processResult({ exitCode: 1 }),
    processResult({ stdout: JSON.stringify({ ...rawInspect(), extra: true }) }),
    processResult({ stdout: JSON.stringify(rawInspect('clean_absent')) }),
    { ...processResult(), unknown: true },
  ];
  for (const result of malformed) {
    throwsCode(
      () => recoveryRemote.parseRuntimeRecoveryInspectProcess(result),
      'RUNTIME_INVENTORY_FAILED',
    );
  }
  for (const result of [
    processResult({ stdout: '{"disposition":"REMOVED","schemaVersion":1}' }),
    processResult({ stdout: '{"schemaVersion":1,"disposition":"REMOVED"}\n' }),
    processResult({ stdout: '{"schemaVersion":1,"disposition":"removed"}' }),
    rejection('RUNTIME_COMPLETION_UNCERTAIN'),
  ]) {
    throwsCode(
      () => recoveryRemote.parseRuntimeRecoveryApplyProcess(result),
      'RUNTIME_COMPLETION_UNCERTAIN',
    );
  }
});

test('inspect maps raw clean absence only from the exact caller-supplied prior binding', async (t) => {
  const priorAuthorizedAttempt = freezeDeep({
    ticketId: PRIOR_TICKET_ID,
    attemptDigest: 'F'.repeat(64),
  });
  for (const [prior, classification] of [
    [null, 'EXTERNALLY_ABSENT'],
    [priorAuthorizedAttempt, 'ALREADY_ABSENT'],
  ]) {
    const fx = await fixture(t, {
      inspectResult: processResult({ stdout: inspectStdout(rawInspect('CLEAN_ABSENT')) }),
    });
    const result = await recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
      target: fx.target,
      operationId: OPERATION_ID,
      beforeBootMarker: bootMarker('41', '01'),
      priorAuthorizedAttempt: prior,
      dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
    }));
    assert.deepEqual(Object.keys(result), [
      'schemaVersion',
      'protocolRevision',
      'deviceId',
      'targetBindingDigest',
      'operationId',
      'bootMarker',
      'classification',
      'priorAuthorizedAttempt',
      'agentRoadAcl',
      'runtimeDirectory',
      'stagingDirectory',
      'operationDirectory',
    ]);
    assert.equal(result.classification, classification);
    assert.deepEqual(result.priorAuthorizedAttempt, prior);
    assert.equal(Object.isFrozen(result), true);
    assert.equal(fx.state.inspectCalls.length, 1);
    assert.deepEqual(fx.state.payloads, [{
      beforeBootMarker: bootMarker('41', '01'),
      operationId: OPERATION_ID,
      protocolRevision: 1,
      schemaVersion: 1,
    }]);
    assert.deepEqual(fx.state.inspectCalls[0].processOptions, {
      timeoutMs: 30_000,
      maxOutputBytes: 32_768,
      stdinText: fx.state.inspectCalls[0].processOptions.stdinText,
    });
  }
});

test('inspect keeps EMPTY_PRE_TRANSACTION un-attributed and permits read-only address selection fallback', async (t) => {
  const fx = await fixture(t, {
    addresses: [ADDRESS, SECOND_ADDRESS],
    failedProbeAddresses: [ADDRESS],
  });
  const result = await recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
    target: fx.target,
    operationId: OPERATION_ID,
    beforeBootMarker: null,
    priorAuthorizedAttempt: null,
    dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
  }));
  assert.equal(result.classification, 'EMPTY_PRE_TRANSACTION');
  assert.equal(result.priorAuthorizedAttempt, null);
  assert.deepEqual(fx.state.probes, [ADDRESS, SECOND_ADDRESS]);
  assert.deepEqual(fx.state.inspectCalls.map(({ address }) => address), [SECOND_ADDRESS]);
});

test('inspect permits an explicit re-apply when a prior attempt still has an empty operation directory', async (t) => {
  const priorAuthorizedAttempt = freezeDeep({
    ticketId: PRIOR_TICKET_ID,
    attemptDigest: 'F'.repeat(64),
  });
  const fx = await fixture(t);
  const result = await recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
    target: fx.target,
    operationId: OPERATION_ID,
    beforeBootMarker: null,
    priorAuthorizedAttempt,
    dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
  }));

  assert.equal(result.classification, 'EMPTY_PRE_TRANSACTION');
  assert.equal(result.priorAuthorizedAttempt, null);
  assert.equal(fx.state.inspectCalls.length, 1);
});

test('inspect treats a success-shaped EMPTY response for another operation as inventory failure', async (t) => {
  const differentOperationId = 'f'.repeat(32);
  const fx = await fixture(t, {
    inspectResult: processResult({
      stdout: inspectStdout(rawInspect('EMPTY_PRE_TRANSACTION', {
        stagingDirectory: directory(
          '0000000000000001',
          '02'.repeat(16),
          [differentOperationId],
        ),
      })),
    }),
  });

  await rejectsCode(recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
    target: fx.target,
    operationId: OPERATION_ID,
    beforeBootMarker: null,
    priorAuthorizedAttempt: null,
    dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
  })), 'RUNTIME_INVENTORY_FAILED');
  assert.equal(fx.state.inspectCalls.length, 1);
});

test('apply validates full store proof and new attempt, then sends only the Windows-observable subset once', async (t) => {
  const fx = await fixture(t);
  const targetBindingDigest = recoveryRemote.runtimeRecoveryTargetBindingDigest(fx.target);
  const proofValue = proof(targetBindingDigest);
  const attempt = authorizedAttempt(proofValue);
  const result = await recoveryRemote.applyRuntimeRecoveryRemote(freezeDeep({
    target: fx.target,
    proof: proofValue,
    authorizedAttempt: attempt,
    dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
  }));

  assert.deepEqual(result, { schemaVersion: 1, disposition: 'REMOVED' });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(fx.state.applyCalls.length, 1);
  assert.deepEqual(fx.state.payloads, [{
    authorizedAttemptDigest: runtimeRecoveryAuthorizedAttemptDigest(attempt),
    expectedWindowsProof: {
      agentRoadAcl: proofValue.agentRoadAcl,
      afterBootMarker: proofValue.afterBootMarker,
      beforeBootMarker: proofValue.beforeBootMarker,
      classification: proofValue.classification,
      operationDirectory: proofValue.operationDirectory,
      priorAuthorizedAttempt: proofValue.priorAuthorizedAttempt,
      runtimeDirectory: proofValue.runtimeDirectory,
      stagingDirectory: proofValue.stagingDirectory,
    },
    operationId: OPERATION_ID,
    protocolRevision: 1,
    schemaVersion: 1,
  }]);
  assert.deepEqual(fx.state.applyCalls[0].processOptions, {
    timeoutMs: 60_000,
    maxOutputBytes: 32_768,
    stdinText: fx.state.applyCalls[0].processOptions.stdinText,
  });
});

test('apply uses exactly one remote SSH process and never sends an administrator probe', async (t) => {
  const fx = await fixture(t, { addresses: [ADDRESS, SECOND_ADDRESS] });
  const targetBindingDigest = recoveryRemote.runtimeRecoveryTargetBindingDigest(fx.target);
  const proofValue = proof(targetBindingDigest);
  const attempt = authorizedAttempt(proofValue);

  await recoveryRemote.applyRuntimeRecoveryRemote(freezeDeep({
    target: fx.target,
    proof: proofValue,
    authorizedAttempt: attempt,
    dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
  }));

  const remoteSshCalls = fx.state.calls.filter(({ command }) => command === '/usr/bin/ssh');
  assert.equal(remoteSshCalls.length, 1);
  assert.deepEqual(fx.state.probes, []);
  assert.deepEqual(fx.state.applyCalls.map(({ address }) => address), [ADDRESS]);
});

test('apply accepts ALREADY_ABSENT only with a distinct prior reference and current authorization', async (t) => {
  const fx = await fixture(t, {
    applyResult: processResult({
      stdout: JSON.stringify({ schemaVersion: 1, disposition: 'ALREADY_ABSENT' }),
    }),
  });
  const targetBindingDigest = recoveryRemote.runtimeRecoveryTargetBindingDigest(fx.target);
  const proofValue = proof(targetBindingDigest, 'ALREADY_ABSENT');
  const attempt = authorizedAttempt(proofValue);
  const result = await recoveryRemote.applyRuntimeRecoveryRemote(freezeDeep({
    target: fx.target,
    proof: proofValue,
    authorizedAttempt: attempt,
    dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
  }));
  assert.deepEqual(result, { schemaVersion: 1, disposition: 'ALREADY_ABSENT' });
  assert.notEqual(proofValue.priorAuthorizedAttempt.ticketId, attempt.ticketId);
  assert.equal(fx.state.applyCalls.length, 1);
});

test('rejects extra, missing, accessor, Proxy, unfrozen, wrong-type, and wrong-binding inputs before SSH', async (t) => {
  const fx = await fixture(t);
  const targetBindingDigest = recoveryRemote.runtimeRecoveryTargetBindingDigest(fx.target);
  const proofValue = proof(targetBindingDigest);
  const attempt = authorizedAttempt(proofValue);
  let getterCalls = 0;
  const accessor = {
    target: fx.target,
    operationId: OPERATION_ID,
    beforeBootMarker: null,
    priorAuthorizedAttempt: null,
  };
  Object.defineProperty(accessor, 'dependencies', {
    enumerable: true,
    get() { getterCalls += 1; throw new Error('hostile accessor'); },
  });
  Object.freeze(accessor);

  const validInspect = freezeDeep({
    target: fx.target,
    operationId: OPERATION_ID,
    beforeBootMarker: null,
    priorAuthorizedAttempt: null,
    dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
  });
  const invalidInspect = [
    { ...validInspect },
    freezeDeep({ ...validInspect, extra: true }),
    freezeDeep({ ...validInspect, operationId: OPERATION_ID.toUpperCase() }),
    freezeDeep({ ...validInspect, priorAuthorizedAttempt: { ticketId: PRIOR_TICKET_ID } }),
    accessor,
    new Proxy(validInspect, {}),
  ];
  for (const input of invalidInspect) {
    await rejectsCode(recoveryRemote.inspectRuntimeRecoveryRemote(input), 'RUNTIME_INPUT_INVALID');
  }

  const validApply = freezeDeep({
    target: fx.target,
    proof: proofValue,
    authorizedAttempt: attempt,
    dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
  });
  const wrongProof = freezeDeep({ ...proofValue, targetBindingDigest: '0'.repeat(64) });
  const wrongAttempt = authorizedAttempt(proofValue, { operationId: 'f'.repeat(32) });
  for (const input of [
    { ...validApply },
    freezeDeep({ ...validApply, extra: true }),
    freezeDeep({ ...validApply, proof: wrongProof }),
    freezeDeep({ ...validApply, authorizedAttempt: wrongAttempt }),
    new Proxy(validApply, {}),
  ]) {
    await rejectsCode(recoveryRemote.applyRuntimeRecoveryRemote(input), 'RUNTIME_INPUT_INVALID');
  }
  assert.equal(getterCalls, 0);
  assert.equal(fx.state.calls.length, 0);
});

test('inspect maps genuine pre-entry trusted-session lock contention without starting SSH', async (t) => {
  const fx = await fixture(t);
  await whileTrustedSessionIsHeld(fx, async () => {
    await rejectsCode(recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
      target: fx.target,
      operationId: OPERATION_ID,
      beforeBootMarker: null,
      priorAuthorizedAttempt: null,
      dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
    })), 'RUNTIME_ALREADY_RUNNING');
  });

  assert.equal(fx.state.calls.filter(({ command }) => command === '/usr/bin/ssh').length, 0);
  assert.deepEqual(fx.state.probes, []);
  assert.deepEqual(fx.state.inspectCalls, []);
});

test('apply maps genuine pre-entry trusted-session lock contention without starting SSH', async (t) => {
  const fx = await fixture(t);
  const targetBindingDigest = recoveryRemote.runtimeRecoveryTargetBindingDigest(fx.target);
  const proofValue = proof(targetBindingDigest);
  await whileTrustedSessionIsHeld(fx, async () => {
    await rejectsCode(recoveryRemote.applyRuntimeRecoveryRemote(freezeDeep({
      target: fx.target,
      proof: proofValue,
      authorizedAttempt: authorizedAttempt(proofValue),
      dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
    })), 'RUNTIME_ALREADY_RUNNING');
  });

  assert.equal(fx.state.calls.filter(({ command }) => command === '/usr/bin/ssh').length, 0);
  assert.deepEqual(fx.state.probes, []);
  assert.deepEqual(fx.state.applyCalls, []);
});

test('runner lock lookalikes cannot spoof finite trusted-session contention', async (t) => {
  const inspectOptions = {};
  const inspectRunnerFx = await fixture(t, inspectOptions);
  inspectOptions.inspectThrow = Object.assign(
    new Error(`Trusted SSH session ${DEVICE_ID} is locked: ${inspectRunnerFx.target.identity.privateKeyPath} (occupied)`),
    { code: 'TRUSTED_SSH_SESSION_LOCKED' },
  );
  await rejectsCode(recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
    target: inspectRunnerFx.target,
    operationId: OPERATION_ID,
    beforeBootMarker: null,
    priorAuthorizedAttempt: null,
    dependencies: { runProcess: inspectRunnerFx.runner, sshLockTimeoutMs: 1_000 },
  })), 'RUNTIME_INVENTORY_FAILED');
  assert.equal(inspectRunnerFx.state.inspectCalls.length, 1);

  const applyOptions = {};
  const applyRunnerFx = await fixture(t, applyOptions);
  applyOptions.applyThrow = Object.assign(
    new Error(`Trusted SSH session ${DEVICE_ID} is locked: ${applyRunnerFx.target.identity.privateKeyPath} (occupied)`),
    { code: 'TRUSTED_SSH_SESSION_LOCKED' },
  );
  const targetBindingDigest = recoveryRemote.runtimeRecoveryTargetBindingDigest(applyRunnerFx.target);
  const proofValue = proof(targetBindingDigest);
  await rejectsCode(recoveryRemote.applyRuntimeRecoveryRemote(freezeDeep({
    target: applyRunnerFx.target,
    proof: proofValue,
    authorizedAttempt: authorizedAttempt(proofValue),
    dependencies: { runProcess: applyRunnerFx.runner, sshLockTimeoutMs: 1_000 },
  })), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(applyRunnerFx.state.applyCalls.length, 1);
});

test('inspect failure is finite while every unacknowledged apply outcome after invoke begins is uncertain and never retried', async (t) => {
  const inspectFx = await fixture(t, { inspectThrow: new Error('synthetic transport failure') });
  await rejectsCode(recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
    target: inspectFx.target,
    operationId: OPERATION_ID,
    beforeBootMarker: null,
    priorAuthorizedAttempt: null,
    dependencies: { runProcess: inspectFx.runner, sshLockTimeoutMs: 1_000 },
  })), 'RUNTIME_INVENTORY_FAILED');
  assert.equal(inspectFx.state.inspectCalls.length, 1);

  for (const mode of ['throw', 'overflow', 'timeout', 'malformed']) {
    const error = mode === 'overflow'
      ? Object.assign(new Error('synthetic overflow'), { code: 'PROCESS_OUTPUT_LIMIT' })
      : Object.assign(new Error('synthetic process failure'), {
        code: mode === 'timeout' ? 'PROCESS_TIMEOUT' : 'SYNTHETIC_FAILURE',
      });
    const fx = await fixture(t, mode === 'malformed'
      ? { applyResult: processResult({ stdout: '{"schemaVersion":1}' }) }
      : { applyThrow: error });
    const targetBindingDigest = recoveryRemote.runtimeRecoveryTargetBindingDigest(fx.target);
    const proofValue = proof(targetBindingDigest);
    await rejectsCode(recoveryRemote.applyRuntimeRecoveryRemote(freezeDeep({
      target: fx.target,
      proof: proofValue,
      authorizedAttempt: authorizedAttempt(proofValue),
      dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
    })), 'RUNTIME_COMPLETION_UNCERTAIN');
    assert.equal(fx.state.applyCalls.length, 1, mode);
  }
});

test('an exact acknowledged apply target rejection remains finite after the single invocation', async (t) => {
  for (const code of ['RUNTIME_ALREADY_RUNNING', 'RUNTIME_STATE_UNSUPPORTED']) {
    const fx = await fixture(t, { applyResult: rejection(code) });
    const targetBindingDigest = recoveryRemote.runtimeRecoveryTargetBindingDigest(fx.target);
    const proofValue = proof(targetBindingDigest);
    await rejectsCode(recoveryRemote.applyRuntimeRecoveryRemote(freezeDeep({
      target: fx.target,
      proof: proofValue,
      authorizedAttempt: authorizedAttempt(proofValue),
      dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
    })), code);
    assert.equal(fx.state.applyCalls.length, 1);
  }
});

for (const [name, options, expectedCode, inspectCalls] of [
  ['acknowledged rejection', { inspectResult: rejection('RUNTIME_STATE_UNSUPPORTED') }, 'RUNTIME_STATE_UNSUPPORTED', 1],
  ['transport exception with same code', { inspectThrow: Object.assign(new Error('synthetic'), { code: 'RUNTIME_STATE_UNSUPPORTED' }) }, 'RUNTIME_INVENTORY_FAILED', 1],
  ['malformed JSON', { inspectResult: processResult({ stdout: '{' }) }, 'RUNTIME_INVENTORY_FAILED', 1],
  ['rejection with stderr', { inspectResult: { ...rejection('RUNTIME_STATE_UNSUPPORTED'), stderr: 'synthetic warning' } }, 'RUNTIME_INVENTORY_FAILED', 1],
  ['rejection with wrong exit', { inspectResult: { ...rejection('RUNTIME_STATE_UNSUPPORTED'), exitCode: 1 } }, 'RUNTIME_INVENTORY_FAILED', 1],
  ['rejection with extra field', { inspectResult: processResult({ exitCode: REJECTION_EXIT_CODE, stdout: JSON.stringify({ schemaVersion: 1, error: 'RUNTIME_STATE_UNSUPPORTED', detail: 'synthetic' }) }) }, 'RUNTIME_INVENTORY_FAILED', 1],
  ['all probes fail', { failedProbeAddresses: [ADDRESS] }, 'RUNTIME_INVENTORY_FAILED', 0],
]) {
  test(`inspect error provenance: ${name}`, async (t) => {
    const fx = await fixture(t, options);
    await rejectsCode(recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
      target: fx.target,
      operationId: OPERATION_ID,
      beforeBootMarker: null,
      priorAuthorizedAttempt: null,
      dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
    })), expectedCode);
    assert.equal(fx.state.probes.length, 1);
    assert.equal(fx.state.inspectCalls.length, inspectCalls);
    assert.equal(fx.state.applyCalls.length, 0);
  });
}

test('inspect error provenance: local private-key metadata rejection precedes probes', async (t) => {
  const fx = await fixture(t);
  await chmod(fx.target.identity.privateKeyPath, 0o644);
  await rejectsCode(recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
    target: fx.target,
    operationId: OPERATION_ID,
    beforeBootMarker: null,
    priorAuthorizedAttempt: null,
    dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
  })), 'RUNTIME_INVENTORY_FAILED');
  assert.equal(fx.state.probes.length, 0);
  assert.equal(fx.state.inspectCalls.length, 0);
  assert.equal(fx.state.applyCalls.length, 0);
});


function diagnosticRejection(stage, overrides = {}) {
  return processResult({ exitCode: REJECTION_EXIT_CODE,
    stdout: JSON.stringify({ schemaVersion: 2, error: 'RUNTIME_STATE_UNSUPPORTED', stage }),
    ...overrides });
}

test('inspect parser accepts each finite Windows stage, while apply rejects schema 2', () => {
  for (const stage of WINDOWS_INSPECT_STAGES) {
    throwsCode(() => recoveryRemote.parseRuntimeRecoveryInspectProcess(diagnosticRejection(stage)),
      'RUNTIME_STATE_UNSUPPORTED');
    throwsCode(() => recoveryRemote.parseRuntimeRecoveryApplyProcess(diagnosticRejection(stage)),
      'RUNTIME_COMPLETION_UNCERTAIN');
  }
});

test('inspect rejects malformed diagnostic envelopes without publishing a Windows stage', async () => {
  const valid = { schemaVersion: 2, error: 'RUNTIME_STATE_UNSUPPORTED', stage: 'WINDOWS_ACL' };
  for (const record of [
    { ...valid, stage: 'PRIVATE_SENTINEL' }, { ...valid, stage: ['WINDOWS_ACL'] },
    { ...valid, stage: null }, { schemaVersion: 2, error: valid.error },
    { ...valid, extra: 'PRIVATE_SENTINEL' }, { ...valid, schemaVersion: 1 },
    { ...valid, schemaVersion: 3 }, { ...valid, error: 'PRIVATE_SENTINEL' },
  ]) {
    const stages = createRecoveryInspectStageCapture();
    await stages.run(async () => {
      throwsCode(() => recoveryRemote.parseRuntimeRecoveryInspectProcess(processResult({
        exitCode: REJECTION_EXIT_CODE, stdout: JSON.stringify(record),
      })), 'RUNTIME_INVENTORY_FAILED');
    });
    assert.equal(stages.snapshot(), 'NOT_REPORTED');
  }
});

test('validated Windows diagnostic survives remote adapter and durable capture', async (t) => {
  const fx = await fixture(t, { inspectResult: diagnosticRejection('WINDOWS_ACL') });
  const root = await realpath(await mkdtemp(join(tmpdir(), 'windows-stage-capture-')));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const runDirectory = join(root, 'run');
  const result = await captureRecoveryInspect({ runDirectory, diagnostics: true,
    stdout: { write() {} }, invoke: async ({ stderr }) => {
      try {
        await recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
          target: fx.target, operationId: OPERATION_ID, beforeBootMarker: null,
          priorAuthorizedAttempt: null,
          dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
        }));
        assert.fail('expected rejection');
      } catch (error) {
        assert.equal(error.code, 'RUNTIME_STATE_UNSUPPORTED');
        assert.equal(Object.hasOwn(error, 'stage'), false);
        stderr.write(`${error.code}\n`); return 2;
      }
    },
  });
  assert.equal(result.code, 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(result.lastStage, 'WINDOWS_ACL');
  assert.deepEqual(await readRecoveryInspectCapture(runDirectory), result);
  assert.equal(fx.state.inspectCalls.length, 1);
  assert.equal(fx.state.applyCalls.length, 0);
});

for (const [name, options] of [
  ['legacy rejection', { inspectResult: rejection('RUNTIME_STATE_UNSUPPORTED') }],
  ['nonempty stderr', { inspectResult: diagnosticRejection('WINDOWS_ACL', { stderr: 'warning' }) }],
  ['trust changed after response', { inspectResult: diagnosticRejection('WINDOWS_ACL'), changeTrustAfterInspect: true }],
  ['wrong exit', { inspectResult: diagnosticRejection('WINDOWS_ACL', { exitCode: 1 }) }],
  ['forged thrown stage', { inspectThrow: Object.assign(new Error('synthetic'), { code: 'RUNTIME_STATE_UNSUPPORTED', stage: 'WINDOWS_ACL' }) }],
]) {
  test(`remote diagnostic provenance: ${name} does not publish a stage`, async (t) => {
    const fx = await fixture(t, options);
    const stages = createRecoveryInspectStageCapture();
    await rejectsCode(stages.run(() => recoveryRemote.inspectRuntimeRecoveryRemote(freezeDeep({
      target: fx.target, operationId: OPERATION_ID, beforeBootMarker: null,
      priorAuthorizedAttempt: null,
      dependencies: { runProcess: fx.runner, sshLockTimeoutMs: 1_000 },
    }))), name === 'legacy rejection' ? 'RUNTIME_STATE_UNSUPPORTED' : 'RUNTIME_INVENTORY_FAILED');
    assert.equal(stages.snapshot(), 'NOT_REPORTED');
  });
}
