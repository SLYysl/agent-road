import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto';
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import { createSignedRuntimeManifest } from '../src/runtime/runtime-manifest.mjs';
import { digestRuntimeInventory } from '../src/runtime/runtime-inventory.mjs';
import { createRuntimePlan } from '../src/runtime/runtime-plan.mjs';
import { decodedPowerShell } from './support/powershell-frame.mjs';

const controller = await import('../src/runtime/runtime-provision.mjs').catch(() => null);

test('exports the transaction-scoped runtime provision controller', () => {
  assert.equal(typeof controller?.runtimeProvision, 'function');
  assert.equal(typeof controller?.runtimeProvisionFromAuthorizedSources, 'function');
});

const OPERATION_ID = 'a'.repeat(32);
const MANIFEST_DIGEST = 'B'.repeat(64);
const GENERATION_DIGEST = 'C'.repeat(64);
const DEVICE_ID = 'dev_abc123';
const ADDRESS = '100.64.0.10';
const STARTED_AT = '2026-07-29T10:00:00.000Z';
const FINISHED_AT = '2026-07-29T10:00:01.000Z';
const SECOND_ADDRESS = '100.64.0.11';
const PROBE_OUTPUT = 'AGENT_ROAD_ADMINISTRATOR_OK';
const PREFLIGHT_OUTPUT = 'AGENT_ROAD_EXEC_PREFLIGHT_OK';
const VERIFY_OUTPUT = 'AGENT_ROAD_EXEC_VERIFIED';
const EXEC_CLEANUP_OUTPUT = 'AGENT_ROAD_EXEC_CLEANED';
const INIT_OUTPUT = 'AGENT_ROAD_PROVISION_INIT_OK';
const INSPECT_PREFIX = 'AGENT_ROAD_PROVISION_INSPECT:';
const FINALIZED_OUTPUT = 'AGENT_ROAD_PROVISION_FINALIZED';
const STAGE_CLEANUP_OUTPUT = 'AGENT_ROAD_PROVISION_CLEANED';
const CORE_BYTES = Buffer.from('powershell portable fixture\n');
const REQUIRED_FREE_BYTES = 256 * 1024 ** 2 + CORE_BYTES.length + CORE_BYTES.length * 4;
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 3072,
  publicExponent: 0x10001,
});
const publicJwk = publicKey.export({ format: 'jwk' });
const PUBLIC_PAYLOAD = {
  algorithm: 'RSA-SHA256',
  modulusBase64Url: publicJwk.n,
  exponentBase64Url: 'AQAB',
};

function sha(bytes) {
  return createHash('sha256').update(bytes).digest('hex').toUpperCase();
}

function sshString(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

const HOST_BLOB = Buffer.concat([
  sshString(Buffer.from('ssh-ed25519')),
  sshString(Buffer.alloc(32, 23)),
]);
const HOST_KEY = `ssh-ed25519 ${HOST_BLOB.toString('base64')} windows-host`;
const FINGERPRINT = `SHA256:${createHash('sha256').update(HOST_BLOB).digest('base64').replace(/=+$/u, '')}`;

const expectedBinding = Object.freeze({
  deviceId: DEVICE_ID,
  address: ADDRESS,
  operationId: OPERATION_ID,
  manifestDigest: MANIFEST_DIGEST,
  generationDigest: GENERATION_DIGEST,
});

function execution(status, exitCode, failureCode) {
  return {
    schemaVersion: 1,
    operation: 'exec',
    deviceId: DEVICE_ID,
    address: ADDRESS,
    exitCode,
    stdout: JSON.stringify({
      schemaVersion: 1,
      status,
      operationId: OPERATION_ID,
      manifestDigest: MANIFEST_DIGEST,
      generationDigest: GENERATION_DIGEST,
      restartRequired: false,
      failureCode,
    }),
    stderr: '',
    startedAt: STARTED_AT,
    finishedAt: FINISHED_AT,
  };
}

function freezeDeep(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function processResult(overrides = {}) {
  return {
    command: '/usr/bin/ssh',
    args: [],
    exitCode: 0,
    signal: null,
    stdout: '',
    stderr: '',
    ...overrides,
  };
}

function inventory(overrides = {}) {
  return {
    schemaVersion: 1,
    platform: {
      os: 'windows',
      version: '10.0.26200',
      build: 26_200,
      edition: 'Microsoft Windows 11 Home',
      architecture: 'x64',
      windowsPowerShellVersion: '5.1.26100.8655',
      elevated: true,
    },
    freeBytes: 50_000_000_000,
    pendingReboot: false,
    interactiveSession: false,
    runtime: {
      schemaVersion: null,
      catalogRevision: null,
      catalogDigest: null,
      generationDigest: null,
      generationVerified: false,
      pendingOperationId: null,
      restartRequired: false,
    },
    managedArtifacts: [],
    ...overrides,
  };
}

function catalog() {
  return {
    schemaVersion: 1,
    catalogRevision: 7,
    platform: { os: 'windows', architecture: 'x64', minimumBuild: 17_763 },
    artifacts: [{
      id: 'powershell-7',
      version: '7.5.2',
      url: 'https://example.com/powershell-7-7.5.2.zip',
      redirectOrigins: [],
      bytes: CORE_BYTES.length,
      maximumExpandedBytes: CORE_BYTES.length * 4,
      sha256: sha(CORE_BYTES),
      packaging: 'zip',
      signerRule: 'microsoft-corporation',
      verificationCommandId: 'powershell-json-roundtrip',
    }],
    profiles: [
      { id: 'core', artifacts: ['powershell-7'], dependencies: [] },
      { id: 'base', artifacts: ['powershell-7'], dependencies: ['core'] },
    ],
  };
}

function payloadFromScript(script) {
  const encoded = /FromBase64String\('([^']+)'\)/u.exec(script)?.[1];
  assert.ok(encoded, 'fixed wrapper must carry one canonical encoded payload');
  return JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
}

function sshAddress(args) {
  return args.find((value) => value.startsWith('AgentRoad@'))?.slice('AgentRoad@'.length);
}

function scpAddress(value) {
  return /^AgentRoad@([^:]+):/u.exec(value)?.[1];
}

function remotePathFromScp(value) {
  return value.slice(value.indexOf(':') + 1);
}

function stagingPaths(capsule, component = null) {
  const manifest = JSON.parse(capsule.manifestJson);
  const root = `C:/ProgramData/AgentRoad/runtime/staging/${manifest.operationId}/${capsule.manifestDigest}`;
  if (component === null) {
    const bytes = Buffer.from(JSON.stringify(capsule), 'utf8');
    const digest = sha(bytes);
    return {
      final: `${root}/capsule.json`,
      temp: `${root}/.capsule-${digest}.upload`,
      bytes,
      sha256: digest,
    };
  }
  return {
    final: `${root}/files/${component.id}-${component.version}.zip`,
    temp: `${root}/files/.${component.id}-${component.version}-${component.sha256}.upload`,
  };
}

async function fixture(t, options = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-runtime-controller-')));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const identityDirectory = join(root, 'identity', 'devices', DEVICE_ID);
  const privateKeyPath = join(identityDirectory, 'id_ed25519');
  const knownHostsPath = join(root, 'known-hosts', `agent-road-known-hosts-${DEVICE_ID}`);
  const artifactPath = join(root, 'powershell-7-7.5.2.zip');
  await mkdir(identityDirectory, { recursive: true, mode: 0o700 });
  await chmod(join(root, 'identity'), 0o700);
  await chmod(join(root, 'identity', 'devices'), 0o700);
  await chmod(identityDirectory, 0o700);
  await writeFile(privateKeyPath, 'PRIVATE FIXTURE NEVER RETURN\n', { mode: 0o600 });
  await writeFile(artifactPath, CORE_BYTES, { mode: 0o600 });

  const inventoryValue = inventory();
  const catalogValue = catalog();
  const plan = createRuntimePlan({
    catalog: catalogValue,
    requestedProfiles: [],
    inventory: inventoryValue,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    createdAt: STARTED_AT,
  });
  const capsule = await createSignedRuntimeManifest({
    catalog: catalogValue,
    inventory: inventoryValue,
    plan,
    dependencies: {
      getSigningPublicKey: async () => ({ ...PUBLIC_PAYLOAD }),
      sign: async (bytes) => cryptoSign('RSA-SHA256', bytes, privateKey).toString('base64'),
    },
  });
  const manifest = JSON.parse(capsule.manifestJson);
  const component = manifest.components[0];
  const addresses = options.addresses ?? [ADDRESS];
  const target = freezeDeep({
    device: {
      id: DEVICE_ID,
      displayName: 'Ready Windows PC',
      controllerPlatform: 'darwin',
      targetPlatform: 'windows',
      status: 'CONNECTED_SSH_ONLY',
      capabilities: ['ssh', 'sftp', 'admin-powershell'],
      createdAt: STARTED_AT,
      updatedAt: STARTED_AT,
      target: {
        version: '10.0.26200', build: 26_200, edition: 'Home', architecture: 'AMD64',
      },
      transport: {
        tailscaleAddresses: [...addresses],
        sshUsername: 'AgentRoad',
        sshHostKeys: [HOST_KEY],
        sshHostKeyFingerprints: [FINGERPRINT],
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
    events: [],
    probes: [],
    mutations: [],
    remoteFiles: new Map(),
    snapshotSources: [],
    inventoryInvokes: 0,
    provisionInvokes: 0,
    executedTasks: [],
    runtimeScp: 0,
    tamperedSnapshotSources: [],
  };

  const stateFor = (final, temp, expectedBytes, expectedHash) => {
    const finalBytes = state.remoteFiles.get(final);
    const tempBytes = state.remoteFiles.get(temp);
    if (finalBytes && tempBytes) return 'R';
    if (finalBytes) return finalBytes.length === expectedBytes && sha(finalBytes) === expectedHash ? 'F' : 'R';
    if (tempBytes) return tempBytes.length === expectedBytes && sha(tempBytes) === expectedHash ? 'T' : 'R';
    return 'M';
  };

  const runProcess = async (command, args, processOptions) => {
    state.calls.push({ command, args: [...args], options: processOptions });
    if (command === '/usr/bin/ssh-keygen') {
      return processResult({
        command,
        args: [...args],
        stdout: `256 ${FINGERPRINT} windows-host (ED25519)\n`,
      });
    }
    if (command === '/usr/bin/scp') {
      const source = args.at(-2);
      const remote = args.at(-1);
      const address = scpAddress(remote);
      const destination = remotePathFromScp(remote);
      const bytes = await readFile(source);
      state.snapshotSources.push(source);
      state.remoteFiles.set(destination, bytes);
      state.mutations.push(address);
      const uploadedTask = bytes.subarray(0, 2).equals(Buffer.from([0xff, 0xfe]))
        ? bytes.subarray(2).toString('utf16le')
        : bytes.toString('utf8');
      if (destination.startsWith('C:/ProgramData/AgentRoad/runtime/staging/')) {
        state.runtimeScp += 1;
        state.events.push('runtime-upload');
        if (options.tamperUploadSnapshotAfterScp && state.runtimeScp === 1) {
          await rm(source, { force: true });
          await writeFile(source, 'replacement upload snapshot\n', { mode: 0o600 });
          state.tamperedSnapshotSources.push(source);
        }
        if (options.stageAmbiguous && state.runtimeScp === 1) {
          throw Object.assign(new Error('private stage transport detail'), { code: 'EPIPE' });
        }
      }
      if (
        options.tamperProvisionScriptSnapshotAfterScp
        && uploadedTask.includes('Write-AgentRoadResult')
      ) {
        await rm(source, { force: true });
        await writeFile(source, 'replacement provision script snapshot\n', { mode: 0o600 });
        state.tamperedSnapshotSources.push(source);
      }
      return processResult({ command, args: [...args] });
    }

    assert.equal(command, '/usr/bin/ssh');
    const address = sshAddress(args);
    const script = decodedPowerShell(args.slice(-8), processOptions);
    if (script.includes(PROBE_OUTPUT)) {
      state.probes.push(address);
      if (options.firstProbeFailure && address === addresses[0]) {
        throw Object.assign(new Error('private first address failure'), { code: 'ECONNREFUSED' });
      }
      return processResult({ command, args: [...args], stdout: PROBE_OUTPUT });
    }
    const payload = payloadFromScript(script);

    if (script.includes(INIT_OUTPUT)) {
      return processResult({ command, args: [...args], stdout: INIT_OUTPUT });
    }
    if (script.includes(INSPECT_PREFIX)) {
      const paths = stagingPaths(capsule, component);
      const capsulePaths = stagingPaths(capsule);
      const artifactState = stateFor(
        paths.final,
        paths.temp,
        payload.components[0].expectedBytes,
        payload.components[0].expectedSha256,
      );
      const capsuleState = stateFor(
        capsulePaths.final,
        capsulePaths.temp,
        payload.capsule.expectedBytes,
        payload.capsule.expectedSha256,
      );
      return processResult({
        command,
        args: [...args],
        stdout: `${INSPECT_PREFIX}${artifactState}:${capsuleState}`,
      });
    }
    if (script.includes(FINALIZED_OUTPUT)) {
      const model = payload.entryType === 'capsule' ? null : component;
      const paths = stagingPaths(capsule, model);
      const temporary = state.remoteFiles.get(paths.temp);
      if (temporary) {
        state.remoteFiles.set(paths.final, temporary);
        state.remoteFiles.delete(paths.temp);
      }
      return processResult({ command, args: [...args], stdout: FINALIZED_OUTPUT });
    }
    if (script.includes(STAGE_CLEANUP_OUTPUT)) {
      const model = payload.entryType === 'capsule' ? null : component;
      const paths = stagingPaths(capsule, model);
      state.remoteFiles.delete(paths.temp);
      return processResult({ command, args: [...args], stdout: STAGE_CLEANUP_OUTPUT });
    }

    const taskPath = `C:/ProgramData/AgentRoad/tasks/${payload.operationId}.ps1`;
    const resultPath = `C:/ProgramData/AgentRoad/tasks/${payload.operationId}.result.json`;
    const resultTempPath = `${resultPath}.tmp`;
    if (script.includes(PREFLIGHT_OUTPUT)) {
      state.mutations.push(address);
      return processResult({ command, args: [...args], stdout: PREFLIGHT_OUTPUT });
    }
    if (script.includes(VERIFY_OUTPUT)) {
      state.mutations.push(address);
      const bytes = state.remoteFiles.get(taskPath);
      const digest = bytes && sha(bytes);
      if (!bytes || bytes.length !== payload.expectedBytes || digest !== payload.expectedSha256) {
        return processResult({ command, args: [...args], exitCode: 73 });
      }
      return processResult({ command, args: [...args], stdout: VERIFY_OUTPUT });
    }
    if (script.includes(EXEC_CLEANUP_OUTPUT)) {
      state.mutations.push(address);
      state.remoteFiles.delete(taskPath);
      state.remoteFiles.delete(resultPath);
      state.remoteFiles.delete(resultTempPath);
      return processResult({ command, args: [...args], stdout: EXEC_CLEANUP_OUTPUT });
    }
    if (script.includes('$exitPattern=') && script.includes('ReadAllText($resultPath')) {
      state.mutations.push(address);
      const record = state.remoteFiles.get(resultPath);
      if (!record) return processResult({ command, args: [...args], exitCode: 1 });
      const match = /^\{"exitCode":(0|[1-4]),"schemaVersion":1\}$/u.exec(record.toString('utf8'));
      if (match && script.includes('catch{exit 78}')) {
        state.remoteFiles.delete(taskPath);
        state.remoteFiles.delete(resultPath);
        state.remoteFiles.delete(resultTempPath);
      }
      return match
        ? processResult({ command, args: [...args], stdout: match[1] })
        : processResult({ command, args: [...args], exitCode: 1 });
    }

    const taskBytes = state.remoteFiles.get(taskPath);
    const task = taskBytes?.subarray(0, 2).equals(Buffer.from([0xff, 0xfe]))
      ? taskBytes.subarray(2).toString('utf16le')
      : taskBytes?.toString('utf8') ?? '';
    state.executedTasks.push(task);
    state.mutations.push(address);
    if (task.includes('Get-AgentRoadRuntimeStateSnapshot')) {
      state.inventoryInvokes += 1;
      state.events.push('inventory');
      const stdout = JSON.stringify(options.freshInventory ?? inventoryValue);
      state.remoteFiles.set(resultPath, Buffer.from('{"exitCode":0,"schemaVersion":1}', 'utf8'));
      return processResult({ command, args: [...args], stdout });
    }
    assert.match(task, /Write-AgentRoadResult/u);
    state.provisionInvokes += 1;
    state.events.push('apply');
    if (options.applyAmbiguous) {
      throw Object.assign(new Error('private apply transport detail'), { code: 'ECONNRESET' });
    }
    const status = options.provisionStatus ?? 'committed';
    const exitCode = options.provisionExitCode ?? 0;
    const failureCode = options.provisionFailureCode ?? null;
    const stdout = JSON.stringify({
      schemaVersion: 1,
      status,
      operationId: OPERATION_ID,
      manifestDigest: capsule.manifestDigest,
      generationDigest: capsule.generationDigest,
      restartRequired: false,
      failureCode,
    });
    state.remoteFiles.set(
      resultPath,
      Buffer.from(`{"exitCode":${exitCode},"schemaVersion":1}`, 'utf8'),
    );
    if (options.tamperTrustAfterApply) {
      await writeFile(privateKeyPath, 'TAMPERED PRIVATE FIXTURE\n', { mode: 0o600 });
    }
    return processResult({ command, args: [...args], stdout });
  };

  let operationIndex = 0;
  let clockIndex = 0;
  const operationIds = ['1'.repeat(32), '2'.repeat(32)];
  const dependencies = {
    runProcess,
    operationId: () => operationIds[operationIndex++],
    clock: () => new Date(Date.parse(STARTED_AT) + clockIndex++ * 1_000),
    sshLockTimeoutMs: 5_000,
  };
  return {
    input: {
      target,
      plan,
      capsule,
      inventorySnapshot: inventoryValue,
      artifactFiles: [{
        artifactId: 'powershell-7',
        version: component.version,
        path: artifactPath,
        bytes: CORE_BYTES.length,
        sha256: sha(CORE_BYTES),
      }],
      dependencies,
    },
    plan,
    capsule,
    component,
    state,
  };
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error?.code, code);
    assert.equal(error.message, code);
    assert.equal(error.cause, undefined);
    assert.deepEqual(Object.keys(error), ['code']);
    assert.doesNotMatch(String(error.stack), /private/u);
    return true;
  });
}

test('accepts only the exact committed result and returns its bound frozen controller result', () => {
  assert.equal(typeof controller?.parseRuntimeProvisionExecution, 'function');
  const result = controller.parseRuntimeProvisionExecution(
    execution('committed', 0, null),
    expectedBinding,
  );
  assert.deepEqual(result, {
    schemaVersion: 1,
    status: 'committed',
    deviceId: DEVICE_ID,
    address: ADDRESS,
    operationId: OPERATION_ID,
    manifestDigest: MANIFEST_DIGEST,
    generationDigest: GENERATION_DIGEST,
    restartRequired: false,
    failureCode: null,
  });
  assert.equal(Object.isFrozen(result), true);
});

test('enforces the finite exit/status/failure matrix without leaking target output', () => {
  for (const [status, exitCode, failureCode, expectedCode] of [
    ['failed', 1, 'RUNTIME_ALREADY_RUNNING', 'RUNTIME_ALREADY_RUNNING'],
    ['rolled-back', 2, 'RUNTIME_SELF_TEST_FAILED', 'RUNTIME_SELF_TEST_FAILED'],
    ['uncertain', 3, 'RUNTIME_COMPLETION_UNCERTAIN', 'RUNTIME_COMPLETION_UNCERTAIN'],
    ['uncertain', 4, 'RUNTIME_ROLLBACK_INCOMPLETE', 'RUNTIME_ROLLBACK_INCOMPLETE'],
  ]) {
    assert.throws(
      () => controller.parseRuntimeProvisionExecution(
        execution(status, exitCode, failureCode),
        expectedBinding,
      ),
      (error) => error?.code === expectedCode
        && error.message === expectedCode
        && error.cause === undefined,
    );
  }

  for (const invalid of [
    execution('committed', 1, null),
    execution('failed', 0, 'RUNTIME_ALREADY_RUNNING'),
    execution('uncertain', 3, 'RUNTIME_ROLLBACK_INCOMPLETE'),
    { ...execution('committed', 0, null), stderr: 'private target detail' },
    { ...execution('committed', 0, null), stdout: '{"private":"target detail"}' },
    {
      ...execution('committed', 0, null),
      stdout: execution('committed', 0, null).stdout.replace(MANIFEST_DIGEST, 'D'.repeat(64)),
    },
  ]) {
    assert.throws(
      () => controller.parseRuntimeProvisionExecution(invalid, expectedBinding),
      (error) => error?.code === 'RUNTIME_COMPLETION_UNCERTAIN'
        && error.message === 'RUNTIME_COMPLETION_UNCERTAIN'
        && !error.message.includes('private'),
    );
  }
});

test('holds one real trusted session, selects once, and keeps fallback inventory/upload/apply on one address', async (t) => {
  const f = await fixture(t, {
    addresses: [ADDRESS, SECOND_ADDRESS],
    firstProbeFailure: true,
  });

  const result = await controller.runtimeProvision(f.input);

  assert.deepEqual(result, {
    schemaVersion: 1,
    status: 'committed',
    deviceId: DEVICE_ID,
    address: SECOND_ADDRESS,
    operationId: OPERATION_ID,
    manifestDigest: f.capsule.manifestDigest,
    generationDigest: f.capsule.generationDigest,
    restartRequired: false,
    failureCode: null,
  });
  assert.deepEqual(f.state.probes, [ADDRESS, SECOND_ADDRESS]);
  assert.equal(
    f.state.calls.filter(({ command }) => command === '/usr/bin/ssh-keygen').length,
    1,
    'one host-key verification proves one outer trusted session',
  );
  assert.equal(f.state.inventoryInvokes, 1);
  assert.equal(f.state.provisionInvokes, 1);
  assert.equal(f.state.runtimeScp, 2);
  assert.deepEqual(f.state.events, ['inventory', 'runtime-upload', 'runtime-upload', 'apply']);
  assert.equal(f.state.mutations.every((address) => address === SECOND_ADDRESS), true);
  for (const path of f.state.snapshotSources) {
    if (path !== f.input.artifactFiles[0].path) {
      await assert.rejects(access(path), { code: 'ENOENT' });
    }
  }
});

test('executes the exact prebound inventory and provision source snapshots', async (t) => {
  const f = await fixture(t);
  const inventorySource = Buffer.from(
    "function Get-AgentRoadRuntimeStateSnapshot { 'bound inventory source' }\n",
    'utf8',
  );
  const provisionSource = Buffer.from(
    "function Write-AgentRoadResult { 'bound provision source' }\n",
    'utf8',
  );
  const sources = {
    inventoryScriptBytes: Buffer.from(inventorySource),
    provisionScriptBytes: Buffer.from(provisionSource),
  };
  const pending = controller.runtimeProvisionFromAuthorizedSources(f.input, sources);
  sources.inventoryScriptBytes.fill(0);
  sources.provisionScriptBytes.fill(0);
  await pending;

  assert.deepEqual(f.state.executedTasks, [
    inventorySource.toString('utf8'),
    provisionSource.toString('utf8'),
  ]);
});

test('permits above-threshold free-space drift before runtime upload and apply', async (t) => {
  const f = await fixture(t, {
    freshInventory: inventory({ freeBytes: 49_999_999_999 }),
  });

  const result = await controller.runtimeProvision(f.input);

  assert.equal(result.status, 'committed');
  assert.equal(f.state.inventoryInvokes, 1);
  assert.equal(f.state.runtimeScp, 2);
  assert.equal(f.state.provisionInvokes, 1);
  assert.deepEqual(f.state.events, ['inventory', 'runtime-upload', 'runtime-upload', 'apply']);
  assert.equal(
    f.state.calls.filter(({ command }) => command === '/usr/bin/ssh-keygen').length,
    1,
  );
});

test('rejects a pre-upload threshold drop or non-free inventory change with zero upload and apply', async (t) => {
  for (const freshInventory of [
    inventory({ freeBytes: REQUIRED_FREE_BYTES - 1 }),
    inventory({ pendingReboot: true }),
  ]) {
    const f = await fixture(t, { freshInventory });

    await rejectsCode(
      controller.runtimeProvision(f.input),
      'RUNTIME_INVENTORY_CHANGED',
    );

    assert.equal(f.state.inventoryInvokes, 1);
    assert.equal(f.state.runtimeScp, 0);
    assert.equal(f.state.provisionInvokes, 0);
    assert.deepEqual(f.state.events, ['inventory']);
  }
});

test('rejects an inventory snapshot whose exact digest is not plan-bound before SSH', async (t) => {
  const f = await fixture(t);
  const input = {
    ...f.input,
    inventorySnapshot: inventory({ freeBytes: f.input.inventorySnapshot.freeBytes - 1 }),
  };

  await rejectsCode(controller.runtimeProvision(input), 'RUNTIME_INPUT_INVALID');

  assert.equal(f.state.calls.length, 0);
  assert.equal(f.state.inventoryInvokes, 0);
  assert.equal(f.state.runtimeScp, 0);
  assert.equal(f.state.provisionInvokes, 0);
  for (const path of f.state.snapshotSources) {
    await assert.rejects(access(path), { code: 'ENOENT' });
  }
});

test('rejects a below-threshold exact baseline before SSH even when its digest is plan-bound', async (t) => {
  const f = await fixture(t);
  const inventorySnapshot = inventory({ freeBytes: REQUIRED_FREE_BYTES - 1 });
  const plan = {
    ...f.plan,
    inventoryDigest: digestRuntimeInventory(inventorySnapshot),
  };
  assert.equal(plan.inventoryDigest, digestRuntimeInventory(inventorySnapshot));

  await rejectsCode(controller.runtimeProvision({
    ...f.input,
    plan,
    inventorySnapshot,
  }), 'RUNTIME_INPUT_INVALID');

  assert.equal(f.state.calls.length, 0);
  assert.equal(f.state.inventoryInvokes, 0);
  assert.equal(f.state.runtimeScp, 0);
  assert.equal(f.state.provisionInvokes, 0);
  assert.equal(f.state.snapshotSources.length, 0,
    'the bound low baseline must fail before local upload preparation or capsule comparison');
});

test('rejects non-core plans and plan-to-capsule binding mismatches before SSH', async (t) => {
  for (const mutatePlan of [
    (plan) => ({ ...plan, profiles: ['base'] }),
    (plan) => ({ ...plan, inventoryDigest: 'D'.repeat(64) }),
    (plan) => ({
      ...plan,
      items: [{
        ...plan.items[0],
        desired: { ...plan.items[0].desired, version: '7.5.3' },
      }],
    }),
    (plan) => ({
      ...plan,
      requiredFreeBytes: plan.requiredFreeBytes + 1,
      items: [{
        ...plan.items[0],
        desired: { ...plan.items[0].desired, bytes: plan.items[0].desired.bytes + 1 },
      }],
    }),
    (plan) => ({
      ...plan,
      requiredFreeBytes: plan.requiredFreeBytes + 1,
      items: [{
        ...plan.items[0],
        desired: {
          ...plan.items[0].desired,
          maximumExpandedBytes: plan.items[0].desired.maximumExpandedBytes + 1,
        },
      }],
    }),
    (plan) => ({
      ...plan,
      items: [{
        ...plan.items[0],
        desired: { ...plan.items[0].desired, sha256: 'D'.repeat(64) },
      }],
    }),
  ]) {
    const f = await fixture(t);
    const input = { ...f.input, plan: mutatePlan(f.plan) };

    await rejectsCode(controller.runtimeProvision(input), 'RUNTIME_INPUT_INVALID');

    assert.equal(f.state.calls.length, 0);
    assert.equal(f.state.inventoryInvokes, 0);
    assert.equal(f.state.runtimeScp, 0);
    assert.equal(f.state.provisionInvokes, 0);
  }
});

test('rejects an exact-present plan before SSH because this controller is mutation-only', async (t) => {
  const f = await fixture(t);
  const desired = f.plan.items[0].desired;
  const plan = {
    ...f.plan,
    requiredFreeBytes: 0,
    items: [{
      ...f.plan.items[0],
      action: 'present',
      reason: null,
      current: {
        version: desired.version,
        bytes: desired.bytes,
        sha256: desired.sha256,
        verified: true,
      },
      rollbackVersion: null,
    }],
  };

  await rejectsCode(
    controller.runtimeProvision({ ...f.input, plan }),
    'RUNTIME_INPUT_INVALID',
  );

  assert.equal(f.state.calls.length, 0);
  assert.equal(f.state.inventoryInvokes, 0);
  assert.equal(f.state.runtimeScp, 0);
  assert.equal(f.state.provisionInvokes, 0);
});

test('rejects malformed or internally inconsistent core plan details before SSH', async (t) => {
  let proxyTraps = 0;
  const hostileDesired = new Proxy({}, {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('must not run');
    },
  });
  for (const mutatePlan of [
    (plan) => ({ ...plan, createdAt: '2026-07-29T10:00:00Z' }),
    (plan) => ({ ...plan, requiredFreeBytes: plan.requiredFreeBytes + 1 }),
    (plan) => ({
      ...plan,
      items: [{ ...plan.items[0], reason: 'managed-artifact-invalid' }],
    }),
    (plan) => ({
      ...plan,
      items: [{ ...plan.items[0], current: { version: '7.5.1' } }],
    }),
    (plan) => ({
      ...plan,
      items: [{ ...plan.items[0], desired: hostileDesired }],
    }),
  ]) {
    const f = await fixture(t);
    const input = { ...f.input, plan: mutatePlan(f.plan) };

    await rejectsCode(controller.runtimeProvision(input), 'RUNTIME_INPUT_INVALID');

    assert.equal(f.state.calls.length, 0);
    assert.equal(f.state.inventoryInvokes, 0);
    assert.equal(f.state.runtimeScp, 0);
  }
  assert.equal(proxyTraps, 0);
});

test('does not retry an ambiguous runtime upload after mutation dispatch', async (t) => {
  const f = await fixture(t, { stageAmbiguous: true });

  await rejectsCode(
    controller.runtimeProvision(f.input),
    'RUNTIME_COMPLETION_UNCERTAIN',
  );

  assert.equal(f.state.inventoryInvokes, 1);
  assert.equal(f.state.runtimeScp, 1);
  assert.equal(f.state.provisionInvokes, 0);
  assert.deepEqual(f.state.events, ['inventory', 'runtime-upload']);
  assert.equal(f.state.probes.length, 1);
  assert.equal(f.state.mutations.every((address) => address === ADDRESS), true);
});

test('does not retry an ambiguous provisioner invoke after mutation dispatch', async (t) => {
  const f = await fixture(t, { applyAmbiguous: true });

  await rejectsCode(
    controller.runtimeProvision(f.input),
    'RUNTIME_COMPLETION_UNCERTAIN',
  );

  assert.equal(f.state.inventoryInvokes, 1);
  assert.equal(f.state.runtimeScp, 2);
  assert.equal(f.state.provisionInvokes, 1);
  assert.deepEqual(f.state.events, ['inventory', 'runtime-upload', 'runtime-upload', 'apply']);
  assert.equal(f.state.probes.length, 1);
  assert.equal(f.state.mutations.every((address) => address === ADDRESS), true);
});

test('maps post-apply local upload snapshot cleanup failure to completion uncertainty', async (t) => {
  const f = await fixture(t, { tamperUploadSnapshotAfterScp: true });
  t.after(async () => {
    for (const path of f.state.tamperedSnapshotSources) {
      await rm(dirname(path), { recursive: true, force: true });
    }
  });

  await rejectsCode(
    controller.runtimeProvision(f.input),
    'RUNTIME_COMPLETION_UNCERTAIN',
  );

  assert.equal(f.state.provisionInvokes, 1);
  assert.equal(f.state.runtimeScp, 2);
  assert.equal(f.state.tamperedSnapshotSources.length, 1);
});

test('maps post-apply prepared-script cleanup failure to completion uncertainty', async (t) => {
  const f = await fixture(t, { tamperProvisionScriptSnapshotAfterScp: true });
  t.after(async () => {
    for (const path of f.state.tamperedSnapshotSources) {
      await rm(dirname(path), { recursive: true, force: true });
    }
  });

  await rejectsCode(
    controller.runtimeProvision(f.input),
    'RUNTIME_COMPLETION_UNCERTAIN',
  );

  assert.equal(f.state.provisionInvokes, 1);
  assert.equal(f.state.tamperedSnapshotSources.length, 1);
});

test('maps a post-mutation trust finalizer failure to completion uncertainty', async (t) => {
  const f = await fixture(t, { tamperTrustAfterApply: true });

  await rejectsCode(
    controller.runtimeProvision(f.input),
    'RUNTIME_COMPLETION_UNCERTAIN',
  );

  assert.equal(f.state.provisionInvokes, 1);
  assert.equal(f.state.runtimeScp, 2);
  assert.equal(f.state.probes.length, 1);
});

test('preserves a validated finite rolled-back target result after mutation', async (t) => {
  const f = await fixture(t, {
    provisionStatus: 'rolled-back',
    provisionExitCode: 2,
    provisionFailureCode: 'RUNTIME_SELF_TEST_FAILED',
  });

  await rejectsCode(
    controller.runtimeProvision(f.input),
    'RUNTIME_SELF_TEST_FAILED',
  );

  assert.equal(f.state.provisionInvokes, 1);
  assert.equal(f.state.runtimeScp, 2);
  assert.equal(f.state.probes.length, 1);
});

test('does not hide local snapshot cleanup failure behind a validated target rollback', async (t) => {
  const f = await fixture(t, {
    provisionStatus: 'rolled-back',
    provisionExitCode: 2,
    provisionFailureCode: 'RUNTIME_SELF_TEST_FAILED',
    tamperUploadSnapshotAfterScp: true,
  });
  t.after(async () => {
    for (const path of f.state.tamperedSnapshotSources) {
      await rm(dirname(path), { recursive: true, force: true });
    }
  });

  await rejectsCode(
    controller.runtimeProvision(f.input),
    'RUNTIME_COMPLETION_UNCERTAIN',
  );

  assert.equal(f.state.provisionInvokes, 1);
  assert.equal(f.state.runtimeScp, 2);
  assert.equal(f.state.tamperedSnapshotSources.length, 1);
});

test('maps an authenticated rolled-back internal error to finite install failure', async (t) => {
  const f = await fixture(t, {
    provisionStatus: 'rolled-back',
    provisionExitCode: 2,
    provisionFailureCode: 'RUNTIME_INTERNAL_ERROR',
  });
  await rejectsCode(controller.runtimeProvision(f.input), 'RUNTIME_INSTALL_FAILED');
  assert.equal(f.state.provisionInvokes, 1);
});

test('keeps an internal error with a mismatched terminal exit uncertain', async (t) => {
  const f = await fixture(t, {
    provisionStatus: 'rolled-back',
    provisionExitCode: 0,
    provisionFailureCode: 'RUNTIME_INTERNAL_ERROR',
  });
  await rejectsCode(controller.runtimeProvision(f.input), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(f.state.provisionInvokes, 1);
});
