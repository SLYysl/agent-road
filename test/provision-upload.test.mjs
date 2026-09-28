import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import { validateWindowsFilePath } from '../src/remote/remote-files.mjs';
import { createRuntimePlan } from '../src/runtime/runtime-plan.mjs';
import { createSignedRuntimeManifest } from '../src/runtime/runtime-manifest.mjs';
import {
  getPreparedProvisionUploadBinding,
  provisionUpload,
  stagePreparedProvisionUploadInSession,
  withPreparedProvisionUpload,
} from '../src/runtime/provision-upload.mjs';
import { decodedPowerShell } from './support/powershell-frame.mjs';
import { provisionFailureStage } from '../src/runtime/provision-diagnostic.mjs';

const DEVICE_ID = 'dev_abc123';
const ADDRESS = '100.64.0.10';
const OPERATION_ID = 'a'.repeat(32);
const CREATED_AT = '2026-07-29T10:00:00.000Z';
const PROBE_OUTPUT = 'AGENT_ROAD_ADMINISTRATOR_OK';
const INIT_OUTPUT = 'AGENT_ROAD_PROVISION_INIT_OK';
const INSPECT_PREFIX = 'AGENT_ROAD_PROVISION_INSPECT:';
const FINALIZED_OUTPUT = 'AGENT_ROAD_PROVISION_FINALIZED';
const CLEANED_OUTPUT = 'AGENT_ROAD_PROVISION_CLEANED';
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

function payloadFromScript(script) {
  const encoded = /FromBase64String\('([^']+)'\)/u.exec(script)?.[1];
  assert.ok(encoded);
  return JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
}

function remotePathFromScp(value) {
  const separator = value.indexOf(':');
  return value.slice(separator + 1);
}

function catalog(artifacts) {
  const ids = artifacts.map(({ id }) => id);
  return {
    schemaVersion: 1,
    catalogRevision: 7,
    platform: { os: 'windows', architecture: 'x64', minimumBuild: 17_763 },
    artifacts: artifacts.map((artifact) => ({
      ...artifact,
      redirectOrigins: [],
      maximumExpandedBytes: artifact.bytes * 4,
      packaging: 'zip',
      signerRule: 'microsoft-corporation',
      verificationCommandId: `${artifact.id}-smoke-test`,
    })),
    profiles: [
      { id: 'core', artifacts: [ids.at(-1)], dependencies: [] },
      { id: 'base', artifacts: ids, dependencies: ['core'] },
    ],
  };
}

function inventory() {
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
  };
}

async function signedCapsule(artifacts) {
  const catalogValue = catalog(artifacts);
  const inventoryValue = inventory();
  const plan = createRuntimePlan({
    catalog: catalogValue,
    requestedProfiles: ['base'],
    inventory: inventoryValue,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    createdAt: CREATED_AT,
  });
  return createSignedRuntimeManifest({
    catalog: catalogValue,
    inventory: inventoryValue,
    plan,
    dependencies: {
      getSigningPublicKey: async () => ({ ...PUBLIC_PAYLOAD }),
      sign: async (bytes) => cryptoSign('RSA-SHA256', bytes, privateKey).toString('base64'),
    },
  });
}

function stagingPaths(capsule, component) {
  const manifest = JSON.parse(capsule.manifestJson);
  const root = `C:/ProgramData/AgentRoad/runtime/staging/${manifest.operationId}/${capsule.manifestDigest}`;
  if (component === null) {
    const capsuleBytes = Buffer.from(JSON.stringify(capsule), 'utf8');
    const capsuleHash = sha(capsuleBytes);
    return {
      root,
      final: `${root}/capsule.json`,
      temp: `${root}/.capsule-${capsuleHash}.upload`,
      bytes: capsuleBytes,
    };
  }
  return {
    root,
    final: `${root}/files/${component.id}-${component.version}.zip`,
    temp: `${root}/files/.${component.id}-${component.version}-${component.sha256}.upload`,
  };
}

async function fixture(t, options = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-provision-upload-')));
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

  const sourceArtifacts = options.artifacts ?? [
    { id: 'mingit', version: '2.50.1', bytes: Buffer.from('mingit fixture bytes\n') },
    { id: 'powershell-7', version: '7.5.2', bytes: Buffer.from('powershell fixture bytes\n') },
  ];
  const catalogArtifacts = [];
  const artifactFiles = [];
  for (const artifact of sourceArtifacts) {
    const path = join(root, `${artifact.id}-${artifact.version}.zip`);
    await writeFile(path, artifact.bytes, { mode: 0o600 });
    const digest = sha(artifact.bytes);
    catalogArtifacts.push({
      id: artifact.id,
      version: artifact.version,
      url: `https://example.com/${artifact.id}-${artifact.version}.zip`,
      bytes: artifact.bytes.length,
      sha256: digest,
    });
    artifactFiles.push({
      artifactId: artifact.id,
      version: artifact.version,
      path,
      bytes: artifact.bytes.length,
      sha256: digest,
    });
  }
  const capsule = await signedCapsule(catalogArtifacts);
  const manifest = JSON.parse(capsule.manifestJson);
  const components = manifest.components;
  const remoteFiles = new Map(options.remoteFiles ?? []);
  const calls = [];
  const scpPaths = [];
  const scripts = [];
  let inspectCalls = 0;
  let cleanupCalls = 0;

  const stateFor = (final, temp, expectedBytes, expectedHash) => {
    const finalBytes = remoteFiles.get(final);
    const tempBytes = remoteFiles.get(temp);
    if (finalBytes && tempBytes) return 'R';
    if (finalBytes) return finalBytes.length === expectedBytes && sha(finalBytes) === expectedHash ? 'F' : 'R';
    if (tempBytes) return tempBytes.length === expectedBytes && sha(tempBytes) === expectedHash ? 'T' : 'R';
    return 'M';
  };

  const target = freezeDeep({
    device: {
      id: DEVICE_ID,
      displayName: 'Ready Windows PC',
      controllerPlatform: 'darwin',
      targetPlatform: 'windows',
      status: 'CONNECTED_SSH_ONLY',
      capabilities: ['ssh', 'sftp', 'admin-powershell'],
      createdAt: CREATED_AT,
      updatedAt: CREATED_AT,
      target: {
        version: '10.0.26200', build: 26_200, edition: 'Home', architecture: 'AMD64',
      },
      transport: {
        tailscaleAddresses: [ADDRESS],
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

  const runProcess = async (command, args, processOptions) => {
    calls.push({ command, args: [...args], options: processOptions });
    if (command === '/usr/bin/ssh-keygen') {
      return processResult({ command, args: [...args], stdout: `256 ${FINGERPRINT} windows-host (ED25519)\n` });
    }
    if (command === '/usr/bin/scp') {
      const source = args.at(-2);
      const destination = remotePathFromScp(args.at(-1));
      scpPaths.push(destination);
      const bytes = await readFile(source);
      if (options.scpThrowAt === scpPaths.length) throw new Error('/private/scp');
      remoteFiles.set(destination, bytes);
      if (options.scpNonzeroAt === scpPaths.length) {
        return processResult({ command, args: [...args], exitCode: 1, stderr: 'private scp failure' });
      }
      return processResult({ command, args: [...args] });
    }

    const script = decodedPowerShell(args.slice(-8), processOptions);
    scripts.push(script);
    if (script.includes(PROBE_OUTPUT)) {
      return processResult({ command, args: [...args], stdout: PROBE_OUTPUT });
    }
    const payload = payloadFromScript(script);
    if (script.includes(INIT_OUTPUT)) {
      if (options.initThrow) throw new Error('/private/init');
      if (options.initNonzero) {
        return processResult({ exitCode: 73, stderr: 'private init failure' });
      }
      return processResult({ command, args: [...args], stdout: INIT_OUTPUT });
    }
    if (script.includes(INSPECT_PREFIX)) {
      inspectCalls += 1;
      if (options.inspectResidue) return processResult({ exitCode: 73, stderr: 'private residue' });
      const states = payload.components.map((component) => {
        const model = {
          id: component.artifactId,
          version: component.version,
          sha256: component.expectedSha256,
        };
        const paths = stagingPaths(capsule, model);
        return stateFor(paths.final, paths.temp, component.expectedBytes, component.expectedSha256);
      });
      const capsulePaths = stagingPaths(capsule, null);
      const capsuleState = stateFor(
        capsulePaths.final,
        capsulePaths.temp,
        payload.capsule.expectedBytes,
        payload.capsule.expectedSha256,
      );
      if (states.includes('R') || capsuleState === 'R') {
        return processResult({ exitCode: 73, stderr: 'private residue' });
      }
      return processResult({
        command,
        args: [...args],
        stdout: `${INSPECT_PREFIX}${states.join(',')}:${capsuleState}`,
      });
    }
    const model = payload.entryType === 'capsule'
      ? null
      : { id: payload.artifactId, version: payload.version, sha256: payload.expectedSha256 };
    const paths = stagingPaths(capsule, model);
    if (script.includes(FINALIZED_OUTPUT)) {
      if (options.finalizeThrow) throw new Error('/private/finalize');
      const temp = remoteFiles.get(paths.temp);
      if (temp) {
        remoteFiles.set(paths.final, temp);
        remoteFiles.delete(paths.temp);
      }
      if (options.mutateTrustAfterCapsuleFinalize && model === null) {
        await writeFile(privateKeyPath, 'CHANGED PRIVATE FIXTURE\n', { mode: 0o600 });
      }
      return processResult({ command, args: [...args], stdout: FINALIZED_OUTPUT });
    }
    assert.match(script, /Remove-Item/u);
    cleanupCalls += 1;
    if (options.cleanupFailure) return processResult({ exitCode: 1, stderr: 'private cleanup' });
    const temp = remoteFiles.get(paths.temp);
    if (temp && temp.length === payload.expectedBytes && sha(temp) === payload.expectedSha256) {
      remoteFiles.delete(paths.temp);
    } else if (temp) {
      return processResult({ exitCode: 1, stderr: 'private unsafe cleanup' });
    }
    return processResult({ command, args: [...args], stdout: CLEANED_OUTPUT });
  };

  const session = Object.freeze({
    addresses: Object.freeze([ADDRESS]),
    invokeSsh(address, remoteArgs, processOptions) {
      return runProcess('/usr/bin/ssh', [`AgentRoad@${address}`, ...remoteArgs], processOptions);
    },
    invokeScp(args, processOptions) {
      return runProcess('/usr/bin/scp', [...args], processOptions);
    },
    invokeCleanup(address, remoteArgs, processOptions) {
      return runProcess('/usr/bin/ssh', [`AgentRoad@${address}`, ...remoteArgs], processOptions);
    },
    remoteSpec(address, path) {
      return `AgentRoad@${address}:${path}`;
    },
  });

  return {
    input: {
      target,
      capsule,
      artifactFiles,
      dependencies: { runProcess, sshLockTimeoutMs: 60_000 },
    },
    capsule,
    components,
    remoteFiles,
    calls,
    scpPaths,
    scripts,
    session,
    counters: {
      get inspect() { return inspectCalls; },
      get cleanup() { return cleanupCalls; },
    },
  };
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    assert.equal(error.cause, undefined);
    assert.deepEqual(Object.keys(error), ['code']);
    assert.doesNotMatch(String(error.stack), /private/u);
    return true;
  });
}

test('stages ID-sorted artifacts through one trusted address and publishes capsule last', async (t) => {
  const f = await fixture(t);
  const result = await provisionUpload(f.input);
  const capsulePaths = stagingPaths(f.capsule, null);

  assert.deepEqual(result, {
    schemaVersion: 1,
    status: 'staged',
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    manifestDigest: f.capsule.manifestDigest,
    generationDigest: f.capsule.generationDigest,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(f.counters.inspect, 2);
  assert.equal(f.scpPaths.length, f.components.length + 1);
  assert.equal(f.scpPaths.at(-1), capsulePaths.temp);
  assert.equal(f.remoteFiles.has(capsulePaths.final), true);
  assert.equal(f.remoteFiles.has(capsulePaths.temp), false);
  for (const component of f.components) {
    const paths = stagingPaths(f.capsule, component);
    assert.equal(f.remoteFiles.has(paths.final), true);
    assert.equal(f.remoteFiles.has(paths.temp), false);
  }
  const remoteTargets = f.calls
    .filter(({ command }) => command === '/usr/bin/ssh')
    .map(({ args }) => args.find((value) => value.startsWith('AgentRoad@')))
    .filter(Boolean);
  assert.equal(remoteTargets.every((value) => value === `AgentRoad@${ADDRESS}`), true);
});

test('prepared upload stages inside the supplied session without a nested lock or address probe', async (t) => {
  const f = await fixture(t);
  let binding;
  const result = await withPreparedProvisionUpload(f.input, async (prepared) => {
    binding = getPreparedProvisionUploadBinding(prepared);
    return stagePreparedProvisionUploadInSession(prepared, f.session, ADDRESS);
  });

  assert.equal(result.status, 'staged');
  assert.deepEqual(binding, {
    schemaVersion: 1,
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    manifestDigest: f.capsule.manifestDigest,
    generationDigest: f.capsule.generationDigest,
    inventoryDigest: JSON.parse(f.capsule.manifestJson).inventoryDigest,
    catalogDigest: JSON.parse(f.capsule.manifestJson).catalogDigest,
    requestedProfiles: ['base'],
    profiles: ['core', 'base'],
    components: JSON.parse(f.capsule.manifestJson).components.map((component) => ({
      id: component.id,
      version: component.version,
      bytes: component.bytes,
      maximumExpandedBytes: component.maximumExpandedBytes,
      sha256: component.sha256,
    })),
  });
  assert.equal(Object.isFrozen(binding), true);
  assert.equal(Object.isFrozen(binding.requestedProfiles), true);
  assert.equal(Object.isFrozen(binding.profiles), true);
  assert.equal(Object.isFrozen(binding.components), true);
  assert.equal(binding.components.every(Object.isFrozen), true);
  assert.equal(
    f.calls.filter(({ command }) => command === '/usr/bin/ssh-keygen').length,
    0,
  );
  assert.equal(f.scripts.some((script) => script.includes(PROBE_OUTPUT)), false);
  assert.equal(f.calls.every(({ args }) => (
    !args.some((value) => typeof value === 'string' && value.startsWith('AgentRoad@'))
    || args.some((value) => value === `AgentRoad@${ADDRESS}`
      || value.startsWith(`AgentRoad@${ADDRESS}:`))
  )), true);
  await assert.rejects(
    stagePreparedProvisionUploadInSession(
      Object.freeze({ schemaVersion: 1 }),
      f.session,
      ADDRESS,
    ),
    { code: 'RUNTIME_INPUT_INVALID' },
  );
});

test('inspects the whole batch before transfer and reconciles exact final/temp states', async (t) => {
  const first = await fixture(t);
  const [firstComponent, secondComponent] = first.components;
  const firstPaths = stagingPaths(first.capsule, firstComponent);
  const secondPaths = stagingPaths(first.capsule, secondComponent);
  const firstBytes = Buffer.from('mingit fixture bytes\n');
  const secondBytes = Buffer.from('powershell fixture bytes\n');
  first.remoteFiles.set(firstPaths.final, firstBytes);
  first.remoteFiles.set(secondPaths.temp, secondBytes);

  await provisionUpload(first.input);

  assert.equal(first.scpPaths.length, 1);
  assert.equal(first.scpPaths[0], stagingPaths(first.capsule, null).temp);
  assert.equal(first.remoteFiles.has(firstPaths.final), true);
  assert.equal(first.remoteFiles.has(secondPaths.final), true);
  const inspectIndexes = first.scripts
    .map((script, index) => (script.includes(INSPECT_PREFIX) ? index : -1))
    .filter((index) => index >= 0);
  const finalizeIndexes = first.scripts
    .map((script, index) => (script.includes(FINALIZED_OUTPUT) ? index : -1))
    .filter((index) => index >= 0);
  assert.equal(inspectIndexes.length, 2);
  assert.ok(finalizeIndexes[0] > inspectIndexes[0]);
  assert.ok(finalizeIndexes.at(-1) > inspectIndexes.at(-1));
});

test('accepts an exact completed capsule without uploading or replacing anything', async (t) => {
  const f = await fixture(t);
  for (const component of f.components) {
    const source = f.input.artifactFiles.find(({ artifactId }) => artifactId === component.id);
    f.remoteFiles.set(stagingPaths(f.capsule, component).final, await readFile(source.path));
  }
  const capsulePaths = stagingPaths(f.capsule, null);
  f.remoteFiles.set(capsulePaths.final, capsulePaths.bytes);

  const result = await provisionUpload(f.input);
  assert.equal(result.status, 'staged');
  assert.deepEqual(f.scpPaths, []);
  assert.equal(f.scripts.filter((script) => script.includes(FINALIZED_OUTPUT)).length, 0);
});

test('rejects capsule signature, device binding, artifact mapping, ordering, and local integrity before SSH', async (t) => {
  const f = await fixture(t);
  const tamperedSignature = { ...f.input, capsule: { ...f.capsule, signatureBase64: 'A'.repeat(512) } };
  await rejectsCode(provisionUpload(tamperedSignature), 'RUNTIME_SIGNATURE_INVALID');

  const manifest = JSON.parse(f.capsule.manifestJson);
  manifest.deviceId = 'dev_other';
  const wrongDevice = { ...f.input, capsule: { ...f.capsule, manifestJson: JSON.stringify(manifest) } };
  await rejectsCode(provisionUpload(wrongDevice), 'RUNTIME_SIGNATURE_INVALID');

  await rejectsCode(provisionUpload({
    ...f.input,
    artifactFiles: [...f.input.artifactFiles].reverse(),
  }), 'RUNTIME_ARTIFACT_INVALID');
  await rejectsCode(provisionUpload({
    ...f.input,
    artifactFiles: f.input.artifactFiles.slice(0, 1),
  }), 'RUNTIME_ARTIFACT_INVALID');
  await rejectsCode(provisionUpload({
    ...f.input,
    artifactFiles: f.input.artifactFiles.map((artifact, index) => (
      index === 0 ? { ...artifact, sha256: 'F'.repeat(64) } : artifact
    )),
  }), 'RUNTIME_ARTIFACT_INVALID');
  await writeFile(f.input.artifactFiles[0].path, 'changed local artifact', { mode: 0o600 });
  await rejectsCode(provisionUpload(f.input), 'RUNTIME_ARTIFACT_INVALID');
  assert.equal(f.calls.length, 0);
});

test('rejects hostile input records and accessors without invoking them or SSH', async (t) => {
  const f = await fixture(t);
  let getterReads = 0;
  const artifact = { ...f.input.artifactFiles[0] };
  Object.defineProperty(artifact, 'path', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('/private/path');
    },
  });
  await rejectsCode(provisionUpload({
    ...f.input,
    artifactFiles: [artifact, f.input.artifactFiles[1]],
  }), 'RUNTIME_ARTIFACT_INVALID');
  assert.equal(getterReads, 0);

  let proxyCalls = 0;
  const proxiedRunProcess = new Proxy(async () => {
    proxyCalls += 1;
    throw new Error('/private/process');
  }, {});
  await rejectsCode(provisionUpload({
    ...f.input,
    dependencies: { ...f.input.dependencies, runProcess: proxiedRunProcess },
  }), 'RUNTIME_INPUT_INVALID');
  assert.equal(proxyCalls, 0);

  const revoked = Proxy.revocable(f.input.capsule, {});
  revoked.revoke();
  await rejectsCode(provisionUpload({ ...f.input, capsule: revoked.proxy }), 'RUNTIME_SIGNATURE_INVALID');
  assert.equal(f.calls.length, 0);
});

test('fails closed on remote residue before any transfer', async (t) => {
  const f = await fixture(t, { inspectResidue: true });
  await rejectsCode(provisionUpload(f.input), 'RUNTIME_STAGE_FAILED');
  assert.deepEqual(f.scpPaths, []);
  assert.equal(f.counters.cleanup, 0);
});

test('does not clean or retry when SCP throws because a writer may remain active', async (t) => {
  const f = await fixture(t, { scpThrowAt: 1 });
  await rejectsCode(provisionUpload(f.input), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(f.scpPaths.length, 1);
  assert.equal(f.counters.cleanup, 0);
});

test('attributes finite failure stage without exposing exception text or changing retry semantics', async (t) => {
  for (const [options, stage] of [[{ initThrow: true }, 'initialize'], [{ inspectResidue: true }, 'inspect'],
    [{ scpThrowAt: 1 }, 'upload'], [{ scpNonzeroAt: 1 }, 'upload'], [{ finalizeThrow: true }, 'finalize'], [{ scpNonzeroAt: 1, cleanupFailure: true }, 'cleanup']]) {
    const f = await fixture(t, options);
    await assert.rejects(provisionUpload(f.input), error => {
      assert.equal(provisionFailureStage(error), stage);
      assert.deepEqual(Object.keys(error), ['code']);
      assert.doesNotMatch(error.message, /private/u);
      return true;
    });
    assert.ok(f.scpPaths.length <= 1);
  }
});

test('cleans only an exact temp after confirmed SCP nonzero and surfaces cleanup uncertainty', async (t) => {
  const cleaned = await fixture(t, { scpNonzeroAt: 1 });
  await rejectsCode(provisionUpload(cleaned.input), 'RUNTIME_STAGE_FAILED');
  assert.equal(cleaned.counters.cleanup, 1);
  assert.equal(cleaned.remoteFiles.has(cleaned.scpPaths[0]), false);

  const uncertain = await fixture(t, { scpNonzeroAt: 1, cleanupFailure: true });
  await rejectsCode(provisionUpload(uncertain.input), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(uncertain.counters.cleanup, 1);
});

test('treats finalization ambiguity as uncertain and never stages the capsule early', async (t) => {
  const f = await fixture(t, { finalizeThrow: true });
  await rejectsCode(provisionUpload(f.input), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(f.scpPaths.length, 1);
  assert.notEqual(f.scpPaths[0], stagingPaths(f.capsule, null).temp);
  assert.equal(f.counters.cleanup, 0);
});

test('distinguishes an unknown init dispatch from a confirmed init rejection', async (t) => {
  const unknown = await fixture(t, { initThrow: true });
  await rejectsCode(provisionUpload(unknown.input), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.deepEqual(unknown.scpPaths, []);

  const rejected = await fixture(t, { initNonzero: true });
  await rejectsCode(provisionUpload(rejected.input), 'RUNTIME_STAGE_FAILED');
  assert.deepEqual(rejected.scpPaths, []);
});

test('treats trusted-session finalization failure after remote completion as uncertain', async (t) => {
  const f = await fixture(t, { mutateTrustAfterCapsuleFinalize: true });
  await rejectsCode(provisionUpload(f.input), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(f.remoteFiles.has(stagingPaths(f.capsule, null).final), true);
});

test('keeps the public remote-file AgentRoad denylist unchanged', () => {
  assert.throws(
    () => validateWindowsFilePath('C:\\ProgramData\\AgentRoad\\runtime\\staging\\x'),
    { code: 'REMOTE_INPUT_INVALID' },
  );
});
