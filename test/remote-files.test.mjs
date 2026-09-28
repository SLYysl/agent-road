import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import {
  getRemoteFile,
  putRemoteFile,
  validateWindowsFilePath,
} from '../src/remote/remote-files.mjs';
import { decodedPowerShell as decodeFramedPowerShell } from './support/powershell-frame.mjs';

const DEVICE_ID = 'dev_abc123';
const FIRST_ADDRESS = '100.64.0.10';
const SECOND_ADDRESS = '100.64.0.11';
const OPERATION_ID = 'a'.repeat(32);
const STARTED_AT = '2026-07-28T00:00:00.000Z';
const FINISHED_AT = '2026-07-28T00:00:01.000Z';
const DESTINATION = 'D:\\work\\site.html';
const STAGING_PATH = `C:/ProgramData/AgentRoad/transfers/${OPERATION_ID}.put.stage`;
const PROBE_OUTPUT = 'AGENT_ROAD_ADMINISTRATOR_OK';
const PREFLIGHT_OUTPUT = 'AGENT_ROAD_PUT_PREFLIGHT_OK';
const PARENT_IDENTITY = '00000001:00000002:00000003';
const REPLACEMENT_PARENT_IDENTITY = '00000001:00000002:00000004';
const PREPARED_MARKER = 'AGENT_ROAD_PUT_PREPARED:';
const PUBLISHED_OUTPUT = 'AGENT_ROAD_PUT_PUBLISHED';
const CLEANED_OUTPUT = 'AGENT_ROAD_PUT_CLEANED';
const GET_SOURCE = 'D:\\work\\dist\\index.html';
const GET_STAGING_PATH = `C:/ProgramData/AgentRoad/transfers/${OPERATION_ID}.get.stage`;
const GET_PREPARED_MARKER = 'AGENT_ROAD_GET_PREPARED:';
const GET_CLEANED_OUTPUT = 'AGENT_ROAD_GET_CLEANED';

function publicationTemp(path, operationId = OPERATION_ID) {
  const separator = path.lastIndexOf('\\');
  return `${path.slice(0, separator)}\\.${path.slice(separator + 1)}.agent-road-${operationId}.tmp`;
}

const TEMP_PATH = publicationTemp(DESTINATION);

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

function decodedPowerShell(args, options) {
  return decodeFramedPowerShell(args.slice(-8), options);
}

function payloadFromScript(script) {
  const payload = /FromBase64String\('([^']+)'\)/u.exec(script)?.[1];
  assert.ok(payload, 'fixed wrapper must contain one encoded canonical payload');
  return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
}

function sshAddress(args) {
  return args.find((arg) => arg.startsWith('AgentRoad@'))?.slice('AgentRoad@'.length);
}

function scpAddress(remote) {
  return /^AgentRoad@([^:]+):/u.exec(remote)?.[1];
}

function remotePathFromScp(remote) {
  return remote.slice(remote.indexOf(':') + 1);
}

async function fixture(t, options = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-remote-put-')));
  await chmod(root, 0o700);
  const identityDirectory = join(root, 'identity', 'devices', DEVICE_ID);
  const privateKeyPath = join(identityDirectory, 'id_ed25519');
  const knownHostsPath = join(root, 'known-hosts', `agent-road-known-hosts-${DEVICE_ID}`);
  const localPath = join(root, options.localName ?? 'site.html');
  await mkdir(identityDirectory, { recursive: true, mode: 0o700 });
  await chmod(join(root, 'identity'), 0o700);
  await chmod(join(root, 'identity', 'devices'), 0o700);
  await chmod(identityDirectory, 0o700);
  await writeFile(privateKeyPath, 'PRIVATE FIXTURE NEVER RETURN\n', { mode: 0o600 });
  const bytes = options.bytes ?? Buffer.from('<h1>Agent Road</h1>\n', 'utf8');
  await writeFile(localPath, bytes, { mode: 0o600 });
  t.after(() => rm(root, { recursive: true, force: true }));

  const addresses = options.addresses ?? [FIRST_ADDRESS];
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
        version: '10.0.26200',
        build: 26200,
        edition: 'Home',
        architecture: 'AMD64',
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
    cleanupAddresses: [],
    cleanupTimeouts: [],
    detachedTemp: null,
    lateWrite: null,
    mutationAddresses: [],
    pendingLateWriter: false,
    replacementDirectoryTouched: false,
    phaseCalls: { preflight: 0, upload: 0, prepare: 0, publish: 0, cleanup: 0 },
    probedAddresses: [],
    remoteFiles: new Map(options.remoteFiles ?? []),
    scripts: [],
    uploadSourcePaths: [],
  };
  const expectedSha256 = createHash('sha256').update(bytes).digest('hex').toUpperCase();

  const resolveDestinationParent = (payload, phase) => {
    if (options.nativeResolverFailure === phase) return null;
    const separator = payload.destinationPath.lastIndexOf('\\');
    const lexicalParent = payload.destinationPath.slice(0, separator);
    return options.longParentByPhase?.[phase] ?? lexicalParent;
  };

  const unsafeResolvedParent = (payload, phase) => {
    const resolvedParent = resolveDestinationParent(payload, phase);
    if (resolvedParent === null) return true;
    const internalRoot = 'C:\\ProgramData\\AgentRoad';
    const folded = resolvedParent.toLowerCase();
    return folded === internalRoot.toLowerCase()
      || folded.startsWith(`${internalRoot.toLowerCase()}\\`);
  };

  const parentIdentity = (phase) => options.parentIdentityByPhase?.[phase]
    ?? (options.parentReplacedBeforePublish && phase !== 'prepare'
      ? REPLACEMENT_PARENT_IDENTITY
      : PARENT_IDENTITY);

  const detachReplacedParent = (tempPath) => {
    if (!options.parentReplacedBeforePublish || state.detachedTemp !== null) return;
    state.detachedTemp = state.remoteFiles.get(tempPath) ?? null;
    state.remoteFiles.delete(tempPath);
  };

  const runner = async (command, args, processOptions) => {
    state.calls.push({ command, args: [...args], options: processOptions });
    if (command === '/usr/bin/ssh-keygen') {
      return processResult({
        command,
        args: [...args],
        stdout: `256 ${FINGERPRINT} windows-host (ED25519)\n`,
      });
    }
    if (command === '/usr/bin/scp') {
      state.phaseCalls.upload += 1;
      const local = args.at(-2);
      const remote = args.at(-1);
      const address = scpAddress(remote);
      state.mutationAddresses.push(address);
      state.uploadSourcePaths.push(local);
      state.remoteFiles.set(remotePathFromScp(remote), await readFile(local));
      if (options.uploadFailure) throw Object.assign(new Error('/private/upload leaked'), { code: 'EPIPE' });
      return processResult({ command, args: [...args] });
    }

    assert.equal(command, '/usr/bin/ssh');
    const address = sshAddress(args);
    const script = decodedPowerShell(args, processOptions);
    state.scripts.push(script);
    if (script.includes(PROBE_OUTPUT)) {
      state.probedAddresses.push(address);
      if (options.firstProbeFailure && address === FIRST_ADDRESS) throw new Error('private probe');
      return processResult({ command, args: [...args], stdout: PROBE_OUTPUT });
    }
    const payload = payloadFromScript(script);
    const stagingPath = `C:/ProgramData/AgentRoad/transfers/${payload.operationId}.put.stage`;
    const tempPath = publicationTemp(payload.destinationPath, payload.operationId);
    state.mutationAddresses.push(address);

    if (script.includes(PREFLIGHT_OUTPUT)) {
      state.phaseCalls.preflight += 1;
      if (options.preflightFailure) return processResult({ exitCode: 1, stderr: 'hidden preflight' });
      if (state.remoteFiles.has(stagingPath)) {
        return processResult({ exitCode: 1, stderr: 'hidden stage collision' });
      }
      return processResult({ command, args: [...args], stdout: PREFLIGHT_OUTPUT });
    }
    if (script.includes(PREPARED_MARKER)) {
      state.phaseCalls.prepare += 1;
      if (options.prepareDisconnect) throw new Error('hidden prepare disconnect');
      if (options.hashMismatch) return processResult({ exitCode: 73, stderr: 'hidden hash' });
      if (unsafeResolvedParent(payload, 'prepare')) return processResult({ exitCode: 74 });
      const destination = state.remoteFiles.get(payload.destinationPath);
      if (
        options.parentMissing
        || options.parentReparse
        || options.ancestorReparse
        || options.aliasToAgentRoad
        || options.destinationDirectory
        || options.destinationReparse
        || (destination !== undefined && !payload.overwrite)
      ) return processResult({ exitCode: 74, stderr: 'hidden path state' });
      const staged = state.remoteFiles.get(stagingPath);
      const actual = staged && createHash('sha256').update(staged).digest('hex').toUpperCase();
      if (!staged || staged.length !== payload.expectedBytes || actual !== payload.expectedSha256) {
        return processResult({ exitCode: 73 });
      }
      state.remoteFiles.set(tempPath, Buffer.from(staged));
      if (options.preparedTempHashMismatch) {
        state.remoteFiles.set(tempPath, Buffer.from('corrupt prepared temp'));
        return processResult({ exitCode: 75 });
      }
      if (options.prepareDisconnectAfterCreate) throw new Error('hidden prepare disconnect');
      if (options.parentIdentityChangesDuringPrepare) return processResult({ exitCode: 76 });
      return processResult({
        command,
        args: [...args],
        stdout: options.preparedOutput ?? `${PREPARED_MARKER}${parentIdentity('prepare')}`,
      });
    }
    if (script.includes(PUBLISHED_OUTPUT)) {
      state.phaseCalls.publish += 1;
      detachReplacedParent(tempPath);
      if (options.publishIntegrityFailure) return processResult({ exitCode: 73 });
      if (
        options.publishPreconditionFailure
        || options.ancestorReparseBeforePublish
        || unsafeResolvedParent(payload, 'publish')
        || payload.expectedParentIdentity !== parentIdentity('publish')
      ) {
        return processResult({ exitCode: 74 });
      }
      const publish = () => {
        const prepared = state.remoteFiles.get(tempPath);
        if (prepared) {
          state.remoteFiles.set(payload.destinationPath, prepared);
          state.remoteFiles.delete(tempPath);
        }
      };
      if (options.publishDisconnect) {
        if (options.lateWriterAfterCleanup) {
          state.pendingLateWriter = true;
        } else publish();
        throw new Error('hidden publish disconnect');
      }
      publish();
      return processResult({ command, args: [...args], stdout: PUBLISHED_OUTPUT });
    }
    assert.match(script, /Remove-Item/u);
    state.phaseCalls.cleanup += 1;
    state.cleanupAddresses.push(address);
    state.cleanupTimeouts.push(processOptions.timeoutMs);
    if (options.cleanupFailure) return processResult({ exitCode: 1, stderr: 'hidden cleanup' });
    if (payload.stagingOwned) {
      const staged = state.remoteFiles.get(stagingPath);
      const stagedHash = staged && createHash('sha256').update(staged).digest('hex').toUpperCase();
      if (staged && (staged.length !== payload.expectedBytes || stagedHash !== payload.expectedSha256)) {
        return processResult({ exitCode: 1, stderr: 'hidden unsafe stage cleanup' });
      }
      state.remoteFiles.delete(stagingPath);
    }
    if (payload.tempOwned) {
      if (payload.expectedParentIdentity !== parentIdentity('cleanup')) {
        return processResult({ exitCode: 1, stderr: 'hidden parent identity mismatch' });
      }
      const temporary = state.remoteFiles.get(tempPath);
      const temporaryHash = temporary
        && createHash('sha256').update(temporary).digest('hex').toUpperCase();
      if (temporary && (
        temporary.length !== payload.expectedBytes
        || temporaryHash !== payload.expectedSha256
      )) return processResult({ exitCode: 1, stderr: 'hidden unsafe temp cleanup' });
      if (options.parentReplacedBeforePublish) state.replacementDirectoryTouched = true;
      state.remoteFiles.delete(tempPath);
    }
    if (state.pendingLateWriter) {
      state.pendingLateWriter = false;
      state.lateWrite = new Promise((resolve) => {
        setImmediate(() => {
          state.remoteFiles.set(tempPath, Buffer.from('late writer residue'));
          resolve();
        });
      });
    }
    return processResult({ command, args: [...args], stdout: CLEANED_OUTPUT });
  };

  const times = [new Date(STARTED_AT), new Date(FINISHED_AT)];
  let clockCalls = 0;
  const dependencies = {
    runProcess: runner,
    operationId: () => OPERATION_ID,
    clock: () => times[clockCalls++],
  };
  const input = {
    target,
    localPath,
    remotePath: options.remotePath ?? DESTINATION,
    overwrite: options.overwrite ?? false,
    dependencies,
  };
  return { bytes, dependencies, expectedSha256, input, localPath, root, state, target };
}

function rejectsCode(operation, code, primaryCode) {
  return assert.rejects(operation, (error) => (
    error?.code === code
    && error.message === code
    && error.cause === undefined
    && (primaryCode === undefined ? error.primaryCode === undefined : error.primaryCode === primaryCode)
    && !String(error.stack).includes('/private/upload leaked')
  ));
}

const INVALID_WINDOWS_PATHS = [
  '',
  'relative.txt',
  'C:',
  'C:\\',
  'c:/work/a.txt',
  '\\\\server\\share\\a',
  '\\\\?\\C:\\a',
  '\\\\.\\C:\\a',
  'C:\\a:stream',
  'C:\\work\\*',
  'C:\\work\\?',
  'C:\\work\\..\\a',
  'C:\\work\\.\\a',
  'C:\\work\\name. ',
  'C:\\work\\name.',
  'C:\\work\\name ',
  'C:\\work\\CON.txt',
  'C:\\work\\aux',
  'C:\\work\\COM1.log',
  'C:\\work\\LPT9',
  'C:\\work\\COM¹',
  'C:\\work\\com².txt',
  'C:\\work\\CoM³.log',
  'D:\\work\\LPT¹',
  'D:\\work\\lpt².bin',
  'D:\\work\\LpT³. ',
  'C:\\ProgramData\\AgentRoad',
  'c:\\programdata\\agentroad\\x',
  'C:\\work\\control\u0001.txt',
  'C:\\work\\double\\\\name.txt',
];

for (const invalid of INVALID_WINDOWS_PATHS) {
  test(`rejects remote path ${JSON.stringify(invalid)}`, () => {
    assert.throws(() => validateWindowsFilePath(invalid), { code: 'REMOTE_INPUT_INVALID' });
  });
}

test('accepts and preserves canonical absolute drive file paths', () => {
  for (const path of ['C:\\file.txt', DESTINATION, 'z:\\one\\two\\three.bin']) {
    assert.equal(validateWindowsFilePath(path), path);
  }
});

test('uploads to internal staging, verifies SHA-256, and publishes once', async (t) => {
  const f = await fixture(t);
  const result = await putRemoteFile(f.input);
  assert.deepEqual(result, {
    schemaVersion: 1,
    operation: 'put',
    deviceId: DEVICE_ID,
    address: FIRST_ADDRESS,
    bytes: f.bytes.length,
    sha256: f.expectedSha256,
    destination: DESTINATION,
    startedAt: STARTED_AT,
    finishedAt: FINISHED_AT,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(f.state.remoteFiles.get(DESTINATION).equals(f.bytes), true);
  assert.equal(f.state.remoteFiles.has(STAGING_PATH), false);
  assert.equal(f.state.remoteFiles.has(TEMP_PATH), false);
  assert.deepEqual(f.state.phaseCalls, { preflight: 1, upload: 1, prepare: 1, publish: 1, cleanup: 1 });
  assert.deepEqual(f.state.cleanupAddresses, [FIRST_ADDRESS]);
  assert.deepEqual(f.state.cleanupTimeouts, [60_000]);
  assert.equal(f.state.mutationAddresses.every((address) => address === FIRST_ADDRESS), true);
  assert.equal(f.state.uploadSourcePaths[0] === f.localPath, false);
});

test('overwrite uses exactly one atomic replacement publication', async (t) => {
  const old = Buffer.from('old destination');
  const f = await fixture(t, { overwrite: true, remoteFiles: [[DESTINATION, old]] });
  await putRemoteFile(f.input);
  assert.equal(f.state.remoteFiles.get(DESTINATION).equals(f.bytes), true);
  assert.equal(f.state.phaseCalls.publish, 1);
  assert.equal(f.state.phaseCalls.upload, 1);
});

test('overwrite also permits a destination that does not yet exist', async (t) => {
  const f = await fixture(t, { overwrite: true });
  await putRemoteFile(f.input);
  assert.equal(f.state.remoteFiles.get(DESTINATION).equals(f.bytes), true);
  assert.equal(f.state.phaseCalls.publish, 1);
});

for (const option of [
  'parentMissing',
  'parentReparse',
  'ancestorReparse',
  'aliasToAgentRoad',
  'destinationDirectory',
  'destinationReparse',
]) {
  test(`rejects unsafe remote destination state: ${option}`, async (t) => {
    const f = await fixture(t, { [option]: true });
    await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
    assert.equal(f.state.phaseCalls.prepare, 1);
    assert.equal(f.state.phaseCalls.publish, 0);
    assert.equal(f.state.phaseCalls.cleanup, 1);
    assert.equal(f.state.remoteFiles.has(DESTINATION), false);
  });
}

test('rechecks the full ancestor chain before final publication', async (t) => {
  const old = Buffer.from('old destination');
  const f = await fixture(t, {
    overwrite: true,
    remoteFiles: [[DESTINATION, old]],
    ancestorReparseBeforePublish: true,
  });
  await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  assert.equal(f.state.phaseCalls.prepare, 1);
  assert.equal(f.state.phaseCalls.publish, 1);
  assert.equal(f.state.remoteFiles.get(DESTINATION).equals(old), true);
  assert.equal(f.state.phaseCalls.cleanup, 1);
});

test('publishes through a normal non-reparse ancestor chain', async (t) => {
  const f = await fixture(t);
  await putRemoteFile(f.input);
  assert.equal(f.state.remoteFiles.get(DESTINATION).equals(f.bytes), true);
});

for (const [name, remotePath] of [
  ['8.3 short alias', 'C:\\ProgramData\\AGENTR~1\\x.txt'],
  ['non-tilde long-name alias', 'C:\\ProgramData\\RoadAlias\\x.txt'],
]) {
  test(`rejects ${name} resolving into the internal AgentRoad tree`, async (t) => {
    const f = await fixture(t, {
      remotePath,
      longParentByPhase: { prepare: 'C:\\ProgramData\\AgentRoad' },
    });
    await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
    assert.equal(f.state.phaseCalls.prepare, 1);
    assert.equal(f.state.phaseCalls.publish, 0);
    assert.equal(f.state.remoteFiles.has(remotePath), false);
  });
}

test('fails closed when native long-path resolution fails', async (t) => {
  const f = await fixture(t, { nativeResolverFailure: 'prepare' });
  await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  assert.equal(f.state.phaseCalls.prepare, 1);
  assert.equal(f.state.phaseCalls.publish, 0);
  assert.equal(f.state.remoteFiles.has(DESTINATION), false);
});

test('repeats long-path resolution before publish and preserves the old destination', async (t) => {
  const remotePath = 'D:\\safe-alias\\site.html';
  const old = Buffer.from('old destination');
  const f = await fixture(t, {
    overwrite: true,
    remotePath,
    remoteFiles: [[remotePath, old]],
    longParentByPhase: {
      prepare: 'D:\\safe-parent',
      publish: 'C:\\ProgramData\\AgentRoad',
    },
  });
  await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  assert.equal(f.state.phaseCalls.prepare, 1);
  assert.equal(f.state.phaseCalls.publish, 1);
  assert.equal(f.state.remoteFiles.get(remotePath).equals(old), true);
});

test('accepts native resolution of a normal parent to the same long path', async (t) => {
  const f = await fixture(t, {
    longParentByPhase: { prepare: 'D:\\work', publish: 'D:\\work' },
  });
  await putRemoteFile(f.input);
  assert.equal(f.state.remoteFiles.get(DESTINATION).equals(f.bytes), true);
});

test('rejects a replaced and recreated parent object before publication without touching it', async (t) => {
  const f = await fixture(t, { parentReplacedBeforePublish: true });
  await rejectsCode(
    putRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.phaseCalls.publish, 1);
  assert.equal(f.state.replacementDirectoryTouched, false);
  assert.equal(f.state.remoteFiles.has(DESTINATION), false);
  assert.equal(f.state.detachedTemp?.equals(f.bytes), true, 'old-parent temp remains recoverable');
});

test('publishes when the same parent path still names the same object', async (t) => {
  const f = await fixture(t, {
    parentIdentityByPhase: {
      prepare: PARENT_IDENTITY,
      publish: PARENT_IDENTITY,
      cleanup: PARENT_IDENTITY,
    },
  });
  await putRemoteFile(f.input);
  assert.equal(f.state.remoteFiles.get(DESTINATION)?.equals(f.bytes), true);
});

test('rejects an existing destination without overwrite', async (t) => {
  const f = await fixture(t, { remoteFiles: [[DESTINATION, Buffer.from('old')]] });
  await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  assert.equal(f.state.remoteFiles.get(DESTINATION).toString(), 'old');
  assert.equal(f.state.phaseCalls.publish, 0);
});

test('maps staged and prepared hash failures to FILE_INTEGRITY_FAILED', async (t) => {
  for (const options of [{ hashMismatch: true }, { publishIntegrityFailure: true }]) {
    const f = await fixture(t, options);
    await rejectsCode(putRemoteFile(f.input), 'FILE_INTEGRITY_FAILED');
    assert.equal(f.state.phaseCalls.upload, 1);
    assert.equal(f.state.phaseCalls.publish, options.publishIntegrityFailure ? 1 : 0);
    assert.equal(f.state.phaseCalls.cleanup, 1);
  }
});

test('falls back only during probes and never retries a mutation phase', async (t) => {
  const f = await fixture(t, {
    addresses: [FIRST_ADDRESS, SECOND_ADDRESS],
    firstProbeFailure: true,
    prepareDisconnect: true,
  });
  await rejectsCode(
    putRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.deepEqual(f.state.probedAddresses, [FIRST_ADDRESS, SECOND_ADDRESS]);
  assert.equal(f.state.mutationAddresses.every((address) => address === SECOND_ADDRESS), true);
  assert.deepEqual(f.state.phaseCalls, { preflight: 1, upload: 1, prepare: 1, publish: 0, cleanup: 1 });
});

for (const options of [
  { preflightFailure: true },
  { publishPreconditionFailure: true },
]) {
  test(`does not retry controlled failure ${Object.keys(options)[0]}`, async (t) => {
    const f = await fixture(t, { addresses: [FIRST_ADDRESS, SECOND_ADDRESS], ...options });
    await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
    assert.equal(f.state.phaseCalls.preflight <= 1, true);
    assert.equal(f.state.phaseCalls.upload <= 1, true);
    assert.equal(f.state.phaseCalls.prepare <= 1, true);
    assert.equal(f.state.phaseCalls.publish <= 1, true);
    assert.equal(f.state.phaseCalls.cleanup, 1);
    assert.equal(f.state.mutationAddresses.every((address) => address === FIRST_ADDRESS), true);
  });
}

for (const options of [
  { uploadFailure: true },
  { prepareDisconnect: true },
]) {
  test(`does not retry uncertain writer ${Object.keys(options)[0]}`, async (t) => {
    const f = await fixture(t, { addresses: [FIRST_ADDRESS, SECOND_ADDRESS], ...options });
    await rejectsCode(
      putRemoteFile(f.input),
      'REMOTE_CLEANUP_UNCERTAIN',
      'FILE_TRANSFER_FAILED',
    );
    assert.equal(f.state.phaseCalls.upload, 1);
    assert.equal(f.state.phaseCalls.prepare <= 1, true);
    assert.equal(f.state.phaseCalls.publish, 0);
    assert.equal(f.state.phaseCalls.cleanup, 1);
    assert.equal(f.state.mutationAddresses.every((address) => address === FIRST_ADDRESS), true);
  });
}

test('a final transport loss is uncertain and an active late writer adds cleanup uncertainty', async (t) => {
  const f = await fixture(t, { publishDisconnect: true, lateWriterAfterCleanup: true });
  await rejectsCode(
    putRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_UNCERTAIN',
  );
  assert.equal(f.state.phaseCalls.publish, 1);
  assert.equal(f.state.phaseCalls.cleanup, 1);
  await f.state.lateWrite;
  assert.equal(f.state.remoteFiles.has(TEMP_PATH), true, 'late writer residue remains uncertain');
});

test('preserves a controlled primary code when cleanup is uncertain', async (t) => {
  const f = await fixture(t, { prepareDisconnect: true, cleanupFailure: true });
  await rejectsCode(
    putRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.phaseCalls.cleanup, 1);
});

test('cleanup uncertainty is primary after an otherwise successful publication', async (t) => {
  const f = await fixture(t, { cleanupFailure: true });
  await rejectsCode(putRemoteFile(f.input), 'REMOTE_CLEANUP_UNCERTAIN');
  assert.equal(f.state.phaseCalls.publish, 1);
  assert.equal(f.state.phaseCalls.cleanup, 1);
});

test('never deletes a pre-existing stage when preflight does not prove ownership', async (t) => {
  const existing = Buffer.from('pre-existing stage');
  const f = await fixture(t, {
    remoteFiles: [[STAGING_PATH, existing]],
  });
  await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  assert.equal(f.state.remoteFiles.get(STAGING_PATH)?.equals(existing), true);
  assert.equal(f.state.phaseCalls.upload, 0);
});

test('a controlled prepare conflict never deletes a pre-existing publication temp', async (t) => {
  const existing = Buffer.from('pre-existing temp');
  const f = await fixture(t, {
    parentMissing: true,
    remoteFiles: [[TEMP_PATH, existing]],
  });
  await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  assert.equal(f.state.remoteFiles.get(TEMP_PATH)?.equals(existing), true);
});

test('prepare transport uncertainty preserves an unconfirmed same-directory temp', async (t) => {
  const existing = Buffer.from('pre-existing temp');
  const f = await fixture(t, {
    prepareDisconnect: true,
    remoteFiles: [[TEMP_PATH, existing]],
  });
  await rejectsCode(
    putRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.remoteFiles.get(TEMP_PATH)?.equals(existing), true);
});

test('prepare transport loss after temp creation leaves it and reports cleanup uncertainty', async (t) => {
  const f = await fixture(t, { prepareDisconnectAfterCreate: true });
  await rejectsCode(
    putRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.remoteFiles.has(TEMP_PATH), true);
  assert.equal(f.state.remoteFiles.has(STAGING_PATH), false);
});

test('prepare rejects a parent identity change around temp creation and leaves ownership unclaimed', async (t) => {
  const f = await fixture(t, { parentIdentityChangesDuringPrepare: true });
  await rejectsCode(
    putRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.phaseCalls.publish, 0);
  assert.equal(f.state.remoteFiles.has(TEMP_PATH), true);
});

test('post-copy temp integrity failure cannot leave residue without cleanup uncertainty', async (t) => {
  const f = await fixture(t, { preparedTempHashMismatch: true });
  await rejectsCode(
    putRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_INTEGRITY_FAILED',
  );
  assert.equal(f.state.phaseCalls.publish, 0);
  assert.equal(f.state.remoteFiles.has(TEMP_PATH), true);
});

test('strictly rejects a malformed prepared identity marker without claiming the temp', async (t) => {
  const f = await fixture(t, { preparedOutput: `${PREPARED_MARKER}not-an-identity` });
  await rejectsCode(
    putRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.phaseCalls.publish, 0);
  assert.equal(f.state.remoteFiles.get(TEMP_PATH)?.equals(f.bytes), true);
});

for (const [name, finishedClock] of [
  ['throws', () => { throw new Error('private clock'); }],
  ['returns an invalid Date', () => new Date(Number.NaN)],
]) {
  test(`maps a clock that ${name} after publication to FILE_TRANSFER_UNCERTAIN`, async (t) => {
    const f = await fixture(t);
    let calls = 0;
    f.input.dependencies.clock = () => (
      calls++ === 0 ? new Date(STARTED_AT) : finishedClock()
    );
    await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_UNCERTAIN');
    assert.equal(f.state.phaseCalls.publish, 1);
    assert.equal(f.state.remoteFiles.get(DESTINATION)?.equals(f.bytes), true);
  });
}

test('maps a noncanonical backwards result interval after publication to uncertainty', async (t) => {
  const f = await fixture(t);
  const times = [new Date(STARTED_AT), new Date('2026-07-27T23:59:59.000Z')];
  let calls = 0;
  f.input.dependencies.clock = () => times[calls++];
  await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_UNCERTAIN');
  assert.equal(f.state.phaseCalls.publish, 1);
  assert.equal(f.state.remoteFiles.get(DESTINATION)?.equals(f.bytes), true);
});

test('rejects unstable local sources and hostile exact input before transport', async (t) => {
  const f = await fixture(t);
  const hard = join(f.root, 'hard.bin');
  const symbolic = join(f.root, 'symbolic.bin');
  await link(f.localPath, hard);
  await symlink(f.localPath, symbolic);

  for (const localPath of [f.localPath, symbolic]) {
    const input = { ...f.input, localPath };
    await rejectsCode(putRemoteFile(input), 'REMOTE_INPUT_INVALID');
  }
  for (const input of [
    { ...f.input, extra: true },
    { ...f.input, overwrite: 'false' },
    new Proxy(f.input, {}),
  ]) await rejectsCode(putRemoteFile(input), 'REMOTE_INPUT_INVALID');
  assert.equal(f.state.probedAddresses.length, 0);
});

test('redacts hostile process results and fixed wrappers contain no caller paths', async (t) => {
  const f = await fixture(t, { preflightFailure: true });
  await rejectsCode(putRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  for (const script of f.state.scripts) {
    assert.doesNotMatch(script, /D:\\work\\site\.html/u);
    assert.doesNotMatch(script, new RegExp(f.localPath.replaceAll('\\', '\\\\'), 'u'));
    assert.doesNotMatch(script, /hidden preflight|PRIVATE FIXTURE/u);
  }
});

async function getFixture(t, options = {}) {
  const bytes = options.bytes ?? Buffer.from('<h1>downloaded through Agent Road</h1>\n', 'utf8');
  const addresses = options.addresses ?? [FIRST_ADDRESS];
  const base = await fixture(t, { bytes, addresses });
  const localPath = join(base.root, 'downloaded.bin');
  if (options.existingLocal !== undefined) {
    await writeFile(localPath, options.existingLocal, { mode: 0o600 });
  }
  if (options.symlinkLocal) {
    const target = join(base.root, 'symlink-target.bin');
    await writeFile(target, 'old target', { mode: 0o600 });
    await symlink(target, localPath);
  }
  if (options.hardlinkLocal) {
    const target = join(base.root, 'hardlink-target.bin');
    await writeFile(target, 'old target', { mode: 0o600 });
    await link(target, localPath);
  }

  const remotePath = options.remotePath ?? GET_SOURCE;
  const remoteFiles = new Map(options.remoteFiles ?? [[remotePath, bytes]]);
  if (options.preexistingSnapshot) {
    remoteFiles.set(GET_STAGING_PATH, Buffer.from('pre-existing remote snapshot'));
  }
  const expectedSha256 = createHash('sha256').update(bytes).digest('hex').toUpperCase();
  const state = {
    cleanupAddresses: [],
    cleanupTimeouts: [],
    downloadedRemotePaths: [],
    localTemporaryPaths: [],
    mutationAddresses: [],
    phaseCalls: { prepare: 0, download: 0, cleanup: 0 },
    probedAddresses: [],
    remoteFiles,
    scripts: [],
    releaseLocalLateWriter: null,
    localLateWrite: null,
  };

  const runner = async (command, args, processOptions) => {
    if (command === '/usr/bin/ssh-keygen') {
      return processResult({
        command,
        args: [...args],
        stdout: `256 ${FINGERPRINT} windows-host (ED25519)\n`,
      });
    }
    if (command === '/usr/bin/scp') {
      state.phaseCalls.download += 1;
      const remote = args.at(-2);
      const temporaryPath = args.at(-1);
      const address = scpAddress(remote);
      state.mutationAddresses.push(address);
      state.downloadedRemotePaths.push(remotePathFromScp(remote));
      state.localTemporaryPaths.push(temporaryPath);
      const staged = state.remoteFiles.get(remotePathFromScp(remote));
      const downloaded = options.shortScp
        ? staged.subarray(0, Math.max(1, staged.length - 1))
        : options.corruptScp
          ? Buffer.from('corrupt download')
          : options.oversizeScp
            ? Buffer.concat([staged, Buffer.from('oversize')])
            : staged;
      await writeFile(temporaryPath, downloaded);
      if (options.localPublicationFailure) {
        await writeFile(localPath, 'concurrent destination', { mode: 0o600 });
      }
      if (options.localCleanupFailure) {
        await unlink(temporaryPath);
        await mkdir(temporaryPath);
      }
      if (options.scpLateWriterAfterCleanup) {
        let release;
        const gate = new Promise((resolve) => { release = resolve; });
        state.releaseLocalLateWriter = release;
        state.localLateWrite = (async () => {
          await gate;
          await writeFile(temporaryPath, 'late local writer residue', { mode: 0o600 });
        })();
        throw new Error('/private/download late writer leaked');
      }
      if (options.scpFailure) throw new Error('/private/download leaked');
      return processResult({ command, args: [...args] });
    }

    assert.equal(command, '/usr/bin/ssh');
    const address = sshAddress(args);
    const script = decodedPowerShell(args, processOptions);
    state.scripts.push(script);
    if (script.includes(PROBE_OUTPUT)) {
      state.probedAddresses.push(address);
      if (options.firstProbeFailure && address === FIRST_ADDRESS) throw new Error('private probe');
      return processResult({ command, args: [...args], stdout: PROBE_OUTPUT });
    }
    const payload = payloadFromScript(script);
    state.mutationAddresses.push(address);
    if (script.includes(GET_PREPARED_MARKER)) {
      state.phaseCalls.prepare += 1;
      if (options.prepareDisconnect) throw new Error('hidden prepare disconnect');
      if (state.remoteFiles.has(GET_STAGING_PATH)) return processResult({ exitCode: 74 });
      if (
        options.remoteMissing
        || options.remoteDirectory
        || options.remoteReparse
        || options.remoteOversized
        || options.remoteUnstable
        || options.sourceAncestorReparse
        || options.sourceAncestorReplacedAfterValidation
        || options.sourceAliasToAgentRoad
      ) return processResult({ exitCode: 73 });
      const source = state.remoteFiles.get(payload.sourcePath);
      if (!source) return processResult({ exitCode: 73 });
      state.remoteFiles.set(GET_STAGING_PATH, Buffer.from(source));
      if (options.prepareDisconnectAfterCreate) throw new Error('hidden prepare disconnect');
      if (options.remoteSnapshotHashMismatch) {
        state.remoteFiles.set(GET_STAGING_PATH, Buffer.from('corrupt remote snapshot'));
      }
      return processResult({
        command,
        args: [...args],
        stdout: options.preparedOutput
          ?? `${GET_PREPARED_MARKER}${source.length}:${expectedSha256}`,
      });
    }
    assert.match(script, /Remove-Item/u);
    state.phaseCalls.cleanup += 1;
    state.cleanupAddresses.push(address);
    state.cleanupTimeouts.push(processOptions.timeoutMs);
    if (options.remoteCleanupFailure) return processResult({ exitCode: 1 });
    if (payload.snapshotOwned) {
      const staged = state.remoteFiles.get(GET_STAGING_PATH);
      const stagedHash = staged
        && createHash('sha256').update(staged).digest('hex').toUpperCase();
      if (staged && (staged.length !== payload.expectedBytes || stagedHash !== payload.expectedSha256)) {
        return processResult({ exitCode: 1 });
      }
      state.remoteFiles.delete(GET_STAGING_PATH);
    }
    return processResult({ command, args: [...args], stdout: GET_CLEANED_OUTPUT });
  };

  const times = [new Date(STARTED_AT), new Date(FINISHED_AT)];
  let clockCalls = 0;
  const dependencies = {
    runProcess: runner,
    operationId: () => OPERATION_ID,
    clock: () => times[clockCalls++],
  };
  const input = {
    target: base.target,
    localPath,
    remotePath,
    overwrite: options.overwrite ?? false,
    dependencies,
  };
  return { bytes, expectedSha256, input, localPath, state };
}

test('downloads a remote snapshot, verifies integrity, and atomically publishes locally', async (t) => {
  const f = await getFixture(t);
  const result = await getRemoteFile(f.input);
  assert.deepEqual(result, {
    schemaVersion: 1,
    operation: 'get',
    deviceId: DEVICE_ID,
    address: FIRST_ADDRESS,
    bytes: f.bytes.length,
    sha256: f.expectedSha256,
    source: GET_SOURCE,
    destination: f.localPath,
    startedAt: STARTED_AT,
    finishedAt: FINISHED_AT,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(await readFile(f.localPath), f.bytes);
  assert.deepEqual(f.state.phaseCalls, { prepare: 1, download: 1, cleanup: 1 });
  assert.deepEqual(f.state.cleanupTimeouts, [60_000]);
  assert.deepEqual(f.state.downloadedRemotePaths, [GET_STAGING_PATH]);
  assert.equal(f.state.localTemporaryPaths[0] === f.localPath, false);
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
});

for (const option of [
  'remoteMissing',
  'remoteDirectory',
  'remoteReparse',
  'remoteOversized',
  'remoteUnstable',
  'sourceAncestorReparse',
  'sourceAliasToAgentRoad',
]) {
  test(`rejects unsafe remote source: ${option}`, async (t) => {
    const f = await getFixture(t, { [option]: true });
    await rejectsCode(getRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
    assert.equal(f.state.phaseCalls.prepare, 1);
    assert.equal(f.state.phaseCalls.download, 0);
    assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
  });
}

test('rejects 8.3 and non-tilde aliases that resolve into the internal tree during get', async (t) => {
  for (const remotePath of [
    'C:\\ProgramData\\AGENTR~1\\secret.bin',
    'C:\\ProgramData\\RoadAlias\\secret.bin',
  ]) {
    const f = await getFixture(t, { remotePath, sourceAliasToAgentRoad: true });
    await rejectsCode(getRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
    assert.equal(f.state.phaseCalls.download, 0);
  }
});

for (const option of ['corruptScp', 'shortScp', 'oversizeScp']) {
  test(`does not publish a ${option} download`, async (t) => {
    const f = await getFixture(t, { [option]: true });
    await rejectsCode(getRemoteFile(f.input), 'FILE_INTEGRITY_FAILED');
    await assert.rejects(readFile(f.localPath), { code: 'ENOENT' });
    assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
  });
}

test('reports integrity plus remote cleanup uncertainty for a swapped remote snapshot', async (t) => {
  const f = await getFixture(t, { remoteSnapshotHashMismatch: true });
  await rejectsCode(
    getRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_INTEGRITY_FAILED',
  );
  await assert.rejects(readFile(f.localPath), { code: 'ENOENT' });
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), true);
});

test('rejects an existing local destination without overwrite and cleans the remote snapshot', async (t) => {
  const old = Buffer.from('old local destination');
  const f = await getFixture(t, { existingLocal: old });
  await rejectsCode(getRemoteFile(f.input), 'REMOTE_INPUT_INVALID');
  assert.deepEqual(await readFile(f.localPath), old);
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
});

test('overwrites one existing regular local destination with verified bytes', async (t) => {
  const f = await getFixture(t, {
    existingLocal: Buffer.from('old local destination'),
    overwrite: true,
  });
  const result = await getRemoteFile(f.input);
  assert.equal(result.operation, 'get');
  assert.deepEqual(await readFile(f.localPath), f.bytes);
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
});

for (const option of ['symlinkLocal', 'hardlinkLocal']) {
  test(`rejects ${option} as a local overwrite target`, async (t) => {
    const f = await getFixture(t, { overwrite: true, [option]: true });
    await rejectsCode(getRemoteFile(f.input), 'REMOTE_INPUT_INVALID');
    assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
  });
}

test('preserves a concurrently created local destination when publication fails', async (t) => {
  const f = await getFixture(t, { localPublicationFailure: true });
  await rejectsCode(getRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  assert.equal((await readFile(f.localPath)).toString(), 'concurrent destination');
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
});

test('remote cleanup uncertainty is primary after a successful local publication', async (t) => {
  const f = await getFixture(t, { remoteCleanupFailure: true });
  await rejectsCode(getRemoteFile(f.input), 'REMOTE_CLEANUP_UNCERTAIN');
  assert.deepEqual(await readFile(f.localPath), f.bytes);
});

test('local cleanup failure preserves an integrity primary', async (t) => {
  const f = await getFixture(t, { corruptScp: true, localCleanupFailure: true });
  await rejectsCode(getRemoteFile(f.input), 'LOCAL_CLEANUP_FAILED', 'FILE_INTEGRITY_FAILED');
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
});

test('combines primary, remote cleanup, and local cleanup failures in stable order', async (t) => {
  const f = await getFixture(t, {
    corruptScp: true,
    localCleanupFailure: true,
    remoteCleanupFailure: true,
  });
  await rejectsCode(
    getRemoteFile(f.input),
    'LOCAL_CLEANUP_FAILED',
    'FILE_INTEGRITY_FAILED:REMOTE_CLEANUP_UNCERTAIN',
  );
});

test('never deletes a pre-existing get snapshot after an operation-id collision', async (t) => {
  const f = await getFixture(t, { preexistingSnapshot: true });
  const existing = Buffer.from(f.state.remoteFiles.get(GET_STAGING_PATH));
  await rejectsCode(getRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  assert.deepEqual(f.state.remoteFiles.get(GET_STAGING_PATH), existing);
});

test('prepare transport uncertainty before creation does not claim or delete the snapshot name', async (t) => {
  const f = await getFixture(t, { prepareDisconnect: true });
  await rejectsCode(
    getRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
});

test('prepare transport uncertainty after creation leaves the unconfirmed snapshot', async (t) => {
  const f = await getFixture(t, { prepareDisconnectAfterCreate: true });
  await rejectsCode(
    getRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), true);
});

test('a malformed prepared marker leaves snapshot ownership uncertain', async (t) => {
  const f = await getFixture(t, { preparedOutput: `${GET_PREPARED_MARKER}1:not-a-hash` });
  await rejectsCode(
    getRemoteFile(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), true);
});

test('an SCP transport failure is attempted once and cleans both owned staging paths', async (t) => {
  const f = await getFixture(t, { scpFailure: true });
  await rejectsCode(
    getRemoteFile(f.input),
    'LOCAL_CLEANUP_FAILED',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.phaseCalls.download, 1);
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
  await assert.rejects(readFile(f.localPath), { code: 'ENOENT' });
});

test('an SCP rejection with a delayed local writer appends only local cleanup uncertainty', async (t) => {
  const f = await getFixture(t, { scpLateWriterAfterCleanup: true });
  await rejectsCode(
    getRemoteFile(f.input),
    'LOCAL_CLEANUP_FAILED',
    'FILE_TRANSFER_FAILED',
  );
  assert.equal(f.state.phaseCalls.cleanup, 1);
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
  await assert.rejects(readFile(f.localPath), { code: 'ENOENT' });
  f.state.releaseLocalLateWriter();
  await f.state.localLateWrite;
  assert.equal((await readFile(f.state.localTemporaryPaths[0])).toString(), 'late local writer residue');
});

test('fails closed when a remote source ancestor is replaced after lexical validation', async (t) => {
  const f = await getFixture(t, { sourceAncestorReplacedAfterValidation: true });
  await rejectsCode(getRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  assert.equal(f.state.phaseCalls.download, 0);
  const prepare = f.state.scripts.find((script) => script.includes(GET_PREPARED_MARKER));
  assert.match(prepare, /GetFinalPathNameByHandleW/u);
  assert.match(prepare, /String\.Equals\(finalPath,source,StringComparison\.OrdinalIgnoreCase\)/u);
});

test('falls back only while probing and fixes one address before remote snapshot creation', async (t) => {
  const f = await getFixture(t, {
    addresses: [FIRST_ADDRESS, SECOND_ADDRESS],
    firstProbeFailure: true,
  });
  await getRemoteFile(f.input);
  assert.deepEqual(f.state.probedAddresses, [FIRST_ADDRESS, SECOND_ADDRESS]);
  assert.equal(f.state.mutationAddresses.every((address) => address === SECOND_ADDRESS), true);
  assert.equal(f.state.phaseCalls.prepare, 1);
  assert.equal(f.state.phaseCalls.download, 1);
});

for (const [name, finishedClock] of [
  ['throws', () => { throw new Error('private clock'); }],
  ['returns an invalid Date', () => new Date(Number.NaN)],
]) {
  test(`maps a get clock that ${name} after publication to FILE_TRANSFER_UNCERTAIN`, async (t) => {
    const f = await getFixture(t);
    let calls = 0;
    f.input.dependencies.clock = () => (
      calls++ === 0 ? new Date(STARTED_AT) : finishedClock()
    );
    await rejectsCode(getRemoteFile(f.input), 'FILE_TRANSFER_UNCERTAIN');
    assert.deepEqual(await readFile(f.localPath), f.bytes);
    assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
  });
}

test('maps a backwards get result interval after publication to FILE_TRANSFER_UNCERTAIN', async (t) => {
  const f = await getFixture(t);
  const times = [new Date(STARTED_AT), new Date('2026-07-27T23:59:59.000Z')];
  let calls = 0;
  f.input.dependencies.clock = () => times[calls++];
  await rejectsCode(getRemoteFile(f.input), 'FILE_TRANSFER_UNCERTAIN');
  assert.deepEqual(await readFile(f.localPath), f.bytes);
  assert.equal(f.state.remoteFiles.has(GET_STAGING_PATH), false);
});

test('fixed get wrappers do not interpolate caller paths and redact child failures', async (t) => {
  const f = await getFixture(t, { remoteMissing: true });
  await rejectsCode(getRemoteFile(f.input), 'FILE_TRANSFER_FAILED');
  for (const script of f.state.scripts) {
    assert.doesNotMatch(script, /D:\\work\\dist\\index\.html/u);
    assert.doesNotMatch(script, new RegExp(f.localPath.replaceAll('\\', '\\\\'), 'u'));
    assert.doesNotMatch(script, /private probe|hidden prepare|private download/u);
  }
});

test('uploads and downloads zero-byte files with their real empty SHA-256', async (t) => {
  const f = await fixture(t, {bytes: Buffer.alloc(0)});
  await putRemoteFile(f.input);
  assert.equal(f.state.remoteFiles.get(DESTINATION).length, 0);
  const g = await getFixture(t, {bytes: Buffer.alloc(0)});
  await getRemoteFile(g.input);
  assert.equal((await readFile(g.input.localPath)).length, 0);
});
