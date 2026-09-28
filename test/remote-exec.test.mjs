import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import {
  executePreparedRemoteScriptInSession,
  executeRemoteScript,
  withPreparedRemoteScript,
  withPreparedRemoteScriptBytes,
} from '../src/remote/remote-exec.mjs';
import {
  decodePowerShellFrame,
  decodedPowerShell as decodeFramedPowerShell,
} from './support/powershell-frame.mjs';

const DEVICE_ID = 'dev_abc123';
const FIRST_ADDRESS = '100.64.0.10';
const SECOND_ADDRESS = '100.64.0.11';
const OPERATION_ID = 'a'.repeat(32);
const STARTED_AT = '2026-07-28T00:00:00.000Z';
const FINISHED_AT = '2026-07-28T00:00:01.000Z';
const REMOTE_PATH = `C:/ProgramData/AgentRoad/tasks/${OPERATION_ID}.ps1`;
const REMOTE_RESULT_PATH = `C:/ProgramData/AgentRoad/tasks/${OPERATION_ID}.result.json`;
const REMOTE_RESULT_TEMP_PATH = `${REMOTE_RESULT_PATH}.tmp`;
const PROBE_OUTPUT = 'AGENT_ROAD_ADMINISTRATOR_OK';
const PREFLIGHT_OUTPUT = 'AGENT_ROAD_EXEC_PREFLIGHT_OK';
const VERIFY_OUTPUT = 'AGENT_ROAD_EXEC_VERIFIED';
const CLEANUP_OUTPUT = 'AGENT_ROAD_EXEC_CLEANED';

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
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-remote-exec-')));
  await chmod(root, 0o700);
  const identityDirectory = join(root, 'identity', 'devices', DEVICE_ID);
  const privateKeyPath = join(identityDirectory, 'id_ed25519');
  const knownHostsPath = join(root, 'known-hosts', `agent-road-known-hosts-${DEVICE_ID}`);
  const scriptPath = join(root, options.scriptName ?? 'task.ps1');
  await mkdir(identityDirectory, { recursive: true, mode: 0o700 });
  await chmod(join(root, 'identity'), 0o700);
  await chmod(join(root, 'identity', 'devices'), 0o700);
  await chmod(identityDirectory, 0o700);
  await writeFile(privateKeyPath, 'PRIVATE FIXTURE NEVER RETURN\n', { mode: 0o600 });
  await writeFile(scriptPath, options.scriptBytes ?? Buffer.from('Write-Output "built"\n', 'utf8'), { mode: 0o600 });
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
      createdAt: '2026-07-28T00:00:00.000Z',
      updatedAt: '2026-07-28T00:00:00.000Z',
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
    cleanedPaths: [],
    cleanupAddresses: [],
    cleanupOptions: null,
    executionCalls: 0,
    executionOptions: null,
    lateResultWritten: null,
    mutationAddresses: [],
    pendingLateResult: null,
    phaseCalls: {
      preflight: 0,
      upload: 0,
      verify: 0,
      invoke: 0,
      readResult: 0,
      cleanup: 0,
    },
    probedAddresses: [],
    remoteFiles: new Map(),
    scripts: [],
    stagedBytes: null,
    uploadSourcePaths: [],
  };
  t.after(async () => {
    for (const directory of new Set(state.uploadSourcePaths.map(dirname))) {
      await rm(directory, { recursive: true, force: true });
    }
  });

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
      const localPath = args.at(-2);
      const remote = args.at(-1);
      const address = scpAddress(remote);
      state.phaseCalls.upload += 1;
      state.mutationAddresses.push(address);
      state.uploadSourcePaths.push(localPath);
      const bytes = await readFile(localPath);
      state.stagedBytes = bytes;
      state.remoteFiles.set(remotePathFromScp(remote), bytes);
      if (options.replaceLocalSnapshotAfterUpload) {
        await unlink(localPath);
        await writeFile(localPath, 'replacement snapshot');
      }
      if (options.uploadFailure) throw Object.assign(new Error('private upload detail'), { code: 'EPIPE' });
      return processResult({ command, args: [...args] });
    }

    assert.equal(command, '/usr/bin/ssh');
    const address = sshAddress(args);
    const script = decodedPowerShell(args, processOptions);
    state.scripts.push(script);
    if (script.includes(PROBE_OUTPUT)) {
      state.probedAddresses.push(address);
      if (options.firstProbeFailure && address === FIRST_ADDRESS) {
        throw Object.assign(new Error('first address unavailable'), { code: 'ECONNREFUSED' });
      }
      return processResult({ command, args: [...args], stdout: PROBE_OUTPUT });
    }
    const payload = payloadFromScript(script);
    const path = `C:/ProgramData/AgentRoad/tasks/${payload.operationId}.ps1`;
    const resultPath = `C:/ProgramData/AgentRoad/tasks/${payload.operationId}.result.json`;
    const resultTempPath = `${resultPath}.tmp`;
    if (script.includes(PREFLIGHT_OUTPUT)) {
      state.phaseCalls.preflight += 1;
      state.mutationAddresses.push(address);
      if (options.preflightFailure) return processResult({ exitCode: 1, stderr: 'hidden preflight detail' });
      return processResult({ command, args: [...args], stdout: PREFLIGHT_OUTPUT });
    }
    if (script.includes(VERIFY_OUTPUT)) {
      state.phaseCalls.verify += 1;
      state.mutationAddresses.push(address);
      if (options.hashMismatch) return processResult({ exitCode: 73, stderr: 'hidden hash detail' });
      const bytes = state.remoteFiles.get(path);
      const sha256 = bytes && createHash('sha256').update(bytes).digest('hex').toUpperCase();
      if (!bytes || bytes.length !== payload.expectedBytes || sha256 !== payload.expectedSha256) {
        return processResult({ exitCode: 73 });
      }
      if (options.replaceAfterVerify) state.remoteFiles.set(path, Buffer.from('replaced after verify'));
      return processResult({ command, args: [...args], stdout: VERIFY_OUTPUT });
    }
    if (script.includes(CLEANUP_OUTPUT)) {
      state.phaseCalls.cleanup += 1;
      state.cleanupAddresses.push(address);
      state.cleanupOptions = processOptions;
      if (options.cleanupFailure) return processResult({ exitCode: 1, stderr: 'hidden cleanup detail' });
      for (const candidate of [path, resultPath, resultTempPath]) {
        if (state.remoteFiles.delete(candidate)) state.cleanedPaths.push(candidate);
      }
      if (state.pendingLateResult) {
        const pending = state.pendingLateResult;
        state.pendingLateResult = null;
        state.lateResultWritten = new Promise((resolve) => {
          setImmediate(() => {
            state.remoteFiles.set(pending.path, pending.bytes);
            resolve();
          });
        });
      }
      return processResult({ command, args: [...args], stdout: CLEANUP_OUTPUT });
    }
    if (script.includes('$exitPattern=') && script.includes('ReadAllText($resultPath')) {
      state.phaseCalls.readResult += 1;
      state.mutationAddresses.push(address);
      if (options.readResultDisconnect) {
        throw Object.assign(new Error('private result read detail'), { code: 'ECONNRESET' });
      }
      const record = state.remoteFiles.get(resultPath);
      if (!record) return processResult({ exitCode: 1, stderr: 'hidden missing result' });
      const text = Buffer.from(record).toString('utf8');
      const match = /^\{"exitCode":(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5]),"schemaVersion":1\}$/u.exec(text);
      if (!match) return processResult({ exitCode: 1, stderr: 'hidden malformed result' });
      if (script.includes('catch{exit 78}')) {
        state.phaseCalls.cleanup += 1;
        state.cleanupAddresses.push(address);
        state.cleanupOptions = processOptions;
        if (options.finalizeCleanupFailure) return processResult({ exitCode: 78 });
        for (const candidate of [path, resultPath, resultTempPath]) {
          if (state.remoteFiles.delete(candidate)) state.cleanedPaths.push(candidate);
        }
        if (options.finalizeResponseLost) throw new Error('response lost after cleanup');
      }
      return processResult({ command, args: [...args], stdout: match[1] });
    }

    assert.match(script, /\$started=\$child\.Start\(\)/u);
    state.phaseCalls.invoke += 1;
    state.mutationAddresses.push(address);
    state.executionOptions = processOptions;
    if (options.parentAclDriftBeforeInvoke) return processResult({ exitCode: 75 });
    const bytes = state.remoteFiles.get(path);
    const sha256 = bytes && createHash('sha256').update(bytes).digest('hex').toUpperCase();
    if (!bytes || bytes.length !== payload.expectedBytes || sha256 !== payload.expectedSha256) {
      return processResult({ exitCode: 74 });
    }
    state.executionCalls += 1;
    if (options.executionError) {
      if (options.lateResultAfterCleanup) {
        state.pendingLateResult = {
          path: resultPath,
          bytes: Buffer.from('{"exitCode":0,"schemaVersion":1}', 'utf8'),
        };
      }
      throw options.executionError;
    }
    const remoteExitCode = options.remoteExitCode ?? 0;
    const record = options.resultRecord
      ?? `{"exitCode":${remoteExitCode},"schemaVersion":1}`;
    if (!options.resultMissing) state.remoteFiles.set(resultPath, Buffer.from(record, 'utf8'));
    return processResult({
      command,
      args: [...args],
      stdout: 'built\r\n',
      ...options.executionTransportResult,
    });
  };

  const times = options.times ?? [new Date(STARTED_AT), new Date(FINISHED_AT)];
  let clockCalls = 0;
  const dependencies = {
    runProcess: runner,
    operationId: options.operationIdDependency ?? (() => options.operationId ?? OPERATION_ID),
    clock: options.clock ?? (() => times[clockCalls++]),
  };
  if (Object.hasOwn(options, 'sshLockTimeoutMs')) {
    dependencies.sshLockTimeoutMs = options.sshLockTimeoutMs;
  }
  const input = {
    target,
    scriptPath,
    dependencies,
  };
  if (!options.omitTimeout) input.timeoutMs = options.timeoutMs ?? 300_000;
  const session = Object.freeze({
    addresses: Object.freeze([...addresses]),
    invokeSsh(address, remoteArgs, processOptions) {
      return runner('/usr/bin/ssh', [`AgentRoad@${address}`, ...remoteArgs], processOptions);
    },
    invokeScp(args, processOptions) {
      return runner('/usr/bin/scp', [...args], processOptions);
    },
    invokeCleanup(address, remoteArgs, processOptions) {
      return runner('/usr/bin/ssh', [`AgentRoad@${address}`, ...remoteArgs], processOptions);
    },
    remoteSpec(address, path) {
      return `AgentRoad@${address}:${path}`;
    },
  });
  return { root, target, scriptPath, input, dependencies, session, state };
}

function rejectsCode(operation, code, primaryCode) {
  return assert.rejects(operation, (error) => (
    error?.code === code
    && error.message === code
    && error.cause === undefined
    && (primaryCode === undefined ? error.primaryCode === undefined : error.primaryCode === primaryCode)
  ));
}

function assertSingleMutationAttempt(state) {
  for (const count of Object.values(state.phaseCalls)) assert.ok(count <= 1);
  assert.equal(state.phaseCalls.cleanup, 1);
  assert.equal(
    state.calls.filter(({ command }) => command === '/usr/bin/scp').length,
    state.phaseCalls.upload,
  );
  assert.equal(state.mutationAddresses.every((address) => address === FIRST_ADDRESS), true);
}

test('executes one staged script on the selected address and returns frozen structured output', async (t) => {
  const f = await fixture(t);
  const result = await executeRemoteScript(f.input);
  assert.deepEqual(result, {
    schemaVersion: 1,
    operation: 'exec',
    deviceId: DEVICE_ID,
    address: FIRST_ADDRESS,
    exitCode: 0,
    stdout: 'built\r\n',
    stderr: '',
    startedAt: STARTED_AT,
    finishedAt: FINISHED_AT,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(f.state.executionCalls, 1);
  assert.equal(f.state.executionOptions.timeoutMs, 300_000);
  assert.equal(f.state.executionOptions.maxOutputBytes, 4 * 1024 * 1024);
  assert.match(
    decodePowerShellFrame(f.state.executionOptions.stdinText),
    /\$child\.StandardInput\.Close\(\);\$child\.WaitForExit\(\)/u,
  );
  assert.deepEqual(f.state.phaseCalls, {
    preflight: 1,
    upload: 1,
    verify: 1,
    invoke: 1,
    readResult: 1,
    cleanup: 1,
  });
  assert.equal(f.state.cleanupOptions.timeoutMs, 60_000);
  assert.equal(f.state.cleanupOptions.maxOutputBytes, 4096);
  assert.deepEqual(new Set(f.state.cleanedPaths), new Set([REMOTE_PATH, REMOTE_RESULT_PATH]));
  assert.equal(f.state.remoteFiles.size, 0);
  assert.deepEqual(f.state.cleanupAddresses, [FIRST_ADDRESS]);
  for (const path of f.state.uploadSourcePaths) await assert.rejects(access(path), { code: 'ENOENT' });
});

test('prepared script executes inside the supplied session and address without a nested lock or probe', async (t) => {
  const f = await fixture(t);
  const result = await withPreparedRemoteScript(f.input, async (prepared) => (
    executePreparedRemoteScriptInSession(prepared, f.session, FIRST_ADDRESS)
  ));

  assert.equal(result.deviceId, DEVICE_ID);
  assert.equal(result.address, FIRST_ADDRESS);
  assert.deepEqual(f.state.probedAddresses, []);
  assert.equal(
    f.state.calls.filter(({ command }) => command === '/usr/bin/ssh-keygen').length,
    0,
  );
  assert.equal(f.state.mutationAddresses.every((address) => address === FIRST_ADDRESS), true);
  assert.deepEqual(f.state.phaseCalls, {
    preflight: 1,
    upload: 1,
    verify: 1,
    invoke: 1,
    readResult: 1,
    cleanup: 1,
  });
});

test('prepared execution accepts immutable in-memory script bytes without rereading a path', async (t) => {
  const f = await fixture(t);
  const source = Buffer.from("Write-Output 'bound source bytes'\n", 'utf8');
  const { scriptPath: _scriptPath, ...withoutPath } = f.input;
  const input = { ...withoutPath, scriptBytes: Buffer.from(source) };
  const pending = withPreparedRemoteScriptBytes(input, async (prepared) => (
    executePreparedRemoteScriptInSession(prepared, f.session, FIRST_ADDRESS)
  ));
  input.scriptBytes.fill(0);
  await pending;

  assert.deepEqual(
    f.state.stagedBytes,
    Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(source.toString('utf8'), 'utf16le')]),
  );
});

test('prepared runtime provision script uses only the dedicated canonical child stdin wrapper', async (t) => {
  const f = await fixture(t);
  const runtimeTransaction = {
    operationId: 'b'.repeat(32),
    manifestDigest: 'B'.repeat(64),
  };
  await withPreparedRemoteScript(
    f.input,
    async (prepared) => executePreparedRemoteScriptInSession(
      prepared,
      f.session,
      FIRST_ADDRESS,
    ),
    { runtimeTransaction },
  );

  const invoke = decodePowerShellFrame(f.state.executionOptions.stdinText);
  assert.match(invoke, /\$child\.StandardInput\.BaseStream\.Write\(\$childInputBytes,0,\$childInputBytes\.Length\)/u);
  assert.match(invoke, /\$payload\.runtimeOperationId/u);
  assert.match(invoke, /\$payload\.manifestDigest/u);
  assert.doesNotMatch(invoke, new RegExp(runtimeTransaction.operationId, 'u'));
  assert.doesNotMatch(invoke, new RegExp(runtimeTransaction.manifestDigest, 'u'));

  for (const invalid of [
    { operationId: 'B'.repeat(32), manifestDigest: 'B'.repeat(64) },
    { operationId: 'b'.repeat(32), manifestDigest: 'b'.repeat(64) },
    { ...runtimeTransaction, extra: true },
    new Proxy(runtimeTransaction, {}),
  ]) {
    await assert.rejects(
      withPreparedRemoteScript(f.input, async () => {}, { runtimeTransaction: invalid }),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
});

test('returns a completed nonzero script exit with raw bounded output', async (t) => {
  const f = await fixture(t, {
    remoteExitCode: 7,
    executionTransportResult: { stdout: 'partial', stderr: 'script failed' },
  });
  const result = await executeRemoteScript(f.input);
  assert.equal(result.exitCode, 7);
  assert.equal(result.stdout, 'partial');
  assert.equal(result.stderr, 'script failed');
  assert.equal(f.state.remoteFiles.size, 0);
});

test('returns a legitimate completed script exit 255 from the result sidecar', async (t) => {
  const f = await fixture(t, {
    remoteExitCode: 255,
    executionTransportResult: { stdout: 'completed 255', stderr: '' },
  });
  const result = await executeRemoteScript(f.input);
  assert.equal(result.exitCode, 255);
  assert.equal(result.stdout, 'completed 255');
  assert.equal(f.state.executionCalls, 1);
  assert.equal(f.state.phaseCalls.readResult, 1);
  assert.equal(f.state.remoteFiles.size, 0);
});

test('converts valid UTF-8 to deterministic UTF-16LE with a BOM', async (t) => {
  const source = 'Write-Output "你好 café"\n';
  const f = await fixture(t, { scriptBytes: Buffer.from(source, 'utf8') });
  await executeRemoteScript(f.input);
  assert.deepEqual(f.state.stagedBytes.subarray(0, 2), Buffer.from([0xff, 0xfe]));
  assert.equal(f.state.stagedBytes.subarray(2).toString('utf16le'), source);
});

test('falls back only when the first read-only address probe fails', async (t) => {
  const f = await fixture(t, {
    addresses: [FIRST_ADDRESS, SECOND_ADDRESS],
    firstProbeFailure: true,
  });
  const result = await executeRemoteScript(f.input);
  assert.equal(result.address, SECOND_ADDRESS);
  assert.deepEqual(f.state.probedAddresses, [FIRST_ADDRESS, SECOND_ADDRESS]);
  assert.equal(f.state.mutationAddresses.every((address) => address === SECOND_ADDRESS), true);
  assert.deepEqual(f.state.cleanupAddresses, [SECOND_ADDRESS]);
});

test('does not fall back after staging starts or retry a failed upload', async (t) => {
  const f = await fixture(t, { addresses: [FIRST_ADDRESS, SECOND_ADDRESS], uploadFailure: true });
  await rejectsCode(executeRemoteScript(f.input), 'FILE_TRANSFER_FAILED');
  assert.deepEqual(f.state.probedAddresses, [FIRST_ADDRESS]);
  assert.equal(f.state.mutationAddresses.every((address) => address === FIRST_ADDRESS), true);
  assert.equal(f.state.executionCalls, 0);
  assert.deepEqual(f.state.cleanupAddresses, [FIRST_ADDRESS]);
  assertSingleMutationAttempt(f.state);
});

test('does not retry a failed preflight on a second address', async (t) => {
  const f = await fixture(t, { addresses: [FIRST_ADDRESS, SECOND_ADDRESS], preflightFailure: true });
  await rejectsCode(executeRemoteScript(f.input), 'FILE_TRANSFER_FAILED');
  assert.deepEqual(f.state.probedAddresses, [FIRST_ADDRESS]);
  assert.equal(f.state.phaseCalls.preflight, 1);
  assert.equal(f.state.phaseCalls.upload, 0);
  assertSingleMutationAttempt(f.state);
});

test('same invoke wrapper rehash blocks a staged replacement before child start', async (t) => {
  const f = await fixture(t, { addresses: [FIRST_ADDRESS, SECOND_ADDRESS], replaceAfterVerify: true });
  await rejectsCode(executeRemoteScript(f.input), 'FILE_INTEGRITY_FAILED');
  assert.equal(f.state.phaseCalls.verify, 1);
  assert.equal(f.state.phaseCalls.invoke, 1);
  assert.equal(f.state.executionCalls, 0);
  assert.equal(f.state.phaseCalls.readResult, 0);
  assert.equal(f.state.phaseCalls.cleanup, 1);
  assert.equal(f.state.remoteFiles.size, 0);
  assertSingleMutationAttempt(f.state);
});

test('invoke wrapper parent ACL drift is a pre-execution transfer failure', async (t) => {
  const f = await fixture(t, {
    addresses: [FIRST_ADDRESS, SECOND_ADDRESS],
    parentAclDriftBeforeInvoke: true,
  });
  await rejectsCode(executeRemoteScript(f.input), 'FILE_TRANSFER_FAILED');
  assert.equal(f.state.executionCalls, 0);
  assert.equal(f.state.phaseCalls.readResult, 0);
  assert.equal(f.state.phaseCalls.cleanup, 1);
  assertSingleMutationAttempt(f.state);
});

test('maps a remote staged-byte hash mismatch to FILE_INTEGRITY_FAILED and cleans it', async (t) => {
  const f = await fixture(t, { addresses: [FIRST_ADDRESS, SECOND_ADDRESS], hashMismatch: true });
  await rejectsCode(executeRemoteScript(f.input), 'FILE_INTEGRITY_FAILED');
  assert.equal(f.state.executionCalls, 0);
  assert.equal(f.state.remoteFiles.size, 0);
  assertSingleMutationAttempt(f.state);
});

for (const [name, resultOptions] of [
  ['missing', { resultMissing: true }],
  ['malformed', { resultRecord: '{"exitCode":255,"schemaVersion":2}' }],
  ['read disconnect', { readResultDisconnect: true }],
]) {
  test(`maps ${name} result sidecar to REMOTE_EXECUTION_UNCERTAIN without retry`, async (t) => {
    const f = await fixture(t, { addresses: [FIRST_ADDRESS, SECOND_ADDRESS], ...resultOptions });
    await rejectsCode(executeRemoteScript(f.input), 'REMOTE_EXECUTION_UNCERTAIN');
    assert.equal(f.state.executionCalls, 1);
    assert.equal(f.state.phaseCalls.invoke, 1);
    assert.equal(f.state.phaseCalls.readResult, 1);
    assert.equal(f.state.remoteFiles.size, 0);
    assertSingleMutationAttempt(f.state);
  });
}

test('preserves transfer failure when local snapshot close also detects replacement', async (t) => {
  const f = await fixture(t, {
    uploadFailure: true,
    replaceLocalSnapshotAfterUpload: true,
  });
  await rejectsCode(executeRemoteScript(f.input), 'LOCAL_CLEANUP_FAILED', 'FILE_TRANSFER_FAILED');
  assert.equal(f.state.remoteFiles.size, 0);
  assertSingleMutationAttempt(f.state);
});

for (const [name, executionError] of [
  ['timeout', Object.assign(new Error('private timeout detail'), { code: 'PROCESS_TIMEOUT' })],
  ['output overflow', Object.assign(new Error('private output detail'), { code: 'PROCESS_OUTPUT_LIMIT' })],
  ['disconnect', Object.assign(new Error('private disconnect detail'), { code: 'ECONNRESET' })],
]) {
  test(`marks cleanup uncertain when ${name} leaves the remote invoke writer potentially active`, async (t) => {
    const f = await fixture(t, {
      addresses: [FIRST_ADDRESS, SECOND_ADDRESS],
      executionError,
      lateResultAfterCleanup: true,
    });
    await rejectsCode(
      executeRemoteScript(f.input),
      'REMOTE_CLEANUP_UNCERTAIN',
      'REMOTE_EXECUTION_UNCERTAIN',
    );
    assert.ok(f.state.lateResultWritten);
    await f.state.lateResultWritten;
    assert.equal(f.state.executionCalls, 1);
    assert.equal(f.state.mutationAddresses.every((address) => address === FIRST_ADDRESS), true);
    assert.equal(f.state.remoteFiles.has(REMOTE_RESULT_PATH), true);
    assertSingleMutationAttempt(f.state);
  });
}

test('maps a returned output overflow after execution starts to REMOTE_EXECUTION_UNCERTAIN', async (t) => {
  const f = await fixture(t, {
    executionTransportResult: { stdout: 'x'.repeat(4 * 1024 * 1024), stderr: 'x' },
  });
  await rejectsCode(executeRemoteScript(f.input), 'REMOTE_EXECUTION_UNCERTAIN');
  assert.equal(f.state.remoteFiles.size, 0);
});

test('preserves the primary execution code when fixed-address cleanup also fails', async (t) => {
  const f = await fixture(t, {
    executionError: Object.assign(new Error('private timeout detail'), { code: 'PROCESS_TIMEOUT' }),
    cleanupFailure: true,
  });
  await rejectsCode(
    executeRemoteScript(f.input),
    'REMOTE_CLEANUP_UNCERTAIN',
    'REMOTE_EXECUTION_UNCERTAIN',
  );
  assert.equal(f.state.remoteFiles.size, 1);
});

test('uses default timeout and strictly rejects input, dependency, id, and timeout boundaries', async (t) => {
  const defaulted = await fixture(t, { omitTimeout: true });
  await executeRemoteScript(defaulted.input);
  assert.equal(defaulted.state.executionOptions.timeoutMs, 300_000);

  for (const timeoutMs of [999, 1_800_001, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const f = await fixture(t, { timeoutMs });
    await rejectsCode(executeRemoteScript(f.input), 'REMOTE_INPUT_INVALID');
    assert.equal(f.state.calls.length, 0);
  }
  for (const operationId of ['A'.repeat(32), 'a'.repeat(31), 'g'.repeat(32)]) {
    const f = await fixture(t, { operationId });
    await rejectsCode(executeRemoteScript(f.input), 'REMOTE_INPUT_INVALID');
    assert.equal(f.state.calls.length, 0);
  }
  for (const sshLockTimeoutMs of [999, 900_001, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const f = await fixture(t, { sshLockTimeoutMs });
    await rejectsCode(executeRemoteScript(f.input), 'REMOTE_INPUT_INVALID');
    assert.equal(f.state.calls.length, 0);
  }

  const f = await fixture(t);
  const hostileInput = { ...f.input };
  let getterCalls = 0;
  Object.defineProperty(hostileInput, 'scriptPath', {
    enumerable: true,
    get() { getterCalls += 1; throw new Error('accessor executed'); },
  });
  await rejectsCode(executeRemoteScript(hostileInput), 'REMOTE_INPUT_INVALID');
  await rejectsCode(executeRemoteScript(new Proxy(f.input, {})), 'REMOTE_INPUT_INVALID');
  await rejectsCode(executeRemoteScript({ ...f.input, extra: true }), 'REMOTE_INPUT_INVALID');
  await rejectsCode(executeRemoteScript({
    ...f.input,
    dependencies: new Proxy(f.dependencies, {}),
  }), 'REMOTE_INPUT_INVALID');
  assert.equal(getterCalls, 0);
});

test('passes an explicit bounded trust-lock wait without starting a remote process', async (t) => {
  const f = await fixture(t, { sshLockTimeoutMs: 1_000 });
  await writeFile(`${f.target.identity.privateKeyPath}.lock`, `${JSON.stringify({
    owner: 'occupied-by-test',
    pid: process.pid,
    createdAt: new Date().toISOString(),
  })}\n`, { mode: 0o600 });

  const started = Date.now();
  await rejectsCode(executeRemoteScript(f.input), 'REMOTE_CONNECTION_FAILED');

  assert.ok(Date.now() - started < 3_000);
  assert.equal(f.state.calls.length, 0);
});

test('rejects invalid script text before spawning and bounds result/time fields', async (t) => {
  for (const scriptBytes of [Buffer.from([0xc3, 0x28]), Buffer.from('bad\0script', 'utf8')]) {
    const f = await fixture(t, { scriptBytes });
    await rejectsCode(executeRemoteScript(f.input), 'REMOTE_INPUT_INVALID');
    assert.equal(f.state.calls.length, 0);
  }

  const badTime = await fixture(t, { times: [new Date(FINISHED_AT), new Date(STARTED_AT)] });
  await rejectsCode(executeRemoteScript(badTime.input), 'REMOTE_INPUT_INVALID');
  assert.equal(badTime.state.executionCalls, 1);
  assert.equal(badTime.state.remoteFiles.size, 0);

  for (const executionTransportResult of [
    { exitCode: 76 },
    { signal: 'SIGTERM', exitCode: null },
    { stdout: 1 },
    { unknown: true },
  ]) {
    const f = await fixture(t, { executionTransportResult });
    await rejectsCode(executeRemoteScript(f.input), 'REMOTE_EXECUTION_UNCERTAIN');
    assert.equal(f.state.remoteFiles.size, 0);
  }
});

test('fixed wrapper source never contains the caller local path or interpolated staged path', async (t) => {
  const f = await fixture(t, { scriptName: "victim';Write-Output injected;#.ps1" });
  await executeRemoteScript(f.input);
  for (const script of f.state.scripts) {
    assert.doesNotMatch(script, new RegExp(f.scriptPath.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'));
    assert.doesNotMatch(script, new RegExp(REMOTE_PATH.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'));
  }
});

test('successful exec reads its receipt and cleans up in one remote invocation', async (t) => {
  const f = await fixture(t);
  await executeRemoteScript(f.input);
  assert.equal(f.state.calls.filter(({ command }) => command === '/usr/bin/ssh').length, 5);
  assert.equal(f.state.remoteFiles.size, 0);
});

test('cleanup failure in finalization stays uncertain even if bounded cleanup later succeeds', async (t) => {
  const f = await fixture(t, { finalizeCleanupFailure: true });
  await rejectsCode(executeRemoteScript(f.input), 'REMOTE_CLEANUP_UNCERTAIN');
  assert.equal(f.state.executionCalls, 1);
  assert.equal(f.state.phaseCalls.readResult, 1);
  assert.equal(f.state.phaseCalls.cleanup, 2);
  assert.equal(f.state.remoteFiles.size, 0);
});

test('lost finalization response does not replay execution or claim success', async (t) => {
  const f = await fixture(t, { finalizeResponseLost: true });
  await rejectsCode(executeRemoteScript(f.input), 'REMOTE_EXECUTION_UNCERTAIN');
  assert.equal(f.state.executionCalls, 1);
  assert.equal(f.state.phaseCalls.readResult, 1);
  assert.equal(f.state.phaseCalls.cleanup, 2);
  assert.equal(f.state.remoteFiles.size, 0);
});
