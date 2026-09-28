import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { isProxy } from 'node:util/types';

import { withTrustedSshSession } from '../ssh/trusted-ssh-session.mjs';
import { snapshotBytes, snapshotLocalFile } from './local-file.mjs';
import { trustedInput } from './remote-target.mjs';
import {
  WINDOWS_EXEC_CLEANUP_WRAPPER,
  WINDOWS_EXEC_FINALIZE_WRAPPER,
  WINDOWS_EXEC_INVOKE_WRAPPER,
  WINDOWS_EXEC_PREFLIGHT_WRAPPER,
  WINDOWS_EXEC_VERIFY_WRAPPER,
  WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER,
  encodeRemotePayload,
  powershellInvocation,
  selectAddress,
} from './windows-remote.mjs';

const DEFAULT_TIMEOUT_MS = 300_000;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 1_800_000;
const DEFAULT_SSH_LOCK_TIMEOUT_MS = 15 * 60 * 1_000;
const MIN_SSH_LOCK_TIMEOUT_MS = 1_000;
const EXEC_CLEANUP_TIMEOUT_MS = 60_000;
const MAX_SOURCE_BYTES = 1024 * 1024;
const MAX_STAGED_BYTES = 2 * 1024 * 1024 + 2;
const MAX_EXEC_OUTPUT_BYTES = 4 * 1024 * 1024;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const ISO_TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const INPUT_FIELDS = new Set(['target', 'scriptPath', 'timeoutMs', 'dependencies']);
const REQUIRED_INPUT_FIELDS = new Set(['target', 'scriptPath', 'dependencies']);
const BYTE_INPUT_FIELDS = new Set(['target', 'scriptBytes', 'timeoutMs', 'dependencies']);
const REQUIRED_BYTE_INPUT_FIELDS = new Set(['target', 'scriptBytes', 'dependencies']);
const DEPENDENCY_FIELDS = new Set(['runProcess', 'operationId', 'clock', 'sshLockTimeoutMs']);
const REQUIRED_DEPENDENCY_FIELDS = new Set(['runProcess', 'operationId', 'clock']);
const PROCESS_RESULT_FIELDS = new Set([
  'command',
  'args',
  'exitCode',
  'signal',
  'stdout',
  'stderr',
]);
const PUBLIC_CODES = new Set([
  'REMOTE_INPUT_INVALID',
  'REMOTE_CONNECTION_FAILED',
  'FILE_TRANSFER_FAILED',
  'FILE_INTEGRITY_FAILED',
  'REMOTE_EXECUTION_UNCERTAIN',
  'REMOTE_CLEANUP_UNCERTAIN',
  'LOCAL_CLEANUP_FAILED',
]);
const ACTIVE_INVOKE_UNCERTAINTIES = new WeakSet();
const PREPARED_SCRIPTS = new WeakMap();
const PREPARATION_OPTION_FIELDS = new Set(['runtimeTransaction']);
const RUNTIME_TRANSACTION_FIELDS = new Set(['operationId', 'manifestDigest']);
const SESSION_FIELDS = new Set([
  'addresses',
  'invokeSsh',
  'invokeScp',
  'invokeCleanup',
  'remoteSpec',
]);
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;

function remoteError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function activeInvokeUncertainty() {
  const error = remoteError('REMOTE_EXECUTION_UNCERTAIN');
  ACTIVE_INVOKE_UNCERTAINTIES.add(error);
  return error;
}

function failInput() {
  throw remoteError('REMOTE_INPUT_INVALID');
}

function exactObject(input, allowedFields, requiredFields = allowedFields) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();
  const snapshot = Object.create(null);
  for (const key of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!allowedFields.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) failInput();
    snapshot[key] = descriptor.value;
  }
  for (const field of requiredFields) {
    if (!Object.hasOwn(snapshot, field)) failInput();
  }
  return snapshot;
}

function validateInput(input) {
  const value = exactObject(input, INPUT_FIELDS, REQUIRED_INPUT_FIELDS);
  const dependencies = exactObject(
    value.dependencies,
    DEPENDENCY_FIELDS,
    REQUIRED_DEPENDENCY_FIELDS,
  );
  for (const field of REQUIRED_DEPENDENCY_FIELDS) {
    if (typeof dependencies[field] !== 'function' || isProxy(dependencies[field])) failInput();
  }
  const sshLockTimeoutMs = Object.hasOwn(dependencies, 'sshLockTimeoutMs')
    ? dependencies.sshLockTimeoutMs
    : DEFAULT_SSH_LOCK_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(sshLockTimeoutMs)
    || sshLockTimeoutMs < MIN_SSH_LOCK_TIMEOUT_MS
    || sshLockTimeoutMs > DEFAULT_SSH_LOCK_TIMEOUT_MS
  ) failInput();
  const timeoutMs = Object.hasOwn(value, 'timeoutMs') ? value.timeoutMs : DEFAULT_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(timeoutMs)
    || timeoutMs < MIN_TIMEOUT_MS
    || timeoutMs > MAX_TIMEOUT_MS
  ) failInput();
  if (typeof value.scriptPath !== 'string') failInput();
  return {
    target: value.target,
    scriptPath: value.scriptPath,
    timeoutMs,
    dependencies: { ...dependencies, sshLockTimeoutMs },
  };
}

function canonicalScriptBytes(input) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Buffer.isBuffer(input)
    || Object.getPrototypeOf(input) !== Buffer.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || input.length < 1
    || input.length > MAX_SOURCE_BYTES
  ) failInput();
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== input.length
    || !names.every((name, index) => name === String(index))
    || (typeof SharedArrayBuffer === 'function' && input.buffer instanceof SharedArrayBuffer)
  ) failInput();
  return Buffer.from(input);
}

function validateByteInput(input) {
  const value = exactObject(input, BYTE_INPUT_FIELDS, REQUIRED_BYTE_INPUT_FIELDS);
  const dependencies = exactObject(
    value.dependencies,
    DEPENDENCY_FIELDS,
    REQUIRED_DEPENDENCY_FIELDS,
  );
  for (const field of REQUIRED_DEPENDENCY_FIELDS) {
    if (typeof dependencies[field] !== 'function' || isProxy(dependencies[field])) failInput();
  }
  const sshLockTimeoutMs = Object.hasOwn(dependencies, 'sshLockTimeoutMs')
    ? dependencies.sshLockTimeoutMs
    : DEFAULT_SSH_LOCK_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(sshLockTimeoutMs)
    || sshLockTimeoutMs < MIN_SSH_LOCK_TIMEOUT_MS
    || sshLockTimeoutMs > DEFAULT_SSH_LOCK_TIMEOUT_MS
  ) failInput();
  const timeoutMs = Object.hasOwn(value, 'timeoutMs') ? value.timeoutMs : DEFAULT_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(timeoutMs)
    || timeoutMs < MIN_TIMEOUT_MS
    || timeoutMs > MAX_TIMEOUT_MS
  ) failInput();
  return {
    target: value.target,
    scriptBytes: canonicalScriptBytes(value.scriptBytes),
    timeoutMs,
    dependencies: { ...dependencies, sshLockTimeoutMs },
  };
}

function validatePreparationOptions(input) {
  const options = exactObject(input, PREPARATION_OPTION_FIELDS, new Set());
  if (!Object.hasOwn(options, 'runtimeTransaction')) return null;
  const transaction = exactObject(
    options.runtimeTransaction,
    RUNTIME_TRANSACTION_FIELDS,
  );
  if (
    typeof transaction.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(transaction.operationId)
    || typeof transaction.manifestDigest !== 'string'
    || !SHA256_PATTERN.test(transaction.manifestDigest)
  ) failInput();
  return Object.freeze({ ...transaction });
}

function snapshotPreparedSession(input, expectedAddresses) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Object.isFrozen(input)
    || Array.isArray(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== SESSION_FIELDS.size || !names.every((name) => SESSION_FIELDS.has(name))) {
    failInput();
  }
  const session = Object.create(null);
  for (const field of SESSION_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      failInput();
    }
    session[field] = descriptor.value;
  }
  if (
    !Array.isArray(session.addresses)
    || !Object.isFrozen(session.addresses)
    || session.addresses.length !== expectedAddresses.length
    || session.addresses.some((address, index) => (
      typeof address !== 'string'
      || isIP(address) === 0
      || address !== expectedAddresses[index]
    ))
    || ['invokeSsh', 'invokeScp', 'invokeCleanup', 'remoteSpec'].some((field) => (
      typeof session[field] !== 'function' || isProxy(session[field])
    ))
  ) failInput();
  return session;
}

function operationId(factory) {
  let value;
  try {
    value = factory();
  } catch {
    failInput();
  }
  if (typeof value !== 'string' || !OPERATION_ID_PATTERN.test(value)) failInput();
  return value;
}

function canonicalTime(clock) {
  let value;
  try {
    value = clock();
  } catch {
    failInput();
  }
  if (
    value === null
    || typeof value !== 'object'
    || isProxy(value)
    || Object.getPrototypeOf(value) !== Date.prototype
  ) failInput();
  let timestamp;
  try {
    timestamp = value.toISOString();
  } catch {
    failInput();
  }
  if (!ISO_TIMESTAMP_PATTERN.test(timestamp) || new Date(timestamp).toISOString() !== timestamp) failInput();
  return timestamp;
}

async function snapshotPowerShellScript(path) {
  const source = await snapshotLocalFile(path, { maximumBytes: MAX_SOURCE_BYTES });
  let primary;
  let stagedSnapshot;
  try {
    const raw = await readFile(source.path);
    stagedSnapshot = await snapshotPowerShellBytes(raw);
  } catch (error) {
    primary = PUBLIC_CODES.has(error?.code) ? error : remoteError('REMOTE_INPUT_INVALID');
  } finally {
    try {
      await source.close();
    } catch (error) {
      if (!primary) primary = error;
      else {
        const cleanup = remoteError('LOCAL_CLEANUP_FAILED');
        cleanup.primaryCode = primary.code;
        primary = cleanup;
      }
    }
  }
  if (primary) {
    if (stagedSnapshot) {
      try { await stagedSnapshot.close(); } catch {
        if (primary.code !== 'LOCAL_CLEANUP_FAILED') {
          const cleanup = remoteError('LOCAL_CLEANUP_FAILED');
          cleanup.primaryCode = primary.code;
          primary = cleanup;
        }
      }
    }
    throw primary;
  }
  return stagedSnapshot;
}

async function snapshotPowerShellBytes(raw) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); } catch { failInput(); }
  if (text.includes('\0')) failInput();
  const staged = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from(text, 'utf16le'),
  ]);
  return snapshotBytes(staged, { maximumBytes: MAX_STAGED_BYTES });
}

function snapshotProcessResult(input, failureCode) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw remoteError(failureCode);
  const result = Object.create(null);
  for (const key of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!PROCESS_RESULT_FIELDS.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw remoteError(failureCode);
    }
    result[key] = descriptor.value;
  }
  for (const field of ['exitCode', 'signal', 'stdout', 'stderr']) {
    if (!Object.hasOwn(result, field)) throw remoteError(failureCode);
  }
  return result;
}

function exactSuccessfulProcess(input, expectedOutput, failureCode) {
  const result = snapshotProcessResult(input, failureCode);
  if (
    result.exitCode !== 0
    || result.signal !== null
    || result.stdout !== expectedOutput
    || result.stderr !== ''
  ) throw remoteError(failureCode);
  return result;
}

function basePayload(id) {
  return encodeRemotePayload({ schemaVersion: 1, operationId: id });
}

async function preflight(session, address, id) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_EXEC_PREFLIGHT_WRAPPER, basePayload(id));
    result = await session.invokeSsh(
      address,
      invocation.argv,
      { timeoutMs: 20_000, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch {
    throw remoteError('FILE_TRANSFER_FAILED');
  }
  exactSuccessfulProcess(result, 'AGENT_ROAD_EXEC_PREFLIGHT_OK', 'FILE_TRANSFER_FAILED');
}

function remoteScriptPath(id) {
  return `C:/ProgramData/AgentRoad/tasks/${id}.ps1`;
}

async function upload(session, address, id, script) {
  let result;
  try {
    result = await session.invokeScp([
      script.path,
      session.remoteSpec(address, remoteScriptPath(id)),
    ], { timeoutMs: 60_000, maxOutputBytes: 16 * 1024 });
  } catch {
    throw remoteError('FILE_TRANSFER_FAILED');
  }
  exactSuccessfulProcess(result, '', 'FILE_TRANSFER_FAILED');
}

async function verifyStaged(session, address, id, script) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_EXEC_VERIFY_WRAPPER, encodeRemotePayload({
      schemaVersion: 1,
      operationId: id,
      expectedBytes: script.bytes,
      expectedSha256: script.sha256,
    }));
    result = await session.invokeSsh(
      address,
      invocation.argv,
      { timeoutMs: 20_000, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch {
    throw remoteError('FILE_TRANSFER_FAILED');
  }
  const snapshot = snapshotProcessResult(result, 'FILE_TRANSFER_FAILED');
  if (snapshot.exitCode === 73 && snapshot.signal === null) {
    throw remoteError('FILE_INTEGRITY_FAILED');
  }
  if (
    snapshot.exitCode !== 0
    || snapshot.signal !== null
    || snapshot.stdout !== 'AGENT_ROAD_EXEC_VERIFIED'
    || snapshot.stderr !== ''
  ) throw remoteError('FILE_TRANSFER_FAILED');
}

function completedTransport(input) {
  const result = snapshotProcessResult(input, 'REMOTE_EXECUTION_UNCERTAIN');
  if (
    result.exitCode !== 0
    || result.signal !== null
    || typeof result.stdout !== 'string'
    || typeof result.stderr !== 'string'
    || Buffer.byteLength(result.stdout) > MAX_EXEC_OUTPUT_BYTES
    || Buffer.byteLength(result.stderr) > MAX_EXEC_OUTPUT_BYTES - Buffer.byteLength(result.stdout)
  ) throw remoteError('REMOTE_EXECUTION_UNCERTAIN');
  return result;
}

async function invokeScript(session, address, id, timeoutMs, script, runtimeTransaction) {
  let result;
  try {
    const payload = {
      schemaVersion: 1,
      operationId: id,
      expectedBytes: script.bytes,
      expectedSha256: script.sha256,
      ...(runtimeTransaction === null ? {} : {
        runtimeOperationId: runtimeTransaction.operationId,
        manifestDigest: runtimeTransaction.manifestDigest,
      }),
    };
    const invocation = powershellInvocation(
      runtimeTransaction === null
        ? WINDOWS_EXEC_INVOKE_WRAPPER
        : WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER,
      encodeRemotePayload(payload),
    );
    result = await session.invokeSsh(
      address,
      invocation.argv,
      { timeoutMs, maxOutputBytes: MAX_EXEC_OUTPUT_BYTES, stdinText: invocation.stdin },
    );
  } catch {
    throw activeInvokeUncertainty();
  }
  const snapshot = snapshotProcessResult(result, 'REMOTE_EXECUTION_UNCERTAIN');
  if (snapshot.exitCode === 74 && snapshot.signal === null) {
    throw remoteError('FILE_INTEGRITY_FAILED');
  }
  if (snapshot.exitCode === 75 && snapshot.signal === null) {
    throw remoteError('FILE_TRANSFER_FAILED');
  }
  return completedTransport(result);
}

async function finalizeRemoteScript(session, address, id) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_EXEC_FINALIZE_WRAPPER, basePayload(id));
    result = await session.invokeSsh(
      address,
      invocation.argv,
      { timeoutMs: EXEC_CLEANUP_TIMEOUT_MS, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch {
    throw remoteError('REMOTE_EXECUTION_UNCERTAIN');
  }
  const snapshot = snapshotProcessResult(result, 'REMOTE_EXECUTION_UNCERTAIN');
  if (snapshot.exitCode === 78 && snapshot.signal === null) {
    throw remoteError('REMOTE_CLEANUP_UNCERTAIN');
  }
  if (
    snapshot.exitCode !== 0
    || snapshot.signal !== null
    || snapshot.stderr !== ''
    || typeof snapshot.stdout !== 'string'
    || !/^(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/u.test(snapshot.stdout)
  ) throw remoteError('REMOTE_EXECUTION_UNCERTAIN');
  return Number(snapshot.stdout);
}

async function cleanupScript(session, address, id) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_EXEC_CLEANUP_WRAPPER, basePayload(id));
    result = await session.invokeCleanup(
      address,
      invocation.argv,
      {
        timeoutMs: EXEC_CLEANUP_TIMEOUT_MS,
        maxOutputBytes: 4096,
        stdinText: invocation.stdin,
      },
    );
  } catch {
    throw remoteError('REMOTE_CLEANUP_UNCERTAIN');
  }
  exactSuccessfulProcess(result, 'AGENT_ROAD_EXEC_CLEANED', 'REMOTE_CLEANUP_UNCERTAIN');
}

function cleanupFailure(primary) {
  const error = remoteError('REMOTE_CLEANUP_UNCERTAIN');
  if (PUBLIC_CODES.has(primary?.code) && primary.code !== 'REMOTE_CLEANUP_UNCERTAIN') {
    error.primaryCode = primary.code;
  }
  return error;
}

function mapFailure(error, phase) {
  if (PUBLIC_CODES.has(error?.code)) return error;
  if (phase.executionStarted) return remoteError('REMOTE_EXECUTION_UNCERTAIN');
  if (phase.selected) return remoteError('FILE_TRANSFER_FAILED');
  return remoteError('REMOTE_CONNECTION_FAILED');
}

function resultFor(deviceId, address, execution, startedAt, finishedAt) {
  if (finishedAt < startedAt) failInput();
  return Object.freeze({
    schemaVersion: 1,
    operation: 'exec',
    deviceId,
    address,
    exitCode: execution.exitCode,
    stdout: execution.stdout,
    stderr: execution.stderr,
    startedAt,
    finishedAt,
  });
}

async function executeAgainstSession(state, session, address) {
  const {
    config,
    deviceId,
    id,
    phase,
    runtimeTransaction,
    script,
  } = state;
  let activeInvokeUncertain = false;
  let cleaned = false;
  let primary;
  let value;
  try {
    await preflight(session, address, id);
    await upload(session, address, id, script);
    phase.staged = true;
    await verifyStaged(session, address, id, script);
    const startedAt = canonicalTime(config.dependencies.clock);
    phase.executionStarted = true;
    const transport = await invokeScript(
      session,
      address,
      id,
      config.timeoutMs,
      script,
      runtimeTransaction,
    );
    const exitCode = await finalizeRemoteScript(session, address, id);
    cleaned = true;
    const finishedAt = canonicalTime(config.dependencies.clock);
    value = resultFor(deviceId, address, {
      exitCode,
      stdout: transport.stdout,
      stderr: transport.stderr,
    }, startedAt, finishedAt);
  } catch (error) {
    activeInvokeUncertain = ACTIVE_INVOKE_UNCERTAINTIES.has(error);
    primary = mapFailure(error, phase);
  }
  try {
    if (!cleaned) await cleanupScript(session, address, id);
  } catch {
    throw cleanupFailure(primary);
  }
  if (activeInvokeUncertain) throw cleanupFailure(primary);
  if (primary) throw primary;
  return value;
}

async function withPreparedRemoteScriptConfig(config, operation, options, scriptSnapshot) {
  if (typeof operation !== 'function' || isProxy(operation)) failInput();
  const runtimeTransaction = validatePreparationOptions(options);
  const trust = trustedInput(config.target, config.dependencies.runProcess);
  const id = operationId(config.dependencies.operationId);
  const phase = Object.seal({ selected: false, staged: false, executionStarted: false });
  const script = await scriptSnapshot();
  const prepared = Object.freeze({ schemaVersion: 1 });
  const state = {
    config,
    deviceId: trust.deviceId,
    executed: false,
    id,
    phase,
    runtimeTransaction,
    script,
    status: 'active',
    trust,
  };
  PREPARED_SCRIPTS.set(prepared, state);
  let primary;
  let value;
  try {
    value = await operation(prepared);
  } catch (error) {
    primary = error;
  }
  state.status = 'closing';
  try {
    await script.close();
  } catch {
    const cleanup = remoteError('LOCAL_CLEANUP_FAILED');
    if (PUBLIC_CODES.has(primary?.code)) cleanup.primaryCode = primary.code;
    primary = cleanup;
  }
  state.status = 'closed';
  PREPARED_SCRIPTS.delete(prepared);
  if (primary) throw primary;
  return value;
}


export async function withPreparedRemoteScript(input, operation, options = {}) {
  const config = validateInput(input);
  return withPreparedRemoteScriptConfig(
    config,
    operation,
    options,
    () => snapshotPowerShellScript(config.scriptPath),
  );
}

export async function withPreparedRemoteScriptBytes(input, operation, options = {}) {
  const config = validateByteInput(input);
  return withPreparedRemoteScriptConfig(
    config,
    operation,
    options,
    () => snapshotPowerShellBytes(config.scriptBytes),
  );
}

export async function executePreparedRemoteScriptInSession(prepared, inputSession, address) {
  const state = PREPARED_SCRIPTS.get(prepared);
  if (
    state === undefined
    || state.status !== 'active'
    || state.executed
    || typeof address !== 'string'
    || isIP(address) === 0
    || !state.trust.addresses.includes(address)
  ) failInput();
  const session = snapshotPreparedSession(inputSession, state.trust.addresses);
  if (!session.addresses.includes(address)) failInput();
  state.executed = true;
  state.phase.selected = true;
  return executeAgainstSession(state, session, address);
}

export async function executeRemoteScript(input) {
  return withPreparedRemoteScript(input, async (prepared) => {
    const state = PREPARED_SCRIPTS.get(prepared);
    try {
      return await withTrustedSshSession(
        state.trust,
        async (session) => {
          const address = await selectAddress(session);
          return executePreparedRemoteScriptInSession(prepared, session, address);
        },
        { lockTimeoutMs: state.config.dependencies.sshLockTimeoutMs },
      );
    } catch (error) {
      throw mapFailure(error, state.phase);
    }
  });
}
