import { isProxy } from 'node:util/types';

import { withTrustedSshSession } from '../ssh/trusted-ssh-session.mjs';
import { createLocalDestination, snapshotLocalFile } from './local-file.mjs';
import { trustedInput } from './remote-target.mjs';
import {
  WINDOWS_GET_CLEANUP_WRAPPER,
  WINDOWS_GET_PREPARE_WRAPPER,
  WINDOWS_PUT_CLEANUP_WRAPPER,
  WINDOWS_PUT_PREFLIGHT_WRAPPER,
  WINDOWS_PUT_PREPARE_WRAPPER,
  WINDOWS_PUT_PUBLISH_WRAPPER,
  encodeRemotePayload,
  powershellInvocation,
  selectAddress,
} from './windows-remote.mjs';

const MAX_FILE_BYTES = 256 * 1024 * 1024;
const MAX_WINDOWS_PATH_BYTES = 4096;
const REMOTE_CLEANUP_TIMEOUT_MS = 60_000;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const PARENT_IDENTITY_PATTERN = /^[A-F0-9]{8}:[A-F0-9]{8}:[A-F0-9]{8}$/u;
const ISO_TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const INPUT_FIELDS = new Set(['target', 'localPath', 'remotePath', 'overwrite', 'dependencies']);
const DEPENDENCY_FIELDS = new Set(['runProcess', 'operationId', 'clock']);
const PROCESS_RESULT_FIELDS = new Set(['command', 'args', 'exitCode', 'signal', 'stdout', 'stderr']);
const PUBLIC_CODES = new Set([
  'REMOTE_INPUT_INVALID',
  'REMOTE_CONNECTION_FAILED',
  'REMOTE_CLEANUP_UNCERTAIN',
  'FILE_TRANSFER_FAILED',
  'FILE_TRANSFER_UNCERTAIN',
  'FILE_INTEGRITY_FAILED',
  'LOCAL_CLEANUP_FAILED',
]);
const ACTIVE_PUBLISH_UNCERTAINTIES = new WeakSet();
const ACTIVE_PREPARE_UNCERTAINTIES = new WeakSet();
const ACTIVE_UPLOAD_UNCERTAINTIES = new WeakSet();
const ACTIVE_GET_PREPARE_UNCERTAINTIES = new WeakSet();
const ACTIVE_GET_DOWNLOAD_UNCERTAINTIES = new WeakSet();

function remoteError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function failInput() {
  throw remoteError('REMOTE_INPUT_INVALID');
}

function exactObject(input, fields) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();
  const result = Object.create(null);
  for (const key of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!fields.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) failInput();
    result[key] = descriptor.value;
  }
  for (const field of fields) {
    if (!Object.hasOwn(result, field)) failInput();
  }
  return result;
}

export function validateWindowsFilePath(value) {
  if (
    typeof value !== 'string'
    || value.length < 4
    || Buffer.byteLength(value) > MAX_WINDOWS_PATH_BYTES
    || !/^[A-Za-z]:\\/u.test(value)
    || value.includes('/')
    || /[\x00-\x1f\x7f*?"<>|]/u.test(value)
    || value.slice(2).includes(':')
  ) failInput();
  const components = value.slice(3).split('\\');
  if (
    components.length === 0
    || components.some((component) => (
      component.length === 0
      || component === '.'
      || component === '..'
      || /[. ]$/u.test(component)
      || /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/iu.test(component)
    ))
  ) failInput();
  const folded = value.toLowerCase();
  if (
    folded === 'c:\\programdata\\agentroad'
    || folded.startsWith('c:\\programdata\\agentroad\\')
  ) failInput();
  return value;
}

function validateInput(input) {
  const value = exactObject(input, INPUT_FIELDS);
  const dependencies = exactObject(value.dependencies, DEPENDENCY_FIELDS);
  for (const dependency of DEPENDENCY_FIELDS) {
    if (typeof dependencies[dependency] !== 'function' || isProxy(dependencies[dependency])) failInput();
  }
  if (typeof value.localPath !== 'string' || typeof value.overwrite !== 'boolean') failInput();
  return {
    target: value.target,
    localPath: value.localPath,
    remotePath: validateWindowsFilePath(value.remotePath),
    overwrite: value.overwrite,
    dependencies,
  };
}

function operationId(factory) {
  let value;
  try { value = factory(); } catch { failInput(); }
  if (typeof value !== 'string' || !OPERATION_ID_PATTERN.test(value)) failInput();
  return value;
}

function canonicalTime(clock) {
  let value;
  try { value = clock(); } catch { failInput(); }
  if (
    value === null
    || typeof value !== 'object'
    || isProxy(value)
    || Object.getPrototypeOf(value) !== Date.prototype
  ) failInput();
  let timestamp;
  try { timestamp = value.toISOString(); } catch { failInput(); }
  if (!ISO_TIMESTAMP_PATTERN.test(timestamp) || new Date(timestamp).toISOString() !== timestamp) failInput();
  return timestamp;
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

function exactSuccessfulProcess(input, output, failureCode) {
  const result = snapshotProcessResult(input, failureCode);
  if (
    result.exitCode !== 0
    || result.signal !== null
    || result.stdout !== output
    || result.stderr !== ''
  ) throw remoteError(failureCode);
}

function transferPayload(config, id, snapshot, phaseFields = {}) {
  return encodeRemotePayload({
    schemaVersion: 1,
    operationId: id,
    destinationPath: config.remotePath,
    overwrite: config.overwrite,
    expectedBytes: snapshot.bytes,
    expectedSha256: snapshot.sha256,
    ...phaseFields,
  });
}

function stagingPath(id) {
  return `C:/ProgramData/AgentRoad/transfers/${id}.put.stage`;
}

async function preflight(session, address, payload) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_PUT_PREFLIGHT_WRAPPER, payload);
    result = await session.invokeSsh(
      address,
      invocation.argv,
      { timeoutMs: 20_000, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch {
    throw remoteError('FILE_TRANSFER_FAILED');
  }
  exactSuccessfulProcess(result, 'AGENT_ROAD_PUT_PREFLIGHT_OK', 'FILE_TRANSFER_FAILED');
}

async function upload(session, address, id, snapshot) {
  let result;
  try {
    result = await session.invokeScp([
      snapshot.path,
      session.remoteSpec(address, stagingPath(id)),
    ], { timeoutMs: 300_000, maxOutputBytes: 16 * 1024 });
  } catch {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_UPLOAD_UNCERTAINTIES.add(error);
    throw error;
  }
  exactSuccessfulProcess(result, '', 'FILE_TRANSFER_FAILED');
}

async function prepare(session, address, payload) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_PUT_PREPARE_WRAPPER, payload);
    result = await session.invokeSsh(
      address,
      invocation.argv,
      { timeoutMs: 300_000, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  let value;
  try {
    value = snapshotProcessResult(result, 'FILE_TRANSFER_FAILED');
  } catch {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  if (value.exitCode === 73 && value.signal === null) throw remoteError('FILE_INTEGRITY_FAILED');
  if (value.exitCode === 74 && value.signal === null) throw remoteError('FILE_TRANSFER_FAILED');
  if (value.exitCode === 75 && value.signal === null) {
    const error = remoteError('FILE_INTEGRITY_FAILED');
    ACTIVE_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  if (value.exitCode === 76 && value.signal === null) {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  if (
    value.exitCode !== 0
    || value.signal !== null
    || value.stderr !== ''
    || typeof value.stdout !== 'string'
  ) {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  const match = /^AGENT_ROAD_PUT_PREPARED:([A-F0-9]{8}:[A-F0-9]{8}:[A-F0-9]{8})$/u.exec(
    value.stdout,
  );
  if (!match || !PARENT_IDENTITY_PATTERN.test(match[1])) {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  return Object.freeze({ parentIdentity: match[1] });
}

async function publish(session, address, payload) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_PUT_PUBLISH_WRAPPER, payload);
    result = await session.invokeSsh(
      address,
      invocation.argv,
      { timeoutMs: 60_000, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch {
    const error = remoteError('FILE_TRANSFER_UNCERTAIN');
    ACTIVE_PUBLISH_UNCERTAINTIES.add(error);
    throw error;
  }
  const value = snapshotProcessResult(result, 'FILE_TRANSFER_UNCERTAIN');
  if (value.exitCode === 73 && value.signal === null) throw remoteError('FILE_INTEGRITY_FAILED');
  if (value.exitCode === 74 && value.signal === null) throw remoteError('FILE_TRANSFER_FAILED');
  exactSuccessfulProcess(value, 'AGENT_ROAD_PUT_PUBLISHED', 'FILE_TRANSFER_UNCERTAIN');
}

async function cleanup(session, address, payload) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_PUT_CLEANUP_WRAPPER, payload);
    result = await session.invokeCleanup(
      address,
      invocation.argv,
      { timeoutMs: REMOTE_CLEANUP_TIMEOUT_MS, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch {
    throw remoteError('REMOTE_CLEANUP_UNCERTAIN');
  }
  exactSuccessfulProcess(result, 'AGENT_ROAD_PUT_CLEANED', 'REMOTE_CLEANUP_UNCERTAIN');
}

function cleanupFailure(primary) {
  const error = remoteError('REMOTE_CLEANUP_UNCERTAIN');
  if (PUBLIC_CODES.has(primary?.code) && primary.code !== 'REMOTE_CLEANUP_UNCERTAIN') {
    error.primaryCode = primary.code;
  }
  return error;
}

function mapFailure(error, phase) {
  if (phase.publicationStarted && error?.code === 'REMOTE_INPUT_INVALID') {
    return remoteError('FILE_TRANSFER_UNCERTAIN');
  }
  if (PUBLIC_CODES.has(error?.code)) return error;
  if (phase.publicationStarted) return remoteError('FILE_TRANSFER_UNCERTAIN');
  if (phase.selected) return remoteError('FILE_TRANSFER_FAILED');
  return remoteError('REMOTE_CONNECTION_FAILED');
}

function resultFor(config, address, snapshot, startedAt, finishedAt) {
  if (finishedAt < startedAt) failInput();
  return Object.freeze({
    schemaVersion: 1,
    operation: 'put',
    deviceId: config.target.device.id,
    address,
    bytes: snapshot.bytes,
    sha256: snapshot.sha256,
    destination: config.remotePath,
    startedAt,
    finishedAt,
  });
}

async function putInSession(config, snapshot, id, phase) {
  return withTrustedSshSession(
    trustedInput(config.target, config.dependencies.runProcess),
    async (session) => {
      const address = await selectAddress(session);
      phase.selected = true;
      const payload = transferPayload(config, id, snapshot);
      const startedAt = canonicalTime(config.dependencies.clock);
      let activeRemoteWriterUncertain = false;
      let primary;
      let value;
      try {
        await preflight(session, address, payload);
        phase.stagingOwned = true;
        await upload(session, address, id, snapshot);
        const prepared = await prepare(session, address, payload);
        phase.tempOwned = true;
        phase.expectedParentIdentity = prepared.parentIdentity;
        phase.publicationStarted = true;
        await publish(session, address, transferPayload(config, id, snapshot, {
          expectedParentIdentity: phase.expectedParentIdentity,
        }));
        const finishedAt = canonicalTime(config.dependencies.clock);
        value = resultFor(config, address, snapshot, startedAt, finishedAt);
      } catch (error) {
        activeRemoteWriterUncertain = ACTIVE_UPLOAD_UNCERTAINTIES.has(error)
          || ACTIVE_PREPARE_UNCERTAINTIES.has(error)
          || ACTIVE_PUBLISH_UNCERTAINTIES.has(error);
        primary = mapFailure(error, phase);
      }
      try {
        await cleanup(session, address, transferPayload(config, id, snapshot, {
          expectedParentIdentity: phase.tempOwned ? phase.expectedParentIdentity : null,
          stagingOwned: phase.stagingOwned,
          tempOwned: phase.tempOwned,
        }));
      } catch {
        throw cleanupFailure(primary);
      }
      if (activeRemoteWriterUncertain) throw cleanupFailure(primary);
      if (primary) throw primary;
      return value;
    },
  );
}

export async function putRemoteFile(input) {
  const config = validateInput(input);
  const id = operationId(config.dependencies.operationId);
  const phase = Object.seal({
    selected: false,
    stagingOwned: false,
    tempOwned: false,
    expectedParentIdentity: null,
    publicationStarted: false,
  });
  const snapshot = await snapshotLocalFile(config.localPath, { minimumBytes: 0, maximumBytes: MAX_FILE_BYTES });
  let primary;
  let value;
  try {
    value = await putInSession(config, snapshot, id, phase);
  } catch (error) {
    primary = mapFailure(error, phase);
  }
  try {
    await snapshot.close();
  } catch {
    const cleanupError = remoteError('LOCAL_CLEANUP_FAILED');
    if (PUBLIC_CODES.has(primary?.code)) cleanupError.primaryCode = primary.code;
    throw cleanupError;
  }
  if (primary) throw primary;
  return value;
}

function getPayload(config, id, prepared, snapshotOwned) {
  const value = {
    schemaVersion: 1,
    operationId: id,
    sourcePath: config.remotePath,
  };
  if (typeof snapshotOwned === 'boolean') {
    value.expectedBytes = snapshotOwned ? prepared.bytes : null;
    value.expectedSha256 = snapshotOwned ? prepared.sha256 : null;
    value.snapshotOwned = snapshotOwned;
  }
  return encodeRemotePayload(value);
}

function getStagingPath(id) {
  return `C:/ProgramData/AgentRoad/transfers/${id}.get.stage`;
}

async function prepareGetSnapshot(session, address, payload) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_GET_PREPARE_WRAPPER, payload);
    result = await session.invokeSsh(
      address,
      invocation.argv,
      { timeoutMs: 300_000, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_GET_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  let value;
  try {
    value = snapshotProcessResult(result, 'FILE_TRANSFER_FAILED');
  } catch {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_GET_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  if (
    (value.exitCode === 73 || value.exitCode === 74)
    && value.signal === null
  ) throw remoteError('FILE_TRANSFER_FAILED');
  if (value.exitCode === 75 && value.signal === null) {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_GET_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  if (
    value.exitCode !== 0
    || value.signal !== null
    || value.stderr !== ''
    || typeof value.stdout !== 'string'
  ) {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_GET_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  const match = /^AGENT_ROAD_GET_PREPARED:(0|[1-9][0-9]{0,8}):([A-F0-9]{64})$/u.exec(value.stdout);
  const bytes = match && Number(match[1]);
  if (!match || !Number.isSafeInteger(bytes) || bytes < 0 || bytes > MAX_FILE_BYTES) {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_GET_PREPARE_UNCERTAINTIES.add(error);
    throw error;
  }
  return Object.freeze({ bytes, sha256: match[2] });
}

async function downloadSnapshot(session, address, id, temporaryPath) {
  let result;
  try {
    result = await session.invokeScp([
      session.remoteSpec(address, getStagingPath(id)),
      temporaryPath,
    ], { timeoutMs: 300_000, maxOutputBytes: 16 * 1024 });
  } catch {
    const error = remoteError('FILE_TRANSFER_FAILED');
    ACTIVE_GET_DOWNLOAD_UNCERTAINTIES.add(error);
    throw error;
  }
  exactSuccessfulProcess(result, '', 'FILE_TRANSFER_FAILED');
}

async function cleanupGetSnapshot(session, address, payload) {
  let result;
  try {
    const invocation = powershellInvocation(WINDOWS_GET_CLEANUP_WRAPPER, payload);
    result = await session.invokeCleanup(
      address,
      invocation.argv,
      { timeoutMs: REMOTE_CLEANUP_TIMEOUT_MS, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch {
    throw remoteError('REMOTE_CLEANUP_UNCERTAIN');
  }
  exactSuccessfulProcess(result, 'AGENT_ROAD_GET_CLEANED', 'REMOTE_CLEANUP_UNCERTAIN');
}

function getResult(config, address, prepared, startedAt, finishedAt) {
  if (finishedAt < startedAt) failInput();
  return Object.freeze({
    schemaVersion: 1,
    operation: 'get',
    deviceId: config.target.device.id,
    address,
    bytes: prepared.bytes,
    sha256: prepared.sha256,
    source: config.remotePath,
    destination: config.localPath,
    startedAt,
    finishedAt,
  });
}

function mapGetFailure(error, phase) {
  if (phase.localPublished && error?.code === 'REMOTE_INPUT_INVALID') {
    return remoteError('FILE_TRANSFER_UNCERTAIN');
  }
  if (PUBLIC_CODES.has(error?.code)) return error;
  if (phase.localPublished) return remoteError('FILE_TRANSFER_UNCERTAIN');
  if (phase.selected) return remoteError('FILE_TRANSFER_FAILED');
  return remoteError('REMOTE_CONNECTION_FAILED');
}

function publicCodeChain(error) {
  const chain = [];
  if (typeof error?.primaryCode === 'string') {
    const parts = error.primaryCode.split(':');
    if (parts.every((part) => PUBLIC_CODES.has(part))) chain.push(...parts);
  }
  if (PUBLIC_CODES.has(error?.code)) chain.push(error.code);
  return chain;
}

function cleanupChain(primary, remoteCleanupFailed, localCleanupFailed) {
  const chain = publicCodeChain(primary);
  if (remoteCleanupFailed && chain.at(-1) !== 'REMOTE_CLEANUP_UNCERTAIN') {
    chain.push('REMOTE_CLEANUP_UNCERTAIN');
  }
  if (localCleanupFailed && chain.at(-1) !== 'LOCAL_CLEANUP_FAILED') {
    chain.push('LOCAL_CLEANUP_FAILED');
  }
  if (chain.length === 0) return undefined;
  const error = remoteError(chain.at(-1));
  if (chain.length > 1) error.primaryCode = chain.slice(0, -1).join(':');
  return error;
}

async function getInSession(config, id, phase) {
  return withTrustedSshSession(
    trustedInput(config.target, config.dependencies.runProcess),
    async (session) => {
      const address = await selectAddress(session);
      phase.selected = true;
      const startedAt = canonicalTime(config.dependencies.clock);
      let prepared = Object.freeze({ bytes: null, sha256: null });
      let local;
      let primary;
      let value;
      let activeRemoteWriterUncertain = false;
      let activeLocalWriterUncertain = false;
      try {
        prepared = await prepareGetSnapshot(session, address, getPayload(config, id));
        phase.snapshotOwned = true;
        local = await createLocalDestination(config.localPath, {
          overwrite: config.overwrite,
          expectedBytes: prepared.bytes,
          expectedSha256: prepared.sha256,
        });
        await downloadSnapshot(session, address, id, local.temporaryPath);
        await local.publish();
        phase.localPublished = true;
        const finishedAt = canonicalTime(config.dependencies.clock);
        value = getResult(config, address, prepared, startedAt, finishedAt);
      } catch (error) {
        activeRemoteWriterUncertain = ACTIVE_GET_PREPARE_UNCERTAINTIES.has(error);
        activeLocalWriterUncertain = ACTIVE_GET_DOWNLOAD_UNCERTAINTIES.has(error);
        primary = mapGetFailure(error, phase);
      }

      let remoteCleanupFailed = activeRemoteWriterUncertain;
      try {
        await cleanupGetSnapshot(
          session,
          address,
          getPayload(config, id, prepared, phase.snapshotOwned),
        );
      } catch {
        remoteCleanupFailed = true;
      }

      let localCleanupFailed = activeLocalWriterUncertain;
      try {
        await local?.close();
      } catch {
        localCleanupFailed = true;
      }
      const cleanupError = cleanupChain(primary, remoteCleanupFailed, localCleanupFailed);
      if (cleanupError) throw cleanupError;
      return value;
    },
  );
}

export async function getRemoteFile(input) {
  const config = validateInput(input);
  const id = operationId(config.dependencies.operationId);
  const phase = Object.seal({
    selected: false,
    snapshotOwned: false,
    localPublished: false,
  });
  try {
    return await getInSession(config, id, phase);
  } catch (error) {
    throw mapGetFailure(error, phase);
  }
}
