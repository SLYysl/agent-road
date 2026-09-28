import { execFile as execFileCallback } from 'node:child_process';
import { constants } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  realpath,
} from 'node:fs/promises';
import {
  dirname,
  isAbsolute,
  resolve,
} from 'node:path';
import { promisify, TextDecoder } from 'node:util';
import { isProxy } from 'node:util/types';

import {assertTerminalRollbackStatePair} from './terminal-rollback-protocol.mjs';
import { runtimeDeviceStatePath } from '../core/paths.mjs';
import { withFileLock } from '../storage/file-lock.mjs';
import { writeJsonAtomic } from '../storage/json-file.mjs';
import {
  verifyTerminalRollbackCommit,
  withTerminalRollbackStateConfirmation,
  verifyRuntimeRecoveredState,
  verifyRuntimeRecoveryCommit,
} from './runtime-recovery-store.mjs';

export const RUNTIME_STATUSES = Object.freeze([
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

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const DIGEST_PATTERN = /^[A-F0-9]{64}$/u;
const TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const MAX_DEVICE_ID_LENGTH = 64;
const MAX_STATE_BYTES = 4_096;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const RUNTIME_STATE_TEST_HOOK = Symbol.for('agent-road.runtime-state-store.test-hook');
const NO_TEST_HOOK = Object.freeze(async () => {});
const execFile = promisify(execFileCallback);
const STATE_FIELDS = Object.freeze([
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
const PROFILE_IDS = Object.freeze(['core', 'base']);
const FAILURE_CODES = new Set([
  'RUNTIME_ACTIVATION_FAILED',
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
  'RUNTIME_ARTIFACT_INTEGRITY_FAILED',
  'RUNTIME_ARTIFACT_INVALID',
  'RUNTIME_ARTIFACT_REDIRECT_INVALID',
  'RUNTIME_ARTIFACT_TIMEOUT',
  'RUNTIME_CACHE_CLEANUP_FAILED',
  'RUNTIME_CACHE_FAILED',
  'RUNTIME_CACHE_LOCKED',
  'RUNTIME_CACHE_UNSAFE',
  'RUNTIME_COMPLETION_UNCERTAIN',
  'RUNTIME_DISK_INSUFFICIENT',
  'RUNTIME_DOWNLOAD_FAILED',
  'RUNTIME_ELEVATION_REQUIRED',
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_INSTALL_FAILED',
  'RUNTIME_INTERNAL_ERROR',
  'RUNTIME_INVENTORY_CHANGED',
  'RUNTIME_INVENTORY_FAILED',
  'RUNTIME_INVENTORY_INVALID',
  'RUNTIME_OPERATION_CONFLICT',
  'RUNTIME_PLATFORM_UNSUPPORTED',
  'RUNTIME_REBOOT_REQUIRED',
  'RUNTIME_ROLLBACK_INCOMPLETE',
  'RUNTIME_SELF_TEST_FAILED',
  'RUNTIME_SIGNATURE_INVALID',
  'RUNTIME_STAGE_FAILED',
  'RUNTIME_STATE_UNSUPPORTED',
  'RUNTIME_VERIFY_FAILED',
]);
const UNCERTAIN_FAILURE_CODES = new Set([
  'RUNTIME_COMPLETION_UNCERTAIN',
  'RUNTIME_ROLLBACK_INCOMPLETE',
]);
const NEXT_STATUSES = Object.freeze({
  UNPROVISIONED: Object.freeze(['INVENTORY_READY', 'FAILED']),
  INVENTORY_READY: Object.freeze(['PLAN_READY', 'READY', 'FAILED']),
  PLAN_READY: Object.freeze(['ACQUIRING', 'READY', 'FAILED']),
  ACQUIRING: Object.freeze(['STAGED', 'READY', 'FAILED']),
  STAGED: Object.freeze(['VERIFYING', 'FAILED']),
  VERIFYING: Object.freeze(['READY', 'FAILED']),
  READY: Object.freeze(['INVENTORY_READY']),
  FAILED: Object.freeze(['INVENTORY_READY', 'PLAN_READY', 'RECOVERED']),
  RECOVERED: Object.freeze(['INVENTORY_READY']),
});
const OWN_ERRORS = new WeakSet();

function runtimeError(code, ErrorType = Error) {
  const error = new ErrorType(code);
  error.code = code;
  OWN_ERRORS.add(error);
  return error;
}

function fail(code, ErrorType = TypeError) {
  throw runtimeError(code, ErrorType);
}

function safeOwnString(input, field) {
  if (
    input === null
    || (typeof input !== 'object' && typeof input !== 'function')
    || isProxy(input)
  ) return null;
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(input, field);
  } catch {
    return null;
  }
  return descriptor !== undefined
    && Object.hasOwn(descriptor, 'value')
    && typeof descriptor.value === 'string'
    ? descriptor.value
    : null;
}

function mapStoreError(error) {
  if (OWN_ERRORS.has(error)) return error;
  const message = safeOwnString(error, 'message');
  if (message?.startsWith('runtime state is locked:')) {
    return runtimeError('RUNTIME_ALREADY_RUNNING');
  }
  return runtimeError('RUNTIME_INTERNAL_ERROR');
}

function validateDeviceId(deviceId, code = 'RUNTIME_INPUT_INVALID') {
  if (
    typeof deviceId !== 'string'
    || deviceId.length > MAX_DEVICE_ID_LENGTH
    || !DEVICE_ID_PATTERN.test(deviceId)
  ) fail(code);
  return deviceId;
}

function validateRoot(root) {
  if (
    typeof root !== 'string'
    || root.length === 0
    || Buffer.byteLength(root, 'utf8') > MAX_STATE_BYTES
    || !isAbsolute(root)
    || resolve(root) !== root
    || /[\r\n\x00-\x1f\x7f]/u.test(root)
  ) fail('RUNTIME_INPUT_INVALID');
  return root;
}

function unprovisionedState(deviceId) {
  return Object.freeze({
    schemaVersion: 1,
    deviceId,
    runtimeStatus: 'UNPROVISIONED',
    requestedProfiles: Object.freeze([]),
    readyProfiles: Object.freeze([]),
    operationId: null,
    manifestDigest: null,
    generationDigest: null,
    failureCode: null,
    updatedAt: null,
  });
}

function readExactRecord(input, code) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code);

  const names = Object.getOwnPropertyNames(input);
  if (names.length !== STATE_FIELDS.length || !STATE_FIELDS.every((field) => names.includes(field))) {
    fail(code);
  }
  const values = Object.create(null);
  for (const field of STATE_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) fail(code);
    values[field] = descriptor.value;
  }
  return values;
}

function readProfiles(input, code) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Array.isArray(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code);

  const lengthDescriptor = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    lengthDescriptor === undefined
    || !Object.hasOwn(lengthDescriptor, 'value')
    || !Number.isInteger(lengthDescriptor.value)
    || lengthDescriptor.value < 0
    || lengthDescriptor.value > PROFILE_IDS.length
  ) fail(code);
  const length = lengthDescriptor.value;
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== length + 1
    || !names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/u.test(name))
  ) fail(code);

  const profiles = [];
  let previousIndex = -1;
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    const profileIndex = descriptor && Object.hasOwn(descriptor, 'value')
      ? PROFILE_IDS.indexOf(descriptor.value)
      : -1;
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
      || profileIndex <= previousIndex
    ) fail(code);
    profiles.push(descriptor.value);
    previousIndex = profileIndex;
  }
  return Object.freeze(profiles);
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function validOperationId(value) {
  return typeof value === 'string' && OPERATION_ID_PATTERN.test(value);
}

function validDigest(value) {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function identitiesAreFull(value) {
  return validOperationId(value.operationId)
    && validDigest(value.manifestDigest)
    && validDigest(value.generationDigest);
}

function profilesCoverRequested(requestedProfiles, readyProfiles) {
  return requestedProfiles.every((profile) => readyProfiles.includes(profile))
    && (!readyProfiles.includes('base') || readyProfiles.includes('core'));
}

function validateStateSemantics(value, requestedProfiles, readyProfiles, code) {
  const status = value.runtimeStatus;
  if (
    value.schemaVersion !== (status === 'RECOVERED' ? 2 : 1)
    || validateDeviceId(value.deviceId, code) !== value.deviceId
    || !RUNTIME_STATUSES.includes(status)
  ) fail(code);

  if (status === 'UNPROVISIONED') {
    if (
      requestedProfiles.length !== 0
      || readyProfiles.length !== 0
      || value.operationId !== null
      || value.manifestDigest !== null
      || value.generationDigest !== null
      || value.failureCode !== null
      || value.updatedAt !== null
    ) fail(code);
    return;
  }

  if (
    requestedProfiles.length === 0
    || !canonicalTimestamp(value.updatedAt)
    || (status === 'FAILED') !== (value.failureCode !== null)
    || (value.failureCode !== null && !FAILURE_CODES.has(value.failureCode))
    || (status !== 'READY' && readyProfiles.length !== 0)
  ) fail(code);

  if (status === 'RECOVERED') {
    if (
      requestedProfiles.length !== 1
      || requestedProfiles[0] !== 'core'
      || !identitiesAreFull(value)
    ) fail(code);
    return;
  }

  if (status === 'INVENTORY_READY') {
    if (
      !validOperationId(value.operationId)
      || value.manifestDigest !== null
      || value.generationDigest !== null
    ) fail(code);
    return;
  }

  if (['PLAN_READY', 'ACQUIRING', 'STAGED', 'VERIFYING'].includes(status)) {
    if (!identitiesAreFull(value)) fail(code);
    return;
  }

  if (status === 'READY') {
    const adoptedGeneration = value.operationId === null
      && value.manifestDigest === null
      && validDigest(value.generationDigest);
    if (
      (!identitiesAreFull(value) && !adoptedGeneration)
      || !profilesCoverRequested(requestedProfiles, readyProfiles)
    ) fail(code);
    return;
  }

  const noManifest = validOperationId(value.operationId)
    && value.manifestDigest === null
    && value.generationDigest === null;
  if (
    (!noManifest && !identitiesAreFull(value))
    || (UNCERTAIN_FAILURE_CODES.has(value.failureCode) && !identitiesAreFull(value))
  ) fail(code);
}

function validateRuntimeState(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactRecord(input, code);
  const requestedProfiles = readProfiles(value.requestedProfiles, code);
  const readyProfiles = readProfiles(value.readyProfiles, code);
  validateStateSemantics(value, requestedProfiles, readyProfiles, code);
  return Object.freeze({
    schemaVersion: value.schemaVersion,
    deviceId: value.deviceId,
    runtimeStatus: value.runtimeStatus,
    requestedProfiles,
    readyProfiles,
    operationId: value.operationId,
    manifestDigest: value.manifestDigest,
    generationDigest: value.generationDigest,
    failureCode: value.failureCode,
    updatedAt: value.updatedAt,
  });
}

export function validateRuntimeStateRecord(input) {
  return validateRuntimeState(input);
}

function sameState(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameRequestedProfiles(left, right) {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function assertTransition(expected, next) {
  if (
    expected.deviceId !== next.deviceId
    || !NEXT_STATUSES[expected.runtimeStatus].includes(next.runtimeStatus)
    || (expected.updatedAt !== null && next.updatedAt <= expected.updatedAt)
  ) fail('RUNTIME_INPUT_INVALID');

  if (expected.runtimeStatus === 'UNPROVISIONED') return;

  if (expected.runtimeStatus === 'FAILED' && next.runtimeStatus === 'RECOVERED') {
    if (
      expected.schemaVersion !== 1
      || next.schemaVersion !== 2
      || expected.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN'
      || expected.requestedProfiles.length !== 1
      || expected.requestedProfiles[0] !== 'core'
      || !sameRequestedProfiles(expected.requestedProfiles, next.requestedProfiles)
      || expected.readyProfiles.length !== 0
      || next.readyProfiles.length !== 0
      || next.operationId !== expected.operationId
      || next.manifestDigest !== expected.manifestDigest
      || next.generationDigest !== expected.generationDigest
      || next.failureCode !== null
    ) fail('RUNTIME_INPUT_INVALID');
    return;
  }

  if (expected.runtimeStatus === 'RECOVERED') {
    if (
      expected.schemaVersion !== 2
      || next.schemaVersion !== 1
      || next.runtimeStatus !== 'INVENTORY_READY'
      || !sameRequestedProfiles(expected.requestedProfiles, next.requestedProfiles)
      || next.operationId === expected.operationId
      || next.readyProfiles.length !== 0
      || next.manifestDigest !== null
      || next.generationDigest !== null
      || next.failureCode !== null
    ) fail('RUNTIME_INPUT_INVALID');
    return;
  }

  const freshAttempt = next.runtimeStatus === 'INVENTORY_READY';
  if (freshAttempt) {
    if (
      !['READY', 'FAILED'].includes(expected.runtimeStatus)
      || UNCERTAIN_FAILURE_CODES.has(expected.failureCode)
      || next.operationId === expected.operationId
      || next.readyProfiles.length !== 0
    ) fail('RUNTIME_INPUT_INVALID');
    return;
  }

  if (!sameRequestedProfiles(expected.requestedProfiles, next.requestedProfiles)) {
    fail('RUNTIME_INPUT_INVALID');
  }

  if (expected.runtimeStatus === 'FAILED') {
    if (
      !UNCERTAIN_FAILURE_CODES.has(expected.failureCode)
      || next.runtimeStatus !== 'PLAN_READY'
      || next.operationId !== expected.operationId
      || next.manifestDigest !== expected.manifestDigest
      || next.generationDigest !== expected.generationDigest
    ) fail('RUNTIME_INPUT_INVALID');
    return;
  }

  if (next.runtimeStatus === 'READY' && next.operationId === null) {
    if (expected.runtimeStatus !== 'INVENTORY_READY') fail('RUNTIME_INPUT_INVALID');
    return;
  }

  if (next.operationId !== expected.operationId) fail('RUNTIME_INPUT_INVALID');
  if (expected.manifestDigest !== null && (
    next.manifestDigest !== expected.manifestDigest
    || next.generationDigest !== expected.generationDigest
  )) fail('RUNTIME_INPUT_INVALID');
  if (next.runtimeStatus === 'FAILED' && expected.manifestDigest === null && (
    next.manifestDigest !== null || next.generationDigest !== null
  )) fail('RUNTIME_INPUT_INVALID');
}

function effectiveUid() {
  return typeof process.geteuid === 'function' ? BigInt(process.geteuid()) : null;
}

function assertSafeDirectory(stats) {
  if (
    !stats.isDirectory()
    || stats.isSymbolicLink()
    || (stats.mode & 0o777n) !== BigInt(DIRECTORY_MODE)
    || (effectiveUid() !== null && stats.uid !== effectiveUid())
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
}

function assertTrustedAncestor(stats) {
  if (
    !stats.isDirectory()
    || stats.isSymbolicLink()
    || (stats.mode & 0o022n) !== 0n
    || (effectiveUid() !== null && stats.uid !== effectiveUid())
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
}

function safeOwnerOnlyFileEndpoint(stats) {
  return stats.isFile()
    && !stats.isSymbolicLink()
    && stats.nlink === 1n
    && (stats.mode & 0o777n) === BigInt(FILE_MODE)
    && (effectiveUid() === null || stats.uid === effectiveUid());
}

function assertSafeFile(stats) {
  if (
    !safeOwnerOnlyFileEndpoint(stats)
    || stats.size < 1n
    || stats.size > BigInt(MAX_STATE_BYTES)
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameMetadata(left, right) {
  return sameIdentity(left, right)
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sameDirectoryMetadata(left, right) {
  return sameIdentity(left, right)
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

async function runStateTestHook(event, context) {
  let hook = NO_TEST_HOOK;
  if (process.env.NODE_TEST_CONTEXT !== undefined) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, RUNTIME_STATE_TEST_HOOK);
    if (descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function') {
      hook = descriptor.value;
    }
  }
  await hook(event, Object.freeze({ ...context }));
}

async function assertNoDarwinExtendedAcl(path) {
  if (process.platform !== 'darwin') return;
  let output;
  try {
    output = await execFile('/bin/ls', ['-lde', '--', path], {
      encoding: 'utf8',
      env: Object.freeze({
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
      }),
      maxBuffer: 16 * 1024,
      timeout: 2_000,
    });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  if (
    output === null
    || typeof output !== 'object'
    || typeof output.stdout !== 'string'
    || typeof output.stderr !== 'string'
    || output.stderr.length !== 0
    || output.stdout.length === 0
    || output.stdout.includes('\0')
    || /^\s+[0-9]+:\s/mu.test(output.stdout)
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
}

async function maybeLstat(path) {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    if (safeOwnString(error, 'code') === 'ENOENT') return null;
    throw error;
  }
}

async function assertCanonicalPath(path) {
  let resolved;
  try {
    resolved = await realpath(path);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  if (resolved !== path) fail('RUNTIME_STATE_UNSUPPORTED', Error);
}

async function assertSafeDirectoryPath(path, expectedIdentity = null) {
  const before = await lstat(path, { bigint: true });
  assertSafeDirectory(before);
  if (expectedIdentity !== null && !sameIdentity(before, expectedIdentity)) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  await assertNoDarwinExtendedAcl(path);
  await runStateTestHook('afterDirectoryAclCheck', { path });
  await assertCanonicalPath(path);
  await assertNoDarwinExtendedAcl(path);
  const after = await lstat(path, { bigint: true });
  assertSafeDirectory(after);
  if (!sameDirectoryMetadata(before, after)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return after;
}

async function assertTrustedAncestorPath(path) {
  const before = await lstat(path, { bigint: true });
  assertTrustedAncestor(before);
  await assertNoDarwinExtendedAcl(path);
  await runStateTestHook('afterDirectoryAclCheck', { path });
  await assertCanonicalPath(path);
  await assertNoDarwinExtendedAcl(path);
  const after = await lstat(path, { bigint: true });
  assertTrustedAncestor(after);
  if (!sameDirectoryMetadata(before, after)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return after;
}

async function assertSafeFilePath(path, expectedIdentity = null) {
  const before = await lstat(path, { bigint: true });
  assertSafeFile(before);
  if (expectedIdentity !== null && !sameIdentity(before, expectedIdentity)) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  await assertNoDarwinExtendedAcl(path);
  const after = await lstat(path, { bigint: true });
  assertSafeFile(after);
  if (!sameMetadata(before, after)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return after;
}

async function assertOptionalSafeFile(path) {
  const stats = await maybeLstat(path);
  if (stats === null) return null;
  return assertSafeFilePath(path, stats);
}

async function assertOptionalSafeLockFile(path) {
  const initial = await maybeLstat(path);
  if (initial === null) return null;
  if (safeOwnerOnlyFileEndpoint(initial) && initial.size === 0n) return null;
  await runStateTestHook('afterOptionalLockObservation', { path });
  try {
    return await assertSafeFilePath(path, initial);
  } catch (error) {
    // The previous owner may release this advisory lock between the stat and
    // ACL probes. Recheck the endpoint; acquisition still uses exclusive create.
    if (!OWN_ERRORS.has(error) && safeOwnString(error, 'code') !== 'ENOENT') throw error;
    const current = await maybeLstat(path);
    if (
      current === null
      || !sameIdentity(initial, current)
      || (
        safeOwnerOnlyFileEndpoint(initial)
        && safeOwnerOnlyFileEndpoint(current)
        && current.size <= BigInt(MAX_STATE_BYTES)
        && !sameMetadata(initial, current)
      )
    ) return null;
    throw error;
  }
}

async function findExistingAncestor(path) {
  const missing = [];
  let current = path;
  let stats = await maybeLstat(current);
  while (stats === null) {
    missing.push(current);
    const parent = dirname(current);
    if (parent === current) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    current = parent;
    stats = await maybeLstat(current);
  }
  return Object.freeze({ current, missing: Object.freeze(missing) });
}

async function assertMissingPathAnchor(path) {
  const { current } = await findExistingAncestor(path);
  await assertTrustedAncestorPath(current);
}

async function ensureSafeDirectoryChain(path) {
  const { current, missing } = await findExistingAncestor(path);
  await assertTrustedAncestorPath(current);
  for (const directory of [...missing].reverse()) {
    try {
      await mkdir(directory, { mode: DIRECTORY_MODE });
    } catch (error) {
      if (safeOwnString(error, 'code') !== 'EEXIST') throw error;
    }
    await assertSafeDirectoryPath(directory);
  }
  return assertSafeDirectoryPath(path);
}

async function inspectReadLayout(root, statePath) {
  const rootStats = await maybeLstat(root);
  if (rootStats === null) {
    await assertMissingPathAnchor(root);
    return null;
  }
  const safeRoot = await assertSafeDirectoryPath(root, rootStats);
  const devicePath = dirname(statePath);
  const deviceStats = await maybeLstat(devicePath);
  if (deviceStats === null) return null;
  const safeDevice = await assertSafeDirectoryPath(devicePath, deviceStats);
  const stateStats = await assertOptionalSafeFile(statePath);
  const lockPath = `${statePath}.lock`;
  const observedLock = await maybeLstat(lockPath);
  if (observedLock !== null) await assertOptionalSafeLockFile(lockPath);
  if (stateStats === null && observedLock === null) return null;
  return Object.freeze({ root: safeRoot, device: safeDevice, state: stateStats });
}

async function ensureWriteLayout(root, statePath) {
  const safeRoot = await ensureSafeDirectoryChain(root);
  const safeDevice = await ensureSafeDirectoryChain(dirname(statePath));
  await assertOptionalSafeFile(statePath);
  await assertOptionalSafeLockFile(`${statePath}.lock`);
  return Object.freeze({ root: safeRoot, device: safeDevice });
}

async function readExact(file, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await file.read(bytes, offset, size - offset, offset);
    if (bytesRead <= 0) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    offset += bytesRead;
  }
  return bytes;
}

async function readPersistedState(statePath, deviceId) {
  let file;
  let primary;
  let bytes;
  try {
    const initial = await assertSafeFilePath(statePath);
    await runStateTestHook('afterStateAclCheck', { path: statePath });
    file = await open(
      statePath,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await file.stat({ bigint: true });
    const pathBefore = await lstat(statePath, { bigint: true });
    assertSafeFile(before);
    assertSafeFile(pathBefore);
    if (!sameMetadata(initial, before) || !sameMetadata(before, pathBefore)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const size = Number(before.size);
    const first = await readExact(file, size);
    const middle = await file.stat({ bigint: true });
    const second = await readExact(file, size);
    await assertNoDarwinExtendedAcl(statePath);
    const after = await file.stat({ bigint: true });
    const pathAfter = await lstat(statePath, { bigint: true });
    if (
      !sameMetadata(before, middle)
      || !sameMetadata(middle, after)
      || !sameMetadata(after, pathAfter)
      || !first.equals(second)
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    bytes = first;
  } catch (error) {
    primary = error;
  } finally {
    try {
      await file?.close();
    } catch (error) {
      primary ??= error;
    }
  }
  if (primary !== undefined) {
    if (OWN_ERRORS.has(primary)) throw primary;
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }

  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  const snapshot = validateRuntimeState(parsed, 'RUNTIME_STATE_UNSUPPORTED');
  if (
    snapshot.deviceId !== deviceId
    || snapshot.runtimeStatus === 'UNPROVISIONED'
    || !bytes.equals(Buffer.from(`${JSON.stringify(snapshot, null, 2)}\n`, 'utf8'))
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return snapshot;
}

async function withMappedErrors(operation) {
  try {
    return await operation();
  } catch (error) {
    throw mapStoreError(error);
  }
}

async function assertPersistedRecoveryCommit(root, snapshot) {
  try {
    await verifyRuntimeRecoveredState({
      runtimeDevicesRoot: root,
      proposedRecoveredState: snapshot,
    });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
}

async function assertRecoveryCommit(root, expected, next) {
  try {
    await verifyRuntimeRecoveryCommit({
      runtimeDevicesRoot: root,
      expectedFailedState: expected,
      proposedRecoveredState: next,
    });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
}

export class RuntimeStateStore {
  #root;

  constructor(runtimeDevicesRoot) {
    this.#root = validateRoot(runtimeDevicesRoot);
    Object.freeze(this);
  }

  async read(deviceIdInput) {
    const deviceId = validateDeviceId(deviceIdInput);
    const statePath = runtimeDeviceStatePath(this.#root, deviceId);
    return withMappedErrors(async () => {
      const layout = await inspectReadLayout(this.#root, statePath);
      if (layout === null) {
        return unprovisionedState(deviceId);
      }
      await runStateTestHook('afterStateLayoutCheck', { path: dirname(statePath) });
      return withFileLock(statePath, async () => {
        await assertSafeDirectoryPath(this.#root, layout.root);
        await assertSafeDirectoryPath(dirname(statePath), layout.device);
        await assertSafeFilePath(`${statePath}.lock`);
        const stateStats = await assertOptionalSafeFile(statePath);
        if (stateStats === null) return unprovisionedState(deviceId);
        const snapshot = await readPersistedState(statePath, deviceId);
        if (snapshot.runtimeStatus === 'RECOVERED') {
          await assertPersistedRecoveryCommit(this.#root, snapshot);
        }
        return snapshot;
      }, { name: 'runtime state' });
    });
  }

  async transition(expectedInput, nextInput) {
    return this.#transition(expectedInput, nextInput, false);
  }

  async confirmTerminalRollback(expectedInput, nextInput) {
    const expected = validateRuntimeState(expectedInput);
    const next = validateRuntimeState(nextInput);
    return withTerminalRollbackStateConfirmation(this.#root, expected, next,
      () => this.#transition(expected, next, true));
  }

  async #transition(expectedInput, nextInput, terminalRollback) {
    const expected = validateRuntimeState(expectedInput);
    const next = validateRuntimeState(nextInput);
    const assertPair = terminalRollback ? assertTerminalRollbackStatePair : assertTransition;
    assertPair(expected, next);
    const statePath = runtimeDeviceStatePath(this.#root, expected.deviceId);
    return withMappedErrors(async () => {
      const layout = await ensureWriteLayout(this.#root, statePath);
      await runStateTestHook('afterStateLayoutCheck', { path: dirname(statePath) });
      return withFileLock(statePath, async () => {
        await assertSafeDirectoryPath(this.#root, layout.root);
        await assertSafeDirectoryPath(dirname(statePath), layout.device);
        await assertSafeFilePath(`${statePath}.lock`);
        const stateStats = await assertOptionalSafeFile(statePath);
        const current = stateStats === null
          ? unprovisionedState(expected.deviceId)
          : await readPersistedState(statePath, expected.deviceId);
        if (current.runtimeStatus === 'RECOVERED') {
          await assertPersistedRecoveryCommit(this.#root, current);
        }
        if (!sameState(current, expected)) fail('RUNTIME_ALREADY_RUNNING', Error);
        assertPair(expected, next);
        if (terminalRollback) await verifyTerminalRollbackCommit(this.#root, expected, next);
        if (next.runtimeStatus === 'RECOVERED') {
          await assertRecoveryCommit(this.#root, expected, next);
        }
        await assertSafeDirectoryPath(this.#root, layout.root);
        await assertSafeDirectoryPath(dirname(statePath), layout.device);
        await writeJsonAtomic(statePath, next);
        await runStateTestHook('afterStatePublication', { path: statePath });
        await assertSafeDirectoryPath(this.#root, layout.root);
        await assertSafeDirectoryPath(dirname(statePath), layout.device);
        const saved = await readPersistedState(statePath, next.deviceId);
        if (!sameState(saved, next)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
        if (saved.runtimeStatus === 'RECOVERED') {
          await assertPersistedRecoveryCommit(this.#root, saved);
        }
        return saved;
      }, { name: 'runtime state' });
    });
  }
}
