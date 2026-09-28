import { execFile as execFileCallback, spawn } from 'node:child_process';
import {
  createHash,
  createHmac,
  randomBytes as cryptoRandomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { constants } from 'node:fs';
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import {
  isAbsolute,
  dirname,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { promisify, TextDecoder } from 'node:util';
import { isProxy } from 'node:util/types';

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const BASELINE_ID_PATTERN = /^rbl_[a-f0-9]{64}$/u;
const COMPARISON_ID_PATTERN = /^rbc_[a-f0-9]{64}$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const ISO_TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const MAX_PATH_BYTES = 4_096;
const MAX_RECORD_BYTES = 16_384;
const MAX_NAMESPACE_ENTRIES = 1_024;
const BASELINE_TTL_MS = 24 * 60 * 60 * 1_000;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const LOCKF_WAIT_SECONDS = 1;
const LOCKF_WATCHDOG_GRACE_MS = 500;
const LOCKF_OUTPUT_LIMIT = 1_024;
const LOCKF_TEMPFAIL = 75;
const AGGREGATE_DOMAIN = Buffer.from('AgentRoad.RuntimeBaseline.Aggregate.v1\0', 'ascii');
const BASELINE_RECORD_DOMAIN = 'AgentRoad.RuntimeBaseline.Record.v1\0';
const COMPARISON_RECORD_DOMAIN = 'AgentRoad.RuntimeBaseline.Comparison.v1\0';
const execFile = promisify(execFileCallback);
const BASELINE_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'baselineId',
  'deviceId',
  'protocolRevision',
  'scriptSha256',
  'hmacKeyBase64',
  'surfaces',
  'captureAggregateMac',
  'capturedAt',
  'expiresAt',
  'recordDigest',
]);
const COMPARISON_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'comparisonId',
  'deviceId',
  'baselineId',
  'baselineRecordDigest',
  'protocolRevision',
  'scriptSha256',
  'observedSurfaces',
  'observedAggregateMac',
  'status',
  'changedSurfaces',
  'comparedAt',
  'recordDigest',
]);
const SURFACE_FIELDS = Object.freeze(['id', 'count', 'mac']);
const CHANGE_FIELDS = Object.freeze(['id', 'countChanged', 'macChanged']);

export const RUNTIME_BASELINE_SURFACE_LIMITS = Object.freeze({
  'account-environment': 128,
  'account-profile-identity': 4,
  'command-resolution': 32,
  'external-sentinel-acls': 16,
  'firewall-profiles': 3,
  'firewall-rules': 32,
  'machine-environment': 256,
  'scheduled-tasks': 64,
  'service-definitions': 16,
});
export const RUNTIME_BASELINE_SURFACE_IDS = Object.freeze(
  Object.keys(RUNTIME_BASELINE_SURFACE_LIMITS),
);

const KNOWN_CODES = new Set([
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_STATE_UNSUPPORTED',
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_INTERNAL_ERROR',
]);

function runtimeError(code, Type = Error) {
  const error = new Type(code);
  error.code = code;
  return error;
}

function failInput() {
  throw runtimeError('RUNTIME_INPUT_INVALID', TypeError);
}

function failState() {
  throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
}

function exactObject(input, fields, failure = failInput) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failure();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    failure();
  }
  const values = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) failure();
    values[field] = descriptor.value;
  }
  return values;
}

function exactArray(input, length, failure = failInput) {
  if (
    input === null
    || typeof input !== 'object'
    || !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failure();
  const lengthDescriptor = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    lengthDescriptor === undefined
    || !Object.hasOwn(lengthDescriptor, 'value')
    || lengthDescriptor.value !== length
  ) failure();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== length + 1) failure();
  const result = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) failure();
    result.push(descriptor.value);
  }
  if (!names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/u.test(name))) {
    failure();
  }
  return result;
}

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const child of value) deepFreeze(child);
  } else if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return Object.freeze(value);
}

function canonicalTimestamp(value, failure = failInput) {
  if (typeof value !== 'string' || !ISO_TIMESTAMP_PATTERN.test(value)) failure();
  let canonical;
  try {
    canonical = new Date(value).toISOString();
  } catch {
    failure();
  }
  if (canonical !== value) failure();
  return value;
}

function canonicalKey(value, failure = failInput) {
  if (typeof value !== 'string' || value.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/u.test(value)) {
    failure();
  }
  let bytes;
  try {
    bytes = Buffer.from(value, 'base64');
  } catch {
    failure();
  }
  if (bytes.length !== 32 || bytes.toString('base64') !== value) failure();
  return Buffer.from(bytes);
}

function canonicalDeviceId(value, failure = failInput) {
  if (typeof value !== 'string' || value.length > 64 || !DEVICE_ID_PATTERN.test(value)) failure();
  return value;
}

function canonicalId(value, pattern, failure = failInput) {
  if (typeof value !== 'string' || !pattern.test(value)) failure();
  return value;
}

function canonicalSha256(value, failure = failInput) {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) failure();
  return value;
}

function canonicalSurfaces(input, failure = failInput) {
  const values = exactArray(input, RUNTIME_BASELINE_SURFACE_IDS.length, failure);
  return deepFreeze(values.map((entry, index) => {
    const surface = exactObject(entry, SURFACE_FIELDS, failure);
    const id = RUNTIME_BASELINE_SURFACE_IDS[index];
    if (
      surface.id !== id
      || !Number.isSafeInteger(surface.count)
      || Object.is(surface.count, -0)
      || surface.count < 0
      || surface.count > RUNTIME_BASELINE_SURFACE_LIMITS[id]
      || (id === 'firewall-profiles' && surface.count !== 3)
      || typeof surface.mac !== 'string'
      || !SHA256_PATTERN.test(surface.mac)
    ) failure();
    return { id, count: surface.count, mac: surface.mac };
  }));
}

function updateFramed(hmac, value) {
  const bytes = Buffer.from(value, 'utf8');
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.length);
  hmac.update(length);
  hmac.update(bytes);
}

export function runtimeBaselineAggregateMac(input) {
  const value = exactObject(input, ['hmacKeyBase64', 'surfaces']);
  const key = canonicalKey(value.hmacKeyBase64);
  const surfaces = canonicalSurfaces(value.surfaces);
  try {
    const hmac = createHmac('sha256', key);
    hmac.update(AGGREGATE_DOMAIN);
    for (const surface of surfaces) {
      updateFramed(hmac, surface.id);
      updateFramed(hmac, String(surface.count));
      updateFramed(hmac, surface.mac);
    }
    return hmac.digest('hex').toUpperCase();
  } finally {
    key.fill(0);
  }
}

export function runtimeBaselineChangedSurfaces(input) {
  const value = exactObject(input, ['baselineSurfaces', 'observedSurfaces']);
  const baseline = canonicalSurfaces(value.baselineSurfaces);
  const observed = canonicalSurfaces(value.observedSurfaces);
  const changed = [];
  for (let index = 0; index < baseline.length; index += 1) {
    const countChanged = baseline[index].count !== observed[index].count;
    const macChanged = !timingSafeEqual(
      Buffer.from(baseline[index].mac, 'hex'),
      Buffer.from(observed[index].mac, 'hex'),
    );
    if (countChanged || macChanged) {
      changed.push(Object.freeze({
        id: baseline[index].id,
        countChanged,
        macChanged,
      }));
    }
  }
  return Object.freeze(changed);
}

function digestRecord(domain, value) {
  return createHash('sha256')
    .update(domain, 'ascii')
    .update(JSON.stringify(value), 'utf8')
    .digest('hex')
    .toUpperCase();
}

function canonicalNow(now) {
  let value;
  let milliseconds;
  let timestamp;
  try {
    value = now();
    if (
      value === null
      || typeof value !== 'object'
      || isProxy(value)
      || Object.getPrototypeOf(value) !== Date.prototype
      || Object.getOwnPropertyNames(value).length !== 0
      || Object.getOwnPropertySymbols(value).length !== 0
    ) throw new TypeError('invalid clock');
    milliseconds = Date.prototype.getTime.call(value);
    timestamp = Date.prototype.toISOString.call(value);
  } catch {
    throw runtimeError('RUNTIME_INTERNAL_ERROR');
  }
  if (!Number.isFinite(milliseconds)) {
    throw runtimeError('RUNTIME_INTERNAL_ERROR');
  }
  return timestamp;
}

function validateRoot(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || !isAbsolute(value)
    || resolve(value) !== value
    || Buffer.byteLength(value, 'utf8') > MAX_PATH_BYTES
    || /[\x00-\x1f\x7f]/u.test(value)
  ) failInput();
  return value;
}

function baselinePaths(root, deviceId, id, kind, baselineId = null) {
  canonicalDeviceId(deviceId);
  const isBaseline = kind === 'baseline';
  canonicalId(id, isBaseline ? BASELINE_ID_PATTERN : COMPARISON_ID_PATTERN);
  if (!isBaseline) canonicalId(baselineId, BASELINE_ID_PATTERN);
  const device = join(root, deviceId);
  const records = join(device, 'runtime-baselines');
  const directory = isBaseline
    ? join(records, 'baselines')
    : join(records, 'comparisons', baselineId);
  const final = join(directory, `${id}.json`);
  if (Buffer.byteLength(`${final}.publish-${'x'.repeat(36)}.tmp`, 'utf8') > MAX_PATH_BYTES) {
    failInput();
  }
  return Object.freeze({ device, records, directory, final });
}

function baselineDigestInput(input) {
  const value = exactObject(input, BASELINE_FIELDS.slice(0, -1));
  return {
    schemaVersion: value.schemaVersion,
    recordType: value.recordType,
    baselineId: value.baselineId,
    deviceId: value.deviceId,
    protocolRevision: value.protocolRevision,
    scriptSha256: value.scriptSha256,
    hmacKeyBase64: value.hmacKeyBase64,
    surfaces: value.surfaces,
    captureAggregateMac: value.captureAggregateMac,
    capturedAt: value.capturedAt,
    expiresAt: value.expiresAt,
  };
}

function comparisonDigestInput(input) {
  const value = exactObject(input, COMPARISON_FIELDS.slice(0, -1));
  return {
    schemaVersion: value.schemaVersion,
    recordType: value.recordType,
    comparisonId: value.comparisonId,
    deviceId: value.deviceId,
    baselineId: value.baselineId,
    baselineRecordDigest: value.baselineRecordDigest,
    protocolRevision: value.protocolRevision,
    scriptSha256: value.scriptSha256,
    observedSurfaces: value.observedSurfaces,
    observedAggregateMac: value.observedAggregateMac,
    status: value.status,
    changedSurfaces: value.changedSurfaces,
    comparedAt: value.comparedAt,
  };
}

function canonicalBaseline(input, failure = failState) {
  const value = exactObject(input, BASELINE_FIELDS, failure);
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RUNTIME_BASELINE'
    || value.protocolRevision !== 1
  ) failure();
  canonicalId(value.baselineId, BASELINE_ID_PATTERN, failure);
  canonicalDeviceId(value.deviceId, failure);
  canonicalSha256(value.scriptSha256, failure);
  canonicalKey(value.hmacKeyBase64, failure).fill(0);
  const surfaces = canonicalSurfaces(value.surfaces, failure);
  canonicalSha256(value.captureAggregateMac, failure);
  canonicalTimestamp(value.capturedAt, failure);
  canonicalTimestamp(value.expiresAt, failure);
  const expectedExpiry = new Date(Date.parse(value.capturedAt) + BASELINE_TTL_MS).toISOString();
  if (value.expiresAt !== expectedExpiry) failure();
  const aggregate = runtimeBaselineAggregateMac({
    hmacKeyBase64: value.hmacKeyBase64,
    surfaces,
  });
  if (!timingSafeEqual(
    Buffer.from(aggregate, 'hex'),
    Buffer.from(value.captureAggregateMac, 'hex'),
  )) failure();
  canonicalSha256(value.recordDigest, failure);
  const canonical = {
    schemaVersion: 1,
    recordType: 'RUNTIME_BASELINE',
    baselineId: value.baselineId,
    deviceId: value.deviceId,
    protocolRevision: 1,
    scriptSha256: value.scriptSha256,
    hmacKeyBase64: value.hmacKeyBase64,
    surfaces,
    captureAggregateMac: value.captureAggregateMac,
    capturedAt: value.capturedAt,
    expiresAt: value.expiresAt,
  };
  const digest = digestRecord(BASELINE_RECORD_DOMAIN, canonical);
  if (!timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(value.recordDigest, 'hex'))) {
    failure();
  }
  return deepFreeze({ ...canonical, recordDigest: value.recordDigest });
}

function canonicalChangedSurfaces(input, failure = failState) {
  if (
    input === null
    || typeof input !== 'object'
    || !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || input.length > RUNTIME_BASELINE_SURFACE_IDS.length
  ) failure();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== input.length + 1) failure();
  let prior = -1;
  const changed = [];
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      failure();
    }
    const value = exactObject(descriptor.value, CHANGE_FIELDS, failure);
    const position = RUNTIME_BASELINE_SURFACE_IDS.indexOf(value.id);
    if (
      position <= prior
      || typeof value.countChanged !== 'boolean'
      || typeof value.macChanged !== 'boolean'
      || (!value.countChanged && !value.macChanged)
    ) failure();
    prior = position;
    changed.push(Object.freeze({
      id: value.id,
      countChanged: value.countChanged,
      macChanged: value.macChanged,
    }));
  }
  if (!names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/u.test(name))) {
    failure();
  }
  return Object.freeze(changed);
}

function canonicalComparison(input, failure = failState) {
  const value = exactObject(input, COMPARISON_FIELDS, failure);
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RUNTIME_BASELINE_COMPARISON'
    || value.protocolRevision !== 1
    || !['UNCHANGED', 'CHANGED'].includes(value.status)
  ) failure();
  canonicalId(value.comparisonId, COMPARISON_ID_PATTERN, failure);
  canonicalDeviceId(value.deviceId, failure);
  canonicalId(value.baselineId, BASELINE_ID_PATTERN, failure);
  canonicalSha256(value.baselineRecordDigest, failure);
  canonicalSha256(value.scriptSha256, failure);
  const observedSurfaces = canonicalSurfaces(value.observedSurfaces, failure);
  canonicalSha256(value.observedAggregateMac, failure);
  const changedSurfaces = canonicalChangedSurfaces(value.changedSurfaces, failure);
  if ((value.status === 'UNCHANGED') !== (changedSurfaces.length === 0)) failure();
  canonicalTimestamp(value.comparedAt, failure);
  canonicalSha256(value.recordDigest, failure);
  const canonical = {
    schemaVersion: 1,
    recordType: 'RUNTIME_BASELINE_COMPARISON',
    comparisonId: value.comparisonId,
    deviceId: value.deviceId,
    baselineId: value.baselineId,
    baselineRecordDigest: value.baselineRecordDigest,
    protocolRevision: 1,
    scriptSha256: value.scriptSha256,
    observedSurfaces,
    observedAggregateMac: value.observedAggregateMac,
    status: value.status,
    changedSurfaces,
    comparedAt: value.comparedAt,
  };
  const digest = digestRecord(COMPARISON_RECORD_DOMAIN, canonical);
  if (!timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(value.recordDigest, 'hex'))) {
    failure();
  }
  return deepFreeze({ ...canonical, recordDigest: value.recordDigest });
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sameDirectoryEndpoint(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

function sameFileEndpoint(left, right) {
  return sameDirectoryEndpoint(left, right)
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs;
}

function currentUid() {
  if (typeof process.geteuid !== 'function') throw runtimeError('RUNTIME_INTERNAL_ERROR');
  return BigInt(process.geteuid());
}

async function safeLstat(path, missing = false) {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    if (missing && error?.code === 'ENOENT') return null;
    if (error?.code === 'ENOENT') failState();
    throw error;
  }
}

async function assertTrustedDirectory(path) {
  const before = await safeLstat(path);
  if (
    !before.isDirectory()
    || before.isSymbolicLink()
    || before.uid !== currentUid()
    || (before.mode & 0o022n) !== 0n
  ) failState();
  await assertNoDarwinExtendedAcl(path);
  let canonical;
  try {
    canonical = await realpath(path);
  } catch {
    failState();
  }
  if (canonical !== path) failState();
  await assertNoDarwinExtendedAcl(path);
  const after = await safeLstat(path);
  if (!sameDirectoryEndpoint(before, after)) failState();
  return after;
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
    failState();
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
  ) failState();
}

async function assertManagedDirectory(path) {
  const stats = await assertTrustedDirectory(path);
  if ((stats.mode & 0o777n) !== BigInt(DIRECTORY_MODE)) failState();
  return stats;
}

async function nearestExistingDirectory(path) {
  let candidate = path;
  while (true) {
    const stats = await safeLstat(candidate, true);
    if (stats !== null) return { path: candidate, stats };
    const parent = dirname(candidate);
    if (parent === candidate) failState();
    candidate = parent;
  }
}

function relativeManagedParts(root, target) {
  const suffix = relative(root, target);
  if (suffix.startsWith('..') || isAbsolute(suffix)) failState();
  if (suffix === '') return [];
  const parts = suffix.split(sep);
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..')) failState();
  return parts;
}

async function assertManagedDirectoryChain(root, target, expected = null) {
  const parts = relativeManagedParts(root, target);
  if (expected !== null && (!Array.isArray(expected) || expected.length !== parts.length + 1)) {
    failState();
  }
  const observed = [];
  let cursor = root;
  let stats = await assertManagedDirectory(cursor);
  if (
    expected !== null
    && (expected[0].path !== cursor || !sameDirectoryEndpoint(expected[0].stats, stats))
  ) failState();
  observed.push(Object.freeze({ path: cursor, stats }));
  let index = 1;
  for (const part of parts) {
    cursor = join(cursor, part);
    stats = await assertManagedDirectory(cursor);
    if (
      expected !== null
      && (expected[index].path !== cursor
        || !sameDirectoryEndpoint(expected[index].stats, stats))
    ) failState();
    observed.push(Object.freeze({ path: cursor, stats }));
    index += 1;
  }
  return Object.freeze(observed);
}

async function ensureManagedRoot(root) {
  const nearest = await nearestExistingDirectory(root);
  await assertTrustedDirectory(nearest.path);
  const suffix = relative(nearest.path, root);
  if (suffix === '' || suffix.startsWith('..') || isAbsolute(suffix)) {
    if (suffix === '') return assertManagedDirectory(root);
    failState();
  }
  let cursor = nearest.path;
  for (const part of suffix.split(sep)) {
    if (part.length === 0 || part === '.' || part === '..') failState();
    cursor = join(cursor, part);
    try {
      await mkdir(cursor, { mode: DIRECTORY_MODE });
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    await assertManagedDirectory(cursor);
    await syncDirectory(dirname(cursor));
  }
  return assertManagedDirectory(root);
}

async function ensureManagedChain(root, target) {
  await ensureManagedRoot(root);
  const parts = relativeManagedParts(root, target);
  let cursor = root;
  for (const part of parts) {
    const parent = cursor;
    cursor = join(cursor, part);
    try {
      await mkdir(cursor, { mode: DIRECTORY_MODE });
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    await assertManagedDirectory(cursor);
    await syncDirectory(parent);
  }
  await assertManagedDirectoryChain(root, target);
}

async function syncDirectory(path) {
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function namespaceLockPath(records, kind) {
  if (!['baseline', 'comparison'].includes(kind)) failState();
  return join(records, kind === 'baseline' ? '.baselines.lock' : '.comparisons.lock');
}

function assertSafeLockStats(stats) {
  if (
    !stats.isFile()
    || stats.isSymbolicLink()
    || stats.uid !== currentUid()
    || (stats.mode & 0o777n) !== BigInt(FILE_MODE)
    || stats.nlink !== 1n
    || stats.size !== 0n
  ) failState();
}

async function assertSafeLockPath(path, expected) {
  const before = await safeLstat(path);
  assertSafeLockStats(before);
  if (!sameIdentity(before, expected)) failState();
  await assertNoDarwinExtendedAcl(path);
  const after = await safeLstat(path);
  assertSafeLockStats(after);
  if (!sameIdentity(before, after)) failState();
  return after;
}

async function openNamespaceLock(root, records, kind, create) {
  if (create) await ensureManagedChain(root, records);
  const chain = await assertManagedDirectoryChain(root, records);
  const path = namespaceLockPath(records, kind);
  let file;
  let primary;
  try {
    if (create) {
      try {
        file = await open(
          path,
          constants.O_RDWR
            | constants.O_CREAT
            | constants.O_EXCL
            | constants.O_NOFOLLOW
            | constants.O_NONBLOCK,
          FILE_MODE,
        );
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
      }
    }
    if (!file) {
      file = await open(
        path,
        constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
    }
    const opened = await file.stat({ bigint: true });
    assertSafeLockStats(opened);
    await assertSafeLockPath(path, opened);
    await file.sync();
    await assertManagedDirectoryChain(root, records, chain);
    await syncDirectory(records);
    await assertManagedDirectoryChain(root, records, chain);
    const synced = await file.stat({ bigint: true });
    assertSafeLockStats(synced);
    const endpoint = await assertSafeLockPath(path, synced);
    if (!sameIdentity(opened, synced) || !sameIdentity(synced, endpoint)) failState();
    return Object.freeze({ file, path, stats: synced, chain });
  } catch (error) {
    primary = error;
  }
  try { await file?.close(); } catch (error) { primary ??= error; }
  if (primary?.code === 'ENOENT') failState();
  throw primary;
}

async function acquireNamespaceLock(file) {
  if (process.platform !== 'darwin') failState();
  await new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let outputLength = 0;
    let outputInvalid = false;
    let timedOut = false;
    let timer;
    const child = spawn('/usr/bin/lockf', [
      '-s',
      '-t',
      String(LOCKF_WAIT_SECONDS),
      '3',
    ], {
      env: Object.freeze({
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
      }),
      stdio: ['ignore', 'pipe', 'pipe', file.fd],
      windowsHide: true,
    });
    const settle = (error = null) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (error === null) resolvePromise();
      else rejectPromise(error);
    };
    const observeOutput = (chunk) => {
      outputLength += chunk.length;
      if (outputLength > LOCKF_OUTPUT_LIMIT) {
        outputInvalid = true;
        child.kill('SIGKILL');
      }
    };
    child.stdout.on('data', observeOutput);
    child.stderr.on('data', observeOutput);
    child.once('error', () => settle(runtimeError('RUNTIME_STATE_UNSUPPORTED')));
    child.once('close', (code, signal) => {
      if (timedOut || outputInvalid || signal !== null || outputLength !== 0) {
        settle(runtimeError('RUNTIME_STATE_UNSUPPORTED'));
      } else if (code === LOCKF_TEMPFAIL) {
        settle(runtimeError('RUNTIME_ALREADY_RUNNING'));
      } else if (code !== 0) {
        settle(runtimeError('RUNTIME_STATE_UNSUPPORTED'));
      } else {
        settle();
      }
    });
    timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, (LOCKF_WAIT_SECONDS * 1_000) + LOCKF_WATCHDOG_GRACE_MS);
    timer.unref();
  });
}

async function withNamespaceLock(root, records, kind, create, operation) {
  const anchor = await openNamespaceLock(root, records, kind, create);
  let primary;
  let result;
  try {
    await acquireNamespaceLock(anchor.file);
    await assertManagedDirectoryChain(root, records, anchor.chain);
    const locked = await anchor.file.stat({ bigint: true });
    assertSafeLockStats(locked);
    const endpoint = await assertSafeLockPath(anchor.path, anchor.stats);
    if (!sameIdentity(anchor.stats, locked) || !sameIdentity(locked, endpoint)) failState();
    result = await operation();
    await assertManagedDirectoryChain(root, records, anchor.chain);
    const completed = await anchor.file.stat({ bigint: true });
    const completedEndpoint = await assertSafeLockPath(anchor.path, anchor.stats);
    if (!sameIdentity(anchor.stats, completed) || !sameIdentity(completed, completedEndpoint)) {
      failState();
    }
  } catch (error) {
    primary = error;
  } finally {
    try { await anchor.file.close(); } catch (error) { primary ??= error; }
  }
  if (primary !== undefined) throw primary;
  return result;
}

function finalPattern(kind) {
  return kind === 'baseline'
    ? /^rbl_[a-f0-9]{64}\.json$/u
    : /^rbc_[a-f0-9]{64}\.json$/u;
}

function witnessPattern(kind) {
  const prefix = kind === 'baseline' ? 'rbl_' : 'rbc_';
  return new RegExp(
    `^(${prefix}[a-f0-9]{64}\\.json)\\.publish-([a-f0-9-]{36})\\.tmp$`,
    'u',
  );
}

async function assertPublicationPair(final, witness) {
  const finalBefore = await safeLstat(final);
  const witnessBefore = await safeLstat(witness);
  for (const stats of [finalBefore, witnessBefore]) {
    if (
      !stats.isFile()
      || stats.isSymbolicLink()
      || stats.uid !== currentUid()
      || (stats.mode & 0o777n) !== BigInt(FILE_MODE)
      || stats.nlink !== 2n
      || stats.size < 1n
      || stats.size > BigInt(MAX_RECORD_BYTES)
    ) failState();
  }
  if (finalBefore.dev !== witnessBefore.dev || finalBefore.ino !== witnessBefore.ino) failState();
  await assertNoDarwinExtendedAcl(final);
  await assertNoDarwinExtendedAcl(witness);
  const finalAfter = await safeLstat(final);
  const witnessAfter = await safeLstat(witness);
  if (!sameIdentity(finalBefore, finalAfter) || !sameIdentity(witnessBefore, witnessAfter)) {
    failState();
  }
  return finalAfter;
}

async function readExactBaselineBound(root, deviceId, baselineId, expected = null) {
  const paths = baselinePaths(root, deviceId, baselineId, 'baseline');
  const result = await readRecordBinding(
    root,
    paths,
    'baseline',
    canonicalBaseline,
    expected,
  );
  const { record } = result;
  if (record.deviceId !== deviceId || record.baselineId !== baselineId) failState();
  return result;
}

async function readExactBaseline(root, deviceId, baselineId) {
  return (await readExactBaselineBound(root, deviceId, baselineId)).record;
}

async function inspectNamespace(root, directory, kind, expectedChain = null) {
  await assertManagedDirectoryChain(root, directory, expectedChain);
  const names = await readdir(directory);
  if (names.length > MAX_NAMESPACE_ENTRIES) failState();
  const records = new Map();
  const finalNamePattern = finalPattern(kind);
  const tempNamePattern = witnessPattern(kind);
  for (const name of names) {
    if (finalNamePattern.test(name)) {
      if (records.has(name) && records.get(name).final) failState();
      const value = records.get(name) ?? { final: false, witnesses: [] };
      value.final = true;
      records.set(name, value);
      continue;
    }
    const match = tempNamePattern.exec(name);
    if (match === null || !UUID_PATTERN.test(match[2])) failState();
    const value = records.get(match[1]) ?? { final: false, witnesses: [] };
    value.witnesses.push(name);
    records.set(match[1], value);
  }
  for (const [name, value] of records) {
    if (!value.final || value.witnesses.length !== 1) failState();
    await assertPublicationPair(join(directory, name), join(directory, value.witnesses[0]));
  }
  return Object.freeze(new Map(records));
}

async function readStableBytes(final, witness) {
  const expected = await assertPublicationPair(final, witness);
  const handle = await open(
    final,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(expected, opened)) failState();
    const size = Number(opened.size);
    const first = Buffer.alloc(size);
    const second = Buffer.alloc(size);
    const firstRead = await handle.read(first, 0, first.length, 0);
    const secondRead = await handle.read(second, 0, second.length, 0);
    if (
      firstRead.bytesRead !== first.length
      || secondRead.bytesRead !== second.length
      || !timingSafeEqual(first, second)
    ) failState();
    const after = await handle.stat({ bigint: true });
    const endpoint = await safeLstat(final);
    if (!sameIdentity(opened, after) || !sameIdentity(after, endpoint)) failState();
    return first;
  } finally {
    await handle.close();
  }
}

function parseCanonicalRecord(bytes, validator) {
  if (bytes.length < 1 || bytes.length > MAX_RECORD_BYTES) failState();
  let raw;
  try {
    raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    failState();
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    failState();
  }
  const record = validator(parsed, failState);
  if (`${JSON.stringify(record, null, 2)}\n` !== raw) failState();
  return record;
}

async function readRecordBinding(root, paths, kind, validator, expected = null) {
  const chain = await assertManagedDirectoryChain(
    root,
    paths.directory,
    expected?.chain ?? null,
  );
  const records = await inspectNamespace(root, paths.directory, kind, chain);
  const finalName = paths.final.slice(paths.directory.length + 1);
  const publication = records.get(finalName);
  if (!publication || !publication.final || publication.witnesses.length !== 1) failState();
  const witness = join(paths.directory, publication.witnesses[0]);
  const publicationStats = await assertPublicationPair(paths.final, witness);
  if (
    expected !== null
    && (expected.witness !== witness || !sameIdentity(expected.stats, publicationStats))
  ) failState();
  const first = await readStableBytes(paths.final, witness);
  await assertManagedDirectoryChain(root, paths.directory, chain);
  await syncDirectory(paths.directory);
  await assertManagedDirectoryChain(root, paths.directory, chain);
  const second = await readStableBytes(paths.final, witness);
  await assertManagedDirectoryChain(root, paths.directory, chain);
  if (first.length !== second.length || !timingSafeEqual(first, second)) failState();
  const completedStats = await assertPublicationPair(paths.final, witness);
  if (!sameIdentity(publicationStats, completedStats)) failState();
  const record = parseCanonicalRecord(first, validator);
  if (expected !== null && expected.recordDigest !== record.recordDigest) failState();
  return Object.freeze({
    record,
    binding: Object.freeze({
      chain,
      witness,
      stats: completedStats,
      recordDigest: record.recordDigest,
    }),
  });
}

async function readRecord(root, paths, kind, validator) {
  return (await readRecordBinding(root, paths, kind, validator)).record;
}

async function publishRecord(root, paths, kind, record) {
  await ensureManagedChain(root, paths.directory);
  const chain = await assertManagedDirectoryChain(root, paths.directory);
  const before = await inspectNamespace(root, paths.directory, kind, chain);
  const finalName = paths.final.slice(paths.directory.length + 1);
  if (before.has(finalName)) throw runtimeError('RUNTIME_ALREADY_RUNNING');
  const temporary = `${paths.final}.publish-${randomUUID()}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, 'utf8');
  if (bytes.length < 1 || bytes.length > MAX_RECORD_BYTES) failInput();
  let handle;
  let written;
  try {
    handle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      FILE_MODE,
    );
    await handle.writeFile(bytes);
    await handle.sync();
    written = await handle.stat({ bigint: true });
    if (
      !written.isFile()
      || written.uid !== currentUid()
      || (written.mode & 0o777n) !== BigInt(FILE_MODE)
      || written.nlink !== 1n
      || written.size !== BigInt(bytes.length)
    ) failState();
  } finally {
    if (handle) await handle.close();
  }
  const staged = await safeLstat(temporary);
  if (!sameIdentity(written, staged)) failState();
  await assertNoDarwinExtendedAcl(temporary);
  await assertManagedDirectoryChain(root, paths.directory, chain);
  try {
    await link(temporary, paths.final);
  } catch (error) {
    if (error?.code === 'EEXIST') throw runtimeError('RUNTIME_ALREADY_RUNNING');
    throw error;
  }
  const published = await assertPublicationPair(paths.final, temporary);
  if (!sameFileEndpoint(written, published)) failState();
  await assertManagedDirectoryChain(root, paths.directory, chain);
  await syncDirectory(paths.directory);
  await assertManagedDirectoryChain(root, paths.directory, chain);
  const after = await inspectNamespace(root, paths.directory, kind, chain);
  const publication = after.get(finalName);
  if (
    !publication
    || !publication.final
    || publication.witnesses.length !== 1
    || join(paths.directory, publication.witnesses[0]) !== temporary
  ) failState();
  return readRecord(
    root,
    paths,
    kind,
    kind === 'baseline' ? canonicalBaseline : canonicalComparison,
  );
}

function storeOptions(input) {
  if (input === undefined) {
    return { now: () => new Date(), randomBytes: cryptoRandomBytes };
  }
  const value = exactObject(input, ['now', 'randomBytes']);
  if (
    typeof value.now !== 'function'
    || isProxy(value.now)
    || typeof value.randomBytes !== 'function'
    || isProxy(value.randomBytes)
  ) failInput();
  return { now: value.now, randomBytes: value.randomBytes };
}

function randomIdentifier(prefix, randomBytes) {
  let value;
  try {
    value = randomBytes(32);
  } catch {
    throw runtimeError('RUNTIME_INTERNAL_ERROR');
  }
  if (!Buffer.isBuffer(value) || value.length !== 32) {
    throw runtimeError('RUNTIME_INTERNAL_ERROR');
  }
  return `${prefix}${value.toString('hex')}`;
}

function mapStoreFailure(error) {
  if (
    error !== null
    && (typeof error === 'object' || typeof error === 'function')
    && !isProxy(error)
  ) {
    let code;
    try {
      const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
      if (descriptor && Object.hasOwn(descriptor, 'value')) code = descriptor.value;
    } catch {
      code = undefined;
    }
    if (typeof code === 'string' && KNOWN_CODES.has(code)) {
      return runtimeError(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    }
    if (['ENOENT', 'ENOTDIR', 'ELOOP', 'EACCES', 'EPERM'].includes(code)) {
      return runtimeError('RUNTIME_STATE_UNSUPPORTED');
    }
  }
  return runtimeError('RUNTIME_INTERNAL_ERROR');
}

async function mapped(operation) {
  try {
    return await operation();
  } catch (error) {
    throw mapStoreFailure(error);
  }
}

function baselineCreateInput(input) {
  const value = exactObject(input, [
    'deviceId',
    'protocolRevision',
    'scriptSha256',
    'hmacKeyBase64',
    'surfaces',
    'captureAggregateMac',
  ]);
  canonicalDeviceId(value.deviceId);
  if (value.protocolRevision !== 1) failInput();
  canonicalSha256(value.scriptSha256);
  canonicalKey(value.hmacKeyBase64).fill(0);
  const surfaces = canonicalSurfaces(value.surfaces);
  canonicalSha256(value.captureAggregateMac);
  const expected = runtimeBaselineAggregateMac({
    hmacKeyBase64: value.hmacKeyBase64,
    surfaces,
  });
  if (!timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(value.captureAggregateMac, 'hex'))) {
    failInput();
  }
  return {
    deviceId: value.deviceId,
    protocolRevision: 1,
    scriptSha256: value.scriptSha256,
    hmacKeyBase64: value.hmacKeyBase64,
    surfaces,
    captureAggregateMac: value.captureAggregateMac,
  };
}

export class RuntimeBaselineStore {
  #root;
  #now;
  #randomBytes;

  constructor(root, options) {
    this.#root = validateRoot(root);
    const selected = storeOptions(options);
    this.#now = selected.now;
    this.#randomBytes = selected.randomBytes;
    Object.freeze(this);
  }

  async createBaseline(input) {
    let value;
    try {
      value = baselineCreateInput(input);
    } catch (error) {
      throw mapStoreFailure(error);
    }
    return mapped(async () => {
      const capturedAt = canonicalNow(this.#now);
      const baselineId = randomIdentifier('rbl_', this.#randomBytes);
      const base = {
        schemaVersion: 1,
        recordType: 'RUNTIME_BASELINE',
        baselineId,
        deviceId: value.deviceId,
        protocolRevision: 1,
        scriptSha256: value.scriptSha256,
        hmacKeyBase64: value.hmacKeyBase64,
        surfaces: value.surfaces,
        captureAggregateMac: value.captureAggregateMac,
        capturedAt,
        expiresAt: new Date(Date.parse(capturedAt) + BASELINE_TTL_MS).toISOString(),
      };
      const record = canonicalBaseline({
        ...base,
        recordDigest: digestRecord(BASELINE_RECORD_DOMAIN, baselineDigestInput(base)),
      });
      const paths = baselinePaths(this.#root, value.deviceId, baselineId, 'baseline');
      return withNamespaceLock(
        this.#root,
        paths.records,
        'baseline',
        true,
        () => publishRecord(this.#root, paths, 'baseline', record),
      );
    });
  }

  async readBaseline(input) {
    let value;
    try {
      value = exactObject(input, ['deviceId', 'baselineId']);
      canonicalDeviceId(value.deviceId);
      canonicalId(value.baselineId, BASELINE_ID_PATTERN);
    } catch (error) {
      throw mapStoreFailure(error);
    }
    return mapped(async () => {
      const paths = baselinePaths(this.#root, value.deviceId, value.baselineId, 'baseline');
      return withNamespaceLock(this.#root, paths.records, 'baseline', false, async () => {
        const record = await readExactBaseline(this.#root, value.deviceId, value.baselineId);
        const now = canonicalNow(this.#now);
        if (
          Date.parse(now) < Date.parse(record.capturedAt)
          || Date.parse(now) >= Date.parse(record.expiresAt)
        ) failState();
        return record;
      });
    });
  }

  async createComparison(input) {
    let value;
    try {
      value = exactObject(input, [
        'deviceId',
        'baselineId',
        'baselineRecordDigest',
        'protocolRevision',
        'scriptSha256',
        'observedSurfaces',
      ]);
      canonicalDeviceId(value.deviceId);
      canonicalId(value.baselineId, BASELINE_ID_PATTERN);
      canonicalSha256(value.baselineRecordDigest);
      if (value.protocolRevision !== 1) failInput();
      canonicalSha256(value.scriptSha256);
      value.observedSurfaces = canonicalSurfaces(value.observedSurfaces);
    } catch (error) {
      throw mapStoreFailure(error);
    }
    return mapped(async () => {
      const baselinePathsValue = baselinePaths(
        this.#root,
        value.deviceId,
        value.baselineId,
        'baseline',
      );
      return withNamespaceLock(
        this.#root,
        baselinePathsValue.records,
        'baseline',
        false,
        async () => {
          const comparedAt = canonicalNow(this.#now);
          const comparisonId = randomIdentifier('rbc_', this.#randomBytes);
          const baselineSnapshot = await readExactBaselineBound(
            this.#root,
            value.deviceId,
            value.baselineId,
          );
          const { record: baseline } = baselineSnapshot;
          if (
            value.protocolRevision !== baseline.protocolRevision
            || value.baselineRecordDigest !== baseline.recordDigest
            || value.scriptSha256 !== baseline.scriptSha256
            || comparedAt < baseline.capturedAt
            || comparedAt >= baseline.expiresAt
          ) failState();
          const changedSurfaces = runtimeBaselineChangedSurfaces({
            baselineSurfaces: baseline.surfaces,
            observedSurfaces: value.observedSurfaces,
          });
          const base = {
            schemaVersion: 1,
            recordType: 'RUNTIME_BASELINE_COMPARISON',
            comparisonId,
            deviceId: value.deviceId,
            baselineId: value.baselineId,
            baselineRecordDigest: baseline.recordDigest,
            protocolRevision: value.protocolRevision,
            scriptSha256: value.scriptSha256,
            observedSurfaces: value.observedSurfaces,
            observedAggregateMac: runtimeBaselineAggregateMac({
              hmacKeyBase64: baseline.hmacKeyBase64,
              surfaces: value.observedSurfaces,
            }),
            status: changedSurfaces.length === 0 ? 'UNCHANGED' : 'CHANGED',
            changedSurfaces,
            comparedAt,
          };
          const record = canonicalComparison({
            ...base,
            recordDigest: digestRecord(COMPARISON_RECORD_DOMAIN, comparisonDigestInput(base)),
          });
          const paths = baselinePaths(
            this.#root,
            value.deviceId,
            comparisonId,
            'comparison',
            value.baselineId,
          );
          return withNamespaceLock(
            this.#root,
            paths.records,
            'comparison',
            true,
            async () => {
              const verifiedBaseline = await readExactBaselineBound(
                this.#root,
                value.deviceId,
                value.baselineId,
                baselineSnapshot.binding,
              );
              if (
                verifiedBaseline.record.recordDigest !== baseline.recordDigest
                || verifiedBaseline.record.recordDigest !== value.baselineRecordDigest
              ) failState();
              const published = await publishRecord(this.#root, paths, 'comparison', record);
              const completedBaseline = await readExactBaselineBound(
                this.#root,
                value.deviceId,
                value.baselineId,
                baselineSnapshot.binding,
              );
              if (completedBaseline.record.recordDigest !== baseline.recordDigest) failState();
              return published;
            },
          );
        },
      );
    });
  }

  async readComparison(input) {
    let value;
    try {
      value = exactObject(input, ['deviceId', 'baselineId', 'comparisonId']);
      canonicalDeviceId(value.deviceId);
      canonicalId(value.baselineId, BASELINE_ID_PATTERN);
      canonicalId(value.comparisonId, COMPARISON_ID_PATTERN);
    } catch (error) {
      throw mapStoreFailure(error);
    }
    return mapped(async () => {
      const paths = baselinePaths(
        this.#root,
        value.deviceId,
        value.comparisonId,
        'comparison',
        value.baselineId,
      );
      const record = await withNamespaceLock(
        this.#root,
        paths.records,
        'comparison',
        false,
        () => readRecord(
          this.#root,
          paths,
          'comparison',
          canonicalComparison,
        ),
      );
      if (
        record.deviceId !== value.deviceId
        || record.baselineId !== value.baselineId
        || record.comparisonId !== value.comparisonId
      ) {
        failState();
      }
      const baselinePathsValue = baselinePaths(
        this.#root,
        record.deviceId,
        record.baselineId,
        'baseline',
      );
      const baseline = await withNamespaceLock(
        this.#root,
        baselinePathsValue.records,
        'baseline',
        false,
        () => readExactBaseline(this.#root, record.deviceId, record.baselineId),
      );
      if (
        record.baselineRecordDigest !== baseline.recordDigest
        || record.protocolRevision !== baseline.protocolRevision
        || record.scriptSha256 !== baseline.scriptSha256
        || record.comparedAt < baseline.capturedAt
        || record.comparedAt >= baseline.expiresAt
      ) failState();
      const expectedAggregate = runtimeBaselineAggregateMac({
        hmacKeyBase64: baseline.hmacKeyBase64,
        surfaces: record.observedSurfaces,
      });
      if (!timingSafeEqual(
        Buffer.from(record.observedAggregateMac, 'hex'),
        Buffer.from(expectedAggregate, 'hex'),
      )) failState();
      const expectedChanges = runtimeBaselineChangedSurfaces({
        baselineSurfaces: baseline.surfaces,
        observedSurfaces: record.observedSurfaces,
      });
      if (JSON.stringify(expectedChanges) !== JSON.stringify(record.changedSurfaces)) failState();
      return record;
    });
  }
}
