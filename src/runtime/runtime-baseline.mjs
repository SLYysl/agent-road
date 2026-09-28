import {
  createHash,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { isProxy } from 'node:util/types';

import {
  RUNTIME_BASELINE_SURFACE_IDS,
  RUNTIME_BASELINE_SURFACE_LIMITS,
  runtimeBaselineAggregateMac,
  runtimeBaselineChangedSurfaces,
} from './runtime-baseline-store.mjs';

const SCRIPT_PATH = fileURLToPath(
  new URL('../../windows/runtime-baseline.ps1', import.meta.url),
);
export const RUNTIME_BASELINE_SCRIPT_PATH = SCRIPT_PATH;

const EXECUTION_TIMEOUT_MS = 120_000;
const MAX_OUTPUT_BYTES = 8_192;
const MAX_INPUT_BYTES = 256;
const MAX_SCRIPT_BYTES = 256 * 1024;
const BASELINE_TTL_MS = 24 * 60 * 60 * 1_000;
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const BASELINE_ID_PATTERN = /^rbl_[a-f0-9]{64}$/u;
const COMPARISON_ID_PATTERN = /^rbc_[a-f0-9]{64}$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const EXECUTION_FIELDS = Object.freeze([
  'schemaVersion',
  'operation',
  'deviceId',
  'address',
  'exitCode',
  'stdout',
  'stderr',
  'startedAt',
  'finishedAt',
]);
const EXPECTED_FIELDS = Object.freeze(['deviceId', 'address']);
const OBSERVATION_FIELDS = Object.freeze(['schemaVersion', 'protocolRevision', 'surfaces']);
const SURFACE_FIELDS = Object.freeze(['id', 'count', 'mac']);
const CAPTURE_FIELDS = Object.freeze(['deviceId', 'dependencies']);
const CAPTURE_DEPENDENCY_FIELDS = Object.freeze([
  'executeBaselineScript',
  'createBaseline',
  'randomBytes',
]);
const COMPARE_FIELDS = Object.freeze(['deviceId', 'baselineId', 'dependencies']);
const COMPARE_DEPENDENCY_FIELDS = Object.freeze([
  'executeBaselineScript',
  'readBaseline',
  'createComparison',
]);
const BASELINE_RECORD_FIELDS = Object.freeze([
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
const COMPARISON_RECORD_FIELDS = Object.freeze([
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
const CHANGE_FIELDS = Object.freeze(['id', 'countChanged', 'macChanged']);
const STORE_CODES = new Set([
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_INTERNAL_ERROR',
  'RUNTIME_STATE_UNSUPPORTED',
]);

function runtimeError(code, ErrorType = Error) {
  const error = new ErrorType(code);
  error.code = code;
  return error;
}

function fail(code, ErrorType = Error) {
  throw runtimeError(code, ErrorType);
}

function exactObject(input, fields, code) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  const output = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    }
    output[field] = descriptor.value;
  }
  return output;
}

function exactArray(input, length, code) {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code);
  const descriptor = Object.getOwnPropertyDescriptor(input, 'length');
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.value !== length) {
    fail(code);
  }
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== length + 1
    || !names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/u.test(name))
  ) fail(code);
  const output = [];
  for (let index = 0; index < length; index += 1) {
    const item = Object.getOwnPropertyDescriptor(input, String(index));
    if (!item || !Object.hasOwn(item, 'value') || item.enumerable !== true) fail(code);
    output.push(item.value);
  }
  return output;
}

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const child of value) deepFreeze(child);
  } else if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return Object.freeze(value);
}

function canonicalTimestamp(value, code) {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value)) fail(code);
  try {
    if (new Date(value).toISOString() !== value) fail(code);
  } catch {
    fail(code);
  }
  return value;
}

function canonicalDeviceId(value, code) {
  if (typeof value !== 'string' || value.length > 64 || !DEVICE_ID_PATTERN.test(value)) {
    fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  return value;
}

function canonicalDigest(value, code) {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) fail(code);
  return value;
}

function canonicalKey(value, code) {
  if (typeof value !== 'string' || value.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/u.test(value)) {
    fail(code);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 32 || bytes.toString('base64') !== value) fail(code);
  return bytes;
}

function canonicalSurfaces(input, code) {
  const values = exactArray(input, RUNTIME_BASELINE_SURFACE_IDS.length, code);
  return deepFreeze(values.map((inputSurface, index) => {
    const surface = exactObject(inputSurface, SURFACE_FIELDS, code);
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
    ) fail(code);
    return { id, count: surface.count, mac: surface.mac };
  }));
}

function canonicalChanges(input, code) {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || input.length > RUNTIME_BASELINE_SURFACE_IDS.length
  ) fail(code);
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== input.length + 1) fail(code);
  let prior = -1;
  const output = [];
  for (let index = 0; index < input.length; index += 1) {
    const item = Object.getOwnPropertyDescriptor(input, String(index));
    if (!item || !Object.hasOwn(item, 'value') || item.enumerable !== true) fail(code);
    const change = exactObject(item.value, CHANGE_FIELDS, code);
    const position = RUNTIME_BASELINE_SURFACE_IDS.indexOf(change.id);
    if (
      position <= prior
      || typeof change.countChanged !== 'boolean'
      || typeof change.macChanged !== 'boolean'
      || (!change.countChanged && !change.macChanged)
    ) fail(code);
    prior = position;
    output.push({
      id: change.id,
      countChanged: change.countChanged,
      macChanged: change.macChanged,
    });
  }
  return deepFreeze(output);
}

function validateExecution(input, expectedInput, expectedDeviceId) {
  const result = exactObject(input, EXECUTION_FIELDS, 'RUNTIME_INVENTORY_FAILED');
  let expected = null;
  if (expectedInput !== undefined) {
    expected = exactObject(expectedInput, EXPECTED_FIELDS, 'RUNTIME_INVENTORY_FAILED');
    canonicalDeviceId(expected.deviceId, 'RUNTIME_INVENTORY_FAILED');
    if (typeof expected.address !== 'string' || isIP(expected.address) === 0) {
      fail('RUNTIME_INVENTORY_FAILED');
    }
  }
  if (
    result.schemaVersion !== 1
    || result.operation !== 'exec'
    || typeof result.deviceId !== 'string'
    || !DEVICE_ID_PATTERN.test(result.deviceId)
    || result.deviceId.length > 64
    || typeof result.address !== 'string'
    || isIP(result.address) === 0
    || !Number.isInteger(result.exitCode)
    || result.exitCode < 0
    || result.exitCode > 255
    || typeof result.stdout !== 'string'
    || typeof result.stderr !== 'string'
    || !TIMESTAMP_PATTERN.test(result.startedAt)
    || !TIMESTAMP_PATTERN.test(result.finishedAt)
  ) fail('RUNTIME_INVENTORY_FAILED');
  canonicalTimestamp(result.startedAt, 'RUNTIME_INVENTORY_FAILED');
  canonicalTimestamp(result.finishedAt, 'RUNTIME_INVENTORY_FAILED');
  if (
    result.finishedAt < result.startedAt
    || (expected !== null && (
      result.deviceId !== expected.deviceId || result.address !== expected.address
    ))
    || (expectedDeviceId !== undefined && result.deviceId !== expectedDeviceId)
  ) fail('RUNTIME_INVENTORY_FAILED');
  return result;
}

function parseExecution(input, expectedInput, expectedDeviceId) {
  const result = validateExecution(input, expectedInput, expectedDeviceId);
  if (
    result.exitCode !== 0
    || result.stderr !== ''
    || Buffer.byteLength(result.stdout, 'utf8') < 1
    || Buffer.byteLength(result.stdout, 'utf8') > MAX_OUTPUT_BYTES
  ) fail('RUNTIME_INVENTORY_FAILED');
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    fail('RUNTIME_INVENTORY_FAILED');
  }
  const value = exactObject(parsed, OBSERVATION_FIELDS, 'RUNTIME_INVENTORY_FAILED');
  if (value.schemaVersion !== 1 || value.protocolRevision !== 1) {
    fail('RUNTIME_INVENTORY_FAILED');
  }
  const observation = deepFreeze({
    schemaVersion: 1,
    protocolRevision: 1,
    surfaces: canonicalSurfaces(value.surfaces, 'RUNTIME_INVENTORY_FAILED'),
  });
  if (JSON.stringify(observation) !== result.stdout) fail('RUNTIME_INVENTORY_FAILED');
  return observation;
}

export function parseRuntimeBaselineExecution(input, expected) {
  return parseExecution(input, expected, undefined);
}

function validateDependencies(input, fields) {
  const dependencies = exactObject(input, fields, 'RUNTIME_INPUT_INVALID');
  for (const field of fields) {
    if (typeof dependencies[field] !== 'function' || isProxy(dependencies[field])) {
      fail('RUNTIME_INPUT_INVALID', TypeError);
    }
  }
  return dependencies;
}

function validateCaptureInput(input) {
  const value = exactObject(input, CAPTURE_FIELDS, 'RUNTIME_INPUT_INVALID');
  canonicalDeviceId(value.deviceId, 'RUNTIME_INPUT_INVALID');
  return {
    deviceId: value.deviceId,
    dependencies: validateDependencies(value.dependencies, CAPTURE_DEPENDENCY_FIELDS),
  };
}

function validateCompareInput(input) {
  const value = exactObject(input, COMPARE_FIELDS, 'RUNTIME_INPUT_INVALID');
  canonicalDeviceId(value.deviceId, 'RUNTIME_INPUT_INVALID');
  if (typeof value.baselineId !== 'string' || !BASELINE_ID_PATTERN.test(value.baselineId)) {
    fail('RUNTIME_INPUT_INVALID', TypeError);
  }
  return {
    deviceId: value.deviceId,
    baselineId: value.baselineId,
    dependencies: validateDependencies(value.dependencies, COMPARE_DEPENDENCY_FIELDS),
  };
}

function safeCode(error) {
  if (
    error === null
    || (typeof error !== 'object' && typeof error !== 'function')
    || isProxy(error)
  ) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    return descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string'
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function mapStoreFailure(error) {
  const code = safeCode(error);
  return runtimeError(STORE_CODES.has(code) ? code : 'RUNTIME_INTERNAL_ERROR');
}

async function checkedScriptSha256() {
  let bytes;
  try {
    bytes = await readFile(SCRIPT_PATH);
  } catch {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_SCRIPT_BYTES) {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  return createHash('sha256').update(bytes).digest('hex').toUpperCase();
}

function executionInput(deviceId, scriptSha256, hmacKeyBase64) {
  const stdinText = JSON.stringify({
    schemaVersion: 1,
    protocolRevision: 1,
    hmacKeyBase64,
  });
  if (Buffer.byteLength(stdinText, 'utf8') > MAX_INPUT_BYTES) fail('RUNTIME_INTERNAL_ERROR');
  return Object.freeze({
    deviceId,
    scriptPath: SCRIPT_PATH,
    scriptSha256,
    timeoutMs: EXECUTION_TIMEOUT_MS,
    maxOutputBytes: MAX_OUTPUT_BYTES,
    stdinText,
  });
}

function recordDigest(domain, value) {
  return createHash('sha256')
    .update(domain, 'ascii')
    .update(JSON.stringify(value), 'utf8')
    .digest('hex')
    .toUpperCase();
}

function validateBaselineRecord(input, expected = {}) {
  const value = exactObject(input, BASELINE_RECORD_FIELDS, 'RUNTIME_STATE_UNSUPPORTED');
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RUNTIME_BASELINE'
    || typeof value.baselineId !== 'string'
    || !BASELINE_ID_PATTERN.test(value.baselineId)
    || value.protocolRevision !== 1
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  canonicalDeviceId(value.deviceId, 'RUNTIME_STATE_UNSUPPORTED');
  canonicalDigest(value.scriptSha256, 'RUNTIME_STATE_UNSUPPORTED');
  const key = canonicalKey(value.hmacKeyBase64, 'RUNTIME_STATE_UNSUPPORTED');
  const surfaces = canonicalSurfaces(value.surfaces, 'RUNTIME_STATE_UNSUPPORTED');
  canonicalDigest(value.captureAggregateMac, 'RUNTIME_STATE_UNSUPPORTED');
  canonicalTimestamp(value.capturedAt, 'RUNTIME_STATE_UNSUPPORTED');
  canonicalTimestamp(value.expiresAt, 'RUNTIME_STATE_UNSUPPORTED');
  canonicalDigest(value.recordDigest, 'RUNTIME_STATE_UNSUPPORTED');
  try {
    if (
      value.expiresAt !== new Date(Date.parse(value.capturedAt) + BASELINE_TTL_MS).toISOString()
      || runtimeBaselineAggregateMac({
        hmacKeyBase64: value.hmacKeyBase64,
        surfaces,
      }) !== value.captureAggregateMac
      || (expected.deviceId !== undefined && value.deviceId !== expected.deviceId)
      || (expected.scriptSha256 !== undefined && value.scriptSha256 !== expected.scriptSha256)
      || (expected.hmacKeyBase64 !== undefined && value.hmacKeyBase64 !== expected.hmacKeyBase64)
      || (expected.surfaces !== undefined
        && JSON.stringify(surfaces) !== JSON.stringify(expected.surfaces))
      || (expected.captureAggregateMac !== undefined
        && value.captureAggregateMac !== expected.captureAggregateMac)
    ) fail('RUNTIME_STATE_UNSUPPORTED');
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
    if (
      recordDigest('AgentRoad.RuntimeBaseline.Record.v1\0', canonical)
      !== value.recordDigest
    ) fail('RUNTIME_STATE_UNSUPPORTED');
    return deepFreeze({ ...canonical, recordDigest: value.recordDigest });
  } finally {
    key.fill(0);
  }
}

function validateComparisonRecord(input, baseline, observation) {
  const value = exactObject(input, COMPARISON_RECORD_FIELDS, 'RUNTIME_STATE_UNSUPPORTED');
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RUNTIME_BASELINE_COMPARISON'
    || typeof value.comparisonId !== 'string'
    || !COMPARISON_ID_PATTERN.test(value.comparisonId)
    || value.deviceId !== baseline.deviceId
    || value.baselineId !== baseline.baselineId
    || value.baselineRecordDigest !== baseline.recordDigest
    || value.protocolRevision !== observation.protocolRevision
    || value.scriptSha256 !== baseline.scriptSha256
    || !['UNCHANGED', 'CHANGED'].includes(value.status)
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  const surfaces = canonicalSurfaces(value.observedSurfaces, 'RUNTIME_STATE_UNSUPPORTED');
  if (JSON.stringify(surfaces) !== JSON.stringify(observation.surfaces)) {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  canonicalDigest(value.observedAggregateMac, 'RUNTIME_STATE_UNSUPPORTED');
  const expectedAggregate = runtimeBaselineAggregateMac({
    hmacKeyBase64: baseline.hmacKeyBase64,
    surfaces,
  });
  if (value.observedAggregateMac !== expectedAggregate) fail('RUNTIME_STATE_UNSUPPORTED');
  const changes = canonicalChanges(value.changedSurfaces, 'RUNTIME_STATE_UNSUPPORTED');
  const expectedChanges = runtimeBaselineChangedSurfaces({
    baselineSurfaces: baseline.surfaces,
    observedSurfaces: surfaces,
  });
  if (
    JSON.stringify(changes) !== JSON.stringify(expectedChanges)
    || (value.status === 'UNCHANGED') !== (changes.length === 0)
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  canonicalTimestamp(value.comparedAt, 'RUNTIME_STATE_UNSUPPORTED');
  canonicalDigest(value.recordDigest, 'RUNTIME_STATE_UNSUPPORTED');
  if (value.comparedAt < baseline.capturedAt || value.comparedAt >= baseline.expiresAt) {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  const canonical = {
    schemaVersion: 1,
    recordType: 'RUNTIME_BASELINE_COMPARISON',
    comparisonId: value.comparisonId,
    deviceId: value.deviceId,
    baselineId: value.baselineId,
    baselineRecordDigest: value.baselineRecordDigest,
    protocolRevision: value.protocolRevision,
    scriptSha256: value.scriptSha256,
    observedSurfaces: surfaces,
    observedAggregateMac: value.observedAggregateMac,
    status: value.status,
    changedSurfaces: changes,
    comparedAt: value.comparedAt,
  };
  if (
    recordDigest('AgentRoad.RuntimeBaseline.Comparison.v1\0', canonical)
    !== value.recordDigest
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  return deepFreeze({ ...canonical, recordDigest: value.recordDigest });
}

function generateKey(randomBytes) {
  let source;
  try {
    source = randomBytes(32);
  } catch {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  if (!Buffer.isBuffer(source) || isProxy(source)) {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  let key;
  let overflow;
  let copied = -1;
  let extra = -1;
  try {
    key = Buffer.allocUnsafe(32);
    overflow = Buffer.allocUnsafe(1);
    copied = Buffer.prototype.copy.call(source, key, 0, 0, 32);
    extra = Buffer.prototype.copy.call(source, overflow, 0, 32, 33);
  } catch {
    try { if (key) Buffer.prototype.fill.call(key, 0); } catch {}
    fail('RUNTIME_INTERNAL_ERROR');
  } finally {
    try { Buffer.prototype.fill.call(source, 0); } catch {}
    try { if (overflow) Buffer.prototype.fill.call(overflow, 0); } catch {}
  }
  if (copied !== 32 || extra !== 0) {
    Buffer.prototype.fill.call(key, 0);
    fail('RUNTIME_INTERNAL_ERROR');
  }
  return key;
}

export async function captureRuntimeBaseline(input) {
  const config = validateCaptureInput(input);
  const scriptSha256 = await checkedScriptSha256();
  const key = generateKey(config.dependencies.randomBytes);
  try {
    let hmacKeyBase64;
    try {
      hmacKeyBase64 = Buffer.prototype.toString.call(key, 'base64');
    } catch {
      fail('RUNTIME_INTERNAL_ERROR');
    }
    let execution;
    try {
      execution = await config.dependencies.executeBaselineScript(
        executionInput(config.deviceId, scriptSha256, hmacKeyBase64),
      );
    } catch (error) {
      if (safeCode(error) === 'RUNTIME_ALREADY_RUNNING') {
        throw runtimeError('RUNTIME_ALREADY_RUNNING');
      }
      fail('RUNTIME_INVENTORY_FAILED');
    }
    const observed = parseExecution(execution, undefined, config.deviceId);
    const captureAggregateMac = runtimeBaselineAggregateMac({
      hmacKeyBase64,
      surfaces: observed.surfaces,
    });
    let persisted;
    try {
      persisted = await config.dependencies.createBaseline({
        deviceId: config.deviceId,
        protocolRevision: observed.protocolRevision,
        scriptSha256,
        hmacKeyBase64,
        surfaces: observed.surfaces,
        captureAggregateMac,
      });
    } catch (error) {
      throw mapStoreFailure(error);
    }
    const record = validateBaselineRecord(persisted, {
      deviceId: config.deviceId,
      scriptSha256,
      hmacKeyBase64,
      surfaces: observed.surfaces,
      captureAggregateMac,
    });
    return Object.freeze({
      baselineId: record.baselineId,
      capturedAt: record.capturedAt,
      expiresAt: record.expiresAt,
    });
  } finally {
    Buffer.prototype.fill.call(key, 0);
  }
}

export async function compareRuntimeBaseline(input) {
  const config = validateCompareInput(input);
  let persistedBaseline;
  try {
    persistedBaseline = await config.dependencies.readBaseline({
      deviceId: config.deviceId,
      baselineId: config.baselineId,
    });
  } catch (error) {
    throw mapStoreFailure(error);
  }
  const baseline = validateBaselineRecord(persistedBaseline, {
    deviceId: config.deviceId,
  });
  if (baseline.baselineId !== config.baselineId) fail('RUNTIME_STATE_UNSUPPORTED');
  const scriptSha256 = await checkedScriptSha256();
  if (baseline.scriptSha256 !== scriptSha256) fail('RUNTIME_STATE_UNSUPPORTED');

  let execution;
  try {
    execution = await config.dependencies.executeBaselineScript(
      executionInput(config.deviceId, scriptSha256, baseline.hmacKeyBase64),
    );
  } catch (error) {
    if (safeCode(error) === 'RUNTIME_ALREADY_RUNNING') {
      throw runtimeError('RUNTIME_ALREADY_RUNNING');
    }
    fail('RUNTIME_INVENTORY_FAILED');
  }
  const observed = parseExecution(execution, undefined, config.deviceId);
  let persistedComparison;
  try {
    persistedComparison = await config.dependencies.createComparison({
      deviceId: config.deviceId,
      baselineId: config.baselineId,
      baselineRecordDigest: baseline.recordDigest,
      protocolRevision: observed.protocolRevision,
      scriptSha256,
      observedSurfaces: observed.surfaces,
    });
  } catch (error) {
    throw mapStoreFailure(error);
  }
  const comparison = validateComparisonRecord(persistedComparison, baseline, observed);
  return deepFreeze({
    baselineId: comparison.baselineId,
    comparisonId: comparison.comparisonId,
    status: comparison.status,
    changedSurfaces: comparison.changedSurfaces.map((change) => ({ ...change })),
  });
}
