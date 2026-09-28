import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { isProxy } from 'node:util/types';

import { validateRuntimeInventory } from './runtime-inventory.mjs';

const INVENTORY_TIMEOUT_MS = 120_000;
const MAX_INVENTORY_BYTES = 32 * 1024;
const SCRIPT_PATH = fileURLToPath(
  new URL('../../windows/runtime-inventory.ps1', import.meta.url),
);
export const RUNTIME_INVENTORY_SCRIPT_PATH = SCRIPT_PATH;

const INPUT_FIELDS = Object.freeze(['target', 'dependencies']);
const DEPENDENCY_FIELDS = Object.freeze([
  'executeRemoteScript',
  'runProcess',
  'operationId',
  'clock',
]);
const RESULT_FIELDS = Object.freeze([
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
const EXPECTED_RESULT_FIELDS = Object.freeze(['deviceId', 'address']);
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const ISO_TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const REMOTE_CODES = new Set([
  'REMOTE_INPUT_INVALID',
  'REMOTE_CONNECTION_FAILED',
  'FILE_TRANSFER_FAILED',
  'FILE_INTEGRITY_FAILED',
  'REMOTE_EXECUTION_UNCERTAIN',
  'REMOTE_CLEANUP_UNCERTAIN',
  'LOCAL_CLEANUP_FAILED',
]);

function runtimeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function failInput() {
  throw runtimeError('RUNTIME_INPUT_INVALID');
}

function readExactRecord(input, fields, failure) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) {
    throw runtimeError(failure);
  }

  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    throw runtimeError(failure);
  }

  const values = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) {
      throw runtimeError(failure);
    }
    values[field] = descriptor.value;
  }
  return values;
}

function validateInput(input) {
  const values = readExactRecord(input, INPUT_FIELDS, 'RUNTIME_INPUT_INVALID');
  const dependencies = readExactRecord(
    values.dependencies,
    DEPENDENCY_FIELDS,
    'RUNTIME_INPUT_INVALID',
  );
  for (const field of DEPENDENCY_FIELDS) {
    if (typeof dependencies[field] !== 'function' || isProxy(dependencies[field])) failInput();
  }
  return { target: values.target, dependencies };
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string' || !ISO_TIMESTAMP_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function validateExpectedResult(input) {
  const expected = readExactRecord(
    input,
    EXPECTED_RESULT_FIELDS,
    'RUNTIME_INVENTORY_FAILED',
  );
  if (
    typeof expected.deviceId !== 'string'
    || expected.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(expected.deviceId)
    || typeof expected.address !== 'string'
    || isIP(expected.address) === 0
  ) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  return expected;
}

function validateExecutionResult(input, expectedInput) {
  const result = readExactRecord(input, RESULT_FIELDS, 'RUNTIME_INVENTORY_FAILED');
  const expected = expectedInput === undefined ? null : validateExpectedResult(expectedInput);
  if (
    result.schemaVersion !== 1
    || result.operation !== 'exec'
    || typeof result.deviceId !== 'string'
    || result.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(result.deviceId)
    || typeof result.address !== 'string'
    || isIP(result.address) === 0
    || !Number.isInteger(result.exitCode)
    || result.exitCode < 0
    || result.exitCode > 255
    || typeof result.stdout !== 'string'
    || typeof result.stderr !== 'string'
    || !canonicalTimestamp(result.startedAt)
    || !canonicalTimestamp(result.finishedAt)
    || result.finishedAt < result.startedAt
    || (expected !== null && (
      result.deviceId !== expected.deviceId || result.address !== expected.address
    ))
  ) {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
  return result;
}

export function parseRuntimeInventoryExecution(input, expected) {
  const result = validateExecutionResult(input, expected);
  if (result.exitCode === 41 && result.stdout === '' && result.stderr === '') {
    throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
  if (result.exitCode !== 0 || result.stderr !== '') {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
  return parseInventory(result.stdout);
}

function parseInventory(raw) {
  if (
    Buffer.byteLength(raw, 'utf8') === 0
    || Buffer.byteLength(raw, 'utf8') > MAX_INVENTORY_BYTES
  ) {
    throw runtimeError('RUNTIME_INVENTORY_INVALID');
  }

  let parsed;
  let snapshot;
  try {
    parsed = JSON.parse(raw);
    snapshot = validateRuntimeInventory(parsed);
  } catch {
    throw runtimeError('RUNTIME_INVENTORY_INVALID');
  }
  if (JSON.stringify(snapshot) !== raw) throw runtimeError('RUNTIME_INVENTORY_INVALID');
  return snapshot;
}

function mapExecutionFailure(error) {
  if (
    error !== null
    && (typeof error === 'object' || typeof error === 'function')
    && !isProxy(error)
  ) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    } catch {
      descriptor = undefined;
    }
    if (
      descriptor !== undefined
      && Object.hasOwn(descriptor, 'value')
      && typeof descriptor.value === 'string'
      && REMOTE_CODES.has(descriptor.value)
    ) {
      return runtimeError(descriptor.value);
    }
  }
  return runtimeError('RUNTIME_INVENTORY_FAILED');
}

export async function readRuntimeInventory(input) {
  const config = validateInput(input);
  let rawResult;
  try {
    rawResult = await config.dependencies.executeRemoteScript({
      target: config.target,
      scriptPath: SCRIPT_PATH,
      timeoutMs: INVENTORY_TIMEOUT_MS,
      dependencies: {
        runProcess: config.dependencies.runProcess,
        operationId: config.dependencies.operationId,
        clock: config.dependencies.clock,
      },
    });
  } catch (error) {
    throw mapExecutionFailure(error);
  }

  return parseRuntimeInventoryExecution(rawResult);
}
