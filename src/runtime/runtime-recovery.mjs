import { isPromise, isProxy } from 'node:util/types';
import { markRecoveryInspectStage as markInspectStage } from './recovery-inspect-stage.mjs';

import {
  createRuntimeRecoveryAuthorizationParent,
  createRuntimeRecoveryProof,
  runtimeRecoveryAuthorizationParentDigest,
  runtimeRecoveryAuthorizedAttemptDigest,
  runtimeRecoveryProofDigest,
  runtimeRecoveryStateDigest,
  runtimeRecoveryTicketDigest,
  validateRuntimeRecoveryBootMarker,
} from './runtime-recovery-store.mjs';
import { runtimeRecoveryTargetBindingDigest } from './runtime-recovery-remote.mjs';
import { validateRuntimeStateRecord } from './runtime-state-store.mjs';

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const DIGEST_PATTERN = /^[A-F0-9]{64}$/u;
const TICKET_ID_PATTERN = /^rct_[a-f0-9]{64}$/u;
const TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const MAX_DISPLAY_NAME_BYTES = 512;
const TARGET_ACL_DIGEST = 'DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44';
const INSPECT_FIELDS = Object.freeze(['deviceId', 'priorTicketId', 'dependencyFactory']);
const APPLY_FIELDS = Object.freeze(['deviceId', 'ticketId', 'dependencyFactory']);
const DEPENDENCY_FIELDS = Object.freeze([
  'loadTarget',
  'readState',
  'transitionState',
  'withRecoveryOperation',
  'inspectRemote',
  'applyRemote',
  'clock',
]);
const SCOPE_FIELDS = Object.freeze([
  'readBootObservation',
  'createBootObservation',
  'createTicket',
  'resolveAuthorizationSuccessor',
  'readTicket',
  'readAuthorizedDeleteAttempt',
  'consumeTicket',
  'readRecoveryCommit',
  'createRecoveryCommit',
]);
const OBSERVATION_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'deviceId',
  'operationId',
  'failedState',
  'failedStateDigest',
  'bootMarker',
  'observedAt',
]);
const TICKET_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'ticketId',
  'deviceId',
  'operationId',
  'authorizationParent',
  'authorizationParentDigest',
  'failedState',
  'failedStateDigest',
  'proof',
  'proofDigest',
  'inspectedAt',
  'expiresAt',
]);
const ATTEMPT_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'ticketId',
  'deviceId',
  'operationId',
  'ticketDigest',
  'failedStateDigest',
  'proofDigest',
  'classification',
  'authorizedAt',
]);
const COMMIT_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'deviceId',
  'operationId',
  'ticketId',
  'authorizedAttemptDigest',
  'expectedFailedStateDigest',
  'proposedRecoveredState',
  'proposedRecoveredStateDigest',
  'proofDigest',
  'disposition',
  'authorizedAt',
  'committedAt',
]);
const REMOTE_INSPECT_FIELDS = Object.freeze([
  'schemaVersion',
  'protocolRevision',
  'deviceId',
  'targetBindingDigest',
  'operationId',
  'bootMarker',
  'classification',
  'priorAuthorizedAttempt',
  'agentRoadAcl',
  'runtimeDirectory',
  'stagingDirectory',
  'operationDirectory',
]);
const ACL_FIELDS = Object.freeze([
  'ownerSid',
  'protected',
  'canonical',
  'accessRuleCount',
  'administratorsFullControl',
  'systemFullControl',
  'aclDigest',
]);
const DIRECTORY_FIELDS = Object.freeze([
  'volumeSerialNumber',
  'fileId',
  'acl',
  'directChildCount',
  'directChildren',
]);
const PRIOR_ATTEMPT_FIELDS = Object.freeze(['ticketId', 'attemptDigest']);
const REMOTE_APPLY_FIELDS = Object.freeze(['schemaVersion', 'disposition']);
const INSPECT_OPERATION_CODES = new Set([
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_INVENTORY_FAILED',
  'RUNTIME_OPERATION_CONFLICT',
  'RUNTIME_REBOOT_REQUIRED',
  'RUNTIME_STATE_UNSUPPORTED',
]);
const APPLY_OPERATION_CODES = new Set([
  ...INSPECT_OPERATION_CODES,
  'RUNTIME_COMPLETION_UNCERTAIN',
  'RUNTIME_INTERNAL_ERROR',
]);
const INSPECT_REMOTE_CODES = new Set([
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
  'RUNTIME_INVENTORY_FAILED',
  'RUNTIME_OPERATION_CONFLICT',
  'RUNTIME_REBOOT_REQUIRED',
  'RUNTIME_STATE_UNSUPPORTED',
]);
const APPLY_REMOTE_CODES = new Set([
  ...INSPECT_REMOTE_CODES,
  'RUNTIME_COMPLETION_UNCERTAIN',
]);
const STORE_CODES = new Set([
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_INTERNAL_ERROR',
  'RUNTIME_STATE_UNSUPPORTED',
]);
const INTRINSIC_APPLY = Reflect.apply;
const NATIVE_PROMISE = Promise;
const INTRINSIC_PROMISE_THEN = Object.getOwnPropertyDescriptor(Promise.prototype, 'then').value;
const INTRINSIC_PROMISE_RESOLVE = Object.getOwnPropertyDescriptor(Promise, 'resolve').value;

function runtimeError(code, ErrorType = Error) {
  const error = new ErrorType(code);
  error.code = code;
  return error;
}

function fail(code, ErrorType = Error) {
  throw runtimeError(code, ErrorType);
}

function safeCode(error) {
  if (
    error === null
    || (typeof error !== 'object' && typeof error !== 'function')
    || isProxy(error)
  ) return undefined;
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(error, 'code');
  } catch {
    return undefined;
  }
  return descriptor
    && Object.hasOwn(descriptor, 'value')
    && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
}

function exactRecord(input, fields, code = 'RUNTIME_INPUT_INVALID', options = {}) {
  const { frozen = false, nullPrototype = false } = options;
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || (nullPrototype
      ? Object.getPrototypeOf(input) !== null
      : Object.getPrototypeOf(input) !== Object.prototype)
    || Object.getOwnPropertySymbols(input).length !== 0
    || (frozen && !Object.isFrozen(input))
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  const output = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    output[field] = descriptor.value;
  }
  return output;
}

function exactArray(input, maximum, code) {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || !Object.isFrozen(input)
  ) fail(code);
  const length = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    !length
    || !Object.hasOwn(length, 'value')
    || !Number.isSafeInteger(length.value)
    || length.value < 0
    || length.value > maximum
    || Object.getOwnPropertyNames(input).length !== length.value + 1
  ) fail(code);
  const output = [];
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) fail(code);
    output.push(descriptor.value);
  }
  return Object.freeze(output);
}

function assertDeepFrozenPlainData(input, code, ancestors = new WeakSet()) {
  if (input === null || typeof input === 'string' || typeof input === 'boolean') return;
  if (typeof input === 'number') {
    if (!Number.isFinite(input) || Object.is(input, -0)) fail(code);
    return;
  }
  if (
    typeof input !== 'object'
    || isProxy(input)
    || !Object.isFrozen(input)
    || ancestors.has(input)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code);
  const array = Array.isArray(input);
  if (
    (array && Object.getPrototypeOf(input) !== Array.prototype)
    || (!array && Object.getPrototypeOf(input) !== Object.prototype)
  ) fail(code);
  ancestors.add(input);
  try {
    const names = Object.getOwnPropertyNames(input);
    if (array) {
      const length = Object.getOwnPropertyDescriptor(input, 'length');
      if (
        !length
        || !Object.hasOwn(length, 'value')
        || !Number.isSafeInteger(length.value)
        || length.value < 0
        || names.length !== length.value + 1
      ) fail(code);
      for (let index = 0; index < length.value; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) fail(code);
        assertDeepFrozenPlainData(descriptor.value, code, ancestors);
      }
      return;
    }
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(input, name);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) fail(code);
      assertDeepFrozenPlainData(descriptor.value, code, ancestors);
    }
  } finally {
    ancestors.delete(input);
  }
}

function validateCallable(value) {
  if (typeof value !== 'function' || isProxy(value)) fail('RUNTIME_INPUT_INVALID', TypeError);
  return value;
}

function invocationEnvelope(value) {
  const envelope = Object.create(null);
  Object.defineProperty(envelope, 'value', { enumerable: true, value });
  return Object.freeze(envelope);
}

function rejectUntrustedThenable(input, invalidCode) {
  let current = input;
  while (current !== null) {
    if (isProxy(current)) {
      fail(invalidCode, invalidCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    }
    let thenDescriptor;
    let prototype;
    try {
      thenDescriptor = Object.getOwnPropertyDescriptor(current, 'then');
      prototype = Object.getPrototypeOf(current);
    } catch {
      fail(invalidCode, invalidCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    }
    if (thenDescriptor !== undefined) {
      fail(invalidCode, invalidCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    }
    current = prototype;
  }
}

function invoke(callable, args, invalidCode = 'RUNTIME_INPUT_INVALID') {
  const output = INTRINSIC_APPLY(callable, undefined, args);
  if (output === null || (typeof output !== 'object' && typeof output !== 'function')) {
    return invocationEnvelope(output);
  }
  if (isProxy(output)) {
    fail(invalidCode, invalidCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  if (!isPromise(output)) {
    rejectUntrustedThenable(output, invalidCode);
    return invocationEnvelope(output);
  }
  const referencePromise = INTRINSIC_APPLY(
    INTRINSIC_PROMISE_RESOLVE,
    NATIVE_PROMISE,
    [undefined],
  );
  const referenceSymbols = Object.getOwnPropertySymbols(referencePromise);
  const outputSymbols = Object.getOwnPropertySymbols(output);
  if (
    Object.getPrototypeOf(output) !== NATIVE_PROMISE.prototype
    || Object.getOwnPropertyNames(output).length !== 0
    || outputSymbols.length !== referenceSymbols.length
    || outputSymbols.some((symbol) => !referenceSymbols.includes(symbol))
  ) fail(invalidCode, invalidCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return new NATIVE_PROMISE((resolve, reject) => {
    INTRINSIC_APPLY(INTRINSIC_PROMISE_THEN, output, [
      (value) => resolve(invocationEnvelope(value)),
      reject,
    ]);
  });
}

function validateDependencies(input) {
  const values = exactRecord(input, DEPENDENCY_FIELDS, 'RUNTIME_INPUT_INVALID', { frozen: true });
  const output = {};
  for (const field of DEPENDENCY_FIELDS) output[field] = validateCallable(values[field]);
  return Object.freeze(output);
}

async function createDependencies(factory) {
  try {
    validateCallable(factory);
    return validateDependencies((await invoke(factory, [])).value);
  } catch {
    throw runtimeError('RUNTIME_INPUT_INVALID', TypeError);
  }
}

async function dependencyValue(dependencies, field, args, fallback, allowed = new Set()) {
  try {
    return (await invoke(dependencies[field], args, fallback)).value;
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(typeof code === 'string' && allowed.has(code) ? code : fallback);
  }
}

function validateDeviceId(value) {
  if (typeof value !== 'string' || value.length > 64 || !DEVICE_ID_PATTERN.test(value)) {
    fail('RUNTIME_INPUT_INVALID', TypeError);
  }
  return value;
}

function validateTicketId(value) {
  if (typeof value !== 'string' || !TICKET_ID_PATTERN.test(value)) {
    fail('RUNTIME_INPUT_INVALID', TypeError);
  }
  return value;
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function sameRecord(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validateState(input, deviceId) {
  try {
    const snapshot = validateRuntimeStateRecord(input);
    if (snapshot.deviceId !== deviceId) fail('RUNTIME_STATE_UNSUPPORTED');
    return snapshot;
  } catch {
    throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
}

function validateEligibleState(input, deviceId) {
  const state = validateState(input, deviceId);
  if (
    state.schemaVersion !== 1
    || state.runtimeStatus !== 'FAILED'
    || state.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN'
    || state.requestedProfiles.length !== 1
    || state.requestedProfiles[0] !== 'core'
    || state.readyProfiles.length !== 0
    || typeof state.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(state.operationId)
    || typeof state.manifestDigest !== 'string'
    || !DIGEST_PATTERN.test(state.manifestDigest)
    || typeof state.generationDigest !== 'string'
    || !DIGEST_PATTERN.test(state.generationDigest)
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  try {
    runtimeRecoveryStateDigest(state);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  return state;
}

async function readState(dependencies, deviceId) {
  const state = await dependencyValue(
    dependencies,
    'readState',
    [deviceId],
    'RUNTIME_STATE_UNSUPPORTED',
    new Set(['RUNTIME_ALREADY_RUNNING', 'RUNTIME_STATE_UNSUPPORTED']),
  );
  return validateState(state, deviceId);
}

async function readEligibleState(dependencies, deviceId) {
  return validateEligibleState(await readState(dependencies, deviceId), deviceId);
}

function safeDeviceDisplayName(target, deviceId) {
  const targetValues = exactRecord(
    target,
    ['device', 'identity', 'knownHostsPath'],
    'RUNTIME_INVENTORY_FAILED',
    { frozen: true },
  );
  if (
    targetValues.device === null
    || typeof targetValues.device !== 'object'
    || isProxy(targetValues.device)
    || Array.isArray(targetValues.device)
    || Object.getPrototypeOf(targetValues.device) !== Object.prototype
    || !Object.isFrozen(targetValues.device)
  ) fail('RUNTIME_INVENTORY_FAILED');
  const id = Object.getOwnPropertyDescriptor(targetValues.device, 'id');
  const displayName = Object.getOwnPropertyDescriptor(targetValues.device, 'displayName');
  if (
    !id
    || !Object.hasOwn(id, 'value')
    || id.value !== deviceId
    || !displayName
    || !Object.hasOwn(displayName, 'value')
    || typeof displayName.value !== 'string'
    || displayName.value.length === 0
    || Buffer.byteLength(displayName.value, 'utf8') > MAX_DISPLAY_NAME_BYTES
    || displayName.value !== displayName.value.trim()
    || /[\r\n\x00-\x1f\x7f]/u.test(displayName.value)
  ) fail('RUNTIME_INVENTORY_FAILED');
  return displayName.value;
}

async function loadTarget(dependencies, deviceId) {
  const target = await dependencyValue(
    dependencies,
    'loadTarget',
    [deviceId],
    'RUNTIME_INVENTORY_FAILED',
    new Set(),
  );
  try {
    const targetBindingDigest = runtimeRecoveryTargetBindingDigest(target);
    const displayName = safeDeviceDisplayName(target, deviceId);
    return Object.freeze({ target, targetBindingDigest, displayName });
  } catch {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
}

function validateScope(input) {
  const values = exactRecord(
    input,
    SCOPE_FIELDS,
    'RUNTIME_INPUT_INVALID',
    { frozen: true, nullPrototype: true },
  );
  const output = Object.create(null);
  for (const field of SCOPE_FIELDS) output[field] = validateCallable(values[field]);
  return Object.freeze(output);
}

async function scopeValue(scope, field, args, fallback, allowed = STORE_CODES) {
  try {
    return (await invoke(scope[field], args, fallback)).value;
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(typeof code === 'string' && allowed.has(code) ? code : fallback);
  }
}

function validateObservation(input, state) {
  assertDeepFrozenPlainData(input, 'RUNTIME_STATE_UNSUPPORTED');
  const value = exactRecord(
    input,
    OBSERVATION_FIELDS,
    'RUNTIME_STATE_UNSUPPORTED',
    { frozen: true },
  );
  let failedState;
  let bootMarker;
  try {
    failedState = validateEligibleState(value.failedState, state.deviceId);
    bootMarker = validateRuntimeRecoveryBootMarker(value.bootMarker);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'BOOT_OBSERVATION'
    || value.deviceId !== state.deviceId
    || value.operationId !== state.operationId
    || !sameRecord(failedState, state)
    || value.failedStateDigest !== runtimeRecoveryStateDigest(state)
    || !canonicalTimestamp(value.observedAt)
    || Date.parse(value.observedAt) < Date.parse(state.updatedAt)
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  return Object.freeze({ ...value, failedState, bootMarker });
}

function validateAcl(input, code) {
  const value = exactRecord(input, ACL_FIELDS, code, { frozen: true });
  if (
    value.ownerSid !== 'S-1-5-32-544'
    || value.protected !== true
    || value.canonical !== true
    || value.accessRuleCount !== 2
    || value.administratorsFullControl !== true
    || value.systemFullControl !== true
    || value.aclDigest !== TARGET_ACL_DIGEST
  ) fail(code);
  return Object.freeze({ ...value });
}

function validateExactChildren(input, expected, code) {
  const children = exactArray(input, 1, code);
  if (
    children.length !== expected.length
    || children.some((child, index) => child !== expected[index])
  ) fail(code);
  return children;
}

function validateDirectory(input, expectedChildren, code) {
  const value = exactRecord(input, DIRECTORY_FIELDS, code, { frozen: true });
  if (
    typeof value.volumeSerialNumber !== 'string'
    || !/^[A-F0-9]{16}$/u.test(value.volumeSerialNumber)
    || typeof value.fileId !== 'string'
    || !/^[A-F0-9]{32}$/u.test(value.fileId)
    || value.directChildCount !== expectedChildren.length
  ) fail(code);
  return Object.freeze({
    volumeSerialNumber: value.volumeSerialNumber,
    fileId: value.fileId,
    acl: validateAcl(value.acl, code),
    directChildCount: expectedChildren.length,
    directChildren: validateExactChildren(value.directChildren, expectedChildren, code),
  });
}

function validatePriorReference(input, code) {
  if (input === null) return null;
  const value = exactRecord(input, PRIOR_ATTEMPT_FIELDS, code, { frozen: true });
  if (
    typeof value.ticketId !== 'string'
    || !TICKET_ID_PATTERN.test(value.ticketId)
    || typeof value.attemptDigest !== 'string'
    || !DIGEST_PATTERN.test(value.attemptDigest)
  ) fail(code);
  return Object.freeze({ ticketId: value.ticketId, attemptDigest: value.attemptDigest });
}

function validateRemoteInspect(input, expected) {
  const code = 'RUNTIME_INVENTORY_FAILED';
  assertDeepFrozenPlainData(input, code);
  const value = exactRecord(input, REMOTE_INSPECT_FIELDS, code, { frozen: true });
  if (
    value.schemaVersion !== 1
    || value.protocolRevision !== 1
    || value.deviceId !== expected.deviceId
    || value.targetBindingDigest !== expected.targetBindingDigest
    || value.operationId !== expected.operationId
    || !['EMPTY_PRE_TRANSACTION', 'ALREADY_ABSENT', 'EXTERNALLY_ABSENT'].includes(
      value.classification,
    )
  ) fail(code);
  let marker;
  try {
    marker = validateRuntimeRecoveryBootMarker(value.bootMarker);
  } catch {
    fail(code);
  }
  const prior = validatePriorReference(value.priorAuthorizedAttempt, code);
  const empty = value.classification === 'EMPTY_PRE_TRANSACTION';
  const alreadyAbsent = value.classification === 'ALREADY_ABSENT';
  if (
    (empty && prior !== null)
    || (alreadyAbsent && (
      prior === null
      || expected.priorAuthorizedAttempt === null
      || !sameRecord(prior, expected.priorAuthorizedAttempt)
    ))
    || (value.classification === 'EXTERNALLY_ABSENT' && prior !== null)
  ) fail(code);
  const agentRoadAcl = validateAcl(value.agentRoadAcl, code);
  const runtimeDirectory = validateDirectory(value.runtimeDirectory, ['staging'], code);
  const stagingDirectory = validateDirectory(
    value.stagingDirectory,
    empty ? [expected.operationId] : [],
    code,
  );
  const operationDirectory = empty
    ? validateDirectory(value.operationDirectory, [], code)
    : value.operationDirectory;
  if (!empty && operationDirectory !== null) fail(code);
  const identities = [runtimeDirectory, stagingDirectory, operationDirectory]
    .filter((entry) => entry !== null)
    .map((entry) => `${entry.volumeSerialNumber}:${entry.fileId}`);
  if (new Set(identities).size !== identities.length) fail(code);
  return Object.freeze({
    schemaVersion: 1,
    protocolRevision: 1,
    deviceId: expected.deviceId,
    targetBindingDigest: expected.targetBindingDigest,
    operationId: expected.operationId,
    bootMarker: marker,
    classification: value.classification,
    priorAuthorizedAttempt: prior,
    agentRoadAcl,
    runtimeDirectory,
    stagingDirectory,
    operationDirectory,
  });
}

async function inspectRemote(dependencies, input, expected) {
  const result = await dependencyValue(
    dependencies,
    'inspectRemote',
    [input],
    'RUNTIME_INVENTORY_FAILED',
    INSPECT_REMOTE_CODES,
  );
  return validateRemoteInspect(result, expected);
}

function validateTicket(input, expected) {
  assertDeepFrozenPlainData(input, 'RUNTIME_STATE_UNSUPPORTED');
  const value = exactRecord(
    input,
    TICKET_FIELDS,
    'RUNTIME_STATE_UNSUPPORTED',
    { frozen: true },
  );
  let ticketDigest;
  let proofDigest;
  let failedState;
  let authorizationParent;
  let authorizationParentDigest;
  try {
    ticketDigest = runtimeRecoveryTicketDigest(input);
    proofDigest = runtimeRecoveryProofDigest(value.proof);
    failedState = validateEligibleState(value.failedState, expected.deviceId);
    authorizationParent = createRuntimeRecoveryAuthorizationParent(value.authorizationParent);
    authorizationParentDigest = runtimeRecoveryAuthorizationParentDigest(authorizationParent);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  const mismatchCode = expected.mismatchCode ?? 'RUNTIME_INPUT_INVALID';
  if (
    value.schemaVersion !== 2
    || value.recordType !== 'RECOVERY_TICKET'
    || value.ticketId !== expected.ticketId
    || value.deviceId !== expected.deviceId
    || value.operationId !== expected.state.operationId
    || authorizationParent.deviceId !== expected.deviceId
    || authorizationParent.operationId !== expected.state.operationId
    || authorizationParent.failedStateDigest !== runtimeRecoveryStateDigest(expected.state)
    || value.authorizationParentDigest !== authorizationParentDigest
    || (expected.authorizationParent !== undefined
      && !sameRecord(authorizationParent, expected.authorizationParent))
    || !sameRecord(failedState, expected.state)
    || value.failedStateDigest !== runtimeRecoveryStateDigest(expected.state)
    || value.proofDigest !== proofDigest
    || value.proof.deviceId !== expected.deviceId
    || value.proof.operationId !== expected.state.operationId
    || value.proof.targetBindingDigest !== expected.targetBindingDigest
    || value.proof.failedStateDigest !== value.failedStateDigest
    || value.proof.manifestDigest !== expected.state.manifestDigest
    || value.proof.generationDigest !== expected.state.generationDigest
  ) fail(mismatchCode, mismatchCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return Object.freeze({
    value: input,
    fields: Object.freeze({ ...value, authorizationParent }),
    digest: ticketDigest,
  });
}

function validateAttempt(input, ticket, code = 'RUNTIME_STATE_UNSUPPORTED') {
  assertDeepFrozenPlainData(input, code);
  const value = exactRecord(input, ATTEMPT_FIELDS, code, { frozen: true });
  let digest;
  try {
    digest = runtimeRecoveryAuthorizedAttemptDigest(input);
  } catch {
    fail(code);
  }
  if (
    value.ticketId !== ticket.fields.ticketId
    || value.deviceId !== ticket.fields.deviceId
    || value.operationId !== ticket.fields.operationId
    || value.ticketDigest !== ticket.digest
    || value.failedStateDigest !== ticket.fields.failedStateDigest
    || value.proofDigest !== ticket.fields.proofDigest
    || value.classification !== ticket.fields.proof.classification
    || Date.parse(value.authorizedAt) < Date.parse(ticket.fields.inspectedAt)
    || Date.parse(value.authorizedAt) >= Date.parse(ticket.fields.expiresAt)
  ) fail(code);
  return Object.freeze({ value: input, fields: value, digest });
}

function createAuthorizationParent(kind, state, ticket = null, attempt = null) {
  try {
    return createRuntimeRecoveryAuthorizationParent({
      schemaVersion: 1,
      kind,
      deviceId: state.deviceId,
      operationId: state.operationId,
      failedStateDigest: runtimeRecoveryStateDigest(state),
      ticketId: ticket?.fields.ticketId ?? null,
      ticketDigest: ticket?.digest ?? null,
      attemptDigest: attempt?.digest ?? null,
    });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
}

function clockMilliseconds(value, code) {
  if (
    value === null
    || typeof value !== 'object'
    || isProxy(value)
    || Object.getPrototypeOf(value) !== Date.prototype
    || Object.getOwnPropertyNames(value).length !== 0
    || Object.getOwnPropertySymbols(value).length !== 0
  ) fail(code);
  let milliseconds;
  try {
    milliseconds = Date.prototype.getTime.call(value);
  } catch {
    fail(code);
  }
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) fail(code);
  return milliseconds;
}

async function resolveAuthorizationParent(scope, ticketId, expected) {
  if (ticketId === null) {
    return Object.freeze({
      authorizationParent: createAuthorizationParent('GENESIS', expected.state),
      priorAuthorizedAttempt: null,
      expiresAt: null,
    });
  }
  const ticketValue = await scopeValue(
    scope,
    'readTicket',
    [ticketId],
    'RUNTIME_STATE_UNSUPPORTED',
    STORE_CODES,
  );
  const ticket = validateTicket(ticketValue, {
    ...expected,
    ticketId,
    mismatchCode: 'RUNTIME_INPUT_INVALID',
  });
  const attemptValue = await scopeValue(
    scope,
    'readAuthorizedDeleteAttempt',
    [ticketId],
    'RUNTIME_STATE_UNSUPPORTED',
    STORE_CODES,
  );
  if (attemptValue !== null) {
    const attempt = validateAttempt(attemptValue, ticket);
    const priorAuthorizedAttempt = ticket.fields.proof.classification === 'EMPTY_PRE_TRANSACTION'
      ? Object.freeze({ ticketId, attemptDigest: attempt.digest })
      : validatePriorReference(
          ticket.fields.proof.priorAuthorizedAttempt,
          'RUNTIME_STATE_UNSUPPORTED',
        );
    if (priorAuthorizedAttempt === null) fail('RUNTIME_STATE_UNSUPPORTED');
    return Object.freeze({
      authorizationParent: createAuthorizationParent(
        'AUTHORIZED_ATTEMPT',
        expected.state,
        ticket,
        attempt,
      ),
      priorAuthorizedAttempt,
      expiresAt: null,
    });
  }
  return Object.freeze({
    authorizationParent: createAuthorizationParent(
      'EXPIRED_TICKET',
      expected.state,
      ticket,
    ),
    priorAuthorizedAttempt: ticket.fields.proof.classification === 'ALREADY_ABSENT'
      ? validatePriorReference(
          ticket.fields.proof.priorAuthorizedAttempt,
          'RUNTIME_STATE_UNSUPPORTED',
        )
      : null,
    expiresAt: ticket.fields.expiresAt,
  });
}

function assertBootAdvanced(before, after) {
  if (
    BigInt(after.eventRecordId) <= BigInt(before.eventRecordId)
    || after.markerDigest === before.markerDigest
  ) fail('RUNTIME_REBOOT_REQUIRED');
}

function createProof(state, observation, remote) {
  assertBootAdvanced(observation.bootMarker, remote.bootMarker);
  try {
    return createRuntimeRecoveryProof({
      schemaVersion: 1,
      protocolRevision: 1,
      deviceId: state.deviceId,
      targetBindingDigest: remote.targetBindingDigest,
      failedState: state,
      beforeBootMarker: observation.bootMarker,
      afterBootMarker: remote.bootMarker,
      classification: remote.classification,
      priorAuthorizedAttempt: remote.priorAuthorizedAttempt,
      agentRoadAcl: remote.agentRoadAcl,
      runtimeDirectory: remote.runtimeDirectory,
      stagingDirectory: remote.stagingDirectory,
      operationDirectory: remote.operationDirectory,
    });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
}

function inspectResult(targetInfo, ticket, status, eligibleAfter = undefined) {
  const result = {
    schemaVersion: 1,
    status,
    deviceId: ticket.fields.deviceId,
    displayName: targetInfo.displayName,
    targetFingerprint: targetInfo.targetBindingDigest.slice(0, 12),
    classification: ticket.fields.proof.classification,
    rebootRequired: false,
    actionable: status === 'RECOVERY_READY',
    ticketId: ticket.fields.ticketId,
    ticketFingerprint: ticket.digest.slice(0, 12),
    expiresAt: ticket.fields.expiresAt,
  };
  if (status === 'RECOVERY_PARENT_REQUIRED') result.eligibleAfter = eligibleAfter;
  return Object.freeze(result);
}

function proposedRecoveredState(failedState, authorizedAt, clockValue) {
  if (
    clockValue === null
    || typeof clockValue !== 'object'
    || isProxy(clockValue)
    || Object.getPrototypeOf(clockValue) !== Date.prototype
    || Object.getOwnPropertyNames(clockValue).length !== 0
    || Object.getOwnPropertySymbols(clockValue).length !== 0
  ) fail('RUNTIME_INTERNAL_ERROR');
  let clockMs;
  try {
    clockMs = Date.prototype.getTime.call(clockValue);
  } catch {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  const nextMs = Math.max(
    clockMs,
    Date.parse(failedState.updatedAt) + 1,
    Date.parse(authorizedAt),
  );
  if (!Number.isSafeInteger(nextMs) || nextMs < 0 || nextMs > 253_402_300_799_999) {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  try {
    return validateRuntimeStateRecord({
      schemaVersion: 2,
      deviceId: failedState.deviceId,
      runtimeStatus: 'RECOVERED',
      requestedProfiles: ['core'],
      readyProfiles: [],
      operationId: failedState.operationId,
      manifestDigest: failedState.manifestDigest,
      generationDigest: failedState.generationDigest,
      failureCode: null,
      updatedAt: new Date(nextMs).toISOString(),
    });
  } catch {
    fail('RUNTIME_INTERNAL_ERROR');
  }
}

function expectedDisposition(classification) {
  return classification === 'EMPTY_PRE_TRANSACTION' ? 'REMOVED' : 'ALREADY_ABSENT';
}

function validateRemoteApply(input, ticket) {
  assertDeepFrozenPlainData(input, 'RUNTIME_COMPLETION_UNCERTAIN');
  const value = exactRecord(
    input,
    REMOTE_APPLY_FIELDS,
    'RUNTIME_COMPLETION_UNCERTAIN',
    { frozen: true },
  );
  if (
    value.schemaVersion !== 1
    || value.disposition !== expectedDisposition(ticket.fields.proof.classification)
  ) fail('RUNTIME_COMPLETION_UNCERTAIN');
  return Object.freeze({ schemaVersion: 1, disposition: value.disposition });
}

function validateCommit(input, expected) {
  assertDeepFrozenPlainData(input, 'RUNTIME_STATE_UNSUPPORTED');
  const value = exactRecord(
    input,
    COMMIT_FIELDS,
    'RUNTIME_STATE_UNSUPPORTED',
    { frozen: true },
  );
  let proposed;
  let proposedDigest;
  try {
    proposed = validateRuntimeStateRecord(value.proposedRecoveredState);
    proposedDigest = runtimeRecoveryStateDigest(proposed);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RECOVERY_COMMIT'
    || value.deviceId !== expected.state.deviceId
    || value.operationId !== expected.state.operationId
    || value.ticketId !== expected.ticket.fields.ticketId
    || value.expectedFailedStateDigest !== runtimeRecoveryStateDigest(expected.state)
    || value.proposedRecoveredStateDigest !== proposedDigest
    || value.proofDigest !== expected.ticket.fields.proofDigest
    || value.disposition !== expectedDisposition(expected.ticket.fields.proof.classification)
    || value.authorizedAttemptDigest !== expected.attempt.digest
    || value.authorizedAt !== expected.attempt.fields.authorizedAt
    || !canonicalTimestamp(value.committedAt)
    || Date.parse(value.committedAt) < Date.parse(value.authorizedAt)
    || proposed.schemaVersion !== 2
    || proposed.runtimeStatus !== 'RECOVERED'
    || proposed.deviceId !== expected.state.deviceId
    || proposed.operationId !== expected.state.operationId
    || proposed.manifestDigest !== expected.state.manifestDigest
    || proposed.generationDigest !== expected.state.generationDigest
    || proposed.requestedProfiles.length !== 1
    || proposed.requestedProfiles[0] !== 'core'
    || proposed.readyProfiles.length !== 0
    || proposed.failureCode !== null
    || proposed.updatedAt <= expected.state.updatedAt
    || Date.parse(proposed.updatedAt) < Date.parse(value.authorizedAt)
    || Date.parse(proposed.updatedAt) > Date.parse(value.committedAt)
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  return Object.freeze({ value: input, fields: value, proposed });
}

async function transitionRecovered(dependencies, expected, proposed) {
  try {
    const savedValue = await dependencyValue(
      dependencies,
      'transitionState',
      [expected, proposed],
      'RUNTIME_STATE_UNSUPPORTED',
      new Set(['RUNTIME_ALREADY_RUNNING', 'RUNTIME_STATE_UNSUPPORTED']),
    );
    const saved = validateState(savedValue, expected.deviceId);
    if (!sameRecord(saved, proposed)) fail('RUNTIME_STATE_UNSUPPORTED');
    return saved;
  } catch (error) {
    let current;
    try {
      current = await dependencyValue(
        dependencies,
        'readState',
        [expected.deviceId],
        'RUNTIME_STATE_UNSUPPORTED',
        new Set(['RUNTIME_ALREADY_RUNNING', 'RUNTIME_STATE_UNSUPPORTED']),
      );
      current = validateState(current, expected.deviceId);
    } catch {
      throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
    }
    if (sameRecord(current, proposed)) return current;
    if (!sameRecord(current, expected) || safeCode(error) === 'RUNTIME_ALREADY_RUNNING') {
      throw runtimeError('RUNTIME_ALREADY_RUNNING');
    }
    throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
}

function recoveredResult(targetInfo, ticket, disposition) {
  return Object.freeze({
    schemaVersion: 1,
    status: 'RECOVERED',
    deviceId: ticket.fields.deviceId,
    displayName: targetInfo.displayName,
    targetFingerprint: targetInfo.targetBindingDigest.slice(0, 12),
    classification: ticket.fields.proof.classification,
    ticketFingerprint: ticket.digest.slice(0, 12),
    disposition,
  });
}

async function withRecoveryOperation(dependencies, state, callback, allowed) {
  return dependencyValue(
    dependencies,
    'withRecoveryOperation',
    [Object.freeze({ deviceId: state.deviceId, operationId: state.operationId }), callback],
    'RUNTIME_STATE_UNSUPPORTED',
    allowed,
  );
}

export async function inspectRuntimeRecovery(input) {
  markInspectStage('INPUT_VALIDATION');
  const values = exactRecord(input, INSPECT_FIELDS);
  const deviceId = validateDeviceId(values.deviceId);
  const priorTicketId = values.priorTicketId === null
    ? null
    : validateTicketId(values.priorTicketId);
  markInspectStage('DEPENDENCIES');
  const dependencies = await createDependencies(values.dependencyFactory);
  markInspectStage('STATE_READ');
  const initialState = await readEligibleState(dependencies, deviceId);
  markInspectStage('TARGET_LOAD');
  const targetInfo = await loadTarget(dependencies, deviceId);

  markInspectStage('RECOVERY_LOCK');
  return withRecoveryOperation(dependencies, initialState, async (scopeInput) => {
    markInspectStage('RECOVERY_SCOPE');
    const scope = validateScope(scopeInput);
    markInspectStage('STATE_RECHECK');
    const state = await readState(dependencies, deviceId);
    if (!sameRecord(state, initialState)) fail('RUNTIME_ALREADY_RUNNING');
    validateEligibleState(state, deviceId);
    markInspectStage('BOOT_OBSERVATION_READ');
    const observationValue = await scopeValue(
      scope,
      'readBootObservation',
      [],
      'RUNTIME_STATE_UNSUPPORTED',
    );
    markInspectStage('COMMIT_READ');
    const commitValue = await scopeValue(
      scope,
      'readRecoveryCommit',
      [],
      'RUNTIME_STATE_UNSUPPORTED',
      STORE_CODES,
    );
    markInspectStage('RECOVERY_RECORDS');
    const observation = observationValue === null
      ? null
      : validateObservation(observationValue, state);
    if (commitValue !== null) {
      if (observation === null) fail('RUNTIME_STATE_UNSUPPORTED');
      assertDeepFrozenPlainData(commitValue, 'RUNTIME_STATE_UNSUPPORTED');
      const commitFields = exactRecord(
        commitValue,
        COMMIT_FIELDS,
        'RUNTIME_STATE_UNSUPPORTED',
        { frozen: true },
      );
      if (
        typeof commitFields.ticketId !== 'string'
        || !TICKET_ID_PATTERN.test(commitFields.ticketId)
      ) fail('RUNTIME_STATE_UNSUPPORTED');
      let ticketValue;
      let attemptValue;
      try {
        ticketValue = await scopeValue(
          scope,
          'readTicket',
          [commitFields.ticketId],
          'RUNTIME_STATE_UNSUPPORTED',
          STORE_CODES,
        );
        attemptValue = await scopeValue(
          scope,
          'readAuthorizedDeleteAttempt',
          [commitFields.ticketId],
          'RUNTIME_STATE_UNSUPPORTED',
          STORE_CODES,
        );
      } catch {
        fail('RUNTIME_STATE_UNSUPPORTED');
      }
      const ticket = validateTicket(ticketValue, {
        deviceId,
        state,
        targetBindingDigest: targetInfo.targetBindingDigest,
        ticketId: commitFields.ticketId,
        mismatchCode: 'RUNTIME_STATE_UNSUPPORTED',
      });
      if (attemptValue === null) fail('RUNTIME_STATE_UNSUPPORTED');
      const attempt = validateAttempt(attemptValue, ticket);
      validateCommit(commitValue, { state, ticket, attempt });
      return inspectResult(targetInfo, ticket, 'RECOVERY_APPLY_REQUIRED');
    }

    if (observation === null) {
      if (priorTicketId !== null) fail('RUNTIME_INPUT_INVALID', TypeError);
      const remoteInput = Object.freeze({
        target: targetInfo.target,
        operationId: state.operationId,
        beforeBootMarker: null,
        priorAuthorizedAttempt: null,
      });
      markInspectStage('REMOTE_INSPECT');
      const remote = await inspectRemote(dependencies, remoteInput, {
        deviceId,
        operationId: state.operationId,
        targetBindingDigest: targetInfo.targetBindingDigest,
        priorAuthorizedAttempt: null,
      });
      markInspectStage('REMOTE_RESULT_VALIDATION');
      if (remote.classification !== 'EMPTY_PRE_TRANSACTION') {
        fail('RUNTIME_STATE_UNSUPPORTED');
      }
      markInspectStage('BOOT_OBSERVATION_PUBLISH');
      const created = await scopeValue(
        scope,
        'createBootObservation',
        [Object.freeze({ deviceId, failedState: state, bootMarker: remote.bootMarker })],
        'RUNTIME_STATE_UNSUPPORTED',
      );
      const createdObservation = validateObservation(created, state);
      if (!sameRecord(createdObservation.bootMarker, remote.bootMarker)) {
        fail('RUNTIME_STATE_UNSUPPORTED');
      }
      throw runtimeError('RUNTIME_REBOOT_REQUIRED');
    }

    const parent = await resolveAuthorizationParent(
      scope,
      priorTicketId,
      {
        deviceId,
        state,
        targetBindingDigest: targetInfo.targetBindingDigest,
      },
    );
    const successorValue = await scopeValue(
      scope,
      'resolveAuthorizationSuccessor',
      [parent.authorizationParent],
      'RUNTIME_STATE_UNSUPPORTED',
      STORE_CODES,
    );
    if (successorValue !== null) {
      const successorFields = exactRecord(
        successorValue,
        TICKET_FIELDS,
        'RUNTIME_STATE_UNSUPPORTED',
        { frozen: true },
      );
      const successorTicket = validateTicket(successorValue, {
        deviceId,
        state,
        targetBindingDigest: targetInfo.targetBindingDigest,
        ticketId: successorFields.ticketId,
        authorizationParent: parent.authorizationParent,
        mismatchCode: 'RUNTIME_STATE_UNSUPPORTED',
      });
      if (successorTicket.fields.ticketId === priorTicketId) {
        fail('RUNTIME_STATE_UNSUPPORTED');
      }
      const successorAttemptValue = await scopeValue(
        scope,
        'readAuthorizedDeleteAttempt',
        [successorTicket.fields.ticketId],
        'RUNTIME_STATE_UNSUPPORTED',
        STORE_CODES,
      );
      const successorAttempt = successorAttemptValue === null
        ? null
        : validateAttempt(successorAttemptValue, successorTicket);
      if (successorAttempt !== null) {
        return inspectResult(
          targetInfo,
          successorTicket,
          'RECOVERY_PARENT_REQUIRED',
          null,
        );
      }
      const successorClock = await dependencyValue(
        dependencies,
        'clock',
        [],
        'RUNTIME_STATE_UNSUPPORTED',
        new Set(),
      );
      if (
        clockMilliseconds(successorClock, 'RUNTIME_STATE_UNSUPPORTED')
        >= Date.parse(successorTicket.fields.expiresAt)
      ) {
        return inspectResult(
          targetInfo,
          successorTicket,
          'RECOVERY_PARENT_REQUIRED',
          null,
        );
      }
    }
    if (successorValue === null && parent.expiresAt !== null) {
      const parentClock = await dependencyValue(
        dependencies,
        'clock',
        [],
        'RUNTIME_STATE_UNSUPPORTED',
        new Set(),
      );
      if (
        clockMilliseconds(parentClock, 'RUNTIME_STATE_UNSUPPORTED')
        < Date.parse(parent.expiresAt)
      ) {
        fail('RUNTIME_INPUT_INVALID', TypeError);
      }
    }
    const remoteInput = Object.freeze({
      target: targetInfo.target,
      operationId: state.operationId,
      beforeBootMarker: observation.bootMarker,
      priorAuthorizedAttempt: parent.priorAuthorizedAttempt,
    });
    markInspectStage('REMOTE_INSPECT');
    const remote = await inspectRemote(dependencies, remoteInput, {
      deviceId,
      operationId: state.operationId,
      targetBindingDigest: targetInfo.targetBindingDigest,
      priorAuthorizedAttempt: parent.priorAuthorizedAttempt,
    });
    markInspectStage('REMOTE_RESULT_VALIDATION');
    if (remote.classification === 'EXTERNALLY_ABSENT') fail('RUNTIME_STATE_UNSUPPORTED');
    const proof = createProof(state, observation, remote);
    markInspectStage('TICKET_PUBLISH');
    const ticketValue = await scopeValue(
      scope,
      'createTicket',
      [Object.freeze({
        deviceId,
        failedState: state,
        proof,
        authorizationParent: parent.authorizationParent,
      })],
      'RUNTIME_STATE_UNSUPPORTED',
    );
    const ticketId = exactRecord(
      ticketValue,
      TICKET_FIELDS,
      'RUNTIME_STATE_UNSUPPORTED',
      { frozen: true },
    ).ticketId;
    if (priorTicketId !== null && ticketId === priorTicketId) {
      fail('RUNTIME_STATE_UNSUPPORTED');
    }
    const ticket = validateTicket(ticketValue, {
      deviceId,
      state,
      targetBindingDigest: targetInfo.targetBindingDigest,
      ticketId,
      authorizationParent: parent.authorizationParent,
      mismatchCode: 'RUNTIME_STATE_UNSUPPORTED',
    });
    const attemptValue = await scopeValue(
      scope,
      'readAuthorizedDeleteAttempt',
      [ticketId],
      'RUNTIME_STATE_UNSUPPORTED',
      STORE_CODES,
    );
    const attempt = attemptValue === null ? null : validateAttempt(attemptValue, ticket);
    const clockValue = await dependencyValue(
      dependencies,
      'clock',
      [],
      'RUNTIME_STATE_UNSUPPORTED',
      new Set(),
    );
    const nowMs = clockMilliseconds(clockValue, 'RUNTIME_STATE_UNSUPPORTED');
    const expiresAtMs = Date.parse(ticket.fields.expiresAt);
    const ready = sameRecord(ticket.fields.proof, proof)
      && attempt === null
      && nowMs < expiresAtMs;
    if (ready) return inspectResult(targetInfo, ticket, 'RECOVERY_READY');
    const eligibleAfter = attempt === null && nowMs < expiresAtMs
      ? ticket.fields.expiresAt
      : null;
    return inspectResult(
      targetInfo,
      ticket,
      'RECOVERY_PARENT_REQUIRED',
      eligibleAfter,
    );
  }, INSPECT_OPERATION_CODES);
}

export async function applyRuntimeRecovery(input) {
  const values = exactRecord(input, APPLY_FIELDS);
  const deviceId = validateDeviceId(values.deviceId);
  const ticketId = validateTicketId(values.ticketId);
  const dependencies = await createDependencies(values.dependencyFactory);
  const initialState = await readEligibleState(dependencies, deviceId);
  const targetInfo = await loadTarget(dependencies, deviceId);

  return withRecoveryOperation(dependencies, initialState, async (scopeInput) => {
    const scope = validateScope(scopeInput);
    const state = await readState(dependencies, deviceId);
    if (!sameRecord(state, initialState)) fail('RUNTIME_ALREADY_RUNNING');
    validateEligibleState(state, deviceId);
    const ticketValue = await scopeValue(
      scope,
      'readTicket',
      [ticketId],
      'RUNTIME_STATE_UNSUPPORTED',
      STORE_CODES,
    );
    const ticket = validateTicket(ticketValue, {
      deviceId,
      state,
      targetBindingDigest: targetInfo.targetBindingDigest,
      ticketId,
      mismatchCode: 'RUNTIME_INPUT_INVALID',
    });
    const commitValue = await scopeValue(
      scope,
      'readRecoveryCommit',
      [],
      'RUNTIME_STATE_UNSUPPORTED',
      STORE_CODES,
    );
    const attemptValue = await scopeValue(
      scope,
      'readAuthorizedDeleteAttempt',
      [ticketId],
      'RUNTIME_STATE_UNSUPPORTED',
      STORE_CODES,
    );
    const attempt = attemptValue === null ? null : validateAttempt(attemptValue, ticket);

    if (commitValue !== null) {
      if (attempt === null) fail('RUNTIME_STATE_UNSUPPORTED');
      const commit = validateCommit(commitValue, { state, ticket, attempt });
      await transitionRecovered(dependencies, state, commit.proposed);
      return recoveredResult(targetInfo, ticket, commit.fields.disposition);
    }
    if (attempt !== null) fail('RUNTIME_COMPLETION_UNCERTAIN');

    const consumedValue = await scopeValue(
      scope,
      'consumeTicket',
      [Object.freeze({
        deviceId,
        operationId: state.operationId,
        ticketId,
        failedState: state,
        proof: ticket.fields.proof,
      })],
      'RUNTIME_STATE_UNSUPPORTED',
      STORE_CODES,
    );
    const consumedAttempt = validateAttempt(consumedValue, ticket);
    const remoteValue = await dependencyValue(
      dependencies,
      'applyRemote',
      [Object.freeze({
        target: targetInfo.target,
        proof: ticket.fields.proof,
        authorizedAttempt: consumedAttempt.value,
      })],
      'RUNTIME_COMPLETION_UNCERTAIN',
      APPLY_REMOTE_CODES,
    );
    const remote = validateRemoteApply(remoteValue, ticket);
    const clockValue = await dependencyValue(
      dependencies,
      'clock',
      [],
      'RUNTIME_INTERNAL_ERROR',
      new Set(),
    );
    const proposed = proposedRecoveredState(
      state,
      consumedAttempt.fields.authorizedAt,
      clockValue,
    );
    const commitRecord = await scopeValue(
      scope,
      'createRecoveryCommit',
      [Object.freeze({
        expectedFailedState: state,
        proposedRecoveredState: proposed,
        ticketId,
        proofDigest: ticket.fields.proofDigest,
        disposition: remote.disposition,
      })],
      'RUNTIME_STATE_UNSUPPORTED',
      STORE_CODES,
    );
    const commit = validateCommit(commitRecord, { state, ticket, attempt: consumedAttempt });
    await transitionRecovered(dependencies, state, commit.proposed);
    return recoveredResult(targetInfo, ticket, commit.fields.disposition);
  }, APPLY_OPERATION_CODES);
}
