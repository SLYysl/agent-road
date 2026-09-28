import { execFile as execFileCallback, spawn } from 'node:child_process';
import { AsyncLocalStorage } from 'node:async_hooks';
import {
  createHash,
  randomBytes as cryptoRandomBytes,
  randomUUID,
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
  basename,
  dirname,
  isAbsolute,
  join as joinPath,
  resolve,
} from 'node:path';
import { promisify, TextDecoder } from 'node:util';
import { isProxy } from 'node:util/types';

import {validateTerminalRollbackCommit, assertTerminalRollbackStatePair} from './terminal-rollback-protocol.mjs';
import {
  runtimeDeviceRecoveryPaths,
  runtimeRecoveryAuthorizationSuccessorPath,
} from '../core/paths.mjs';

import {
  createStagedRetentionProposal,
  isStagedRetentionProtocolError,
  validateStagedRetentionProposal,
  createStagedRetentionAttempt,
  validateStagedRetentionAttempt,
  reconcileStagedRetention,
  validateStagedRetentionReconciliation,
} from './staged-retention-protocol.mjs';

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const DIGEST_PATTERN = /^[A-F0-9]{64}$/u;
const TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const BOOT_PROVIDER_GUID = '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}';
const MAX_UINT64 = 18_446_744_073_709_551_615n;
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
const BOOT_MARKER_INPUT_FIELDS = Object.freeze([
  'schemaVersion',
  'providerGuid',
  'channel',
  'eventId',
  'version',
  'eventRecordId',
  'timeCreated',
  'startTime',
]);
const BOOT_MARKER_FIELDS = Object.freeze([...BOOT_MARKER_INPUT_FIELDS, 'markerDigest']);
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
const PRIOR_AUTHORIZED_ATTEMPT_FIELDS = Object.freeze([
  'ticketId',
  'attemptDigest',
]);
const PROOF_INPUT_FIELDS = Object.freeze([
  'schemaVersion',
  'protocolRevision',
  'deviceId',
  'targetBindingDigest',
  'failedState',
  'beforeBootMarker',
  'afterBootMarker',
  'classification',
  'priorAuthorizedAttempt',
  'agentRoadAcl',
  'runtimeDirectory',
  'stagingDirectory',
  'operationDirectory',
]);
const PROOF_FIELDS = Object.freeze([
  'schemaVersion',
  'protocolRevision',
  'deviceId',
  'targetBindingDigest',
  'failedStateDigest',
  'operationId',
  'manifestDigest',
  'generationDigest',
  'beforeBootMarker',
  'afterBootMarker',
  'classification',
  'priorAuthorizedAttempt',
  'agentRoadAcl',
  'runtimeDirectory',
  'stagingDirectory',
  'operationDirectory',
]);
const BOOT_OBSERVATION_INPUT_FIELDS = Object.freeze([
  'deviceId',
  'failedState',
  'bootMarker',
]);
const BOOT_OBSERVATION_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'deviceId',
  'operationId',
  'failedState',
  'failedStateDigest',
  'bootMarker',
  'observedAt',
]);
const AUTHORIZATION_PARENT_FIELDS = Object.freeze([
  'schemaVersion',
  'kind',
  'deviceId',
  'operationId',
  'failedStateDigest',
  'ticketId',
  'ticketDigest',
  'attemptDigest',
]);
const TICKET_INPUT_FIELDS = Object.freeze([
  'deviceId',
  'failedState',
  'proof',
  'authorizationParent',
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
const AUTHORIZATION_SUCCESSOR_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'deviceId',
  'operationId',
  'authorizationParent',
  'authorizationParentDigest',
  'ticket',
  'ticketDigest',
]);
const CONSUME_TICKET_INPUT_FIELDS = Object.freeze([
  'deviceId',
  'operationId',
  'ticketId',
  'failedState',
  'proof',
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
const COMMIT_INPUT_FIELDS = Object.freeze([
  'expectedFailedState',
  'proposedRecoveredState',
  'ticketId',
  'proofDigest',
  'disposition',
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
const TICKET_ID_PATTERN = /^rct_[a-f0-9]{64}$/u;
const TICKET_TTL_MS = 10 * 60 * 1_000;
const MAX_RECORD_BYTES = 16_384;
const LOCKF_OUTPUT_LIMIT = 1_024;
const LOCKF_DEFAULT_WAIT_SECONDS = 1;
const LOCKF_TICKET_COALESCE_WAIT_SECONDS = 5;
const LOCKF_WATCHDOG_GRACE_MS = 1_500;
const LOCKF_TEMPFAIL = 75;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const IMMUTABLE_TEMPORARY_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const V2_RETAINED_WITNESS_DIRECTORIES = new Set([
  'authorization-successors',
  'tickets-v2',
  'authorized-delete-attempts-v2',
]);
const OWN_ERRORS = new WeakSet();
const RECOVERY_TEST_HOOK = Symbol.for('agent-road.runtime-recovery-store.test-hook');
const NO_TEST_HOOK = Object.freeze(async () => {});
const RECOVERY_HELD_READ_CONTEXT = new AsyncLocalStorage();
const execFile = promisify(execFileCallback);

function runtimeError(code, ErrorType = Error) {
  const error = new ErrorType(code);
  error.code = code;
  OWN_ERRORS.add(error);
  return error;
}

function fail(code = 'RUNTIME_INPUT_INVALID', ErrorType = TypeError) {
  throw runtimeError(code, ErrorType);
}

async function runRecoveryTestHook(event, context) {
  let hook = NO_TEST_HOOK;
  if (process.env.NODE_TEST_CONTEXT !== undefined) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, RECOVERY_TEST_HOOK);
    if (descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function') {
      hook = descriptor.value;
    }
  }
  await hook(event, Object.freeze({ ...context }));
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function readExactObject(input, fields, code = 'RUNTIME_INPUT_INVALID') {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code);
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) fail(code);
  const values = Object.create(null);
  for (const field of fields) {
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

function exactSingleCoreProfiles(input, code) {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || Object.getOwnPropertyNames(input).length !== 2
  ) fail(code);
  const length = Object.getOwnPropertyDescriptor(input, 'length');
  const zero = Object.getOwnPropertyDescriptor(input, '0');
  if (
    !length
    || !Object.hasOwn(length, 'value')
    || length.value !== 1
    || !zero
    || !Object.hasOwn(zero, 'value')
    || zero.value !== 'core'
    || zero.enumerable !== true
  ) fail(code);
  return Object.freeze(['core']);
}

function exactEmptyProfiles(input, code) {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || Object.getOwnPropertyNames(input).length !== 1
    || Object.getOwnPropertyDescriptor(input, 'length')?.value !== 0
  ) fail(code);
  return Object.freeze([]);
}

function canonicalRecoveryState(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactObject(input, STATE_FIELDS, code);
  const requestedProfiles = exactSingleCoreProfiles(value.requestedProfiles, code);
  const readyProfiles = exactEmptyProfiles(value.readyProfiles, code);
  const common = typeof value.deviceId === 'string'
    && DEVICE_ID_PATTERN.test(value.deviceId)
    && value.deviceId.length <= 64
    && typeof value.operationId === 'string'
    && OPERATION_ID_PATTERN.test(value.operationId)
    && typeof value.manifestDigest === 'string'
    && DIGEST_PATTERN.test(value.manifestDigest)
    && typeof value.generationDigest === 'string'
    && DIGEST_PATTERN.test(value.generationDigest)
    && canonicalTimestamp(value.updatedAt);
  const failed = value.schemaVersion === 1
    && value.runtimeStatus === 'FAILED'
    && value.failureCode === 'RUNTIME_COMPLETION_UNCERTAIN';
  const recovered = value.schemaVersion === 2
    && value.runtimeStatus === 'RECOVERED'
    && value.failureCode === null;
  if (!common || (!failed && !recovered)) fail(code);
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

export function runtimeRecoveryStateDigest(input) {
  const state = canonicalRecoveryState(input);
  return createHash('sha256')
    .update('AGENT_ROAD_RUNTIME_RECOVERY_STATE_V1\0', 'utf8')
    .update(JSON.stringify(state), 'utf8')
    .digest('hex')
    .toUpperCase();
}

function canonicalAuthorizationParent(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactObject(input, AUTHORIZATION_PARENT_FIELDS, code);
  const common = value.schemaVersion === 1
    && ['GENESIS', 'EXPIRED_TICKET', 'AUTHORIZED_ATTEMPT'].includes(value.kind)
    && typeof value.deviceId === 'string'
    && value.deviceId.length <= 64
    && DEVICE_ID_PATTERN.test(value.deviceId)
    && typeof value.operationId === 'string'
    && OPERATION_ID_PATTERN.test(value.operationId)
    && typeof value.failedStateDigest === 'string'
    && DIGEST_PATTERN.test(value.failedStateDigest);
  const genesis = value.kind === 'GENESIS'
    && value.ticketId === null
    && value.ticketDigest === null
    && value.attemptDigest === null;
  const expired = value.kind === 'EXPIRED_TICKET'
    && typeof value.ticketId === 'string'
    && TICKET_ID_PATTERN.test(value.ticketId)
    && typeof value.ticketDigest === 'string'
    && DIGEST_PATTERN.test(value.ticketDigest)
    && value.attemptDigest === null;
  const authorized = value.kind === 'AUTHORIZED_ATTEMPT'
    && typeof value.ticketId === 'string'
    && TICKET_ID_PATTERN.test(value.ticketId)
    && typeof value.ticketDigest === 'string'
    && DIGEST_PATTERN.test(value.ticketDigest)
    && typeof value.attemptDigest === 'string'
    && DIGEST_PATTERN.test(value.attemptDigest);
  if (!common || (!genesis && !expired && !authorized)) {
    fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: value.kind,
    deviceId: value.deviceId,
    operationId: value.operationId,
    failedStateDigest: value.failedStateDigest,
    ticketId: value.ticketId,
    ticketDigest: value.ticketDigest,
    attemptDigest: value.attemptDigest,
  });
}

export function createRuntimeRecoveryAuthorizationParent(input) {
  return canonicalAuthorizationParent(input);
}

export function runtimeRecoveryAuthorizationParentDigest(input) {
  const parent = canonicalAuthorizationParent(input);
  return createHash('sha256')
    .update('AGENT_ROAD_RUNTIME_RECOVERY_AUTHORIZATION_PARENT_V1\0', 'utf8')
    .update(JSON.stringify(parent), 'utf8')
    .digest('hex')
    .toUpperCase();
}

function canonicalEventRecordId(value, code) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value)) fail(code);
  let number;
  try {
    number = BigInt(value);
  } catch {
    fail(code);
  }
  if (number <= 0n || number > MAX_UINT64) fail(code);
  return value;
}

function canonicalBootMarkerInput(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactObject(input, BOOT_MARKER_INPUT_FIELDS, code);
  if (
    value.schemaVersion !== 1
    || value.providerGuid !== BOOT_PROVIDER_GUID
    || value.channel !== 'System'
    || value.eventId !== 12
    || !Number.isInteger(value.version)
    || value.version < 0
    || value.version > 255
    || !canonicalTimestamp(value.timeCreated)
    || !canonicalTimestamp(value.startTime)
  ) fail(code);
  return Object.freeze({
    schemaVersion: 1,
    providerGuid: BOOT_PROVIDER_GUID,
    channel: 'System',
    eventId: 12,
    version: value.version,
    eventRecordId: canonicalEventRecordId(value.eventRecordId, code),
    timeCreated: value.timeCreated,
    startTime: value.startTime,
  });
}

function bootMarkerDigest(input) {
  return createHash('sha256')
    .update('AGENT_ROAD_WINDOWS_BOOT_EVENT_12_V1\0', 'utf8')
    .update(JSON.stringify(input), 'utf8')
    .digest('hex')
    .toUpperCase();
}

export function createRuntimeRecoveryBootMarker(input) {
  const marker = canonicalBootMarkerInput(input);
  return Object.freeze({ ...marker, markerDigest: bootMarkerDigest(marker) });
}

export function validateRuntimeRecoveryBootMarker(input) {
  const value = readExactObject(input, BOOT_MARKER_FIELDS, 'RUNTIME_INPUT_INVALID');
  const marker = canonicalBootMarkerInput(Object.fromEntries(
    BOOT_MARKER_INPUT_FIELDS.map((field) => [field, value[field]]),
  ));
  if (value.markerDigest !== bootMarkerDigest(marker)) fail('RUNTIME_INPUT_INVALID');
  return Object.freeze({ ...marker, markerDigest: value.markerDigest });
}

function canonicalAcl(input, code) {
  const value = readExactObject(input, ACL_FIELDS, code);
  if (
    value.ownerSid !== 'S-1-5-32-544'
    || value.protected !== true
    || value.canonical !== true
    || value.accessRuleCount !== 2
    || value.administratorsFullControl !== true
    || value.systemFullControl !== true
    || typeof value.aclDigest !== 'string'
    || !DIGEST_PATTERN.test(value.aclDigest)
  ) fail(code);
  return Object.freeze({
    ownerSid: value.ownerSid,
    protected: true,
    canonical: true,
    accessRuleCount: 2,
    administratorsFullControl: true,
    systemFullControl: true,
    aclDigest: value.aclDigest,
  });
}

function canonicalDirectChildren(input, expected, code) {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || Object.getOwnPropertyNames(input).length !== expected.length + 1
    || Object.getOwnPropertyDescriptor(input, 'length')?.value !== expected.length
  ) fail(code);
  const values = [];
  for (let index = 0; index < expected.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (
      !descriptor
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
      || descriptor.value !== expected[index]
    ) fail(code);
    values.push(descriptor.value);
  }
  return Object.freeze(values);
}

function canonicalDirectory(input, expectedChildren, code) {
  const value = readExactObject(input, DIRECTORY_FIELDS, code);
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
    acl: canonicalAcl(value.acl, code),
    directChildCount: expectedChildren.length,
    directChildren: canonicalDirectChildren(value.directChildren, expectedChildren, code),
  });
}

function canonicalPriorAuthorizedAttempt(input, code) {
  if (input === null) return null;
  const value = readExactObject(input, PRIOR_AUTHORIZED_ATTEMPT_FIELDS, code);
  if (
    typeof value.ticketId !== 'string'
    || !TICKET_ID_PATTERN.test(value.ticketId)
    || typeof value.attemptDigest !== 'string'
    || !DIGEST_PATTERN.test(value.attemptDigest)
  ) fail(code);
  return Object.freeze({
    ticketId: value.ticketId,
    attemptDigest: value.attemptDigest,
  });
}

function canonicalRecoveryProof(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactObject(input, PROOF_FIELDS, code);
  if (
    value.schemaVersion !== 1
    || value.protocolRevision !== 1
    || typeof value.deviceId !== 'string'
    || value.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || typeof value.targetBindingDigest !== 'string'
    || !DIGEST_PATTERN.test(value.targetBindingDigest)
    || typeof value.failedStateDigest !== 'string'
    || !DIGEST_PATTERN.test(value.failedStateDigest)
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || typeof value.manifestDigest !== 'string'
    || !DIGEST_PATTERN.test(value.manifestDigest)
    || typeof value.generationDigest !== 'string'
    || !DIGEST_PATTERN.test(value.generationDigest)
    || !['EMPTY_PRE_TRANSACTION', 'ALREADY_ABSENT'].includes(value.classification)
  ) fail(code);
  const beforeBootMarker = validateRuntimeRecoveryBootMarker(value.beforeBootMarker);
  const afterBootMarker = validateRuntimeRecoveryBootMarker(value.afterBootMarker);
  if (
    BigInt(afterBootMarker.eventRecordId) <= BigInt(beforeBootMarker.eventRecordId)
    || afterBootMarker.markerDigest === beforeBootMarker.markerDigest
  ) fail(code);
  const empty = value.classification === 'EMPTY_PRE_TRANSACTION';
  const priorAuthorizedAttempt = canonicalPriorAuthorizedAttempt(
    value.priorAuthorizedAttempt,
    code,
  );
  if ((empty && priorAuthorizedAttempt !== null) || (!empty && priorAuthorizedAttempt === null)) {
    fail(code);
  }
  const agentRoadAcl = canonicalAcl(value.agentRoadAcl, code);
  const runtimeDirectory = canonicalDirectory(value.runtimeDirectory, ['staging'], code);
  const stagingDirectory = canonicalDirectory(
    value.stagingDirectory,
    empty ? [value.operationId] : [],
    code,
  );
  const operationDirectory = empty
    ? canonicalDirectory(value.operationDirectory, [], code)
    : value.operationDirectory;
  if ((!empty && operationDirectory !== null)) fail(code);
  const identities = [runtimeDirectory, stagingDirectory, operationDirectory]
    .filter((entry) => entry !== null)
    .map((entry) => `${entry.volumeSerialNumber}:${entry.fileId}`);
  if (new Set(identities).size !== identities.length) fail(code);
  return Object.freeze({
    schemaVersion: 1,
    protocolRevision: 1,
    deviceId: value.deviceId,
    targetBindingDigest: value.targetBindingDigest,
    failedStateDigest: value.failedStateDigest,
    operationId: value.operationId,
    manifestDigest: value.manifestDigest,
    generationDigest: value.generationDigest,
    beforeBootMarker,
    afterBootMarker,
    classification: value.classification,
    priorAuthorizedAttempt,
    agentRoadAcl,
    runtimeDirectory,
    stagingDirectory,
    operationDirectory,
  });
}

export function createRuntimeRecoveryProof(input) {
  const value = readExactObject(input, PROOF_INPUT_FIELDS, 'RUNTIME_INPUT_INVALID');
  const failedState = canonicalRecoveryState(value.failedState);
  if (
    failedState.runtimeStatus !== 'FAILED'
    || value.deviceId !== failedState.deviceId
  ) fail('RUNTIME_INPUT_INVALID');
  return canonicalRecoveryProof({
    schemaVersion: value.schemaVersion,
    protocolRevision: value.protocolRevision,
    deviceId: value.deviceId,
    targetBindingDigest: value.targetBindingDigest,
    failedStateDigest: runtimeRecoveryStateDigest(failedState),
    operationId: failedState.operationId,
    manifestDigest: failedState.manifestDigest,
    generationDigest: failedState.generationDigest,
    beforeBootMarker: value.beforeBootMarker,
    afterBootMarker: value.afterBootMarker,
    classification: value.classification,
    priorAuthorizedAttempt: value.priorAuthorizedAttempt,
    agentRoadAcl: value.agentRoadAcl,
    runtimeDirectory: value.runtimeDirectory,
    stagingDirectory: value.stagingDirectory,
    operationDirectory: value.operationDirectory,
  });
}

export function runtimeRecoveryProofDigest(input) {
  const proof = canonicalRecoveryProof(input);
  return createHash('sha256')
    .update('AGENT_ROAD_RUNTIME_RECOVERY_PROOF_V1\0', 'utf8')
    .update(JSON.stringify(proof), 'utf8')
    .digest('hex')
    .toUpperCase();
}

function validateRoot(root) {
  if (
    typeof root !== 'string'
    || root.length === 0
    || Buffer.byteLength(root, 'utf8') > 4_096
    || !isAbsolute(root)
    || resolve(root) !== root
    || /[\r\n\x00-\x1f\x7f]/u.test(root)
  ) fail('RUNTIME_INPUT_INVALID');
  return root;
}

function canonicalNow(now) {
  let value;
  let milliseconds;
  try {
    value = now();
    if (
      !(value instanceof Date)
      || isProxy(value)
      || Object.getPrototypeOf(value) !== Date.prototype
      || Object.getOwnPropertyNames(value).length !== 0
      || Object.getOwnPropertySymbols(value).length !== 0
    ) fail('RUNTIME_INTERNAL_ERROR', Error);
    milliseconds = Date.prototype.getTime.call(value);
  } catch {
    fail('RUNTIME_INTERNAL_ERROR', Error);
  }
  if (Number.isNaN(milliseconds)) {
    fail('RUNTIME_INTERNAL_ERROR', Error);
  }
  try {
    return new Date(milliseconds).toISOString();
  } catch {
    fail('RUNTIME_INTERNAL_ERROR', Error);
  }
}

function recoveryStoreOptions(input) {
  if (input === undefined) {
    return Object.freeze({ now: () => new Date(), randomBytes: cryptoRandomBytes });
  }
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail('RUNTIME_INPUT_INVALID');
  const allowed = new Set(['now', 'randomBytes']);
  const values = Object.create(null);
  for (const name of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (
      !allowed.has(name)
      || !descriptor
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) fail('RUNTIME_INPUT_INVALID');
    values[name] = descriptor.value;
  }
  const now = Object.hasOwn(values, 'now') ? values.now : () => new Date();
  const randomBytes = Object.hasOwn(values, 'randomBytes')
    ? values.randomBytes
    : cryptoRandomBytes;
  if (typeof now !== 'function' || typeof randomBytes !== 'function') {
    fail('RUNTIME_INPUT_INVALID');
  }
  return Object.freeze({ now, randomBytes });
}

function canonicalBootObservation(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactObject(input, BOOT_OBSERVATION_FIELDS, code);
  const failedState = canonicalRecoveryState(value.failedState, code);
  const bootMarker = (() => {
    try {
      return validateRuntimeRecoveryBootMarker(value.bootMarker);
    } catch {
      fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    }
  })();
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'BOOT_OBSERVATION'
    || value.deviceId !== failedState.deviceId
    || value.operationId !== failedState.operationId
    || value.failedStateDigest !== runtimeRecoveryStateDigest(failedState)
    || !canonicalTimestamp(value.observedAt)
    || Date.parse(value.observedAt) < Date.parse(failedState.updatedAt)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return Object.freeze({
    schemaVersion: 1,
    recordType: 'BOOT_OBSERVATION',
    deviceId: value.deviceId,
    operationId: value.operationId,
    failedState,
    failedStateDigest: value.failedStateDigest,
    bootMarker,
    observedAt: value.observedAt,
  });
}

function sameRecord(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function effectiveUid() {
  return typeof process.geteuid === 'function' ? BigInt(process.geteuid()) : null;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameDirectoryMetadata(left, right) {
  return sameIdentity(left, right)
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

function sameFileMetadata(left, right) {
  return sameIdentity(left, right)
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sameFileEndpoint(left, right) {
  return sameIdentity(left, right)
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
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

function safeOwnerOnlyFileEndpoint(stats, allowedLinks = [1n]) {
  return stats.isFile()
    && !stats.isSymbolicLink()
    && allowedLinks.includes(stats.nlink)
    && (stats.mode & 0o777n) === BigInt(FILE_MODE)
    && (effectiveUid() === null || stats.uid === effectiveUid());
}

function assertSafeFile(stats, allowedLinks = [1n]) {
  if (
    !safeOwnerOnlyFileEndpoint(stats, allowedLinks)
    || stats.size < 1n
    || stats.size > BigInt(MAX_RECORD_BYTES)
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
}

async function maybeLstat(path) {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
}

async function assertCanonicalPath(path) {
  let canonical;
  try {
    canonical = await realpath(path);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  if (canonical !== path) fail('RUNTIME_STATE_UNSUPPORTED', Error);
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

async function assertSafeDirectoryPath(path, expected = null) {
  let before;
  try {
    before = await lstat(path, { bigint: true });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  assertSafeDirectory(before);
  if (expected !== null && !sameIdentity(before, expected)) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  await assertNoDarwinExtendedAcl(path);
  await assertCanonicalPath(path);
  await assertNoDarwinExtendedAcl(path);
  let after;
  try {
    after = await lstat(path, { bigint: true });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  assertSafeDirectory(after);
  if (!sameDirectoryMetadata(before, after)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return after;
}

async function assertSafeFilePath(path, expected = null, allowedLinks = [1n]) {
  let before;
  try {
    before = await lstat(path, { bigint: true });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  assertSafeFile(before, allowedLinks);
  if (expected !== null && !sameIdentity(before, expected)) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  await assertNoDarwinExtendedAcl(path);
  await assertCanonicalPath(path);
  await assertNoDarwinExtendedAcl(path);
  let after;
  try {
    after = await lstat(path, { bigint: true });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  assertSafeFile(after, allowedLinks);
  if (!sameFileMetadata(before, after)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return after;
}

function assertSafeLockFile(stats) {
  if (!safeOwnerOnlyFileEndpoint(stats, [1n]) || stats.size !== 0n) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
}

async function assertSafeLockFilePath(path, expected = null) {
  let before;
  try {
    before = await lstat(path, { bigint: true });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  assertSafeLockFile(before);
  if (expected !== null && !sameIdentity(before, expected)) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  await assertNoDarwinExtendedAcl(path);
  await assertCanonicalPath(path);
  await assertNoDarwinExtendedAcl(path);
  let after;
  try {
    after = await lstat(path, { bigint: true });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  assertSafeLockFile(after);
  if (!sameFileMetadata(before, after)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return after;
}

async function assertOptionalSafeLockFile(path) {
  const initial = await maybeLstat(path);
  if (initial === null) return null;
  return assertSafeLockFilePath(path, initial);
}

async function assertTrustedAncestorPath(path) {
  let before;
  try {
    before = await lstat(path, { bigint: true });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  assertTrustedAncestor(before);
  await assertNoDarwinExtendedAcl(path);
  await assertCanonicalPath(path);
  await assertNoDarwinExtendedAcl(path);
  let after;
  try {
    after = await lstat(path, { bigint: true });
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  assertTrustedAncestor(after);
  if (!sameDirectoryMetadata(before, after)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return after;
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

async function ensureSafeDirectoryChain(path) {
  const { current, missing } = await findExistingAncestor(path);
  let parent = current;
  await assertTrustedAncestorPath(parent);
  for (const directory of [...missing].reverse()) {
    try {
      await mkdir(directory, { mode: DIRECTORY_MODE });
    } catch (error) {
      if (error?.code !== 'EEXIST') fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const child = await assertSafeDirectoryPath(directory);
    await syncVerifiedDirectory(directory, child, false);
    await syncVerifiedDirectory(parent, null, true);
    parent = directory;
  }
  const stable = await assertSafeDirectoryPath(path);
  await syncVerifiedDirectory(path, stable, false);
  const pathParent = dirname(path);
  if (pathParent !== path) await syncVerifiedDirectory(pathParent, null, true);
  return assertSafeDirectoryPath(path, stable);
}

async function assertManagedDirectoryChain(root, path) {
  const directories = [];
  let current = path;
  while (current !== root) {
    directories.push(current);
    const parent = dirname(current);
    if (parent === current || current.length <= root.length) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    current = parent;
  }
  directories.push(root);
  for (const directory of directories.reverse()) await assertSafeDirectoryPath(directory);
}

async function ensureManagedDirectoryChain(root, path) {
  await ensureSafeDirectoryChain(root);
  const directories = [];
  let current = path;
  while (current !== root) {
    directories.push(current);
    const parent = dirname(current);
    if (parent === current || current.length <= root.length) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    current = parent;
  }
  let parent = root;
  for (const directory of directories.reverse()) {
    const observed = await maybeLstat(directory);
    if (observed === null) {
      try {
        await mkdir(directory, { mode: DIRECTORY_MODE });
      } catch (error) {
        if (error?.code !== 'EEXIST') fail('RUNTIME_STATE_UNSUPPORTED', Error);
      }
    }
    const child = await assertSafeDirectoryPath(directory);
    await syncVerifiedDirectory(directory, child, false);
    await syncVerifiedDirectory(parent, null, false);
    parent = directory;
  }
  await assertManagedDirectoryChain(root, path);
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

async function readStableBytes(path, allowedLinks = [1n]) {
  let file;
  let primary;
  let bytes;
  try {
    const initial = await assertSafeFilePath(path, null, allowedLinks);
    await runRecoveryTestHook('afterRecordAclCheck', { path });
    file = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await file.stat({ bigint: true });
    const pathBefore = await lstat(path, { bigint: true });
    assertSafeFile(before, allowedLinks);
    assertSafeFile(pathBefore, allowedLinks);
    if (!sameFileMetadata(initial, before) || !sameFileMetadata(before, pathBefore)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const size = Number(before.size);
    const first = await readExact(file, size);
    await file.sync();
    const middle = await file.stat({ bigint: true });
    const second = await readExact(file, size);
    const after = await file.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (
      !sameFileMetadata(before, middle)
      || !sameFileMetadata(middle, after)
      || !sameFileMetadata(after, pathAfter)
      || !first.equals(second)
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    bytes = first;
  } catch (error) {
    primary = error;
  } finally {
    try { await file?.close(); } catch (error) { primary ??= error; }
  }
  if (primary !== undefined) {
    if (OWN_ERRORS.has(primary)) throw primary;
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  return bytes;
}

function canonicalTicket(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactObject(input, TICKET_FIELDS, code);
  const failedState = canonicalRecoveryState(value.failedState, code);
  const authorizationParent = canonicalAuthorizationParent(value.authorizationParent, code);
  let proof;
  try {
    proof = canonicalRecoveryProof(value.proof, code);
  } catch {
    fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  if (!canonicalTimestamp(value.inspectedAt) || !canonicalTimestamp(value.expiresAt)) {
    fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  const inspectedAtMs = Date.parse(value.inspectedAt);
  const expiresAtMs = Date.parse(value.expiresAt);
  if (
    value.schemaVersion !== 2
    || value.recordType !== 'RECOVERY_TICKET'
    || typeof value.ticketId !== 'string'
    || !TICKET_ID_PATTERN.test(value.ticketId)
    || value.deviceId !== failedState.deviceId
    || value.operationId !== failedState.operationId
    || authorizationParent.deviceId !== failedState.deviceId
    || authorizationParent.operationId !== failedState.operationId
    || authorizationParent.failedStateDigest !== runtimeRecoveryStateDigest(failedState)
    || value.authorizationParentDigest
      !== runtimeRecoveryAuthorizationParentDigest(authorizationParent)
    || value.failedStateDigest !== runtimeRecoveryStateDigest(failedState)
    || proof.deviceId !== failedState.deviceId
    || proof.failedStateDigest !== value.failedStateDigest
    || proof.operationId !== failedState.operationId
    || proof.manifestDigest !== failedState.manifestDigest
    || proof.generationDigest !== failedState.generationDigest
    || value.proofDigest !== runtimeRecoveryProofDigest(proof)
    || inspectedAtMs < Date.parse(failedState.updatedAt)
    || expiresAtMs - inspectedAtMs !== TICKET_TTL_MS
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return Object.freeze({
    schemaVersion: 2,
    recordType: 'RECOVERY_TICKET',
    ticketId: value.ticketId,
    deviceId: value.deviceId,
    operationId: value.operationId,
    authorizationParent,
    authorizationParentDigest: value.authorizationParentDigest,
    failedState,
    failedStateDigest: value.failedStateDigest,
    proof,
    proofDigest: value.proofDigest,
    inspectedAt: value.inspectedAt,
    expiresAt: value.expiresAt,
  });
}

export function runtimeRecoveryTicketDigest(input) {
  const ticket = canonicalTicket(input);
  return createHash('sha256')
    .update('AGENT_ROAD_RUNTIME_RECOVERY_TICKET_V2\0', 'utf8')
    .update(JSON.stringify(ticket), 'utf8')
    .digest('hex')
    .toUpperCase();
}

function canonicalAuthorizationSuccessor(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactObject(input, AUTHORIZATION_SUCCESSOR_FIELDS, code);
  const authorizationParent = canonicalAuthorizationParent(value.authorizationParent, code);
  const ticket = canonicalTicket(value.ticket, code);
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RECOVERY_AUTHORIZATION_SUCCESSOR'
    || value.deviceId !== authorizationParent.deviceId
    || value.operationId !== authorizationParent.operationId
    || value.authorizationParentDigest
      !== runtimeRecoveryAuthorizationParentDigest(authorizationParent)
    || !sameRecord(ticket.authorizationParent, authorizationParent)
    || ticket.authorizationParentDigest !== value.authorizationParentDigest
    || ticket.deviceId !== value.deviceId
    || ticket.operationId !== value.operationId
    || value.ticketDigest !== runtimeRecoveryTicketDigest(ticket)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return Object.freeze({
    schemaVersion: 1,
    recordType: 'RECOVERY_AUTHORIZATION_SUCCESSOR',
    deviceId: value.deviceId,
    operationId: value.operationId,
    authorizationParent,
    authorizationParentDigest: value.authorizationParentDigest,
    ticket,
    ticketDigest: value.ticketDigest,
  });
}

function canonicalAuthorizedDeleteAttempt(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactObject(input, ATTEMPT_FIELDS, code);
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'AUTHORIZED_DELETE_ATTEMPT'
    || typeof value.ticketId !== 'string'
    || !TICKET_ID_PATTERN.test(value.ticketId)
    || typeof value.deviceId !== 'string'
    || value.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || typeof value.ticketDigest !== 'string'
    || !DIGEST_PATTERN.test(value.ticketDigest)
    || typeof value.failedStateDigest !== 'string'
    || !DIGEST_PATTERN.test(value.failedStateDigest)
    || typeof value.proofDigest !== 'string'
    || !DIGEST_PATTERN.test(value.proofDigest)
    || !['EMPTY_PRE_TRANSACTION', 'ALREADY_ABSENT'].includes(value.classification)
    || !canonicalTimestamp(value.authorizedAt)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return Object.freeze({
    schemaVersion: 1,
    recordType: 'AUTHORIZED_DELETE_ATTEMPT',
    ticketId: value.ticketId,
    deviceId: value.deviceId,
    operationId: value.operationId,
    ticketDigest: value.ticketDigest,
    failedStateDigest: value.failedStateDigest,
    proofDigest: value.proofDigest,
    classification: value.classification,
    authorizedAt: value.authorizedAt,
  });
}

export function runtimeRecoveryAuthorizedAttemptDigest(input) {
  const attempt = canonicalAuthorizedDeleteAttempt(input);
  return createHash('sha256')
    .update('AGENT_ROAD_RUNTIME_AUTHORIZED_DELETE_ATTEMPT_V1\0', 'utf8')
    .update(JSON.stringify(attempt), 'utf8')
    .digest('hex')
    .toUpperCase();
}

function canonicalRecoveryCommit(input, code = 'RUNTIME_INPUT_INVALID') {
  const value = readExactObject(input, COMMIT_FIELDS, code);
  const proposedRecoveredState = canonicalRecoveryState(value.proposedRecoveredState, code);
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RECOVERY_COMMIT'
    || typeof value.deviceId !== 'string'
    || value.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || typeof value.ticketId !== 'string'
    || !TICKET_ID_PATTERN.test(value.ticketId)
    || typeof value.authorizedAttemptDigest !== 'string'
    || !DIGEST_PATTERN.test(value.authorizedAttemptDigest)
    || typeof value.expectedFailedStateDigest !== 'string'
    || !DIGEST_PATTERN.test(value.expectedFailedStateDigest)
    || proposedRecoveredState.runtimeStatus !== 'RECOVERED'
    || proposedRecoveredState.deviceId !== value.deviceId
    || proposedRecoveredState.operationId !== value.operationId
    || typeof value.proposedRecoveredStateDigest !== 'string'
    || !DIGEST_PATTERN.test(value.proposedRecoveredStateDigest)
    || value.proposedRecoveredStateDigest !== runtimeRecoveryStateDigest(proposedRecoveredState)
    || typeof value.proofDigest !== 'string'
    || !DIGEST_PATTERN.test(value.proofDigest)
    || !['REMOVED', 'ALREADY_ABSENT'].includes(value.disposition)
    || !canonicalTimestamp(value.authorizedAt)
    || !canonicalTimestamp(value.committedAt)
    || Date.parse(value.committedAt) < Date.parse(value.authorizedAt)
    || Date.parse(proposedRecoveredState.updatedAt) < Date.parse(value.authorizedAt)
    || Date.parse(proposedRecoveredState.updatedAt) > Date.parse(value.committedAt)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return Object.freeze({
    schemaVersion: 1,
    recordType: 'RECOVERY_COMMIT',
    deviceId: value.deviceId,
    operationId: value.operationId,
    ticketId: value.ticketId,
    authorizedAttemptDigest: value.authorizedAttemptDigest,
    expectedFailedStateDigest: value.expectedFailedStateDigest,
    proposedRecoveredState,
    proposedRecoveredStateDigest: value.proposedRecoveredStateDigest,
    proofDigest: value.proofDigest,
    disposition: value.disposition,
    authorizedAt: value.authorizedAt,
    committedAt: value.committedAt,
  });
}

function assertRecoveryStatePair(expected, proposed, code = 'RUNTIME_INPUT_INVALID') {
  if (
    expected.runtimeStatus !== 'FAILED'
    || proposed.runtimeStatus !== 'RECOVERED'
    || expected.deviceId !== proposed.deviceId
    || expected.operationId !== proposed.operationId
    || expected.manifestDigest !== proposed.manifestDigest
    || expected.generationDigest !== proposed.generationDigest
    || !sameRecord(expected.requestedProfiles, proposed.requestedProfiles)
    || proposed.updatedAt <= expected.updatedAt
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
}

function assertRecoveryCommitMatchesRequest(commit, expected, proposed, input) {
  if (
    commit.deviceId !== expected.deviceId
    || commit.operationId !== expected.operationId
    || commit.ticketId !== input.ticketId
    || commit.expectedFailedStateDigest !== runtimeRecoveryStateDigest(expected)
    || !sameRecord(commit.proposedRecoveredState, proposed)
    || commit.proposedRecoveredStateDigest !== runtimeRecoveryStateDigest(proposed)
    || commit.proofDigest !== input.proofDigest
    || commit.disposition !== input.disposition
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return commit;
}

async function syncVerifiedDirectory(path, expected = null, trusted = false) {
  const before = trusted
    ? await assertTrustedAncestorPath(path)
    : await assertSafeDirectoryPath(path);
  if (expected !== null && !sameIdentity(before, expected)) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  let directory;
  let primary;
  try {
    directory = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const opened = await directory.stat({ bigint: true });
    if (trusted) assertTrustedAncestor(opened);
    else assertSafeDirectory(opened);
    if (!sameDirectoryMetadata(before, opened)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    await directory.sync();
    const afterSync = await directory.stat({ bigint: true });
    if (trusted) assertTrustedAncestor(afterSync);
    else assertSafeDirectory(afterSync);
    if (!sameDirectoryMetadata(opened, afterSync)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
  } catch (error) {
    primary = error;
  } finally {
    try { await directory?.close(); } catch (error) { primary ??= error; }
  }
  if (primary !== undefined) {
    if (OWN_ERRORS.has(primary)) throw primary;
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  const after = trusted
    ? await assertTrustedAncestorPath(path)
    : await assertSafeDirectoryPath(path);
  if (!sameDirectoryMetadata(before, after)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return after;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function deterministicRepairPublicationId(digest) {
  if (typeof digest !== 'string' || !DIGEST_PATTERN.test(digest)) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  const value = digest.toLowerCase();
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-4${value.slice(13, 16)}-a${value.slice(17, 20)}-${value.slice(20, 32)}`;
}

function requiresRetainedWitness(path) {
  return V2_RETAINED_WITNESS_DIRECTORIES.has(basename(dirname(path)));
}

function sameImmutablePublication(left, right) {
  return left.temporaryPath === right.temporaryPath
    && sameFileMetadata(left.finalStats, right.finalStats)
    && (
      left.temporaryStats === null
        ? right.temporaryStats === null
        : right.temporaryStats !== null
          && sameFileMetadata(left.temporaryStats, right.temporaryStats)
    );
}

async function inspectImmutablePublication(root, path, allowMissing = false) {
  const parent = dirname(path);
  await assertManagedDirectoryChain(root, parent);
  let entries;
  try {
    entries = await readdir(parent);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  await assertManagedDirectoryChain(root, parent);
  if (entries.length > 1_024) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  const finalName = basename(path);
  const foldedFinalName = finalName.toLowerCase();
  const relatedPrefix = `${finalName}.`;
  const foldedRelatedPrefix = relatedPrefix.toLowerCase();
  if (entries.some((name) => (
    name !== finalName
    && name.toLowerCase() === foldedFinalName
  ) || (
    !name.startsWith(relatedPrefix)
    && name.toLowerCase().startsWith(foldedRelatedPrefix)
  ))) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  const temporaryPattern = new RegExp(
    `^${escapeRegExp(finalName)}\\.[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.tmp$`,
    'u',
  );
  const lockName = `${finalName}.lock`;
  const related = entries.filter((name) => name.startsWith(`${finalName}.`));
  const temporaryNames = related.filter((name) => temporaryPattern.test(name));
  const permitsLock = finalName === 'recovery-commit.json';
  if (related.some((name) => !temporaryPattern.test(name) && !(permitsLock && name === lockName))) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  if (permitsLock && related.includes(lockName)) {
    await assertOptionalSafeLockFile(`${path}.lock`);
  }
  if (temporaryNames.length > 1) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  const finalStats = await maybeLstat(path);
  if (finalStats === null) {
    if (
      entries.includes(finalName)
      || temporaryNames.length !== 0
      || !allowMissing
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    return null;
  }
  if (!entries.includes(finalName)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  if (temporaryNames.length === 0) {
    if (requiresRetainedWitness(path)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    const stableFinal = await assertSafeFilePath(path, finalStats, [1n]);
    return Object.freeze({
      allowedLinks: Object.freeze([1n]),
      finalStats: stableFinal,
      temporaryPath: null,
      temporaryStats: null,
    });
  }
  const temporaryPath = joinPath(parent, temporaryNames[0]);
  const temporaryStats = await maybeLstat(temporaryPath);
  if (temporaryStats === null) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  const stableFinal = await assertSafeFilePath(path, finalStats, [2n]);
  const stableTemporary = await assertSafeFilePath(temporaryPath, temporaryStats, [2n]);
  if (
    !sameIdentity(stableFinal, stableTemporary)
    || !sameFileEndpoint(stableFinal, stableTemporary)
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return Object.freeze({
    allowedLinks: Object.freeze([2n]),
    finalStats: stableFinal,
    temporaryPath,
    temporaryStats: stableTemporary,
  });
}

async function inspectOptionalImmutablePublication(root, path) {
  const parent = dirname(path);
  if (await maybeLstat(parent) === null) {
    const grandparent = dirname(parent);
    await assertManagedDirectoryChain(root, grandparent);
    await runRecoveryTestHook('afterOptionalRecordParentMissing', { path });
    if (await maybeLstat(parent) === null) {
      await assertManagedDirectoryChain(root, grandparent);
      return null;
    }
  }
  return inspectImmutablePublication(root, path, true);
}

async function assertLegacyRecoveryNamespacesAbsent(root, paths) {
  await assertManagedDirectoryChain(root, paths.operation);
  for (const path of [paths.legacyTickets, paths.legacyAuthorizedDeleteAttempts]) {
    if (await maybeLstat(path) !== null) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  await runRecoveryTestHook('afterLegacyRecoveryNamespaceCheck', {
    operation: paths.operation,
  });
  await assertManagedDirectoryChain(root, paths.operation);
  for (const path of [paths.legacyTickets, paths.legacyAuthorizedDeleteAttempts]) {
    if (await maybeLstat(path) !== null) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  await assertManagedDirectoryChain(root, paths.operation);
}

async function publishImmutable(root, path, value, options = {}) {
  const {
    beforeLink = null,
    temporaryId = null,
  } = options;
  const content = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  if (content.length < 1 || content.length > MAX_RECORD_BYTES) fail('RUNTIME_INPUT_INVALID');
  await ensureManagedDirectoryChain(root, dirname(path));
  await assertManagedDirectoryChain(root, dirname(path));
  await runRecoveryTestHook('afterRecoveryLayoutCheck', { path: dirname(path) });
  await assertManagedDirectoryChain(root, dirname(path));
  if (await inspectImmutablePublication(root, path, true) !== null) {
    fail('RUNTIME_ALREADY_RUNNING', Error);
  }
  const publicationId = temporaryId ?? randomUUID();
  if (!IMMUTABLE_TEMPORARY_ID_PATTERN.test(publicationId)) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  const temporaryPath = `${path}.${publicationId}.tmp`;
  let file;
  try {
    file = await open(
      temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      FILE_MODE,
    );
    await file.writeFile(content);
    await file.sync();
    const created = await file.stat({ bigint: true });
    const createdPath = await lstat(temporaryPath, { bigint: true });
    assertSafeFile(created);
    assertSafeFile(createdPath);
    if (
      !sameFileMetadata(created, createdPath)
      || created.size !== BigInt(content.length)
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    await assertNoDarwinExtendedAcl(temporaryPath);
    await file.close();
    file = undefined;
    await runRecoveryTestHook('afterTemporarySyncBeforePublish', {
      path,
      temporaryPath,
    });
    const stableTemporaryBeforeLink = await assertSafeFilePath(temporaryPath, created);
    if (!sameFileMetadata(stableTemporaryBeforeLink, created)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    await assertManagedDirectoryChain(root, dirname(path));
    if (beforeLink !== null) {
      if (typeof beforeLink !== 'function') fail('RUNTIME_STATE_UNSUPPORTED', Error);
      await beforeLink();
    }
    try {
      await link(temporaryPath, path);
    } catch (error) {
      if (error?.code === 'EEXIST') fail('RUNTIME_ALREADY_RUNNING', Error);
      throw error;
    }
    const linkedTemporary = await lstat(temporaryPath, { bigint: true });
    const linkedFinal = await lstat(path, { bigint: true });
    assertSafeFile(linkedTemporary, [2n]);
    assertSafeFile(linkedFinal, [2n]);
    if (
      !sameFileEndpoint(linkedTemporary, created)
      || !sameFileEndpoint(linkedFinal, created)
      || !sameIdentity(linkedTemporary, linkedFinal)
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    await assertNoDarwinExtendedAcl(temporaryPath);
    await assertNoDarwinExtendedAcl(path);
    await runRecoveryTestHook('afterPublishLinkBeforeDirectorySync', {
      path,
      temporaryPath,
    });
    await syncVerifiedDirectory(dirname(path), null, false);
    await runRecoveryTestHook('afterPublishDirectorySync', {
      path,
      temporaryPath,
    });
    const publication = await inspectImmutablePublication(root, path);
    if (
      publication.temporaryPath !== temporaryPath
      || publication.temporaryStats === null
      || !sameFileEndpoint(publication.finalStats, created)
      || !sameFileEndpoint(publication.temporaryStats, created)
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    await assertManagedDirectoryChain(root, dirname(path));
    await runRecoveryTestHook('afterImmutablePublicationValidation', { path });
    const validated = await inspectImmutablePublication(root, path);
    if (!sameImmutablePublication(publication, validated)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    await assertManagedDirectoryChain(root, dirname(path));
  } finally {
    try { await file?.close(); } catch {}
  }
}

async function readCanonicalRecord(root, path, validator) {
  const before = await inspectImmutablePublication(root, path);
  const bytes = await readStableBytes(path, before.allowedLinks);
  const parent = dirname(path);
  await assertManagedDirectoryChain(root, parent);
  await syncVerifiedDirectory(parent, null, false);
  await runRecoveryTestHook('afterImmutableReadDirectorySync', { path });
  await assertManagedDirectoryChain(root, parent);
  const stabilized = await inspectImmutablePublication(root, path);
  if (!sameImmutablePublication(before, stabilized)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  const confirmed = await readStableBytes(path, stabilized.allowedLinks);
  const after = await inspectImmutablePublication(root, path);
  if (
    !bytes.equals(confirmed)
    || !sameImmutablePublication(stabilized, after)
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  const value = validator(parsed, 'RUNTIME_STATE_UNSUPPORTED');
  if (text !== `${JSON.stringify(value, null, 2)}\n`) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return value;
}

function assertAttemptMatchesTicket(ticket, attempt, code = 'RUNTIME_STATE_UNSUPPORTED') {
  if (
    attempt.ticketId !== ticket.ticketId
    || attempt.deviceId !== ticket.deviceId
    || attempt.operationId !== ticket.operationId
    || attempt.ticketDigest !== runtimeRecoveryTicketDigest(ticket)
    || attempt.failedStateDigest !== ticket.failedStateDigest
    || attempt.proofDigest !== ticket.proofDigest
    || attempt.classification !== ticket.proof.classification
    || Date.parse(attempt.authorizedAt) < Date.parse(ticket.inspectedAt)
    || Date.parse(attempt.authorizedAt) >= Date.parse(ticket.expiresAt)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return attempt;
}

function assertDispositionMatchesClassification(classification, disposition, code) {
  if (
    (classification === 'EMPTY_PRE_TRANSACTION' && disposition !== 'REMOVED')
    || (classification === 'ALREADY_ABSENT' && disposition !== 'ALREADY_ABSENT')
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
}

function assertRecordPathIds(record, expected, code = 'RUNTIME_STATE_UNSUPPORTED') {
  if (
    record.deviceId !== expected.deviceId
    || record.operationId !== expected.operationId
    || (
      Object.hasOwn(expected, 'ticketId')
      && record.ticketId !== expected.ticketId
    )
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return record;
}

function assertTicketMatchesObservation(ticket, observation, code = 'RUNTIME_STATE_UNSUPPORTED') {
  if (
    observation.deviceId !== ticket.deviceId
    || observation.operationId !== ticket.operationId
    || !sameRecord(observation.failedState, ticket.failedState)
    || !sameRecord(observation.bootMarker, ticket.proof.beforeBootMarker)
    || Date.parse(ticket.inspectedAt) < Date.parse(observation.observedAt)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return ticket;
}

function successorPathForParent(root, parent) {
  return runtimeRecoveryAuthorizationSuccessorPath(
    root,
    parent.deviceId,
    parent.operationId,
    runtimeRecoveryAuthorizationParentDigest(parent),
  );
}

function assertSuccessorMatchesTicket(successor, ticket, code = 'RUNTIME_STATE_UNSUPPORTED') {
  if (
    successor.deviceId !== ticket.deviceId
    || successor.operationId !== ticket.operationId
    || !sameRecord(successor.authorizationParent, ticket.authorizationParent)
    || successor.authorizationParentDigest !== ticket.authorizationParentDigest
    || !sameRecord(successor.ticket, ticket)
    || successor.ticketDigest !== runtimeRecoveryTicketDigest(ticket)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return successor;
}

async function readAuthorizationSuccessor(root, parent) {
  const path = successorPathForParent(root, parent);
  const successor = await readCanonicalRecord(root, path, canonicalAuthorizationSuccessor);
  if (
    !sameRecord(successor.authorizationParent, parent)
    || successor.authorizationParentDigest !== runtimeRecoveryAuthorizationParentDigest(parent)
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return successor;
}

async function readOptionalAuthorizationSuccessor(root, parent) {
  const path = successorPathForParent(root, parent);
  if (await inspectOptionalImmutablePublication(root, path) === null) return null;
  return readAuthorizationSuccessor(root, parent);
}

async function readOptionalAttemptForTicket(root, ticket, code = 'RUNTIME_STATE_UNSUPPORTED') {
  const paths = runtimeDeviceRecoveryPaths(
    root,
    ticket.deviceId,
    ticket.operationId,
    ticket.ticketId,
  );
  if (await inspectOptionalImmutablePublication(root, paths.authorizedDeleteAttempt) === null) {
    return null;
  }
  const attempt = await readCanonicalRecord(
    root,
    paths.authorizedDeleteAttempt,
    canonicalAuthorizedDeleteAttempt,
  );
  assertRecordPathIds(attempt, ticket, code);
  return assertAttemptMatchesTicket(ticket, attempt, code);
}

function expectedDeletionProvenance(parentTicket, parentAttempt) {
  if (parentTicket.proof.classification === 'EMPTY_PRE_TRANSACTION') {
    if (parentAttempt === null) return null;
    return Object.freeze({
      ticketId: parentTicket.ticketId,
      attemptDigest: runtimeRecoveryAuthorizedAttemptDigest(parentAttempt),
    });
  }
  return parentTicket.proof.priorAuthorizedAttempt;
}

async function verifyAuthorizationParent(
  root,
  parent,
  proof,
  failedState,
  currentInspectedAt,
  code = 'RUNTIME_STATE_UNSUPPORTED',
  seen = new Set(),
) {
  if (
    parent.deviceId !== failedState.deviceId
    || parent.operationId !== failedState.operationId
    || parent.failedStateDigest !== runtimeRecoveryStateDigest(failedState)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  if (parent.kind === 'GENESIS') {
    if (proof.classification !== 'EMPTY_PRE_TRANSACTION' || proof.priorAuthorizedAttempt !== null) {
      fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    }
    return null;
  }
  const expected = Object.freeze({
    deviceId: parent.deviceId,
    operationId: parent.operationId,
    ticketId: parent.ticketId,
  });
  const parentTicket = await readValidatedTicket(root, expected, code, seen);
  if (
    parent.ticketDigest !== runtimeRecoveryTicketDigest(parentTicket)
    || !sameRecord(parentTicket.failedState, failedState)
    || parentTicket.proof.targetBindingDigest !== proof.targetBindingDigest
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  const parentAttempt = await readOptionalAttemptForTicket(root, parentTicket, code);
  if (parent.kind === 'EXPIRED_TICKET') {
    if (
      parentAttempt !== null
      || Date.parse(currentInspectedAt) < Date.parse(parentTicket.expiresAt)
    ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  } else if (
    parentAttempt === null
    || parent.attemptDigest !== runtimeRecoveryAuthorizedAttemptDigest(parentAttempt)
    || Date.parse(parentAttempt.authorizedAt) > Date.parse(currentInspectedAt)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  const provenance = expectedDeletionProvenance(parentTicket, parentAttempt);
  if (
    proof.classification === 'EMPTY_PRE_TRANSACTION'
      ? proof.priorAuthorizedAttempt !== null
      : provenance === null || !sameRecord(proof.priorAuthorizedAttempt, provenance)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  return Object.freeze({ parentTicket, parentAttempt });
}

async function readValidatedTicket(
  root,
  expected,
  code = 'RUNTIME_STATE_UNSUPPORTED',
  seen = new Set(),
) {
  const key = `${expected.deviceId}:${expected.operationId}:${expected.ticketId}`;
  if (seen.has(key) || seen.size >= 64) {
    fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  const nextSeen = new Set(seen);
  nextSeen.add(key);
  const paths = runtimeDeviceRecoveryPaths(
    root,
    expected.deviceId,
    expected.operationId,
    expected.ticketId,
  );
  await assertLegacyRecoveryNamespacesAbsent(root, paths);
  const ticket = await readCanonicalRecord(root, paths.ticket, canonicalTicket);
  assertRecordPathIds(ticket, expected, code);
  const successor = await readAuthorizationSuccessor(root, ticket.authorizationParent);
  assertSuccessorMatchesTicket(successor, ticket, code);
  const observation = await readValidatedBootObservation(root, {
    deviceId: expected.deviceId,
    operationId: expected.operationId,
  }, code);
  assertTicketMatchesObservation(ticket, observation, code);
  await verifyAuthorizationParent(
    root,
    ticket.authorizationParent,
    ticket.proof,
    ticket.failedState,
    ticket.inspectedAt,
    code,
    nextSeen,
  );
  return ticket;
}

async function readValidatedBootObservation(
  root,
  expected,
  code = 'RUNTIME_STATE_UNSUPPORTED',
) {
  const paths = runtimeDeviceRecoveryPaths(root, expected.deviceId, expected.operationId);
  const observation = await readCanonicalRecord(
    root,
    paths.bootObservation,
    canonicalBootObservation,
  );
  return assertRecordPathIds(observation, expected, code);
}

async function inspectAttemptPublication(root, paths, ticket) {
  await ensureManagedDirectoryChain(root, paths.authorizedDeleteAttempts);
  await assertManagedDirectoryChain(root, paths.authorizedDeleteAttempts);
  if (await inspectImmutablePublication(root, paths.authorizedDeleteAttempt, true) === null) {
    return false;
  }
  const attempt = await readCanonicalRecord(
    root,
    paths.authorizedDeleteAttempt,
    canonicalAuthorizedDeleteAttempt,
  );
  assertAttemptMatchesTicket(ticket, attempt);
  return true;
}

async function withMappedErrors(operation, preserveError = null) {
  try {
    return await operation();
  } catch (error) {
    if (preserveError !== null && preserveError(error)) throw error;
    if (OWN_ERRORS.has(error)) throw error;
    let message = null;
    if (error !== null && (typeof error === 'object' || typeof error === 'function')) {
      try {
        const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
        if (descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string') {
          message = descriptor.value;
        }
      } catch {}
    }
    if (message?.startsWith('runtime recovery is locked:')) {
      throw runtimeError('RUNTIME_ALREADY_RUNNING');
    }
    throw runtimeError('RUNTIME_INTERNAL_ERROR');
  }
}

async function openRecoveryLockAnchor(root, path) {
  let file;
  let primary;
  try {
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
      file = await open(
        path,
        constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
    }
    const opened = await file.stat({ bigint: true });
    assertSafeLockFile(opened);
    const initialPath = await assertSafeLockFilePath(path, opened);
    if (!sameFileMetadata(opened, initialPath)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    await file.sync();
    await syncVerifiedDirectory(dirname(path), null, false);
    const synced = await file.stat({ bigint: true });
    const syncedPath = await assertSafeLockFilePath(path, opened);
    assertSafeLockFile(synced);
    if (
      !sameFileMetadata(opened, synced)
      || !sameFileMetadata(synced, syncedPath)
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    await assertManagedDirectoryChain(root, dirname(path));
    return { file, stats: synced };
  } catch (error) {
    primary = error;
  }
  try { await file?.close(); } catch (error) { primary ??= error; }
  if (OWN_ERRORS.has(primary)) throw primary;
  fail('RUNTIME_STATE_UNSUPPORTED', Error);
}

async function acquireRecoveryKernelLock(file, waitSeconds = LOCKF_DEFAULT_WAIT_SECONDS) {
  if (process.platform !== 'darwin') fail('RUNTIME_STATE_UNSUPPORTED', Error);
  await new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let outputLength = 0;
    let outputInvalid = false;
    let timedOut = false;
    let timer;
    const child = spawn('/usr/bin/lockf', ['-s', '-t', String(waitSeconds), '3'], {
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
        return;
      }
      if (code === LOCKF_TEMPFAIL) {
        settle(runtimeError('RUNTIME_ALREADY_RUNNING'));
        return;
      }
      if (code !== 0) {
        settle(runtimeError('RUNTIME_STATE_UNSUPPORTED'));
        return;
      }
      settle();
    });
    timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, (waitSeconds * 1_000) + LOCKF_WATCHDOG_GRACE_MS);
    timer.unref();
  });
}

async function withRecoveryOperationLock(
  root,
  paths,
  operation,
  waitSeconds = LOCKF_DEFAULT_WAIT_SECONDS,
) {
  await ensureManagedDirectoryChain(root, paths.operation);
  await assertManagedDirectoryChain(root, paths.operation);
  const lockPath = `${paths.recoveryCommit}.lock`;
  await assertOptionalSafeLockFile(lockPath);
  const anchor = await openRecoveryLockAnchor(root, lockPath);
  let primary;
  let result;
  try {
    await acquireRecoveryKernelLock(anchor.file, waitSeconds);
    await assertManagedDirectoryChain(root, paths.operation);
    const lockedFile = await anchor.file.stat({ bigint: true });
    const lockedPath = await assertSafeLockFilePath(lockPath, anchor.stats);
    assertSafeLockFile(lockedFile);
    if (
      !sameFileMetadata(anchor.stats, lockedFile)
      || !sameFileMetadata(lockedFile, lockedPath)
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    await runRecoveryTestHook('afterRecoveryKernelLockAcquired', { path: lockPath });
    result = await operation();
  } catch (error) {
    primary = error;
  } finally {
    try { await anchor.file.close(); } catch (error) { primary ??= error; }
  }
  if (primary !== undefined) throw primary;
  return result;
}

export class RuntimeRecoveryStore {
  #root;
  #now;
  #randomBytes;

  constructor(runtimeDevicesRoot, options) {
    this.#root = validateRoot(runtimeDevicesRoot);
    const { now, randomBytes } = recoveryStoreOptions(options);
    this.#now = now;
    this.#randomBytes = randomBytes;
    Object.freeze(this);
  }

  #prepareBootObservation(input) {
    const value = readExactObject(input, BOOT_OBSERVATION_INPUT_FIELDS, 'RUNTIME_INPUT_INVALID');
    const failedState = canonicalRecoveryState(value.failedState);
    if (failedState.runtimeStatus !== 'FAILED' || value.deviceId !== failedState.deviceId) {
      fail('RUNTIME_INPUT_INVALID');
    }
    const observedAt = canonicalNow(this.#now);
    if (Date.parse(observedAt) < Date.parse(failedState.updatedAt)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const record = canonicalBootObservation({
      schemaVersion: 1,
      recordType: 'BOOT_OBSERVATION',
      deviceId: value.deviceId,
      operationId: failedState.operationId,
      failedState,
      failedStateDigest: runtimeRecoveryStateDigest(failedState),
      bootMarker: value.bootMarker,
      observedAt,
    });
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      record.deviceId,
      record.operationId,
    );
    return { paths, record };
  }

  async #createBootObservationUnderLock(prepared) {
    await publishImmutable(this.#root, prepared.paths.bootObservation, prepared.record);
    return this.#readBootObservationUnderLock({
      deviceId: prepared.record.deviceId,
      operationId: prepared.record.operationId,
    });
  }

  async createBootObservation(input) {
    const prepared = this.#prepareBootObservation(input);
    return withMappedErrors(() => withRecoveryOperationLock(
      this.#root,
      prepared.paths,
      () => this.#createBootObservationUnderLock(prepared),
    ));
  }

  async #readBootObservationUnderLock(value, allowMissing = false) {
    const paths = runtimeDeviceRecoveryPaths(this.#root, value.deviceId, value.operationId);
    if (
      allowMissing
      && await inspectOptionalImmutablePublication(this.#root, paths.bootObservation) === null
    ) return null;
    return readValidatedBootObservation(this.#root, value);
  }

  async readBootObservation(input) {
    const value = readExactObject(input, ['deviceId', 'operationId'], 'RUNTIME_INPUT_INVALID');
    runtimeDeviceRecoveryPaths(this.#root, value.deviceId, value.operationId);
    return withMappedErrors(() => this.#readBootObservationUnderLock(value));
  }

  #prepareTicket(input) {
    const value = readExactObject(input, TICKET_INPUT_FIELDS, 'RUNTIME_INPUT_INVALID');
    const failedState = canonicalRecoveryState(value.failedState);
    const authorizationParent = canonicalAuthorizationParent(value.authorizationParent);
    let proof;
    try {
      proof = canonicalRecoveryProof(value.proof);
    } catch {
      fail('RUNTIME_INPUT_INVALID');
    }
    if (
      failedState.runtimeStatus !== 'FAILED'
      || value.deviceId !== failedState.deviceId
      || proof.deviceId !== failedState.deviceId
      || proof.failedStateDigest !== runtimeRecoveryStateDigest(failedState)
      || proof.operationId !== failedState.operationId
      || proof.manifestDigest !== failedState.manifestDigest
      || proof.generationDigest !== failedState.generationDigest
      || authorizationParent.deviceId !== failedState.deviceId
      || authorizationParent.operationId !== failedState.operationId
      || authorizationParent.failedStateDigest !== runtimeRecoveryStateDigest(failedState)
    ) fail('RUNTIME_INPUT_INVALID');
    const operationPaths = runtimeDeviceRecoveryPaths(
      this.#root,
      failedState.deviceId,
      failedState.operationId,
    );
    return { authorizationParent, failedState, operationPaths, proof };
  }

  async #restoreResolvedSuccessorTicketUnderLock(authorizationParent, successor) {
    const confirmedSuccessor = await readAuthorizationSuccessor(
      this.#root,
      authorizationParent,
    );
    if (!sameRecord(confirmedSuccessor, successor)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const ticket = successor.ticket;
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      ticket.deviceId,
      ticket.operationId,
      ticket.ticketId,
    );
    const ticketPublication = await inspectOptionalImmutablePublication(
      this.#root,
      paths.ticket,
    );
    if (ticketPublication === null) {
      try {
        await publishImmutable(this.#root, paths.ticket, ticket, {
          beforeLink: () => assertLegacyRecoveryNamespacesAbsent(this.#root, paths),
          temporaryId: deterministicRepairPublicationId(runtimeRecoveryTicketDigest(ticket)),
        });
      } catch (error) {
        if (error?.code === 'RUNTIME_ALREADY_RUNNING') {
          fail('RUNTIME_STATE_UNSUPPORTED', Error);
        }
        throw error;
      }
    } else {
      const published = await readCanonicalRecord(
        this.#root,
        paths.ticket,
        canonicalTicket,
      );
      if (!sameRecord(published, ticket)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const resolved = await this.#readTicketUnderLock({
      deviceId: ticket.deviceId,
      operationId: ticket.operationId,
      ticketId: ticket.ticketId,
    });
    if (!sameRecord(resolved, ticket)) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    return resolved;
  }

  async #createTicketUnderLock(prepared) {
    const { authorizationParent, failedState, proof } = prepared;
    await assertLegacyRecoveryNamespacesAbsent(this.#root, prepared.operationPaths);
    const existingSuccessor = await readOptionalAuthorizationSuccessor(
      this.#root,
      authorizationParent,
    );
    if (existingSuccessor !== null) {
      return this.#restoreResolvedSuccessorTicketUnderLock(
        authorizationParent,
        existingSuccessor,
      );
    }
    const observation = await this.#readBootObservationUnderLock({
      deviceId: failedState.deviceId,
      operationId: failedState.operationId,
    });
    if (
      !sameRecord(observation.failedState, failedState)
      || !sameRecord(observation.bootMarker, proof.beforeBootMarker)
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    const inspectedAt = canonicalNow(this.#now);
    const inspectedAtMs = Date.parse(inspectedAt);
    if (inspectedAtMs < Date.parse(observation.observedAt)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    await verifyAuthorizationParent(
      this.#root,
      authorizationParent,
      proof,
      failedState,
      inspectedAt,
    );
    const entropy = this.#randomBytes(32);
    if (!Buffer.isBuffer(entropy) || entropy.length !== 32) {
      fail('RUNTIME_INTERNAL_ERROR', Error);
    }
    const ticketId = `rct_${entropy.toString('hex')}`;
    const record = canonicalTicket({
      schemaVersion: 2,
      recordType: 'RECOVERY_TICKET',
      ticketId,
      deviceId: failedState.deviceId,
      operationId: failedState.operationId,
      authorizationParent,
      authorizationParentDigest: runtimeRecoveryAuthorizationParentDigest(authorizationParent),
      failedState,
      failedStateDigest: runtimeRecoveryStateDigest(failedState),
      proof,
      proofDigest: runtimeRecoveryProofDigest(proof),
      inspectedAt,
      expiresAt: new Date(inspectedAtMs + TICKET_TTL_MS).toISOString(),
    });
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      record.deviceId,
      record.operationId,
      record.ticketId,
    );
    if (await inspectOptionalImmutablePublication(this.#root, paths.ticket) !== null) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const successor = canonicalAuthorizationSuccessor({
      schemaVersion: 1,
      recordType: 'RECOVERY_AUTHORIZATION_SUCCESSOR',
      deviceId: record.deviceId,
      operationId: record.operationId,
      authorizationParent,
      authorizationParentDigest: record.authorizationParentDigest,
      ticket: record,
      ticketDigest: runtimeRecoveryTicketDigest(record),
    });
    try {
      await publishImmutable(
        this.#root,
        successorPathForParent(this.#root, authorizationParent),
        successor,
        {
          beforeLink: () => assertLegacyRecoveryNamespacesAbsent(
            this.#root,
            prepared.operationPaths,
          ),
        },
      );
      await publishImmutable(this.#root, paths.ticket, record, {
        beforeLink: () => assertLegacyRecoveryNamespacesAbsent(this.#root, paths),
      });
    } catch (error) {
      if (error?.code === 'RUNTIME_ALREADY_RUNNING') {
        fail('RUNTIME_STATE_UNSUPPORTED', Error);
      }
      throw error;
    }
    return this.#readTicketUnderLock({
      deviceId: record.deviceId,
      operationId: record.operationId,
      ticketId: record.ticketId,
    });
  }

  async createTicket(input) {
    const prepared = this.#prepareTicket(input);
    return withMappedErrors(() => withRecoveryOperationLock(
      this.#root,
      prepared.operationPaths,
      () => this.#createTicketUnderLock(prepared),
      LOCKF_TICKET_COALESCE_WAIT_SECONDS,
    ));
  }

  #prepareAuthorizationSuccessor(input) {
    const authorizationParent = canonicalAuthorizationParent(input);
    const operationPaths = runtimeDeviceRecoveryPaths(
      this.#root,
      authorizationParent.deviceId,
      authorizationParent.operationId,
    );
    return { authorizationParent, operationPaths };
  }

  async #resolveAuthorizationSuccessorUnderLock(prepared) {
    await assertLegacyRecoveryNamespacesAbsent(this.#root, prepared.operationPaths);
    const successor = await readOptionalAuthorizationSuccessor(
      this.#root,
      prepared.authorizationParent,
    );
    if (successor === null) return null;
    await runRecoveryTestHook('afterAuthorizationSuccessorResolved', {
      path: successorPathForParent(this.#root, prepared.authorizationParent),
    });
    return this.#restoreResolvedSuccessorTicketUnderLock(
      prepared.authorizationParent,
      successor,
    );
  }

  async resolveAuthorizationSuccessor(input) {
    const prepared = this.#prepareAuthorizationSuccessor(input);
    return withMappedErrors(() => withRecoveryOperationLock(
      this.#root,
      prepared.operationPaths,
      () => this.#resolveAuthorizationSuccessorUnderLock(prepared),
    ));
  }

  async #readTicketUnderLock(value, missingCode = null) {
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      value.deviceId,
      value.operationId,
      value.ticketId,
    );
    if (
      missingCode !== null
      && await inspectOptionalImmutablePublication(this.#root, paths.ticket) === null
    ) fail(missingCode, missingCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    return readValidatedTicket(this.#root, value);
  }

  async readTicket(input) {
    const value = readExactObject(
      input,
      ['deviceId', 'operationId', 'ticketId'],
      'RUNTIME_INPUT_INVALID',
    );
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      value.deviceId,
      value.operationId,
      value.ticketId,
    );
    return withMappedErrors(() => withRecoveryOperationLock(
      this.#root,
      paths,
      () => this.#readTicketUnderLock(value),
    ));
  }

  #prepareConsumeTicket(input) {
    const value = readExactObject(
      input,
      CONSUME_TICKET_INPUT_FIELDS,
      'RUNTIME_INPUT_INVALID',
    );
    const failedState = canonicalRecoveryState(value.failedState);
    let proof;
    try {
      proof = canonicalRecoveryProof(value.proof);
    } catch {
      fail('RUNTIME_INPUT_INVALID');
    }
    if (
      failedState.runtimeStatus !== 'FAILED'
      || value.deviceId !== failedState.deviceId
      || value.operationId !== failedState.operationId
      || proof.deviceId !== failedState.deviceId
      || proof.failedStateDigest !== runtimeRecoveryStateDigest(failedState)
      || proof.operationId !== failedState.operationId
      || value.ticketId === undefined
    ) fail('RUNTIME_INPUT_INVALID');
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      value.deviceId,
      value.operationId,
      value.ticketId,
    );
    return { failedState, paths, proof, value };
  }

  async #consumeTicketUnderLock(prepared) {
    const { failedState, paths, proof, value } = prepared;
    const ticket = await this.#readTicketUnderLock(value);
    if (
      !sameRecord(ticket.failedState, failedState)
      || !sameRecord(ticket.proof, proof)
    ) fail('RUNTIME_INPUT_INVALID');
    const expiredParent = canonicalAuthorizationParent({
      schemaVersion: 1,
      kind: 'EXPIRED_TICKET',
      deviceId: ticket.deviceId,
      operationId: ticket.operationId,
      failedStateDigest: ticket.failedStateDigest,
      ticketId: ticket.ticketId,
      ticketDigest: runtimeRecoveryTicketDigest(ticket),
      attemptDigest: null,
    });
    if (await readOptionalAuthorizationSuccessor(this.#root, expiredParent) !== null) {
      fail('RUNTIME_INPUT_INVALID');
    }
    const authorizedAt = canonicalNow(this.#now);
    const authorizedAtMs = Date.parse(authorizedAt);
    if (authorizedAtMs < Date.parse(ticket.inspectedAt)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    if (authorizedAtMs >= Date.parse(ticket.expiresAt)) {
      fail('RUNTIME_INPUT_INVALID');
    }
    const attempt = canonicalAuthorizedDeleteAttempt({
      schemaVersion: 1,
      recordType: 'AUTHORIZED_DELETE_ATTEMPT',
      ticketId: ticket.ticketId,
      deviceId: ticket.deviceId,
      operationId: ticket.operationId,
      ticketDigest: runtimeRecoveryTicketDigest(ticket),
      failedStateDigest: ticket.failedStateDigest,
      proofDigest: ticket.proofDigest,
      classification: ticket.proof.classification,
      authorizedAt,
    });
    if (await inspectAttemptPublication(this.#root, paths, ticket)) {
      fail('RUNTIME_ALREADY_RUNNING', Error);
    }
    await assertLegacyRecoveryNamespacesAbsent(this.#root, paths);
    await publishImmutable(this.#root, paths.authorizedDeleteAttempt, attempt, {
      beforeLink: () => assertLegacyRecoveryNamespacesAbsent(this.#root, paths),
    });
    return this.#readAuthorizedDeleteAttemptUnderLock(value, 'RUNTIME_STATE_UNSUPPORTED');
  }

  async consumeTicket(input) {
    const prepared = this.#prepareConsumeTicket(input);
    return withMappedErrors(() => withRecoveryOperationLock(
      this.#root,
      prepared.paths,
      () => this.#consumeTicketUnderLock(prepared),
    ));
  }

  async #readAuthorizedDeleteAttemptUnderLock(
    value,
    missingCode = null,
    allowMissingAttempt = false,
  ) {
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      value.deviceId,
      value.operationId,
      value.ticketId,
    );
    const ticket = await this.#readTicketUnderLock(value, missingCode);
    const publication = await inspectOptionalImmutablePublication(
      this.#root,
      paths.authorizedDeleteAttempt,
    );
    if (publication === null) {
      if (allowMissingAttempt) return null;
      if (missingCode !== null) {
        fail(missingCode, missingCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
      }
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const attempt = await readCanonicalRecord(
      this.#root,
      paths.authorizedDeleteAttempt,
      canonicalAuthorizedDeleteAttempt,
    );
    assertRecordPathIds(attempt, value);
    return assertAttemptMatchesTicket(ticket, attempt);
  }

  async readAuthorizedDeleteAttempt(input) {
    const value = readExactObject(
      input,
      ['deviceId', 'operationId', 'ticketId'],
      'RUNTIME_INPUT_INVALID',
    );
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      value.deviceId,
      value.operationId,
      value.ticketId,
    );
    return withMappedErrors(() => withRecoveryOperationLock(
      this.#root,
      paths,
      () => this.#readAuthorizedDeleteAttemptUnderLock(value),
    ));
  }

  #prepareRecoveryCommit(input) {
    const value = readExactObject(input, COMMIT_INPUT_FIELDS, 'RUNTIME_INPUT_INVALID');
    const expected = canonicalRecoveryState(value.expectedFailedState);
    const proposed = canonicalRecoveryState(value.proposedRecoveredState);
    assertRecoveryStatePair(expected, proposed);
    if (
      typeof value.ticketId !== 'string'
      || !TICKET_ID_PATTERN.test(value.ticketId)
      || typeof value.proofDigest !== 'string'
      || !DIGEST_PATTERN.test(value.proofDigest)
      || !['REMOVED', 'ALREADY_ABSENT'].includes(value.disposition)
    ) fail('RUNTIME_INPUT_INVALID');
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      expected.deviceId,
      expected.operationId,
      value.ticketId,
    );
    return { expected, paths, proposed, value };
  }

  async #createRecoveryCommitUnderLock(prepared) {
    const { expected, paths, proposed, value } = prepared;
    const existing = await this.#readRecoveryCommitUnderLock({
      deviceId: expected.deviceId,
      operationId: expected.operationId,
    }, true);
    if (existing !== null) {
      return assertRecoveryCommitMatchesRequest(existing, expected, proposed, value);
    }
    const exact = {
      deviceId: expected.deviceId,
      operationId: expected.operationId,
      ticketId: value.ticketId,
    };
    const ticket = await this.#readTicketUnderLock(exact);
    const attempt = await this.#readAuthorizedDeleteAttemptUnderLock(exact);
    if (
      !sameRecord(ticket.failedState, expected)
      || value.proofDigest !== ticket.proofDigest
    ) fail('RUNTIME_INPUT_INVALID');
    assertDispositionMatchesClassification(
      ticket.proof.classification,
      value.disposition,
      'RUNTIME_INPUT_INVALID',
    );
    const committedAt = canonicalNow(this.#now);
    if (Date.parse(committedAt) < Date.parse(attempt.authorizedAt)) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const commit = canonicalRecoveryCommit({
      schemaVersion: 1,
      recordType: 'RECOVERY_COMMIT',
      deviceId: expected.deviceId,
      operationId: expected.operationId,
      ticketId: ticket.ticketId,
      authorizedAttemptDigest: runtimeRecoveryAuthorizedAttemptDigest(attempt),
      expectedFailedStateDigest: runtimeRecoveryStateDigest(expected),
      proposedRecoveredState: proposed,
      proposedRecoveredStateDigest: runtimeRecoveryStateDigest(proposed),
      proofDigest: ticket.proofDigest,
      disposition: value.disposition,
      authorizedAt: attempt.authorizedAt,
      committedAt,
    });
    try {
      await publishImmutable(this.#root, paths.recoveryCommit, commit, {
        beforeLink: () => assertLegacyRecoveryNamespacesAbsent(this.#root, paths),
      });
    } catch (error) {
      if (error?.code !== 'RUNTIME_ALREADY_RUNNING') throw error;
    }
    const saved = await this.#readRecoveryCommitUnderLock({
      deviceId: expected.deviceId,
      operationId: expected.operationId,
    });
    return assertRecoveryCommitMatchesRequest(saved, expected, proposed, value);
  }

  async createRecoveryCommit(input) {
    const prepared = this.#prepareRecoveryCommit(input);
    return withMappedErrors(() => withRecoveryOperationLock(
      this.#root,
      prepared.paths,
      () => this.#createRecoveryCommitUnderLock(prepared),
    ));
  }

  async #readRecoveryCommitUnderLock(value, allowMissing = false) {
    const operationPaths = runtimeDeviceRecoveryPaths(
      this.#root,
      value.deviceId,
      value.operationId,
    );
    await assertLegacyRecoveryNamespacesAbsent(this.#root, operationPaths);
    if (
      allowMissing
      && await inspectOptionalImmutablePublication(
        this.#root,
        operationPaths.recoveryCommit,
      ) === null
    ) return null;
    const commit = await readCanonicalRecord(
      this.#root,
      operationPaths.recoveryCommit,
      canonicalRecoveryCommit,
    );
    if (commit.deviceId !== value.deviceId || commit.operationId !== value.operationId) {
      fail('RUNTIME_STATE_UNSUPPORTED', Error);
    }
    const expected = {
      deviceId: commit.deviceId,
      operationId: commit.operationId,
      ticketId: commit.ticketId,
    };
    const ticket = await this.#readTicketUnderLock(expected);
    const attempt = await this.#readAuthorizedDeleteAttemptUnderLock(expected);
    assertRecoveryStatePair(
      ticket.failedState,
      commit.proposedRecoveredState,
      'RUNTIME_STATE_UNSUPPORTED',
    );
    if (
      commit.authorizedAttemptDigest !== runtimeRecoveryAuthorizedAttemptDigest(attempt)
      || commit.expectedFailedStateDigest !== ticket.failedStateDigest
      || commit.proofDigest !== ticket.proofDigest
      || commit.authorizedAt !== attempt.authorizedAt
    ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
    assertDispositionMatchesClassification(
      ticket.proof.classification,
      commit.disposition,
      'RUNTIME_STATE_UNSUPPORTED',
    );
    return commit;
  }

  async readRecoveryCommit(input) {
    const value = readExactObject(input, ['deviceId', 'operationId'], 'RUNTIME_INPUT_INVALID');
    const paths = runtimeDeviceRecoveryPaths(this.#root, value.deviceId, value.operationId);
    return withMappedErrors(() => withRecoveryOperationLock(
      this.#root,
      paths,
      () => this.#readRecoveryCommitUnderLock(value),
    ));
  }

  async withOperationLock(input, callback) {
    const value = readExactObject(input, ['deviceId', 'operationId'], 'RUNTIME_INPUT_INVALID');
    if (typeof callback !== 'function' || isProxy(callback)) fail('RUNTIME_INPUT_INVALID');
    const paths = runtimeDeviceRecoveryPaths(
      this.#root,
      value.deviceId,
      value.operationId,
    );
    const binding = Object.freeze({
      deviceId: value.deviceId,
      operationId: value.operationId,
    });
    let callbackFailed = false;
    let callbackFailure;
    return withMappedErrors(
      () => withRecoveryOperationLock(this.#root, paths, async () => {
        let active = true;
        let busy = false;
        const records = [];
        const assertBinding = (deviceId, operationId) => {
          if (deviceId !== binding.deviceId || operationId !== binding.operationId) {
            fail('RUNTIME_INPUT_INVALID');
          }
        };
        const rejectObserved = (error) => {
          const rejected = Promise.reject(error);
          void rejected.catch(() => {});
          return rejected;
        };
        const expose = (pending, releasesBusy) => {
          const record = {
            drain: null,
            failure: undefined,
            status: 'pending',
          };
          const exposed = pending.finally(() => {
            if (releasesBusy) busy = false;
          });
          record.drain = exposed.then(
            () => {
              record.status = 'fulfilled';
            },
            (error) => {
              record.failure = error;
              record.status = 'rejected';
            },
          );
          records.push(record);
          return exposed;
        };
        const invoke = (operation) => {
          if (!active) {
            return rejectObserved(runtimeError('RUNTIME_INPUT_INVALID', TypeError));
          }
          if (busy) {
            return expose(Promise.reject(runtimeError('RUNTIME_ALREADY_RUNNING')), false);
          }
          busy = true;
          return expose(withMappedErrors(operation), true);
        };
        const noArguments = (args, operation) => invoke(() => {
          if (args.length !== 0) fail('RUNTIME_INPUT_INVALID');
          return operation();
        });
        const oneInput = (args, operation) => invoke(() => {
          if (args.length !== 1) fail('RUNTIME_INPUT_INVALID');
          return operation(args[0]);
        });
        const facade = Object.create(null);
        Object.defineProperties(facade, {
          readBootObservation: {
            enumerable: true,
            value: (...args) => noArguments(
              args,
              () => this.#readBootObservationUnderLock(binding, true),
            ),
          },
          createBootObservation: {
            enumerable: true,
            value: (...args) => oneInput(args, (scopeInput) => {
              const prepared = this.#prepareBootObservation(scopeInput);
              assertBinding(prepared.record.deviceId, prepared.record.operationId);
              return this.#createBootObservationUnderLock(prepared);
            }),
          },
          createTicket: {
            enumerable: true,
            value: (...args) => oneInput(args, (scopeInput) => {
              const prepared = this.#prepareTicket(scopeInput);
              assertBinding(prepared.failedState.deviceId, prepared.failedState.operationId);
              return this.#createTicketUnderLock(prepared);
            }),
          },
          resolveAuthorizationSuccessor: {
            enumerable: true,
            value: (...args) => oneInput(args, (authorizationParent) => {
              const prepared = this.#prepareAuthorizationSuccessor(authorizationParent);
              assertBinding(
                prepared.authorizationParent.deviceId,
                prepared.authorizationParent.operationId,
              );
              return this.#resolveAuthorizationSuccessorUnderLock(prepared);
            }),
          },
          readTicket: {
            enumerable: true,
            value: (...args) => oneInput(args, (ticketId) => {
              const exact = { ...binding, ticketId };
              runtimeDeviceRecoveryPaths(
                this.#root,
                exact.deviceId,
                exact.operationId,
                exact.ticketId,
              );
              return this.#readTicketUnderLock(exact, 'RUNTIME_INPUT_INVALID');
            }),
          },
          readAuthorizedDeleteAttempt: {
            enumerable: true,
            value: (...args) => oneInput(args, (ticketId) => {
              const exact = { ...binding, ticketId };
              runtimeDeviceRecoveryPaths(
                this.#root,
                exact.deviceId,
                exact.operationId,
                exact.ticketId,
              );
              return this.#readAuthorizedDeleteAttemptUnderLock(
                exact,
                'RUNTIME_INPUT_INVALID',
                true,
              );
            }),
          },
          consumeTicket: {
            enumerable: true,
            value: (...args) => oneInput(args, (scopeInput) => {
              const prepared = this.#prepareConsumeTicket(scopeInput);
              assertBinding(prepared.value.deviceId, prepared.value.operationId);
              return this.#consumeTicketUnderLock(prepared);
            }),
          },
          readRecoveryCommit: {
            enumerable: true,
            value: (...args) => noArguments(
              args,
              () => this.#readRecoveryCommitUnderLock(binding, true),
            ),
          },
          createRecoveryCommit: {
            enumerable: true,
            value: (...args) => oneInput(args, (scopeInput) => {
              const prepared = this.#prepareRecoveryCommit(scopeInput);
              assertBinding(prepared.expected.deviceId, prepared.expected.operationId);
              return this.#createRecoveryCommitUnderLock(prepared);
            }),
          },
        });
        Object.freeze(facade);
        const heldReadContext = Object.freeze({
          root: this.#root,
          deviceId: binding.deviceId,
          operationId: binding.operationId,
          isActive: () => active,
          readRecoveryCommit: () => invoke(
            () => this.#readRecoveryCommitUnderLock(binding),
          ),
          readTicket: (ticketId) => invoke(() => this.#readTicketUnderLock({
            ...binding,
            ticketId,
          })),
        });
        let result;
        try {
          result = await RECOVERY_HELD_READ_CONTEXT.run(
            heldReadContext,
            () => callback(facade),
          );
        } catch (error) {
          callbackFailed = true;
          callbackFailure = error;
        } finally {
          active = false;
        }
        await Promise.all(records.map((record) => record.drain));
        if (!callbackFailed) {
          const failedRecord = records.find((record) => record.status === 'rejected');
          if (failedRecord !== undefined) {
            callbackFailed = true;
            callbackFailure = failedRecord.failure;
          }
        }
        if (callbackFailed) throw callbackFailure;
        return result;
      }),
      (error) => callbackFailed && error === callbackFailure,
    );
  }
}

export async function verifyRuntimeRecoveredState(input) {
  const value = readExactObject(
    input,
    ['runtimeDevicesRoot', 'proposedRecoveredState'],
    'RUNTIME_INPUT_INVALID',
  );
  const proposed = canonicalRecoveryState(value.proposedRecoveredState);
  if (proposed.runtimeStatus !== 'RECOVERED') fail('RUNTIME_INPUT_INVALID');
  const runtimeDevicesRoot = validateRoot(value.runtimeDevicesRoot);
  const heldReadContext = RECOVERY_HELD_READ_CONTEXT.getStore();
  if (heldReadContext !== undefined && (
    heldReadContext.root !== runtimeDevicesRoot
    || heldReadContext.deviceId !== proposed.deviceId
    || heldReadContext.operationId !== proposed.operationId
    || heldReadContext.isActive() !== true
  )) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  const store = heldReadContext === undefined
    ? new RuntimeRecoveryStore(runtimeDevicesRoot)
    : null;
  const commit = heldReadContext === undefined
    ? await store.readRecoveryCommit({
        deviceId: proposed.deviceId,
        operationId: proposed.operationId,
      })
    : await heldReadContext.readRecoveryCommit();
  if (
    !sameRecord(commit.proposedRecoveredState, proposed)
    || commit.proposedRecoveredStateDigest !== runtimeRecoveryStateDigest(proposed)
  ) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  const ticket = heldReadContext === undefined
    ? await store.readTicket({
        deviceId: commit.deviceId,
        operationId: commit.operationId,
        ticketId: commit.ticketId,
      })
    : await heldReadContext.readTicket(commit.ticketId);
  if (
    ticket.failedState.deviceId !== proposed.deviceId
    || ticket.failedState.operationId !== proposed.operationId
    || ticket.failedState.manifestDigest !== proposed.manifestDigest
    || ticket.failedState.generationDigest !== proposed.generationDigest
    || !sameRecord(ticket.failedState.requestedProfiles, proposed.requestedProfiles)
    || proposed.updatedAt <= ticket.failedState.updatedAt
  ) fail('RUNTIME_STATE_UNSUPPORTED', Error);
  return commit;
}

export async function verifyRuntimeRecoveryCommit(input) {
  const value = readExactObject(
    input,
    ['runtimeDevicesRoot', 'expectedFailedState', 'proposedRecoveredState'],
    'RUNTIME_INPUT_INVALID',
  );
  const expected = canonicalRecoveryState(value.expectedFailedState);
  const proposed = canonicalRecoveryState(value.proposedRecoveredState);
  assertRecoveryStatePair(expected, proposed);
  const commit = await verifyRuntimeRecoveredState({
    runtimeDevicesRoot: value.runtimeDevicesRoot,
    proposedRecoveredState: proposed,
  });
  if (commit.expectedFailedStateDigest !== runtimeRecoveryStateDigest(expected)) {
    fail('RUNTIME_STATE_UNSUPPORTED', Error);
  }
  return commit;
}

export const verifyRecoveredState = verifyRuntimeRecoveredState;


// Separate namespace and records: retention is not an empty-operation recovery
// ticket or a FAILED -> RECOVERED transition. Reuse the same kernel lock and
// immutable publication machinery so both protocols serialize per operation.
export class StagedRetentionStore {
  #root;
  #now;
  #held = new AsyncLocalStorage();

  constructor(runtimeDevicesRoot, options) {
    this.#root = validateRoot(runtimeDevicesRoot);
    this.#now = recoveryStoreOptions(options).now;
    Object.freeze(this);
  }

  #paths(input) {
    const binding = readExactObject(input, ['deviceId', 'operationId'], 'RUNTIME_INPUT_INVALID');
    const paths = runtimeDeviceRecoveryPaths(this.#root, binding.deviceId, binding.operationId);
    return Object.freeze({ ...paths, deviceId: binding.deviceId, operationId: binding.operationId,
      proposal: joinPath(paths.operation, 'staged-retention-v1', 'proposal.json'),
      attempt: joinPath(paths.operation, 'staged-retention-v1', 'attempt.json'),
      reconciliation: joinPath(paths.operation, 'staged-retention-v1', 'reconciliation.json'),
    });
  }

  async #optional(path, validator) {
    if (await inspectOptionalImmutablePublication(this.#root, path) === null) return null;
    return readCanonicalRecord(this.#root, path, validator);
  }

  async #read(paths) {
    const proposal = await this.#optional(paths.proposal, validateStagedRetentionProposal);
    if (proposal !== null && (proposal.deviceId !== paths.deviceId || proposal.operationId !== paths.operationId)) {
      fail('RUNTIME_STATE_UNSUPPORTED');
    }
    const attempt = await this.#optional(paths.attempt, value => validateStagedRetentionAttempt(value, proposal));
    const reconciliation = await this.#optional(paths.reconciliation,
      value => validateStagedRetentionReconciliation(value, proposal, attempt));
    return Object.freeze({ proposal, attempt, reconciliation });
  }

  #locked(paths, operation) {
    const held = this.#held.getStore();
    if (held !== undefined) {
      if (!held.active || held.operation !== paths.operation) fail('RUNTIME_INPUT_INVALID');
      if (held.busy) fail('RUNTIME_ALREADY_RUNNING');
      held.busy = true;
      const pending = withMappedErrors(operation, isStagedRetentionProtocolError)
        .finally(() => { held.busy = false; });
      const record = { error: null, drain: null };
      record.drain = pending.then(() => {}, error => { record.error = error; });
      held.records.push(record);
      return pending;
    }
    return withMappedErrors(
      () => withRecoveryOperationLock(this.#root, paths, operation),
      isStagedRetentionProtocolError,
    );
  }

  async withOperationLock(binding, callback) {
    const paths = this.#paths(binding);
    if (typeof callback !== 'function' || isProxy(callback) || this.#held.getStore() !== undefined) {
      fail('RUNTIME_INPUT_INVALID');
    }
    return this.#locked(paths, async () => {
      const held = { active: true, busy: false, operation: paths.operation, records: [] };
      let result;
      let primary;
      try { result = await this.#held.run(held, callback); } catch (error) { primary = error; }
      held.active = false;
      await Promise.all(held.records.map(record => record.drain));
      primary ??= held.records.find(record => record.error !== null)?.error;
      if (primary !== undefined && primary !== null) throw primary;
      return result;
    });
  }

  async read(binding) {
    const paths = this.#paths(binding);
    return this.#locked(paths, () => this.#read(paths));
  }

  async propose(evidence) {
    const proposal = createStagedRetentionProposal(evidence, canonicalNow(this.#now));
    const paths = this.#paths({ deviceId: proposal.deviceId, operationId: proposal.operationId });
    return this.#locked(paths, async () => {
      const existing = await this.#read(paths);
      if (existing.proposal !== null) fail('RUNTIME_ALREADY_RUNNING');
      createStagedRetentionAttempt(proposal, proposal.evidence, canonicalNow(this.#now));
      await publishImmutable(this.#root, paths.proposal, proposal);
      return (await this.#read(paths)).proposal;
    });
  }

  async consume(binding, proposalDigest, currentEvidence) {
    const paths = this.#paths(binding);
    if (typeof proposalDigest !== 'string' || !DIGEST_PATTERN.test(proposalDigest)) fail('RUNTIME_INPUT_INVALID');
    // Capture caller data before waiting for the operation lock.
    const current = createStagedRetentionProposal(currentEvidence, canonicalNow(this.#now)).evidence;
    return this.#locked(paths, async () => {
      const { proposal, attempt: previous } = await this.#read(paths);
      if (previous !== null) fail('RUNTIME_ALREADY_RUNNING');
      if (proposal === null || proposal.proposalDigest !== proposalDigest) fail('RUNTIME_STATE_UNSUPPORTED');
      const attempt = createStagedRetentionAttempt(proposal, current, canonicalNow(this.#now));
      // Caller must not dispatch unless publication AND this independent reread
      // succeed. Uncertain publication never grants permission to retry.
      await publishImmutable(this.#root, paths.attempt, attempt);
      return (await this.#read(paths)).attempt;
    });
  }

  async reconcile(binding, observation) {
    const paths = this.#paths(binding);
    return this.#locked(paths, async () => {
      const { proposal, attempt, reconciliation } = await this.#read(paths);
      if (reconciliation !== null) fail('RUNTIME_ALREADY_RUNNING');
      const result = reconcileStagedRetention(proposal, attempt, observation, canonicalNow(this.#now));
      await publishImmutable(this.#root, paths.reconciliation, result);
      return (await this.#read(paths)).reconciliation;
    });
  }
}


// Read-only Windows confirmation has no dispatch attempt: this immutable commit
// is published before the one local CAS and survives a lost state-write reply.
const TERMINAL_ROLLBACK_CONTEXT = new AsyncLocalStorage();
export async function withTerminalRollbackConfirmation(rootInput, bindingInput, callback) {
  const root = validateRoot(rootInput);
  const binding = readExactObject(bindingInput, ['deviceId','operationId'], 'RUNTIME_INPUT_INVALID');
  const paths = runtimeDeviceRecoveryPaths(root, binding.deviceId, binding.operationId);
  const path = joinPath(paths.operation, 'terminal-rollback-v1', 'commit.json');
  if (typeof callback !== 'function' || isProxy(callback) || TERMINAL_ROLLBACK_CONTEXT.getStore() !== undefined) {
    fail('RUNTIME_INPUT_INVALID');
  }
  return withMappedErrors(() => withRecoveryOperationLock(root, paths, async () => {
    let active = true;
    let busy = false;
    const pending = [];
    const invoke = operation => {
      if (!active) fail('RUNTIME_INPUT_INVALID');
      if (busy) fail('RUNTIME_ALREADY_RUNNING');
      busy = true;
      const promise = Promise.resolve().then(operation).finally(() => { busy = false; });
      const record = {error:null};
      record.drain = promise.catch(error => { record.error = error; });
      pending.push(record);
      return promise;
    };
    const read = async () => {
      if (await inspectOptionalImmutablePublication(root,path) === null) return null;
      const commit = await readCanonicalRecord(root,path,validateTerminalRollbackCommit);
      if (commit.evidence.failedState.deviceId !== binding.deviceId
        || commit.evidence.failedState.operationId !== binding.operationId) fail('RUNTIME_STATE_UNSUPPORTED');
      return commit;
    };
    let stateBusy = false;
    const runState = operation => {
      if (!active) fail('RUNTIME_INPUT_INVALID');
      if (busy || stateBusy) fail('RUNTIME_ALREADY_RUNNING');
      stateBusy = true;
      const promise = Promise.resolve().then(operation).finally(() => { stateBusy = false; });
      const record = {error:null};
      record.drain = promise.catch(error => { record.error = error; });
      pending.push(record);
      return promise;
    };
    const scope = Object.freeze({
      read: () => invoke(read),
      publish: input => {
        const commit = validateTerminalRollbackCommit(input);
        if (commit.evidence.failedState.deviceId !== binding.deviceId
          || commit.evidence.failedState.operationId !== binding.operationId) fail('RUNTIME_INPUT_INVALID');
        return invoke(async () => {
          if (await read() !== null) fail('RUNTIME_ALREADY_RUNNING');
          await publishImmutable(root,path,commit);
          return read();
        });
      },
    });
    let result, primary;
    try { result = await TERMINAL_ROLLBACK_CONTEXT.run({root,binding,read:scope.read,runState}, () => callback(scope)); }
    catch(error) { primary = error; }
    active = false;
    await Promise.all(pending.map(p => p.drain));
    primary ??= pending.find(p => p.error !== null)?.error;
    if (primary !== undefined && primary !== null) throw primary;
    return result;
  }));
}

export async function verifyTerminalRollbackCommit(root, expected, next) {
  assertTerminalRollbackStatePair(expected,next);
  const binding = {deviceId:expected.deviceId,operationId:expected.operationId};
  const held = TERMINAL_ROLLBACK_CONTEXT.getStore();
  if (held !== undefined && (held.root !== root || !sameRecord(held.binding,binding))) fail('RUNTIME_STATE_UNSUPPORTED');
  const commit = held === undefined
    ? await withTerminalRollbackConfirmation(root,binding,scope => scope.read())
    : await held.read();
  if (commit === null || !sameRecord(commit.evidence.failedState,expected) || !sameRecord(commit.nextState,next)) {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  return commit;
}

// All terminal CAS callers take the operation lock before the state-file lock.
// Reuse a live controller scope rather than attempting a recursive kernel lock.
export async function withTerminalRollbackStateConfirmation(rootInput, expected, next, callback) {
  const root = validateRoot(rootInput);
  assertTerminalRollbackStatePair(expected,next);
  const binding = {deviceId:expected.deviceId,operationId:expected.operationId};
  const held = TERMINAL_ROLLBACK_CONTEXT.getStore();
  if (held !== undefined) {
    if (held.root !== root || !sameRecord(held.binding,binding)) fail('RUNTIME_STATE_UNSUPPORTED');
    return held.runState(callback);
  }
  return withTerminalRollbackConfirmation(root,binding,() => callback());
}
