import { createHash } from 'node:crypto';
import { isAbsolute, resolve } from 'node:path';
import { isPromise, isProxy } from 'node:util/types';

import {
  applyPreparedRuntimePlan,
  runtimePlanFailureCode,
} from './ensure-runtime.mjs';
import { RUNTIME_ACQUISITION_POLICY } from './runtime-acquisition-policy.mjs';
import { validateRuntimeCatalog } from './runtime-catalog.mjs';
import {
  runtimeInventoriesSemanticallyEqual,
  validateRuntimeInventory,
} from './runtime-inventory.mjs';
import { deriveRuntimeControllerKeyIdentity } from './runtime-manifest.mjs';
import { createRuntimePlan } from './runtime-plan.mjs';
import { RUNTIME_PLAN_TICKET_TTL_MS } from './runtime-plan-ticket-policy.mjs';
import { validateRuntimeStateRecord } from './runtime-state-store.mjs';

const PLAN_TICKET_ID_PATTERN = /^rpt_[a-f0-9]{64}$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const HOST_FINGERPRINT_PATTERN = /^SHA256:[A-Za-z0-9+/]{43}$/u;
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const BASELINE_ID_PATTERN = /^rbl_[a-f0-9]{64}$/u;
const PROFILE_IDS = Object.freeze(['core', 'base']);
const INTERMEDIATE_STATUSES = new Set([
  'INVENTORY_READY',
  'PLAN_READY',
  'ACQUIRING',
  'STAGED',
  'VERIFYING',
]);
const UNCERTAIN_CODES = new Set([
  'RUNTIME_COMPLETION_UNCERTAIN',
  'RUNTIME_ROLLBACK_INCOMPLETE',
]);
const SIGNER_DRIFT_CODES = new Set([
  'BOOTSTRAP_SIGNING_KEY_PARTIAL',
  'BOOTSTRAP_SIGNING_KEY_MISMATCH',
]);
const SIGNER_UNSAFE_CODES = new Set([
  'BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE',
  'BOOTSTRAP_SIGNING_KEY_PERMISSIONS',
  'BOOTSTRAP_SIGNING_KEY_PRIVATE_INVALID',
  'BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID',
]);
const APPROVED_SIGNER_CODES = new Set([
  ...SIGNER_DRIFT_CODES,
  ...SIGNER_UNSAFE_CODES,
]);
const REVIEW_FIELDS = Object.freeze([
  'deviceId',
  'requestedProfiles',
  'baselineId',
  'dependencyFactory',
]);
const APPROVED_FIELDS = Object.freeze([
  'deviceId',
  'requestedProfiles',
  'planTicketId',
  'dependencyFactory',
]);
const REVIEW_DEPENDENCY_FIELDS = Object.freeze([
  'loadTarget',
  'readState',
  'readInventoryPair',
  'loadCatalog',
  'readBaselineBinding',
  'getSigningPublicKey',
  'readMutatorRevisions',
  'createPlanTicket',
  'operationId',
  'clock',
]);
const APPROVED_DEPENDENCY_FIELDS = Object.freeze([
  'loadTarget',
  'readState',
  'transitionState',
  'readInventoryPair',
  'loadCatalog',
  'readBaselineBinding',
  'getSigningPublicKey',
  'readMutatorRevisions',
  'readPlanTicket',
  'consumePlanTicket',
  'sign',
  'acquireArtifact',
  'provision',
]);
const INVENTORY_PAIR_FIELDS = Object.freeze([
  'schemaVersion',
  'firstInventory',
  'firstControllerTrust',
  'secondInventory',
  'secondControllerTrust',
  'scriptSha256',
]);
const TRUST_FIELDS = Object.freeze(['state', 'controllerKeyId']);
const TICKET_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'planTicketId',
  'deviceId',
  'operationId',
  'createdAt',
  'state',
  'catalog',
  'inventory',
  'plan',
  'controller',
  'mutators',
  'baseline',
  'authorization',
  'authorizationDigest',
  'expiresAt',
  'recordDigest',
]);
const CONSUMED_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'planTicketId',
  'deviceId',
  'ticketRecordDigest',
  'authorizationDigest',
  'consumedAt',
  'recordDigest',
]);
const INTRINSIC_APPLY = Reflect.apply;
const INTRINSIC_PROMISE_THEN = Object.getOwnPropertyDescriptor(Promise.prototype, 'then').value;
const INTRINSIC_PROMISE_RESOLVE = Object.getOwnPropertyDescriptor(Promise, 'resolve').value;
const ROOT_FIELDS = Object.freeze([
  'target',
  'state',
  'catalog',
  'inventory',
  'plan',
  'acquisitionPolicy',
  'controller',
  'mutators',
  'baseline',
]);
const PLAN_FIELDS = Object.freeze([
  'schemaVersion',
  'operationId',
  'createdAt',
  'deviceId',
  'inventoryDigest',
  'catalogDigest',
  'requestedProfiles',
  'profiles',
  'acquisition',
  'transactionMode',
  'status',
  'blockedReasons',
  'requiredFreeBytes',
  'items',
]);
const MUTATION_SCOPE = Object.freeze({
  runtimeRoot: 'C:\\ProgramData\\AgentRoad\\runtime',
  allowedDescendants: Object.freeze([
    'staging/<operationId>',
    'trust/controller-key.json',
    'versions/<manifestDigest>',
    'versions/.rollback-<manifestDigest>',
    'versions/.retired-<manifestDigest>',
    'state/journal.json',
    'state/active.json',
    'state/previous.json',
  ]),
});
const TRANSPORT_SCOPE = Object.freeze({
  transportRoot: 'C:\\ProgramData\\AgentRoad\\tasks',
  allowedDescendants: Object.freeze([
    '<transportOperationId>.ps1',
    '<transportOperationId>.result.json',
    '<transportOperationId>.result.json.tmp',
  ]),
  operationSets: Object.freeze({
    noOp: 0,
    actionableMaximum: 2,
    roles: Object.freeze(['inventory', 'provision']),
    identifier: 'fresh-lowercase-hex-32-per-set',
    distinct: true,
  }),
  lifecycle: Object.freeze({
    create: 'root-if-absent-and-operation-files-as-needed',
    verify: 'root-acl-and-script-bytes-before-execute',
    execute: 'verified-operation-script-without-retry',
    result: 'temporary-write-atomic-publish-then-read',
    cleanup: 'attempt-all-three-operation-files-after-staging',
  }),
  temporariness: Object.freeze({
    transportRoot: 'may-create-and-retain',
    normal: 'cleanup-attempted-for-all-three-operation-files',
    uncertain: 'bounded-operation-file-residue-may-remain',
  }),
});
const NON_MUTATION_CLAIMS = Object.freeze({
  pathEnvironment: 'not-mutated',
  registryRegistration: 'not-mutated',
  services: 'not-mutated',
  scheduledTasks: 'not-mutated',
  firewall: 'not-mutated',
  userProfiles: 'not-mutated',
  unrelatedAcls: 'not-mutated',
});

function inputError() {
  const error = new TypeError('RUNTIME_INPUT_INVALID');
  error.code = 'RUNTIME_INPUT_INVALID';
  return error;
}

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
  try { descriptor = Object.getOwnPropertyDescriptor(error, 'code'); } catch { return undefined; }
  return descriptor !== undefined
    && Object.hasOwn(descriptor, 'value')
    && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
}

function exactArray(input, maximum) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Array.isArray(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw inputError();
  const length = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    !length
    || !Object.hasOwn(length, 'value')
    || !Number.isSafeInteger(length.value)
    || length.value < 0
    || length.value > maximum
    || Object.getOwnPropertyNames(input).length !== length.value + 1
  ) throw inputError();
  const output = [];
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      throw inputError();
    }
    output.push(descriptor.value);
  }
  return output;
}

function validateCallable(value) {
  if (typeof value !== 'function' || isProxy(value)) throw inputError();
  return value;
}

async function invoke(callable, args, invalidCode = 'RUNTIME_INPUT_INVALID') {
  const output = INTRINSIC_APPLY(callable, undefined, args);
  if (output !== null && (typeof output === 'object' || typeof output === 'function')) {
    if (isProxy(output)) fail(invalidCode, invalidCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    if (isPromise(output)) {
      const reference = INTRINSIC_APPLY(INTRINSIC_PROMISE_RESOLVE, Promise, [undefined]);
      const referenceSymbols = Object.getOwnPropertySymbols(reference);
      const outputSymbols = Object.getOwnPropertySymbols(output);
      if (
        Object.getPrototypeOf(output) !== Promise.prototype
        || Object.getOwnPropertyNames(output).length !== 0
        || outputSymbols.length !== referenceSymbols.length
        || outputSymbols.some((symbol) => !referenceSymbols.includes(symbol))
      ) fail(invalidCode, invalidCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
      return new Promise((resolvePromise, rejectPromise) => {
        INTRINSIC_APPLY(INTRINSIC_PROMISE_THEN, output, [
          (value) => resolvePromise(Object.freeze({ value })),
          rejectPromise,
        ]);
      });
    }
  }
  return Object.freeze({ value: output });
}

async function dependenciesFrom(factory, fields) {
  try {
    validateCallable(factory);
    const { value } = await invoke(factory, []);
    const selected = exactObject(value, fields);
    const result = {};
    for (const field of fields) result[field] = validateCallable(selected[field]);
    return Object.freeze(result);
  } catch {
    throw inputError();
  }
}

function validateDeviceId(value) {
  if (typeof value !== 'string' || value.length > 64 || !DEVICE_ID_PATTERN.test(value)) {
    throw inputError();
  }
  return value;
}

function validateProfiles(input) {
  const profiles = exactArray(input, PROFILE_IDS.length);
  if (
    profiles.length === 0
    || profiles.some((profile) => typeof profile !== 'string' || !PROFILE_IDS.includes(profile))
    || new Set(profiles).size !== profiles.length
  ) throw inputError();
  if (profiles.includes('base')) fail('RUNTIME_PROFILE_UNAVAILABLE');
  if (profiles.length !== 1 || profiles[0] !== 'core') throw inputError();
  return Object.freeze(['core']);
}

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const child of value) deepFreeze(child);
  } else if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return Object.freeze(value);
}

function exactObject(input, fields) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw inputError();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    throw inputError();
  }
  const output = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      throw inputError();
    }
    output[field] = descriptor.value;
  }
  return output;
}

function safeClone(input, state = { nodes: 0 }, depth = 0) {
  state.nodes += 1;
  if (state.nodes > 8_192 || depth > 24) throw inputError();
  if (input === null || typeof input === 'boolean' || typeof input === 'string') return input;
  if (typeof input === 'number') {
    if (!Number.isSafeInteger(input) || Object.is(input, -0)) throw inputError();
    return input;
  }
  if (typeof input !== 'object' || isProxy(input)) throw inputError();
  if (Array.isArray(input)) {
    if (
      Object.getPrototypeOf(input) !== Array.prototype
      || Object.getOwnPropertySymbols(input).length !== 0
    ) throw inputError();
    const names = Object.getOwnPropertyNames(input);
    const length = Object.getOwnPropertyDescriptor(input, 'length');
    if (
      !length
      || !Object.hasOwn(length, 'value')
      || !Number.isSafeInteger(length.value)
      || length.value < 0
      || length.value > 512
      || names.length !== length.value + 1
    ) throw inputError();
    const output = [];
    for (let index = 0; index < length.value; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
        throw inputError();
      }
      output.push(safeClone(descriptor.value, state, depth + 1));
    }
    return output;
  }
  if (
    Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || Object.getOwnPropertyNames(input).length > 64
  ) throw inputError();
  const output = {};
  for (const name of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      throw inputError();
    }
    output[name] = safeClone(descriptor.value, state, depth + 1);
  }
  return output;
}

function targetProjection(input, expectedDeviceId) {
  const value = exactObject(input, ['deviceId', 'sshHostKeyFingerprints']);
  const fingerprints = exactArray(value.sshHostKeyFingerprints, 16);
  if (
    value.deviceId !== expectedDeviceId
    || typeof value.deviceId !== 'string'
    || value.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || fingerprints.length < 1
    || fingerprints.some((fingerprint) => (
      typeof fingerprint !== 'string' || !HOST_FINGERPRINT_PATTERN.test(fingerprint)
    ))
    || new Set(fingerprints).size !== fingerprints.length
  ) throw inputError();
  return {
    deviceId: value.deviceId,
    sshHostKeyFingerprints: [...fingerprints].sort(),
  };
}

function planProjection(input, deviceId, inventory) {
  const value = exactObject(input, PLAN_FIELDS);
  const plan = safeClone(input);
  if (
    plan.schemaVersion !== 1
    || plan.deviceId !== deviceId
    || typeof plan.operationId !== 'string'
    || !/^[a-f0-9]{32}$/u.test(plan.operationId)
    || canonicalTimestamp(plan.createdAt) !== plan.createdAt
    || typeof plan.inventoryDigest !== 'string'
    || !SHA256_PATTERN.test(plan.inventoryDigest)
    || typeof plan.catalogDigest !== 'string'
    || !SHA256_PATTERN.test(plan.catalogDigest)
    || !Number.isSafeInteger(plan.requiredFreeBytes)
    || plan.requiredFreeBytes < 0
  ) throw inputError();
  const { operationId, createdAt, inventoryDigest, ...stable } = plan;
  void operationId;
  void createdAt;
  void inventoryDigest;
  return {
    plan: stable,
    inventory: {
      schemaVersion: inventory.schemaVersion,
      platform: safeClone(inventory.platform),
      pendingReboot: inventory.pendingReboot,
      interactiveSession: inventory.interactiveSession,
      runtime: safeClone(inventory.runtime),
      managedArtifacts: safeClone(inventory.managedArtifacts),
      requiredFreeBytes: plan.requiredFreeBytes,
      freeSpaceSufficient: inventory.freeBytes >= plan.requiredFreeBytes,
    },
  };
}

function canonicalController(input) {
  const value = exactObject(input, [
    'controllerKeyId',
    'controllerPublicKey',
    'firstTrustPinningRequired',
  ]);
  if (
    typeof value.controllerKeyId !== 'string'
    || !SHA256_PATTERN.test(value.controllerKeyId)
    || typeof value.firstTrustPinningRequired !== 'boolean'
  ) throw inputError();
  return {
    controllerKeyId: value.controllerKeyId,
    controllerPublicKey: safeClone(value.controllerPublicKey),
    firstTrustPinningRequired: value.firstTrustPinningRequired,
  };
}

function canonicalMutators(input) {
  const value = exactObject(input, [
    'inventoryScriptSha256',
    'inventorySha256',
    'provisionSha256',
    'recoverySha256',
  ]);
  if ([
    value.inventoryScriptSha256,
    value.inventorySha256,
    value.provisionSha256,
    value.recoverySha256,
  ].some(
    (digest) => typeof digest !== 'string' || !SHA256_PATTERN.test(digest),
  )) throw inputError();
  return { ...value };
}

function canonicalBaseline(input) {
  const value = exactObject(input, [
    'baselineId',
    'schemaVersion',
    'protocolRevision',
    'captureAggregateMac',
    'recordDigest',
    'capturedAt',
    'expiresAt',
  ]);
  if (
    typeof value.baselineId !== 'string'
    || !/^rbl_[a-f0-9]{64}$/u.test(value.baselineId)
    || value.schemaVersion !== 1
    || value.protocolRevision !== 1
    || !SHA256_PATTERN.test(value.captureAggregateMac)
    || !SHA256_PATTERN.test(value.recordDigest)
    || canonicalTimestamp(value.capturedAt) !== value.capturedAt
    || canonicalTimestamp(value.expiresAt) !== value.expiresAt
    || value.expiresAt <= value.capturedAt
  ) throw inputError();
  return { ...value };
}

function canonicalTimestamp(value, code = 'RUNTIME_INPUT_INVALID') {
  if (
    typeof value !== 'string'
    || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u.test(value)
  ) fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  try {
    if (new Date(value).toISOString() !== value) {
      fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    }
  } catch {
    fail(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  return value;
}

function validatePlanningTarget(input, deviceId) {
  try {
    if (
      input === null
      || typeof input !== 'object'
      || isProxy(input)
      || !Object.isFrozen(input)
    ) fail('RUNTIME_INVENTORY_FAILED');
    const target = exactObject(input, ['device', 'identity', 'knownHostsPath']);
    if (
      target.device === null
      || typeof target.device !== 'object'
      || isProxy(target.device)
      || Array.isArray(target.device)
      || Object.getPrototypeOf(target.device) !== Object.prototype
      || Object.getOwnPropertySymbols(target.device).length !== 0
      || !Object.isFrozen(target.device)
    ) fail('RUNTIME_INVENTORY_FAILED');
    const id = Object.getOwnPropertyDescriptor(target.device, 'id');
    const transport = Object.getOwnPropertyDescriptor(target.device, 'transport');
    if (
      !id
      || !Object.hasOwn(id, 'value')
      || id.enumerable !== true
      || id.value !== deviceId
      || !transport
      || !Object.hasOwn(transport, 'value')
      || transport.enumerable !== true
    ) fail('RUNTIME_INVENTORY_FAILED');
    const transportValue = transport.value;
    if (
      transportValue === null
      || typeof transportValue !== 'object'
      || isProxy(transportValue)
      || Array.isArray(transportValue)
      || Object.getPrototypeOf(transportValue) !== Object.prototype
      || Object.getOwnPropertySymbols(transportValue).length !== 0
      || !Object.isFrozen(transportValue)
    ) fail('RUNTIME_INVENTORY_FAILED');
    const fingerprintsDescriptor = Object.getOwnPropertyDescriptor(
      transportValue,
      'sshHostKeyFingerprints',
    );
    if (
      !fingerprintsDescriptor
      || !Object.hasOwn(fingerprintsDescriptor, 'value')
      || fingerprintsDescriptor.enumerable !== true
      || fingerprintsDescriptor.value === null
      || typeof fingerprintsDescriptor.value !== 'object'
      || isProxy(fingerprintsDescriptor.value)
      || !Object.isFrozen(fingerprintsDescriptor.value)
    ) fail('RUNTIME_INVENTORY_FAILED');
    const fingerprints = exactArray(fingerprintsDescriptor.value, 16);
    if (
      fingerprints.length === 0
      || fingerprints.some((fingerprint) => (
        typeof fingerprint !== 'string' || !HOST_FINGERPRINT_PATTERN.test(fingerprint)
      ))
      || new Set(fingerprints).size !== fingerprints.length
    ) fail('RUNTIME_INVENTORY_FAILED');

    if (
      target.identity === null
      || typeof target.identity !== 'object'
      || isProxy(target.identity)
      || !Object.isFrozen(target.identity)
    ) fail('RUNTIME_INVENTORY_FAILED');
    const identity = exactObject(target.identity, [
      'privateKeyPath',
      'publicKeyPath',
      'publicKey',
    ]);
    if (
      typeof identity.privateKeyPath !== 'string'
      || !isAbsolute(identity.privateKeyPath)
      || resolve(identity.privateKeyPath) !== identity.privateKeyPath
      || identity.publicKeyPath !== `${identity.privateKeyPath}.pub`
      || typeof identity.publicKey !== 'string'
      || identity.publicKey.length === 0
      || /[\r\n\0]/u.test(identity.publicKey)
      || typeof target.knownHostsPath !== 'string'
      || !isAbsolute(target.knownHostsPath)
      || resolve(target.knownHostsPath) !== target.knownHostsPath
    ) fail('RUNTIME_INVENTORY_FAILED');
    return Object.freeze({
      target: input,
      authorizationTarget: deepFreeze({
        deviceId,
        sshHostKeyFingerprints: [...fingerprints].sort(),
      }),
    });
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(code === 'RUNTIME_INVENTORY_FAILED' ? code : 'RUNTIME_INVENTORY_FAILED');
  }
}

function guardRuntimeState(state) {
  if (INTERMEDIATE_STATUSES.has(state.runtimeStatus)) fail('RUNTIME_ALREADY_RUNNING');
  if (state.runtimeStatus === 'FAILED' && UNCERTAIN_CODES.has(state.failureCode)) {
    fail(state.failureCode);
  }
}

async function loadPlanningTarget(dependencies, deviceId) {
  try {
    const { value } = await invoke(dependencies.loadTarget, [deviceId]);
    return validatePlanningTarget(value, deviceId);
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(code === 'RUNTIME_ALREADY_RUNNING' ? code : 'RUNTIME_INVENTORY_FAILED');
  }
}

async function loadPlanningState(dependencies, deviceId, exposeUncertain = true) {
  try {
    const { value } = await invoke(dependencies.readState, [deviceId]);
    const state = validateRuntimeStateRecord(value);
    if (state.deviceId !== deviceId) fail('RUNTIME_STATE_UNSUPPORTED');
    guardRuntimeState(state);
    return state;
  } catch (error) {
    const code = safeCode(error);
    if (code === 'RUNTIME_ALREADY_RUNNING') throw runtimeError(code);
    if (exposeUncertain && UNCERTAIN_CODES.has(code)) throw runtimeError(code);
    throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
}

async function callDependency(dependencies, field, args, fallback, allowed = new Set()) {
  try {
    return (await invoke(dependencies[field], args, fallback)).value;
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(allowed.has(code) ? code : fallback, fallback === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
}

function operationTimestamp(clockValue, previous) {
  if (
    clockValue === null
    || typeof clockValue !== 'object'
    || isProxy(clockValue)
    || Object.getPrototypeOf(clockValue) !== Date.prototype
    || Object.getOwnPropertyNames(clockValue).length !== 0
    || Object.getOwnPropertySymbols(clockValue).length !== 0
  ) fail('RUNTIME_INTERNAL_ERROR');
  let milliseconds;
  try { milliseconds = Date.prototype.getTime.call(clockValue); } catch {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  const previousMs = previous === null ? -1 : Date.parse(previous);
  const next = Math.max(milliseconds, previousMs + 1);
  if (!Number.isSafeInteger(next) || next < 0 || next > 253_402_300_799_999) {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  return Object.freeze({ milliseconds: next, timestamp: new Date(next).toISOString() });
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function samePlanExceptInventoryDigest(left, right) {
  return sameJson(
    { ...left, inventoryDigest: null },
    { ...right, inventoryDigest: null },
  );
}

function canonicalTrust(input) {
  const value = exactObject(input, TRUST_FIELDS);
  if (
    !['unpinned', 'pinned'].includes(value.state)
    || (value.state === 'unpinned' && value.controllerKeyId !== null)
    || (value.state === 'pinned' && (
      typeof value.controllerKeyId !== 'string' || !SHA256_PATTERN.test(value.controllerKeyId)
    ))
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  return Object.freeze({ state: value.state, controllerKeyId: value.controllerKeyId });
}

function canonicalInventoryPair(
  input,
  controllerIdentity,
  mutators,
  controllerMismatchCode = 'RUNTIME_STATE_UNSUPPORTED',
) {
  let value;
  try { value = exactObject(input, INVENTORY_PAIR_FIELDS); } catch {
    fail('RUNTIME_INVENTORY_FAILED');
  }
  if (value.schemaVersion !== 1) fail('RUNTIME_INVENTORY_FAILED');
  let firstInventory;
  let secondInventory;
  let firstTrust;
  let secondTrust;
  try {
    firstInventory = validateRuntimeInventory(value.firstInventory);
    secondInventory = validateRuntimeInventory(value.secondInventory);
    firstTrust = canonicalTrust(value.firstControllerTrust);
    secondTrust = canonicalTrust(value.secondControllerTrust);
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(code === 'RUNTIME_STATE_UNSUPPORTED' ? code : 'RUNTIME_INVENTORY_FAILED');
  }
  if (
    typeof value.scriptSha256 !== 'string'
    || !SHA256_PATTERN.test(value.scriptSha256)
    || value.scriptSha256 !== mutators.inventoryScriptSha256
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  if (!sameJson(firstTrust, secondTrust)) fail('RUNTIME_INVENTORY_CHANGED');
  if (
    firstTrust.state === 'pinned'
    && firstTrust.controllerKeyId !== controllerIdentity.controllerKeyId
  ) fail(controllerMismatchCode);
  return Object.freeze({
    firstInventory,
    secondInventory,
    firstTrust,
    firstTrustPinningRequired: firstTrust.state === 'unpinned',
  });
}

function buildStablePlan(input) {
  const firstPlan = createRuntimePlan({
    catalog: input.catalog,
    requestedProfiles: input.requestedProfiles,
    inventory: input.pair.firstInventory,
    deviceId: input.deviceId,
    operationId: input.operationId,
    createdAt: input.createdAt,
  });
  const plan = createRuntimePlan({
    catalog: input.catalog,
    requestedProfiles: input.requestedProfiles,
    inventory: input.pair.secondInventory,
    deviceId: input.deviceId,
    operationId: input.operationId,
    createdAt: input.createdAt,
  });
  if (
    !samePlanExceptInventoryDigest(firstPlan, plan)
    || !runtimeInventoriesSemanticallyEqual(
      input.pair.firstInventory,
      input.pair.secondInventory,
      plan.requiredFreeBytes,
    )
  ) fail('RUNTIME_INVENTORY_CHANGED');
  return plan;
}

function controllerProjection(identity, pair) {
  return deepFreeze({
    controllerKeyId: identity.controllerKeyId,
    controllerPublicKey: structuredClone(identity.controllerPublicKey),
    firstTrustPinningRequired: pair.firstTrustPinningRequired,
  });
}

function ticketSnapshot(input, expected) {
  let value;
  let snapshot;
  try {
    snapshot = safeClone(input);
    value = exactObject(snapshot, TICKET_FIELDS);
  } catch { throw inputError(); }
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RUNTIME_PLAN_TICKET'
    || !PLAN_TICKET_ID_PATTERN.test(value.planTicketId ?? '')
    || !DEVICE_ID_PATTERN.test(value.deviceId ?? '')
    || !OPERATION_ID_PATTERN.test(value.operationId ?? '')
    || !SHA256_PATTERN.test(value.authorizationDigest ?? '')
    || !SHA256_PATTERN.test(value.recordDigest ?? '')
    || (expected.planTicketId !== undefined && value.planTicketId !== expected.planTicketId)
    || value.deviceId !== expected.deviceId
  ) throw inputError();
  canonicalTimestamp(value.createdAt);
  canonicalTimestamp(value.expiresAt);
  if (
    value.expiresAt !== new Date(
      Date.parse(value.createdAt) + RUNTIME_PLAN_TICKET_TTL_MS,
    ).toISOString()
    || value.plan?.operationId !== value.operationId
    || value.plan?.createdAt !== value.createdAt
  ) throw inputError();
  const { recordDigest, ...base } = snapshot;
  if (createHash('sha256')
    .update('AgentRoad.RuntimePlanTicket.v1\0', 'utf8')
    .update(JSON.stringify(base), 'utf8')
    .digest('hex')
    .toUpperCase() !== recordDigest) throw inputError();
  let authorization;
  try {
    authorization = createRuntimePlanAuthorizationProjection({
      target: value.authorization.target,
      state: value.state,
      catalog: value.catalog,
      inventory: value.inventory,
      plan: value.plan,
      acquisitionPolicy: value.authorization.acquisitionPolicy,
      controller: value.controller,
      mutators: value.mutators,
      baseline: value.baseline,
    });
  } catch { throw inputError(); }
  if (
    !sameJson(authorization, value.authorization)
    || digestRuntimePlanAuthorization(authorization) !== value.authorizationDigest
  ) throw inputError();
  if (Date.parse(value.baseline.expiresAt) < Date.parse(value.expiresAt)) {
    throw inputError();
  }
  return deepFreeze(snapshot);
}

function consumedPlanSnapshot(input, ticket) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Object.isFrozen(input)
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  let snapshot;
  let value;
  try {
    snapshot = safeClone(input);
    value = exactObject(snapshot, CONSUMED_FIELDS);
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RUNTIME_PLAN_CONSUMED'
    || value.planTicketId !== ticket.planTicketId
    || value.deviceId !== ticket.deviceId
    || value.ticketRecordDigest !== ticket.recordDigest
    || value.authorizationDigest !== ticket.authorizationDigest
    || !SHA256_PATTERN.test(value.recordDigest ?? '')
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  try { canonicalTimestamp(value.consumedAt, 'RUNTIME_STATE_UNSUPPORTED'); } catch {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  if (value.consumedAt < ticket.createdAt || value.consumedAt >= ticket.expiresAt) {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  const { recordDigest, ...base } = snapshot;
  if (createHash('sha256')
    .update('AgentRoad.RuntimePlanConsumed.v1\0', 'utf8')
    .update(JSON.stringify(base), 'utf8')
    .digest('hex')
    .toUpperCase() !== recordDigest) fail('RUNTIME_STATE_UNSUPPORTED');
  return deepFreeze(snapshot);
}

export function createRuntimePlanAuthorizationProjection(input) {
  const value = exactObject(input, ROOT_FIELDS);
  const state = validateRuntimeStateRecord(value.state);
  const catalog = validateRuntimeCatalog(value.catalog);
  const inventory = validateRuntimeInventory(value.inventory);
  const stable = planProjection(value.plan, state.deviceId, inventory);
  const acquisitionPolicy = exactObject(value.acquisitionPolicy, ['timeoutMs', 'maxRedirects']);
  if (
    !Number.isSafeInteger(acquisitionPolicy.timeoutMs)
    || acquisitionPolicy.timeoutMs < 1
    || !Number.isSafeInteger(acquisitionPolicy.maxRedirects)
    || acquisitionPolicy.maxRedirects < 0
  ) throw inputError();
  return deepFreeze({
    schemaVersion: 1,
    target: targetProjection(value.target, state.deviceId),
    state: safeClone(state),
    catalog: safeClone(catalog),
    inventory: stable.inventory,
    plan: stable.plan,
    acquisitionPolicy: { ...acquisitionPolicy },
    controller: canonicalController(value.controller),
    mutators: canonicalMutators(value.mutators),
    baseline: canonicalBaseline(value.baseline),
    mutationScope: safeClone(MUTATION_SCOPE),
    transportScope: safeClone(TRANSPORT_SCOPE),
    nonMutationClaims: safeClone(NON_MUTATION_CLAIMS),
  });
}

export function digestRuntimePlanAuthorization(input) {
  const snapshot = safeClone(input);
  return createHash('sha256')
    .update('AGENT_ROAD_RUNTIME_PLAN_AUTHORIZATION_V1\0', 'ascii')
    .update(JSON.stringify(snapshot), 'utf8')
    .digest('hex')
    .toUpperCase();
}

function artifactReview(item, catalogArtifacts) {
  const artifact = catalogArtifacts.find(({ id }) => id === item.artifactId);
  if (artifact === undefined) throw inputError();
  let sourceOrigin;
  try {
    sourceOrigin = new URL(artifact.url).origin;
  } catch {
    throw inputError();
  }
  return {
    artifactId: item.artifactId,
    action: item.action,
    reason: item.reason,
    desiredVersion: item.desired.version,
    downloadBytes: item.desired.bytes,
    maximumExpandedBytes: item.desired.maximumExpandedBytes,
    rollbackVersion: item.rollbackVersion,
    sourceOrigins: [...artifact.redirectOrigins, sourceOrigin].sort(),
    signerRule: artifact.signerRule,
    verifierId: artifact.verificationCommandId,
    fingerprint: item.desired.sha256.slice(0, 12),
  };
}

function reviewStringArray(input, maximum, predicate) {
  const values = exactArray(input, maximum);
  if (values.some((value) => !predicate(value)) || new Set(values).size !== values.length) {
    throw inputError();
  }
  return values;
}

export function validateRuntimePlanReviewResult(input) {
  const snapshot = safeClone(input);
  const value = exactObject(snapshot, [
    'schemaVersion',
    'status',
    'planTicketId',
    'plan',
    'controller',
    'mutators',
    'mutationScope',
    'transportScope',
    'nonMutationClaims',
  ]);
  if (
    value.schemaVersion !== 1
    || value.status !== 'PLAN_REVIEW_READY'
    || !PLAN_TICKET_ID_PATTERN.test(value.planTicketId ?? '')
  ) throw inputError();
  const plan = exactObject(value.plan, [
    'status',
    'blockers',
    'requestedProfiles',
    'resolvedProfiles',
    'acquisition',
    'transactionMode',
    'requiredFreeBytes',
    'artifacts',
  ]);
  const blockers = reviewStringArray(
    plan.blockers,
    16,
    (item) => typeof item === 'string' && /^[a-z][a-z0-9-]{0,63}$/u.test(item),
  );
  const requestedProfiles = reviewStringArray(
    plan.requestedProfiles,
    PROFILE_IDS.length,
    (item) => PROFILE_IDS.includes(item),
  );
  const resolvedProfiles = reviewStringArray(
    plan.resolvedProfiles,
    PROFILE_IDS.length,
    (item) => PROFILE_IDS.includes(item),
  );
  if (
    !['actionable', 'blocked'].includes(plan.status)
    || (plan.status === 'blocked') !== (blockers.length > 0)
    || requestedProfiles.length !== 1
    || !resolvedProfiles.includes(requestedProfiles[0])
    || plan.acquisition !== 'mac-relay'
    || !['new', 'reconcile', 'conflict'].includes(plan.transactionMode)
    || !Number.isSafeInteger(plan.requiredFreeBytes)
    || plan.requiredFreeBytes < 0
  ) throw inputError();
  const artifacts = exactArray(plan.artifacts, 64).map((item) => {
    const artifact = exactObject(item, [
      'artifactId',
      'action',
      'reason',
      'desiredVersion',
      'downloadBytes',
      'maximumExpandedBytes',
      'rollbackVersion',
      'sourceOrigins',
      'signerRule',
      'verifierId',
      'fingerprint',
    ]);
    const sources = reviewStringArray(artifact.sourceOrigins, 16, (origin) => {
      if (typeof origin !== 'string') return false;
      try {
        const parsed = new URL(origin);
        return parsed.protocol === 'https:' && parsed.origin === origin;
      } catch { return false; }
    });
    const reasons = Object.freeze({
      install: 'managed-artifact-missing',
      upgrade: 'managed-version-older',
      blocked: 'managed-version-newer',
      present: null,
      repair: 'managed-artifact-invalid',
    });
    if (
      typeof artifact.artifactId !== 'string'
      || !/^[a-z0-9][a-z0-9-]{0,63}$/u.test(artifact.artifactId)
      || !Object.hasOwn(reasons, artifact.action)
      || artifact.reason !== reasons[artifact.action]
      || typeof artifact.desiredVersion !== 'string'
      || artifact.desiredVersion.length < 1
      || artifact.desiredVersion.length > 64
      || !Number.isSafeInteger(artifact.downloadBytes)
      || artifact.downloadBytes < 0
      || !Number.isSafeInteger(artifact.maximumExpandedBytes)
      || artifact.maximumExpandedBytes < 1
      || (artifact.rollbackVersion !== null && typeof artifact.rollbackVersion !== 'string')
      || sources.length < 1
      || !sources.every((source, index) => index === 0 || sources[index - 1] < source)
      || typeof artifact.signerRule !== 'string'
      || artifact.signerRule.length < 1
      || artifact.signerRule.length > 128
      || typeof artifact.verifierId !== 'string'
      || artifact.verifierId.length < 1
      || artifact.verifierId.length > 128
      || typeof artifact.fingerprint !== 'string'
      || !/^[A-F0-9]{12}$/u.test(artifact.fingerprint)
    ) throw inputError();
    return { ...artifact, sourceOrigins: sources };
  });
  const controller = exactObject(value.controller, [
    'controllerKeyId',
    'firstTrustPinningRequired',
  ]);
  if (
    typeof controller.controllerKeyId !== 'string'
    || !SHA256_PATTERN.test(controller.controllerKeyId)
    || typeof controller.firstTrustPinningRequired !== 'boolean'
  ) throw inputError();
  const mutators = exactObject(value.mutators, [
    'inventoryRevision',
    'provisionRevision',
    'recoveryRevision',
  ]);
  if (Object.values(mutators).some((revision) => (
    typeof revision !== 'string' || !/^[A-F0-9]{12}$/u.test(revision)
  ))) throw inputError();
  if (
    !sameJson(value.mutationScope, MUTATION_SCOPE)
    || !sameJson(value.transportScope, TRANSPORT_SCOPE)
    || !sameJson(value.nonMutationClaims, NON_MUTATION_CLAIMS)
  ) throw inputError();
  return deepFreeze({
    ...snapshot,
    plan: {
      ...plan,
      blockers,
      requestedProfiles,
      resolvedProfiles,
      artifacts,
    },
  });
}

export function createRuntimePlanReviewResult(input) {
  const value = exactObject(input, ['planTicketId', 'authorization']);
  if (
    !PLAN_TICKET_ID_PATTERN.test(value.planTicketId ?? '')
    || value.authorization === null
    || typeof value.authorization !== 'object'
    || isProxy(value.authorization)
  ) throw inputError();
  const authorization = safeClone(value.authorization);
  const { plan } = authorization;
  if (plan === null || typeof plan !== 'object' || !Array.isArray(plan.items)) {
    throw inputError();
  }
  const result = {
    schemaVersion: 1,
    status: 'PLAN_REVIEW_READY',
    planTicketId: value.planTicketId,
    plan: {
      status: plan.status,
      blockers: [...plan.blockedReasons],
      requestedProfiles: [...plan.requestedProfiles],
      resolvedProfiles: [...plan.profiles],
      acquisition: plan.acquisition,
      transactionMode: plan.transactionMode,
      requiredFreeBytes: plan.requiredFreeBytes,
      artifacts: plan.items.map((item) => artifactReview(item, authorization.catalog.artifacts)),
    },
    controller: {
      controllerKeyId: authorization.controller.controllerKeyId,
      firstTrustPinningRequired: authorization.controller.firstTrustPinningRequired,
    },
    mutators: {
      inventoryRevision: authorization.mutators.inventorySha256.slice(0, 12),
      provisionRevision: authorization.mutators.provisionSha256.slice(0, 12),
      recoveryRevision: authorization.mutators.recoverySha256.slice(0, 12),
    },
    mutationScope: structuredClone(authorization.mutationScope),
    transportScope: structuredClone(authorization.transportScope),
    nonMutationClaims: structuredClone(authorization.nonMutationClaims),
  };
  return validateRuntimePlanReviewResult(result);
}

export async function reviewRuntimePlan(input) {
  const values = exactObject(input, REVIEW_FIELDS);
  const deviceId = validateDeviceId(values.deviceId);
  const requestedProfiles = validateProfiles(values.requestedProfiles);
  if (typeof values.baselineId !== 'string' || !BASELINE_ID_PATTERN.test(values.baselineId)) {
    throw inputError();
  }
  validateCallable(values.dependencyFactory);
  const dependencies = await dependenciesFrom(values.dependencyFactory, REVIEW_DEPENDENCY_FIELDS);
  const target = await loadPlanningTarget(dependencies, deviceId);
  const state = await loadPlanningState(dependencies, deviceId, false);

  const operationId = await callDependency(
    dependencies,
    'operationId',
    [],
    'RUNTIME_INTERNAL_ERROR',
  );
  if (typeof operationId !== 'string' || !OPERATION_ID_PATTERN.test(operationId)) {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  if (state.runtimeStatus === 'RECOVERED' && operationId === state.operationId) {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  const clock = await callDependency(dependencies, 'clock', [], 'RUNTIME_INTERNAL_ERROR');
  const operationTime = operationTimestamp(clock, state.updatedAt);

  let catalog;
  try {
    catalog = validateRuntimeCatalog(await callDependency(
      dependencies,
      'loadCatalog',
      [],
      'RUNTIME_INTERNAL_ERROR',
    ));
  } catch {
    fail('RUNTIME_INTERNAL_ERROR');
  }

  let baseline;
  try {
    baseline = canonicalBaseline(await callDependency(
      dependencies,
      'readBaselineBinding',
      [Object.freeze({ deviceId, baselineId: values.baselineId })],
      'RUNTIME_STATE_UNSUPPORTED',
      new Set(['RUNTIME_ALREADY_RUNNING', 'RUNTIME_STATE_UNSUPPORTED']),
    ));
    if (baseline.baselineId !== values.baselineId) fail('RUNTIME_STATE_UNSUPPORTED');
    if (
      Date.parse(baseline.expiresAt)
        < operationTime.milliseconds + RUNTIME_PLAN_TICKET_TTL_MS
    ) fail('RUNTIME_STATE_UNSUPPORTED');
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(code === 'RUNTIME_ALREADY_RUNNING' ? code : 'RUNTIME_STATE_UNSUPPORTED');
  }

  let controllerIdentity;
  try {
    controllerIdentity = deriveRuntimeControllerKeyIdentity(await callDependency(
      dependencies,
      'getSigningPublicKey',
      [],
      'RUNTIME_SIGNATURE_INVALID',
      new Set(['RUNTIME_SIGNATURE_INVALID']),
    ));
  } catch {
    fail('RUNTIME_SIGNATURE_INVALID');
  }

  let mutators;
  try {
    mutators = deepFreeze(canonicalMutators(await callDependency(
      dependencies,
      'readMutatorRevisions',
      [],
      'RUNTIME_STATE_UNSUPPORTED',
      new Set(['RUNTIME_STATE_UNSUPPORTED']),
    )));
  } catch {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }

  const pair = canonicalInventoryPair(await callDependency(
    dependencies,
    'readInventoryPair',
    [target.target],
    'RUNTIME_INVENTORY_FAILED',
    new Set([
      'RUNTIME_ALREADY_RUNNING',
      'RUNTIME_INVENTORY_FAILED',
      'RUNTIME_STATE_UNSUPPORTED',
    ]),
  ), controllerIdentity, mutators);
  const plan = buildStablePlan({
    catalog,
    requestedProfiles,
    pair,
    deviceId,
    operationId,
    createdAt: operationTime.timestamp,
  });
  const controller = controllerProjection(controllerIdentity, pair);
  const authorization = createRuntimePlanAuthorizationProjection({
    target: target.authorizationTarget,
    state,
    catalog,
    inventory: pair.secondInventory,
    plan,
    acquisitionPolicy: RUNTIME_ACQUISITION_POLICY,
    controller,
    mutators,
    baseline,
  });
  const authorizationDigest = digestRuntimePlanAuthorization(authorization);
  const ticketInput = deepFreeze({
    deviceId,
    operationId,
    createdAt: operationTime.timestamp,
    state: structuredClone(state),
    catalog: structuredClone(catalog),
    inventory: structuredClone(pair.secondInventory),
    plan: structuredClone(plan),
    controller: structuredClone(controller),
    mutators: structuredClone(mutators),
    baseline: structuredClone(baseline),
    authorization: structuredClone(authorization),
    authorizationDigest,
  });
  const created = await callDependency(
    dependencies,
    'createPlanTicket',
    [ticketInput],
    'RUNTIME_INTERNAL_ERROR',
    new Set([
      'RUNTIME_ALREADY_RUNNING',
      'RUNTIME_INPUT_INVALID',
      'RUNTIME_STATE_UNSUPPORTED',
    ]),
  );
  const ticket = ticketSnapshot(created, { deviceId });
  if (
    ticket.operationId !== operationId
    || ticket.createdAt !== operationTime.timestamp
    || !sameJson(ticket.state, state)
    || !sameJson(ticket.catalog, catalog)
    || !sameJson(ticket.inventory, pair.secondInventory)
    || !sameJson(ticket.plan, plan)
    || !sameJson(ticket.controller, controller)
    || !sameJson(ticket.mutators, mutators)
    || !sameJson(ticket.baseline, baseline)
    || !sameJson(ticket.authorization, authorization)
    || ticket.authorizationDigest !== authorizationDigest
  ) fail('RUNTIME_STATE_UNSUPPORTED');
  return createRuntimePlanReviewResult({
    planTicketId: ticket.planTicketId,
    authorization,
  });
}

export async function prepareApprovedRuntime(input) {
  const values = exactObject(input, APPROVED_FIELDS);
  const deviceId = validateDeviceId(values.deviceId);
  const requestedProfiles = validateProfiles(values.requestedProfiles);
  if (
    typeof values.planTicketId !== 'string'
    || !PLAN_TICKET_ID_PATTERN.test(values.planTicketId)
  ) throw inputError();
  validateCallable(values.dependencyFactory);
  const dependencies = await dependenciesFrom(
    values.dependencyFactory,
    APPROVED_DEPENDENCY_FIELDS,
  );

  let ticket;
  try {
    const loaded = await callDependency(
      dependencies,
      'readPlanTicket',
      [Object.freeze({ deviceId, planTicketId: values.planTicketId })],
      'RUNTIME_INPUT_INVALID',
      new Set([
        'RUNTIME_ALREADY_RUNNING',
        'RUNTIME_INPUT_INVALID',
        'RUNTIME_STATE_UNSUPPORTED',
      ]),
    );
    ticket = ticketSnapshot(loaded, { deviceId, planTicketId: values.planTicketId });
  } catch (error) {
    const code = safeCode(error);
    if (code === 'RUNTIME_ALREADY_RUNNING' || code === 'RUNTIME_STATE_UNSUPPORTED') {
      throw runtimeError(code);
    }
    throw inputError();
  }

  const target = await loadPlanningTarget(dependencies, deviceId);
  const state = await loadPlanningState(dependencies, deviceId);

  if (
    !sameJson(ticket.plan.requestedProfiles, requestedProfiles)
    || !sameJson(ticket.state, state)
    || !sameJson(ticket.authorization.target, target.authorizationTarget)
  ) fail('RUNTIME_INVENTORY_CHANGED');

  let catalog;
  try {
    catalog = validateRuntimeCatalog(await callDependency(
      dependencies,
      'loadCatalog',
      [],
      'RUNTIME_INVENTORY_CHANGED',
      new Set(['RUNTIME_INVENTORY_CHANGED']),
    ));
  } catch {
    fail('RUNTIME_INVENTORY_CHANGED');
  }
  if (!sameJson(catalog, ticket.catalog)) fail('RUNTIME_INVENTORY_CHANGED');

  let baseline;
  try {
    baseline = canonicalBaseline(await callDependency(
      dependencies,
      'readBaselineBinding',
      [Object.freeze({ deviceId, baselineId: ticket.baseline.baselineId })],
      'RUNTIME_INVENTORY_CHANGED',
      new Set(['RUNTIME_ALREADY_RUNNING', 'RUNTIME_INVENTORY_CHANGED']),
    ));
  } catch (error) {
    const code = safeCode(error);
    if (code === 'RUNTIME_ALREADY_RUNNING') throw runtimeError(code);
    fail('RUNTIME_INVENTORY_CHANGED');
  }
  if (!sameJson(baseline, ticket.baseline)) fail('RUNTIME_INVENTORY_CHANGED');

  let controllerIdentity;
  try {
    controllerIdentity = deriveRuntimeControllerKeyIdentity(await callDependency(
      dependencies,
      'getSigningPublicKey',
      [],
      'RUNTIME_INTERNAL_ERROR',
      APPROVED_SIGNER_CODES,
    ));
  } catch (error) {
    const code = safeCode(error);
    if (SIGNER_DRIFT_CODES.has(code)) fail('RUNTIME_INVENTORY_CHANGED');
    if (SIGNER_UNSAFE_CODES.has(code)) fail('RUNTIME_STATE_UNSUPPORTED');
    fail('RUNTIME_INTERNAL_ERROR');
  }

  let mutators;
  try {
    mutators = deepFreeze(canonicalMutators(await callDependency(
      dependencies,
      'readMutatorRevisions',
      [],
      'RUNTIME_INVENTORY_CHANGED',
      new Set(['RUNTIME_INVENTORY_CHANGED']),
    )));
  } catch {
    fail('RUNTIME_INVENTORY_CHANGED');
  }
  if (!sameJson(mutators, ticket.mutators)) fail('RUNTIME_INVENTORY_CHANGED');

  const pair = canonicalInventoryPair(await callDependency(
    dependencies,
    'readInventoryPair',
    [target.target],
    'RUNTIME_INVENTORY_FAILED',
    new Set([
      'RUNTIME_ALREADY_RUNNING',
      'RUNTIME_INVENTORY_FAILED',
      'RUNTIME_STATE_UNSUPPORTED',
    ]),
  ), controllerIdentity, mutators, 'RUNTIME_INVENTORY_CHANGED');
  const controller = controllerProjection(controllerIdentity, pair);
  if (!sameJson(controller, ticket.controller)) fail('RUNTIME_INVENTORY_CHANGED');

  const plan = buildStablePlan({
    catalog,
    requestedProfiles,
    pair,
    deviceId,
    operationId: ticket.operationId,
    createdAt: ticket.createdAt,
  });
  if (
    !samePlanExceptInventoryDigest(ticket.plan, plan)
    || !runtimeInventoriesSemanticallyEqual(
      ticket.inventory,
      pair.secondInventory,
      plan.requiredFreeBytes,
    )
  ) fail('RUNTIME_INVENTORY_CHANGED');

  const authorization = createRuntimePlanAuthorizationProjection({
    target: target.authorizationTarget,
    state,
    catalog,
    inventory: pair.secondInventory,
    plan,
    acquisitionPolicy: RUNTIME_ACQUISITION_POLICY,
    controller,
    mutators,
    baseline,
  });
  const authorizationDigest = digestRuntimePlanAuthorization(authorization);
  if (
    authorizationDigest !== ticket.authorizationDigest
    || !sameJson(authorization, ticket.authorization)
  ) fail('RUNTIME_INVENTORY_CHANGED');
  if (plan.status === 'blocked') fail(runtimePlanFailureCode(plan.blockedReasons));

  const consumed = await callDependency(
    dependencies,
    'consumePlanTicket',
    [Object.freeze({
      deviceId,
      planTicketId: ticket.planTicketId,
      ticketRecordDigest: ticket.recordDigest,
      authorizationDigest: ticket.authorizationDigest,
    })],
    'RUNTIME_INTERNAL_ERROR',
    new Set([
      'RUNTIME_ALREADY_RUNNING',
      'RUNTIME_INPUT_INVALID',
      'RUNTIME_STATE_UNSUPPORTED',
    ]),
  );
  consumedPlanSnapshot(consumed, ticket);

  return applyPreparedRuntimePlan({
    dependencies: {
      transitionState: dependencies.transitionState,
      getSigningPublicKey: () => controllerIdentity.controllerPublicKey,
      sign: dependencies.sign,
      acquireArtifact: (artifact) => dependencies.acquireArtifact(
        artifact,
        authorization.acquisitionPolicy,
      ),
      provision: dependencies.provision,
    },
    target: target.target,
    current: state,
    catalog,
    inventory: pair.secondInventory,
    plan,
    requestedProfiles,
    firstTimestampMs: Date.parse(ticket.createdAt),
  });
}
