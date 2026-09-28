import { isAbsolute, resolve } from 'node:path';
import { isIP } from 'node:net';
import { isPromise, isProxy } from 'node:util/types';

import {
  resolveRuntimeProfiles,
  validateRuntimeCatalog,
} from './runtime-catalog.mjs';
import {
  runtimeInventoriesSemanticallyEqual,
  validateRuntimeInventory,
} from './runtime-inventory.mjs';
import { createSignedRuntimeManifest } from './runtime-manifest.mjs';
import { createRuntimePlan } from './runtime-plan.mjs';
import { validateRuntimeStateRecord } from './runtime-state-store.mjs';

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
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
const DEPENDENCY_FIELDS = Object.freeze([
  'loadTarget',
  'readState',
  'transitionState',
  'readInventory',
  'loadCatalog',
  'getSigningPublicKey',
  'sign',
  'acquireArtifact',
  'provision',
  'operationId',
  'clock',
]);
const ENSURE_FIELDS = Object.freeze(['deviceId', 'requestedProfiles', 'dependencyFactory']);
const QUERY_FIELDS = Object.freeze(['deviceId', 'dependencyFactory']);
const PREPARED_APPLY_FIELDS = Object.freeze([
  'dependencies',
  'target',
  'current',
  'catalog',
  'inventory',
  'plan',
  'requestedProfiles',
  'firstTimestampMs',
]);
const PREPARED_DEPENDENCY_FIELDS = Object.freeze([
  'transitionState',
  'getSigningPublicKey',
  'sign',
  'acquireArtifact',
  'provision',
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
const ARTIFACT_RESULT_FIELDS = Object.freeze([
  'artifactId',
  'version',
  'path',
  'bytes',
  'sha256',
]);
const PROVISION_RESULT_FIELDS = Object.freeze([
  'schemaVersion',
  'status',
  'deviceId',
  'address',
  'operationId',
  'manifestDigest',
  'generationDigest',
  'restartRequired',
  'failureCode',
]);
const RUNTIME_CODES = new Set([
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
const ACQUISITION_CODES = new Set([
  'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
  'RUNTIME_ARTIFACT_INTEGRITY_FAILED',
  'RUNTIME_ARTIFACT_INVALID',
  'RUNTIME_ARTIFACT_REDIRECT_INVALID',
  'RUNTIME_ARTIFACT_TIMEOUT',
  'RUNTIME_CACHE_CLEANUP_FAILED',
  'RUNTIME_CACHE_FAILED',
  'RUNTIME_CACHE_LOCKED',
  'RUNTIME_CACHE_UNSAFE',
  'RUNTIME_DOWNLOAD_FAILED',
]);
const PROVISION_CODES = new Set([
  'RUNTIME_ACTIVATION_FAILED',
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_ARTIFACT_INVALID',
  'RUNTIME_COMPLETION_UNCERTAIN',
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_INSTALL_FAILED',
  'RUNTIME_INVENTORY_CHANGED',
  'RUNTIME_INVENTORY_FAILED',
  'RUNTIME_INVENTORY_INVALID',
  'RUNTIME_OPERATION_CONFLICT',
  'RUNTIME_ROLLBACK_INCOMPLETE',
  'RUNTIME_SELF_TEST_FAILED',
  'RUNTIME_SIGNATURE_INVALID',
  'RUNTIME_STAGE_FAILED',
  'RUNTIME_STATE_UNSUPPORTED',
]);
const INTRINSIC_APPLY = Reflect.apply;
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
  return descriptor !== undefined
    && Object.hasOwn(descriptor, 'value')
    && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
}

function exactRecord(input, fields, code = 'RUNTIME_INPUT_INVALID') {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code, TypeError);
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    fail(code, TypeError);
  }
  const output = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) fail(code, TypeError);
    output[field] = descriptor.value;
  }
  return output;
}

function exactArray(input, maximum, code = 'RUNTIME_INPUT_INVALID') {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code, TypeError);
  const length = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    length === undefined
    || !Object.hasOwn(length, 'value')
    || !Number.isSafeInteger(length.value)
    || length.value < 0
    || length.value > maximum
  ) fail(code, TypeError);
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== length.value + 1
    || !names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/u.test(name))
  ) fail(code, TypeError);
  const output = [];
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) fail(code, TypeError);
    output.push(descriptor.value);
  }
  return output;
}

function snapshotData(input, state = { nodes: 0 }, depth = 0) {
  state.nodes += 1;
  if (state.nodes > 16_384 || depth > 32) fail('RUNTIME_INPUT_INVALID', TypeError);
  if (input === null || typeof input === 'boolean' || typeof input === 'string') return input;
  if (typeof input === 'number') {
    if (!Number.isSafeInteger(input) || Object.is(input, -0)) {
      fail('RUNTIME_INPUT_INVALID', TypeError);
    }
    return input;
  }
  if (typeof input !== 'object' || isProxy(input)) fail('RUNTIME_INPUT_INVALID', TypeError);
  if (Array.isArray(input)) {
    const values = exactArray(input, 2_048);
    return values.map((value) => snapshotData(value, state, depth + 1));
  }
  if (
    Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || Object.getOwnPropertyNames(input).length > 128
  ) fail('RUNTIME_INPUT_INVALID', TypeError);
  const output = {};
  for (const name of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      fail('RUNTIME_INPUT_INVALID', TypeError);
    }
    output[name] = snapshotData(descriptor.value, state, depth + 1);
  }
  return output;
}

function validateDeviceId(value) {
  if (typeof value !== 'string' || value.length > 64 || !DEVICE_ID_PATTERN.test(value)) {
    fail('RUNTIME_INPUT_INVALID', TypeError);
  }
  return value;
}

function validateProfiles(input) {
  const profiles = exactArray(input, PROFILE_IDS.length);
  if (
    profiles.length === 0
    || profiles.some((profile) => typeof profile !== 'string' || !PROFILE_IDS.includes(profile))
    || new Set(profiles).size !== profiles.length
  ) fail('RUNTIME_INPUT_INVALID', TypeError);
  if (profiles.includes('base')) fail('RUNTIME_PROFILE_UNAVAILABLE');
  if (profiles.length !== 1 || profiles[0] !== 'core') fail('RUNTIME_INPUT_INVALID', TypeError);
  return Object.freeze(['core']);
}

function validateCallable(value) {
  if (typeof value !== 'function' || isProxy(value)) fail('RUNTIME_INPUT_INVALID', TypeError);
  return value;
}

async function invoke(callable, args, invalidCode = 'RUNTIME_INPUT_INVALID') {
  let output;
  try {
    output = INTRINSIC_APPLY(callable, undefined, args);
  } catch (error) {
    throw error;
  }
  if (output !== null && (typeof output === 'object' || typeof output === 'function')) {
    if (isProxy(output)) fail(invalidCode, TypeError);
    if (isPromise(output)) {
      const referencePromise = INTRINSIC_APPLY(INTRINSIC_PROMISE_RESOLVE, Promise, [undefined]);
      const referenceSymbols = Object.getOwnPropertySymbols(referencePromise);
      const outputSymbols = Object.getOwnPropertySymbols(output);
      if (
        Object.getPrototypeOf(output) !== Promise.prototype
        || Object.getOwnPropertyNames(output).length !== 0
        || outputSymbols.length !== referenceSymbols.length
        || outputSymbols.some((symbol) => !referenceSymbols.includes(symbol))
      ) fail(invalidCode, TypeError);
      return new Promise((resolve, reject) => {
        INTRINSIC_APPLY(INTRINSIC_PROMISE_THEN, output, [
          (value) => resolve(Object.freeze({ value })),
          reject,
        ]);
      });
    }
  }
  return Object.freeze({ value: output });
}

function validateDependencies(input) {
  const values = exactRecord(input, DEPENDENCY_FIELDS);
  const output = {};
  for (const field of DEPENDENCY_FIELDS) output[field] = validateCallable(values[field]);
  return Object.freeze(output);
}

async function createDependencies(factory) {
  try {
    validateCallable(factory);
    const { value } = await invoke(factory, []);
    return validateDependencies(value);
  } catch {
    throw runtimeError('RUNTIME_INPUT_INVALID', TypeError);
  }
}

function validateTarget(input, deviceId) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || !Object.isFrozen(input)
  ) fail('RUNTIME_INVENTORY_FAILED');
  const target = exactRecord(
    input,
    ['device', 'identity', 'knownHostsPath'],
    'RUNTIME_INVENTORY_FAILED',
  );
  const device = target.device;
  if (
    device === null
    || typeof device !== 'object'
    || isProxy(device)
    || Array.isArray(device)
    || Object.getPrototypeOf(device) !== Object.prototype
    || Object.getOwnPropertySymbols(device).length !== 0
    || !Object.isFrozen(device)
  ) fail('RUNTIME_INVENTORY_FAILED');
  const id = Object.getOwnPropertyDescriptor(device, 'id');
  if (
    !id
    || !Object.hasOwn(id, 'value')
    || id.enumerable !== true
    || id.value !== deviceId
  ) {
    fail('RUNTIME_INVENTORY_FAILED');
  }
  if (
    target.identity === null
    || typeof target.identity !== 'object'
    || isProxy(target.identity)
    || !Object.isFrozen(target.identity)
  ) fail('RUNTIME_INVENTORY_FAILED');
  const identity = exactRecord(
    target.identity,
    ['privateKeyPath', 'publicKeyPath', 'publicKey'],
    'RUNTIME_INVENTORY_FAILED',
  );
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
  return input;
}

async function loadTarget(dependencies, deviceId) {
  try {
    const { value } = await invoke(dependencies.loadTarget, [deviceId]);
    return validateTarget(value, deviceId);
  } catch {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
}

async function readState(dependencies, deviceId) {
  try {
    const { value } = await invoke(dependencies.readState, [deviceId]);
    const snapshot = validateRuntimeStateRecord(value);
    if (snapshot.deviceId !== deviceId) fail('RUNTIME_STATE_UNSUPPORTED');
    return snapshot;
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(code === 'RUNTIME_ALREADY_RUNNING' ? code : 'RUNTIME_STATE_UNSUPPORTED');
  }
}

async function readInventory(dependencies, target) {
  try {
    const { value } = await invoke(dependencies.readInventory, [target]);
    return validateRuntimeInventory(value);
  } catch (error) {
    const code = safeCode(error);
    if (['RUNTIME_STATE_UNSUPPORTED', 'RUNTIME_INVENTORY_INVALID'].includes(code)) {
      throw runtimeError(code);
    }
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
}

async function loadCatalog(dependencies) {
  try {
    const { value } = await invoke(dependencies.loadCatalog, []);
    return validateRuntimeCatalog(value);
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(code === 'RUNTIME_INTERNAL_ERROR' ? code : 'RUNTIME_INTERNAL_ERROR');
  }
}

function exactTimestamp(clockValue, previous) {
  if (
    clockValue === null
    || typeof clockValue !== 'object'
    || isProxy(clockValue)
    || Object.getPrototypeOf(clockValue) !== Date.prototype
    || Object.getOwnPropertyNames(clockValue).length !== 0
    || Object.getOwnPropertySymbols(clockValue).length !== 0
  ) fail('RUNTIME_INTERNAL_ERROR');
  let milliseconds;
  try {
    milliseconds = Date.prototype.getTime.call(clockValue);
  } catch {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  const previousMs = previous === null ? -1 : Date.parse(previous);
  const next = Math.max(milliseconds, previousMs + 1);
  if (!Number.isSafeInteger(next) || next < 0 || next > 253_402_300_799_999) {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  return next;
}

function timestampSequence(initial) {
  let current = initial - 1;
  return () => {
    current += 1;
    return new Date(current).toISOString();
  };
}

function runtimeState(current, overrides) {
  return {
    schemaVersion: 1,
    deviceId: current.deviceId,
    runtimeStatus: overrides.runtimeStatus,
    requestedProfiles: overrides.requestedProfiles,
    readyProfiles: overrides.readyProfiles ?? [],
    operationId: overrides.operationId,
    manifestDigest: overrides.manifestDigest ?? null,
    generationDigest: overrides.generationDigest ?? null,
    failureCode: overrides.failureCode ?? null,
    updatedAt: overrides.updatedAt,
  };
}

async function transition(dependencies, expected, next, uncertain = false) {
  try {
    const canonicalNext = validateRuntimeStateRecord(next);
    const { value } = await invoke(dependencies.transitionState, [expected, canonicalNext]);
    const saved = validateRuntimeStateRecord(value);
    if (JSON.stringify(saved) !== JSON.stringify(canonicalNext)) {
      fail(uncertain ? 'RUNTIME_COMPLETION_UNCERTAIN' : 'RUNTIME_STATE_UNSUPPORTED');
    }
    return saved;
  } catch (error) {
    const code = safeCode(error);
    if (code === 'RUNTIME_ALREADY_RUNNING') throw runtimeError(code);
    throw runtimeError(uncertain ? 'RUNTIME_COMPLETION_UNCERTAIN' : 'RUNTIME_STATE_UNSUPPORTED');
  }
}

export function runtimePlanFailureCode(reasons) {
  if (reasons.some((reason) => [
    'platform-architecture-unsupported',
    'platform-build-unsupported',
    'windows-powershell-unsupported',
  ].includes(reason))) return 'RUNTIME_PLATFORM_UNSUPPORTED';
  if (reasons.includes('elevation-required')) return 'RUNTIME_ELEVATION_REQUIRED';
  if (reasons.some((reason) => ['pending-reboot', 'runtime-restart-required'].includes(reason))) {
    return 'RUNTIME_REBOOT_REQUIRED';
  }
  if (reasons.some((reason) => [
    'runtime-schema-unsupported',
    'catalog-revision-newer',
    'catalog-revision-equivocation',
    'managed-version-newer',
  ].includes(reason))) return 'RUNTIME_STATE_UNSUPPORTED';
  if (reasons.includes('runtime-operation-conflict')) return 'RUNTIME_OPERATION_CONFLICT';
  if (reasons.includes('disk-insufficient')) return 'RUNTIME_DISK_INSUFFICIENT';
  return 'RUNTIME_INTERNAL_ERROR';
}

function samePlanExceptInventoryDigest(left, right) {
  const leftComparable = { ...left, inventoryDigest: null };
  const rightComparable = { ...right, inventoryDigest: null };
  return JSON.stringify(leftComparable) === JSON.stringify(rightComparable);
}

function exactNoop(plan, inventory) {
  return plan.status === 'actionable'
    && plan.items.length > 0
    && plan.items.every(({ action }) => action === 'present')
    && inventory.runtime.generationVerified
    && typeof inventory.runtime.generationDigest === 'string'
    && SHA256_PATTERN.test(inventory.runtime.generationDigest);
}

function alreadyReady(state, profiles, generationDigest) {
  return state.runtimeStatus === 'READY'
    && state.generationDigest === generationDigest
    && state.requestedProfiles.length === profiles.length
    && state.requestedProfiles.every((profile, index) => profile === profiles[index])
    && profiles.every((profile) => state.readyProfiles.includes(profile));
}

function artifactProjection(artifact) {
  return Object.freeze({
    id: artifact.id,
    version: artifact.version,
    url: artifact.url,
    redirectOrigins: Object.freeze([...artifact.redirectOrigins]),
    bytes: artifact.bytes,
    sha256: artifact.sha256,
  });
}

function validateArtifactResult(input, artifact) {
  const value = exactRecord(input, ARTIFACT_RESULT_FIELDS, 'RUNTIME_ARTIFACT_INVALID');
  if (
    value.artifactId !== artifact.id
    || value.version !== artifact.version
    || value.bytes !== artifact.bytes
    || value.sha256 !== artifact.sha256
    || typeof value.path !== 'string'
    || value.path.length === 0
    || value.path.includes('\0')
    || !isAbsolute(value.path)
    || resolve(value.path) !== value.path
  ) fail('RUNTIME_ARTIFACT_INVALID');
  return Object.freeze({ ...value });
}

function validateProvisionResult(input, expected) {
  const value = exactRecord(input, PROVISION_RESULT_FIELDS, 'RUNTIME_COMPLETION_UNCERTAIN');
  if (
    value.schemaVersion !== 1
    || value.status !== 'committed'
    || value.deviceId !== expected.deviceId
    || typeof value.address !== 'string'
    || isIP(value.address) === 0
    || value.operationId !== expected.operationId
    || value.manifestDigest !== expected.manifestDigest
    || value.generationDigest !== expected.generationDigest
    || value.restartRequired !== false
    || value.failureCode !== null
  ) fail('RUNTIME_COMPLETION_UNCERTAIN');
  return value;
}

async function dependencyValue(dependencies, field, args, fallback, allowed = RUNTIME_CODES) {
  try {
    return (await invoke(dependencies[field], args)).value;
  } catch (error) {
    const code = safeCode(error);
    throw runtimeError(typeof code === 'string' && allowed.has(code) ? code : fallback);
  }
}

async function recordFailure(dependencies, current, code, nextTimestamp) {
  const failed = runtimeState(current, {
    runtimeStatus: 'FAILED',
    requestedProfiles: current.requestedProfiles,
    operationId: current.operationId,
    manifestDigest: current.manifestDigest,
    generationDigest: current.generationDigest,
    failureCode: code,
    updatedAt: nextTimestamp(),
  });
  return transition(dependencies, current, failed, code === 'RUNTIME_COMPLETION_UNCERTAIN');
}

function throwStateFailure(saved) {
  throw runtimeError(saved.failureCode);
}

function validatePreparedRuntimePlan(input) {
  const values = exactRecord(input, PREPARED_APPLY_FIELDS);
  const dependencyValues = exactRecord(values.dependencies, PREPARED_DEPENDENCY_FIELDS);
  const dependencies = {};
  for (const field of PREPARED_DEPENDENCY_FIELDS) {
    dependencies[field] = validateCallable(dependencyValues[field]);
  }
  const current = validateRuntimeStateRecord(values.current);
  const deviceId = validateDeviceId(current.deviceId);
  const requestedProfiles = validateProfiles(values.requestedProfiles);
  const target = validateTarget(values.target, deviceId);
  const catalog = validateRuntimeCatalog(values.catalog);
  const inventory = validateRuntimeInventory(values.inventory);
  const planSnapshot = snapshotData(values.plan);
  const planValues = exactRecord(planSnapshot, PLAN_FIELDS);
  if (
    !Number.isSafeInteger(values.firstTimestampMs)
    || values.firstTimestampMs < 0
    || values.firstTimestampMs > 253_402_300_799_999
    || typeof planValues.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(planValues.operationId)
    || typeof planValues.createdAt !== 'string'
    || Date.parse(planValues.createdAt) !== values.firstTimestampMs
  ) fail('RUNTIME_INPUT_INVALID', TypeError);
  let canonicalPlan;
  try {
    canonicalPlan = createRuntimePlan({
      catalog,
      requestedProfiles,
      inventory,
      deviceId,
      operationId: planValues.operationId,
      createdAt: planValues.createdAt,
    });
  } catch {
    fail('RUNTIME_INPUT_INVALID', TypeError);
  }
  if (JSON.stringify(canonicalPlan) !== JSON.stringify(planSnapshot)) {
    fail('RUNTIME_INPUT_INVALID', TypeError);
  }
  if (INTERMEDIATE_STATUSES.has(current.runtimeStatus)) fail('RUNTIME_ALREADY_RUNNING');
  if (current.runtimeStatus === 'FAILED' && UNCERTAIN_CODES.has(current.failureCode)) {
    fail(current.failureCode);
  }
  if (current.runtimeStatus === 'RECOVERED' && canonicalPlan.operationId === current.operationId) {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  return Object.freeze({
    dependencies: Object.freeze(dependencies),
    target,
    current,
    catalog,
    inventory,
    plan: canonicalPlan,
    requestedProfiles,
    firstTimestampMs: values.firstTimestampMs,
  });
}

export async function applyPreparedRuntimePlan(input) {
  let {
    dependencies,
    target,
    current,
    catalog,
    inventory,
    plan,
    requestedProfiles,
    firstTimestampMs,
  } = validatePreparedRuntimePlan(input);
  const deviceId = current.deviceId;
  const operationId = plan.operationId;
  const nextTimestamp = timestampSequence(firstTimestampMs);

  if (exactNoop(plan, inventory) && alreadyReady(
    current,
    requestedProfiles,
    inventory.runtime.generationDigest,
  )) return current;

  const inventoryReady = runtimeState(current, {
    runtimeStatus: 'INVENTORY_READY',
    requestedProfiles,
    operationId,
    updatedAt: nextTimestamp(),
  });
  current = await transition(dependencies, current, inventoryReady);

  if (plan.status === 'blocked') {
    const saved = await recordFailure(
      dependencies,
      current,
      runtimePlanFailureCode(plan.blockedReasons),
      nextTimestamp,
    );
    throwStateFailure(saved);
  }

  if (exactNoop(plan, inventory)) {
    const ready = runtimeState(current, {
      runtimeStatus: 'READY',
      requestedProfiles,
      readyProfiles: requestedProfiles,
      operationId: null,
      generationDigest: inventory.runtime.generationDigest,
      updatedAt: nextTimestamp(),
    });
    return transition(dependencies, current, ready);
  }

  let capsule;
  try {
    capsule = await createSignedRuntimeManifest({
      catalog,
      inventory,
      plan,
      dependencies: {
        getSigningPublicKey: dependencies.getSigningPublicKey,
        sign: dependencies.sign,
      },
    });
  } catch {
    const saved = await recordFailure(
      dependencies,
      current,
      'RUNTIME_SIGNATURE_INVALID',
      nextTimestamp,
    );
    throwStateFailure(saved);
  }

  current = await transition(dependencies, current, runtimeState(current, {
    runtimeStatus: 'PLAN_READY',
    requestedProfiles,
    operationId,
    manifestDigest: capsule.manifestDigest,
    generationDigest: capsule.generationDigest,
    updatedAt: nextTimestamp(),
  }));
  current = await transition(dependencies, current, runtimeState(current, {
    runtimeStatus: 'ACQUIRING',
    requestedProfiles,
    operationId,
    manifestDigest: capsule.manifestDigest,
    generationDigest: capsule.generationDigest,
    updatedAt: nextTimestamp(),
  }));

  const resolution = resolveRuntimeProfiles(catalog, requestedProfiles);
  const artifactFiles = [];
  try {
    for (const artifact of resolution.artifacts) {
      const projection = artifactProjection(artifact);
      const acquired = await dependencyValue(
        dependencies,
        'acquireArtifact',
        [projection],
        'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
      );
      artifactFiles.push(validateArtifactResult(acquired, projection));
    }
  } catch (error) {
    const code = ACQUISITION_CODES.has(safeCode(error))
      ? safeCode(error)
      : 'RUNTIME_ARTIFACT_ACQUISITION_FAILED';
    const saved = await recordFailure(dependencies, current, code, nextTimestamp);
    throwStateFailure(saved);
  }

  let provisioned;
  try {
    provisioned = await dependencyValue(
      dependencies,
      'provision',
      [Object.freeze({
        target,
        plan,
        capsule,
        inventorySnapshot: inventory,
        artifactFiles: Object.freeze(artifactFiles),
      })],
      'RUNTIME_COMPLETION_UNCERTAIN',
    );
    validateProvisionResult(provisioned, {
      deviceId,
      operationId,
      manifestDigest: capsule.manifestDigest,
      generationDigest: capsule.generationDigest,
    });
  } catch (error) {
    const code = PROVISION_CODES.has(safeCode(error))
      ? safeCode(error)
      : 'RUNTIME_COMPLETION_UNCERTAIN';
    const saved = await recordFailure(dependencies, current, code, nextTimestamp);
    throwStateFailure(saved);
  }

  const ready = runtimeState(current, {
    runtimeStatus: 'READY',
    requestedProfiles,
    readyProfiles: requestedProfiles,
    operationId,
    manifestDigest: capsule.manifestDigest,
    generationDigest: capsule.generationDigest,
    updatedAt: nextTimestamp(),
  });
  try {
    return await transition(dependencies, current, ready, true);
  } catch {
    try {
      await recordFailure(
        dependencies,
        current,
        'RUNTIME_COMPLETION_UNCERTAIN',
        nextTimestamp,
      );
    } catch {}
    throw runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
  }
}

export async function ensureRuntime(input) {
  const values = exactRecord(input, ENSURE_FIELDS);
  const deviceId = validateDeviceId(values.deviceId);
  const requestedProfiles = validateProfiles(values.requestedProfiles);
  const dependencies = await createDependencies(values.dependencyFactory);
  const target = await loadTarget(dependencies, deviceId);
  let current = await readState(dependencies, deviceId);

  if (INTERMEDIATE_STATUSES.has(current.runtimeStatus)) fail('RUNTIME_ALREADY_RUNNING');
  if (current.runtimeStatus === 'FAILED' && UNCERTAIN_CODES.has(current.failureCode)) {
    fail(current.failureCode);
  }

  const operationId = await dependencyValue(
    dependencies,
    'operationId',
    [],
    'RUNTIME_INTERNAL_ERROR',
    new Set(),
  );
  if (typeof operationId !== 'string' || !OPERATION_ID_PATTERN.test(operationId)) {
    fail('RUNTIME_INTERNAL_ERROR');
  }
  if (current.runtimeStatus === 'RECOVERED' && operationId === current.operationId) {
    fail('RUNTIME_STATE_UNSUPPORTED');
  }
  const clock = await dependencyValue(
    dependencies,
    'clock',
    [],
    'RUNTIME_INTERNAL_ERROR',
    new Set(),
  );
  const firstTimestampMs = exactTimestamp(clock, current.updatedAt);
  const createdAt = new Date(firstTimestampMs).toISOString();
  const catalog = await loadCatalog(dependencies);
  const firstInventory = await readInventory(dependencies, target);
  const firstPlan = createRuntimePlan({
    catalog,
    requestedProfiles,
    inventory: firstInventory,
    deviceId,
    operationId,
    createdAt,
  });
  const secondInventory = await readInventory(dependencies, target);
  const plan = createRuntimePlan({
    catalog,
    requestedProfiles,
    inventory: secondInventory,
    deviceId,
    operationId,
    createdAt,
  });
  if (
    !samePlanExceptInventoryDigest(firstPlan, plan)
    || !runtimeInventoriesSemanticallyEqual(
      firstInventory,
      secondInventory,
      plan.requiredFreeBytes,
    )
  ) fail('RUNTIME_INVENTORY_CHANGED');

  return applyPreparedRuntimePlan({
    dependencies: {
      transitionState: dependencies.transitionState,
      getSigningPublicKey: dependencies.getSigningPublicKey,
      sign: dependencies.sign,
      acquireArtifact: dependencies.acquireArtifact,
      provision: dependencies.provision,
    },
    target,
    current,
    catalog,
    inventory: secondInventory,
    plan,
    requestedProfiles,
    firstTimestampMs,
  });
}

async function queryInput(input) {
  const values = exactRecord(input, QUERY_FIELDS);
  const deviceId = validateDeviceId(values.deviceId);
  const dependencies = await createDependencies(values.dependencyFactory);
  const target = await loadTarget(dependencies, deviceId);
  return Object.freeze({ deviceId, dependencies, target });
}

export async function doctorRuntime(input) {
  const query = await queryInput(input);
  return readInventory(query.dependencies, query.target);
}

export async function runtimeStatus(input) {
  const query = await queryInput(input);
  return readState(query.dependencies, query.deviceId);
}
