import { isIP } from 'node:net';
import { isProxy } from 'node:util/types';
import { fileURLToPath } from 'node:url';

import { markProvisionFailure, provisionFailureStage } from './provision-diagnostic.mjs';
import {
  executePreparedRemoteScriptInSession,
  withPreparedRemoteScript,
  withPreparedRemoteScriptBytes,
} from '../remote/remote-exec.mjs';
import { trustedInput } from '../remote/remote-target.mjs';
import { selectAddress } from '../remote/windows-remote.mjs';
import { withTrustedSshSession } from '../ssh/trusted-ssh-session.mjs';
import {
  getPreparedProvisionUploadBinding,
  stagePreparedProvisionUploadInSession,
  withPreparedProvisionUpload,
} from './provision-upload.mjs';
import {
  parseRuntimeInventoryExecution,
  RUNTIME_INVENTORY_SCRIPT_PATH,
} from './runtime-doctor.mjs';
import {
  digestRuntimeInventory,
  runtimeInventoriesSemanticallyEqual,
  validateRuntimeInventory,
} from './runtime-inventory.mjs';

const PROVISION_SCRIPT_PATH = fileURLToPath(
  new URL('../../windows/runtime-provision-core.ps1', import.meta.url),
);
export const RUNTIME_PROVISION_SCRIPT_PATH = PROVISION_SCRIPT_PATH;

const INVENTORY_TIMEOUT_MS = 120_000;
const PROVISION_TIMEOUT_MS = 1_800_000;
const MIN_LOCK_TIMEOUT_MS = 1_000;
const MAX_LOCK_TIMEOUT_MS = 15 * 60 * 1_000;
const INPUT_FIELDS = Object.freeze([
  'target',
  'plan',
  'capsule',
  'inventorySnapshot',
  'artifactFiles',
  'dependencies',
]);
const DEPENDENCY_FIELDS = Object.freeze([
  'runProcess',
  'operationId',
  'clock',
  'sshLockTimeoutMs',
]);
const AUTHORIZED_SOURCE_FIELDS = Object.freeze([
  'inventoryScriptBytes',
  'provisionScriptBytes',
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
const PLAN_ITEM_FIELDS = Object.freeze([
  'artifactId',
  'action',
  'reason',
  'desired',
  'current',
  'rollbackVersion',
]);
const PLAN_DESIRED_FIELDS = Object.freeze([
  'version',
  'bytes',
  'maximumExpandedBytes',
  'sha256',
]);
const PLAN_CURRENT_FIELDS = Object.freeze([
  'version',
  'bytes',
  'sha256',
  'verified',
]);

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
const EXPECTED_FIELDS = Object.freeze([
  'deviceId',
  'address',
  'operationId',
  'manifestDigest',
  'generationDigest',
]);
const RESULT_FIELDS = Object.freeze([
  'schemaVersion',
  'status',
  'operationId',
  'manifestDigest',
  'generationDigest',
  'restartRequired',
  'failureCode',
]);
const FAILURE_CODES = new Set([
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_OPERATION_CONFLICT',
  'RUNTIME_STATE_UNSUPPORTED',
  'RUNTIME_INVENTORY_CHANGED',
  'RUNTIME_SIGNATURE_INVALID',
  'RUNTIME_ARTIFACT_INVALID',
  'RUNTIME_SELF_TEST_FAILED',
  'RUNTIME_ACTIVATION_FAILED',
  'RUNTIME_COMPLETION_UNCERTAIN',
  'RUNTIME_ROLLBACK_INCOMPLETE',
  'RUNTIME_INTERNAL_ERROR',
]);
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const MAX_RESULT_BYTES = 4_096;
const MAX_ARTIFACT_BYTES = 256 * 1024 ** 2;
const MAX_EXPANDED_BYTES = 32 * 1024 ** 3;
const TRANSACTION_RESERVE_BYTES = 256 * 1024 ** 2;
const DEFINITIVE_CODES = new Set([
  ...FAILURE_CODES,
  'RUNTIME_INVENTORY_INVALID',
  'RUNTIME_INVENTORY_FAILED',
  'RUNTIME_STATE_UNSUPPORTED',
  'RUNTIME_STAGE_FAILED',
  'RUNTIME_INSTALL_FAILED',
]);
const VALIDATED_TARGET_FAILURES = new WeakSet();

function runtimeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function validatedTargetFailure(code) {
  const error = runtimeError(code);
  VALIDATED_TARGET_FAILURES.add(error);
  return error;
}

function readExactRecord(input, fields, code) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw runtimeError(code);
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== fields.length
    || !fields.every((field, index) => names[index] === field)
  ) throw runtimeError(code);
  const values = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw runtimeError(code);
    values[field] = descriptor.value;
  }
  return values;
}

function readExactUnorderedRecord(input, fields, code) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw runtimeError(code);
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== fields.length
    || !fields.every((field) => names.includes(field))
  ) throw runtimeError(code);
  const values = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw runtimeError(code);
    values[field] = descriptor.value;
  }
  return values;
}

function readExactArray(input, maximum, code) {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw runtimeError(code);
  const length = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    length === undefined
    || !Object.hasOwn(length, 'value')
    || !Number.isInteger(length.value)
    || length.value < 0
    || length.value > maximum
  ) throw runtimeError(code);
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== length.value + 1
    || !names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/u.test(name))
  ) throw runtimeError(code);
  const values = [];
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw runtimeError(code);
    values.push(descriptor.value);
  }
  return values;
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

function validateStringArray(input, maximum, allowed) {
  const values = readExactArray(input, maximum, 'RUNTIME_INPUT_INVALID');
  if (
    values.some((value) => typeof value !== 'string' || !allowed.includes(value))
    || new Set(values).size !== values.length
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
  return Object.freeze([...values]);
}

function validVersion(value) {
  return typeof value === 'string'
    && value.length <= 64
    && VERSION_PATTERN.test(value);
}

function compareVersions(left, right) {
  const leftParts = left.split('.').map((part) => BigInt(part));
  const rightParts = right.split('.').map((part) => BigInt(part));
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] < rightParts[index]) return -1;
    if (leftParts[index] > rightParts[index]) return 1;
  }
  return 0;
}

function validateDesiredPlanArtifact(input) {
  const value = readExactUnorderedRecord(
    input,
    PLAN_DESIRED_FIELDS,
    'RUNTIME_INPUT_INVALID',
  );
  if (
    !validVersion(value.version)
    || !Number.isSafeInteger(value.bytes)
    || value.bytes < 1
    || value.bytes > MAX_ARTIFACT_BYTES
    || !Number.isSafeInteger(value.maximumExpandedBytes)
    || value.maximumExpandedBytes < 1
    || value.maximumExpandedBytes > MAX_EXPANDED_BYTES
    || typeof value.sha256 !== 'string'
    || !SHA256_PATTERN.test(value.sha256)
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
  return value;
}

function validateCurrentPlanArtifact(input) {
  if (input === null) return null;
  const value = readExactUnorderedRecord(
    input,
    PLAN_CURRENT_FIELDS,
    'RUNTIME_INPUT_INVALID',
  );
  const nullBytes = value.bytes === null;
  const nullHash = value.sha256 === null;
  if (
    !validVersion(value.version)
    || typeof value.verified !== 'boolean'
    || nullBytes !== nullHash
    || (!nullBytes && (
      !Number.isSafeInteger(value.bytes)
      || value.bytes < 1
      || value.bytes > MAX_ARTIFACT_BYTES
    ))
    || (!nullHash && (typeof value.sha256 !== 'string' || !SHA256_PATTERN.test(value.sha256)))
    || (value.verified && nullBytes)
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
  return value;
}

function validatePlanItem(input) {
  const item = readExactUnorderedRecord(input, PLAN_ITEM_FIELDS, 'RUNTIME_INPUT_INVALID');
  const desired = validateDesiredPlanArtifact(item.desired);
  const current = validateCurrentPlanArtifact(item.current);
  const reasonByAction = {
    install: 'managed-artifact-missing',
    repair: 'managed-artifact-invalid',
    upgrade: 'managed-version-older',
  };
  if (
    item.artifactId !== 'powershell-7'
    || typeof item.action !== 'string'
    || !Object.hasOwn(reasonByAction, item.action)
    || item.reason !== reasonByAction[item.action]
    || ((item.action === 'install') !== (current === null))
    || (item.action !== 'install' && current.version !== desired.version
      && item.action !== 'upgrade')
    || (item.action === 'upgrade' && (
      current === null || compareVersions(current.version, desired.version) >= 0
    ))
    || (item.action === 'present' && (
      !current.verified
      || current.bytes !== desired.bytes
      || current.sha256 !== desired.sha256
    ))
    || (item.rollbackVersion !== null && (
      item.action !== 'upgrade'
      || !validVersion(item.rollbackVersion)
      || item.rollbackVersion !== current.version
    ))
    || (item.action !== 'upgrade' && item.rollbackVersion !== null)
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
  return Object.freeze({
    action: item.action,
    desired: Object.freeze({ ...desired }),
  });
}

function validatePlan(input) {
  const value = readExactUnorderedRecord(input, PLAN_FIELDS, 'RUNTIME_INPUT_INVALID');
  const requestedProfiles = validateStringArray(value.requestedProfiles, 1, ['core']);
  const profiles = validateStringArray(value.profiles, 1, ['core']);
  const blockedReasons = readExactArray(value.blockedReasons, 0, 'RUNTIME_INPUT_INVALID');
  const items = readExactArray(value.items, 1, 'RUNTIME_INPUT_INVALID');
  if (items.length !== 1) throw runtimeError('RUNTIME_INPUT_INVALID');
  const item = validatePlanItem(items[0]);
  const requiredFreeBytes = TRANSACTION_RESERVE_BYTES
    + item.desired.bytes
    + item.desired.maximumExpandedBytes;
  if (
    value.schemaVersion !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || !canonicalTimestamp(value.createdAt)
    || typeof value.deviceId !== 'string'
    || value.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || typeof value.inventoryDigest !== 'string'
    || !SHA256_PATTERN.test(value.inventoryDigest)
    || typeof value.catalogDigest !== 'string'
    || !SHA256_PATTERN.test(value.catalogDigest)
    || profiles.length !== 1
    || profiles[0] !== 'core'
    || value.acquisition !== 'mac-relay'
    || !['new', 'reconcile'].includes(value.transactionMode)
    || value.status !== 'actionable'
    || blockedReasons.length !== 0
    || !Number.isSafeInteger(value.requiredFreeBytes)
    || value.requiredFreeBytes < 0
    || value.requiredFreeBytes !== requiredFreeBytes
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
  return Object.freeze({
    operationId: value.operationId,
    deviceId: value.deviceId,
    inventoryDigest: value.inventoryDigest,
    catalogDigest: value.catalogDigest,
    requiredFreeBytes: value.requiredFreeBytes,
    requestedProfiles,
    profiles,
    item,
  });
}

function validateControllerInput(input) {
  const value = readExactUnorderedRecord(input, INPUT_FIELDS, 'RUNTIME_INPUT_INVALID');
  const plan = validatePlan(value.plan);
  const inventorySnapshot = validateRuntimeInventory(value.inventorySnapshot);
  const dependencies = readExactUnorderedRecord(
    value.dependencies,
    DEPENDENCY_FIELDS,
    'RUNTIME_INPUT_INVALID',
  );
  if (
    ['runProcess', 'operationId', 'clock'].some((field) => (
      typeof dependencies[field] !== 'function' || isProxy(dependencies[field])
    ))
    || !Number.isSafeInteger(dependencies.sshLockTimeoutMs)
    || dependencies.sshLockTimeoutMs < MIN_LOCK_TIMEOUT_MS
    || dependencies.sshLockTimeoutMs > MAX_LOCK_TIMEOUT_MS
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
  if (
    digestRuntimeInventory(inventorySnapshot) !== plan.inventoryDigest
    || inventorySnapshot.freeBytes < plan.requiredFreeBytes
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
  return Object.freeze({
    target: value.target,
    plan,
    capsule: value.capsule,
    inventorySnapshot,
    artifactFiles: value.artifactFiles,
    dependencies: Object.freeze({ ...dependencies }),
  });
}

function canonicalAuthorizedSource(input) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Buffer.isBuffer(input)
    || Object.getPrototypeOf(input) !== Buffer.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || input.length < 1
    || input.length > 1024 * 1024
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== input.length
    || !names.every((name, index) => name === String(index))
    || (typeof SharedArrayBuffer === 'function' && input.buffer instanceof SharedArrayBuffer)
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
  return Buffer.from(input);
}

function validateAuthorizedSources(input) {
  const value = readExactUnorderedRecord(
    input,
    AUTHORIZED_SOURCE_FIELDS,
    'RUNTIME_INPUT_INVALID',
  );
  return Object.freeze({
    inventoryScriptBytes: canonicalAuthorizedSource(value.inventoryScriptBytes),
    provisionScriptBytes: canonicalAuthorizedSource(value.provisionScriptBytes),
  });
}

function sameStrings(left, right) {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function assertPlanBinding(plan, binding) {
  const components = Array.isArray(binding.components) ? binding.components : [];
  const component = components.length === 1 ? components[0] : null;
  if (
    binding.schemaVersion !== 1
    || binding.deviceId !== plan.deviceId
    || binding.operationId !== plan.operationId
    || binding.inventoryDigest !== plan.inventoryDigest
    || binding.catalogDigest !== plan.catalogDigest
    || !sameStrings(binding.requestedProfiles, plan.requestedProfiles)
    || !sameStrings(binding.profiles, plan.profiles)
    || component === null
    || component.id !== 'powershell-7'
    || component.version !== plan.item.desired.version
    || component.bytes !== plan.item.desired.bytes
    || component.maximumExpandedBytes !== plan.item.desired.maximumExpandedBytes
    || component.sha256 !== plan.item.desired.sha256
  ) throw runtimeError('RUNTIME_INPUT_INVALID');
}

function mapControllerFailure(error, phase, mutationStarted) {
  const code = safeCode(error);
  if (VALIDATED_TARGET_FAILURES.has(error)) {
    // Only the exact, bound terminal result/exit matrix grants finite failure.
    // The durable state vocabulary uses INSTALL_FAILED for a target internal error.
    return runtimeError(code === 'RUNTIME_INTERNAL_ERROR' ? 'RUNTIME_INSTALL_FAILED' : code);
  }
  if (code === 'RUNTIME_COMPLETION_UNCERTAIN') {
    return runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
  }
  if (code === 'RUNTIME_ROLLBACK_INCOMPLETE') {
    return runtimeError('RUNTIME_ROLLBACK_INCOMPLETE');
  }
  if (mutationStarted) {
    if (phase === 'stage' && code === 'RUNTIME_STAGE_FAILED') {
      return runtimeError('RUNTIME_STAGE_FAILED');
    }
    return runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
  }
  if (DEFINITIVE_CODES.has(code)) return runtimeError(code);
  if (phase === 'inventory' || phase === 'connection') {
    return runtimeError('RUNTIME_INVENTORY_FAILED');
  }
  if (phase === 'stage') return runtimeError('RUNTIME_STAGE_FAILED');
  if (phase === 'apply') return runtimeError('RUNTIME_INSTALL_FAILED');
  return runtimeError('RUNTIME_INPUT_INVALID');
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function validateExpectedBinding(input) {
  const value = readExactRecord(input, EXPECTED_FIELDS, 'RUNTIME_COMPLETION_UNCERTAIN');
  if (
    typeof value.deviceId !== 'string'
    || value.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || typeof value.address !== 'string'
    || isIP(value.address) === 0
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || typeof value.manifestDigest !== 'string'
    || !SHA256_PATTERN.test(value.manifestDigest)
    || typeof value.generationDigest !== 'string'
    || !SHA256_PATTERN.test(value.generationDigest)
  ) throw runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
  return value;
}

function validateExecution(input, expected) {
  const value = readExactRecord(input, EXECUTION_FIELDS, 'RUNTIME_COMPLETION_UNCERTAIN');
  if (
    value.schemaVersion !== 1
    || value.operation !== 'exec'
    || value.deviceId !== expected.deviceId
    || value.address !== expected.address
    || !Number.isInteger(value.exitCode)
    || value.exitCode < 0
    || value.exitCode > 255
    || typeof value.stdout !== 'string'
    || Buffer.byteLength(value.stdout, 'utf8') === 0
    || Buffer.byteLength(value.stdout, 'utf8') > MAX_RESULT_BYTES
    || value.stderr !== ''
    || !canonicalTimestamp(value.startedAt)
    || !canonicalTimestamp(value.finishedAt)
    || value.finishedAt < value.startedAt
  ) throw runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
  return value;
}

function parseResult(raw, expected) {
  let parsed;
  let value;
  try {
    parsed = JSON.parse(raw);
    value = readExactRecord(parsed, RESULT_FIELDS, 'RUNTIME_COMPLETION_UNCERTAIN');
  } catch {
    throw runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
  }
  if (
    JSON.stringify(parsed) !== raw
    || value.schemaVersion !== 1
    || !['committed', 'failed', 'uncertain', 'rolled-back'].includes(value.status)
    || value.operationId !== expected.operationId
    || value.manifestDigest !== expected.manifestDigest
    || value.generationDigest !== expected.generationDigest
    || value.restartRequired !== false
    || (value.failureCode !== null && !FAILURE_CODES.has(value.failureCode))
  ) throw runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
  return value;
}

export function parseRuntimeProvisionExecution(input, expectedInput) {
  const expected = validateExpectedBinding(expectedInput);
  const execution = validateExecution(input, expected);
  const result = parseResult(execution.stdout, expected);
  if (
    result.status === 'committed'
    && execution.exitCode === 0
    && result.failureCode === null
  ) {
    return Object.freeze({
      schemaVersion: 1,
      status: 'committed',
      deviceId: expected.deviceId,
      address: expected.address,
      operationId: result.operationId,
      manifestDigest: result.manifestDigest,
      generationDigest: result.generationDigest,
      restartRequired: false,
      failureCode: null,
    });
  }
  const matrixMatches = (
    (result.status === 'failed'
      && execution.exitCode === 1
      && result.failureCode !== null
      && !['RUNTIME_COMPLETION_UNCERTAIN', 'RUNTIME_ROLLBACK_INCOMPLETE'].includes(result.failureCode))
    || (result.status === 'rolled-back'
      && execution.exitCode === 2
      && result.failureCode !== null
      && !['RUNTIME_COMPLETION_UNCERTAIN', 'RUNTIME_ROLLBACK_INCOMPLETE'].includes(result.failureCode))
    || (result.status === 'uncertain'
      && execution.exitCode === 3
      && result.failureCode === 'RUNTIME_COMPLETION_UNCERTAIN')
    || (result.status === 'uncertain'
      && execution.exitCode === 4
      && result.failureCode === 'RUNTIME_ROLLBACK_INCOMPLETE')
  );
  if (!matrixMatches) throw runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
  throw validatedTargetFailure(result.failureCode);
}

async function runRuntimeProvision(input, authorizedSourceInput) {
  let config;
  let trust;
  let phase = 'input';
  let mutationStarted = false;
  try {
    config = validateControllerInput(input);
    const authorizedSources = authorizedSourceInput === null
      ? null
      : validateAuthorizedSources(authorizedSourceInput);
    trust = trustedInput(config.target, config.dependencies.runProcess);
    const scriptDependencies = {
      runProcess: config.dependencies.runProcess,
      operationId: config.dependencies.operationId,
      clock: config.dependencies.clock,
      sshLockTimeoutMs: config.dependencies.sshLockTimeoutMs,
    };
    const prepareScript = authorizedSources === null
      ? withPreparedRemoteScript
      : withPreparedRemoteScriptBytes;
    return await prepareScript({
      target: config.target,
      ...(authorizedSources === null
        ? { scriptPath: RUNTIME_INVENTORY_SCRIPT_PATH }
        : { scriptBytes: authorizedSources.inventoryScriptBytes }),
      timeoutMs: INVENTORY_TIMEOUT_MS,
      dependencies: scriptDependencies,
    }, async (preparedInventory) => withPreparedProvisionUpload({
      target: config.target,
      capsule: config.capsule,
      artifactFiles: config.artifactFiles,
      dependencies: {
        runProcess: config.dependencies.runProcess,
        sshLockTimeoutMs: config.dependencies.sshLockTimeoutMs,
      },
    }, async (preparedUpload) => {
      const binding = getPreparedProvisionUploadBinding(preparedUpload);
      assertPlanBinding(config.plan, binding);
      return prepareScript({
        target: config.target,
        ...(authorizedSources === null
          ? { scriptPath: PROVISION_SCRIPT_PATH }
          : { scriptBytes: authorizedSources.provisionScriptBytes }),
        timeoutMs: PROVISION_TIMEOUT_MS,
        dependencies: scriptDependencies,
      }, async (preparedProvisioner) => {
        phase = 'connection';
        return withTrustedSshSession(
          trust,
          async (session) => {
            const address = await selectAddress(session);
            phase = 'inventory';
            const inventoryExecution = await executePreparedRemoteScriptInSession(
              preparedInventory,
              session,
              address,
            );
            const inventory = parseRuntimeInventoryExecution(inventoryExecution, {
              deviceId: binding.deviceId,
              address,
            });
            if (
              inventory.freeBytes < config.plan.requiredFreeBytes
              || !runtimeInventoriesSemanticallyEqual(
                config.inventorySnapshot,
                inventory,
                config.plan.requiredFreeBytes,
              )
            ) {
              throw runtimeError('RUNTIME_INVENTORY_CHANGED');
            }

            phase = 'stage';
            mutationStarted = true;
            await stagePreparedProvisionUploadInSession(preparedUpload, session, address);

            phase = 'apply';
            const provisionExecution = await executePreparedRemoteScriptInSession(
              preparedProvisioner,
              session,
              address,
            );
            return parseRuntimeProvisionExecution(provisionExecution, {
              deviceId: binding.deviceId,
              address,
              operationId: binding.operationId,
              manifestDigest: binding.manifestDigest,
              generationDigest: binding.generationDigest,
            });
          },
          { lockTimeoutMs: config.dependencies.sshLockTimeoutMs },
        );
      }, {
        runtimeTransaction: {
          operationId: binding.operationId,
          manifestDigest: binding.manifestDigest,
        },
      });
    }));
  } catch (error) {
    throw markProvisionFailure(mapControllerFailure(error, phase, mutationStarted), provisionFailureStage(error));
  }
}

export async function runtimeProvision(input) {
  return runRuntimeProvision(input, null);
}

export async function runtimeProvisionFromAuthorizedSources(input, authorizedSources) {
  return runRuntimeProvision(input, authorizedSources);
}
