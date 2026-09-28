import { createHash } from 'node:crypto';
import { isProxy } from 'node:util/types';

import { isWindowsInspectStage, markRecoveryInspectStage } from './recovery-inspect-stage.mjs';

import { trustedInput } from '../remote/remote-target.mjs';
import {
  WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER,
  WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER,
  encodeRemotePayload,
  powershellInvocation,
  selectAddress,
} from '../remote/windows-remote.mjs';
import {
  isTrustedSshSessionLockError,
  withTrustedSshSession,
} from '../ssh/trusted-ssh-session.mjs';
import {
  runtimeRecoveryAuthorizedAttemptDigest,
  runtimeRecoveryProofDigest,
  validateRuntimeRecoveryBootMarker,
} from './runtime-recovery-store.mjs';

const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const DIGEST_PATTERN = /^[A-F0-9]{64}$/u;
const TICKET_ID_PATTERN = /^rct_[a-f0-9]{64}$/u;
const INSPECT_TIMEOUT_MS = 30_000;
const APPLY_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_BYTES = 32_768;
const REJECTION_EXIT_CODE = 73;
const ACL_DIGEST = 'DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44';
const INSPECT_FIELDS = Object.freeze([
  'target',
  'operationId',
  'beforeBootMarker',
  'priorAuthorizedAttempt',
  'dependencies',
]);
const APPLY_FIELDS = Object.freeze([
  'target',
  'proof',
  'authorizedAttempt',
  'dependencies',
]);
const DEPENDENCY_FIELDS = Object.freeze(['runProcess', 'sshLockTimeoutMs']);
const PRIOR_ATTEMPT_FIELDS = Object.freeze(['ticketId', 'attemptDigest']);
const PROCESS_FIELDS = new Set(['command', 'args', 'exitCode', 'signal', 'stdout', 'stderr']);
const RAW_INSPECT_FIELDS = Object.freeze([
  'schemaVersion',
  'rawClassification',
  'bootMarker',
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
const INSPECT_REJECTIONS = new Set([
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
  'RUNTIME_REBOOT_REQUIRED',
  'RUNTIME_OPERATION_CONFLICT',
  'RUNTIME_STATE_UNSUPPORTED',
]);
const APPLY_REJECTIONS = new Set([
  ...INSPECT_REJECTIONS,
  'RUNTIME_ALREADY_RUNNING',
]);
const ACKNOWLEDGED_REJECTIONS = new WeakSet();
const INSPECT_REJECTION_STAGES = new WeakMap();
const NOOP_RUN_PROCESS = Object.freeze(async () => {});

function runtimeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function failInput() {
  throw runtimeError('RUNTIME_INPUT_INVALID');
}

function acknowledgedRejection(code) {
  const error = runtimeError(code);
  ACKNOWLEDGED_REJECTIONS.add(error);
  return error;
}

function exactFrozenObject(input, fields) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || !Object.isFrozen(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) failInput();
  const value = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      !descriptor
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) failInput();
    value[field] = descriptor.value;
  }
  return value;
}

function assertDeepFrozenPlainData(input, ancestors = new WeakSet()) {
  if (input === null) return;
  if (['string', 'boolean'].includes(typeof input)) return;
  if (typeof input === 'number') {
    if (!Number.isFinite(input) || Object.is(input, -0)) failInput();
    return;
  }
  if (
    typeof input !== 'object'
    || isProxy(input)
    || !Object.isFrozen(input)
    || ancestors.has(input)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();
  const array = Array.isArray(input);
  const prototype = Object.getPrototypeOf(input);
  if (
    (array && prototype !== Array.prototype)
    || (!array && prototype !== Object.prototype)
  ) failInput();
  ancestors.add(input);
  try {
    const names = Object.getOwnPropertyNames(input);
    if (array) {
      const length = Object.getOwnPropertyDescriptor(input, 'length');
      if (
        !length
        || !Object.hasOwn(length, 'value')
        || names.length !== length.value + 1
      ) failInput();
      for (let index = 0; index < length.value; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) failInput();
        assertDeepFrozenPlainData(descriptor.value, ancestors);
      }
      return;
    }
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(input, name);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) failInput();
      assertDeepFrozenPlainData(descriptor.value, ancestors);
    }
  } finally {
    ancestors.delete(input);
  }
}

function dependencies(input) {
  const value = exactFrozenObject(input, DEPENDENCY_FIELDS);
  if (
    typeof value.runProcess !== 'function'
    || isProxy(value.runProcess)
    || !Number.isSafeInteger(value.sshLockTimeoutMs)
    || value.sshLockTimeoutMs < 1_000
    || value.sshLockTimeoutMs > 900_000
  ) failInput();
  return Object.freeze({
    runProcess: value.runProcess,
    sshLockTimeoutMs: value.sshLockTimeoutMs,
  });
}

function priorAuthorizedAttempt(input) {
  if (input === null) return null;
  assertDeepFrozenPlainData(input);
  const value = exactFrozenObject(input, PRIOR_ATTEMPT_FIELDS);
  if (
    typeof value.ticketId !== 'string'
    || !TICKET_ID_PATTERN.test(value.ticketId)
    || typeof value.attemptDigest !== 'string'
    || !DIGEST_PATTERN.test(value.attemptDigest)
  ) failInput();
  return Object.freeze({
    ticketId: value.ticketId,
    attemptDigest: value.attemptDigest,
  });
}

function bootMarker(input) {
  if (input === null) return null;
  assertDeepFrozenPlainData(input);
  try {
    return validateRuntimeRecoveryBootMarker(input);
  } catch {
    failInput();
  }
}

function trustedTarget(input, runProcess) {
  assertDeepFrozenPlainData(input);
  try {
    return trustedInput(input, runProcess);
  } catch {
    failInput();
  }
}

function targetDigestFromTrust(trust) {
  const binding = {
    deviceId: trust.deviceId,
    sshHostKeyFingerprints: [...trust.fingerprints].sort(),
  };
  return createHash('sha256')
    .update('AGENT_ROAD_RUNTIME_RECOVERY_TARGET_V1\0', 'utf8')
    .update(JSON.stringify(binding), 'utf8')
    .digest('hex')
    .toUpperCase();
}

export function runtimeRecoveryTargetBindingDigest(inputTarget) {
  return targetDigestFromTrust(trustedTarget(inputTarget, NOOP_RUN_PROCESS));
}

function inspectInput(input) {
  const value = exactFrozenObject(input, INSPECT_FIELDS);
  if (typeof value.operationId !== 'string' || !OPERATION_ID_PATTERN.test(value.operationId)) {
    failInput();
  }
  const configDependencies = dependencies(value.dependencies);
  const trust = trustedTarget(value.target, configDependencies.runProcess);
  return Object.freeze({
    target: value.target,
    trust,
    targetBindingDigest: targetDigestFromTrust(trust),
    operationId: value.operationId,
    beforeBootMarker: bootMarker(value.beforeBootMarker),
    priorAuthorizedAttempt: priorAuthorizedAttempt(value.priorAuthorizedAttempt),
    dependencies: configDependencies,
  });
}

function applyInput(input) {
  const value = exactFrozenObject(input, APPLY_FIELDS);
  assertDeepFrozenPlainData(value.proof);
  assertDeepFrozenPlainData(value.authorizedAttempt);
  const configDependencies = dependencies(value.dependencies);
  const trust = trustedTarget(value.target, configDependencies.runProcess);
  const targetBindingDigest = targetDigestFromTrust(trust);
  let proofDigest;
  let attemptDigest;
  try {
    proofDigest = runtimeRecoveryProofDigest(value.proof);
    attemptDigest = runtimeRecoveryAuthorizedAttemptDigest(value.authorizedAttempt);
  } catch {
    failInput();
  }
  if (
    value.proof.deviceId !== trust.deviceId
    || value.proof.targetBindingDigest !== targetBindingDigest
    || value.authorizedAttempt.deviceId !== trust.deviceId
    || value.authorizedAttempt.operationId !== value.proof.operationId
    || value.authorizedAttempt.failedStateDigest !== value.proof.failedStateDigest
    || value.authorizedAttempt.proofDigest !== proofDigest
    || value.authorizedAttempt.classification !== value.proof.classification
    || (
      value.proof.classification === 'ALREADY_ABSENT'
      && value.proof.priorAuthorizedAttempt.ticketId === value.authorizedAttempt.ticketId
    )
  ) failInput();
  return Object.freeze({
    trust,
    proof: value.proof,
    authorizedAttempt: value.authorizedAttempt,
    authorizedAttemptDigest: attemptDigest,
    dependencies: configDependencies,
  });
}

function exactParsedObject(input, fields, failureCode) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
  ) throw runtimeError(failureCode);
  const names = Object.keys(input);
  if (
    names.length !== fields.length
    || names.some((name, index) => name !== fields[index])
  ) throw runtimeError(failureCode);
  return input;
}

function processResult(input, failureCode) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw runtimeError(failureCode);
  const value = Object.create(null);
  for (const name of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (
      !PROCESS_FIELDS.has(name)
      || !descriptor
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw runtimeError(failureCode);
    value[name] = descriptor.value;
  }
  for (const name of ['exitCode', 'signal', 'stdout', 'stderr']) {
    if (!Object.hasOwn(value, name)) throw runtimeError(failureCode);
  }
  if (
    !Number.isSafeInteger(value.exitCode)
    || value.signal !== null
    || typeof value.stdout !== 'string'
    || typeof value.stderr !== 'string'
    || value.stderr !== ''
  ) throw runtimeError(failureCode);
  return value;
}

function parsedJson(stdout, failureCode) {
  try {
    return JSON.parse(stdout);
  } catch {
    throw runtimeError(failureCode);
  }
}

function parseRejection(value, allowed, failureCode, inspect = false) {
  if (value.exitCode !== REJECTION_EXIT_CODE) return false;
  const decoded = parsedJson(value.stdout, failureCode);
  const diagnostic = inspect && decoded?.schemaVersion === 2;
  const parsed = exactParsedObject(decoded,
    diagnostic ? ['schemaVersion', 'error', 'stage'] : ['schemaVersion', 'error'],
    failureCode);
  const expected = diagnostic
    ? { schemaVersion: 2, error: parsed.error, stage: parsed.stage }
    : { schemaVersion: 1, error: parsed.error };
  if (
    parsed.schemaVersion !== (diagnostic ? 2 : 1)
    || typeof parsed.error !== 'string'
    || !allowed.has(parsed.error)
    || (diagnostic && !isWindowsInspectStage(parsed.stage))
    || JSON.stringify(expected) !== value.stdout
  ) throw runtimeError(failureCode);
  const error = acknowledgedRejection(parsed.error);
  if (diagnostic) INSPECT_REJECTION_STAGES.set(error, parsed.stage);
  throw error;
}

function canonicalAcl(input, failureCode) {
  const value = exactParsedObject(input, ACL_FIELDS, failureCode);
  if (
    value.ownerSid !== 'S-1-5-32-544'
    || value.protected !== true
    || value.canonical !== true
    || value.accessRuleCount !== 2
    || value.administratorsFullControl !== true
    || value.systemFullControl !== true
    || value.aclDigest !== ACL_DIGEST
  ) throw runtimeError(failureCode);
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

function canonicalDirectory(input, expectedChildren, failureCode) {
  const value = exactParsedObject(input, DIRECTORY_FIELDS, failureCode);
  if (
    typeof value.volumeSerialNumber !== 'string'
    || !/^[A-F0-9]{16}$/u.test(value.volumeSerialNumber)
    || typeof value.fileId !== 'string'
    || !/^[A-F0-9]{32}$/u.test(value.fileId)
    || value.directChildCount !== expectedChildren.length
    || !Array.isArray(value.directChildren)
    || Object.getPrototypeOf(value.directChildren) !== Array.prototype
    || value.directChildren.length !== expectedChildren.length
    || value.directChildren.some((child, index) => child !== expectedChildren[index])
  ) throw runtimeError(failureCode);
  return Object.freeze({
    volumeSerialNumber: value.volumeSerialNumber,
    fileId: value.fileId,
    acl: canonicalAcl(value.acl, failureCode),
    directChildCount: expectedChildren.length,
    directChildren: Object.freeze([...expectedChildren]),
  });
}

export function parseRuntimeRecoveryInspectProcess(input) {
  const failureCode = 'RUNTIME_INVENTORY_FAILED';
  try {
    const result = processResult(input, failureCode);
    parseRejection(result, INSPECT_REJECTIONS, failureCode, true);
    if (result.exitCode !== 0) throw runtimeError(failureCode);
    const parsed = exactParsedObject(parsedJson(result.stdout, failureCode), RAW_INSPECT_FIELDS, failureCode);
    if (
      parsed.schemaVersion !== 1
      || !['EMPTY_PRE_TRANSACTION', 'CLEAN_ABSENT'].includes(parsed.rawClassification)
    ) throw runtimeError(failureCode);
    let marker;
    try { marker = validateRuntimeRecoveryBootMarker(parsed.bootMarker); } catch {
      throw runtimeError(failureCode);
    }
    const empty = parsed.rawClassification === 'EMPTY_PRE_TRANSACTION';
    const agentRoadAcl = canonicalAcl(parsed.agentRoadAcl, failureCode);
    const runtimeDirectory = canonicalDirectory(parsed.runtimeDirectory, ['staging'], failureCode);
    const operationChild = empty && Array.isArray(parsed.stagingDirectory?.directChildren)
      ? parsed.stagingDirectory.directChildren[0]
      : null;
    if (empty && (typeof operationChild !== 'string' || !OPERATION_ID_PATTERN.test(operationChild))) {
      throw runtimeError(failureCode);
    }
    const stagingDirectory = canonicalDirectory(
      parsed.stagingDirectory,
      empty ? [operationChild] : [],
      failureCode,
    );
    if (empty && stagingDirectory.directChildren.length !== 1) throw runtimeError(failureCode);
    const operationId = empty ? stagingDirectory.directChildren[0] : null;
    if (empty && !OPERATION_ID_PATTERN.test(operationId)) throw runtimeError(failureCode);
    const operationDirectory = empty
      ? canonicalDirectory(parsed.operationDirectory, [], failureCode)
      : parsed.operationDirectory;
    if (!empty && operationDirectory !== null) throw runtimeError(failureCode);
    const identities = [runtimeDirectory, stagingDirectory, operationDirectory]
      .filter((entry) => entry !== null)
      .map((entry) => `${entry.volumeSerialNumber}:${entry.fileId}`);
    if (new Set(identities).size !== identities.length) throw runtimeError(failureCode);
    const output = Object.freeze({
      schemaVersion: 1,
      rawClassification: parsed.rawClassification,
      bootMarker: marker,
      agentRoadAcl,
      runtimeDirectory,
      stagingDirectory,
      operationDirectory,
    });
    if (JSON.stringify(output) !== result.stdout) throw runtimeError(failureCode);
    return output;
  } catch (error) {
    if (ACKNOWLEDGED_REJECTIONS.has(error)) throw error;
    throw runtimeError(failureCode);
  }
}

export function parseRuntimeRecoveryApplyProcess(input) {
  const failureCode = 'RUNTIME_COMPLETION_UNCERTAIN';
  try {
    const result = processResult(input, failureCode);
    parseRejection(result, APPLY_REJECTIONS, failureCode);
    if (result.exitCode !== 0) throw runtimeError(failureCode);
    const parsed = exactParsedObject(
      parsedJson(result.stdout, failureCode),
      ['schemaVersion', 'disposition'],
      failureCode,
    );
    if (
      parsed.schemaVersion !== 1
      || !['REMOVED', 'ALREADY_ABSENT'].includes(parsed.disposition)
      || JSON.stringify({ schemaVersion: 1, disposition: parsed.disposition }) !== result.stdout
    ) throw runtimeError(failureCode);
    return Object.freeze({ schemaVersion: 1, disposition: parsed.disposition });
  } catch (error) {
    if (ACKNOWLEDGED_REJECTIONS.has(error)) throw error;
    throw runtimeError(failureCode);
  }
}

function inspectResult(config, raw) {
  if (
    raw.rawClassification === 'EMPTY_PRE_TRANSACTION'
    && raw.stagingDirectory.directChildren[0] !== config.operationId
  ) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  const classification = raw.rawClassification === 'EMPTY_PRE_TRANSACTION'
    ? 'EMPTY_PRE_TRANSACTION'
    : config.priorAuthorizedAttempt === null
      ? 'EXTERNALLY_ABSENT'
      : 'ALREADY_ABSENT';
  return Object.freeze({
    schemaVersion: 1,
    protocolRevision: 1,
    deviceId: config.trust.deviceId,
    targetBindingDigest: config.targetBindingDigest,
    operationId: config.operationId,
    bootMarker: raw.bootMarker,
    classification,
    priorAuthorizedAttempt: raw.rawClassification === 'EMPTY_PRE_TRANSACTION'
      ? null
      : config.priorAuthorizedAttempt,
    agentRoadAcl: raw.agentRoadAcl,
    runtimeDirectory: raw.runtimeDirectory,
    stagingDirectory: raw.stagingDirectory,
    operationDirectory: raw.operationDirectory,
  });
}

export async function inspectRuntimeRecoveryRemote(input) {
  let config;
  try { config = inspectInput(input); } catch { failInput(); }
  try {
    return await withTrustedSshSession(
      config.trust,
      async (session) => {
        const address = await selectAddress(session);
        const invocation = powershellInvocation(
          WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER,
          encodeRemotePayload({
            schemaVersion: 1,
            protocolRevision: 1,
            operationId: config.operationId,
            beforeBootMarker: config.beforeBootMarker,
          }),
        );
        const process = await session.invokeSsh(address, invocation.argv, {
          timeoutMs: INSPECT_TIMEOUT_MS,
          maxOutputBytes: MAX_OUTPUT_BYTES,
          stdinText: invocation.stdin,
        });
        return inspectResult(config, parseRuntimeRecoveryInspectProcess(process));
      },
      { lockTimeoutMs: config.dependencies.sshLockTimeoutMs },
    );
  } catch (error) {
    if (isTrustedSshSessionLockError(error)) throw runtimeError('RUNTIME_ALREADY_RUNNING');
    if (ACKNOWLEDGED_REJECTIONS.has(error)) {
      const stage = INSPECT_REJECTION_STAGES.get(error);
      if (stage !== undefined) markRecoveryInspectStage(stage);
      throw error;
    }
    if (error?.code === 'RUNTIME_INPUT_INVALID') throw error;
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
}

function expectedWindowsProof(proof) {
  return {
    beforeBootMarker: proof.beforeBootMarker,
    afterBootMarker: proof.afterBootMarker,
    classification: proof.classification,
    priorAuthorizedAttempt: proof.priorAuthorizedAttempt,
    agentRoadAcl: proof.agentRoadAcl,
    runtimeDirectory: proof.runtimeDirectory,
    stagingDirectory: proof.stagingDirectory,
    operationDirectory: proof.operationDirectory,
  };
}

export async function applyRuntimeRecoveryRemote(input) {
  let config;
  try { config = applyInput(input); } catch { failInput(); }
  const phase = Object.seal({ invoked: false });
  try {
    return await withTrustedSshSession(
      config.trust,
      async (session) => {
        const address = session.addresses[0];
        const invocation = powershellInvocation(
          WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER,
          encodeRemotePayload({
            schemaVersion: 1,
            protocolRevision: 1,
            operationId: config.proof.operationId,
            expectedWindowsProof: expectedWindowsProof(config.proof),
            authorizedAttemptDigest: config.authorizedAttemptDigest,
          }),
        );
        phase.invoked = true;
        const process = await session.invokeSsh(address, invocation.argv, {
          timeoutMs: APPLY_TIMEOUT_MS,
          maxOutputBytes: MAX_OUTPUT_BYTES,
          stdinText: invocation.stdin,
        });
        const result = parseRuntimeRecoveryApplyProcess(process);
        const expectedDisposition = config.proof.classification === 'EMPTY_PRE_TRANSACTION'
          ? 'REMOVED'
          : 'ALREADY_ABSENT';
        if (result.disposition !== expectedDisposition) {
          throw runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
        }
        return result;
      },
      { lockTimeoutMs: config.dependencies.sshLockTimeoutMs },
    );
  } catch (error) {
    if (isTrustedSshSessionLockError(error)) throw runtimeError('RUNTIME_ALREADY_RUNNING');
    if (ACKNOWLEDGED_REJECTIONS.has(error)) throw error;
    if (phase.invoked) throw runtimeError('RUNTIME_COMPLETION_UNCERTAIN');
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
}
