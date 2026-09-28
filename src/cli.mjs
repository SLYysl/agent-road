#!/usr/bin/env node

import { runAuthCommand } from './auth/client.mjs';

import { realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { isPromise, isProxy } from 'node:util/types';
import { join } from 'node:path';

import { statePaths } from './core/paths.mjs';
import { CompletionTicketStore } from './enrollment/completion-ticket-store.mjs';
import { startEnrollmentReceiver } from './enrollment/enrollment-receiver.mjs';
import { runWindowsEnrollment } from './enrollment/run-windows-enrollment.mjs';
import { EnrollmentTokenStore } from './enrollment/token-store.mjs';
import { buildWindowsStageZeroCommand } from './enrollment/windows-stage-zero.mjs';
import { BootstrapSigner } from './identity/bootstrap-signer.mjs';
import { SshIdentityStore } from './identity/ssh-identity-store.mjs';
import { runProcess } from './process/run-process.mjs';
import { loadReleaseManifest } from './releases/release-manifest.mjs';
import { executeRemoteScript } from './remote/remote-exec.mjs';
import { getRemoteFile, putRemoteFile } from './remote/remote-files.mjs';
import { loadRemoteTarget } from './remote/remote-target.mjs';
import {
  doctorRuntime as runRuntimeDoctor,
  ensureRuntime as runEnsureRuntime,
  runtimeStatus as readRuntimeStatus,
} from './runtime/ensure-runtime.mjs';
import {
  createProductionApprovedRuntimeDependencies,
  createProductionRuntimeBaselineDependencies,
  createProductionRuntimeDependencies,
  createProductionRuntimePlanDependencies,
  createProductionRuntimeRecoveryDependencies,
} from './runtime/production-runtime-dependencies.mjs';
import {
  captureRuntimeBaseline as runRuntimeBaselineCapture,
  compareRuntimeBaseline as runRuntimeBaselineCompare,
} from './runtime/runtime-baseline.mjs';
import { RUNTIME_BASELINE_SURFACE_IDS } from './runtime/runtime-baseline-store.mjs';
import {
  prepareApprovedRuntime as runApprovedRuntime,
  reviewRuntimePlan as runRuntimePlanReview,
  validateRuntimePlanReviewResult,
} from './runtime/runtime-plan-authorization.mjs';
import {
  applyRuntimeRecovery,
  inspectRuntimeRecovery,
} from './runtime/runtime-recovery.mjs';
import {
  confirmInitialCoreRollback,
  createProductionTerminalRollbackDependencies,
} from './runtime/terminal-rollback-controller.mjs';
import { validateRuntimeInventory } from './runtime/runtime-inventory.mjs';
import { validateRuntimeStateRecord } from './runtime/runtime-state-store.mjs';
import { verifyWindowsSsh } from './ssh/ssh-verifier.mjs';
import { DeviceRegistry } from './storage/device-registry.mjs';
import { TailscaleAdapter } from './tailscale/tailscale-adapter.mjs';
import { runPairCommand } from './pairing/controller.mjs';
import { isWorkCommand, runWorkCommand, workCapabilities } from './work/commands.mjs';

const HELP = `Agent Road controller

Usage:
  agent-road login [--no-browser]
  agent-road whoami
  agent-road logout
  agent-road pair [--name <display-name>] [--config <private-config-path>] [--timeout-minutes <5-30>]
  agent-road enroll [--name <display-name>] [--timeout-minutes <5-30>]
  agent-road list
  agent-road status <device-id>
  agent-road capabilities
  agent-road session <device-id> <absolute.ps1> [more absolute.ps1...]
  agent-road job <start|status|logs|cancel|remove> <device-id> <script-or-job-id> [start-timeout-seconds | logs: --include-output]
  agent-road base-inspect <device-id>
  agent-road base-exec <device-id> <absolute-inspection-directory> <absolute.ps1> <git,node,python,rg subset> [timeout-seconds]
  agent-road measure-exec <device-id> [1-20 iterations]
  agent-road exec <device-id> --script <local.ps1> [--timeout-seconds <1-1800>]
  agent-road put <device-id> <local-file> <absolute-windows-path> [--overwrite]
  agent-road get <device-id> <absolute-windows-path> <local-file> [--overwrite]
  agent-road doctor <device-id>
  agent-road runtime-plan <device-id> --profile <core|base> --baseline <baseline-id>
  agent-road prepare <device-id> --profile <core|base> --approved <plan-ticket-id>
  agent-road runtime-status <device-id>
  agent-road runtime-readiness <device-id> [--interval-seconds <30-120; default 60>]
  agent-road runtime-retain-empty-stage <device-id> --inspect|--apply|--reconcile
  agent-road runtime-confirm-rollback <device-id>
  agent-road runtime-recover <device-id> --inspect [--prior-ticket <ticket-id>]
  agent-road runtime-recover <device-id> --apply --ticket <ticket-id>
  agent-road runtime-baseline <device-id> --capture
  agent-road runtime-baseline <device-id> --compare --baseline <baseline-id>

Remote work options:
  --timeout-seconds <1-1800>  Stop waiting after this many seconds (default: 300)
  --overwrite                 Replace an existing regular destination file
`;
const ENROLLMENT_ERROR_CODES = new Set([
  'TAILSCALE_NOT_AVAILABLE_ON_MAC',
  'TAILSCALE_NOT_RUNNING_ON_MAC',
  'TAILSCALE_SERVE_AUTH_REQUIRED',
  'BOOTSTRAP_FAILED',
  'SSH_VERIFY_FAILED',
]);
const REMOTE_COMMANDS = new Set(['exec', 'put', 'get']);
const RUNTIME_COMMANDS = new Set([
  'doctor',
  'runtime-plan',
  'prepare',
  'runtime-status',
  'runtime-confirm-rollback',
  'runtime-recover',
  'runtime-baseline',
]);
const RUNTIME_AUTHORIZATION_NOTICE = 'NOTICE: Pasting the generated Windows command authorizes Agent Road to install its private core runtime under C:\\ProgramData\\AgentRoad after pinned SSH verification.\n';
const RUNTIME_ERROR_CODES = new Set([
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
  'RUNTIME_PROFILE_UNAVAILABLE',
  'RUNTIME_REBOOT_REQUIRED',
  'RUNTIME_ROLLBACK_INCOMPLETE',
  'RUNTIME_SELF_TEST_FAILED',
  'RUNTIME_SIGNATURE_INVALID',
  'RUNTIME_STAGE_FAILED',
  'RUNTIME_STATE_UNSUPPORTED',
  'RUNTIME_VERIFY_FAILED',
]);
const RUNTIME_RECOVERY_INSPECT_ERROR_CODES = new Set([
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_INTERNAL_ERROR',
  'RUNTIME_INVENTORY_FAILED',
  'RUNTIME_OPERATION_CONFLICT',
  'RUNTIME_REBOOT_REQUIRED',
  'RUNTIME_STATE_UNSUPPORTED',
]);
const RUNTIME_RECOVERY_APPLY_ERROR_CODES = new Set([
  ...RUNTIME_RECOVERY_INSPECT_ERROR_CODES,
  'RUNTIME_COMPLETION_UNCERTAIN',
]);
const RUNTIME_BASELINE_ERROR_CODES = new Set([
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_INTERNAL_ERROR',
  'RUNTIME_INVENTORY_FAILED',
  'RUNTIME_STATE_UNSUPPORTED',
]);
const RUNTIME_PLAN_ERROR_CODES = new Set([
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_INTERNAL_ERROR',
  'RUNTIME_INVENTORY_CHANGED',
  'RUNTIME_INVENTORY_FAILED',
  'RUNTIME_PROFILE_UNAVAILABLE',
  'RUNTIME_SIGNATURE_INVALID',
  'RUNTIME_STATE_UNSUPPORTED',
]);
const RUNTIME_PARSE_ERROR_CODES = new Set(['RUNTIME_INPUT_INVALID']);
const RUNTIME_BASELINE_ID_PATTERN = /^rbl_[a-f0-9]{64}$/u;
const RUNTIME_PLAN_TICKET_ID_PATTERN = /^rpt_[a-f0-9]{64}$/u;
const RUNTIME_BASELINE_COMPARISON_ID_PATTERN = /^rbc_[a-f0-9]{64}$/u;
const RUNTIME_BASELINE_TTL_MS = 24 * 60 * 60 * 1_000;
const RUNTIME_BASELINE_DEPENDENCY_FIELDS = Object.freeze([
  'executeBaselineScript',
  'createBaseline',
  'readBaseline',
  'createComparison',
  'randomBytes',
]);
const REMOTE_ERROR_CODES = new Set([
  'DEVICE_NOT_FOUND',
  'DEVICE_NOT_READY',
  'DEVICE_BUSY',
  'REMOTE_INPUT_INVALID',
  'REMOTE_CONNECTION_FAILED',
  'REMOTE_EXECUTION_UNCERTAIN',
  'REMOTE_OUTPUT_LIMIT',
  'REMOTE_CLEANUP_UNCERTAIN',
  'FILE_TRANSFER_FAILED',
  'FILE_TRANSFER_UNCERTAIN',
  'FILE_INTEGRITY_FAILED',
  'LOCAL_CLEANUP_FAILED',
]);
const REMOTE_RESULT_FIELDS = Object.freeze({
  exec: Object.freeze([
    'schemaVersion',
    'operation',
    'deviceId',
    'address',
    'exitCode',
    'stdout',
    'stderr',
    'startedAt',
    'finishedAt',
  ]),
  put: Object.freeze([
    'schemaVersion',
    'operation',
    'deviceId',
    'address',
    'bytes',
    'sha256',
    'destination',
    'startedAt',
    'finishedAt',
  ]),
  get: Object.freeze([
    'schemaVersion',
    'operation',
    'deviceId',
    'address',
    'bytes',
    'sha256',
    'source',
    'destination',
    'startedAt',
    'finishedAt',
  ]),
});
const REMOTE_RESULT_MAX_FILE_BYTES = 256 * 1024 * 1024;
const REMOTE_RESULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const REMOTE_RESULT_MAX_PATH_BYTES = 4096;
const REMOTE_RESULT_DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const RUNTIME_RECOVERY_TICKET_ID_PATTERN = /^rct_[a-f0-9]{64}$/u;
const RUNTIME_RECOVERY_FINGERPRINT_PATTERN = /^[A-F0-9]{12}$/u;
const RUNTIME_RECOVERY_DISPLAY_NAME_MAX_BYTES = 512;
const RUNTIME_RECOVERY_CLASSIFICATIONS = new Set([
  'EMPTY_PRE_TRANSACTION',
  'ALREADY_ABSENT',
]);
const RUNTIME_RECOVERY_RESULT_FIELDS = Object.freeze({
  RECOVERY_READY: Object.freeze([
    'schemaVersion',
    'status',
    'deviceId',
    'displayName',
    'targetFingerprint',
    'classification',
    'rebootRequired',
    'actionable',
    'ticketId',
    'ticketFingerprint',
    'expiresAt',
  ]),
  RECOVERY_PARENT_REQUIRED: Object.freeze([
    'schemaVersion',
    'status',
    'deviceId',
    'displayName',
    'targetFingerprint',
    'classification',
    'rebootRequired',
    'actionable',
    'ticketId',
    'ticketFingerprint',
    'expiresAt',
    'eligibleAfter',
  ]),
  RECOVERY_APPLY_REQUIRED: Object.freeze([
    'schemaVersion',
    'status',
    'deviceId',
    'displayName',
    'targetFingerprint',
    'classification',
    'rebootRequired',
    'actionable',
    'ticketId',
    'ticketFingerprint',
    'expiresAt',
  ]),
  RECOVERED: Object.freeze([
    'schemaVersion',
    'status',
    'deviceId',
    'displayName',
    'targetFingerprint',
    'classification',
    'ticketFingerprint',
    'disposition',
  ]),
});
const REMOTE_RESULT_SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const REMOTE_RESULT_TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const REMOTE_DEPENDENCY_FIELDS = Object.freeze([
  'registry',
  'sshIdentity',
  'knownHostsPath',
  'runProcess',
  'clock',
  'operationId',
]);
const REMOTE_CLEANUP_CODES = new Set([
  'REMOTE_CLEANUP_UNCERTAIN',
  'LOCAL_CLEANUP_FAILED',
]);
const REMOTE_CHAINABLE_PRIMARY_CODES = Object.freeze({
  exec: new Set([
    'REMOTE_INPUT_INVALID',
    'REMOTE_CONNECTION_FAILED',
    'FILE_TRANSFER_FAILED',
    'FILE_INTEGRITY_FAILED',
    'REMOTE_EXECUTION_UNCERTAIN',
  ]),
  put: new Set([
    'REMOTE_INPUT_INVALID',
    'REMOTE_CONNECTION_FAILED',
    'FILE_TRANSFER_FAILED',
    'FILE_TRANSFER_UNCERTAIN',
    'FILE_INTEGRITY_FAILED',
  ]),
  get: new Set([
    'REMOTE_INPUT_INVALID',
    'REMOTE_CONNECTION_FAILED',
    'FILE_TRANSFER_FAILED',
    'FILE_TRANSFER_UNCERTAIN',
    'FILE_INTEGRITY_FAILED',
  ]),
});
const REMOTE_STANDALONE_CODES = Object.freeze({
  exec: new Set([
    'DEVICE_NOT_FOUND',
    'DEVICE_NOT_READY',
    'DEVICE_BUSY',
    'REMOTE_INPUT_INVALID',
    'REMOTE_CONNECTION_FAILED',
    'REMOTE_EXECUTION_UNCERTAIN',
    'REMOTE_OUTPUT_LIMIT',
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
    'FILE_INTEGRITY_FAILED',
    'LOCAL_CLEANUP_FAILED',
  ]),
  put: new Set([
    'DEVICE_NOT_FOUND',
    'DEVICE_NOT_READY',
    'DEVICE_BUSY',
    'REMOTE_INPUT_INVALID',
    'REMOTE_CONNECTION_FAILED',
    'REMOTE_OUTPUT_LIMIT',
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
    'FILE_TRANSFER_UNCERTAIN',
    'FILE_INTEGRITY_FAILED',
    'LOCAL_CLEANUP_FAILED',
  ]),
  get: new Set([
    'DEVICE_NOT_FOUND',
    'DEVICE_NOT_READY',
    'DEVICE_BUSY',
    'REMOTE_INPUT_INVALID',
    'REMOTE_CONNECTION_FAILED',
    'REMOTE_OUTPUT_LIMIT',
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
    'FILE_TRANSFER_UNCERTAIN',
    'FILE_INTEGRITY_FAILED',
    'LOCAL_CLEANUP_FAILED',
  ]),
});
const INTRINSIC_APPLY = Reflect.apply;
const INTRINSIC_PROMISE = Promise;
const INTRINSIC_PROMISE_PROTOTYPE = Promise.prototype;
const INTRINSIC_PROMISE_CONSTRUCTOR = Object.getOwnPropertyDescriptor(
  INTRINSIC_PROMISE_PROTOTYPE,
  'constructor',
);
const INTRINSIC_PROMISE_THEN = Object.getOwnPropertyDescriptor(
  INTRINSIC_PROMISE_PROTOTYPE,
  'then',
);

function remoteInputError() {
  const error = new Error('REMOTE_INPUT_INVALID');
  error.code = 'REMOTE_INPUT_INVALID';
  return error;
}

function runtimeInputError() {
  const error = new TypeError('RUNTIME_INPUT_INVALID');
  error.code = 'RUNTIME_INPUT_INVALID';
  return error;
}

function stableCodeSegments(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024) return null;
  const segments = value.split(':');
  return segments.length > 0 && segments.every((segment) => REMOTE_ERROR_CODES.has(segment))
    ? segments
    : null;
}

function canonicalRemoteCodeChain(command, segments) {
  if (segments.length === 0) return false;
  if (segments.length === 1) return REMOTE_STANDALONE_CODES[command]?.has(segments[0]) === true;
  if (new Set(segments).size !== segments.length) return false;

  const primaryIndexes = segments
    .map((segment, index) => REMOTE_CLEANUP_CODES.has(segment) ? -1 : index)
    .filter((index) => index !== -1);
  if (primaryIndexes.length > 1 || (primaryIndexes.length === 1 && primaryIndexes[0] !== 0)) {
    return false;
  }
  const cleanupStart = primaryIndexes.length;
  if (
    primaryIndexes.length === 1
    && !REMOTE_CHAINABLE_PRIMARY_CODES[command]?.has(segments[0])
  ) return false;
  const cleanupChain = segments.slice(cleanupStart).join(':');
  return cleanupChain === 'REMOTE_CLEANUP_UNCERTAIN'
    || cleanupChain === 'LOCAL_CLEANUP_FAILED'
    || cleanupChain === 'REMOTE_CLEANUP_UNCERTAIN:LOCAL_CLEANUP_FAILED'
    || (command === 'get' && cleanupChain === 'LOCAL_CLEANUP_FAILED:REMOTE_CLEANUP_UNCERTAIN');
}

function remoteErrorCode(error, command) {
  if (
    error === null
    || (typeof error !== 'object' && typeof error !== 'function')
    || isProxy(error)
  ) {
    return 'REMOTE_INPUT_INVALID';
  }
  try {
    const primaryDescriptor = Object.getOwnPropertyDescriptor(error, 'primaryCode');
    const codeDescriptor = Object.getOwnPropertyDescriptor(error, 'code');
    if (!codeDescriptor || !Object.hasOwn(codeDescriptor, 'value')) return 'REMOTE_INPUT_INVALID';
    const codeSegments = stableCodeSegments(codeDescriptor.value);
    if (codeSegments === null || codeSegments.length !== 1) return 'REMOTE_INPUT_INVALID';
    if (primaryDescriptor === undefined) {
      return canonicalRemoteCodeChain(command, codeSegments)
        ? codeSegments[0]
        : 'REMOTE_INPUT_INVALID';
    }
    if (!Object.hasOwn(primaryDescriptor, 'value')) return 'REMOTE_INPUT_INVALID';
    const primarySegments = stableCodeSegments(primaryDescriptor.value);
    if (primarySegments === null) return 'REMOTE_INPUT_INVALID';
    const segments = [...primarySegments, codeSegments[0]];
    return canonicalRemoteCodeChain(command, segments)
      ? segments.join(':')
      : 'REMOTE_INPUT_INVALID';
  } catch {
    return 'REMOTE_INPUT_INVALID';
  }
}

function inspectHookResult(value) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
    return false;
  }
  if (isProxy(value) || typeof value === 'function') throw remoteInputError();
  if (isPromise(value)) {
    let ownThen;
    let ownConstructor;
    let prototype;
    let constructorDescriptor;
    let thenDescriptor;
    try {
      ownThen = Object.getOwnPropertyDescriptor(value, 'then');
      ownConstructor = Object.getOwnPropertyDescriptor(value, 'constructor');
      prototype = Object.getPrototypeOf(value);
      constructorDescriptor = Object.getOwnPropertyDescriptor(
        INTRINSIC_PROMISE_PROTOTYPE,
        'constructor',
      );
      thenDescriptor = Object.getOwnPropertyDescriptor(INTRINSIC_PROMISE_PROTOTYPE, 'then');
    } catch {
      throw remoteInputError();
    }
    if (
      ownThen !== undefined
      || ownConstructor !== undefined
      || prototype !== INTRINSIC_PROMISE_PROTOTYPE
      || !constructorDescriptor
      || !Object.hasOwn(constructorDescriptor, 'value')
      || constructorDescriptor.value !== INTRINSIC_PROMISE
      || constructorDescriptor.value !== INTRINSIC_PROMISE_CONSTRUCTOR?.value
      || typeof constructorDescriptor.value !== 'function'
      || isProxy(constructorDescriptor.value)
      || !thenDescriptor
      || !Object.hasOwn(thenDescriptor, 'value')
      || thenDescriptor.value !== INTRINSIC_PROMISE_THEN?.value
      || typeof thenDescriptor.value !== 'function'
      || isProxy(thenDescriptor.value)
    ) throw remoteInputError();
    return true;
  }

  let prototype = value;
  while (prototype !== null) {
    if (isProxy(prototype)) throw remoteInputError();
    let thenDescriptor;
    try {
      thenDescriptor = Object.getOwnPropertyDescriptor(prototype, 'then');
      prototype = Object.getPrototypeOf(prototype);
    } catch {
      throw remoteInputError();
    }
    if (thenDescriptor !== undefined) throw remoteInputError();
  }
  return false;
}

function parseRemoteCommand(command, args) {
  const isExec = command === 'exec';
  const options = isExec
    ? {
        script: { type: 'string' },
        'timeout-seconds': { type: 'string', default: '300' },
      }
    : { overwrite: { type: 'boolean', default: false } };
  const { values, positionals, tokens } = parseArgs({
    args,
    options,
    allowPositionals: true,
    strict: true,
    tokens: true,
  });
  const optionCounts = new Map();
  for (const token of tokens) {
    if (token.kind !== 'option') continue;
    optionCounts.set(token.name, (optionCounts.get(token.name) ?? 0) + 1);
  }
  if ([...optionCounts.values()].some((count) => count !== 1)) throw remoteInputError();

  if (isExec) {
    if (positionals.length !== 1 || optionCounts.get('script') !== 1) throw remoteInputError();
    const timeout = values['timeout-seconds'];
    if (!/^[1-9][0-9]{0,3}$/u.test(timeout)) throw remoteInputError();
    const timeoutSeconds = Number(timeout);
    if (timeoutSeconds > 1800) throw remoteInputError();
    return Object.freeze({
      deviceId: positionals[0],
      scriptPath: values.script,
      timeoutMs: timeoutSeconds * 1000,
    });
  }

  if (positionals.length !== 3) throw remoteInputError();
  return command === 'put'
    ? Object.freeze({
        deviceId: positionals[0],
        localPath: positionals[1],
        remotePath: positionals[2],
        overwrite: values.overwrite,
      })
    : Object.freeze({
        deviceId: positionals[0],
        remotePath: positionals[1],
        localPath: positionals[2],
        overwrite: values.overwrite,
      });
}

function ownDataValue(input, field, fallback) {
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(input, field);
  } catch {
    throw remoteInputError();
  }
  if (descriptor === undefined) return fallback;
  if (!Object.hasOwn(descriptor, 'value')) throw remoteInputError();
  return descriptor.value;
}

function assertSafeCallable(value) {
  if (typeof value !== 'function' || isProxy(value)) throw remoteInputError();
  return value;
}

function snapshotWriteSink(value) {
  if (
    value === null
    || (typeof value !== 'object' && typeof value !== 'function')
    || isProxy(value)
  ) throw remoteInputError();
  let prototype = value;
  while (prototype !== null) {
    if (isProxy(prototype)) throw remoteInputError();
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(prototype, 'write');
    } catch {
      throw remoteInputError();
    }
    if (descriptor !== undefined) {
      if (!Object.hasOwn(descriptor, 'value')) throw remoteInputError();
      return Object.freeze({ receiver: value, write: assertSafeCallable(descriptor.value) });
    }
    try {
      prototype = Object.getPrototypeOf(prototype);
    } catch {
      throw remoteInputError();
    }
  }
  throw remoteInputError();
}

function writeSnapshot(snapshot, value) {
  snapshot.write.call(snapshot.receiver, value);
}

function validateRemoteContainer(input) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
  ) throw remoteInputError();
  let prototype;
  let symbols;
  try {
    prototype = Object.getPrototypeOf(input);
    symbols = Object.getOwnPropertySymbols(input);
  } catch {
    throw remoteInputError();
  }
  if ((prototype !== Object.prototype && prototype !== null) || symbols.length !== 0) {
    throw remoteInputError();
  }
  return input;
}

function remoteOperationFor(command, runtime) {
  const defaults = {
    exec: executeRemoteScript,
    put: putRemoteFile,
    get: getRemoteFile,
  };
  const fields = {
    exec: 'executeRemoteScript',
    put: 'putRemoteFile',
    get: 'getRemoteFile',
  };
  return assertSafeCallable(ownDataValue(runtime, fields[command], defaults[command]));
}

function snapshotRemoteRuntime(command, input) {
  const runtime = validateRemoteContainer(input);
  return Object.freeze({
    stdout: snapshotWriteSink(ownDataValue(runtime, 'stdout', process.stdout)),
    stderr: snapshotWriteSink(ownDataValue(runtime, 'stderr', process.stderr)),
    createDependencies: assertSafeCallable(ownDataValue(
      runtime,
      'createRemoteDependencies',
      createRemoteDependencies,
    )),
    loadTarget: assertSafeCallable(ownDataValue(runtime, 'loadRemoteTarget', loadRemoteTarget)),
    operation: remoteOperationFor(command, runtime),
  });
}

function remoteErrorSink(input) {
  try {
    if (
      input === null
      || typeof input !== 'object'
      || Array.isArray(input)
      || isProxy(input)
    ) return snapshotWriteSink(process.stderr);
    return snapshotWriteSink(ownDataValue(input, 'stderr', process.stderr));
  } catch {
    return snapshotWriteSink(process.stderr);
  }
}

function snapshotRequiredDependency(input, methodName) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
  ) throw remoteInputError();

  let method;
  let prototype = input;
  while (prototype !== null) {
    if (isProxy(prototype)) throw remoteInputError();
    let symbols;
    let descriptor;
    try {
      symbols = Object.getOwnPropertySymbols(prototype);
      descriptor = Object.getOwnPropertyDescriptor(prototype, methodName);
    } catch {
      throw remoteInputError();
    }
    if (symbols.length !== 0) throw remoteInputError();
    if (descriptor !== undefined) {
      if (
        method !== undefined
        || !Object.hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'function'
        || isProxy(descriptor.value)
      ) throw remoteInputError();
      method = descriptor.value;
    }
    try {
      prototype = Object.getPrototypeOf(prototype);
    } catch {
      throw remoteInputError();
    }
  }
  if (method === undefined) throw remoteInputError();

  const callable = Object.freeze((...args) => INTRINSIC_APPLY(method, input, args));
  const snapshot = Object.create(null);
  Object.defineProperty(snapshot, methodName, {
    value: callable,
    enumerable: true,
  });
  return Object.freeze(snapshot);
}

function snapshotRemoteDependencies(input) {
  const dependencies = validateRemoteContainer(input);
  let names;
  try {
    names = Object.getOwnPropertyNames(dependencies);
  } catch {
    throw remoteInputError();
  }
  if (
    names.length !== REMOTE_DEPENDENCY_FIELDS.length
    || names.some((name) => !REMOTE_DEPENDENCY_FIELDS.includes(name))
  ) throw remoteInputError();
  const snapshot = Object.create(null);
  for (const field of REMOTE_DEPENDENCY_FIELDS) {
    snapshot[field] = ownDataValue(dependencies, field, undefined);
  }
  for (const field of ['knownHostsPath', 'runProcess', 'clock', 'operationId']) {
    assertSafeCallable(snapshot[field]);
  }
  snapshot.registry = snapshotRequiredDependency(snapshot.registry, 'get');
  snapshot.sshIdentity = snapshotRequiredDependency(snapshot.sshIdentity, 'getExisting');
  return Object.freeze(snapshot);
}

function remoteDependencyViews(inputDependencies) {
  const dependencies = snapshotRemoteDependencies(inputDependencies);
  return Object.freeze({
    target: Object.freeze({
      registry: dependencies.registry,
      sshIdentity: dependencies.sshIdentity,
      knownHostsPath: dependencies.knownHostsPath,
    }),
    operation: Object.freeze({
      runProcess: dependencies.runProcess,
      clock: dependencies.clock,
      operationId: dependencies.operationId,
    }),
  });
}

function execCliExitCode(result) {
  if (result === null || (typeof result !== 'object' && typeof result !== 'function')) {
    throw remoteInputError();
  }
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(result, 'exitCode');
  } catch {
    throw remoteInputError();
  }
  if (
    !descriptor
    || !Object.hasOwn(descriptor, 'value')
    || !Number.isSafeInteger(descriptor.value)
    || descriptor.value < 0
    || descriptor.value > 255
  ) throw remoteInputError();
  return descriptor.value === 0 ? 0 : 1;
}

function validCanonicalTimestamp(value) {
  if (typeof value !== 'string' || !REMOTE_RESULT_TIMESTAMP_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function validBoundedPath(value) {
  return typeof value === 'string'
    && value.length > 0
    && Buffer.byteLength(value) <= REMOTE_RESULT_MAX_PATH_BYTES
    && !value.includes('\0');
}

function snapshotRemoteResult(command, input) {
  const fields = REMOTE_RESULT_FIELDS[command];
  if (
    !fields
    || input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
  ) throw remoteInputError();
  let prototype;
  let names;
  let symbols;
  try {
    prototype = Object.getPrototypeOf(input);
    names = Object.getOwnPropertyNames(input);
    symbols = Object.getOwnPropertySymbols(input);
  } catch {
    throw remoteInputError();
  }
  if (
    (prototype !== Object.prototype && prototype !== null)
    || symbols.length !== 0
    || names.length !== fields.length
    || names.some((name) => !fields.includes(name))
  ) throw remoteInputError();

  const result = Object.create(null);
  for (const field of fields) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(input, field);
    } catch {
      throw remoteInputError();
    }
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw remoteInputError();
    result[field] = descriptor.value;
  }

  if (
    result.schemaVersion !== 1
    || result.operation !== command
    || typeof result.deviceId !== 'string'
    || result.deviceId.length > 64
    || !REMOTE_RESULT_DEVICE_ID_PATTERN.test(result.deviceId)
    || typeof result.address !== 'string'
    || result.address !== result.address.trim()
    || isIP(result.address) === 0
    || !validCanonicalTimestamp(result.startedAt)
    || !validCanonicalTimestamp(result.finishedAt)
    || result.finishedAt < result.startedAt
  ) throw remoteInputError();

  if (command === 'exec') {
    if (
      !Number.isSafeInteger(result.exitCode)
      || result.exitCode < 0
      || result.exitCode > 255
      || typeof result.stdout !== 'string'
      || typeof result.stderr !== 'string'
      || Buffer.byteLength(result.stdout) > REMOTE_RESULT_MAX_OUTPUT_BYTES
      || Buffer.byteLength(result.stderr) > REMOTE_RESULT_MAX_OUTPUT_BYTES - Buffer.byteLength(result.stdout)
    ) throw remoteInputError();
  } else {
    if (
      !Number.isSafeInteger(result.bytes)
      || result.bytes < 0
      || result.bytes > REMOTE_RESULT_MAX_FILE_BYTES
      || typeof result.sha256 !== 'string'
      || !REMOTE_RESULT_SHA256_PATTERN.test(result.sha256)
      || !validBoundedPath(result.destination)
      || (command === 'get' && !validBoundedPath(result.source))
    ) throw remoteInputError();
  }
  return Object.freeze(result);
}

function jsonObjectLine(result) {
  return `${JSON.stringify(result)}\n`;
}

function safeRuntimeCode(
  error,
  fallback = 'RUNTIME_INTERNAL_ERROR',
  allowedCodes = RUNTIME_ERROR_CODES,
) {
  if (
    error === null
    || (typeof error !== 'object' && typeof error !== 'function')
    || isProxy(error)
  ) return fallback;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    if (
      descriptor
      && Object.hasOwn(descriptor, 'value')
      && descriptor.value === 'REMOTE_INPUT_INVALID'
    ) return 'RUNTIME_INPUT_INVALID';
    return descriptor
      && Object.hasOwn(descriptor, 'value')
      && allowedCodes.has(descriptor.value)
      ? descriptor.value
      : fallback;
  } catch {
    return fallback;
  }
}

function runtimeErrorSink(input) {
  try {
    if (
      input === null
      || typeof input !== 'object'
      || Array.isArray(input)
      || isProxy(input)
    ) return snapshotWriteSink(process.stderr);
    return snapshotWriteSink(ownDataValue(input, 'stderr', process.stderr));
  } catch {
    return snapshotWriteSink(process.stderr);
  }
}

function validRuntimeDeviceId(value) {
  return typeof value === 'string'
    && value.length <= 64
    && REMOTE_RESULT_DEVICE_ID_PATTERN.test(value);
}

function projectRuntimeBaselineDependencies(input, mode) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
  ) throw runtimeInputError();
  let prototype;
  let names;
  let symbols;
  try {
    prototype = Object.getPrototypeOf(input);
    names = Object.getOwnPropertyNames(input);
    symbols = Object.getOwnPropertySymbols(input);
  } catch {
    throw runtimeInputError();
  }
  if (
    (prototype !== Object.prototype && prototype !== null)
    || symbols.length !== 0
    || names.length !== RUNTIME_BASELINE_DEPENDENCY_FIELDS.length
    || names.some((name) => !RUNTIME_BASELINE_DEPENDENCY_FIELDS.includes(name))
  ) throw runtimeInputError();
  const snapshot = Object.create(null);
  for (const field of RUNTIME_BASELINE_DEPENDENCY_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
      || typeof descriptor.value !== 'function'
      || isProxy(descriptor.value)
    ) throw runtimeInputError();
    snapshot[field] = descriptor.value;
  }
  return mode === 'capture'
    ? Object.freeze({
        executeBaselineScript: snapshot.executeBaselineScript,
        createBaseline: snapshot.createBaseline,
        randomBytes: snapshot.randomBytes,
      })
    : Object.freeze({
        executeBaselineScript: snapshot.executeBaselineScript,
        readBaseline: snapshot.readBaseline,
        createComparison: snapshot.createComparison,
      });
}

function captureRuntimeBaselineCommand(input) {
  return runRuntimeBaselineCapture(Object.freeze({
    deviceId: input.deviceId,
    dependencies: projectRuntimeBaselineDependencies(input.dependencyFactory(), 'capture'),
  }));
}

function compareRuntimeBaselineCommand(input) {
  return runRuntimeBaselineCompare(Object.freeze({
    deviceId: input.deviceId,
    baselineId: input.baselineId,
    dependencies: projectRuntimeBaselineDependencies(input.dependencyFactory(), 'compare'),
  }));
}

async function confirmTerminalRollbackCommand(input) {
  const pending = input.dependencyFactory();
  const dependencies = inspectHookResult(pending) ? await pending : pending;
  return confirmInitialCoreRollback(input.deviceId, dependencies);
}

function parseRuntimeCommand(command, args) {
  try {
    if (command === 'runtime-confirm-rollback') {
      const { positionals, tokens } = parseArgs({
        args, options: {}, allowPositionals: true, strict: true, tokens: true,
      });
      if (positionals.length !== 1 || !validRuntimeDeviceId(positionals[0])
        || tokens.some(token => token.kind !== 'positional')) throw runtimeInputError();
      return Object.freeze({ deviceId: positionals[0] });
    }
    if (command === 'runtime-baseline') {
      const { values, positionals, tokens } = parseArgs({
        args,
        options: {
          capture: { type: 'boolean' },
          compare: { type: 'boolean' },
          baseline: { type: 'string' },
        },
        allowPositionals: true,
        strict: true,
        tokens: true,
      });
      const optionCounts = new Map();
      for (const token of tokens) {
        if (token.kind !== 'option') continue;
        optionCounts.set(token.name, (optionCounts.get(token.name) ?? 0) + 1);
      }
      if (
        positionals.length !== 1
        || !validRuntimeDeviceId(positionals[0])
        || [...optionCounts.values()].some((count) => count !== 1)
        || (values.capture === true) === (values.compare === true)
      ) throw runtimeInputError();
      if (values.capture === true) {
        if (values.baseline !== undefined) throw runtimeInputError();
        return Object.freeze({ deviceId: positionals[0], mode: 'capture' });
      }
      if (
        optionCounts.get('baseline') !== 1
        || !RUNTIME_BASELINE_ID_PATTERN.test(values.baseline ?? '')
      ) throw runtimeInputError();
      return Object.freeze({
        deviceId: positionals[0],
        mode: 'compare',
        baselineId: values.baseline,
      });
    }

    if (command === 'runtime-recover') {
      const { values, positionals, tokens } = parseArgs({
        args,
        options: {
          inspect: { type: 'boolean' },
          apply: { type: 'boolean' },
          ticket: { type: 'string' },
          'prior-ticket': { type: 'string' },
        },
        allowPositionals: true,
        strict: true,
        tokens: true,
      });
      const optionCounts = new Map();
      for (const token of tokens) {
        if (token.kind !== 'option') continue;
        optionCounts.set(token.name, (optionCounts.get(token.name) ?? 0) + 1);
      }
      if (
        positionals.length !== 1
        || !validRuntimeDeviceId(positionals[0])
        || [...optionCounts.values()].some((count) => count !== 1)
        || (values.inspect === true) === (values.apply === true)
      ) throw runtimeInputError();
      if (values.inspect === true) {
        if (values.ticket !== undefined) throw runtimeInputError();
        if (
          values['prior-ticket'] !== undefined
          && !RUNTIME_RECOVERY_TICKET_ID_PATTERN.test(values['prior-ticket'])
        ) throw runtimeInputError();
        return Object.freeze({
          deviceId: positionals[0],
          mode: 'inspect',
          priorTicketId: values['prior-ticket'] ?? null,
        });
      }
      if (
        values['prior-ticket'] !== undefined
        || !RUNTIME_RECOVERY_TICKET_ID_PATTERN.test(values.ticket ?? '')
      ) throw runtimeInputError();
      return Object.freeze({
        deviceId: positionals[0],
        mode: 'apply',
        ticketId: values.ticket,
      });
    }

    if (command === 'runtime-plan' || command === 'prepare') {
      const authorizationOption = command === 'runtime-plan' ? 'baseline' : 'approved';
      const { values, positionals, tokens } = parseArgs({
        args,
        options: {
          profile: { type: 'string' },
          [authorizationOption]: { type: 'string' },
        },
        allowPositionals: true,
        strict: true,
        tokens: true,
      });
      const counts = new Map();
      for (const token of tokens) {
        if (token.kind !== 'option') continue;
        counts.set(token.name, (counts.get(token.name) ?? 0) + 1);
      }
      if (
        positionals.length !== 1
        || counts.get('profile') !== 1
        || counts.get(authorizationOption) !== 1
        || [...counts.values()].some((count) => count !== 1)
        || !['core', 'base'].includes(values.profile)
      ) throw runtimeInputError();
      if (!validRuntimeDeviceId(positionals[0])) throw runtimeInputError();
      if (command === 'runtime-plan') {
        if (!RUNTIME_BASELINE_ID_PATTERN.test(values.baseline ?? '')) throw runtimeInputError();
        return Object.freeze({
          deviceId: positionals[0],
          profile: values.profile,
          baselineId: values.baseline,
        });
      }
      if (!RUNTIME_PLAN_TICKET_ID_PATTERN.test(values.approved ?? '')) throw runtimeInputError();
      return Object.freeze({
        deviceId: positionals[0],
        profile: values.profile,
        planTicketId: values.approved,
      });
    }

    const { positionals } = parseArgs({
      args,
      options: {},
      allowPositionals: true,
      strict: true,
    });
    if (
      positionals.length !== 1
      || !validRuntimeDeviceId(positionals[0])
    ) throw runtimeInputError();
    return Object.freeze({ deviceId: positionals[0] });
  } catch (error) {
    if (safeRuntimeCode(error, null) === 'RUNTIME_INPUT_INVALID') throw error;
    throw runtimeInputError();
  }
}

function runtimeOperationFor(command, mode, runtime) {
  const defaults = {
    doctor: runRuntimeDoctor,
    'runtime-plan': runRuntimePlanReview,
    prepare: runApprovedRuntime,
    'runtime-status': readRuntimeStatus,
    'runtime-confirm-rollback': confirmTerminalRollbackCommand,
    'runtime-recover:inspect': inspectRuntimeRecovery,
    'runtime-recover:apply': applyRuntimeRecovery,
    'runtime-baseline:capture': captureRuntimeBaselineCommand,
    'runtime-baseline:compare': compareRuntimeBaselineCommand,
  };
  const fields = {
    doctor: 'doctorRuntime',
    'runtime-plan': 'reviewRuntimePlan',
    prepare: 'prepareApprovedRuntime',
    'runtime-status': 'runtimeStatus',
    'runtime-confirm-rollback': 'confirmTerminalRollback',
    'runtime-recover:inspect': 'inspectRuntimeRecovery',
    'runtime-recover:apply': 'applyRuntimeRecovery',
    'runtime-baseline:capture': 'captureRuntimeBaseline',
    'runtime-baseline:compare': 'compareRuntimeBaseline',
  };
  const operation = ['runtime-recover', 'runtime-baseline'].includes(command)
    ? `${command}:${mode}`
    : command;
  return assertSafeCallable(ownDataValue(runtime, fields[operation], defaults[operation]));
}

function snapshotRuntimeCommand(command, parsed, input, env) {
  let runtime;
  try {
    runtime = validateRemoteContainer(input);
    const factories = {
      'runtime-confirm-rollback': Object.freeze({
        field: 'terminalRollbackDependencyFactory',
        create: () => createProductionTerminalRollbackDependencies(env),
      }),
      'runtime-recover': Object.freeze({
        field: 'runtimeRecoveryDependencyFactory',
        create: () => createProductionRuntimeRecoveryDependencies(env),
      }),
      'runtime-baseline': Object.freeze({
        field: 'runtimeBaselineDependencyFactory',
        create: () => createProductionRuntimeBaselineDependencies(env),
      }),
      'runtime-plan': Object.freeze({
        field: 'runtimePlanDependencyFactory',
        create: () => createProductionRuntimePlanDependencies(env),
      }),
      prepare: Object.freeze({
        field: 'approvedRuntimeDependencyFactory',
        create: () => createProductionApprovedRuntimeDependencies(env),
      }),
    };
    const selected = factories[command] ?? Object.freeze({
      field: 'runtimeDependencyFactory',
      create: () => createProductionRuntimeDependencies(env),
    });
    return Object.freeze({
      stdout: snapshotWriteSink(ownDataValue(runtime, 'stdout', process.stdout)),
      stderr: snapshotWriteSink(ownDataValue(runtime, 'stderr', process.stderr)),
      dependencyFactory: assertSafeCallable(ownDataValue(
        runtime,
        selected.field,
        selected.create,
      )),
      operation: runtimeOperationFor(command, parsed.mode, runtime),
    });
  } catch {
    throw runtimeInputError();
  }
}

function snapshotRuntimeRecoveryResult(status, input) {
  const fields = RUNTIME_RECOVERY_RESULT_FIELDS[status];
  if (
    fields === undefined
    || input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
  ) throw runtimeInputError();
  let prototype;
  let names;
  let symbols;
  try {
    prototype = Object.getPrototypeOf(input);
    names = Object.getOwnPropertyNames(input);
    symbols = Object.getOwnPropertySymbols(input);
  } catch {
    throw runtimeInputError();
  }
  if (
    (prototype !== Object.prototype && prototype !== null)
    || symbols.length !== 0
    || names.length !== fields.length
    || names.some((name) => !fields.includes(name))
  ) throw runtimeInputError();
  const result = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw runtimeInputError();
    result[field] = descriptor.value;
  }
  if (
    result.schemaVersion !== 1
    || result.status !== status
    || !validRuntimeDeviceId(result.deviceId)
    || typeof result.displayName !== 'string'
    || result.displayName !== result.displayName.trim()
    || Buffer.byteLength(result.displayName, 'utf8') < 1
    || Buffer.byteLength(result.displayName, 'utf8') > RUNTIME_RECOVERY_DISPLAY_NAME_MAX_BYTES
    || /[\r\n\x00-\x1f\x7f]/u.test(result.displayName)
    || !RUNTIME_RECOVERY_FINGERPRINT_PATTERN.test(result.targetFingerprint)
    || !RUNTIME_RECOVERY_CLASSIFICATIONS.has(result.classification)
    || !RUNTIME_RECOVERY_FINGERPRINT_PATTERN.test(result.ticketFingerprint)
  ) throw runtimeInputError();
  if (status !== 'RECOVERED') {
    if (
      result.rebootRequired !== false
      || result.actionable !== (status === 'RECOVERY_READY')
      || !RUNTIME_RECOVERY_TICKET_ID_PATTERN.test(result.ticketId)
      || !validCanonicalTimestamp(result.expiresAt)
    ) throw runtimeInputError();
    if (status === 'RECOVERY_PARENT_REQUIRED' && (
      result.eligibleAfter !== null
      && (
        !validCanonicalTimestamp(result.eligibleAfter)
        || result.eligibleAfter !== result.expiresAt
      )
    )) throw runtimeInputError();
  } else if (
    (result.classification === 'EMPTY_PRE_TRANSACTION' && result.disposition !== 'REMOVED')
    || (result.classification === 'ALREADY_ABSENT' && result.disposition !== 'ALREADY_ABSENT')
  ) throw runtimeInputError();
  return Object.freeze({ ...result });
}

function snapshotRuntimeBaselineObject(input, fields) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
  ) throw runtimeInputError();
  let prototype;
  let names;
  let symbols;
  try {
    prototype = Object.getPrototypeOf(input);
    names = Object.getOwnPropertyNames(input);
    symbols = Object.getOwnPropertySymbols(input);
  } catch {
    throw runtimeInputError();
  }
  if (
    (prototype !== Object.prototype && prototype !== null)
    || symbols.length !== 0
    || names.length !== fields.length
    || names.some((name) => !fields.includes(name))
  ) throw runtimeInputError();
  const result = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw runtimeInputError();
    result[field] = descriptor.value;
  }
  return result;
}

function snapshotRuntimeBaselineChanges(input) {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || input.length > RUNTIME_BASELINE_SURFACE_IDS.length
    || Object.getOwnPropertyNames(input).length !== input.length + 1
  ) throw runtimeInputError();
  const changes = [];
  let prior = -1;
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      throw runtimeInputError();
    }
    const change = snapshotRuntimeBaselineObject(
      descriptor.value,
      ['id', 'countChanged', 'macChanged'],
    );
    const position = RUNTIME_BASELINE_SURFACE_IDS.indexOf(change.id);
    if (
      position <= prior
      || typeof change.countChanged !== 'boolean'
      || typeof change.macChanged !== 'boolean'
      || (!change.countChanged && !change.macChanged)
    ) throw runtimeInputError();
    prior = position;
    changes.push(Object.freeze({ ...change }));
  }
  return Object.freeze(changes);
}

function snapshotRuntimeBaselineResult(mode, parsed, input) {
  if (mode === 'capture') {
    const result = snapshotRuntimeBaselineObject(
      input,
      ['baselineId', 'capturedAt', 'expiresAt'],
    );
    if (
      !RUNTIME_BASELINE_ID_PATTERN.test(result.baselineId)
      || !validCanonicalTimestamp(result.capturedAt)
      || !validCanonicalTimestamp(result.expiresAt)
      || result.expiresAt !== new Date(
        Date.parse(result.capturedAt) + RUNTIME_BASELINE_TTL_MS,
      ).toISOString()
    ) throw runtimeInputError();
    return Object.freeze({ ...result });
  }
  const result = snapshotRuntimeBaselineObject(
    input,
    ['baselineId', 'comparisonId', 'status', 'changedSurfaces'],
  );
  const changedSurfaces = snapshotRuntimeBaselineChanges(result.changedSurfaces);
  if (
    result.baselineId !== parsed.baselineId
    || !RUNTIME_BASELINE_COMPARISON_ID_PATTERN.test(result.comparisonId)
    || !['UNCHANGED', 'CHANGED'].includes(result.status)
    || (result.status === 'UNCHANGED') !== (changedSurfaces.length === 0)
  ) throw runtimeInputError();
  return Object.freeze({
    baselineId: result.baselineId,
    comparisonId: result.comparisonId,
    status: result.status,
    changedSurfaces,
  });
}

function validateRuntimeCommandResult(command, parsed, input) {
  try {
    if (command === 'doctor') return validateRuntimeInventory(input);
    if (command === 'runtime-plan') {
      const result = validateRuntimePlanReviewResult(input);
      if (
        result.plan.requestedProfiles.length !== 1
        || result.plan.requestedProfiles[0] !== parsed.profile
      ) throw runtimeInputError();
      return result;
    }
    if (command === 'runtime-baseline') {
      return snapshotRuntimeBaselineResult(parsed.mode, parsed, input);
    }
    if (command === 'runtime-recover') {
      let status = 'RECOVERED';
      if (parsed.mode === 'inspect') {
        if (
          input === null
          || typeof input !== 'object'
          || Array.isArray(input)
          || isProxy(input)
        ) throw runtimeInputError();
        status = ownDataValue(input, 'status', undefined);
        if (![
          'RECOVERY_READY',
          'RECOVERY_PARENT_REQUIRED',
          'RECOVERY_APPLY_REQUIRED',
        ].includes(status)) throw runtimeInputError();
      }
      const result = snapshotRuntimeRecoveryResult(status, input);
      if (result.deviceId !== parsed.deviceId) throw runtimeInputError();
      return result;
    }
    const state = validateRuntimeStateRecord(input);
    if (state.deviceId !== parsed.deviceId) throw runtimeInputError();
    if (command === 'runtime-confirm-rollback') {
      if (state.runtimeStatus !== 'FAILED' || state.failureCode !== 'RUNTIME_INSTALL_FAILED'
        || state.requestedProfiles.length !== 1 || state.requestedProfiles[0] !== 'core'
        || state.readyProfiles.length !== 0) throw runtimeInputError();
      return Object.freeze({
        schemaVersion: 1, status: 'ROLLBACK_CONFIRMED', runtimeStatus: 'FAILED',
        failureCode: 'RUNTIME_INSTALL_FAILED', remoteMutation: false,
      });
    }
    if (command === 'prepare' && (
      state.runtimeStatus !== 'READY'
      || !state.requestedProfiles.includes(parsed.profile)
      || !state.readyProfiles.includes(parsed.profile)
    )) throw runtimeInputError();
    return state;
  } catch {
    throw runtimeInputError();
  }
}

async function runRuntimeCommand(command, args, env, runtime) {
  const errorSink = runtimeErrorSink(runtime);
  let parsed = null;
  try {
    parsed = parseRuntimeCommand(command, args);
    const snapshot = snapshotRuntimeCommand(command, parsed, runtime, env);
    let options;
    if (command === 'runtime-plan') {
      options = Object.freeze({
          deviceId: parsed.deviceId,
          requestedProfiles: Object.freeze([parsed.profile]),
          baselineId: parsed.baselineId,
          dependencyFactory: snapshot.dependencyFactory,
        });
    } else if (command === 'prepare') {
      options = Object.freeze({
          deviceId: parsed.deviceId,
          requestedProfiles: Object.freeze([parsed.profile]),
          planTicketId: parsed.planTicketId,
          dependencyFactory: snapshot.dependencyFactory,
        });
    } else if (command === 'runtime-recover') {
      options = parsed.mode === 'inspect'
        ? Object.freeze({
            deviceId: parsed.deviceId,
            priorTicketId: parsed.priorTicketId,
            dependencyFactory: snapshot.dependencyFactory,
          })
        : Object.freeze({
            deviceId: parsed.deviceId,
            ticketId: parsed.ticketId,
            dependencyFactory: snapshot.dependencyFactory,
          });
    } else if (command === 'runtime-baseline') {
      options = parsed.mode === 'capture'
        ? Object.freeze({
            deviceId: parsed.deviceId,
            dependencyFactory: snapshot.dependencyFactory,
          })
        : Object.freeze({
            deviceId: parsed.deviceId,
            baselineId: parsed.baselineId,
            dependencyFactory: snapshot.dependencyFactory,
          });
    } else {
      options = Object.freeze({
          deviceId: parsed.deviceId,
          dependencyFactory: snapshot.dependencyFactory,
        });
    }
    const pending = INTRINSIC_APPLY(snapshot.operation, undefined, [options]);
    const result = inspectHookResult(pending) ? await pending : pending;
    const canonical = validateRuntimeCommandResult(command, parsed, result);
    const output = jsonObjectLine(canonical);
    try {
      writeSnapshot(snapshot.stdout, output);
    } catch {
      const error = new Error('RUNTIME_INTERNAL_ERROR');
      error.code = 'RUNTIME_INTERNAL_ERROR';
      throw error;
    }
    return 0;
  } catch (error) {
    const allowedCodes = command === 'runtime-plan'
      ? parsed === null
        ? RUNTIME_PARSE_ERROR_CODES
        : RUNTIME_PLAN_ERROR_CODES
      : command === 'runtime-baseline'
      ? parsed === null
        ? RUNTIME_PARSE_ERROR_CODES
        : RUNTIME_BASELINE_ERROR_CODES
      : command !== 'runtime-recover'
        ? RUNTIME_ERROR_CODES
      : parsed === null
        ? RUNTIME_PARSE_ERROR_CODES
        : parsed.mode === 'inspect'
          ? RUNTIME_RECOVERY_INSPECT_ERROR_CODES
          : RUNTIME_RECOVERY_APPLY_ERROR_CODES;
    const code = safeRuntimeCode(error, 'RUNTIME_INTERNAL_ERROR', allowedCodes);
    try {
      writeSnapshot(errorSink, `${code}\n`);
    } catch {
      // Do not reveal runtime details through a broken diagnostic sink.
    }
    return 2;
  }
}

async function runRemoteCommand(command, args, env, runtime) {
  const errorSink = remoteErrorSink(runtime);
  try {
    const remoteRuntime = snapshotRemoteRuntime(command, runtime);
    const parsed = parseRemoteCommand(command, args);
    const pendingDependencies = remoteRuntime.createDependencies(env);
    const dependencies = inspectHookResult(pendingDependencies)
      ? await pendingDependencies
      : pendingDependencies;
    const views = remoteDependencyViews(dependencies);
    const pendingTarget = remoteRuntime.loadTarget(parsed.deviceId, views.target);
    const target = inspectHookResult(pendingTarget) ? await pendingTarget : pendingTarget;
    let result;
    let pendingResult;
    if (command === 'exec') {
      pendingResult = remoteRuntime.operation({
        target,
        scriptPath: parsed.scriptPath,
        timeoutMs: parsed.timeoutMs,
        dependencies: views.operation,
      });
    } else {
      pendingResult = remoteRuntime.operation({
        target,
        localPath: parsed.localPath,
        remotePath: parsed.remotePath,
        overwrite: parsed.overwrite,
        dependencies: views.operation,
      });
    }
    result = inspectHookResult(pendingResult) ? await pendingResult : pendingResult;
    const snapshot = snapshotRemoteResult(command, result);
    const exitCode = command === 'exec' ? execCliExitCode(snapshot) : 0;
    const output = jsonObjectLine(snapshot);
    writeSnapshot(remoteRuntime.stdout, output);
    return exitCode;
  } catch (error) {
    const code = remoteErrorCode(error, command);
    try {
      writeSnapshot(errorSink, `${code}\n`);
    } catch {
      // A broken stderr sink cannot be repaired here, but remote details remain redacted.
    }
    return 2;
  }
}

function enrollmentErrorCode(error) {
  if (
    error === null
    || (typeof error !== 'object' && typeof error !== 'function')
    || isProxy(error)
  ) {
    return 'BOOTSTRAP_FAILED';
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    return descriptor
      && Object.hasOwn(descriptor, 'value')
      && ENROLLMENT_ERROR_CODES.has(descriptor.value)
      ? descriptor.value
      : 'BOOTSTRAP_FAILED';
  } catch {
    return 'BOOTSTRAP_FAILED';
  }
}

function enrollmentConsentUrl(error, code) {
  if (
    code !== 'TAILSCALE_SERVE_AUTH_REQUIRED'
    || error === null
    || (typeof error !== 'object' && typeof error !== 'function')
    || isProxy(error)
  ) {
    return null;
  }
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(error, 'details');
  } catch {
    return null;
  }
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
  const value = descriptor.value;
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048 || /[\s\x00-\x1f\x7f]/.test(value)) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:'
      && url.hostname === 'login.tailscale.com'
      && url.username === ''
      && url.password === ''
      && url.port === ''
      && url.href === value
      && value.startsWith('https://login.tailscale.com/')
      ? value
      : null;
  } catch {
    return null;
  }
}

function snapshotBoundMethod(input, methodName) {
  if (
    input === null
    || (typeof input !== 'object' && typeof input !== 'function')
    || isProxy(input)
  ) throw remoteInputError();
  let prototype = input;
  while (prototype !== null) {
    if (isProxy(prototype)) throw remoteInputError();
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(prototype, methodName);
      prototype = Object.getPrototypeOf(prototype);
    } catch {
      throw remoteInputError();
    }
    if (descriptor !== undefined) {
      if (!Object.hasOwn(descriptor, 'value')) throw remoteInputError();
      const method = assertSafeCallable(descriptor.value);
      return Object.freeze((...args) => INTRINSIC_APPLY(method, input, args));
    }
  }
  throw remoteInputError();
}

function validateEnrollmentRuntimeContainer(input) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
  ) throw remoteInputError();
  try {
    if (Object.getOwnPropertySymbols(input).length !== 0) throw remoteInputError();
  } catch {
    throw remoteInputError();
  }
  return input;
}

function ownEnrollmentRuntimeValue(input, field, fallback) {
  let ownDescriptor;
  try {
    ownDescriptor = Object.getOwnPropertyDescriptor(input, field);
  } catch {
    throw remoteInputError();
  }
  if (ownDescriptor !== undefined) {
    if (!Object.hasOwn(ownDescriptor, 'value')) throw remoteInputError();
    return ownDescriptor.value;
  }
  let prototype;
  try {
    prototype = Object.getPrototypeOf(input);
  } catch {
    throw remoteInputError();
  }
  while (prototype !== null) {
    if (isProxy(prototype)) throw remoteInputError();
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(prototype, field);
      prototype = Object.getPrototypeOf(prototype);
    } catch {
      throw remoteInputError();
    }
    if (descriptor !== undefined) throw remoteInputError();
  }
  return fallback;
}

function snapshotEnrollmentRuntime(input) {
  try {
    const runtime = validateEnrollmentRuntimeContainer(input);
    const signalSource = ownEnrollmentRuntimeValue(runtime, 'signalSource', process);
    return Object.freeze({
      stdout: snapshotWriteSink(ownEnrollmentRuntimeValue(runtime, 'stdout', process.stdout)),
      stderr: snapshotWriteSink(ownEnrollmentRuntimeValue(runtime, 'stderr', process.stderr)),
      dependencyFactory: assertSafeCallable(ownEnrollmentRuntimeValue(
        runtime,
        'dependencyFactory',
        createProductionDependencies,
      )),
      runEnrollment: assertSafeCallable(ownEnrollmentRuntimeValue(
        runtime,
        'runEnrollment',
        runWindowsEnrollment,
      )),
      signalOn: snapshotBoundMethod(signalSource, 'on'),
      signalOff: snapshotBoundMethod(signalSource, 'off'),
    });
  } catch {
    throw remoteInputError();
  }
}

function snapshotEnrollmentHandoff(input, env) {
  try {
    const runtime = validateEnrollmentRuntimeContainer(input);
    return Object.freeze({
      runtimeDependencyFactory: assertSafeCallable(ownEnrollmentRuntimeValue(
        runtime,
        'runtimeDependencyFactory',
        () => createProductionRuntimeDependencies(env),
      )),
      ensureRuntime: assertSafeCallable(ownEnrollmentRuntimeValue(
        runtime,
        'ensureRuntime',
        runEnsureRuntime,
      )),
    });
  } catch {
    throw remoteInputError();
  }
}

async function invokeCliHook(callable, args) {
  const pending = INTRINSIC_APPLY(callable, undefined, args);
  return inspectHookResult(pending) ? await pending : pending;
}

function snapshotConnectedEnrollment(input) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
  ) throw remoteInputError();
  let prototype;
  let names;
  let symbols;
  try {
    prototype = Object.getPrototypeOf(input);
    names = Object.getOwnPropertyNames(input);
    symbols = Object.getOwnPropertySymbols(input);
  } catch {
    throw remoteInputError();
  }
  if (
    (prototype !== Object.prototype && prototype !== null)
    || symbols.length !== 0
    || !names.includes('id')
    || !names.includes('status')
  ) throw remoteInputError();

  const values = Object.create(null);
  for (const name of names) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(input, name);
    } catch {
      throw remoteInputError();
    }
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw remoteInputError();
    if (name === 'id' || name === 'status') values[name] = descriptor.value;
  }
  if (
    typeof values.id !== 'string'
    || values.id.length > 64
    || !REMOTE_RESULT_DEVICE_ID_PATTERN.test(values.id)
    || values.status !== 'CONNECTED_SSH_ONLY'
  ) throw remoteInputError();
  return Object.freeze({ id: values.id, status: values.status });
}

function validateReadyHandoff(input, deviceId) {
  try {
    const state = validateRuntimeStateRecord(input);
    if (
      state.deviceId !== deviceId
      || state.runtimeStatus !== 'READY'
      || !state.requestedProfiles.includes('core')
      || !state.readyProfiles.includes('core')
    ) throw runtimeInputError();
    return state;
  } catch {
    throw runtimeInputError();
  }
}

async function runEnrollmentCommand(args, env, runtime) {
  const { values } = parseArgs({
    args,
    options: {
      name: { type: 'string', default: 'New Windows PC' },
      'timeout-minutes': { type: 'string', default: '10' },
    },
    strict: true,
  });
  if (!/^(?:[5-9]|[12][0-9]|30)$/.test(values['timeout-minutes'])) {
    throw new Error('--timeout-minutes must be an integer from 5 to 30');
  }

  let snapshot;
  try {
    snapshot = snapshotEnrollmentRuntime(runtime);
  } catch (error) {
    const sink = remoteErrorSink(runtime);
    try { writeSnapshot(sink, `${enrollmentErrorCode(error)}\n`); } catch { /* redacted */ }
    return 2;
  }
  let handoff;
  let handoffFailure;
  try {
    handoff = snapshotEnrollmentHandoff(runtime, env);
  } catch (error) {
    handoffFailure = error;
  }

  const abortController = new AbortController();
  let commitStarted = false;
  const abort = () => {
    if (!commitStarted) abortController.abort();
  };
  let listeningForSigint = false;
  let listeningForSigterm = false;
  let connected;
  let enrollmentFailure;
  try {
    snapshot.signalOn('SIGINT', abort);
    listeningForSigint = true;
    snapshot.signalOn('SIGTERM', abort);
    listeningForSigterm = true;
    const dependencies = await invokeCliHook(snapshot.dependencyFactory, [env]);
    writeSnapshot(snapshot.stderr, 'ENROLLING\n');
    const result = await invokeCliHook(snapshot.runEnrollment, [{
      displayName: values.name,
      timeoutMs: Number(values['timeout-minutes']) * 60_000,
      dependencies,
      signal: abortController.signal,
      onCommitStart() {
        commitStarted = true;
      },
      onCommand(enrollmentCommand) {
        if (typeof enrollmentCommand !== 'string') throw remoteInputError();
        writeSnapshot(snapshot.stderr, RUNTIME_AUTHORIZATION_NOTICE);
        writeSnapshot(snapshot.stdout, `${enrollmentCommand}\n`);
      },
    }]);
    connected = snapshotConnectedEnrollment(result);
  } catch (error) {
    enrollmentFailure = error;
  }

  try {
    if (listeningForSigterm) snapshot.signalOff('SIGTERM', abort);
  } catch (error) {
    enrollmentFailure ??= error;
  }
  try {
    if (listeningForSigint) snapshot.signalOff('SIGINT', abort);
  } catch (error) {
    enrollmentFailure ??= error;
  }

  if (enrollmentFailure !== undefined) {
    const code = enrollmentErrorCode(enrollmentFailure);
    try {
      writeSnapshot(snapshot.stderr, `${code}\n`);
      const consentUrl = enrollmentConsentUrl(enrollmentFailure, code);
      if (consentUrl !== null) writeSnapshot(snapshot.stderr, `${consentUrl}\n`);
    } catch {
      // Preserve redaction if the diagnostic sink is broken.
    }
    return 2;
  }

  const deferRuntimeSignal = () => {};
  let guardingRuntimeSigint = false;
  let guardingRuntimeSigterm = false;
  let runtimeFailure = handoffFailure;
  try {
    snapshot.signalOn('SIGINT', deferRuntimeSignal);
    guardingRuntimeSigint = true;
    snapshot.signalOn('SIGTERM', deferRuntimeSignal);
    guardingRuntimeSigterm = true;
  } catch (error) {
    runtimeFailure ??= error;
  }

  try {
    writeSnapshot(snapshot.stderr, 'CONNECTED_SSH_ONLY\n');
    if (runtimeFailure !== undefined) throw runtimeFailure;
    const result = await invokeCliHook(handoff.ensureRuntime, [Object.freeze({
      deviceId: connected.id,
      requestedProfiles: Object.freeze(['core']),
      dependencyFactory: handoff.runtimeDependencyFactory,
    })]);
    validateReadyHandoff(result, connected.id);
  } catch (error) {
    runtimeFailure ??= error;
  }

  try {
    if (guardingRuntimeSigterm) snapshot.signalOff('SIGTERM', deferRuntimeSignal);
  } catch (error) {
    runtimeFailure ??= error;
  }
  try {
    if (guardingRuntimeSigint) snapshot.signalOff('SIGINT', deferRuntimeSignal);
  } catch (error) {
    runtimeFailure ??= error;
  }

  if (runtimeFailure !== undefined) {
    const code = safeRuntimeCode(runtimeFailure);
    try { writeSnapshot(snapshot.stderr, `${code}\n`); } catch { /* redacted */ }
    return 2;
  }
  try {
    writeSnapshot(snapshot.stderr, 'RUNTIME_READY\n');
    return 0;
  } catch {
    try { writeSnapshot(snapshot.stderr, 'RUNTIME_INTERNAL_ERROR\n'); } catch { /* redacted */ }
    return 2;
  }
}

export async function createProductionDependencies(env = process.env) {
  const paths = statePaths(env);
  return {
    tailscale: new TailscaleAdapter(),
    signer: new BootstrapSigner(paths.signingPrivateKey, paths.signingPublicKey),
    sshIdentity: new SshIdentityStore(paths.sshIdentities),
    startReceiver: startEnrollmentReceiver,
    tokenStore: new EnrollmentTokenStore(paths.tokens),
    completionTickets: new CompletionTicketStore(),
    registry: new DeviceRegistry(paths.devices),
    releaseManifest: await loadReleaseManifest(new URL('../config/releases.json', import.meta.url)),
    stageOneBytes: await readFile(new URL('../windows/bootstrap-stage-one.ps1', import.meta.url)),
    buildCommand: buildWindowsStageZeroCommand,
    verifySsh: verifyWindowsSsh,
    knownHostsPath: (deviceId) => join(paths.knownHosts, `agent-road-known-hosts-${deviceId}`),
    now: () => new Date(),
    createDeviceId: () => `dev_${randomUUID().replaceAll('-', '')}`,
  };
}

export function createRemoteDependencies(env = process.env) {
  const paths = statePaths(env);
  return Object.freeze({
    registry: new DeviceRegistry(paths.devices),
    sshIdentity: new SshIdentityStore(paths.sshIdentities),
    knownHostsPath: (deviceId) => join(paths.knownHosts, `agent-road-known-hosts-${deviceId}`),
    runProcess,
    clock: () => new Date(),
    operationId: () => randomUUID().replaceAll('-', ''),
  });
}

export async function main(argv = process.argv.slice(2), env = process.env, runtime = {}) {
  const [command, ...args] = argv;

  if (command === 'capabilities') {
    if (args.length) {
      (runtime.stderr ?? process.stderr).write('WORK_INPUT_INVALID\n');
      return 2;
    }
    (runtime.stdout ?? process.stdout).write(`${JSON.stringify(workCapabilities())}\n`);
    return 0;
  }

  if (isWorkCommand(command) && !args.includes('--help') && !args.includes('-h')) {
    return runWorkCommand(command, args, env, runtime);
  }

  if (REMOTE_COMMANDS.has(command)) {
    return runRemoteCommand(command, args, env, runtime);
  }

  if (RUNTIME_COMMANDS.has(command)) {
    return runRuntimeCommand(command, args, env, runtime);
  }

  const stdout = runtime.stdout ?? process.stdout;
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    stdout.write(HELP);
    return 0;
  }

  if (['login', 'whoami', 'logout'].includes(command)) return runAuthCommand(command, args, env, runtime);

  if (command === 'runtime-readiness' || command === 'runtime-retain-empty-stage') {
    try {
      const [deviceId, ...flags] = args;
      if (!/^dev_[a-z0-9]+$/u.test(deviceId ?? '')) throw new Error('RUNTIME_INPUT_INVALID');
      let result;
      if (command === 'runtime-readiness') {
        if (flags.length && (flags.length !== 2 || flags[0] !== '--interval-seconds' || !/^\d+$/u.test(flags[1]))) throw new Error('RUNTIME_INPUT_INVALID');
        const { observeReadiness } = await import('./runtime/runtime-readiness.mjs');
        result = await observeReadiness(deviceId, flags.length ? Number(flags[1]) : 60, env);
      } else {
        if (flags.length !== 1 || !['--inspect', '--apply', '--reconcile'].includes(flags[0])) throw new Error('RUNTIME_INPUT_INVALID');
        const { retainEmptyStage } = await import('./runtime/empty-stage-retention.mjs');
        result = await retainEmptyStage(flags[0].slice(2), deviceId, env);
      }
      stdout.write(`${JSON.stringify(result)}\n`);
      return result.status === 'READY_FOR_PLAN' || command === 'runtime-retain-empty-stage' ? 0 : 2;
    } catch (error) {
      const code = error?.code ?? error?.message;
      const allowed = typeof code === 'string' && (/^RUNTIME_[A-Z_]+$/u.test(code)
        || ['DEVICE_NOT_FOUND', 'DEVICE_NOT_READY', 'DEVICE_BUSY'].includes(code));
      (runtime.stderr ?? process.stderr).write(`${allowed ? code : 'RUNTIME_INVENTORY_FAILED'}\n`);
      return 2;
    }
  }

  if (command === 'pair') {
    return runPairCommand(args, env, runtime);
  }

  if (command === 'enroll') {
    return runEnrollmentCommand(args, env, runtime);
  }

  const paths = statePaths(env);
  const registry = new DeviceRegistry(paths.devices);

  if (command === 'list') {
    parseArgs({ args, options: {}, strict: true });
    stdout.write(`${JSON.stringify(await registry.list(), null, 2)}\n`);
    return 0;
  }

  if (command === 'status') {
    const [id, ...extraArgs] = args;
    if (!id) {
      throw new Error('device id is required');
    }
    parseArgs({ args: extraArgs, options: {}, strict: true });
    const device = await registry.get(id);
    if (!device) {
      throw new Error(`device not found: ${id}`);
    }
    stdout.write(`${JSON.stringify(device, null, 2)}\n`);
    return 0;
  }

  throw new Error(`unknown command: ${command}`);
}

if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
) {
  main().then(
    (exitCode) => { process.exitCode = exitCode; },
    (error) => {
      process.stderr.write(`agent-road: ${error.message}\n`);
      process.exitCode = 2;
    },
  );
}
