import { captureProvisionFailure } from './provision-diagnostic.mjs';
import {
  createHash,
  randomBytes as cryptoRandomBytes,
  randomUUID,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isProxy } from 'node:util/types';

import { statePaths } from '../core/paths.mjs';
import { BootstrapSigner } from '../identity/bootstrap-signer.mjs';
import { SshIdentityStore } from '../identity/ssh-identity-store.mjs';
import { runProcess } from '../process/run-process.mjs';
import { executeRemoteScript } from '../remote/remote-exec.mjs';
import { loadRemoteTarget, trustedInput } from '../remote/remote-target.mjs';
import { selectAddress } from '../remote/windows-remote.mjs';
import {
  isTrustedSshSessionLockError,
  withTrustedSshSession,
} from '../ssh/trusted-ssh-session.mjs';
import { DeviceRegistry } from '../storage/device-registry.mjs';
import { acquireRuntimeArtifact } from './artifact-cache.mjs';
import {
  isRuntimeAcquisitionPolicy,
  RUNTIME_ACQUISITION_POLICY,
} from './runtime-acquisition-policy.mjs';
import { loadProductionRuntimeCatalog } from './production-runtime-catalog.mjs';
import { RUNTIME_BASELINE_SCRIPT_PATH } from './runtime-baseline.mjs';
import { RuntimeBaselineStore } from './runtime-baseline-store.mjs';
import { readRuntimeInventory } from './runtime-doctor.mjs';
import {
  RUNTIME_PROVISION_SCRIPT_PATH,
  runtimeProvision,
  runtimeProvisionFromAuthorizedSources,
} from './runtime-provision.mjs';
import {
  readRuntimePlanInventoryPair,
  RUNTIME_PLAN_INVENTORY_SCRIPT_PATH,
} from './runtime-plan-inventory.mjs';
import { RuntimePlanTicketStore } from './runtime-plan-ticket-store.mjs';
import {
  applyRuntimeRecoveryRemote,
  inspectRuntimeRecoveryRemote,
} from './runtime-recovery-remote.mjs';
import { RuntimeRecoveryStore } from './runtime-recovery-store.mjs';
import { RuntimeStateStore } from './runtime-state-store.mjs';

const SSH_LOCK_TIMEOUT_MS = 15 * 60 * 1_000;
const BASELINE_SCRIPT_TIMEOUT_MS = 120_000;
const BASELINE_OUTPUT_BYTES = 8_192;
const BASELINE_PROTOCOL_INPUT_BYTES = 256;
const SSH_STDIN_BYTES = 64 * 1_024;
const WINDOWS_COMMAND_BYTES = 7_000;
const BASELINE_SCRIPT_BYTES = SSH_STDIN_BYTES - BASELINE_PROTOCOL_INPUT_BYTES;
const BASELINE_EXECUTION_FIELDS = Object.freeze([
  'deviceId',
  'scriptPath',
  'scriptSha256',
  'timeoutMs',
  'maxOutputBytes',
  'stdinText',
]);
const BASELINE_EXECUTION_DEPENDENCY_FIELDS = Object.freeze([
  'readBaselineScript',
  'loadTarget',
  'trustedInput',
  'withTrustedSshSession',
  'selectAddress',
  'isTrustedSshSessionLockError',
  'runProcess',
  'clock',
]);
const BASELINE_PROCESS_FIELDS = Object.freeze([
  'command',
  'args',
  'exitCode',
  'signal',
  'stdout',
  'stderr',
]);
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const PROVISION_FIELDS = Object.freeze([
  'target',
  'plan',
  'capsule',
  'inventorySnapshot',
  'artifactFiles',
]);
const RECOVERY_INSPECT_FIELDS = Object.freeze([
  'target',
  'operationId',
  'beforeBootMarker',
  'priorAuthorizedAttempt',
]);
const RECOVERY_APPLY_FIELDS = Object.freeze([
  'target',
  'proof',
  'authorizedAttempt',
]);
const RUNTIME_RECOVERY_MUTATOR_PATH = fileURLToPath(
  new URL('./runtime-recovery-remote.mjs', import.meta.url),
);
const RUNTIME_PLAN_INVENTORY_MUTATOR_PATH = fileURLToPath(
  new URL('./runtime-plan-inventory.mjs', import.meta.url),
);
const REMOTE_EXEC_MUTATOR_PATH = fileURLToPath(
  new URL('../remote/remote-exec.mjs', import.meta.url),
);
const PROVISION_UPLOAD_MUTATOR_PATH = fileURLToPath(
  new URL('./provision-upload.mjs', import.meta.url),
);
const RUNTIME_PROVISION_MUTATOR_PATH = fileURLToPath(
  new URL('./runtime-provision.mjs', import.meta.url),
);
const ENSURE_RUNTIME_MUTATOR_PATH = fileURLToPath(
  new URL('./ensure-runtime.mjs', import.meta.url),
);
const RUNTIME_MANIFEST_MUTATOR_PATH = fileURLToPath(
  new URL('./runtime-manifest.mjs', import.meta.url),
);
const WINDOWS_REMOTE_MUTATOR_PATH = fileURLToPath(
  new URL('../remote/windows-remote.mjs', import.meta.url),
);
const PROVISION_REVISION_DOMAIN = Buffer.from(
  'AgentRoad.RuntimeProvisionRevision.v1\0',
  'utf8',
);
const INVENTORY_REVISION_DOMAIN = Buffer.from(
  'AgentRoad.RuntimePlanInventoryRevision.v1\0',
  'utf8',
);
const RECOVERY_REVISION_DOMAIN = Buffer.from(
  'AgentRoad.RuntimeRecoveryRevision.v1\0',
  'utf8',
);

export const PRODUCTION_RUNTIME_ACQUISITION_POLICY = RUNTIME_ACQUISITION_POLICY;

function inputError() {
  const error = new TypeError('RUNTIME_INPUT_INVALID');
  error.code = 'RUNTIME_INPUT_INVALID';
  return error;
}

function runtimeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function updateRevisionComponent(hash, label, bytes) {
  if (!Buffer.isBuffer(bytes) || Object.getPrototypeOf(bytes) !== Buffer.prototype) {
    throw inputError();
  }
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hash.update(Buffer.from(`${label}\0`, 'utf8'));
  hash.update(length);
  hash.update(bytes);
}

export function digestRuntimeRecoveryRevision(recoveryAdapterBytes, windowsRemoteBytes) {
  const hash = createHash('sha256');
  hash.update(RECOVERY_REVISION_DOMAIN);
  updateRevisionComponent(hash, 'recovery-adapter', recoveryAdapterBytes);
  updateRevisionComponent(hash, 'windows-remote', windowsRemoteBytes);
  return hash.digest('hex').toUpperCase();
}

export function digestRuntimeInventoryRevision(inventoryScriptBytes, inventoryAdapterBytes) {
  const hash = createHash('sha256');
  hash.update(INVENTORY_REVISION_DOMAIN);
  updateRevisionComponent(hash, 'inventory-script', inventoryScriptBytes);
  updateRevisionComponent(hash, 'inventory-adapter', inventoryAdapterBytes);
  return hash.digest('hex').toUpperCase();
}

export function digestRuntimeProvisionRevision(
  provisionScriptBytes,
  remoteExecBytes,
  provisionUploadBytes,
  runtimeProvisionBytes,
  windowsRemoteBytes,
  ensureRuntimeBytes,
  runtimeManifestBytes,
) {
  const hash = createHash('sha256');
  hash.update(PROVISION_REVISION_DOMAIN);
  updateRevisionComponent(hash, 'provision-script', provisionScriptBytes);
  updateRevisionComponent(hash, 'remote-exec', remoteExecBytes);
  updateRevisionComponent(hash, 'provision-upload', provisionUploadBytes);
  updateRevisionComponent(hash, 'runtime-provision', runtimeProvisionBytes);
  updateRevisionComponent(hash, 'windows-remote', windowsRemoteBytes);
  updateRevisionComponent(hash, 'ensure-runtime', ensureRuntimeBytes);
  updateRevisionComponent(hash, 'runtime-manifest', runtimeManifestBytes);
  return hash.digest('hex').toUpperCase();
}

function snapshotExactDataObject(input, fields) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw inputError();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    throw inputError();
  }
  const result = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw inputError();
    result[field] = descriptor.value;
  }
  return result;
}

function snapshotBaselineExecution(input) {
  const value = snapshotExactDataObject(input, BASELINE_EXECUTION_FIELDS);
  if (
    typeof value.deviceId !== 'string'
    || value.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || value.scriptPath !== RUNTIME_BASELINE_SCRIPT_PATH
    || typeof value.scriptSha256 !== 'string'
    || !SHA256_PATTERN.test(value.scriptSha256)
    || value.timeoutMs !== BASELINE_SCRIPT_TIMEOUT_MS
    || value.maxOutputBytes !== BASELINE_OUTPUT_BYTES
  ) throw inputError();
  if (
    typeof value.stdinText !== 'string'
    || Buffer.byteLength(value.stdinText, 'utf8') < 1
    || Buffer.byteLength(value.stdinText, 'utf8') > BASELINE_PROTOCOL_INPUT_BYTES
    || /[^\x01-\x7f]/u.test(value.stdinText)
  ) throw inputError();
  let protocol;
  try {
    protocol = JSON.parse(value.stdinText);
  } catch {
    throw inputError();
  }
  const canonical = snapshotExactDataObject(
    protocol,
    Object.freeze(['schemaVersion', 'protocolRevision', 'hmacKeyBase64']),
  );
  let canonicalKey = false;
  let keyBytes;
  if (
    typeof canonical.hmacKeyBase64 === 'string'
    && /^[A-Za-z0-9+/]{43}=$/u.test(canonical.hmacKeyBase64)
  ) {
    try {
      keyBytes = Buffer.from(canonical.hmacKeyBase64, 'base64');
      canonicalKey = keyBytes.length === 32
        && keyBytes.toString('base64') === canonical.hmacKeyBase64;
    } finally {
      if (keyBytes) keyBytes.fill(0);
    }
  }
  if (
    canonical.schemaVersion !== 1
    || canonical.protocolRevision !== 1
    || !canonicalKey
    || JSON.stringify(canonical) !== value.stdinText
  ) throw inputError();
  return Object.freeze({ ...value });
}

function snapshotBaselineExecutionDependencies(input) {
  const value = snapshotExactDataObject(input, BASELINE_EXECUTION_DEPENDENCY_FIELDS);
  for (const field of BASELINE_EXECUTION_DEPENDENCY_FIELDS) {
    if (typeof value[field] !== 'function' || isProxy(value[field])) throw inputError();
  }
  return Object.freeze({ ...value });
}

function canonicalClock(clock) {
  let value;
  try {
    value = clock();
    if (
      value === null
      || typeof value !== 'object'
      || isProxy(value)
      || Object.getPrototypeOf(value) !== Date.prototype
      || Object.getOwnPropertyNames(value).length !== 0
      || Object.getOwnPropertySymbols(value).length !== 0
    ) throw new TypeError('invalid clock');
    return Date.prototype.toISOString.call(value);
  } catch {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
}

function snapshotBaselineProcess(input, maxOutputBytes) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== BASELINE_PROCESS_FIELDS.length
    || !BASELINE_PROCESS_FIELDS.every((field) => names.includes(field))
  ) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  const value = Object.create(null);
  for (const field of BASELINE_PROCESS_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw runtimeError('RUNTIME_INVENTORY_FAILED');
    }
    value[field] = descriptor.value;
  }
  if (
    !Number.isSafeInteger(value.exitCode)
    || value.exitCode < 0
    || value.exitCode > 255
    || value.signal !== null
    || typeof value.stdout !== 'string'
    || typeof value.stderr !== 'string'
    || Buffer.byteLength(value.stdout, 'utf8') > maxOutputBytes
    || Buffer.byteLength(value.stderr, 'utf8') > maxOutputBytes - Buffer.byteLength(value.stdout, 'utf8')
  ) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  return value;
}

function baselineLoader(scriptBytes, scriptSha256) {
  const source = [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    "$VerbosePreference='SilentlyContinue'",
    "$DebugPreference='SilentlyContinue'",
    "$InformationPreference='SilentlyContinue'",
    "$WarningPreference='SilentlyContinue'",
    `$n=${scriptBytes}`,
    `$e='${scriptSha256}'`,
    '$s=[Console]::OpenStandardInput()',
    "$b=New-Object 'byte[]' $n",
    '$o=0',
    'while($o -lt $n){$r=$s.Read($b,$o,$n-$o);if($r -le 0){exit 42};$o+=$r}',
    "$h=[Security.Cryptography.SHA256]::Create()",
    "try{$a=[BitConverter]::ToString($h.ComputeHash($b)).Replace('-','')}finally{$h.Dispose()}",
    'if($a -cne $e){[Array]::Clear($b,0,$b.Length);exit 42}',
    'try{$u=New-Object Text.UTF8Encoding($false,$true);$x=$u.GetString($b);[Array]::Clear($b,0,$b.Length);&([ScriptBlock]::Create($x))}catch{[Array]::Clear($b,0,$b.Length);exit 42}',
  ].join(';');
  const encoded = Buffer.from(source, 'utf16le').toString('base64');
  const argv = Object.freeze([
    'powershell.exe',
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-EncodedCommand',
    encoded,
  ]);
  if (Buffer.byteLength(argv.join(' '), 'utf8') >= WINDOWS_COMMAND_BYTES) {
    throw runtimeError('RUNTIME_INTERNAL_ERROR');
  }
  return argv;
}

async function runProductionRuntimeBaselineScript(config, dependencies) {
  let source;
  try {
    source = await dependencies.readBaselineScript();
  } catch {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
  if (
    !Buffer.isBuffer(source)
    || isProxy(source)
    || Object.getPrototypeOf(source) !== Buffer.prototype
    || source.length < 1
    || source.length > BASELINE_SCRIPT_BYTES
  ) throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  const script = Buffer.from(source);
  const scriptSha256 = createHash('sha256').update(script).digest('hex').toUpperCase();
  if (scriptSha256 !== config.scriptSha256) {
    throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
  const scriptText = script.toString('ascii');
  if (!Buffer.from(scriptText, 'ascii').equals(script)) {
    throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
  const framedInput = `${scriptText}${config.stdinText}`;
  if (Buffer.byteLength(framedInput, 'ascii') > SSH_STDIN_BYTES) {
    throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
  const argv = baselineLoader(script.length, scriptSha256);
  let target;
  let trust;
  try {
    target = await dependencies.loadTarget(config.deviceId);
    trust = dependencies.trustedInput(target, dependencies.runProcess);
  } catch {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }

  try {
    return await dependencies.withTrustedSshSession(
      trust,
      async (session) => {
        const address = await dependencies.selectAddress(session);
        if (typeof address !== 'string' || isIP(address) === 0) {
          throw runtimeError('RUNTIME_INVENTORY_FAILED');
        }
        const startedAt = canonicalClock(dependencies.clock);
        const process = snapshotBaselineProcess(await session.invokeSsh(address, argv, {
          timeoutMs: config.timeoutMs,
          maxOutputBytes: config.maxOutputBytes,
          stdinText: framedInput,
        }), config.maxOutputBytes);
        const finishedAt = canonicalClock(dependencies.clock);
        if (finishedAt < startedAt) throw runtimeError('RUNTIME_INVENTORY_FAILED');
        return Object.freeze({
          schemaVersion: 1,
          operation: 'exec',
          deviceId: config.deviceId,
          address,
          exitCode: process.exitCode,
          stdout: process.stdout,
          stderr: process.stderr,
          startedAt,
          finishedAt,
        });
      },
      { lockTimeoutMs: SSH_LOCK_TIMEOUT_MS },
    );
  } catch (error) {
    let locked = false;
    try { locked = dependencies.isTrustedSshSessionLockError(error) === true; } catch {}
    throw runtimeError(locked ? 'RUNTIME_ALREADY_RUNNING' : 'RUNTIME_INVENTORY_FAILED');
  }
}

export function executeProductionRuntimeBaselineScript(input, inputDependencies) {
  const config = snapshotBaselineExecution(input);
  const dependencies = snapshotBaselineExecutionDependencies(inputDependencies);
  return runProductionRuntimeBaselineScript(config, dependencies);
}

function snapshotProvisionInput(input) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw inputError();
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== PROVISION_FIELDS.length
    || !PROVISION_FIELDS.every((field) => names.includes(field))
  ) throw inputError();
  const snapshot = Object.create(null);
  for (const field of PROVISION_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw inputError();
    snapshot[field] = descriptor.value;
  }
  return snapshot;
}

export function createProductionRuntimeProvisionInput(input, dependencies) {
  const value = snapshotProvisionInput(input);
  return Object.freeze({
    target: value.target,
    plan: value.plan,
    capsule: value.capsule,
    inventorySnapshot: value.inventorySnapshot,
    artifactFiles: value.artifactFiles,
    dependencies,
  });
}

async function provisionRuntime(input, dependencies) {
  return runtimeProvision(createProductionRuntimeProvisionInput(input, dependencies));
}

function createProductionRecoveryRemoteInput(input, fields, dependencies) {
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
  const result = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw inputError();
    result[field] = descriptor.value;
  }
  result.dependencies = dependencies;
  return Object.freeze(result);
}

function createRuntimeMutatorSourceCache() {
  let pending = null;
  return async () => {
    pending ??= Promise.all([
      readFile(RUNTIME_PLAN_INVENTORY_SCRIPT_PATH),
      readFile(RUNTIME_PLAN_INVENTORY_MUTATOR_PATH),
      readFile(RUNTIME_PROVISION_SCRIPT_PATH),
      readFile(RUNTIME_RECOVERY_MUTATOR_PATH),
      readFile(WINDOWS_REMOTE_MUTATOR_PATH),
      readFile(REMOTE_EXEC_MUTATOR_PATH),
      readFile(PROVISION_UPLOAD_MUTATOR_PATH),
      readFile(RUNTIME_PROVISION_MUTATOR_PATH),
      readFile(ENSURE_RUNTIME_MUTATOR_PATH),
      readFile(RUNTIME_MANIFEST_MUTATOR_PATH),
    ]).then(([
      inventory,
      inventoryAdapter,
      provision,
      recovery,
      windowsRemote,
      remoteExec,
      provisionUpload,
      runtimeProvisionSource,
      ensureRuntimeSource,
      runtimeManifestSource,
    ]) => Object.freeze({
      inventoryBytes: Buffer.from(inventory),
      provisionBytes: Buffer.from(provision),
      recoveryBytes: Buffer.from(recovery),
      revisions: Object.freeze({
        inventoryScriptSha256: createHash('sha256')
          .update(inventory)
          .digest('hex')
          .toUpperCase(),
        inventorySha256: digestRuntimeInventoryRevision(inventory, inventoryAdapter),
        provisionSha256: digestRuntimeProvisionRevision(
          provision,
          remoteExec,
          provisionUpload,
          runtimeProvisionSource,
          windowsRemote,
          ensureRuntimeSource,
          runtimeManifestSource,
        ),
        recoverySha256: digestRuntimeRecoveryRevision(recovery, windowsRemote),
      }),
    }));
    return pending;
  };
}

function createRuntimeAuthorizationContext(env) {
  const paths = statePaths(env);
  const registry = new DeviceRegistry(paths.devices);
  const sshIdentity = new SshIdentityStore(paths.sshIdentities);
  const signer = new BootstrapSigner(paths.signingPrivateKey, paths.signingPublicKey);
  const stateStore = new RuntimeStateStore(paths.runtimeDevices);
  const baselineStore = new RuntimeBaselineStore(paths.runtimeDevices);
  const ticketStore = new RuntimePlanTicketStore(paths.runtimeDevices);
  const sourceManifest = createRuntimeMutatorSourceCache();
  const knownHostsPath = (deviceId) => join(
    paths.knownHosts,
    `agent-road-known-hosts-${deviceId}`,
  );
  const operationId = () => randomUUID().replaceAll('-', '');
  const clock = () => new Date();
  const loadTarget = (deviceId) => loadRemoteTarget(deviceId, {
    registry,
    sshIdentity,
    knownHostsPath,
  });
  const readInventoryPair = (target) => readRuntimePlanInventoryPair({
    target,
    dependencies: {
      readInventoryScript: async () => Buffer.from((await sourceManifest()).inventoryBytes),
      trustedInput,
      withTrustedSshSession,
      selectAddress,
      isTrustedSshSessionLockError,
      runProcess,
    },
  });
  const readBaselineBinding = async (input) => {
    const baseline = await baselineStore.readBaseline(input);
    return Object.freeze({
      baselineId: baseline.baselineId,
      schemaVersion: baseline.schemaVersion,
      protocolRevision: baseline.protocolRevision,
      captureAggregateMac: baseline.captureAggregateMac,
      recordDigest: baseline.recordDigest,
      capturedAt: baseline.capturedAt,
      expiresAt: baseline.expiresAt,
    });
  };
  const readMutatorRevisions = async () => (await sourceManifest()).revisions;
  return Object.freeze({
    paths,
    signer,
    stateStore,
    ticketStore,
    loadTarget,
    readInventoryPair,
    readBaselineBinding,
    readMutatorRevisions,
    sourceManifest,
    operationId,
    clock,
  });
}

export function createProductionRuntimePlanDependencies(env = process.env) {
  const context = createRuntimeAuthorizationContext(env);
  return Object.freeze({
    loadTarget: context.loadTarget,
    readState: (deviceId) => context.stateStore.read(deviceId),
    readInventoryPair: context.readInventoryPair,
    loadCatalog: () => loadProductionRuntimeCatalog(),
    readBaselineBinding: context.readBaselineBinding,
    getSigningPublicKey: () => context.signer.getOrCreate(),
    readMutatorRevisions: context.readMutatorRevisions,
    createPlanTicket: (input) => context.ticketStore.createTicket(input),
    operationId: context.operationId,
    clock: context.clock,
  });
}

export function createProductionApprovedRuntimeDependencies(env = process.env) {
  const context = createRuntimeAuthorizationContext(env);
  let approvedSigningPublicKey = null;
  const fetchImplementation = globalThis.fetch;
  const fetchEnvelope = async (url, options) => Object.freeze({
    response: await Reflect.apply(fetchImplementation, globalThis, [url, options]),
  });
  return Object.freeze({
    loadTarget: context.loadTarget,
    readState: (deviceId) => context.stateStore.read(deviceId),
    transitionState: (expected, next) => context.stateStore.transition(expected, next),
    readInventoryPair: context.readInventoryPair,
    loadCatalog: () => loadProductionRuntimeCatalog(),
    readBaselineBinding: context.readBaselineBinding,
    getSigningPublicKey: async () => {
      approvedSigningPublicKey = await context.signer.getExisting();
      return approvedSigningPublicKey;
    },
    readMutatorRevisions: context.readMutatorRevisions,
    readPlanTicket: (input) => context.ticketStore.readTicket(input),
    consumePlanTicket: (input) => context.ticketStore.consumeTicket(input),
    sign: (bytes) => {
      if (approvedSigningPublicKey === null) {
        const error = new Error('BOOTSTRAP_SIGNING_KEY_MISMATCH');
        error.code = 'BOOTSTRAP_SIGNING_KEY_MISMATCH';
        throw error;
      }
      return context.signer.signExisting(bytes, approvedSigningPublicKey);
    },
    acquireArtifact: (artifact, acquisitionPolicy) => {
      if (!isRuntimeAcquisitionPolicy(acquisitionPolicy)) throw inputError();
      return acquireRuntimeArtifact({
        cacheRoot: context.paths.runtimeArtifacts,
        artifact,
        policy: RUNTIME_ACQUISITION_POLICY,
        dependencies: { fetch: fetchEnvelope },
      });
    },
    provision: async (input) => {
      const sources = await context.sourceManifest();
      try { return await runtimeProvisionFromAuthorizedSources(
        createProductionRuntimeProvisionInput(input, {
          runProcess,
          operationId: context.operationId,
          clock: context.clock,
          sshLockTimeoutMs: SSH_LOCK_TIMEOUT_MS,
        }),
        {
          inventoryScriptBytes: Buffer.from(sources.inventoryBytes),
          provisionScriptBytes: Buffer.from(sources.provisionBytes),
        },
      ); } catch (error) {
        // Diagnostic publication must not replace the authoritative failure.
        try { await captureProvisionFailure(env, error); } catch { /* retain original failure */ }
        throw error;
      }
    },
  });
}

export function createProductionRuntimeDependencies(env = process.env) {
  const paths = statePaths(env);
  const registry = new DeviceRegistry(paths.devices);
  const sshIdentity = new SshIdentityStore(paths.sshIdentities);
  const signer = new BootstrapSigner(paths.signingPrivateKey, paths.signingPublicKey);
  const stateStore = new RuntimeStateStore(paths.runtimeDevices);
  const knownHostsPath = (deviceId) => join(
    paths.knownHosts,
    `agent-road-known-hosts-${deviceId}`,
  );
  const operationId = () => randomUUID().replaceAll('-', '');
  const clock = () => new Date();
  const fetchImplementation = globalThis.fetch;
  const fetchEnvelope = async (url, options) => Object.freeze({
    response: await Reflect.apply(fetchImplementation, globalThis, [url, options]),
  });

  return Object.freeze({
    loadTarget: (deviceId) => loadRemoteTarget(deviceId, {
      registry,
      sshIdentity,
      knownHostsPath,
    }),
    readState: (deviceId) => stateStore.read(deviceId),
    transitionState: (expected, next) => stateStore.transition(expected, next),
    readInventory: (target) => readRuntimeInventory({
      target,
      dependencies: {
        executeRemoteScript,
        runProcess,
        operationId,
        clock,
      },
    }),
    loadCatalog: () => loadProductionRuntimeCatalog(),
    getSigningPublicKey: () => signer.getOrCreate(),
    sign: (bytes) => signer.sign(bytes),
    acquireArtifact: (artifact) => acquireRuntimeArtifact({
      cacheRoot: paths.runtimeArtifacts,
      artifact,
      policy: PRODUCTION_RUNTIME_ACQUISITION_POLICY,
      dependencies: { fetch: fetchEnvelope },
    }),
    provision: (input) => provisionRuntime(input, {
        runProcess,
        operationId,
        clock,
        sshLockTimeoutMs: SSH_LOCK_TIMEOUT_MS,
    }),
    operationId,
    clock,
  });
}

export function createProductionRuntimeBaselineDependencies(env = process.env) {
  const paths = statePaths(env);
  const registry = new DeviceRegistry(paths.devices);
  const sshIdentity = new SshIdentityStore(paths.sshIdentities);
  const baselineStore = new RuntimeBaselineStore(paths.runtimeDevices);
  const knownHostsPath = (deviceId) => join(
    paths.knownHosts,
    `agent-road-known-hosts-${deviceId}`,
  );
  const executionDependencies = Object.freeze({
    readBaselineScript: () => readFile(RUNTIME_BASELINE_SCRIPT_PATH),
    loadTarget: (deviceId) => loadRemoteTarget(deviceId, {
      registry,
      sshIdentity,
      knownHostsPath,
    }),
    trustedInput,
    withTrustedSshSession,
    selectAddress,
    isTrustedSshSessionLockError,
    runProcess,
    clock: () => new Date(),
  });

  return Object.freeze({
    executeBaselineScript: (input) => executeProductionRuntimeBaselineScript(
      input,
      executionDependencies,
    ),
    createBaseline: (input) => baselineStore.createBaseline(input),
    readBaseline: (input) => baselineStore.readBaseline(input),
    createComparison: (input) => baselineStore.createComparison(input),
    randomBytes: (size) => cryptoRandomBytes(size),
  });
}

export function createProductionRuntimeRecoveryDependencies(env = process.env) {
  const paths = statePaths(env);
  const registry = new DeviceRegistry(paths.devices);
  const sshIdentity = new SshIdentityStore(paths.sshIdentities);
  const stateStore = new RuntimeStateStore(paths.runtimeDevices);
  const recoveryStore = new RuntimeRecoveryStore(paths.runtimeDevices);
  const knownHostsPath = (deviceId) => join(
    paths.knownHosts,
    `agent-road-known-hosts-${deviceId}`,
  );
  const transportDependencies = Object.freeze({
    runProcess,
    sshLockTimeoutMs: SSH_LOCK_TIMEOUT_MS,
  });

  return Object.freeze({
    loadTarget: (deviceId) => loadRemoteTarget(deviceId, {
      registry,
      sshIdentity,
      knownHostsPath,
    }),
    readState: (deviceId) => stateStore.read(deviceId),
    transitionState: (expected, next) => stateStore.transition(expected, next),
    withRecoveryOperation: (input, callback) => recoveryStore.withOperationLock(
      input,
      callback,
    ),
    inspectRemote: (input) => inspectRuntimeRecoveryRemote(
      createProductionRecoveryRemoteInput(
        input,
        RECOVERY_INSPECT_FIELDS,
        transportDependencies,
      ),
    ),
    applyRemote: (input) => applyRuntimeRecoveryRemote(
      createProductionRecoveryRemoteInput(
        input,
        RECOVERY_APPLY_FIELDS,
        transportDependencies,
      ),
    ),
    clock: () => new Date(),
  });
}
