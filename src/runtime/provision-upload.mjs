import {
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from 'node:crypto';
import { isIP } from 'node:net';
import { isAbsolute, resolve } from 'node:path';
import { isProxy } from 'node:util/types';

import { snapshotBytes, snapshotLocalFile } from '../remote/local-file.mjs';
import { trustedInput } from '../remote/remote-target.mjs';
import {
  WINDOWS_PROVISION_CLEANUP_WRAPPER,
  WINDOWS_PROVISION_FINALIZE_WRAPPER,
  WINDOWS_PROVISION_INIT_WRAPPER,
  WINDOWS_PROVISION_INSPECT_WRAPPER,
  encodeRemotePayload,
  powershellInvocation,
  selectAddress,
} from '../remote/windows-remote.mjs';
import { withTrustedSshSession } from '../ssh/trusted-ssh-session.mjs';
import { markProvisionFailure, provisionFailureStage } from './provision-diagnostic.mjs';

const MAX_TRANSFER_BYTES = 256 * 1024 * 1024;
const MAX_COMPONENTS = 32;
const MAX_VERSION_LENGTH = 64;
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_CAPSULE_BYTES = 128 * 1024;
const MAX_PATH_BYTES = 4_096;
const MIN_LOCK_TIMEOUT_MS = 1_000;
const MAX_LOCK_TIMEOUT_MS = 15 * 60 * 1_000;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const ID_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const CREATED_AT_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const RUNTIME_DOMAIN = Buffer.from('AGENT_ROAD_RUNTIME_V1\0', 'ascii');
const CONTROLLER_KEY_DOMAIN = Buffer.from('AGENT_ROAD_CONTROLLER_KEY_V1\0', 'ascii');
const ROOT_FIELDS = Object.freeze(['target', 'capsule', 'artifactFiles', 'dependencies']);
const DEPENDENCY_FIELDS = Object.freeze(['runProcess', 'sshLockTimeoutMs']);
const CAPSULE_FIELDS = Object.freeze([
  'schemaVersion',
  'manifestJson',
  'manifestDigest',
  'generationDigest',
  'signatureAlgorithm',
  'signatureBase64',
  'controllerKeyId',
  'controllerPublicKeyJson',
]);
const MANIFEST_FIELDS = Object.freeze([
  'schemaVersion',
  'deviceId',
  'operationId',
  'createdAt',
  'platform',
  'catalogRevision',
  'catalogDigest',
  'inventoryDigest',
  'requestedProfiles',
  'profiles',
  'acquisition',
  'generationDigest',
  'phases',
  'components',
]);
const PLATFORM_FIELDS = Object.freeze([
  'os',
  'version',
  'build',
  'edition',
  'architecture',
  'windowsPowerShellVersion',
  'elevated',
]);
const COMPONENT_FIELDS = Object.freeze([
  'id',
  'version',
  'bytes',
  'maximumExpandedBytes',
  'sha256',
  'packaging',
  'signerRule',
  'verificationCommandId',
]);
const PUBLIC_KEY_FIELDS = Object.freeze([
  'algorithm',
  'modulusBase64Url',
  'exponentBase64Url',
]);
const ARTIFACT_FILE_FIELDS = Object.freeze([
  'artifactId',
  'version',
  'path',
  'bytes',
  'sha256',
]);
const PHASES = Object.freeze([
  'discover',
  'verify-manifest',
  'verify-artifacts',
  'snapshot',
  'materialize-generation',
  'self-test',
  'atomic-activate',
  'validate',
  'commit',
  'rollback',
  'reconcile',
]);
const PUBLIC_CODES = new Set([
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_SIGNATURE_INVALID',
  'RUNTIME_ARTIFACT_INVALID',
  'RUNTIME_STAGE_FAILED',
  'RUNTIME_COMPLETION_UNCERTAIN',
]);
const PROCESS_RESULT_FIELDS = new Set([
  'command', 'args', 'exitCode', 'signal', 'stdout', 'stderr',
]);
const PREPARED_UPLOADS = new WeakMap();
const SESSION_FIELDS = new Set([
  'addresses',
  'invokeSsh',
  'invokeScp',
  'invokeCleanup',
  'remoteSpec',
]);

function runtimeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function fail(code = 'RUNTIME_INPUT_INVALID') {
  throw runtimeError(code);
}

function safeCode(error) {
  if (
    error === null
    || (typeof error !== 'object' && typeof error !== 'function')
    || isProxy(error)
  ) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
  return descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
}

function readExactRecord(input, fields, code = 'RUNTIME_INPUT_INVALID') {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code);
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== fields.length
    || !fields.every((field) => names.includes(field))
  ) fail(code);
  const result = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) fail(code);
    result[field] = descriptor.value;
  }
  return result;
}

function readExactArray(input, minimum, maximum, code) {
  if (
    isProxy(input)
    || !Array.isArray(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail(code);
  const length = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    length === undefined
    || !Object.hasOwn(length, 'value')
    || !Number.isSafeInteger(length.value)
    || length.value < minimum
    || length.value > maximum
    || Object.getOwnPropertyNames(input).length !== length.value + 1
  ) fail(code);
  const values = [];
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) fail(code);
    values.push(descriptor.value);
  }
  return values;
}

function digest(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest('hex').toUpperCase();
}

function canonicalDate(value) {
  if (typeof value !== 'string' || !CREATED_AT_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function validateStringArray(input, allowed, { minimum = 0, maximum = 2 } = {}) {
  const values = readExactArray(input, minimum, maximum, 'RUNTIME_SIGNATURE_INVALID');
  if (
    values.some((value) => typeof value !== 'string' || !allowed.includes(value))
    || new Set(values).size !== values.length
  ) fail('RUNTIME_SIGNATURE_INVALID');
  return values;
}

function validateComponent(input, previousId) {
  const value = readExactRecord(input, COMPONENT_FIELDS, 'RUNTIME_SIGNATURE_INVALID');
  if (
    typeof value.id !== 'string'
    || !ID_PATTERN.test(value.id)
    || (previousId !== null && value.id <= previousId)
    || typeof value.version !== 'string'
    || value.version.length > MAX_VERSION_LENGTH
    || !VERSION_PATTERN.test(value.version)
    || !Number.isSafeInteger(value.bytes)
    || value.bytes < 1
    || value.bytes > MAX_TRANSFER_BYTES
    || !Number.isSafeInteger(value.maximumExpandedBytes)
    || value.maximumExpandedBytes < 1
    || value.maximumExpandedBytes > 32 * 1024 ** 3
    || typeof value.sha256 !== 'string'
    || !SHA256_PATTERN.test(value.sha256)
    || value.packaging !== 'zip'
    || typeof value.signerRule !== 'string'
    || !ID_PATTERN.test(value.signerRule)
    || typeof value.verificationCommandId !== 'string'
    || !ID_PATTERN.test(value.verificationCommandId)
  ) fail('RUNTIME_SIGNATURE_INVALID');
  return Object.freeze({ ...value });
}

function validateManifest(input, canonicalJson) {
  const value = readExactRecord(input, MANIFEST_FIELDS, 'RUNTIME_SIGNATURE_INVALID');
  const platform = readExactRecord(value.platform, PLATFORM_FIELDS, 'RUNTIME_SIGNATURE_INVALID');
  if (
    value.schemaVersion !== 1
    || typeof value.deviceId !== 'string'
    || value.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || !canonicalDate(value.createdAt)
    || platform.os !== 'windows'
    || typeof platform.version !== 'string'
    || platform.version.length === 0
    || !Number.isSafeInteger(platform.build)
    || platform.build < 10_240
    || platform.build > 99_999
    || typeof platform.edition !== 'string'
    || platform.edition.length === 0
    || platform.edition !== platform.edition.trim()
    || platform.architecture !== 'x64'
    || typeof platform.windowsPowerShellVersion !== 'string'
    || platform.windowsPowerShellVersion.length === 0
    || platform.elevated !== true
    || !Number.isSafeInteger(value.catalogRevision)
    || value.catalogRevision < 1
    || value.catalogRevision > 2_147_483_647
    || typeof value.catalogDigest !== 'string'
    || !SHA256_PATTERN.test(value.catalogDigest)
    || typeof value.inventoryDigest !== 'string'
    || !SHA256_PATTERN.test(value.inventoryDigest)
    || value.acquisition !== 'mac-relay'
    || typeof value.generationDigest !== 'string'
    || !SHA256_PATTERN.test(value.generationDigest)
  ) fail('RUNTIME_SIGNATURE_INVALID');
  const requestedProfiles = validateStringArray(value.requestedProfiles, ['base', 'core']);
  const profiles = validateStringArray(value.profiles, ['core', 'base'], { minimum: 1 });
  if (profiles[0] !== 'core' || (profiles.length === 2 && profiles[1] !== 'base')) {
    fail('RUNTIME_SIGNATURE_INVALID');
  }
  const phases = readExactArray(value.phases, PHASES.length, PHASES.length, 'RUNTIME_SIGNATURE_INVALID');
  if (!phases.every((phase, index) => phase === PHASES[index])) fail('RUNTIME_SIGNATURE_INVALID');
  const componentInputs = readExactArray(
    value.components,
    1,
    MAX_COMPONENTS,
    'RUNTIME_SIGNATURE_INVALID',
  );
  const components = [];
  let previousId = null;
  for (const component of componentInputs) {
    const validated = validateComponent(component, previousId);
    components.push(validated);
    previousId = validated.id;
  }
  const snapshot = {
    schemaVersion: value.schemaVersion,
    deviceId: value.deviceId,
    operationId: value.operationId,
    createdAt: value.createdAt,
    platform: { ...platform },
    catalogRevision: value.catalogRevision,
    catalogDigest: value.catalogDigest,
    inventoryDigest: value.inventoryDigest,
    requestedProfiles: [...requestedProfiles],
    profiles: [...profiles],
    acquisition: value.acquisition,
    generationDigest: value.generationDigest,
    phases: [...phases],
    components: components.map((component) => ({ ...component })),
  };
  if (JSON.stringify(snapshot) !== canonicalJson) fail('RUNTIME_SIGNATURE_INVALID');
  return Object.freeze({ ...snapshot, components: Object.freeze(components) });
}

function validatePublicKey(input) {
  if (
    typeof input !== 'string'
    || input.length === 0
    || Buffer.byteLength(input, 'utf8') > 2_048
  ) fail('RUNTIME_SIGNATURE_INVALID');
  let parsed;
  try { parsed = JSON.parse(input); } catch { fail('RUNTIME_SIGNATURE_INVALID'); }
  const value = readExactRecord(parsed, PUBLIC_KEY_FIELDS, 'RUNTIME_SIGNATURE_INVALID');
  if (
    JSON.stringify(Object.fromEntries(PUBLIC_KEY_FIELDS.map((field) => [field, value[field]]))) !== input
    || value.algorithm !== 'RSA-SHA256'
    || typeof value.modulusBase64Url !== 'string'
    || !/^[A-Za-z0-9_-]+$/u.test(value.modulusBase64Url)
    || value.exponentBase64Url !== 'AQAB'
  ) fail('RUNTIME_SIGNATURE_INVALID');
  const modulus = Buffer.from(value.modulusBase64Url, 'base64url');
  if (
    modulus.length !== 384
    || modulus.toString('base64url') !== value.modulusBase64Url
    || (modulus[0] & 0x80) === 0
  ) fail('RUNTIME_SIGNATURE_INVALID');
  let key;
  try {
    key = createPublicKey({
      key: { kty: 'RSA', n: value.modulusBase64Url, e: value.exponentBase64Url },
      format: 'jwk',
    });
  } catch {
    fail('RUNTIME_SIGNATURE_INVALID');
  }
  if (
    key.asymmetricKeyType !== 'rsa'
    || key.asymmetricKeyDetails?.modulusLength !== 3072
    || key.asymmetricKeyDetails?.publicExponent !== 65_537n
  ) fail('RUNTIME_SIGNATURE_INVALID');
  return key;
}

function validateCapsule(input) {
  const value = readExactRecord(input, CAPSULE_FIELDS, 'RUNTIME_SIGNATURE_INVALID');
  if (
    value.schemaVersion !== 1
    || typeof value.manifestJson !== 'string'
    || Buffer.byteLength(value.manifestJson, 'utf8') > MAX_MANIFEST_BYTES
    || typeof value.manifestDigest !== 'string'
    || !SHA256_PATTERN.test(value.manifestDigest)
    || typeof value.generationDigest !== 'string'
    || !SHA256_PATTERN.test(value.generationDigest)
    || value.signatureAlgorithm !== 'RSA-SHA256'
    || typeof value.signatureBase64 !== 'string'
    || !/^[A-Za-z0-9+/]{512}$/u.test(value.signatureBase64)
    || typeof value.controllerKeyId !== 'string'
    || !SHA256_PATTERN.test(value.controllerKeyId)
  ) fail('RUNTIME_SIGNATURE_INVALID');
  let manifestInput;
  try { manifestInput = JSON.parse(value.manifestJson); } catch { fail('RUNTIME_SIGNATURE_INVALID'); }
  const manifest = validateManifest(manifestInput, value.manifestJson);
  const publicKey = validatePublicKey(value.controllerPublicKeyJson);
  const signature = Buffer.from(value.signatureBase64, 'base64');
  const signedBytes = Buffer.concat([RUNTIME_DOMAIN, Buffer.from(value.manifestJson, 'utf8')]);
  if (
    value.manifestDigest !== digest(Buffer.from(value.manifestJson, 'utf8'))
    || value.generationDigest !== manifest.generationDigest
    || value.controllerKeyId !== digest(
      CONTROLLER_KEY_DOMAIN,
      Buffer.from(value.controllerPublicKeyJson, 'utf8'),
    )
    || signature.length !== 384
    || signature.toString('base64') !== value.signatureBase64
    || !cryptoVerify('RSA-SHA256', signedBytes, publicKey, signature)
  ) fail('RUNTIME_SIGNATURE_INVALID');
  const snapshot = Object.fromEntries(CAPSULE_FIELDS.map((field) => [field, value[field]]));
  const bytes = Buffer.from(JSON.stringify(snapshot), 'utf8');
  if (bytes.length < 1 || bytes.length > MAX_CAPSULE_BYTES) fail('RUNTIME_SIGNATURE_INVALID');
  return Object.freeze({ snapshot: Object.freeze(snapshot), bytes, manifest });
}

function targetDeviceId(input) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || !Object.isFrozen(input)
  ) fail();
  const target = Object.getOwnPropertyDescriptor(input, 'device');
  if (!target || !Object.hasOwn(target, 'value')) fail();
  const device = target.value;
  if (
    device === null
    || typeof device !== 'object'
    || isProxy(device)
    || !Object.isFrozen(device)
  ) fail();
  const id = Object.getOwnPropertyDescriptor(device, 'id');
  if (
    !id
    || !Object.hasOwn(id, 'value')
    || typeof id.value !== 'string'
    || id.value.length > 64
    || !DEVICE_ID_PATTERN.test(id.value)
  ) fail();
  return id.value;
}

function validateArtifactRecords(input, components) {
  const values = readExactArray(input, components.length, components.length, 'RUNTIME_ARTIFACT_INVALID');
  const records = [];
  for (let index = 0; index < values.length; index += 1) {
    const value = readExactRecord(values[index], ARTIFACT_FILE_FIELDS, 'RUNTIME_ARTIFACT_INVALID');
    const component = components[index];
    if (
      value.artifactId !== component.id
      || value.version !== component.version
      || value.bytes !== component.bytes
      || value.sha256 !== component.sha256
      || typeof value.path !== 'string'
      || value.path.length === 0
      || Buffer.byteLength(value.path, 'utf8') > MAX_PATH_BYTES
      || value.path.includes('\0')
      || !isAbsolute(value.path)
      || resolve(value.path) !== value.path
    ) fail('RUNTIME_ARTIFACT_INVALID');
    records.push(Object.freeze({ ...value }));
  }
  return Object.freeze(records);
}

function validateInput(input) {
  const value = readExactRecord(input, ROOT_FIELDS);
  const dependencies = readExactRecord(value.dependencies, DEPENDENCY_FIELDS);
  if (
    typeof dependencies.runProcess !== 'function'
    || isProxy(dependencies.runProcess)
    || !Number.isSafeInteger(dependencies.sshLockTimeoutMs)
    || dependencies.sshLockTimeoutMs < MIN_LOCK_TIMEOUT_MS
    || dependencies.sshLockTimeoutMs > MAX_LOCK_TIMEOUT_MS
  ) fail();
  const capsule = validateCapsule(value.capsule);
  const deviceId = targetDeviceId(value.target);
  if (deviceId !== capsule.manifest.deviceId) fail('RUNTIME_SIGNATURE_INVALID');
  const artifactFiles = validateArtifactRecords(value.artifactFiles, capsule.manifest.components);
  return Object.freeze({
    target: value.target,
    deviceId,
    capsule,
    artifactFiles,
    dependencies: Object.freeze({ ...dependencies }),
  });
}

function snapshotPreparedSession(input, expectedAddresses) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Object.isFrozen(input)
    || Array.isArray(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) fail();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== SESSION_FIELDS.size || !names.every((name) => SESSION_FIELDS.has(name))) {
    fail();
  }
  const session = Object.create(null);
  for (const field of SESSION_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail();
    session[field] = descriptor.value;
  }
  if (
    !Array.isArray(session.addresses)
    || !Object.isFrozen(session.addresses)
    || session.addresses.length !== expectedAddresses.length
    || session.addresses.some((address, index) => (
      typeof address !== 'string'
      || isIP(address) === 0
      || address !== expectedAddresses[index]
    ))
    || ['invokeSsh', 'invokeScp', 'invokeCleanup', 'remoteSpec'].some((field) => (
      typeof session[field] !== 'function' || isProxy(session[field])
    ))
  ) fail();
  return session;
}

async function closeSnapshots(snapshots) {
  let failed = false;
  for (const snapshot of snapshots) {
    try { await snapshot.close(); } catch { failed = true; }
  }
  if (failed) fail('RUNTIME_ARTIFACT_INVALID');
}

async function snapshotArtifacts(config) {
  const snapshots = [];
  try {
    for (let index = 0; index < config.artifactFiles.length; index += 1) {
      const record = config.artifactFiles[index];
      let snapshot;
      try {
        snapshot = await snapshotLocalFile(record.path, {
          minimumBytes: record.bytes,
          maximumBytes: record.bytes,
        });
      } catch {
        fail('RUNTIME_ARTIFACT_INVALID');
      }
      if (snapshot.bytes !== record.bytes || snapshot.sha256 !== record.sha256) {
        try { await snapshot.close(); } catch {}
        fail('RUNTIME_ARTIFACT_INVALID');
      }
      snapshots.push(Object.freeze({ record, snapshot }));
    }
    const capsuleSnapshot = await snapshotBytes(config.capsule.bytes, {
      minimumBytes: config.capsule.bytes.length,
      maximumBytes: config.capsule.bytes.length,
    });
    snapshots.push(Object.freeze({ record: null, snapshot: capsuleSnapshot }));
    return snapshots;
  } catch (error) {
    try { await closeSnapshots(snapshots.map(({ snapshot }) => snapshot)); } catch {}
    const code = safeCode(error);
    if (PUBLIC_CODES.has(code)) throw runtimeError(code);
    fail('RUNTIME_ARTIFACT_INVALID');
  }
}

function snapshotProcessResult(input) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) return null;
  const result = Object.create(null);
  for (const key of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!PROCESS_RESULT_FIELDS.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) return null;
    result[key] = descriptor.value;
  }
  if (!['exitCode', 'signal', 'stdout', 'stderr'].every((field) => Object.hasOwn(result, field))) {
    return null;
  }
  return result;
}

function basePayload(config) {
  return {
    schemaVersion: 1,
    operationId: config.capsule.manifest.operationId,
    manifestDigest: config.capsule.snapshot.manifestDigest,
  };
}

function entryPayload(config, record, snapshot) {
  return {
    ...basePayload(config),
    entryType: record === null ? 'capsule' : 'artifact',
    artifactId: record === null ? null : record.artifactId,
    version: record === null ? null : record.version,
    expectedBytes: snapshot.bytes,
    expectedSha256: snapshot.sha256,
  };
}

function remoteEntryPaths(config, record, snapshot) {
  const root = `C:/ProgramData/AgentRoad/runtime/staging/${config.capsule.manifest.operationId}/${config.capsule.snapshot.manifestDigest}`;
  if (record === null) {
    return Object.freeze({
      final: `${root}/capsule.json`,
      temp: `${root}/.capsule-${snapshot.sha256}.upload`,
    });
  }
  return Object.freeze({
    final: `${root}/files/${record.artifactId}-${record.version}.zip`,
    temp: `${root}/files/.${record.artifactId}-${record.version}-${snapshot.sha256}.upload`,
  });
}

function inspectPayload(config, snapshots) {
  const artifacts = snapshots.slice(0, -1);
  const capsule = snapshots.at(-1).snapshot;
  return {
    ...basePayload(config),
    components: artifacts.map(({ record, snapshot }) => ({
      artifactId: record.artifactId,
      version: record.version,
      expectedBytes: snapshot.bytes,
      expectedSha256: snapshot.sha256,
    })),
    capsule: { expectedBytes: capsule.bytes, expectedSha256: capsule.sha256 },
  };
}

function prepareInvocation(wrapper, payload) {
  return powershellInvocation(wrapper, encodeRemotePayload(payload));
}

function prepareInvocations(config, snapshots) {
  return Object.freeze({
    init: prepareInvocation(WINDOWS_PROVISION_INIT_WRAPPER, basePayload(config)),
    inspect: prepareInvocation(
      WINDOWS_PROVISION_INSPECT_WRAPPER,
      inspectPayload(config, snapshots),
    ),
    entries: Object.freeze(snapshots.map(({ record, snapshot }) => Object.freeze({
      finalize: prepareInvocation(
        WINDOWS_PROVISION_FINALIZE_WRAPPER,
        entryPayload(config, record, snapshot),
      ),
      cleanup: prepareInvocation(
        WINDOWS_PROVISION_CLEANUP_WRAPPER,
        entryPayload(config, record, snapshot),
      ),
    }))),
  });
}

async function invokePrepared(session, address, invocation, timeoutMs) {
  let result;
  try {
    result = await session.invokeSsh(address, invocation.argv, {
      timeoutMs,
      maxOutputBytes: 32 * 1024,
      stdinText: invocation.stdin,
    });
  } catch {
    return Object.freeze({ state: 'unknown' });
  }
  const value = snapshotProcessResult(result);
  if (
    value === null
    || !Number.isSafeInteger(value.exitCode)
    || value.signal !== null
    || typeof value.stdout !== 'string'
    || typeof value.stderr !== 'string'
  ) return Object.freeze({ state: 'unknown' });
  if (value.exitCode !== 0) return Object.freeze({ state: 'rejected' });
  return Object.freeze({ state: 'completed', stdout: value.stdout, stderr: value.stderr });
}

async function invokeFixed(session, address, invocation, expected, timeoutMs, phase) {
  phase.mutationDispatched = true;
  const outcome = await invokePrepared(session, address, invocation, timeoutMs);
  if (
    outcome.state === 'completed'
    && outcome.stdout === expected
    && outcome.stderr === ''
  ) return 'confirmed';
  if (outcome.state === 'rejected') return 'rejected';
  return 'unknown';
}

async function initialize(session, address, frames, phase) {
  phase.stage = 'initialize';
  const status = await invokeFixed(
    session,
    address,
    frames.init,
    'AGENT_ROAD_PROVISION_INIT_OK',
    60_000,
    phase,
  );
  if (status === 'rejected') fail('RUNTIME_STAGE_FAILED');
  if (status !== 'confirmed') fail('RUNTIME_COMPLETION_UNCERTAIN');
}

async function inspect(session, address, snapshots, frames, phase) {
  phase.stage = 'inspect';
  const artifacts = snapshots.slice(0, -1);
  const outcome = await invokePrepared(session, address, frames.inspect, 60_000);
  if (outcome.state === 'rejected') fail('RUNTIME_STAGE_FAILED');
  if (outcome.state !== 'completed' || outcome.stderr !== '') {
    fail('RUNTIME_COMPLETION_UNCERTAIN');
  }
  const pattern = new RegExp(
    `^AGENT_ROAD_PROVISION_INSPECT:([FTM](?:,[FTM]){${artifacts.length - 1}}):([FTM])$`,
    'u',
  );
  const match = pattern.exec(outcome.stdout);
  if (!match) fail('RUNTIME_COMPLETION_UNCERTAIN');
  const artifactStates = match[1].split(',');
  const capsuleState = match[2];
  if (capsuleState === 'F' && artifactStates.some((state) => state !== 'F')) {
    fail('RUNTIME_STAGE_FAILED');
  }
  return Object.freeze({ artifactStates: Object.freeze(artifactStates), capsuleState });
}

async function cleanupExactTemp(session, address, frame, phase) {
  phase.stage = 'cleanup';
  const status = await invokeFixed(
    session,
    address,
    frame.cleanup,
    'AGENT_ROAD_PROVISION_CLEANED',
    60_000,
    phase,
  );
  if (status !== 'confirmed') fail('RUNTIME_COMPLETION_UNCERTAIN');
}

async function finalizeExactTemp(session, address, frame, phase) {
  phase.stage = 'finalize';
  const status = await invokeFixed(
    session,
    address,
    frame.finalize,
    'AGENT_ROAD_PROVISION_FINALIZED',
    60_000,
    phase,
  );
  if (status !== 'confirmed') fail('RUNTIME_COMPLETION_UNCERTAIN');
}

async function uploadMissing(session, address, config, entry, frame, phase) {
  phase.stage = 'upload';
  const paths = remoteEntryPaths(config, entry.record, entry.snapshot);
  let result;
  try {
    phase.mutationDispatched = true;
    result = await session.invokeScp([
      entry.snapshot.path,
      session.remoteSpec(address, paths.temp),
    ], { timeoutMs: 300_000, maxOutputBytes: 16 * 1024 });
  } catch {
    fail('RUNTIME_COMPLETION_UNCERTAIN');
  }
  const value = snapshotProcessResult(result);
  if (
    value === null
    || !Number.isSafeInteger(value.exitCode)
    || value.signal !== null
    || typeof value.stdout !== 'string'
    || typeof value.stderr !== 'string'
  ) {
    fail('RUNTIME_COMPLETION_UNCERTAIN');
  }
  if (value.exitCode !== 0 || value.stdout !== '' || value.stderr !== '') {
    await cleanupExactTemp(session, address, frame, phase);
    phase.stage = 'upload';
    fail('RUNTIME_STAGE_FAILED');
  }
  await finalizeExactTemp(session, address, frame, phase);
}

function stagedResult(config) {
  return Object.freeze({
    schemaVersion: 1,
    status: 'staged',
    deviceId: config.deviceId,
    operationId: config.capsule.manifest.operationId,
    manifestDigest: config.capsule.snapshot.manifestDigest,
    generationDigest: config.capsule.snapshot.generationDigest,
  });
}

async function stageAgainstSession(state, session, address) {
  const {
    config,
    frames,
    phase,
    snapshots,
  } = state;
  await initialize(session, address, frames, phase);
  const inspection = await inspect(session, address, snapshots, frames, phase);
  const artifactEntries = snapshots.slice(0, -1);
  const capsuleEntry = snapshots.at(-1);
  if (inspection.capsuleState === 'F') return stagedResult(config);

  for (let index = 0; index < artifactEntries.length; index += 1) {
    const entry = artifactEntries[index];
    const frame = frames.entries[index];
    if (inspection.artifactStates[index] === 'T') {
      await finalizeExactTemp(session, address, frame, phase);
    } else if (inspection.artifactStates[index] === 'M') {
      await uploadMissing(session, address, config, entry, frame, phase);
    }
  }
  const ready = await inspect(session, address, snapshots, frames, phase);
  if (ready.artifactStates.some((artifactState) => artifactState !== 'F')) {
    fail('RUNTIME_STAGE_FAILED');
  }
  if (ready.capsuleState === 'F') return stagedResult(config);
  const capsuleFrame = frames.entries.at(-1);
  if (ready.capsuleState === 'T') {
    await finalizeExactTemp(session, address, capsuleFrame, phase);
  } else {
    await uploadMissing(session, address, config, capsuleEntry, capsuleFrame, phase);
  }
  return stagedResult(config);
}

export async function withPreparedProvisionUpload(input, operation) {
  if (typeof operation !== 'function' || isProxy(operation)) {
    throw runtimeError('RUNTIME_INPUT_INVALID');
  }
  let config;
  try {
    config = validateInput(input);
  } catch (error) {
    const code = safeCode(error);
    if (PUBLIC_CODES.has(code)) throw runtimeError(code);
    throw runtimeError('RUNTIME_INPUT_INVALID');
  }
  const snapshots = await snapshotArtifacts(config);
  let frames;
  try {
    frames = prepareInvocations(config, snapshots);
  } catch {
    try { await closeSnapshots(snapshots.map(({ snapshot }) => snapshot)); } catch {}
    throw runtimeError('RUNTIME_INPUT_INVALID');
  }
  let trust;
  try {
    trust = trustedInput(config.target, config.dependencies.runProcess);
  } catch {
    try { await closeSnapshots(snapshots.map(({ snapshot }) => snapshot)); } catch {}
    throw runtimeError('RUNTIME_STAGE_FAILED');
  }
  const phase = Object.seal({ mutationDispatched: false, stage: null });
  const prepared = Object.freeze({ schemaVersion: 1 });
  const state = {
    config,
    executed: false,
    frames,
    phase,
    snapshots,
    status: 'active',
    trust,
  };
  PREPARED_UPLOADS.set(prepared, state);
  let result;
  let primary;
  try {
    result = await operation(prepared);
  } catch (error) {
    primary = error;
  }
  state.status = 'closing';
  try {
    await closeSnapshots(snapshots.map(({ snapshot }) => snapshot));
  } catch {
    const cleanup = runtimeError('RUNTIME_ARTIFACT_INVALID');
    const primaryCode = safeCode(primary);
    if (PUBLIC_CODES.has(primaryCode)) {
      Object.defineProperty(cleanup, 'primaryCode', {
        configurable: false,
        enumerable: false,
        value: primaryCode,
        writable: false,
      });
    }
    primary = cleanup;
  }
  state.status = 'closed';
  PREPARED_UPLOADS.delete(prepared);
  if (primary) throw primary;
  return result;
}

export async function stagePreparedProvisionUploadInSession(prepared, inputSession, address) {
  const state = PREPARED_UPLOADS.get(prepared);
  if (
    state === undefined
    || state.status !== 'active'
    || state.executed
    || typeof address !== 'string'
    || isIP(address) === 0
    || !state.trust.addresses.includes(address)
  ) fail();
  const session = snapshotPreparedSession(inputSession, state.trust.addresses);
  if (!session.addresses.includes(address)) fail();
  state.executed = true;
  try { return await stageAgainstSession(state, session, address); }
  catch (error) { throw markProvisionFailure(error, state.phase.stage); }
}

export function getPreparedProvisionUploadBinding(prepared) {
  const state = PREPARED_UPLOADS.get(prepared);
  if (state === undefined || state.status !== 'active') fail();
  const { manifest } = state.config.capsule;
  const components = Object.freeze(manifest.components.map((component) => Object.freeze({
    id: component.id,
    version: component.version,
    bytes: component.bytes,
    maximumExpandedBytes: component.maximumExpandedBytes,
    sha256: component.sha256,
  })));
  return Object.freeze({
    schemaVersion: 1,
    deviceId: state.config.deviceId,
    operationId: manifest.operationId,
    manifestDigest: state.config.capsule.snapshot.manifestDigest,
    generationDigest: state.config.capsule.snapshot.generationDigest,
    inventoryDigest: manifest.inventoryDigest,
    catalogDigest: manifest.catalogDigest,
    requestedProfiles: Object.freeze([...manifest.requestedProfiles]),
    profiles: Object.freeze([...manifest.profiles]),
    components,
  });
}

export async function provisionUpload(input) {
  return withPreparedProvisionUpload(input, async (prepared) => {
    const state = PREPARED_UPLOADS.get(prepared);
    try {
      return await withTrustedSshSession(
        state.trust,
        async (session) => {
          const address = await selectAddress(session);
          return stagePreparedProvisionUploadInSession(prepared, session, address);
        },
        { lockTimeoutMs: state.config.dependencies.sshLockTimeoutMs },
      );
    } catch (error) {
      const code = safeCode(error);
      const marked = (value) => markProvisionFailure(runtimeError(value), provisionFailureStage(error));
      if (code === 'RUNTIME_COMPLETION_UNCERTAIN') {
        throw marked('RUNTIME_COMPLETION_UNCERTAIN');
      }
      if (PUBLIC_CODES.has(code)) throw marked(code);
      if (state.phase.mutationDispatched) throw marked('RUNTIME_COMPLETION_UNCERTAIN');
      throw marked('RUNTIME_STAGE_FAILED');
    }
  });
}
