import { createHash } from 'node:crypto';
import { isProxy } from 'node:util/types';

const ERROR_CODE = 'RUNTIME_INPUT_INVALID';
const MIN_WINDOWS_BUILD = 10_240;
const MAX_WINDOWS_BUILD = 99_999;
const MAX_CATALOG_REVISION = 2_147_483_647;
const MAX_MANAGED_ARTIFACTS = 32;
const MAX_ARTIFACT_BYTES = 256 * 1024 ** 2;
const MAX_INVENTORY_BYTES = 32 * 1024;
const MAX_VERSION_LENGTH = 64;
const MAX_PLATFORM_VERSION_LENGTH = 32;
const MAX_EDITION_BYTES = 256;

const ROOT_FIELDS = Object.freeze([
  'schemaVersion',
  'platform',
  'freeBytes',
  'pendingReboot',
  'interactiveSession',
  'runtime',
  'managedArtifacts',
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
const RUNTIME_FIELDS = Object.freeze([
  'schemaVersion',
  'catalogRevision',
  'catalogDigest',
  'generationDigest',
  'generationVerified',
  'pendingOperationId',
  'restartRequired',
]);
const ARTIFACT_FIELDS = Object.freeze([
  'id',
  'version',
  'bytes',
  'sha256',
  'verified',
]);

const ID_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const PLATFORM_VERSION_PATTERN = /^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,3}$/;
const POWERSHELL_VERSION_PATTERN = /^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}$/;
const SHA256_PATTERN = /^[0-9A-F]{64}$/;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/;

function failInput() {
  const error = new TypeError(ERROR_CODE);
  error.code = ERROR_CODE;
  throw error;
}

function readExactRecord(input, fields) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) {
    failInput();
  }

  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    failInput();
  }

  const values = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) {
      failInput();
    }
    values[field] = descriptor.value;
  }
  return values;
}

function readExactArray(input, maximumLength) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Array.isArray(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) {
    failInput();
  }

  const lengthDescriptor = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    lengthDescriptor === undefined
    || !Object.hasOwn(lengthDescriptor, 'value')
    || !Number.isInteger(lengthDescriptor.value)
    || lengthDescriptor.value < 0
    || lengthDescriptor.value > maximumLength
  ) {
    failInput();
  }

  const length = lengthDescriptor.value;
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== length + 1) failInput();

  const values = [];
  for (let index = 0; index < length; index += 1) {
    const name = String(index);
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) {
      failInput();
    }
    values.push(descriptor.value);
  }
  if (!names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/.test(name))) {
    failInput();
  }
  return values;
}

function freezeDeep(value) {
  if (Array.isArray(value)) {
    for (const child of value) freezeDeep(child);
  } else {
    for (const child of Object.values(value)) {
      if (child !== null && typeof child === 'object') freezeDeep(child);
    }
  }
  return Object.freeze(value);
}

function validPositiveInteger(value, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= 1 && value <= maximum;
}

function validatePlatform(input) {
  const platform = readExactRecord(input, PLATFORM_FIELDS);
  if (
    platform.os !== 'windows'
    || typeof platform.version !== 'string'
    || platform.version.length === 0
    || platform.version.length > MAX_PLATFORM_VERSION_LENGTH
    || !PLATFORM_VERSION_PATTERN.test(platform.version)
    || !Number.isSafeInteger(platform.build)
    || Object.is(platform.build, -0)
    || platform.build < MIN_WINDOWS_BUILD
    || platform.build > MAX_WINDOWS_BUILD
    || typeof platform.edition !== 'string'
    || platform.edition.length === 0
    || platform.edition !== platform.edition.trim()
    || Buffer.byteLength(platform.edition, 'utf8') > MAX_EDITION_BYTES
    || /[\x00-\x1F\x7F]/.test(platform.edition)
    || !['x64', 'arm64'].includes(platform.architecture)
    || typeof platform.windowsPowerShellVersion !== 'string'
    || platform.windowsPowerShellVersion.length === 0
    || platform.windowsPowerShellVersion.length > MAX_PLATFORM_VERSION_LENGTH
    || !POWERSHELL_VERSION_PATTERN.test(platform.windowsPowerShellVersion)
    || typeof platform.elevated !== 'boolean'
  ) {
    failInput();
  }

  return {
    os: platform.os,
    version: platform.version,
    build: platform.build,
    edition: platform.edition,
    architecture: platform.architecture,
    windowsPowerShellVersion: platform.windowsPowerShellVersion,
    elevated: platform.elevated,
  };
}

function validateRuntime(input) {
  const runtime = readExactRecord(input, RUNTIME_FIELDS);
  if (
    typeof runtime.generationVerified !== 'boolean'
    || typeof runtime.restartRequired !== 'boolean'
    || (
      runtime.pendingOperationId !== null
      && (typeof runtime.pendingOperationId !== 'string'
        || !OPERATION_ID_PATTERN.test(runtime.pendingOperationId))
    )
  ) {
    failInput();
  }

  const tupleIsNull = runtime.schemaVersion === null
    && runtime.catalogRevision === null
    && runtime.catalogDigest === null
    && runtime.generationDigest === null;
  const tupleIsComplete = validPositiveInteger(runtime.schemaVersion, MAX_CATALOG_REVISION)
    && validPositiveInteger(runtime.catalogRevision, MAX_CATALOG_REVISION)
    && typeof runtime.catalogDigest === 'string'
    && SHA256_PATTERN.test(runtime.catalogDigest)
    && typeof runtime.generationDigest === 'string'
    && SHA256_PATTERN.test(runtime.generationDigest);

  if ((!tupleIsNull && !tupleIsComplete) || (tupleIsNull && runtime.generationVerified)) {
    failInput();
  }

  return {
    schemaVersion: runtime.schemaVersion,
    catalogRevision: runtime.catalogRevision,
    catalogDigest: runtime.catalogDigest,
    generationDigest: runtime.generationDigest,
    generationVerified: runtime.generationVerified,
    pendingOperationId: runtime.pendingOperationId,
    restartRequired: runtime.restartRequired,
  };
}

function validateArtifact(input) {
  const artifact = readExactRecord(input, ARTIFACT_FIELDS);
  const bytesAreNull = artifact.bytes === null;
  const hashIsNull = artifact.sha256 === null;
  if (
    typeof artifact.id !== 'string'
    || !ID_PATTERN.test(artifact.id)
    || typeof artifact.version !== 'string'
    || artifact.version.length === 0
    || artifact.version.length > MAX_VERSION_LENGTH
    || !VERSION_PATTERN.test(artifact.version)
    || typeof artifact.verified !== 'boolean'
    || bytesAreNull !== hashIsNull
    || (!bytesAreNull && !validPositiveInteger(artifact.bytes, MAX_ARTIFACT_BYTES))
    || (!hashIsNull && (typeof artifact.sha256 !== 'string' || !SHA256_PATTERN.test(artifact.sha256)))
    || (artifact.verified && bytesAreNull)
  ) {
    failInput();
  }

  return {
    id: artifact.id,
    version: artifact.version,
    bytes: artifact.bytes,
    sha256: artifact.sha256,
    verified: artifact.verified,
  };
}

function canonicalInventory(input) {
  const inventory = readExactRecord(input, ROOT_FIELDS);
  if (
    inventory.schemaVersion !== 1
    || !Number.isSafeInteger(inventory.freeBytes)
    || Object.is(inventory.freeBytes, -0)
    || inventory.freeBytes < 0
    || typeof inventory.pendingReboot !== 'boolean'
    || typeof inventory.interactiveSession !== 'boolean'
  ) {
    failInput();
  }

  const platform = validatePlatform(inventory.platform);
  const runtime = validateRuntime(inventory.runtime);
  const artifactInputs = readExactArray(inventory.managedArtifacts, MAX_MANAGED_ARTIFACTS);
  const managedArtifacts = artifactInputs.map(validateArtifact);

  let previousId = null;
  for (const artifact of managedArtifacts) {
    if (previousId !== null && artifact.id <= previousId) failInput();
    previousId = artifact.id;
  }
  if (
    runtime.generationVerified
    && !managedArtifacts.every(({ verified }) => verified)
  ) {
    failInput();
  }
  if (
    runtime.generationDigest === null
    && managedArtifacts.some(({ verified }) => verified)
  ) {
    failInput();
  }

  const snapshot = {
    schemaVersion: inventory.schemaVersion,
    platform,
    freeBytes: inventory.freeBytes,
    pendingReboot: inventory.pendingReboot,
    interactiveSession: inventory.interactiveSession,
    runtime,
    managedArtifacts,
  };
  const json = JSON.stringify(snapshot);
  if (Buffer.byteLength(json, 'utf8') > MAX_INVENTORY_BYTES) failInput();
  return snapshot;
}

export function validateRuntimeInventory(input) {
  return freezeDeep(canonicalInventory(input));
}

export function digestRuntimeInventory(input) {
  const snapshot = canonicalInventory(input);
  return createHash('sha256')
    .update(JSON.stringify(snapshot), 'utf8')
    .digest('hex')
    .toUpperCase();
}

export function runtimeInventoriesSemanticallyEqual(expectedInput, actualInput, requiredFreeBytes) {
  if (
    !Number.isSafeInteger(requiredFreeBytes)
    || Object.is(requiredFreeBytes, -0)
    || requiredFreeBytes < 0
  ) failInput();

  const expected = canonicalInventory(expectedInput);
  const actual = canonicalInventory(actualInput);
  const expectedAboveThreshold = expected.freeBytes >= requiredFreeBytes;
  const actualAboveThreshold = actual.freeBytes >= requiredFreeBytes;
  expected.freeBytes = 0;
  actual.freeBytes = 0;
  return expectedAboveThreshold === actualAboveThreshold
    && JSON.stringify(expected) === JSON.stringify(actual);
}
