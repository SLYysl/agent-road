import { createHash } from 'node:crypto';
import { isProxy } from 'node:util/types';

import {
  resolveRuntimeProfiles,
  validateRuntimeCatalog,
} from './runtime-catalog.mjs';
import {
  digestRuntimeInventory,
  validateRuntimeInventory,
} from './runtime-inventory.mjs';

const ERROR_CODE = 'RUNTIME_INPUT_INVALID';
const MAX_DEVICE_ID_LENGTH = 64;
const TRANSACTION_RESERVE_BYTES = 256 * 1024 ** 2;

const ROOT_FIELDS = Object.freeze([
  'catalog',
  'requestedProfiles',
  'inventory',
  'deviceId',
  'operationId',
  'createdAt',
]);
const PROFILE_IDS = Object.freeze(['core', 'base']);
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
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

function readRequestedProfiles(input) {
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
    || lengthDescriptor.value > PROFILE_IDS.length
  ) {
    failInput();
  }

  const length = lengthDescriptor.value;
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== length + 1
    || !names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/.test(name))
  ) {
    failInput();
  }

  const requested = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
      || typeof descriptor.value !== 'string'
      || !PROFILE_IDS.includes(descriptor.value)
    ) {
      failInput();
    }
    requested.push(descriptor.value);
  }

  if (new Set(requested).size !== requested.length) failInput();
  return PROFILE_IDS.filter((profileId) => requested.includes(profileId));
}

function assertOperationInputs({ deviceId, operationId, createdAt }) {
  if (
    typeof deviceId !== 'string'
    || deviceId.length > MAX_DEVICE_ID_LENGTH
    || !DEVICE_ID_PATTERN.test(deviceId)
    || typeof operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(operationId)
    || typeof createdAt !== 'string'
  ) {
    failInput();
  }

  try {
    if (new Date(createdAt).toISOString() !== createdAt) failInput();
  } catch {
    failInput();
  }
}

function digestCanonical(value) {
  return createHash('sha256')
    .update(JSON.stringify(value), 'utf8')
    .digest('hex')
    .toUpperCase();
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

function supportsWindowsPowerShell(version) {
  const [major, minor] = version.split('.').map((part) => BigInt(part));
  return major > 5n || (major === 5n && minor >= 1n);
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

function desiredArtifact(artifact) {
  return {
    version: artifact.version,
    bytes: artifact.bytes,
    maximumExpandedBytes: artifact.maximumExpandedBytes,
    sha256: artifact.sha256,
  };
}

function currentArtifact(artifact) {
  if (artifact === undefined) return null;
  return {
    version: artifact.version,
    bytes: artifact.bytes,
    sha256: artifact.sha256,
    verified: artifact.verified,
  };
}

function planArtifact(artifact, current, inventory, catalogRevision, catalogDigest) {
  const desired = desiredArtifact(artifact);
  const observed = currentArtifact(current);
  if (current === undefined) {
    return {
      artifactId: artifact.id,
      action: 'install',
      reason: 'managed-artifact-missing',
      desired,
      current: observed,
      rollbackVersion: null,
    };
  }

  const versionOrder = compareVersions(current.version, artifact.version);
  if (versionOrder < 0) {
    return {
      artifactId: artifact.id,
      action: 'upgrade',
      reason: 'managed-version-older',
      desired,
      current: observed,
      rollbackVersion: inventory.runtime.schemaVersion === 1
        && current.verified
        && inventory.runtime.generationVerified
        ? current.version
        : null,
    };
  }
  if (versionOrder > 0) {
    return {
      artifactId: artifact.id,
      action: 'blocked',
      reason: 'managed-version-newer',
      desired,
      current: observed,
      rollbackVersion: null,
    };
  }

  const generationMatches = inventory.runtime.schemaVersion === 1
    && inventory.runtime.catalogRevision === catalogRevision;
  const exactVerified = current.verified
    && current.bytes === artifact.bytes
    && current.sha256 === artifact.sha256
    && inventory.runtime.generationVerified
    && inventory.runtime.catalogDigest === catalogDigest;

  if (generationMatches && exactVerified) {
    return {
      artifactId: artifact.id,
      action: 'present',
      reason: null,
      desired,
      current: observed,
      rollbackVersion: null,
    };
  }

  return {
    artifactId: artifact.id,
    action: 'repair',
    reason: 'managed-artifact-invalid',
    desired,
    current: observed,
    rollbackVersion: null,
  };
}

function transactionMode(inventory, operationId) {
  if (inventory.runtime.pendingOperationId === null) return 'new';
  if (inventory.runtime.pendingOperationId === operationId) return 'reconcile';
  return 'conflict';
}

function globalBlockers(catalog, catalogDigest, inventory, mode, requiredFreeBytes) {
  const blockers = [];
  if (inventory.platform.architecture !== catalog.platform.architecture) {
    blockers.push('platform-architecture-unsupported');
  }
  if (inventory.platform.build < catalog.platform.minimumBuild) {
    blockers.push('platform-build-unsupported');
  }
  if (!supportsWindowsPowerShell(inventory.platform.windowsPowerShellVersion)) {
    blockers.push('windows-powershell-unsupported');
  }
  if (!inventory.platform.elevated) blockers.push('elevation-required');
  if (inventory.pendingReboot) blockers.push('pending-reboot');
  if (inventory.runtime.schemaVersion !== null && inventory.runtime.schemaVersion !== 1) {
    blockers.push('runtime-schema-unsupported');
  }
  if (
    inventory.runtime.generationVerified
    && inventory.runtime.catalogRevision > catalog.catalogRevision
  ) {
    blockers.push('catalog-revision-newer');
  }
  if (
    inventory.runtime.schemaVersion === 1
    && inventory.runtime.generationVerified
    && inventory.runtime.catalogRevision === catalog.catalogRevision
    && inventory.runtime.catalogDigest !== catalogDigest
  ) {
    blockers.push('catalog-revision-equivocation');
  }
  if (mode === 'conflict') blockers.push('runtime-operation-conflict');
  if (inventory.runtime.restartRequired) blockers.push('runtime-restart-required');
  if (inventory.freeBytes < requiredFreeBytes) blockers.push('disk-insufficient');
  return blockers;
}

export function createRuntimePlan(input) {
  const values = readExactRecord(input, ROOT_FIELDS);
  assertOperationInputs(values);

  const requestedProfiles = readRequestedProfiles(values.requestedProfiles);
  const catalog = validateRuntimeCatalog(values.catalog);
  const inventory = validateRuntimeInventory(values.inventory);
  const resolution = resolveRuntimeProfiles(catalog, requestedProfiles);
  const catalogDigest = digestCanonical(catalog);
  const inventoryDigest = digestRuntimeInventory(inventory);
  const currentById = new Map(
    inventory.managedArtifacts.map((artifact) => [artifact.id, artifact]),
  );

  const items = resolution.artifacts.map((artifact) => planArtifact(
    artifact,
    currentById.get(artifact.id),
    inventory,
    catalog.catalogRevision,
    catalogDigest,
  ));
  const mutationNeeded = items.some(({ action }) => (
    action === 'install' || action === 'repair' || action === 'upgrade'
  ));
  const requiredFreeBytes = mutationNeeded
    ? TRANSACTION_RESERVE_BYTES + resolution.artifacts.reduce(
      (total, artifact) => total + artifact.bytes + artifact.maximumExpandedBytes,
      0,
    )
    : 0;
  const mode = transactionMode(inventory, values.operationId);
  const blockedReasons = globalBlockers(
    catalog,
    catalogDigest,
    inventory,
    mode,
    requiredFreeBytes,
  );
  if (items.some(({ reason }) => reason === 'managed-version-newer')) {
    blockedReasons.push('managed-version-newer');
  }

  return freezeDeep({
    schemaVersion: 1,
    operationId: values.operationId,
    createdAt: values.createdAt,
    deviceId: values.deviceId,
    inventoryDigest,
    catalogDigest,
    requestedProfiles,
    profiles: [...resolution.profiles],
    acquisition: 'mac-relay',
    transactionMode: mode,
    status: blockedReasons.length === 0 ? 'actionable' : 'blocked',
    blockedReasons,
    requiredFreeBytes,
    items,
  });
}
