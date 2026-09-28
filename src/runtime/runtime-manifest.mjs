import {
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from 'node:crypto';
import { isProxy } from 'node:util/types';

import {
  resolveRuntimeProfiles,
  validateRuntimeCatalog,
} from './runtime-catalog.mjs';
import { validateRuntimeInventory } from './runtime-inventory.mjs';
import { createRuntimePlan } from './runtime-plan.mjs';

const INPUT_ERROR = 'RUNTIME_INPUT_INVALID';
const SIGNATURE_ERROR = 'RUNTIME_SIGNATURE_INVALID';
const RUNTIME_DOMAIN = Buffer.from('AGENT_ROAD_RUNTIME_V1\0', 'ascii');
const GENERATION_DOMAIN = Buffer.from('AGENT_ROAD_GENERATION_V1\0', 'ascii');
const CONTROLLER_KEY_DOMAIN = Buffer.from('AGENT_ROAD_CONTROLLER_KEY_V1\0', 'ascii');
const MAX_SAFE_PLAN_NODES = 4_096;
const MAX_SAFE_STRING_BYTES = 4_096;

const ROOT_FIELDS = Object.freeze(['catalog', 'inventory', 'plan', 'dependencies']);
const DEPENDENCY_FIELDS = Object.freeze(['getSigningPublicKey', 'sign']);
const PUBLIC_KEY_FIELDS = Object.freeze([
  'algorithm',
  'modulusBase64Url',
  'exponentBase64Url',
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

function runtimeError(code, ErrorType = Error) {
  const error = new ErrorType(code);
  error.code = code;
  return error;
}

function failInput() {
  throw runtimeError(INPUT_ERROR, TypeError);
}

function failSignature() {
  throw runtimeError(SIGNATURE_ERROR);
}

function readExactRecord(input, fields, fail = failInput) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) {
    fail();
  }

  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    fail();
  }

  const values = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) {
      fail();
    }
    values[field] = descriptor.value;
  }
  return values;
}

function cloneSafeJson(input, state = { nodes: 0 }, depth = 0) {
  state.nodes += 1;
  if (state.nodes > MAX_SAFE_PLAN_NODES || depth > 16) failInput();
  if (input === null || typeof input === 'boolean') return input;
  if (typeof input === 'string') {
    if (Buffer.byteLength(input, 'utf8') > MAX_SAFE_STRING_BYTES) failInput();
    return input;
  }
  if (typeof input === 'number') {
    if (!Number.isSafeInteger(input) || Object.is(input, -0)) failInput();
    return input;
  }
  if (typeof input !== 'object' || isProxy(input)) failInput();

  if (Array.isArray(input)) {
    if (
      Object.getPrototypeOf(input) !== Array.prototype
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
      || lengthDescriptor.value > 256
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
    const output = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
      if (
        descriptor === undefined
        || !Object.hasOwn(descriptor, 'value')
        || descriptor.enumerable !== true
      ) {
        failInput();
      }
      output.push(cloneSafeJson(descriptor.value, state, depth + 1));
    }
    return output;
  }

  if (
    Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) {
    failInput();
  }
  const names = Object.getOwnPropertyNames(input);
  if (names.length > 32) failInput();
  const output = Object.create(null);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) {
      failInput();
    }
    output[name] = cloneSafeJson(descriptor.value, state, depth + 1);
  }
  return output;
}

function digestBytes(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest('hex').toUpperCase();
}

function artifactComponent(artifact) {
  return {
    id: artifact.id,
    version: artifact.version,
    bytes: artifact.bytes,
    maximumExpandedBytes: artifact.maximumExpandedBytes,
    sha256: artifact.sha256,
    packaging: artifact.packaging,
    signerRule: artifact.signerRule,
    verificationCommandId: artifact.verificationCommandId,
  };
}

function prepareInput(input) {
  const values = readExactRecord(input, ROOT_FIELDS);
  const dependencyValues = readExactRecord(values.dependencies, DEPENDENCY_FIELDS);
  if (
    typeof dependencyValues.getSigningPublicKey !== 'function'
    || isProxy(dependencyValues.getSigningPublicKey)
    || typeof dependencyValues.sign !== 'function'
    || isProxy(dependencyValues.sign)
  ) {
    failInput();
  }

  const catalog = validateRuntimeCatalog(values.catalog);
  const inventory = validateRuntimeInventory(values.inventory);
  readExactRecord(values.plan, PLAN_FIELDS);
  const plan = cloneSafeJson(values.plan);
  const recomputedPlan = createRuntimePlan({
    catalog,
    requestedProfiles: plan.requestedProfiles,
    inventory,
    deviceId: plan.deviceId,
    operationId: plan.operationId,
    createdAt: plan.createdAt,
  });
  if (
    JSON.stringify(plan) !== JSON.stringify(recomputedPlan)
    || recomputedPlan.status !== 'actionable'
    || !['new', 'reconcile'].includes(recomputedPlan.transactionMode)
  ) {
    failInput();
  }

  const resolution = resolveRuntimeProfiles(catalog, recomputedPlan.requestedProfiles);
  const components = resolution.artifacts.map(artifactComponent);
  const generationDescriptor = {
    schemaVersion: 1,
    catalogRevision: catalog.catalogRevision,
    catalogDigest: recomputedPlan.catalogDigest,
    platform: { ...resolution.platform },
    profiles: [...resolution.profiles],
    components,
  };
  const generationDigest = digestBytes(
    GENERATION_DOMAIN,
    Buffer.from(JSON.stringify(generationDescriptor), 'utf8'),
  );
  const manifest = {
    schemaVersion: 1,
    deviceId: recomputedPlan.deviceId,
    operationId: recomputedPlan.operationId,
    createdAt: recomputedPlan.createdAt,
    platform: { ...inventory.platform },
    catalogRevision: catalog.catalogRevision,
    catalogDigest: recomputedPlan.catalogDigest,
    inventoryDigest: recomputedPlan.inventoryDigest,
    requestedProfiles: [...recomputedPlan.requestedProfiles],
    profiles: [...resolution.profiles],
    acquisition: 'mac-relay',
    generationDigest,
    phases: [...PHASES],
    components: components.map((component) => ({ ...component })),
  };
  const manifestJson = JSON.stringify(manifest);

  return {
    dependencies: dependencyValues,
    manifestJson,
    manifestDigest: digestBytes(Buffer.from(manifestJson, 'utf8')),
    generationDigest,
  };
}

function decodeCanonicalBase64Url(value) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return null;
  }
  const bytes = Buffer.from(value, 'base64url');
  return bytes.toString('base64url') === value ? bytes : null;
}

function validatePublicKey(input) {
  const value = readExactRecord(input, PUBLIC_KEY_FIELDS, failSignature);
  const modulus = decodeCanonicalBase64Url(value.modulusBase64Url);
  if (
    value.algorithm !== 'RSA-SHA256'
    || value.exponentBase64Url !== 'AQAB'
    || modulus === null
    || modulus.length !== 384
    || (modulus[0] & 0x80) === 0
  ) {
    failSignature();
  }

  let key;
  try {
    key = createPublicKey({
      key: {
        kty: 'RSA',
        n: value.modulusBase64Url,
        e: value.exponentBase64Url,
      },
      format: 'jwk',
    });
  } catch {
    failSignature();
  }
  if (
    key.asymmetricKeyType !== 'rsa'
    || key.asymmetricKeyDetails?.modulusLength !== 3072
    || key.asymmetricKeyDetails?.publicExponent !== 65537n
  ) {
    failSignature();
  }

  const snapshot = {
    algorithm: value.algorithm,
    modulusBase64Url: value.modulusBase64Url,
    exponentBase64Url: value.exponentBase64Url,
  };
  return { key, json: JSON.stringify(snapshot), snapshot };
}

export function deriveRuntimeControllerKeyIdentity(input) {
  try {
    const publicKey = validatePublicKey(input);
    const controllerPublicKey = Object.freeze({ ...publicKey.snapshot });
    return Object.freeze({
      controllerKeyId: digestBytes(
        CONTROLLER_KEY_DOMAIN,
        Buffer.from(publicKey.json, 'utf8'),
      ),
      controllerPublicKeyJson: publicKey.json,
      controllerPublicKey,
    });
  } catch {
    throw runtimeError(SIGNATURE_ERROR);
  }
}

function validateSignature(input, signedBytes, publicKey) {
  if (typeof input !== 'string' || !/^[A-Za-z0-9+/]{512}$/.test(input)) {
    failSignature();
  }
  const bytes = Buffer.from(input, 'base64');
  if (
    bytes.length !== 384
    || bytes.toString('base64') !== input
    || !cryptoVerify('RSA-SHA256', signedBytes, publicKey, bytes)
  ) {
    failSignature();
  }
  return input;
}

function pendingKind(value) {
  if (value === null || typeof value !== 'object' || isProxy(value)) return 'value';
  return Object.getPrototypeOf(value) === Promise.prototype ? 'promise' : 'value';
}

export async function createSignedRuntimeManifest(input) {
  let prepared;
  try {
    prepared = prepareInput(input);
  } catch {
    throw runtimeError(INPUT_ERROR, TypeError);
  }

  try {
    const publicPending = prepared.dependencies.getSigningPublicKey();
    const publicOutput = pendingKind(publicPending) === 'promise'
      ? await publicPending
      : publicPending;
    const publicKey = validatePublicKey(publicOutput);
    const expectedSignedBytes = Buffer.concat([
      RUNTIME_DOMAIN,
      Buffer.from(prepared.manifestJson, 'utf8'),
    ]);
    const signaturePending = prepared.dependencies.sign(Buffer.from(expectedSignedBytes));
    const signatureOutput = pendingKind(signaturePending) === 'promise'
      ? await signaturePending
      : signaturePending;
    const signatureBase64 = validateSignature(
      signatureOutput,
      expectedSignedBytes,
      publicKey.key,
    );
    const controllerKeyId = digestBytes(
      CONTROLLER_KEY_DOMAIN,
      Buffer.from(publicKey.json, 'utf8'),
    );

    return Object.freeze({
      schemaVersion: 1,
      manifestJson: prepared.manifestJson,
      manifestDigest: prepared.manifestDigest,
      generationDigest: prepared.generationDigest,
      signatureAlgorithm: 'RSA-SHA256',
      signatureBase64,
      controllerKeyId,
      controllerPublicKeyJson: publicKey.json,
    });
  } catch {
    throw runtimeError(SIGNATURE_ERROR);
  }
}
