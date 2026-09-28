import { createHash, createPublicKey, verify } from 'node:crypto';
import { isProxy } from 'node:util/types';

import { deriveRuntimeControllerKeyIdentity } from './runtime-manifest.mjs';
import { validateRuntimeStateRecord } from './runtime-state-store.mjs';
import {
  digestRuntimeInventory,
  runtimeInventoriesSemanticallyEqual,
  validateRuntimeInventory,
} from './runtime-inventory.mjs';

const INPUT_FIELDS = ['failedState', 'controllerPublicKey', 'capsuleJson', 'firstInventory', 'secondInventory', 'staged'];
const CAPSULE_FIELDS = ['schemaVersion', 'manifestJson', 'manifestDigest', 'generationDigest', 'signatureAlgorithm', 'signatureBase64', 'controllerKeyId', 'controllerPublicKeyJson'];
const MANIFEST_FIELDS = ['schemaVersion', 'deviceId', 'operationId', 'createdAt', 'platform', 'catalogRevision', 'catalogDigest', 'inventoryDigest', 'requestedProfiles', 'profiles', 'acquisition', 'generationDigest', 'phases', 'components'];
const COMPONENT_FIELDS = ['id', 'version', 'bytes', 'maximumExpandedBytes', 'sha256', 'packaging', 'signerRule', 'verificationCommandId'];
const STAGED_FIELDS = ['operationId', 'manifestDigest', 'generationDigest', 'capsuleSha256', 'archiveBytes', 'archiveSha256', 'hasWork', 'hasTemporary', 'onlyExpectedTransaction'];
const PHASES = ['discover', 'verify-manifest', 'verify-artifacts', 'snapshot', 'materialize-generation', 'self-test', 'atomic-activate', 'validate', 'commit', 'rollback', 'reconcile'];
const SHA = /^[A-F0-9]{64}$/u;

function fail(code = 'RUNTIME_STATE_UNSUPPORTED') {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function record(input, fields) {
  if (input === null || typeof input !== 'object' || isProxy(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0) fail();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || fields.some((field) => !names.includes(field))) fail();
  const result = {};
  for (const field of fields) {
    const property = Object.getOwnPropertyDescriptor(input, field);
    if (!Object.hasOwn(property, 'value') || !property.enumerable) fail();
    result[field] = property.value;
  }
  return result;
}

function sha(value) {
  return createHash('sha256').update(value).digest('hex').toUpperCase();
}

function canonicalJson(text, maximum) {
  if (typeof text !== 'string' || Buffer.byteLength(text) < 2 || Buffer.byteLength(text) > maximum) fail();
  let parsed;
  try { parsed = JSON.parse(text); } catch { fail(); }
  if (JSON.stringify(parsed) !== text) fail();
  return parsed;
}

// Observation only. This result is deliberately not a recovery ticket, a state
// transition, or permission to move files. Inputs must come from fresh strict
// remote observations; booleans supplied by a caller cannot confer authority.
function assessStagedCandidate(input, allowCurrentPlatform) {
  const value = record(input, INPUT_FIELDS);
  const state = validateRuntimeStateRecord(value.failedState);
  if (state.runtimeStatus !== 'FAILED' || state.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN'
    || JSON.stringify(state.requestedProfiles) !== '["core"]' || state.readyProfiles.length !== 0) fail();
  const first = validateRuntimeInventory(value.firstInventory);
  const second = validateRuntimeInventory(value.secondInventory);
  const staged = record(value.staged, STAGED_FIELDS);
  const capsule = record(canonicalJson(value.capsuleJson, 131_072), CAPSULE_FIELDS);
  const identity = deriveRuntimeControllerKeyIdentity(value.controllerPublicKey);
  if (capsule.schemaVersion !== 1 || capsule.signatureAlgorithm !== 'RSA-SHA256'
    || capsule.controllerKeyId !== identity.controllerKeyId
    || capsule.controllerPublicKeyJson !== identity.controllerPublicKeyJson
    || typeof capsule.signatureBase64 !== 'string' || !/^[A-Za-z0-9+/]{512}$/u.test(capsule.signatureBase64)) {
    fail('RUNTIME_SIGNATURE_INVALID');
  }
  const manifest = record(canonicalJson(capsule.manifestJson, 65_536), MANIFEST_FIELDS);
  const publicKey = createPublicKey({ format: 'jwk', key: {
    kty: 'RSA', n: identity.controllerPublicKey.modulusBase64Url,
    e: identity.controllerPublicKey.exponentBase64Url,
  } });
  if (!verify('RSA-SHA256', Buffer.concat([Buffer.from('AGENT_ROAD_RUNTIME_V1\0'), Buffer.from(capsule.manifestJson)]), publicKey,
    Buffer.from(capsule.signatureBase64, 'base64'))) fail('RUNTIME_SIGNATURE_INVALID');
  if (manifest.schemaVersion !== 1 || manifest.deviceId !== state.deviceId
    || manifest.operationId !== state.operationId || capsule.manifestDigest !== state.manifestDigest
    || sha(capsule.manifestJson) !== state.manifestDigest || capsule.generationDigest !== state.generationDigest
    || manifest.generationDigest !== state.generationDigest || manifest.acquisition !== 'mac-relay'
    || JSON.stringify(manifest.requestedProfiles) !== '["core"]' || JSON.stringify(manifest.profiles) !== '["core"]'
    || JSON.stringify(manifest.phases) !== JSON.stringify(PHASES)
    || !Number.isSafeInteger(manifest.catalogRevision) || manifest.catalogRevision < 1
    || typeof manifest.catalogDigest !== 'string' || !SHA.test(manifest.catalogDigest)
    || typeof manifest.inventoryDigest !== 'string' || !SHA.test(manifest.inventoryDigest)
    || typeof manifest.createdAt !== 'string' || !Number.isFinite(Date.parse(manifest.createdAt))
    || new Date(manifest.createdAt).toISOString() !== manifest.createdAt
    || !Array.isArray(manifest.components) || manifest.components.length !== 1) fail();
  const component = record(manifest.components[0], COMPONENT_FIELDS);
  if (component.id !== 'powershell-7' || typeof component.version !== 'string'
    || !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(component.version)
    || component.packaging !== 'zip' || component.signerRule !== 'microsoft-corporation'
    || component.verificationCommandId !== 'powershell-json-roundtrip'
    || !Number.isSafeInteger(component.bytes) || component.bytes < 1 || component.bytes > 268_435_456
    || !Number.isSafeInteger(component.maximumExpandedBytes) || component.maximumExpandedBytes < 1
    || component.maximumExpandedBytes > 2_147_483_648
    || typeof component.sha256 !== 'string' || !SHA.test(component.sha256)) fail();
  const requiredFreeBytes = component.maximumExpandedBytes + 268_435_456;
  const runtime = second.runtime;
  if (runtime.pendingOperationId !== state.operationId || runtime.generationVerified
    || runtime.restartRequired || runtime.schemaVersion !== null || runtime.catalogRevision !== null
    || runtime.catalogDigest !== null || runtime.generationDigest !== null || second.managedArtifacts.length !== 0) fail();
  const oldPlatform = validateRuntimeInventory({ ...second, platform: manifest.platform }).platform;
  const changedFields = Object.keys(oldPlatform).filter((field) => oldPlatform[field] !== second.platform[field]);
  const currentPlatform = changedFields.length === 0;
  if (!(allowCurrentPlatform && currentPlatform)
    && (changedFields.length !== 1 || changedFields[0] !== 'windowsPowerShellVersion')) fail();
  if (staged.operationId !== state.operationId || staged.manifestDigest !== state.manifestDigest
    || staged.generationDigest !== state.generationDigest || staged.capsuleSha256 !== sha(value.capsuleJson)
    || staged.archiveBytes !== component.bytes || staged.archiveSha256 !== component.sha256
    || staged.hasWork !== false || staged.hasTemporary !== false || staged.onlyExpectedTransaction !== true) fail();
  if (!runtimeInventoriesSemanticallyEqual(first, second, requiredFreeBytes)) fail('RUNTIME_INVENTORY_CHANGED');
  if (second.pendingReboot) fail('RUNTIME_REBOOT_REQUIRED');
  if (second.interactiveSession || !second.platform.elevated
    || second.freeBytes < requiredFreeBytes) fail('RUNTIME_INVENTORY_CHANGED');
  return Object.freeze({
    schemaVersion: 1,
    classification: currentPlatform ? 'UNSTARTED_STAGED_TRANSACTION' : 'OBSOLETE_STAGED_TRANSACTION',
    actionable: false,
    authority: 'OBSERVATION_ONLY',
    deviceId: state.deviceId,
    operationId: state.operationId,
    manifestDigest: state.manifestDigest,
    generationDigest: state.generationDigest,
    capsuleSha256: staged.capsuleSha256,
    inventoryDigest: digestRuntimeInventory(second),
    reason: currentPlatform ? 'COMPLETE_STAGE_WITHOUT_RUNTIME_WORK' : 'WINDOWS_POWERSHELL_VERSION_CHANGED',
    requiredNextStep: 'RETAIN_TRANSACTION_BEFORE_EMPTY_OPERATION_RECOVERY',
  });
}

export function assessStagedRetirement(input) {
  return assessStagedCandidate(input, false);
}

// Retention may also preserve a current-platform capsule after uncertain
// transport, but only with the same complete stage and absent runtime/work facts.
// This never authorizes resuming installation or reusing its consumed ticket.
export function assessUnstartedStagedRetention(input) {
  return assessStagedCandidate(input, true);
}

// Preserve signed bytes across Windows console code pages. Never reconstruct a
// signed manifest from JSON text emitted through the legacy console encoding.
export function decodeStagedRetirementObservation(stdout) {
  const wire = record(canonicalJson(stdout, 200_000), ['schemaVersion', 'capsuleBase64', 'staged']);
  if (wire.schemaVersion !== 1 || typeof wire.capsuleBase64 !== 'string'
    || wire.capsuleBase64.length > 174_764 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(wire.capsuleBase64)) fail();
  const bytes = Buffer.from(wire.capsuleBase64, 'base64');
  if (bytes.length > 131_072 || bytes.toString('base64') !== wire.capsuleBase64) fail();
  let capsuleJson;
  try { capsuleJson = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { fail(); }
  record(canonicalJson(capsuleJson, 131_072), CAPSULE_FIELDS);
  return Object.freeze({ capsuleJson, staged: Object.freeze(record(wire.staged, STAGED_FIELDS)) });
}
