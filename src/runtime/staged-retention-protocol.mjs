import { createHash } from 'node:crypto';
import { isProxy } from 'node:util/types';
import { assessUnstartedStagedRetention } from './staged-retirement-assessment.mjs';

const SHA = /^[A-F0-9]{64}$/u;
const ID = /^[A-F0-9]{16}:[A-F0-9]{32}$/u;
const SOURCE = ['programData', 'agentRoad', 'runtime', 'staging', 'operation', 'transaction', 'files', 'capsule', 'archive'];
const PARENTS = SOURCE.slice(0, 5);
const TTL_MS = 300_000;
const PROTOCOL_ERRORS = new WeakSet();
function fail(code = 'RUNTIME_STATE_UNSUPPORTED') {
  const error = new Error(code);
  error.code = code;
  PROTOCOL_ERRORS.add(error);
  throw error;
}

export function isStagedRetentionProtocolError(error) {
  return PROTOCOL_ERRORS.has(error);
}

// Snapshot plain data without invoking getters/toJSON. Signed capsule text stays
// opaque; only the surrounding protocol records have sorted canonical keys.
function snapshot(value, depth = 0, ancestors = new Set()) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (depth > 20 || typeof value !== 'object' || isProxy(value) || ancestors.has(value)
    || Object.getOwnPropertySymbols(value).length) fail();
  const array = Array.isArray(value);
  if (Object.getPrototypeOf(value) !== (array ? Array.prototype : Object.prototype)) fail();
  const keys = Object.getOwnPropertyNames(value).filter(k => !array || k !== 'length');
  if (keys.length > 100 || (array && (value.length !== keys.length
    || keys.some((k, i) => k !== String(i))))) fail();
  ancestors.add(value);
  const result = array ? [] : {};
  for (const key of array ? keys : keys.sort()) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || key === '__proto__') fail();
    result[key] = snapshot(descriptor.value, depth + 1, ancestors);
  }
  ancestors.delete(value);
  return Object.freeze(result);
}
function exact(value, keys) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) fail();
  return value;
}
function time(value) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))
    || new Date(value).toISOString() !== value) fail();
  return Date.parse(value);
}
function same(a, b) { return JSON.stringify(snapshot(a)) === JSON.stringify(snapshot(b)); }
function digest(domain, value) {
  const json = JSON.stringify(snapshot(value));
  if (Buffer.byteLength(json) > 65_536) fail();
  return createHash('sha256').update(domain + '\0' + json).digest('hex').toUpperCase();
}
function seal(domain, fields, digestField) {
  return snapshot({ ...fields, [digestField]: digest(domain, fields) });
}
function identities(source, destination) {
  exact(source, SOURCE);
  const values = [...Object.values(source), ...Object.values(destination).filter(v => v !== null)];
  if (values.some(v => typeof v !== 'string' || !ID.test(v))
    || new Set(values).size !== values.length
    || values.some(v => v.slice(0, 16) !== source.programData.slice(0, 16))) fail();
  if (destination.rootIdentity === null && destination.operationIdentity !== null) fail();
}
function evidence(input) {
  const value = exact(snapshot(input), ['assessmentInput', 'targetBindingDigest', 'executorDigest', 'sourceIdentity', 'sourceAclSha256', 'destination']);
  for (const key of ['targetBindingDigest', 'executorDigest']) {
    if (typeof value[key] !== 'string' || !SHA.test(value[key])) fail();
  }
  try { assessUnstartedStagedRetention(value.assessmentInput); } catch (error) {
    const allowed = ['RUNTIME_SIGNATURE_INVALID', 'RUNTIME_INVENTORY_CHANGED', 'RUNTIME_REBOOT_REQUIRED'];
    fail(allowed.includes(error?.code) ? error.code : 'RUNTIME_STATE_UNSUPPORTED');
  }
  exact(value.sourceAclSha256, SOURCE);
  if (Object.values(value.sourceAclSha256).some(v => typeof v !== 'string' || !SHA.test(v))) fail();
  const dest = exact(value.destination, ['rootIdentity', 'operationIdentity', 'transactionAbsent']);
  if (dest.transactionAbsent !== true) fail();
  identities(value.sourceIdentity, { rootIdentity: dest.rootIdentity, operationIdentity: dest.operationIdentity });
  return value;
}

function comparableEvidence(value) {
  const assessmentInput = value.assessmentInput;
  // Both observations independently passed the same signed disk threshold.
  // Background disk usage alone must not invalidate an otherwise stable proof.
  return { ...value, assessmentInput: { ...assessmentInput,
    firstInventory: { ...assessmentInput.firstInventory, freeBytes: 0 },
    secondInventory: { ...assessmentInput.secondInventory, freeBytes: 0 },
  } };
}

// These constructors establish local protocol bindings, never trusted remote
// observations. Only a future pinned transport/handle executor may supply them.
export function createStagedRetentionProposal(input, now) {
  const observed = evidence(input);
  const start = time(now);
  const state = observed.assessmentInput.failedState;
  if (start < time(state.updatedAt) || start + TTL_MS > 8_640_000_000_000_000) fail();
  return seal('AGENT_ROAD_STAGED_RETENTION_PROPOSAL_V1', {
    schemaVersion: 1, deviceId: state.deviceId, operationId: state.operationId,
    evidence: observed, issuedAt: now, expiresAt: new Date(start + TTL_MS).toISOString(),
  }, 'proposalDigest');
}
export function validateStagedRetentionProposal(input) {
  const value = exact(snapshot(input), ['schemaVersion', 'deviceId', 'operationId', 'evidence', 'issuedAt', 'expiresAt', 'proposalDigest']);
  const expected = createStagedRetentionProposal(value.evidence, value.issuedAt);
  if (!same(expected, value)) fail();
  return expected;
}
export function createStagedRetentionAttempt(input, currentEvidence, now) {
  const proposal = validateStagedRetentionProposal(input);
  const current = evidence(currentEvidence);
  const at = time(now);
  if (at < time(proposal.issuedAt) || at >= time(proposal.expiresAt)
    || !same(comparableEvidence(current), comparableEvidence(proposal.evidence))) fail('RUNTIME_INVENTORY_CHANGED');
  return seal('AGENT_ROAD_STAGED_RETENTION_ATTEMPT_V1', {
    schemaVersion: 1, deviceId: proposal.deviceId, operationId: proposal.operationId,
    proposalDigest: proposal.proposalDigest, authorizedAt: now,
  }, 'attemptDigest');
}
export function validateStagedRetentionAttempt(input, inputProposal) {
  const proposal = validateStagedRetentionProposal(inputProposal);
  const value = exact(snapshot(input), ['schemaVersion', 'deviceId', 'operationId', 'proposalDigest', 'authorizedAt', 'attemptDigest']);
  const expected = createStagedRetentionAttempt(proposal, proposal.evidence, value.authorizedAt);
  if (!same(expected, value)) fail();
  return expected;
}
export function reconcileStagedRetention(inputProposal, inputAttempt, inputObservation, now) {
  const proposal = validateStagedRetentionProposal(inputProposal);
  const attempt = validateStagedRetentionAttempt(inputAttempt, proposal);
  const observation = exact(snapshot(inputObservation), ['source', 'retained', 'parents', 'destination', 'targetBindingDigest', 'executorDigest',
    'sourceOperationEmpty', 'retainedOnlyExpectedTransaction', 'parentAclSha256', 'runtimeOnlyStaging', 'stagingOnlyExpectedOperation']);
  if (time(now) < time(attempt.authorizedAt)
    || observation.targetBindingDigest !== proposal.evidence.targetBindingDigest
    || observation.executorDigest !== proposal.evidence.executorDigest) fail();
  // Source-only never licenses redispatch: a timed-out executor may still run.
  if (observation.source !== null || observation.retained === null
    || observation.sourceOperationEmpty !== true || observation.retainedOnlyExpectedTransaction !== true
    || observation.runtimeOnlyStaging !== true || observation.stagingOnlyExpectedOperation !== true) {
    fail('RUNTIME_COMPLETION_UNCERTAIN');
  }
  const ids = proposal.evidence.sourceIdentity;
  exact(observation.parents, PARENTS);
  if (PARENTS.some(k => observation.parents[k] !== ids[k])) fail();
  exact(observation.parentAclSha256, PARENTS);
  const acl = proposal.evidence.sourceAclSha256;
  if (PARENTS.some(k => observation.parentAclSha256[k] !== acl[k])) fail();
  const dest = exact(observation.destination, ['rootIdentity', 'operationIdentity']);
  if (dest.rootIdentity === null || dest.operationIdentity === null) fail();
  identities(ids, dest);
  for (const key of Object.keys(dest)) {
    const before = proposal.evidence.destination[key];
    if (before !== null && before !== dest[key]) fail();
  }
  const staged = proposal.evidence.assessmentInput.staged;
  const expected = { transaction: ids.transaction, files: ids.files, capsule: ids.capsule, archive: ids.archive,
    capsuleSha256: staged.capsuleSha256, archiveSha256: staged.archiveSha256, archiveBytes: staged.archiveBytes,
    transactionAclSha256: acl.transaction, filesAclSha256: acl.files, capsuleAclSha256: acl.capsule, archiveAclSha256: acl.archive };
  if (!same(observation.retained, expected)) fail();
  return seal('AGENT_ROAD_STAGED_RETENTION_RECONCILIATION_V1', {
    schemaVersion: 1, deviceId: proposal.deviceId, operationId: proposal.operationId,
    proposalDigest: proposal.proposalDigest, attemptDigest: attempt.attemptDigest,
    observedAt: now, observation, disposition: 'RETAINED', runtimeRecovered: false,
    nextStep: 'EMPTY_OPERATION_RECOVERY',
  }, 'reconciliationDigest');
}
export function validateStagedRetentionReconciliation(input, proposal, attempt) {
  const value = exact(snapshot(input), ['schemaVersion', 'deviceId', 'operationId', 'proposalDigest', 'attemptDigest',
    'observedAt', 'observation', 'disposition', 'runtimeRecovered', 'nextStep', 'reconciliationDigest']);
  const expected = reconcileStagedRetention(proposal, attempt, value.observation, value.observedAt);
  if (!same(expected, value)) fail();
  return expected;
}
