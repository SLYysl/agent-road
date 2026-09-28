import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { statePaths } from '../core/paths.mjs';
import { validateRuntimeStateRecord } from './runtime-state-store.mjs';
import { StagedRetentionStore } from './runtime-recovery-store.mjs';
import { createProductionRuntimePlanDependencies, createProductionRuntimeRecoveryDependencies } from './production-runtime-dependencies.mjs';
import { runtimeRecoveryTargetBindingDigest } from './runtime-recovery-remote.mjs';
import { loadStagedRetentionWindowsBundle } from './staged-retention-windows.mjs';
import { executeStagedRetentionRemote } from './staged-retention-remote.mjs';
import { decodeStagedRetirementObservation } from './staged-retirement-assessment.mjs';
import { reconcileStagedRetention } from './staged-retention-protocol.mjs';

function fail(code = 'RUNTIME_STATE_UNSUPPORTED') { const error = new Error(code); error.code = code; throw error; }
function sameState(left, right) {
  return JSON.stringify(validateRuntimeStateRecord(left)) === JSON.stringify(validateRuntimeStateRecord(right));
}
function observation(value) {
  const fields = ['schemaVersion', 'capsuleBase64', 'staged', 'sourceIdentity', 'sourceAclSha256', 'destination'];
  if (!value || Object.keys(value).length !== fields.length || fields.some(k => !Object.hasOwn(value, k))) fail();
  return { ...decodeStagedRetirementObservation(JSON.stringify({ schemaVersion: value.schemaVersion,
    capsuleBase64: value.capsuleBase64, staged: value.staged })), sourceIdentity: value.sourceIdentity,
    sourceAclSha256: value.sourceAclSha256, destination: value.destination };
}

// No CLI entry point or runtime status transition. A durable RETAINED result is
// only a prerequisite for the existing empty-operation recovery protocol.
async function retainUnderLock(deviceId, dependencies, expectedState) {
  const d = dependencies;
  const bundle = await d.loadBundle();
  const state = validateRuntimeStateRecord(await d.readState(deviceId));
  if (!sameState(state, expectedState) || state.deviceId !== deviceId || state.runtimeStatus !== 'FAILED'
    || state.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN') fail();
  const binding = Object.freeze({ deviceId, operationId: state.operationId });
  const target = await d.loadTarget(deviceId);
  const targetBindingDigest = d.targetDigest(target);
  const controllerPublicKey = await d.readPublicKey();
  const stored = await d.store.read(binding);
  let proposal = stored.proposal;
  let attempt = stored.attempt;
  const base = { failedState: state, controllerPublicKey };
  const run = (mode, p = null, a = null) => d.remote({ target, bundle, input: { ...base, mode, proposal: p, attempt: a } });
  const assertCurrent = async () => {
    if (!sameState(state, await d.readState(deviceId))
      || targetBindingDigest !== d.targetDigest(await d.loadTarget(deviceId))) fail('RUNTIME_INVENTORY_CHANGED');
  };
  if (proposal !== null && (proposal.evidence.executorDigest !== bundle.executorDigest
    || proposal.evidence.targetBindingDigest !== targetBindingDigest
    || !sameState(proposal.evidence.assessmentInput.failedState, state))) fail();
  if (attempt === null) {
    const pair = await d.readInventoryPair(target);
    const remote = observation(await run('observe'));
    await assertCurrent();
    const evidence = {
      assessmentInput: { failedState: state, controllerPublicKey, capsuleJson: remote.capsuleJson, staged: remote.staged,
        firstInventory: pair.firstInventory, secondInventory: pair.secondInventory },
      targetBindingDigest, executorDigest: bundle.executorDigest,
      sourceIdentity: remote.sourceIdentity, sourceAclSha256: remote.sourceAclSha256, destination: remote.destination,
    };
    if (proposal === null) proposal = await d.store.propose(evidence);
    attempt = await d.store.consume(binding, proposal.proposalDigest, evidence);
    await assertCurrent();
    // Exactly one apply invocation. Even a rejected/lost acknowledgement leads
    // only to read-only reconciliation; no retry is inferred from a timeout.
    try { await run('apply', proposal, attempt); } catch { /* durable attempt remains consumed */ }
  }
  await assertCurrent();
  const post = await run('reconcile', proposal, attempt);
  await assertCurrent();
  reconcileStagedRetention(proposal, attempt, post, d.now());
  if (stored.reconciliation !== null) return stored.reconciliation;
  return d.store.reconcile(binding, post);
}

export async function retainObsoleteStagedTransaction(deviceId, dependencies) {
  const expected = validateRuntimeStateRecord(await dependencies.readState(deviceId));
  if (expected.deviceId !== deviceId || expected.runtimeStatus !== 'FAILED'
    || expected.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN') fail();
  return dependencies.store.withOperationLock({ deviceId, operationId: expected.operationId },
    () => retainUnderLock(deviceId, dependencies, expected));
}

export function createProductionStagedRetentionDependencies(env = process.env) {
  const paths = statePaths(env);
  const recovery = createProductionRuntimeRecoveryDependencies(env);
  const planning = createProductionRuntimePlanDependencies(env);
  return Object.freeze({
    loadBundle: loadStagedRetentionWindowsBundle,
    loadTarget: recovery.loadTarget,
    targetDigest: runtimeRecoveryTargetBindingDigest,
    readState: recovery.readState,
    readPublicKey: async () => JSON.parse(await readFile(paths.signingPublicKey, 'utf8')),
    readInventoryPair: planning.readInventoryPair,
    store: new StagedRetentionStore(paths.runtimeDevices),
    now: () => new Date().toISOString(),
    remote: input => executeStagedRetentionRemote({ ...input, captureRoot: join(paths.root, 'inspection-captures') }),
  });
}

// The same one-attempt protocol also retains a complete current-platform stage
// when no runtime work exists. It does not resume a failed installation.
export const retainUnstartedStagedTransaction = retainObsoleteStagedTransaction;
