import assert from 'node:assert/strict';
import test from 'node:test';
import { validateEmptyStageProof, eligibleEmptyStageState, emptyStageBundle, emptyStageScript } from '../src/runtime/empty-stage-retention.mjs';

function proof() {
  const names = ['programData', 'agentRoad', 'runtime', 'staging', 'operation', 'transaction', 'files'];
  return { tree: { identities: Object.fromEntries(names.map((n, i) => [n, 'A'.repeat(16) + ':' + String(i).padStart(32, '0')])),
    acls: Object.fromEntries(names.map(n => [n, 'B'.repeat(64)])) }, bootUtc: '2026-09-21T12:00:00.0000000Z', destinationAbsent: true };
}
test('maintenance admission is restricted to the same failed core operation', () => {
  const state = { schemaVersion: 1, deviceId: 'dev_abc123', runtimeStatus: 'FAILED', requestedProfiles: ['core'],
    readyProfiles: [], operationId: 'a'.repeat(32), manifestDigest: 'B'.repeat(64), generationDigest: 'C'.repeat(64),
    failureCode: 'RUNTIME_COMPLETION_UNCERTAIN', updatedAt: '2026-09-21T12:00:00.000Z' };
  assert.equal(eligibleEmptyStageState(state, state.deviceId).operationId, state.operationId);
  for (const change of [{ runtimeStatus: 'READY', readyProfiles: ['core'], failureCode: null },
    { requestedProfiles: ['core', 'base'] }, { failureCode: 'RUNTIME_INSTALL_FAILED' }, { operationId: null }]) {
    assert.throws(() => eligibleEmptyStageState({ ...state, ...change }, state.deviceId));
  }
  assert.throws(() => eligibleEmptyStageState(state, 'dev_other'));
});
test('empty scaffold proof requires complete unique same-volume identities and ACLs', () => {
  assert.equal(validateEmptyStageProof(proof()).destinationAbsent, true);
  for (const mutate of [p => delete p.tree.identities.files, p => { p.tree.identities.files = p.tree.identities.transaction; },
    p => { p.tree.identities.files = 'C'.repeat(16) + ':' + 'D'.repeat(32); }, p => { p.destinationAbsent = false; },
    p => { p.tree.acls.files = ''; }, p => { p.bootUtc = 'invalid'; }, p => { p.extra = true; }]) {
    const p = proof(); mutate(p); assert.throws(() => validateEmptyStageProof(p), /RUNTIME_STATE_UNSUPPORTED/u);
  }
});
test('maintenance script uses existing handle-bound retention and no runtime transition', async () => {
  const b = await emptyStageBundle();
  const s = emptyStageScript(b, { mode: 'observe' });
  assert.ok(s.includes('Invoke-EmptyStageRetention'));
  assert.ok(s.includes('AgentRoadRetention.Native'));
  assert.ok(Buffer.byteLength(s) < 131072);
  assert.throws(() => emptyStageScript(b, {}, "C:\\bad';exit"), /RUNTIME_INPUT_INVALID/u);
});
