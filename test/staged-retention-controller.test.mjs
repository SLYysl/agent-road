import assert from 'node:assert/strict';
import test from 'node:test';
import { retainObsoleteStagedTransaction } from '../src/runtime/staged-retention-controller.mjs';
import { createStagedRetentionProposal, createStagedRetentionAttempt, reconcileStagedRetention } from '../src/runtime/staged-retention-protocol.mjs';
import { retentionFixture, postObservation, now } from './fixtures/staged-retention.mjs';
import { parseStagedRetentionResponse, retentionScriptInvocation } from '../src/runtime/staged-retention-remote.mjs';
function setup() {
  const evidence = retentionFixture();
  const state = evidence.assessmentInput.failedState;
  const trace = [];
  const stored = { proposal: null, attempt: null, reconciliation: null };
  let held = false;
  const d = {
    loadBundle: async () => ({ source: 'fixture', executorDigest: evidence.executorDigest }),
    readState: async () => state, loadTarget: async () => ({}), targetDigest: () => evidence.targetBindingDigest,
    readPublicKey: async () => evidence.assessmentInput.controllerPublicKey,
    readInventoryPair: async () => ({ firstInventory: evidence.assessmentInput.firstInventory, secondInventory: evidence.assessmentInput.secondInventory }),
    now: () => now,
    store: {
      withOperationLock: async (_binding, callback) => { held = true; try { return await callback(); } finally { held = false; } },
      read: async () => ({ ...stored }),
      propose: async value => { assert.equal(held, true);trace.push('proposal');return stored.proposal = createStagedRetentionProposal(value, now); },
      consume: async (_binding, _digest, value) => {
        assert.equal(held, true);assert.equal(stored.attempt, null);trace.push('attempt');
        return stored.attempt = createStagedRetentionAttempt(stored.proposal, value, now);
      },
      reconcile: async (_binding, value) => { trace.push('record');return stored.reconciliation = reconcileStagedRetention(stored.proposal, stored.attempt, value, now); },
    },
    remote: async ({ input }) => {
      assert.equal(held, true);trace.push(input.mode);
      if(input.mode==='observe') return { schemaVersion:1, capsuleBase64:Buffer.from(evidence.assessmentInput.capsuleJson).toString('base64'),
        staged:evidence.assessmentInput.staged,sourceIdentity:evidence.sourceIdentity,sourceAclSha256:evidence.sourceAclSha256,destination:evidence.destination };
      if(input.mode==='apply') {assert.ok(stored.attempt);return {};}
      return postObservation(stored.proposal);
    },
  };
  return { evidence, state, trace, stored, d };
}
test('holds operation lock; consumes before exactly one dispatch and independent reconciliation', async () => {
 const {state,trace,d}=setup();const result=await retainObsoleteStagedTransaction(state.deviceId,d);
 assert.equal(result.runtimeRecovered,false);assert.deepEqual(trace,['observe','proposal','attempt','apply','reconcile','record']);
});
test('lost apply acknowledgement is reconciled without redispatch', async () => {
 const {state,trace,d}=setup();const original=d.remote;
 d.remote=async input=>{if(input.input.mode==='apply'){trace.push('apply');throw new Error('lost acknowledgement');}return original(input);};
 assert.equal((await retainObsoleteStagedTransaction(state.deviceId,d)).disposition,'RETAINED');
 assert.equal(trace.filter(x=>x==='apply').length,1);
});
test('restart with a durable attempt only reconciles', async () => {
 const {state,stored,trace,d,evidence}=setup();stored.proposal=createStagedRetentionProposal(evidence,now);stored.attempt=createStagedRetentionAttempt(stored.proposal,evidence,now);
 await retainObsoleteStagedTransaction(state.deviceId,d);assert.deepEqual(trace,['reconcile','record']);
});
test('uncertain postcheck preserves consumed attempt; next invocation never applies again', async () => {
 const {state,stored,trace,d}=setup();const original=d.remote;
 d.remote=async input=>{if(input.input.mode==='reconcile'){trace.push('reconcile');throw new Error('unknown remote result');}return original(input);};
 await assert.rejects(retainObsoleteStagedTransaction(state.deviceId,d));assert.ok(stored.attempt);assert.equal(stored.reconciliation,null);
 await assert.rejects(retainObsoleteStagedTransaction(state.deviceId,d));assert.equal(trace.filter(x=>x==='apply').length,1);
});
test('failed attempt publication prevents dispatch', async () => {
 const {state,d,trace}=setup();d.store.consume=async()=>{throw new Error('disk interrupted');};
 await assert.rejects(retainObsoleteStagedTransaction(state.deviceId,d));assert.equal(trace.includes('apply'),false);
});
test('state drift after durable consumption prevents dispatch and preserves attempt', async () => {
 const {state,stored,d,trace}=setup();d.readState=async()=>stored.attempt?{...state,updatedAt:'2026-09-18T10:01:01.000Z'}:state;
 await assert.rejects(retainObsoleteStagedTransaction(state.deviceId,d));assert.ok(stored.attempt);assert.equal(trace.includes('apply'),false);
});
test('changed executor cannot reuse an earlier proposal', async () => {
 const {state,stored,d,trace,evidence}=setup();stored.proposal=createStagedRetentionProposal(evidence,now);
 d.loadBundle=async()=>({executorDigest:'F'.repeat(64)});
 await assert.rejects(retainObsoleteStagedTransaction(state.deviceId,d));assert.deepEqual(trace,[]);
});
test('response parser rejects malformed, duplicate, error, and nonterminal output', () => {
 const base={exitCode:0,signal:null,stderr:'',stdout:'{"ok":true}'};
 assert.deepEqual(parseStagedRetentionResponse(base),{ok:true});
 for(const change of [{stdout:'{"x":1,"x":2}'},{stdout:'{"error":"RUNTIME_STATE_UNSUPPORTED"}'},{exitCode:73},{signal:'SIGTERM'},{stderr:'warning'},{stdout:'{}\n'}])
  assert.throws(()=>parseStagedRetentionResponse({...base,...change}));
 assert.throws(()=>retentionScriptInvocation('x'.repeat(131073)));
 assert.ok(retentionScriptInvocation('Write-Output "fixture"').stdin.length>0);
});
