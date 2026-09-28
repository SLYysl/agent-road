import assert from 'node:assert/strict';
import test from 'node:test';
import { retentionFixture, postObservation, now } from './fixtures/staged-retention.mjs';
import { createStagedRetentionProposal, validateStagedRetentionProposal, createStagedRetentionAttempt,
  validateStagedRetentionAttempt, reconcileStagedRetention } from '../src/runtime/staged-retention-protocol.mjs';

function setup() {
 const evidence = retentionFixture();
 const proposal = createStagedRetentionProposal(evidence, now);
 const attempt = createStagedRetentionAttempt(proposal, evidence, now);
 return { evidence, proposal, attempt, observation: postObservation(proposal) };
}
test('proposal and one-time attempt bind signed evidence; reconciliation never marks runtime recovered', () => {
 const { proposal, attempt, observation } = setup();
 assert.deepEqual(validateStagedRetentionProposal(proposal), proposal);
 assert.deepEqual(validateStagedRetentionAttempt(attempt, proposal), attempt);
 const result = reconcileStagedRetention(proposal, attempt, observation, now);
 assert.equal(result.disposition, 'RETAINED');
 assert.equal(result.runtimeRecovered, false);
 assert.equal(result.nextStep, 'EMPTY_OPERATION_RECOVERY');
 assert.equal(Object.isFrozen(proposal.evidence.sourceIdentity), true);
});
for (const [name, change] of [
 ['state', v => { v.assessmentInput.failedState.updatedAt = '2026-09-18T10:01:01.000Z'; }],
 ['target', v => { v.targetBindingDigest = 'F'.repeat(64); }],
 ['executor', v => { v.executorDigest = 'F'.repeat(64); }],
 ['source directory', v => { v.sourceIdentity.transaction = 'A'.repeat(16)+':'+ 'F'.repeat(32); }],
 ['destination appeared', v => { v.destination.transactionAbsent = false; }],
 ['reboot pending', v => { v.assessmentInput.firstInventory.pendingReboot=true; v.assessmentInput.secondInventory.pendingReboot=true; }],
]) test(`cannot consume with changed ${name}`, () => {
 const { evidence, proposal } = setup(); change(evidence);
 assert.throws(() => createStagedRetentionAttempt(proposal, evidence, now));
});
test('rejects expired, future, or pre-failure proposal times', () => {
 const { evidence, proposal } = setup();
 for(const t of ['2026-09-18T10:07:00.000Z','2026-09-18T10:01:59.999Z'])
   assert.throws(() => createStagedRetentionAttempt(proposal,evidence,t));
 assert.throws(() => createStagedRetentionProposal(evidence,'2026-09-18T10:00:00.000Z'));
});
for(const [name, change] of [
 ['different volume', v=>{v.sourceIdentity.archive='B'.repeat(16)+':'+ 'F'.repeat(32);}],
 ['aliased source IDs',v=>{v.sourceIdentity.archive=v.sourceIdentity.capsule;}],
 ['aliased destination',v=>{v.destination.rootIdentity=v.sourceIdentity.runtime;}],
 ['destination child without parent',v=>{v.destination.operationIdentity='A'.repeat(16)+':'+ 'F'.repeat(32);}],
 ['extra path',v=>{v.destination.path='C:\\other';}],
]) test(`proposal rejects ${name}`,()=>{ const v=retentionFixture();change(v);assert.throws(()=>createStagedRetentionProposal(v,now)); });
for(const [name,change] of [
 ['source only',o=>{o.source=o.retained;o.retained=null;o.sourceOperationEmpty=false;o.retainedOnlyExpectedTransaction=false;}],
 ['both',o=>{o.source=o.retained;o.sourceOperationEmpty=false;}],
 ['neither',o=>{o.retained=null;}],
 ['postcheck target changed',o=>{o.targetBindingDigest='B'.repeat(64);}],
 ['postcheck executor changed',o=>{o.executorDigest='B'.repeat(64);}],
 ['parent ACL changed',o=>{o.parentAclSha256.operation='B'.repeat(64);}],
 ['retained ACL changed',o=>{o.retained.archiveAclSha256='B'.repeat(64);}],
 ['other operation appeared',o=>{o.stagingOnlyExpectedOperation=false;}],
 ['other runtime content appeared',o=>{o.runtimeOnlyStaging=false;}],
 ['archive changed',o=>{o.retained.archiveSha256='F'.repeat(64);}],
 ['transaction replaced',o=>{o.retained.transaction='A'.repeat(16)+':'+ 'F'.repeat(32);}],
 ['source parent replaced',o=>{o.parents.operation='A'.repeat(16)+':'+ 'F'.repeat(32);}],
 ['extra source content',o=>{o.sourceOperationEmpty=false;}],
 ['extra retained content',o=>{o.retainedOnlyExpectedTransaction=false;}],
 ['destination aliases source',o=>{o.destination.rootIdentity=o.parents.runtime;}],
]) test(`reconciliation refuses ${name}`,()=>{const {proposal,attempt,observation}=setup();change(observation);assert.throws(()=>reconcileStagedRetention(proposal,attempt,observation,now));});
test('lost acknowledgement can reconcile later, but an attempt is mandatory',()=>{
 const {proposal,attempt,observation}=setup();
 assert.equal(reconcileStagedRetention(proposal,attempt,observation,'2026-09-19T10:00:00.000Z').disposition,'RETAINED');
 assert.throws(()=>reconcileStagedRetention(proposal,null,observation,now));
 assert.throws(()=>reconcileStagedRetention(proposal,{...attempt,proposalDigest:'F'.repeat(64)},observation,now));
});
test('rejects altered proposal and accessor without invoking it',()=>{
 const {proposal}=setup();
 assert.throws(()=>validateStagedRetentionProposal({...proposal,expiresAt:'2026-10-18T10:07:00.000Z'}));
 let calls=0;const evidence=retentionFixture();Object.defineProperty(evidence,'sourceIdentity',{enumerable:true,get(){calls++;return {};}});
 assert.throws(()=>createStagedRetentionProposal(evidence,now));assert.equal(calls,0);
 assert.throws(()=>createStagedRetentionProposal(new Proxy(retentionFixture(),{}),now));
});

test('fresh inventories allow harmless disk drift but still enforce capacity', () => {
 const { evidence, proposal } = setup();
 evidence.assessmentInput.firstInventory.freeBytes -= 4096;
 evidence.assessmentInput.secondInventory.freeBytes -= 8192;
 assert.ok(createStagedRetentionAttempt(proposal, evidence, now));
 evidence.assessmentInput.firstInventory.freeBytes = 0;
 evidence.assessmentInput.secondInventory.freeBytes = 0;
 assert.throws(() => createStagedRetentionAttempt(proposal, evidence, now));
});

test('attempt validation never reads accessors on an unvalidated proposal', () => {
 const { attempt, proposal } = setup();
 let invoked = false;
 const unsafe = { ...proposal };
 Object.defineProperty(unsafe, 'evidence', { enumerable: true, get() { invoked = true; return proposal.evidence; } });
 assert.throws(() => validateStagedRetentionAttempt(attempt, unsafe));
 assert.equal(invoked, false);
});

test('retains a complete current-platform stage without resuming its failed installation',()=>{
 const evidence=retentionFixture();
 const manifest=JSON.parse(JSON.parse(evidence.assessmentInput.capsuleJson).manifestJson);
 evidence.assessmentInput.firstInventory.platform=structuredClone(manifest.platform);
 evidence.assessmentInput.secondInventory.platform=structuredClone(manifest.platform);
 const proposal=createStagedRetentionProposal(evidence,now);
 const attempt=createStagedRetentionAttempt(proposal,evidence,now);
 assert.equal(reconcileStagedRetention(proposal,attempt,postObservation(proposal),now).runtimeRecovered,false);
 for(const change of [v=>{v.staged.hasWork=true;},v=>{v.staged.hasTemporary=true;},v=>{v.secondInventory.runtime.schemaVersion=1;},v=>{v.firstInventory.platform.edition='different';v.secondInventory.platform.edition='different';}]){
  const bad=structuredClone(evidence);change(bad.assessmentInput);
  assert.throws(()=>createStagedRetentionProposal(bad,now));
 }
});
