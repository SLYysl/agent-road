import assert from 'node:assert/strict';
import { mkdtemp, realpath, rm, readFile, stat, symlink, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { StagedRetentionStore } from '../src/runtime/runtime-recovery-store.mjs';
import { runtimeDeviceRecoveryPaths } from '../src/core/paths.mjs';
import { retentionFixture, postObservation, now } from './fixtures/staged-retention.mjs';
const hook = Symbol.for('agent-road.runtime-recovery-store.test-hook');
async function fixture(t) {
 const directory=await realpath(await mkdtemp(join(tmpdir(),'ar-retention-')));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const root=join(directory,'devices');
 const store=new StagedRetentionStore(root,{now:()=>new Date(now)});
 const evidence=retentionFixture();
 const binding={deviceId:evidence.assessmentInput.failedState.deviceId,operationId:evidence.assessmentInput.failedState.operationId};
 const paths=runtimeDeviceRecoveryPaths(root,binding.deviceId,binding.operationId);
 return {store,root,evidence,binding,paths};
}
test('durable proposal, single consumption, independent postcheck and reread',async t=>{
 const {store,evidence,binding,paths}=await fixture(t);
 assert.deepEqual(await store.read(binding),{proposal:null,attempt:null,reconciliation:null});
 const proposal=await store.propose(evidence);
 await assert.rejects(store.propose(evidence));
 const attempt=await store.consume(binding,proposal.proposalDigest,evidence);
 await assert.rejects(store.consume(binding,proposal.proposalDigest,evidence));
 const record=await store.reconcile(binding,postObservation(proposal));
 assert.equal(record.disposition,'RETAINED');
 assert.deepEqual(await store.read(binding),{proposal,attempt,reconciliation:record});
 const path=join(paths.operation,'staged-retention-v1','attempt.json');
 assert.equal((await stat(path)).mode&0o777,0o600);
 assert.equal(JSON.parse(await readFile(path)).attemptDigest,attempt.attemptDigest);
});
test('reconciliation cannot succeed without a durable attempt',async t=>{
 const {store,evidence,binding}=await fixture(t);const proposal=await store.propose(evidence);
 await assert.rejects(store.reconcile(binding,postObservation(proposal)));
 assert.equal((await store.read(binding)).attempt,null);
});
test('two consumers race: exactly one gets an attempt',async t=>{
 const {store,evidence,binding}=await fixture(t);const proposal=await store.propose(evidence);
 const results=await Promise.allSettled([store.consume(binding,proposal.proposalDigest,evidence),store.consume(binding,proposal.proposalDigest,evidence)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
});
test('expired proposal cannot create a durable attempt',async t=>{
 const {store,root,evidence,binding}=await fixture(t);const proposal=await store.propose(evidence);
 const late=new StagedRetentionStore(root,{now:()=>new Date('2026-09-18T10:07:00.000Z')});
 await assert.rejects(late.consume(binding,proposal.proposalDigest,evidence), { code: 'RUNTIME_INVENTORY_CHANGED' });
 assert.equal((await store.read(binding)).attempt,null);
});
test('lost publish acknowledgement leaves attempt consumed across a new store instance',async t=>{
 const {store,root,evidence,binding}=await fixture(t);const proposal=await store.propose(evidence);
 globalThis[hook]=async(name,{path})=>{if(name==='afterPublishDirectorySync' && path.endsWith('/attempt.json'))throw new Error('simulated process loss');};
 try{await assert.rejects(store.consume(binding,proposal.proposalDigest,evidence));}finally{delete globalThis[hook];}
 const restarted=new StagedRetentionStore(root,{now:()=>new Date(now)});
 assert.ok((await restarted.read(binding)).attempt);
 await assert.rejects(restarted.consume(binding,proposal.proposalDigest,evidence));
 assert.equal((await restarted.reconcile(binding,postObservation(proposal))).disposition,'RETAINED');
});
test('incomplete dispatch outcome preserves attempt and permits later read-only reconciliation',async t=>{
 const {store,evidence,binding}=await fixture(t);const proposal=await store.propose(evidence);
 await store.consume(binding,proposal.proposalDigest,evidence);
 const unknown=postObservation(proposal);unknown.source=unknown.retained;unknown.retained=null;
 await assert.rejects(store.reconcile(binding,unknown), { code: 'RUNTIME_COMPLETION_UNCERTAIN' });
 assert.equal((await store.read(binding)).reconciliation,null);
 await assert.rejects(store.consume(binding,proposal.proposalDigest,evidence));
 assert.equal((await store.reconcile(binding,postObservation(proposal))).runtimeRecovered,false);
});
test('rejects a symlinked retention namespace without following it',async t=>{
 const {store,evidence,binding,paths}=await fixture(t);
 await store.read(binding);
 const elsewhere=join(paths.device,'elsewhere');await mkdir(elsewhere,{mode:0o700});
 await symlink(elsewhere,join(paths.operation,'staged-retention-v1'));
 await assert.rejects(store.propose(evidence));
});

test('interruption before attempt publication fails closed without allowing a dispatch', async t => {
 const { store, evidence, binding } = await fixture(t);
 const proposal = await store.propose(evidence);
 globalThis[hook] = async (name, { path }) => {
   if (name === 'afterTemporarySyncBeforePublish' && path.endsWith('/attempt.json')) throw new Error('interrupted before publish');
 };
 try { await assert.rejects(store.consume(binding, proposal.proposalDigest, evidence)); }
 finally { delete globalThis[hook]; }
 await assert.rejects(store.consume(binding, proposal.proposalDigest, evidence));
 await assert.rejects(store.reconcile(binding, postObservation(proposal)));
});

test('controller lock holds across remote work and excludes a second store', async t => {
 const {store,root,evidence,binding}=await fixture(t);
 const other=new StagedRetentionStore(root,{now:()=>new Date(now)});
 await store.withOperationLock(binding,async()=>{
  const proposal=await store.propose(evidence);
  await assert.rejects(other.read(binding), {code:'RUNTIME_ALREADY_RUNNING'});
  await store.consume(binding,proposal.proposalDigest,evidence);
  await store.reconcile(binding,postObservation(proposal));
 });
 assert.equal((await other.read(binding)).reconciliation.disposition,'RETAINED');
});

test('controller scope rejects nested locks and escaped asynchronous access', async t => {
 const {store,binding}=await fixture(t);
 let resume;const gate=new Promise(resolve=>{resume=resolve;});let escaped;
 await store.withOperationLock(binding,async()=>{
  await assert.rejects(store.withOperationLock(binding,()=>{}),{code:'RUNTIME_INPUT_INVALID'});
  escaped=gate.then(()=>store.read(binding));
  await store.read(binding);
 });
 resume();
 await assert.rejects(escaped,{code:'RUNTIME_INPUT_INVALID'});
 assert.equal((await store.read(binding)).attempt,null);
});

test('controller scope drains unawaited publication before releasing its kernel lock', async t => {
 const {store,root,evidence,binding}=await fixture(t);
 const other=new StagedRetentionStore(root,{now:()=>new Date(now)});
 let resume,entered;const gate=new Promise(resolve=>{resume=resolve;});
 const ready=new Promise(resolve=>{entered=resolve;});let finished=false;
 globalThis[hook]=async(name,{path})=>{
  if(name==='afterTemporarySyncBeforePublish' && path.endsWith('/proposal.json')){entered();await gate;}
 };
 try {
  const scope=store.withOperationLock(binding,()=>{void store.propose(evidence);}).then(()=>{finished=true;});
  await ready;
  assert.equal(finished,false);
  await assert.rejects(other.read(binding),{code:'RUNTIME_ALREADY_RUNNING'});
  resume();await scope;
  assert.ok((await other.read(binding)).proposal);
 } finally {resume();delete globalThis[hook];}
});

test('persists current-platform unstarted retention with the same one-use record chain',async t=>{
 const {store,evidence,binding}=await fixture(t);
 const platform=JSON.parse(JSON.parse(evidence.assessmentInput.capsuleJson).manifestJson).platform;
 evidence.assessmentInput.firstInventory.platform=structuredClone(platform);
 evidence.assessmentInput.secondInventory.platform=structuredClone(platform);
 await store.withOperationLock(binding,async()=>{
  const proposal=await store.propose(evidence);
  await store.consume(binding,proposal.proposalDigest,evidence);
  await store.reconcile(binding,postObservation(proposal));
 });
 const saved=await store.read(binding);
 assert.equal(saved.reconciliation.disposition,'RETAINED');
 await assert.rejects(store.consume(binding,saved.proposal.proposalDigest,evidence));
});
