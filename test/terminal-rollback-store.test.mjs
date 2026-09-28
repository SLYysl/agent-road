import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtemp,realpath,rm,mkdir,writeFile,readFile,stat,unlink,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fixture} from './fixtures/terminal-rollback.mjs';
import {now} from './fixtures/staged-retention.mjs';
import {createTerminalRollbackCommit} from '../src/runtime/terminal-rollback-protocol.mjs';
import {withTerminalRollbackConfirmation} from '../src/runtime/runtime-recovery-store.mjs';
import {RuntimeStateStore} from '../src/runtime/runtime-state-store.mjs';
import {runtimeDeviceStatePath,runtimeDeviceRecoveryPaths} from '../src/core/paths.mjs';
async function setup(t) {
 const directory=await realpath(await mkdtemp(join(tmpdir(),'ar-terminal-')));t.after(()=>rm(directory,{recursive:true,force:true}));
 const root=join(directory,'devices');const evidence=fixture(),expected=evidence.failedState;
 const binding={deviceId:expected.deviceId,operationId:expected.operationId};
 const path=runtimeDeviceStatePath(root,expected.deviceId);await mkdir(dirname(path),{recursive:true,mode:0o700});await writeFile(path,JSON.stringify(expected,null,2)+'\n',{mode:0o600});
 const commit=createTerminalRollbackCommit(evidence,evidence.observation,now);
 const commitPath=join(runtimeDeviceRecoveryPaths(root,binding.deviceId,binding.operationId).operation,'terminal-rollback-v1','commit.json');
 return {root,binding,expected,commit,commitPath,store:new RuntimeStateStore(root)};
}
test('ordinary transition cannot clear uncertainty; confirmation needs a durable commit',async t=>{
 const f=await setup(t);
 await assert.rejects(f.store.transition(f.expected,f.commit.nextState));
 await assert.rejects(f.store.confirmTerminalRollback(f.expected,f.commit.nextState));
 assert.deepEqual(await f.store.read(f.binding.deviceId),f.expected);
});
test('commit survives restart before CAS and cannot be republished',async t=>{
 const f=await setup(t);
 await withTerminalRollbackConfirmation(f.root,f.binding,async s=>{assert.equal(await s.read(),null);assert.deepEqual(await s.publish(f.commit),f.commit);});
 await assert.rejects(withTerminalRollbackConfirmation(f.root,f.binding,s=>s.publish(f.commit)));
 assert.equal((await stat(f.commitPath)).mode&0o777,0o600);
 assert.deepEqual(await f.store.confirmTerminalRollback(f.expected,f.commit.nextState),f.commit.nextState);
 assert.deepEqual(await f.store.read(f.binding.deviceId),f.commit.nextState);
 await assert.rejects(f.store.confirmTerminalRollback(f.expected,f.commit.nextState));
});
test('held confirmation lock permits the state CAS without reacquiring its own kernel lock',async t=>{
 const f=await setup(t);let escaped;
 await withTerminalRollbackConfirmation(f.root,f.binding,async s=>{escaped=s;await s.publish(f.commit);await f.store.confirmTerminalRollback(f.expected,f.commit.nextState);});
 assert.throws(()=>escaped.read());
});
test('corrupt receipt and symlink substitution cannot authorize state mutation',async t=>{
 const f=await setup(t);await withTerminalRollbackConfirmation(f.root,f.binding,s=>s.publish(f.commit));
 const original=await readFile(f.commitPath);let corrupt=JSON.parse(original);corrupt.nextState.failureCode='RUNTIME_SELF_TEST_FAILED';await writeFile(f.commitPath,JSON.stringify(corrupt)+'\n');
 await assert.rejects(f.store.confirmTerminalRollback(f.expected,f.commit.nextState));
 const other=f.commitPath+'.other';await writeFile(other,original,{mode:0o600});await unlink(f.commitPath);await symlink(other,f.commitPath);
 await assert.rejects(f.store.confirmTerminalRollback(f.expected,f.commit.nextState));
 assert.deepEqual(await f.store.read(f.binding.deviceId),f.expected);
});
test('lost state publication acknowledgement retains a rereadable finite state and receipt',async t=>{
 const f=await setup(t),hook=Symbol.for('agent-road.runtime-state-store.test-hook');
 await withTerminalRollbackConfirmation(f.root,f.binding,s=>s.publish(f.commit));
 globalThis[hook]=async stage=>{if(stage==='afterStatePublication')throw Error('lost acknowledgement');};
 try{await assert.rejects(f.store.confirmTerminalRollback(f.expected,f.commit.nextState));}finally{delete globalThis[hook];}
 assert.deepEqual(await f.store.read(f.binding.deviceId),f.commit.nextState);
 assert.deepEqual(await withTerminalRollbackConfirmation(f.root,f.binding,s=>s.read()),f.commit);
});
test('lost immutable-publication reply leaves state unchanged and a resumable exact commit',async t=>{
 const f=await setup(t),hook=Symbol.for('agent-road.runtime-recovery-store.test-hook');
 globalThis[hook]=async stage=>{if(stage==='afterImmutablePublicationValidation')throw Error('lost publication reply');};
 try{await assert.rejects(withTerminalRollbackConfirmation(f.root,f.binding,s=>s.publish(f.commit)));}finally{delete globalThis[hook];}
 assert.deepEqual(await f.store.read(f.binding.deviceId),f.expected);
 assert.deepEqual(await withTerminalRollbackConfirmation(f.root,f.binding,s=>s.read()),f.commit);
 await f.store.confirmTerminalRollback(f.expected,f.commit.nextState);
});
test('unawaited scoped reads drain before lock release and escaped scopes reject',async t=>{
 const f=await setup(t);let escaped,pending;
 await withTerminalRollbackConfirmation(f.root,f.binding,async s=>{escaped=s;pending=s.read();});
 assert.equal(await pending,null);assert.throws(()=>escaped.read());
});
test('direct confirmation acquires operation lock before the state-file lock',async t=>{
 const f=await setup(t),recoveryHook=Symbol.for('agent-road.runtime-recovery-store.test-hook'),stateHook=Symbol.for('agent-road.runtime-state-store.test-hook'),events=[];
 await withTerminalRollbackConfirmation(f.root,f.binding,s=>s.publish(f.commit));
 globalThis[recoveryHook]=async stage=>{if(stage==='afterRecoveryKernelLockAcquired')events.push('operation');};
 globalThis[stateHook]=async stage=>{if(stage==='afterStateLayoutCheck')events.push('state');};
 try{await f.store.confirmTerminalRollback(f.expected,f.commit.nextState);}finally{delete globalThis[recoveryHook];delete globalThis[stateHook];}
 assert.deepEqual(events,['operation','state']);
});
test('a state CAS started inside the scope drains before the operation lock is released',async t=>{
 const f=await setup(t),hook=Symbol.for('agent-road.runtime-state-store.test-hook');
 let entered,release,pending,settled=false;
 const observed=new Promise(resolve=>{entered=resolve;});const gate=new Promise(resolve=>{release=resolve;});
 globalThis[hook]=async stage=>{if(stage==='afterStatePublication'){entered();await gate;}};
 const running=withTerminalRollbackConfirmation(f.root,f.binding,async s=>{
  await s.publish(f.commit);pending=f.store.confirmTerminalRollback(f.expected,f.commit.nextState);pending.catch(()=>{});
  await observed;
 }).finally(()=>{settled=true;});
 try{await observed;await new Promise(resolve=>setTimeout(resolve,20));assert.equal(settled,false);release();await running;assert.deepEqual(await pending,f.commit.nextState);}
 finally{release();delete globalThis[hook];await running.catch(()=>{});}
});
