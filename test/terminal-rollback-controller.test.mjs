import assert from 'node:assert/strict';
import test from 'node:test';
import {fixture} from './fixtures/terminal-rollback.mjs';
import {now} from './fixtures/staged-retention.mjs';
import {confirmInitialCoreRollback} from '../src/runtime/terminal-rollback-controller.mjs';
function setup(){
 const f=fixture();let state=structuredClone(f.failedState),commit=null,observes=0,transitions=0;
 const d={readState:async()=>state,loadTarget:async()=>({}),targetDigest:()=>f.targetBindingDigest,readPublicKey:async()=>f.controllerPublicKey,
 now:()=>now,loadBundle:async()=>({executorDigest:f.executorDigest}),observe:async()=>{observes++;return structuredClone(f.observation);},
 withConfirmation:async(b,callback)=>callback({read:async()=>commit,publish:async c=>{commit=c;return c;}}),
 confirmState:async(a,b)=>{assert.deepEqual(state,a);transitions++;state=b;return b;}};
 return {f,d,get state(){return state;},get commit(){return commit;},get observes(){return observes;},get transitions(){return transitions;}};
}
test('two equal observations persist before CAS; reentry returns existing finite state',async()=>{
 const f=setup();await confirmInitialCoreRollback(f.f.failedState.deviceId,f.d);
 assert.equal(f.observes,2);assert.equal(f.transitions,1);assert.ok(f.commit);
 await confirmInitialCoreRollback(f.f.failedState.deviceId,f.d);assert.equal(f.observes,2);assert.equal(f.transitions,1);
});
test('interruption before CAS resumes the durable commit without remote invocation',async()=>{
 const f=setup(),original=f.d.confirmState;f.d.confirmState=async()=>{throw Error('crash');};
 await assert.rejects(confirmInitialCoreRollback(f.f.failedState.deviceId,f.d));assert.ok(f.commit);
 f.d.confirmState=original;await confirmInitialCoreRollback(f.f.failedState.deviceId,f.d);assert.equal(f.observes,2);
});
test('lost state-write reply is reconciled by readback, without re-dispatch',async()=>{
 const f=setup(),original=f.d.confirmState;f.d.confirmState=async(...a)=>{await original(...a);throw Error('lost reply');};
 await assert.rejects(confirmInitialCoreRollback(f.f.failedState.deviceId,f.d));
 await confirmInitialCoreRollback(f.f.failedState.deviceId,f.d);assert.equal(f.transitions,1);assert.equal(f.observes,2);
});
for(const mode of ['observation','target','source','key','deadline'])test(`rejects changed ${mode} before publishing`,async()=>{
 const f=setup();let calls=0;
 if(mode==='observation'){const orig=f.d.observe;f.d.observe=async()=>{const o=await orig();if(++calls===2)o.archiveBytes++;return o;};}
 if(mode==='target')f.d.targetDigest=()=>++calls===1?f.f.targetBindingDigest:'A'.repeat(64);
 if(mode==='source')f.d.loadBundle=async()=>({executorDigest:++calls===1?f.f.executorDigest:'A'.repeat(64)});
 if(mode==='key')f.d.readPublicKey=async()=>++calls===1?f.f.controllerPublicKey:{};
 if(mode==='deadline')f.d.now=()=>++calls===1?now:'2026-09-18T11:02:00.000Z';
 await assert.rejects(confirmInitialCoreRollback(f.f.failedState.deviceId,f.d));assert.equal(f.commit,null);assert.equal(f.transitions,0);
});
