import assert from 'node:assert/strict';
import test from 'node:test';
import {main} from '../src/cli.mjs';
import {fixture} from './fixtures/terminal-rollback.mjs';
const DEVICE='dev_retirementfixture';
function result(){return {...fixture().failedState,failureCode:'RUNTIME_INSTALL_FAILED',updatedAt:'2026-09-19T12:00:00.000Z'};}
async function run(args,overrides={}){let out='',err='',calls=0;const code=await main(args,{}, {stdout:{write:s=>{out+=s;}},stderr:{write:s=>{err+=s;}},confirmTerminalRollback:async input=>{calls++;assert.equal(input.deviceId,DEVICE);return result();},...overrides});return {code,out,err,calls};}
test('exposes confirmation as one explicit command with a redacted finite result',async()=>{
 const r=await run(['runtime-confirm-rollback',DEVICE]);assert.equal(r.code,0);assert.equal(r.calls,1);assert.equal(r.err,'');
 assert.deepEqual(JSON.parse(r.out),{schemaVersion:1,status:'ROLLBACK_CONFIRMED',runtimeStatus:'FAILED',failureCode:'RUNTIME_INSTALL_FAILED',remoteMutation:false});assert.ok(!r.out.includes(DEVICE));
});
for(const args of [[],[DEVICE,'--apply'],[DEVICE,'--profile','base'],[DEVICE,DEVICE],['latest'],['--',DEVICE]])test(`rejects invalid confirmation args ${args.join(' ')}`,async()=>{const r=await run(['runtime-confirm-rollback',...args]);assert.equal(r.code,2);assert.equal(r.calls,0);assert.equal(r.out,'');assert.equal(r.err,'RUNTIME_INPUT_INVALID\n');});
for(const [name,change]of [['READY',r=>{r.runtimeStatus='READY';r.failureCode=null;r.readyProfiles=['core'];}],['foreign device',r=>{r.deviceId='dev_other';}],['uncertainty',r=>{r.failureCode='RUNTIME_COMPLETION_UNCERTAIN';}],['extra data',r=>{r.secret='private';}]])test(`does not publish ${name} as confirmation`,async()=>{const r=await run(['runtime-confirm-rollback',DEVICE],{confirmTerminalRollback:async()=>{const v=result();change(v);return v;}});assert.equal(r.code,2);assert.equal(r.out,'');assert.equal(r.err,'RUNTIME_INPUT_INVALID\n');});
test('finite and unknown errors do not leak details or retry',async()=>{for(const code of ['RUNTIME_STATE_UNSUPPORTED','PRIVATE_ERROR']){let n=0;const r=await run(['runtime-confirm-rollback',DEVICE],{confirmTerminalRollback:async()=>{n++;throw Object.assign(Error('secret host/path'),{code});}});assert.equal(n,1);assert.equal(r.code,2);assert.equal(r.out,'');assert.equal(r.err,code==='PRIVATE_ERROR'?'RUNTIME_INTERNAL_ERROR\n':code+'\n');}});
test('default adapter uses the confirmation dependency factory, without a provision dependency',async()=>{
 const f=fixture();let state=f.failedState,commit=null,observations=0;
 const deps={readState:async()=>state,loadTarget:async()=>({}),targetDigest:()=>f.targetBindingDigest,readPublicKey:async()=>f.controllerPublicKey,now:()=> '2026-09-19T12:00:00.000Z',loadBundle:async()=>({executorDigest:f.executorDigest}),observe:async()=>{observations++;return f.observation;},withConfirmation:async(b,fn)=>fn({read:async()=>commit,publish:async c=>(commit=c)}),confirmState:async(a,b)=>(state=b)};
 let out='',err='';const code=await main(['runtime-confirm-rollback',DEVICE],{}, {stdout:{write:s=>{out+=s;}},stderr:{write:s=>{err+=s;}},terminalRollbackDependencyFactory:()=>deps});
 assert.equal(code,0);assert.equal(err,'');assert.equal(JSON.parse(out).status,'ROLLBACK_CONFIRMED');assert.equal(observations,2);assert.ok(commit);
});
