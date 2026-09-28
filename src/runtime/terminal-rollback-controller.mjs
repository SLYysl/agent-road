import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {statePaths} from '../core/paths.mjs';
import {RuntimeStateStore,validateRuntimeStateRecord} from './runtime-state-store.mjs';
import {withTerminalRollbackConfirmation} from './runtime-recovery-store.mjs';
import {createTerminalRollbackCommit,validateTerminalRollbackCommit,validateTerminalRollbackEvidence} from './terminal-rollback-protocol.mjs';
import {createProductionRuntimeRecoveryDependencies} from './production-runtime-dependencies.mjs';
import {runtimeRecoveryTargetBindingDigest} from './runtime-recovery-remote.mjs';
import {loadTerminalRollbackObserver,observeTerminalRollback} from './terminal-rollback-remote.mjs';
function fail(){const e=new Error('RUNTIME_STATE_UNSUPPORTED');e.code=e.message;throw e;}
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function timestamp(d){const t=d.now();if(typeof t!=='string'||!Number.isFinite(Date.parse(t))||new Date(t).toISOString()!==t)fail();return t;}
// No provision/cleanup/reboot dependency exists in this confirmation controller.
export async function confirmInitialCoreRollback(deviceId,d) {
 const initial=validateRuntimeStateRecord(await d.readState(deviceId));
 if(initial.deviceId!==deviceId||initial.runtimeStatus!=='FAILED'||!['RUNTIME_COMPLETION_UNCERTAIN','RUNTIME_INSTALL_FAILED'].includes(initial.failureCode))fail();
 return d.withConfirmation({deviceId,operationId:initial.operationId},async scope=>{
  let commit=await scope.read();
  if(commit!==null){
   commit=validateTerminalRollbackCommit(commit);
   const current=validateRuntimeStateRecord(await d.readState(deviceId));
   if(same(current,commit.nextState))return current;
   if(!same(current,commit.evidence.failedState))fail();
   if(d.targetDigest(await d.loadTarget(deviceId))!==commit.evidence.targetBindingDigest
     || !same(await d.readPublicKey(),commit.evidence.controllerPublicKey))fail();
  }else{
   if(initial.failureCode!=='RUNTIME_COMPLETION_UNCERTAIN')fail();
   const start=timestamp(d),bundle=await d.loadBundle(),target=await d.loadTarget(deviceId),key=await d.readPublicKey();
   const targetBindingDigest=d.targetDigest(target);
   const observation=await d.observe({target,bundle,state:initial,controllerPublicKey:key});
   const evidence=validateTerminalRollbackEvidence({failedState:initial,controllerPublicKey:key,targetBindingDigest,executorDigest:bundle.executorDigest,observation});
   const second=await d.observe({target,bundle,state:initial,controllerPublicKey:key});
   const end=timestamp(d);
   if(Date.parse(end)<Date.parse(start)||Date.parse(end)-Date.parse(start)>240000
     || !same(initial,await d.readState(deviceId))||targetBindingDigest!==d.targetDigest(await d.loadTarget(deviceId))
     || !same(key,await d.readPublicKey())||bundle.executorDigest!==(await d.loadBundle()).executorDigest)fail();
   commit=await scope.publish(createTerminalRollbackCommit(evidence,second,end));
   commit=validateTerminalRollbackCommit(commit);
  }
  const saved=await d.confirmState(commit.evidence.failedState,commit.nextState);
  if(!same(saved,commit.nextState)||!same(await d.readState(deviceId),commit.nextState))fail();
  return saved;
 });
}
export function createProductionTerminalRollbackDependencies(env=process.env) {
 const p=statePaths(env),recovery=createProductionRuntimeRecoveryDependencies(env),state=new RuntimeStateStore(p.runtimeDevices);
 return Object.freeze({readState:id=>state.read(id),confirmState:(a,b)=>state.confirmTerminalRollback(a,b),
  withConfirmation:(binding,callback)=>withTerminalRollbackConfirmation(p.runtimeDevices,binding,callback),
  loadTarget:recovery.loadTarget,targetDigest:runtimeRecoveryTargetBindingDigest,
  readPublicKey:async()=>JSON.parse(await readFile(p.signingPublicKey,'utf8')),now:()=>new Date().toISOString(),
  loadBundle:loadTerminalRollbackObserver,observe:input=>observeTerminalRollback({...input,captureRoot:join(p.root,'inspection-captures')})});
}
