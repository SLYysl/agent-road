import assert from 'node:assert/strict';
import test from 'node:test';
import {now} from './fixtures/staged-retention.mjs';
import {createTerminalRollbackCommit,validateTerminalRollbackCommit} from '../src/runtime/terminal-rollback-protocol.mjs';
import {fixture} from './fixtures/terminal-rollback.mjs';

test('confirms only equal observations and preserves exact capsule and journal',()=>{
 const f=fixture(),c=createTerminalRollbackCommit(f,f.observation,now);
 assert.equal(c.nextState.failureCode,'RUNTIME_INSTALL_FAILED');
 assert.equal(c.evidence.observation.capsuleJson,f.observation.capsuleJson);
 assert.deepEqual(validateTerminalRollbackCommit(c),c);
 const altered=structuredClone(c);altered.nextState.operationId='2'.repeat(32);
 assert.throws(()=>validateTerminalRollbackCommit(altered));
 assert.throws(()=>createTerminalRollbackCommit(f,{...f.observation,activeAbsent:false},now));
});
for(const [name,mutate] of [
 ['pointer exists',f=>{f.observation.activeAbsent=false;}],
 ['foreign operation',f=>{f.failedState.operationId='2'.repeat(32);}],
 ['foreign target',f=>{f.targetBindingDigest='invalid';}],
 ['archive changed',f=>{f.observation.archiveBytes++;}],
 ['signature changed',f=>{let c=JSON.parse(f.observation.capsuleJson);c.signatureBase64='A'.repeat(512);f.observation.capsuleJson=JSON.stringify(c);}],
 ['unfinished rollback',f=>{let j=JSON.parse(f.observation.journalJson);j.rollbackStatus='pending';f.observation.journalJson=JSON.stringify(j);}],
 ['later installation phase',f=>{let j=JSON.parse(f.observation.journalJson);j.completedPhases.push('materialize-generation');f.observation.journalJson=JSON.stringify(j);}],
 ['unexpected journal field',f=>{let j=JSON.parse(f.observation.journalJson);j.extra=true;f.observation.journalJson=JSON.stringify(j);}],
 ['noncanonical JSON',f=>{f.observation.journalJson+='\n';}],
 ['accessor',f=>{Object.defineProperty(f,'observation',{enumerable:true,get(){throw Error('executed');}});}],
])test(`rejects ${name}`,()=>{const f=fixture();mutate(f);assert.throws(()=>createTerminalRollbackCommit(f,Object.getOwnPropertyDescriptor(f,'observation').value ?? {},now),{code:'RUNTIME_STATE_UNSUPPORTED'});});
